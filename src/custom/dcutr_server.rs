//! DCUtR mode server implementation.
//!
//! This module provides the server-side logic for DCUtR tunnels:
//! - Connects to signaling server and registers
//! - Waits for client connection requests
//! - Coordinates hole punch timing with client
//! - Accepts QUIC connections and forwards to local sources

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;

use crate::signaling::dcutr::DCUtRSignaling;
use crate::transport::ice::{IceEndpoint, IceRole};
use crate::transport::quic;
use crate::tunnel_common::{
    bind_udp_for_targets, extract_addr_from_source, forward_stream_to_udp_server,
    handle_tcp_server_stream, resolve_all_target_addrs, QUIC_CONNECTION_TIMEOUT,
};


/// Get current time in milliseconds since Unix epoch
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Generate a random server ID if not provided
fn generate_server_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let random: u64 = rng.random();
    format!("server_{:016x}", random)
}

/// Run DCUtR TCP server.
///
/// Registers with signaling server, waits for client connection requests,
/// performs coordinated ICE hole punch, accepts QUIC connections,
/// and forwards traffic to the configured TCP source.
pub async fn run_dcutr_tcp_server(
    source: String,
    signaling_server: String,
    server_id: Option<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    // Ensure crypto provider is installed
    quic::ensure_crypto_provider();

    // Use provided server_id or generate one
    let server_id = server_id.unwrap_or_else(generate_server_id);

    log::info!("DCUtR TCP Tunnel - Server Mode");
    log::info!("==============================");
    log::info!("Server ID: {}", server_id);
    log::info!("Signaling server: {}", signaling_server);
    log::info!("Source: {}", source);

    loop {
        match run_dcutr_tcp_server_session(
            &source,
            &signaling_server,
            &server_id,
            &stun_servers,
        )
        .await
        {
            Ok(()) => {
                log::info!("Session ended normally, waiting for next connection...");
            }
            Err(e) => {
                log::warn!("Session error: {}. Retrying in 5 seconds...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Run a single DCUtR TCP server session
async fn run_dcutr_tcp_server_session(
    source: &str,
    signaling_server: &str,
    server_id: &str,
    stun_servers: &[String],
) -> Result<()> {
    // 1. Gather ICE candidates first (use fast timing for coordinated hole punching)
    let ice = IceEndpoint::gather_fast(stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    log::info!("Gathered {} ICE candidates", local_candidates.len());

    // 2. Generate QUIC identity (server needs to provide fingerprint)
    let quic_identity = quic::generate_server_identity()?;

    // 3. Connect to signaling server
    let mut signaling = DCUtRSignaling::connect(signaling_server).await?;

    // 4. Register with signaling server (server provides QUIC fingerprint)
    signaling
        .register(
            server_id,
            &local_creds.ufrag,
            &local_creds.pass,
            local_candidates.clone(),
            Some(quic_identity.fingerprint.clone()),
        )
        .await?;

    // 5. Measure RTT to signaling server
    let rtt = signaling.measure_rtt().await?;
    log::info!("RTT to signaling server: {}ms", rtt);

    log::info!("Waiting for client connection request...");

    // 6. Wait for sync_connect notification (triggered when client requests to connect)
    let sync_params = signaling.wait_for_sync_connect().await?;
    log::info!(
        "Received sync_connect: {} peer candidates, start at {}, is_server={}",
        sync_params.peer_candidates.len(),
        sync_params.start_at_ms,
        sync_params.is_server
    );

    // Server should receive is_server=true
    if !sync_params.is_server {
        return Err(anyhow!(
            "Server received is_server=false but should be accepting QUIC connections. Check signaling setup."
        ));
    }

    // 7. Wait until start time for coordinated hole punch
    let now_ms = current_time_ms();
    if sync_params.start_at_ms > now_ms {
        let wait_ms = sync_params.start_at_ms - now_ms;
        log::info!("Waiting {}ms for coordinated hole punch...", wait_ms);
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    }

    // 8. Perform ICE connectivity check with peer's credentials (with retry)
    log::info!("Starting ICE connectivity check...");

    let remote_creds = str0m::IceCreds {
        ufrag: sync_params.peer_ice_ufrag.clone(),
        pass: sync_params.peer_ice_pwd.clone(),
    };

    // As server (responder), we are the controlled agent
    let ice_conn = ice
        .connect(
            IceRole::Controlled,
            remote_creds,
            sync_params.peer_candidates.clone(),
        )
        .await?;

    log::info!("ICE connection established");

    // Report success to signaling server
    signaling
        .report_result(true, Some("ice".to_string()))
        .await?;

    // Spawn the ICE keeper
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // 9. Accept QUIC connections as server
    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;

    log::info!(
        "Waiting for QUIC connection (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;

    log::info!("Client connected via QUIC");

    // 10. Handle incoming streams and forward to configured source
    // Pre-resolve the target once
    let target_hostport = extract_addr_from_source(source)
        .ok_or_else(|| anyhow!("Invalid source format: {}", source))?;
    let target_addrs = Arc::new(
        resolve_all_target_addrs(&target_hostport)
            .await
            .with_context(|| format!("Invalid source '{}'", source))?,
    );
    if target_addrs.is_empty() {
        return Err(anyhow!("No addresses resolved for: {}", target_hostport));
    }
    log::info!(
        "Forwarding TCP traffic to {} ({} address(es) resolved)",
        target_addrs.first().unwrap(),
        target_addrs.len()
    );

    let mut stream_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = conn.accept_bi() => {
                let (send_stream, recv_stream) = match accept_result {
                    Ok(streams) => streams,
                    Err(e) => {
                        log::info!("QUIC connection ended: {}", e);
                        break;
                    }
                };

                let target_addrs_clone = Arc::clone(&target_addrs);
                stream_tasks.spawn(async move {
                    if let Err(e) = handle_tcp_server_stream(send_stream, recv_stream, target_addrs_clone).await {
                        let err_str = e.to_string();
                        if !err_str.contains("closed") && !err_str.contains("reset") {
                            log::warn!("TCP stream error: {}", e);
                        }
                    }
                });
            }
            error = conn.closed() => {
                log::info!("QUIC connection closed: {}", error);
                break;
            }
            result = ice_disconnect_rx.changed() => {
                match result {
                    Ok(()) => {
                        if *ice_disconnect_rx.borrow() {
                            log::warn!("ICE disconnected; ending session.");
                            break;
                        }
                    }
                    Err(_) => {
                        log::warn!("ICE disconnect watcher closed; ending session.");
                        break;
                    }
                }
            }
        }

        // Clean up completed tasks
        while let Some(result) = stream_tasks.try_join_next() {
            if let Err(e) = result {
                log::error!("Stream task panicked: {}", e);
            }
        }
    }

    // Cleanup
    let remaining = stream_tasks.len();
    if remaining > 0 {
        log::debug!("Aborting {} remaining stream tasks", remaining);
    }
    stream_tasks.shutdown().await;

    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    Ok(())
}

/// Run DCUtR UDP server.
///
/// Registers with signaling server, waits for client connection requests,
/// performs coordinated ICE hole punch, accepts QUIC connections,
/// and forwards traffic to the configured UDP source.
pub async fn run_dcutr_udp_server(
    source: String,
    signaling_server: String,
    server_id: Option<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    // Ensure crypto provider is installed
    quic::ensure_crypto_provider();

    // Use provided server_id or generate one
    let server_id = server_id.unwrap_or_else(generate_server_id);

    log::info!("DCUtR UDP Tunnel - Server Mode");
    log::info!("==============================");
    log::info!("Server ID: {}", server_id);
    log::info!("Signaling server: {}", signaling_server);
    log::info!("Source: {}", source);

    loop {
        match run_dcutr_udp_server_session(
            &source,
            &signaling_server,
            &server_id,
            &stun_servers,
        )
        .await
        {
            Ok(()) => {
                log::info!("Session ended normally, waiting for next connection...");
            }
            Err(e) => {
                log::warn!("Session error: {}. Retrying in 5 seconds...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Run a single DCUtR UDP server session
async fn run_dcutr_udp_server_session(
    source: &str,
    signaling_server: &str,
    server_id: &str,
    stun_servers: &[String],
) -> Result<()> {
    // 1. Gather ICE candidates first (use fast timing for coordinated hole punching)
    let ice = IceEndpoint::gather_fast(stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    log::info!("Gathered {} ICE candidates", local_candidates.len());

    // 2. Generate QUIC identity (server needs to provide fingerprint)
    let quic_identity = quic::generate_server_identity()?;

    // 3. Connect to signaling server
    let mut signaling = DCUtRSignaling::connect(signaling_server).await?;

    // 4. Register with signaling server (server provides QUIC fingerprint)
    signaling
        .register(
            server_id,
            &local_creds.ufrag,
            &local_creds.pass,
            local_candidates.clone(),
            Some(quic_identity.fingerprint.clone()),
        )
        .await?;

    // 5. Measure RTT to signaling server
    let rtt = signaling.measure_rtt().await?;
    log::info!("RTT to signaling server: {}ms", rtt);

    log::info!("Waiting for client connection request...");

    // 6. Wait for sync_connect notification
    let sync_params = signaling.wait_for_sync_connect().await?;
    log::info!(
        "Received sync_connect: {} peer candidates, start at {}, is_server={}",
        sync_params.peer_candidates.len(),
        sync_params.start_at_ms,
        sync_params.is_server
    );

    // Server should receive is_server=true
    if !sync_params.is_server {
        return Err(anyhow!(
            "Server received is_server=false but should be accepting QUIC connections."
        ));
    }

    // 7. Wait until start time for coordinated hole punch
    let now_ms = current_time_ms();
    if sync_params.start_at_ms > now_ms {
        let wait_ms = sync_params.start_at_ms - now_ms;
        log::info!("Waiting {}ms for coordinated hole punch...", wait_ms);
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    }

    // 8. Perform ICE connectivity check with peer's credentials (with retry)
    log::info!("Starting ICE connectivity check...");

    let remote_creds = str0m::IceCreds {
        ufrag: sync_params.peer_ice_ufrag.clone(),
        pass: sync_params.peer_ice_pwd.clone(),
    };

    // As server (responder), we are the controlled agent
    let ice_conn = ice
        .connect(
            IceRole::Controlled,
            remote_creds,
            sync_params.peer_candidates.clone(),
        )
        .await?;

    log::info!("ICE connection established");

    // Report success to signaling server
    signaling
        .report_result(true, Some("ice".to_string()))
        .await?;

    // Spawn the ICE keeper
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // 9. Accept QUIC connections as server
    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;

    log::info!(
        "Waiting for QUIC connection (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;

    log::info!("Client connected via QUIC");

    // 10. Accept stream and forward UDP
    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from client")?;

    let target_hostport = extract_addr_from_source(source)
        .ok_or_else(|| anyhow!("Invalid source format: {}", source))?;

    let target_addrs = Arc::new(
        resolve_all_target_addrs(&target_hostport)
            .await
            .with_context(|| format!("Invalid source '{}'", source))?,
    );
    if target_addrs.is_empty() {
        return Err(anyhow!("No addresses resolved for: {}", target_hostport));
    }

    log::info!(
        "Forwarding UDP traffic to {} ({} address(es) resolved)",
        target_addrs.first().unwrap(),
        target_addrs.len()
    );

    // Bind to appropriate address family based on all resolved targets
    let udp_socket = Arc::new(
        bind_udp_for_targets(&target_addrs)
            .await
            .context("Failed to bind UDP socket")?,
    );

    // Handle ICE disconnect
    let disconnect_conn = conn.clone();
    let disconnect_task = tokio::spawn(async move {
        match ice_disconnect_rx.changed().await {
            Ok(()) => {
                if *ice_disconnect_rx.borrow() {
                    log::warn!("ICE disconnected; closing QUIC connection.");
                    disconnect_conn.close(0u32.into(), b"ice disconnected");
                }
            }
            Err(_) => {
                log::warn!("ICE disconnect watcher closed; closing QUIC connection.");
                disconnect_conn.close(0u32.into(), b"ice watcher closed");
            }
        }
    });

    let forward_result = tokio::select! {
        result = forward_stream_to_udp_server(recv_stream, send_stream, udp_socket, Arc::clone(&target_addrs)) => {
            result
        }
        error = conn.closed() => {
            log::info!("QUIC connection closed: {}", error);
            Ok(())
        }
    };

    conn.close(0u32.into(), b"done");
    log::info!("UDP session closed");

    if !disconnect_task.is_finished() {
        disconnect_task.abort();
    }
    match disconnect_task.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE disconnect task failed: {}", e),
    }

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    forward_result
}
