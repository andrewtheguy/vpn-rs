//! DCUtR mode client implementation.
//!
//! This module provides the client-side logic for DCUtR tunnels:
//! - Connects to signaling server
//! - Registers and measures RTT
//! - Coordinates hole punch timing with peer
//! - Establishes QUIC tunnel

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::signaling::dcutr::DCUtRSignaling;
use crate::transport::ice::{IceEndpoint, IceRole};
use crate::transport::quic;
use crate::tunnel_common::{
    forward_stream_to_udp_client, forward_udp_to_stream, handle_tcp_client_connection,
    open_bi_with_retry, QUIC_CONNECTION_TIMEOUT,
};

/// Get current time in milliseconds since Unix epoch
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Generate a random client ID if not provided
fn generate_client_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let random: u64 = rng.random();
    format!("client_{:016x}", random)
}

/// Run DCUtR TCP client.
///
/// Connects to signaling server, registers, requests connection to peer,
/// performs coordinated ICE hole punch, establishes QUIC tunnel.
pub async fn run_dcutr_tcp_client(
    listen: String,
    source: String,
    signaling_server: String,
    peer_id: String,
    client_id: Option<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    // Ensure crypto provider is installed
    quic::ensure_crypto_provider();

    // Validate source URL
    let source_url = url::Url::parse(&source).with_context(|| {
        format!(
            "Invalid source URL '{}'. Expected format: tcp://host:port",
            source
        )
    })?;
    if source_url.scheme() != "tcp" {
        anyhow::bail!(
            "Source URL must use tcp:// scheme for TCP client (got '{}://'). Use run_dcutr_udp_client for udp://",
            source_url.scheme()
        );
    }
    if source_url.host_str().is_none() {
        anyhow::bail!("Source URL '{}' missing host", source);
    }
    if source_url.port().is_none() {
        anyhow::bail!("Source URL '{}' missing port", source);
    }

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    // Use provided client_id or generate one
    let client_id = client_id.unwrap_or_else(generate_client_id);

    log::info!("DCUtR TCP Tunnel - Client Mode");
    log::info!("==============================");
    log::info!("Client ID: {}", client_id);
    log::info!("Peer ID: {}", peer_id);
    log::info!("Signaling server: {}", signaling_server);
    log::info!("Requesting source: {}", source);

    // 1. Gather ICE candidates first
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let _local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    log::info!(
        "Gathered {} ICE candidates",
        local_candidates.len()
    );

    // Parse SDP candidate strings to extract socket addresses
    // SDP format: "candidate:... <addr> <port> ..."
    let my_addrs: Vec<SocketAddr> = local_candidates
        .iter()
        .filter_map(|sdp| {
            str0m::Candidate::from_sdp_string(sdp)
                .ok()
                .map(|c| c.addr())
        })
        .collect();

    // 2. Connect to signaling server
    let mut signaling = DCUtRSignaling::connect(&signaling_server).await?;

    // 3. Register with signaling server
    signaling.register(&client_id).await?;

    // 4. Measure RTT to signaling server
    let rtt = signaling.measure_rtt().await?;
    log::info!("RTT to signaling server: {}ms", rtt);

    // 5. Request connection to peer
    signaling.connect_request(&peer_id, my_addrs).await?;

    // 6. Wait for sync_connect notification with timing info
    let sync_params = signaling.wait_for_sync_connect().await?;
    log::info!(
        "Received sync_connect: {} peer addresses, start at {}",
        sync_params.peer_addrs.len(),
        sync_params.start_at_ms
    );

    // 7. Wait until start time for coordinated hole punch
    let now_ms = current_time_ms();
    if sync_params.start_at_ms > now_ms {
        let wait_ms = sync_params.start_at_ms - now_ms;
        log::info!("Waiting {}ms for coordinated hole punch...", wait_ms);
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    }

    // 8. Perform ICE connectivity check
    log::info!("Starting ICE connectivity check...");

    // Convert peer addresses to SDP candidate strings
    // The connect method expects Vec<String> in SDP format
    let remote_candidates: Vec<String> = sync_params
        .peer_addrs
        .iter()
        .map(|addr| {
            // Create SDP candidate string from socket address
            // Format: candidate:<foundation> <component> <protocol> <priority> <addr> <port> typ <type>
            format!(
                "candidate:dcutr 1 UDP 2130706431 {} {} typ host",
                addr.ip(),
                addr.port()
            )
        })
        .collect();

    if remote_candidates.is_empty() {
        anyhow::bail!("No valid ICE candidates from peer");
    }

    // We need remote credentials - for now use a placeholder
    // In a full implementation, these would be exchanged via signaling
    let remote_creds = str0m::IceCreds {
        ufrag: peer_id.clone(),
        pass: peer_id.clone(),
    };

    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, remote_candidates)
        .await?;

    // Report success to signaling server
    signaling
        .report_result(true, Some("ice".to_string()))
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // 9. Generate QUIC identity and establish connection
    let quic_identity = quic::generate_server_identity()?;
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
    log::info!("Peer connected over QUIC.");

    // 10. Run TCP tunnel loop
    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    log::info!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (tcp_stream, peer_addr) = match accept_result {
                    Ok(result) => result,
                    Err(e) => {
                        log::warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                log::info!("New local connection from {}", peer_addr);
                let conn_clone = conn.clone();
                let established = tunnel_established.clone();

                connection_tasks.spawn(async move {
                    match handle_tcp_client_connection(conn_clone, tcp_stream, peer_addr, established)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let err_str = e.to_string();
                            if !err_str.contains("closed") && !err_str.contains("reset") {
                                log::warn!("TCP tunnel error for {}: {}", peer_addr, e);
                            }
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
                            log::warn!("ICE disconnected; shutting down client.");
                            break;
                        }
                    }
                    Err(_) => {
                        log::warn!("ICE disconnect watcher closed; shutting down client.");
                        break;
                    }
                }
            }
        }

        // Clean up completed tasks
        while let Some(result) = connection_tasks.try_join_next() {
            if let Err(e) = result {
                log::error!("Connection task panicked: {}", e);
            }
        }
    }

    // Cleanup
    let remaining = connection_tasks.len();
    if remaining > 0 {
        log::debug!("Aborting {} remaining connection tasks", remaining);
    }
    connection_tasks.shutdown().await;

    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    log::info!("TCP client stopped.");
    Ok(())
}

/// Run DCUtR UDP client.
pub async fn run_dcutr_udp_client(
    listen: String,
    source: String,
    signaling_server: String,
    peer_id: String,
    client_id: Option<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    // Ensure crypto provider is installed
    quic::ensure_crypto_provider();

    // Validate source URL
    let source_url = url::Url::parse(&source).with_context(|| {
        format!(
            "Invalid source URL '{}'. Expected format: udp://host:port",
            source
        )
    })?;
    if source_url.scheme() != "udp" {
        anyhow::bail!(
            "Source URL must use udp:// scheme for UDP client (got '{}://'). Use run_dcutr_tcp_client for tcp://",
            source_url.scheme()
        );
    }
    if source_url.host_str().is_none() {
        anyhow::bail!("Source URL '{}' missing host", source);
    }
    if source_url.port().is_none() {
        anyhow::bail!("Source URL '{}' missing port", source);
    }

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    // Use provided client_id or generate one
    let client_id = client_id.unwrap_or_else(generate_client_id);

    log::info!("DCUtR UDP Tunnel - Client Mode");
    log::info!("==============================");
    log::info!("Client ID: {}", client_id);
    log::info!("Peer ID: {}", peer_id);
    log::info!("Signaling server: {}", signaling_server);
    log::info!("Requesting source: {}", source);

    // 1. Gather ICE candidates first
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let _local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    log::info!(
        "Gathered {} ICE candidates",
        local_candidates.len()
    );

    // Parse SDP candidate strings to extract socket addresses
    // SDP format: "candidate:... <addr> <port> ..."
    let my_addrs: Vec<SocketAddr> = local_candidates
        .iter()
        .filter_map(|sdp| {
            str0m::Candidate::from_sdp_string(sdp)
                .ok()
                .map(|c| c.addr())
        })
        .collect();

    // 2. Connect to signaling server
    let mut signaling = DCUtRSignaling::connect(&signaling_server).await?;

    // 3. Register with signaling server
    signaling.register(&client_id).await?;

    // 4. Measure RTT to signaling server
    let rtt = signaling.measure_rtt().await?;
    log::info!("RTT to signaling server: {}ms", rtt);

    // 5. Request connection to peer
    signaling.connect_request(&peer_id, my_addrs).await?;

    // 6. Wait for sync_connect notification with timing info
    let sync_params = signaling.wait_for_sync_connect().await?;
    log::info!(
        "Received sync_connect: {} peer addresses, start at {}",
        sync_params.peer_addrs.len(),
        sync_params.start_at_ms
    );

    // 7. Wait until start time for coordinated hole punch
    let now_ms = current_time_ms();
    if sync_params.start_at_ms > now_ms {
        let wait_ms = sync_params.start_at_ms - now_ms;
        log::info!("Waiting {}ms for coordinated hole punch...", wait_ms);
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    }

    // 8. Perform ICE connectivity check
    log::info!("Starting ICE connectivity check...");

    // Convert peer addresses to SDP candidate strings
    let remote_candidates: Vec<String> = sync_params
        .peer_addrs
        .iter()
        .map(|addr| {
            format!(
                "candidate:dcutr 1 UDP 2130706431 {} {} typ host",
                addr.ip(),
                addr.port()
            )
        })
        .collect();

    if remote_candidates.is_empty() {
        anyhow::bail!("No valid ICE candidates from peer");
    }

    let remote_creds = str0m::IceCreds {
        ufrag: peer_id.clone(),
        pass: peer_id.clone(),
    };

    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, remote_candidates)
        .await?;

    signaling
        .report_result(true, Some("ice".to_string()))
        .await?;

    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // 9. Establish QUIC connection
    let quic_identity = quic::generate_server_identity()?;
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
    log::info!("Peer connected over QUIC.");

    // 10. Run UDP tunnel
    let (send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    log::info!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                log::warn!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_client(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
        }
        result = ice_disconnect_rx.changed() => {
            match result {
                Ok(()) => {
                    if *ice_disconnect_rx.borrow() {
                        log::warn!("ICE disconnected; shutting down client.");
                    }
                }
                Err(_) => {
                    log::warn!("ICE disconnect watcher closed; shutting down client.");
                }
            }
        }
    }

    conn.close(0u32.into(), b"done");
    log::info!("Connection closed.");

    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    Ok(())
}
