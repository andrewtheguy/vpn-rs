//! DCUtR mode client implementation.
//!
//! This module provides the client-side logic for DCUtR tunnels:
//! - Connects to signaling server
//! - Registers and measures RTT
//! - Coordinates hole punch timing with peer
//! - Establishes QUIC tunnel as client (connecting to server)

use anyhow::{anyhow, Context, Result};
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

/// Server name for QUIC TLS (must match server's certificate)
const DCUTR_SERVER_NAME: &str = "dcutr";

/// Maximum ICE connection attempts per signaling session
const MAX_ICE_ATTEMPTS: usize = 3;

/// Delay between ICE retry attempts (milliseconds)
const ICE_RETRY_DELAY_MS: u64 = 500;

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
/// performs coordinated ICE hole punch, establishes QUIC tunnel as CLIENT.
/// Retries on failure.
pub async fn run_dcutr_tcp_client(
    listen: String,
    _source: String, // Source is requested from server, not used directly by client
    signaling_server: String,
    peer_id: String,
    client_id: Option<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    // Ensure crypto provider is installed
    quic::ensure_crypto_provider();

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

    loop {
        match run_dcutr_tcp_client_session(
            listen_addr,
            &signaling_server,
            &peer_id,
            &client_id,
            &stun_servers,
        )
        .await
        {
            Ok(()) => {
                log::info!("Session ended normally, reconnecting...");
            }
            Err(e) => {
                log::warn!("Session error: {}. Retrying in 5 seconds...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Run a single DCUtR TCP client session
async fn run_dcutr_tcp_client_session(
    listen_addr: SocketAddr,
    signaling_server: &str,
    peer_id: &str,
    client_id: &str,
    stun_servers: &[String],
) -> Result<()> {
    // 1. Gather ICE candidates first (use fast timing for coordinated hole punching)
    let mut initial_ice = Some(IceEndpoint::gather_fast(stun_servers).await?);
    let local_creds = initial_ice.as_ref().unwrap().local_credentials();
    let local_candidates = initial_ice.as_ref().unwrap().local_candidates();

    log::info!(
        "Gathered {} ICE candidates",
        local_candidates.len()
    );

    // 2. Connect to signaling server
    let mut signaling = DCUtRSignaling::connect(signaling_server).await?;

    // 3. Register with signaling server (client doesn't need QUIC fingerprint)
    signaling
        .register(
            client_id,
            &local_creds.ufrag,
            &local_creds.pass,
            local_candidates.clone(),
            None, // Client doesn't provide QUIC fingerprint (server does)
        )
        .await?;

    // 4. Measure RTT to signaling server
    let rtt = signaling.measure_rtt().await?;
    log::info!("RTT to signaling server: {}ms", rtt);

    // 5. Request connection to peer
    signaling
        .connect_request(
            peer_id,
            &local_creds.ufrag,
            &local_creds.pass,
            local_candidates,
            None, // Client doesn't need QUIC fingerprint
        )
        .await?;

    // 6. Wait for sync_connect notification with timing info and peer's ICE credentials
    let sync_params = signaling.wait_for_sync_connect().await?;
    log::info!(
        "Received sync_connect: {} peer candidates, start at {}, is_server={}",
        sync_params.peer_candidates.len(),
        sync_params.start_at_ms,
        sync_params.is_server
    );

    // Client should NOT be server (server side handles that)
    if sync_params.is_server {
        return Err(anyhow!(
            "Client received is_server=true but should be connecting as QUIC client. Use server mode instead."
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

    // ICE retry loop - try multiple times with fresh candidates
    let mut ice_conn = None;
    let mut last_error = None;

    for attempt in 0..MAX_ICE_ATTEMPTS {
        // Use initial ice on first attempt, re-gather with fast timing on retries
        let ice_endpoint = if let Some(ice) = initial_ice.take() {
            ice
        } else {
            log::info!("ICE attempt {} failed, re-gathering candidates...", attempt);
            tokio::time::sleep(Duration::from_millis(ICE_RETRY_DELAY_MS)).await;
            IceEndpoint::gather_fast(stun_servers).await?
        };

        // As client (initiator), we are the controlling agent
        match ice_endpoint
            .connect(
                IceRole::Controlling,
                remote_creds.clone(),
                sync_params.peer_candidates.clone(),
            )
            .await
        {
            Ok(conn) => {
                if attempt > 0 {
                    log::info!("ICE succeeded on attempt {}", attempt + 1);
                }
                ice_conn = Some(conn);
                break;
            }
            Err(e) => {
                log::warn!("ICE attempt {} failed: {}", attempt + 1, e);
                last_error = Some(e);
            }
        }
    }

    let ice_conn = ice_conn.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow!("ICE connection failed after {} attempts", MAX_ICE_ATTEMPTS))
    })?;

    // Report success to signaling server
    signaling
        .report_result(true, Some("ice".to_string()))
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // 9. Connect as QUIC CLIENT to the server
    // Server's QUIC fingerprint is required for TLS verification
    let server_fingerprint = sync_params.peer_quic_fingerprint.as_ref().ok_or_else(|| {
        anyhow!("Server did not provide QUIC fingerprint for TLS verification")
    })?;

    let endpoint = quic::make_client_endpoint(ice_conn.socket, server_fingerprint)?;

    log::info!(
        "Connecting to peer via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );

    let conn = tokio::time::timeout(
        QUIC_CONNECTION_TIMEOUT,
        endpoint.connect(ice_conn.remote_addr, DCUTR_SERVER_NAME)?,
    )
    .await
    .context("Timeout during QUIC connection")?
    .context("Failed to connect via QUIC")?;

    log::info!("Connected to peer via QUIC.");

    // 10. Run TCP tunnel loop (listen locally, forward to server via QUIC)
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
///
/// Connects to signaling server, registers, requests connection to peer,
/// performs coordinated ICE hole punch, establishes QUIC tunnel as CLIENT for UDP.
/// Retries on failure.
pub async fn run_dcutr_udp_client(
    listen: String,
    _source: String, // Source is requested from server, not used directly by client
    signaling_server: String,
    peer_id: String,
    client_id: Option<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    // Ensure crypto provider is installed
    quic::ensure_crypto_provider();

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

    loop {
        match run_dcutr_udp_client_session(
            listen_addr,
            &signaling_server,
            &peer_id,
            &client_id,
            &stun_servers,
        )
        .await
        {
            Ok(()) => {
                log::info!("Session ended normally, reconnecting...");
            }
            Err(e) => {
                log::warn!("Session error: {}. Retrying in 5 seconds...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Run a single DCUtR UDP client session
async fn run_dcutr_udp_client_session(
    listen_addr: SocketAddr,
    signaling_server: &str,
    peer_id: &str,
    client_id: &str,
    stun_servers: &[String],
) -> Result<()> {
    // 1. Gather ICE candidates first (use fast timing for coordinated hole punching)
    let mut initial_ice = Some(IceEndpoint::gather_fast(stun_servers).await?);
    let local_creds = initial_ice.as_ref().unwrap().local_credentials();
    let local_candidates = initial_ice.as_ref().unwrap().local_candidates();

    log::info!(
        "Gathered {} ICE candidates",
        local_candidates.len()
    );

    // 2. Connect to signaling server
    let mut signaling = DCUtRSignaling::connect(signaling_server).await?;

    // 3. Register with signaling server (client doesn't need QUIC fingerprint)
    signaling
        .register(
            client_id,
            &local_creds.ufrag,
            &local_creds.pass,
            local_candidates.clone(),
            None, // Client doesn't provide QUIC fingerprint
        )
        .await?;

    // 4. Measure RTT to signaling server
    let rtt = signaling.measure_rtt().await?;
    log::info!("RTT to signaling server: {}ms", rtt);

    // 5. Request connection to peer
    signaling
        .connect_request(
            peer_id,
            &local_creds.ufrag,
            &local_creds.pass,
            local_candidates,
            None, // Client doesn't need QUIC fingerprint
        )
        .await?;

    // 6. Wait for sync_connect notification with timing info
    let sync_params = signaling.wait_for_sync_connect().await?;
    log::info!(
        "Received sync_connect: {} peer candidates, start at {}, is_server={}",
        sync_params.peer_candidates.len(),
        sync_params.start_at_ms,
        sync_params.is_server
    );

    // Client should NOT be server
    if sync_params.is_server {
        return Err(anyhow!(
            "Client received is_server=true but should be connecting as QUIC client. Use server mode instead."
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

    // ICE retry loop - try multiple times with fresh candidates
    let mut ice_conn = None;
    let mut last_error = None;

    for attempt in 0..MAX_ICE_ATTEMPTS {
        // Use initial ice on first attempt, re-gather with fast timing on retries
        let ice_endpoint = if let Some(ice) = initial_ice.take() {
            ice
        } else {
            log::info!("ICE attempt {} failed, re-gathering candidates...", attempt);
            tokio::time::sleep(Duration::from_millis(ICE_RETRY_DELAY_MS)).await;
            IceEndpoint::gather_fast(stun_servers).await?
        };

        // As client (initiator), we are the controlling agent
        match ice_endpoint
            .connect(
                IceRole::Controlling,
                remote_creds.clone(),
                sync_params.peer_candidates.clone(),
            )
            .await
        {
            Ok(conn) => {
                if attempt > 0 {
                    log::info!("ICE succeeded on attempt {}", attempt + 1);
                }
                ice_conn = Some(conn);
                break;
            }
            Err(e) => {
                log::warn!("ICE attempt {} failed: {}", attempt + 1, e);
                last_error = Some(e);
            }
        }
    }

    let ice_conn = ice_conn.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow!("ICE connection failed after {} attempts", MAX_ICE_ATTEMPTS))
    })?;

    signaling
        .report_result(true, Some("ice".to_string()))
        .await?;

    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // 9. Connect as QUIC CLIENT to the server
    // Server's QUIC fingerprint is required for TLS verification
    let server_fingerprint = sync_params.peer_quic_fingerprint.as_ref().ok_or_else(|| {
        anyhow!("Server did not provide QUIC fingerprint for TLS verification")
    })?;

    let endpoint = quic::make_client_endpoint(ice_conn.socket, server_fingerprint)?;

    log::info!(
        "Connecting to peer via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );

    let conn = tokio::time::timeout(
        QUIC_CONNECTION_TIMEOUT,
        endpoint.connect(ice_conn.remote_addr, DCUTR_SERVER_NAME)?,
    )
    .await
    .context("Timeout during QUIC connection")?
    .context("Failed to connect via QUIC")?;

    log::info!("Connected to peer via QUIC.");

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
