//! Custom mode tunnel implementations (ICE + QUIC).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn):
//! - **manual**: Manual stdin/stdout signaling with PEM-like markers

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::signaling::{
    display_answer, display_offer, read_answer_from_stdin, read_offer_from_stdin, ManualAnswer,
    ManualOffer, MANUAL_SIGNAL_VERSION,
};
use crate::transport::ice::{IceEndpoint, IceRole};
use crate::transport::quic;
use crate::tunnel_common::{
    extract_addr_from_source, forward_stream_to_udp_receiver, forward_stream_to_udp_sender,
    forward_udp_to_stream, handle_tcp_receiver_connection, handle_tcp_sender_stream,
    is_source_allowed, open_bi_with_retry, resolve_all_target_addrs, QUIC_CONNECTION_TIMEOUT,
};

// ============================================================================
// Manual Mode: Receiver-Initiated Pattern (ICE + QUIC)
// ============================================================================

/// Custom-manual sender (receiver-first pattern).
/// Reads offer from stdin, validates source, generates answer with QUIC fingerprint.
pub async fn run_manual_sender(
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    log::info!("Manual Tunnel - Sender Mode (Receiver-First)");
    log::info!("=============================================");

    // Gather ICE candidates
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    // Generate QUIC server identity
    let quic_identity = quic::generate_server_identity()?;

    // Read offer from receiver (includes source)
    log::info!("Paste receiver offer (include BEGIN/END markers), then press Enter:");
    let offer = read_offer_from_stdin()?;
    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    // Validate requested source
    let source = offer.source.as_ref().context(
        "Offer missing source field. Receiver must specify --source (e.g., --source tcp://127.0.0.1:22)"
    )?;
    let is_tcp = source.starts_with("tcp://");
    let is_udp = source.starts_with("udp://");
    if !is_tcp && !is_udp {
        anyhow::bail!("Invalid source protocol. Must start with tcp:// or udp://");
    }

    let allowed_networks = if is_tcp { &allowed_tcp } else { &allowed_udp };
    if !is_source_allowed(source, allowed_networks).await {
        anyhow::bail!(
            "Source '{}' not in allowed networks. Sender has: --allowed-{} {:?}",
            source,
            if is_tcp { "tcp" } else { "udp" },
            allowed_networks
        );
    }

    // Extract address from source URL (strip tcp:// or udp:// prefix)
    let addr_str = extract_addr_from_source(source)
        .context("Failed to parse source URL")?;

    // Resolve target addresses
    let target_addrs = Arc::new(
        resolve_all_target_addrs(&addr_str)
            .await
            .with_context(|| format!("Invalid source address '{}'", source))?,
    );
    let target_addr = *target_addrs.first().context("No target addresses resolved")?;

    // Generate and display answer with QUIC fingerprint
    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: None,
    };
    log::info!("\nManual Answer (copy to receiver):");
    log::info!("QUIC fingerprint: {}", quic_identity.fingerprint);
    display_answer(&answer)?;

    // Connect via ICE (sender is Controlled in receiver-first pattern)
    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };
    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // Create QUIC server endpoint
    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;
    log::info!(
        "Waiting for receiver QUIC connection (timeout: {:?})...",
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
    log::info!("Receiver connected over QUIC.");

    // Handle connections based on protocol
    if is_tcp {
        log::info!("Forwarding TCP connections to {}", target_addr);
        loop {
            tokio::select! {
                accept_result = conn.accept_bi() => {
                    let (send_stream, recv_stream) = match accept_result {
                        Ok(streams) => streams,
                        Err(e) => {
                            log::info!("Receiver disconnected: {}", e);
                            break;
                        }
                    };

                    log::info!("New TCP connection request received");
                    let target = Arc::clone(&target_addrs);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await {
                            log::warn!("TCP connection error: {}", e);
                        }
                    });
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
        }
    } else {
        // UDP mode
        log::info!("Forwarding UDP traffic to {}", target_addr);
        let (send_stream, recv_stream) = conn
            .accept_bi()
            .await
            .context("Failed to accept stream from receiver")?;

        let bind_addr: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let udp_socket = Arc::new(
            UdpSocket::bind(bind_addr)
                .await
                .context("Failed to bind UDP socket")?,
        );

        tokio::select! {
            result = forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr) => {
                result?;
            }
            result = ice_disconnect_rx.changed() => {
                match result {
                    Ok(()) => {
                        if *ice_disconnect_rx.borrow() {
                            log::warn!("ICE disconnected; ending session.");
                        }
                    }
                    Err(_) => {
                        log::warn!("ICE disconnect watcher closed; ending session.");
                    }
                }
            }
        }
    }

    conn.close(0u32.into(), b"done");

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    log::info!("Connection closed.");
    Ok(())
}

/// Custom-manual receiver (receiver-first pattern).
/// Generates offer with source, reads answer with QUIC fingerprint, connects.
pub async fn run_manual_receiver(
    source: String,
    listen: SocketAddr,
    stun_servers: Vec<String>,
) -> Result<()> {
    let is_tcp = source.starts_with("tcp://");
    let is_udp = source.starts_with("udp://");
    if !is_tcp && !is_udp {
        anyhow::bail!("Invalid source protocol '{}'. Must start with tcp:// or udp://", source);
    }

    log::info!("Manual Tunnel - Receiver Mode (Receiver-First)");
    log::info!("===============================================");
    log::info!("Requesting source: {}", source);

    // Gather ICE candidates
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    // Create offer with source (no QUIC fingerprint - receiver is client)
    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: String::new(), // Will be provided by sender in answer
        session_id: None,
        source: Some(source.clone()),
    };
    log::info!("\nManual Offer (copy to sender):");
    display_offer(&offer)?;

    // Read answer from sender (includes QUIC fingerprint)
    log::info!("Paste sender answer (include BEGIN/END markers), then press Enter:");
    log::info!("The sender will also display a QUIC fingerprint - enter it when prompted.");
    let answer = read_answer_from_stdin()?;
    if answer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            answer.version
        );
    }

    // Read QUIC fingerprint from stdin
    log::info!("Enter the QUIC fingerprint from sender:");
    let mut fingerprint_line = String::new();
    std::io::stdin().read_line(&mut fingerprint_line)?;
    let quic_fingerprint = fingerprint_line.trim().to_string();
    if quic_fingerprint.is_empty() {
        anyhow::bail!("QUIC fingerprint is required");
    }

    // Connect via ICE (receiver is Controlling in receiver-first pattern)
    let remote_creds = str0m::IceCreds {
        ufrag: answer.ice_ufrag,
        pass: answer.ice_pwd,
    };
    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, answer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    // Create QUIC client endpoint
    let endpoint = quic::make_client_endpoint(ice_conn.socket, &quic_fingerprint)?;
    log::info!(
        "Connecting to sender via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to sender")?;
    log::info!("Connected to sender over QUIC.");

    if is_tcp {
        let conn = Arc::new(conn);
        let tunnel_established = Arc::new(AtomicBool::new(false));

        let listener = TcpListener::bind(listen)
            .await
            .context("Failed to bind TCP listener")?;
        log::info!(
            "Listening on TCP {} - configure your client to connect here",
            listen
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
                        match handle_tcp_receiver_connection(conn_clone, tcp_stream, peer_addr, established)
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
                                log::warn!("ICE disconnected; shutting down receiver.");
                                break;
                            }
                        }
                        Err(_) => {
                            log::warn!("ICE disconnect watcher closed; shutting down receiver.");
                            break;
                        }
                    }
                }
            }

            while let Some(result) = connection_tasks.try_join_next() {
                if let Err(e) = result {
                    log::error!("Connection task panicked: {}", e);
                }
            }
        }

        let remaining = connection_tasks.len();
        if remaining > 0 {
            log::debug!("Aborting {} remaining connection tasks", remaining);
        }
        connection_tasks.shutdown().await;

        conn.close(0u32.into(), b"done");

        // Clean up the ICE keeper task
        ice_keeper_handle.abort();
        match ice_keeper_handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {}
            Err(e) => log::warn!("ICE keeper task failed: {}", e),
        }

        log::info!("TCP receiver stopped.");
    } else {
        // UDP mode
        let (send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

        let udp_socket = Arc::new(
            UdpSocket::bind(listen)
                .await
                .context("Failed to bind UDP socket")?,
        );
        log::info!(
            "Listening on UDP {} - configure your client to connect here",
            listen
        );

        let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let udp_clone = udp_socket.clone();
        let client_clone = client_addr.clone();

        tokio::select! {
            result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
                if let Err(ref e) = result {
                    log::warn!("UDP to stream error: {}", e);
                }
            }
            result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
                if let Err(ref e) = result {
                    log::warn!("Stream to UDP error: {}", e);
                }
            }
            result = ice_disconnect_rx.changed() => {
                match result {
                    Ok(()) => {
                        if *ice_disconnect_rx.borrow() {
                            log::warn!("ICE disconnected; shutting down receiver.");
                        }
                    }
                    Err(_) => {
                        log::warn!("ICE disconnect watcher closed; shutting down receiver.");
                    }
                }
            }
        }

        conn.close(0u32.into(), b"done");

        // Clean up the ICE keeper task
        ice_keeper_handle.abort();
        match ice_keeper_handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {}
            Err(e) => log::warn!("ICE keeper task failed: {}", e),
        }

        log::info!("UDP receiver stopped.");
    }

    Ok(())
}

