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
    forward_stream_to_udp_receiver, forward_stream_to_udp_sender, forward_udp_to_stream,
    handle_tcp_receiver_connection, handle_tcp_sender_stream, open_bi_with_retry,
    resolve_all_target_addrs, resolve_target_addr, QUIC_CONNECTION_TIMEOUT,
};

// ============================================================================
// Manual TCP Tunnel Implementation (ICE + QUIC)
// ============================================================================

pub async fn run_manual_tcp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addrs = Arc::new(
        resolve_all_target_addrs(&target)
            .await
            .with_context(|| format!("Invalid target address or hostname '{}'", target))?,
    );

    log::info!("Manual TCP Tunnel - Sender Mode");
    log::info!("================================");

    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    let quic_identity = quic::generate_server_identity()?;

    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: quic_identity.fingerprint.clone(),
        session_id: None,
    };

    log::info!("\nManual Offer (copy to receiver):");
    display_offer(&offer)?;

    log::info!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
    let answer = read_answer_from_stdin()?;
    if answer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            answer.version
        );
    }

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

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    Ok(())
}

pub async fn run_manual_tcp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    log::info!("Manual TCP Tunnel - Receiver Mode");
    log::info!("=================================");

    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    log::info!("Paste sender offer (include BEGIN/END markers), then press Enter:");
    let offer = read_offer_from_stdin()?;
    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: None,
    };

    log::info!("\nManual Answer (copy to sender):");
    display_answer(&answer)?;

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

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
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
                    match handle_tcp_receiver_connection(conn_clone, tcp_stream, peer_addr, established)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            // Connection closed errors are expected when tunnel shuts down
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

        // Clean up completed tasks and log any panics
        while let Some(result) = connection_tasks.try_join_next() {
            if let Err(e) = result {
                log::error!("Connection task panicked: {}", e);
            }
        }
    }

    // Abort remaining connection tasks
    let remaining = connection_tasks.len();
    if remaining > 0 {
        log::debug!("Aborting {} remaining connection tasks", remaining);
    }
    connection_tasks.shutdown().await;

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    log::info!("TCP receiver stopped.");
    Ok(())
}

// ============================================================================
// Manual UDP Tunnel Implementation (ICE + QUIC)
// ============================================================================

pub async fn run_manual_udp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    log::info!("Manual UDP Tunnel - Sender Mode");
    log::info!("================================");

    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    let quic_identity = quic::generate_server_identity()?;

    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: quic_identity.fingerprint.clone(),
        session_id: None,
    };

    log::info!("\nManual Offer (copy to receiver):");
    display_offer(&offer)?;

    log::info!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
    let answer = read_answer_from_stdin()?;
    if answer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            answer.version
        );
    }

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

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    log::info!("Forwarding UDP traffic to {}", target_addr);

    // Bind to the same address family as the target
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

    let forward_res = tokio::select! {
        result = forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr) => {
            result
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
            Ok(())
        }
    };

    conn.close(0u32.into(), b"done");
    log::info!("Connection closed.");

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    forward_res
}

pub async fn run_manual_udp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    log::info!("Manual UDP Tunnel - Receiver Mode");
    log::info!("=================================");

    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    log::info!("Paste sender offer (include BEGIN/END markers), then press Enter:");
    let offer = read_offer_from_stdin()?;
    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: None,
    };

    log::info!("\nManual Answer (copy to sender):");
    display_answer(&answer)?;

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

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
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

    // Use select! for UDP: forward_udp_to_stream has no exit mechanism when peer closes,
    // so we need select! to ensure prompt shutdown. UDP is inherently unreliable, so
    // losing buffered data on shutdown is acceptable.
    let forward_res = tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                log::warn!("UDP to stream error: {}", e);
            }
            result
        }
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
            result
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
            Ok(())
        }
    }

    conn.close(0u32.into(), b"done");
    log::info!("Connection closed.");

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    forward_res
}
