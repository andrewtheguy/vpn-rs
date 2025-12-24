//! Iroh-based tunnel implementations.
//!
//! This module provides tunnel implementations using the Iroh networking stack:
//! - **iroh**: Multi-source mode with Iroh relays and discovery (receiver requests source)
//! - **iroh-manual**: Manual signaling with direct STUN/local addresses (no relay)

use anyhow::{Context, Result};
use iroh::discovery::static_provider::StaticProvider;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::iroh::endpoint::{
    connect_to_sender, create_receiver_endpoint, create_sender_endpoint, print_connection_type,
    validate_relay_only, MULTI_ALPN,
};
use crate::signaling::{
    decode_source_request, decode_source_response, display_iroh_answer, display_iroh_offer,
    encode_source_request, encode_source_response, read_iroh_answer_from_stdin,
    read_iroh_offer_from_stdin, read_length_prefixed, IrohManualAnswer, IrohManualOffer,
    SourceRequest, SourceResponse, IROH_SIGNAL_VERSION,
};
use crate::tunnel_common::{
    bind_udp_for_targets, check_source_allowed, copy_stream, extract_addr_from_source,
    order_udp_addresses, resolve_all_target_addrs, resolve_stun_addrs, retry_with_backoff,
    validate_allowed_networks, STREAM_OPEN_BASE_DELAY_MS, STREAM_OPEN_MAX_ATTEMPTS,
};


async fn handle_tcp_sender_stream(
    send_stream: iroh::endpoint::SendStream,
    recv_stream: iroh::endpoint::RecvStream,
    target_addrs: Arc<Vec<SocketAddr>>,
) -> Result<()> {
    let tcp_stream = crate::tunnel_common::try_connect_tcp(&target_addrs)
        .await
        .context("Failed to connect to target TCP service")?;

    let target_addr = tcp_stream.peer_addr().ok();
    log::info!("-> Connected to target {:?}", target_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    log::info!("<- TCP connection to {:?} closed", target_addr);
    Ok(())
}

async fn handle_tcp_receiver_connection(
    conn: Arc<iroh::endpoint::Connection>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    tunnel_established: Arc<AtomicBool>,
) -> Result<()> {
    let (send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    // Print success message only on first successful stream
    if !tunnel_established.swap(true, Ordering::Relaxed) {
        log::info!("Tunnel to sender established!");
    }
    log::info!("-> Opened tunnel for {}", peer_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    log::info!("<- Connection from {} closed", peer_addr);
    Ok(())
}

// ============================================================================
// Iroh Multi-Source Mode
// ============================================================================

/// Default maximum concurrent sessions for multi-source mode.
const DEFAULT_MAX_SESSIONS: usize = 100;

/// Run iroh multi-source sender.
///
/// This mode allows receivers to request specific sources (tcp://host:port or udp://host:port).
/// The sender validates requests against allowed_tcp and allowed_udp CIDR lists.
pub async fn run_multi_source_sender(
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    max_sessions: Option<usize>,
    secret: Option<SecretKey>,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    // Validate CIDR notation at startup
    validate_allowed_networks(&allowed_tcp, "--allowed-tcp")?;
    validate_allowed_networks(&allowed_udp, "--allowed-udp")?;

    if allowed_tcp.is_empty() && allowed_udp.is_empty() {
        anyhow::bail!(
            "At least one --allowed-tcp or --allowed-udp network must be specified.\n\
            Example: --allowed-tcp 127.0.0.0/8 --allowed-udp 10.0.0.0/8"
        );
    }

    validate_relay_only(relay_only, &relay_urls)?;

    log::info!("Multi-Source Tunnel - Sender Mode");
    log::info!("==================================");
    log::info!("Creating iroh endpoint...");

    let endpoint = create_sender_endpoint(
        &relay_urls,
        relay_only,
        secret,
        dns_server.as_deref(),
        MULTI_ALPN,
    )
    .await?;

    let endpoint_id = endpoint.id();
    let max_sessions = max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS);

    log::info!("\nEndpointId: {}", endpoint_id);
    log::info!("Allowed TCP networks: {:?}", allowed_tcp);
    log::info!("Allowed UDP networks: {:?}", allowed_udp);
    log::info!("Max concurrent sessions: {}", max_sessions);
    log::info!("\nOn the receiver side, run:");
    log::info!(
        "  tunnel-rs receiver iroh --node-id {} --source tcp://target:port --target 127.0.0.1:port\n",
        endpoint_id
    );
    log::info!("Waiting for receivers to connect...");

    // Session management with semaphore for concurrency limit
    let session_semaphore = Arc::new(tokio::sync::Semaphore::new(max_sessions));
    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        // Clean up completed tasks
        while connection_tasks.try_join_next().is_some() {}

        let incoming = match endpoint.accept().await {
            Some(incoming) => incoming,
            None => {
                log::info!("Endpoint closed");
                break;
            }
        };

        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let remote_id = conn.remote_id();
        log::info!("Receiver connected from: {}", remote_id);

        // Clone for the spawned task
        let allowed_tcp = allowed_tcp.clone();
        let allowed_udp = allowed_udp.clone();
        let semaphore = session_semaphore.clone();

        connection_tasks.spawn(async move {
            if let Err(e) =
                handle_multi_source_connection(conn, allowed_tcp, allowed_udp, semaphore).await
            {
                log::warn!("Connection error for {}: {}", remote_id, e);
            }
        });
    }

    // Wait for remaining tasks to complete
    connection_tasks.shutdown().await;
    endpoint.close().await;
    log::info!("Multi-source sender stopped.");

    Ok(())
}

/// Handle a single multi-source connection.
/// Each bidirectional stream from the receiver is a separate source request.
async fn handle_multi_source_connection(
    conn: iroh::endpoint::Connection,
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let remote_id = conn.remote_id();
    let mut stream_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = conn.accept_bi() => {
                let (send_stream, recv_stream) = match accept_result {
                    Ok(streams) => streams,
                    Err(e) => {
                        log::info!("Receiver {} disconnected: {}", remote_id, e);
                        break;
                    }
                };

                // Try to acquire a session permit
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!("Session limit reached, rejecting stream from {}", remote_id);
                        // Send rejection and close stream
                        let response = SourceResponse::rejected("Session limit reached");
                        match encode_source_response(&response) {
                            Ok(encoded) => {
                                let mut send = send_stream;
                                if let Err(e) = send.write_all(&encoded).await {
                                    log::warn!("Failed to write rejection response to {}: {}", remote_id, e);
                                }
                                if let Err(e) = send.finish() {
                                    log::warn!("Failed to finish rejection stream to {}: {}", remote_id, e);
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to encode rejection response for {}: {}", remote_id, e);
                            }
                        }
                        continue;
                    }
                };

                let allowed_tcp = allowed_tcp.clone();
                let allowed_udp = allowed_udp.clone();

                stream_tasks.spawn(async move {
                    let _permit = permit; // Hold permit until task completes
                    if let Err(e) = handle_multi_source_stream(
                        send_stream,
                        recv_stream,
                        allowed_tcp,
                        allowed_udp,
                    ).await {
                        log::warn!("Stream error: {}", e);
                    }
                });
            }
            error = conn.closed() => {
                log::info!("Receiver {} disconnected: {}", remote_id, error);
                break;
            }
        }

        // Clean up completed stream tasks
        while stream_tasks.try_join_next().is_some() {}
    }

    // Wait for remaining stream tasks
    stream_tasks.shutdown().await;
    conn.close(0u32.into(), b"done");
    log::info!("Connection from {} closed", remote_id);

    Ok(())
}

/// Handle a single stream within a multi-source connection.
/// Reads SourceRequest, validates, sends SourceResponse, then forwards traffic.
async fn handle_multi_source_stream(
    mut send_stream: iroh::endpoint::SendStream,
    mut recv_stream: iroh::endpoint::RecvStream,
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
) -> Result<()> {
    // Read the source request
    let request_bytes = read_length_prefixed(&mut recv_stream)
        .await
        .context("Failed to read source request")?;
    let request = decode_source_request(&request_bytes).context("Invalid source request")?;

    log::info!("Source request: {}", request.source);

    // Determine protocol and validate
    let is_tcp = request.source.starts_with("tcp://");
    let is_udp = request.source.starts_with("udp://");

    if !is_tcp && !is_udp {
        let response = SourceResponse::rejected("Invalid protocol (must be tcp:// or udp://)");
        let encoded = encode_source_response(&response)?;
        send_stream.write_all(&encoded).await?;
        send_stream.finish()?;
        anyhow::bail!("Invalid protocol in source request: {}", request.source);
    }

    // Validate against allowed networks
    let allowed_networks = if is_tcp { &allowed_tcp } else { &allowed_udp };
    let check_result = check_source_allowed(&request.source, allowed_networks).await;

    if !check_result.allowed {
        let reason = check_result.rejection_reason(&request.source, allowed_networks);
        let response = SourceResponse::rejected(&reason);
        let encoded = encode_source_response(&response)?;
        send_stream.write_all(&encoded).await?;
        send_stream.finish()?;
        anyhow::bail!("{}", reason);
    }

    // Extract target address
    let target_addr = extract_addr_from_source(&request.source)
        .ok_or_else(|| anyhow::anyhow!("Invalid source URL format: {}", request.source))?;

    // Send acceptance response
    let response = SourceResponse::accepted();
    let encoded = encode_source_response(&response)?;
    send_stream.write_all(&encoded).await?;

    log::info!("Accepted source request, forwarding to {}", target_addr);

    // Route to appropriate handler based on protocol
    if is_tcp {
        // Resolve and connect to TCP target
        let target_addrs = resolve_all_target_addrs(&target_addr).await?;
        let tcp_stream = crate::tunnel_common::try_connect_tcp(&target_addrs)
            .await
            .context("Failed to connect to target TCP service")?;

        log::info!("-> Connected to TCP target {}", target_addr);
        bridge_streams(recv_stream, send_stream, tcp_stream).await?;
        log::info!("<- TCP connection to {} closed", target_addr);
    } else {
        // UDP forwarding with multi-address fallback
        let target_addrs = Arc::new(resolve_all_target_addrs(&target_addr).await?);
        if target_addrs.is_empty() {
            anyhow::bail!("No target addresses resolved for '{}'", target_addr);
        }
        let primary_addr = target_addrs.first().copied().unwrap();

        // Bind UDP socket with appropriate address family
        let udp_socket = Arc::new(
            bind_udp_for_targets(&target_addrs)
                .await
                .context("Failed to bind UDP socket")?,
        );

        log::info!(
            "-> Forwarding UDP to {} ({} address(es) resolved)",
            primary_addr,
            target_addrs.len()
        );
        forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addrs).await?;
        log::info!("<- UDP forwarding to {} closed", primary_addr);
    }

    Ok(())
}

/// Run iroh multi-source receiver.
///
/// Connects to a sender and requests a specific source (tcp://host:port or udp://host:port).
/// The sender validates the request and either accepts or rejects it.
pub async fn run_multi_source_receiver(
    node_id: String,
    source: String,
    target: String,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    // Validate source format
    let is_tcp = source.starts_with("tcp://");
    let is_udp = source.starts_with("udp://");
    if !is_tcp && !is_udp {
        anyhow::bail!(
            "Source must start with tcp:// or udp:// (got: {})",
            source
        );
    }

    let listen_addr: SocketAddr = target.parse().context(
        "Invalid target address format. Use format like 127.0.0.1:2222 or [::]:2222",
    )?;

    let sender_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    log::info!("Multi-Source Tunnel - Receiver Mode");
    log::info!("====================================");
    log::info!("Requesting source: {}", source);
    log::info!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only, dns_server.as_deref()).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, MULTI_ALPN).await?;

    log::info!("Connected to sender!");
    print_connection_type(&endpoint, conn.remote_id());

    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    if is_tcp {
        run_multi_source_tcp_receiver(conn, source, listen_addr, tunnel_established).await?;
    } else {
        run_multi_source_udp_receiver(conn, source, listen_addr).await?;
    }

    endpoint.close().await;
    log::info!("Multi-source receiver stopped.");

    Ok(())
}

/// Run TCP receiver for multi-source mode.
/// Opens streams for each local connection and sends source requests.
async fn run_multi_source_tcp_receiver(
    conn: Arc<iroh::endpoint::Connection>,
    source: String,
    listen_addr: SocketAddr,
    tunnel_established: Arc<AtomicBool>,
) -> Result<()> {
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
                let source_clone = source.clone();
                let established = tunnel_established.clone();

                connection_tasks.spawn(async move {
                    match handle_multi_source_tcp_receiver_connection(
                        conn_clone,
                        tcp_stream,
                        peer_addr,
                        source_clone,
                        established,
                    ).await {
                        Ok(()) => {}
                        Err(e) => {
                            log::warn!("TCP tunnel error for {}: {}", peer_addr, e);
                        }
                    }
                });
            }
            error = conn.closed() => {
                log::info!("QUIC connection closed: {}", error);
                break;
            }
        }

        // Clean up completed tasks
        while let Some(result) = connection_tasks.try_join_next() {
            if let Err(e) = result {
                log::error!("Connection task panicked: {}", e);
            }
        }
    }

    connection_tasks.shutdown().await;
    conn.close(0u32.into(), b"done");
    log::info!("TCP receiver stopped.");

    Ok(())
}

/// Handle a single TCP connection in multi-source receiver mode.
async fn handle_multi_source_tcp_receiver_connection(
    conn: Arc<iroh::endpoint::Connection>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    source: String,
    tunnel_established: Arc<AtomicBool>,
) -> Result<()> {
    let (mut send_stream, mut recv_stream) = open_bi_with_retry(&conn).await?;

    // Send source request
    let request = SourceRequest::new(source.clone());
    let encoded = encode_source_request(&request)?;
    send_stream.write_all(&encoded).await?;

    // Read response
    let response_bytes = read_length_prefixed(&mut recv_stream)
        .await
        .context("Failed to read source response")?;
    let response = decode_source_response(&response_bytes).context("Invalid source response")?;

    if !response.accepted {
        let reason = response.reason.unwrap_or_else(|| "Unknown".to_string());
        anyhow::bail!("Source request rejected: {}", reason);
    }

    // Print success message only on first successful stream
    if !tunnel_established.swap(true, Ordering::Relaxed) {
        log::info!("Tunnel to sender established! Source: {}", source);
    }
    log::info!("-> Opened tunnel for {}", peer_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    log::info!("<- Connection from {} closed", peer_addr);
    Ok(())
}

/// Run UDP receiver for multi-source mode.
/// Opens a single stream and sends source request, then forwards UDP traffic.
async fn run_multi_source_udp_receiver(
    conn: Arc<iroh::endpoint::Connection>,
    source: String,
    listen_addr: SocketAddr,
) -> Result<()> {
    let (mut send_stream, mut recv_stream) = open_bi_with_retry(&conn).await?;

    // Send source request
    let request = SourceRequest::new(source.clone());
    let encoded = encode_source_request(&request)?;
    send_stream.write_all(&encoded).await?;

    // Read response
    let response_bytes = read_length_prefixed(&mut recv_stream)
        .await
        .context("Failed to read source response")?;
    let response = decode_source_response(&response_bytes).context("Invalid source response")?;

    if !response.accepted {
        let reason = response.reason.unwrap_or_else(|| "Unknown".to_string());
        anyhow::bail!("Source request rejected: {}", reason);
    }

    log::info!("Tunnel established! Source: {}", source);

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
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
        }
        error = conn.closed() => {
            log::warn!("QUIC connection closed: {}", error);
        }
    }

    conn.close(0u32.into(), b"done");
    log::info!("UDP receiver stopped.");

    Ok(())
}

// ============================================================================
// Iroh-Manual Mode: Receiver-Initiated Pattern
// ============================================================================

/// Iroh-manual sender (receiver-first pattern).
/// Reads offer from stdin, validates source, generates answer, handles connections.
pub async fn run_iroh_manual_sender(
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    log::info!("Iroh Manual Tunnel - Sender Mode (Receiver-First)");
    log::info!("==================================================");
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(MULTI_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    // Read offer from receiver (includes source)
    log::info!("Paste receiver offer (include BEGIN/END markers), then press Enter:");
    let offer = read_iroh_offer_from_stdin()?;
    if offer.version != IROH_SIGNAL_VERSION {
        anyhow::bail!(
            "Iroh signaling version mismatch (expected {}, got {})",
            IROH_SIGNAL_VERSION,
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
    let check_result = check_source_allowed(source, allowed_networks).await;
    if !check_result.allowed {
        anyhow::bail!("{}", check_result.rejection_reason(source, allowed_networks));
    }

    // Resolve target addresses (supports both IP addresses and hostnames)
    let addr_str = extract_addr_from_source(source)
        .context("Failed to parse source URL")?;
    let target_addrs = Arc::new(
        resolve_all_target_addrs(&addr_str)
            .await
            .with_context(|| format!("Invalid source address '{}'", source))?,
    );
    if target_addrs.is_empty() {
        anyhow::bail!("No target addresses resolved for '{}'", source);
    }
    let primary_addr = target_addrs.first().copied().unwrap();

    // Generate and display answer
    let answer = IrohManualAnswer {
        version: IROH_SIGNAL_VERSION,
        node_id: node_id.to_string(),
        direct_addresses: direct_addrs,
    };
    log::info!("\nIroh Manual Answer (copy to receiver):");
    display_iroh_answer(&answer)?;

    // Add remote peer to discovery
    let remote_id: EndpointId = offer
        .node_id
        .parse()
        .context("Invalid remote NodeId format")?;
    let remote_addrs: Vec<SocketAddr> = offer
        .direct_addresses
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let remote_addr =
        EndpointAddr::new(remote_id).with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    log::info!(
        "Added remote peer: {} ({} addresses)",
        remote_id,
        offer.direct_addresses.len()
    );

    // Race connect vs accept
    let conn = race_connect_accept(&endpoint, remote_id, MULTI_ALPN).await?;
    log::info!("Peer connected: {}", conn.remote_id());

    // Handle connections based on protocol
    if is_tcp {
        log::info!(
            "Forwarding TCP connections to {} ({} address(es) resolved)",
            primary_addr,
            target_addrs.len()
        );
        loop {
            tokio::select! {
                accept_result = conn.accept_bi() => {
                    let (send_stream, recv_stream) = match accept_result {
                        Ok(streams) => streams,
                        Err(e) => {
                            log::info!("Connection ended: {}", e);
                            break;
                        }
                    };
                    let target = Arc::clone(&target_addrs);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await {
                            log::warn!("TCP connection error: {}", e);
                        }
                    });
                }
                error = conn.closed() => {
                    log::info!("Connection ended: {}", error);
                    break;
                }
            }
        }
    } else {
        // UDP mode with multi-address fallback
        log::info!(
            "Forwarding UDP traffic to {} ({} address(es) resolved)",
            primary_addr,
            target_addrs.len()
        );
        let (send_stream, recv_stream) = conn
            .accept_bi()
            .await
            .context("Failed to accept stream from receiver")?;

        let udp_socket = Arc::new(
            bind_udp_for_targets(&target_addrs)
                .await
                .context("Failed to bind UDP socket")?,
        );

        tokio::select! {
            result = forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, Arc::clone(&target_addrs)) => {
                result?;
            }
            error = conn.closed() => {
                log::warn!("QUIC connection closed: {}", error);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("Connection closed.");

    Ok(())
}

/// Iroh-manual receiver (receiver-first pattern).
/// Generates offer with source, reads answer, listens for local connections.
pub async fn run_iroh_manual_receiver(
    source: String,
    listen: SocketAddr,
    stun_servers: Vec<String>,
) -> Result<()> {
    let is_tcp = source.starts_with("tcp://");
    let is_udp = source.starts_with("udp://");
    if !is_tcp && !is_udp {
        anyhow::bail!("Invalid source protocol '{}'. Must start with tcp:// or udp://", source);
    }

    log::info!("Iroh Manual Tunnel - Receiver Mode (Receiver-First)");
    log::info!("====================================================");
    log::info!("Requesting source: {}", source);
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(MULTI_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    // Create offer with source
    let offer = IrohManualOffer {
        version: IROH_SIGNAL_VERSION,
        node_id: node_id.to_string(),
        direct_addresses: direct_addrs,
        source: Some(source.clone()),
    };
    log::info!("\nIroh Manual Offer (copy to sender):");
    display_iroh_offer(&offer)?;

    // Read answer from sender
    log::info!("Paste sender answer (include BEGIN/END markers), then press Enter:");
    let answer = read_iroh_answer_from_stdin()?;
    if answer.version != IROH_SIGNAL_VERSION {
        anyhow::bail!(
            "Iroh signaling version mismatch (expected {}, got {})",
            IROH_SIGNAL_VERSION,
            answer.version
        );
    }

    // Add remote peer to discovery
    let remote_id: EndpointId = answer
        .node_id
        .parse()
        .context("Invalid remote NodeId format")?;
    let remote_addrs: Vec<SocketAddr> = answer
        .direct_addresses
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let remote_addr =
        EndpointAddr::new(remote_id).with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    log::info!(
        "Added remote peer: {} ({} addresses)",
        remote_id,
        answer.direct_addresses.len()
    );

    // Race connect vs accept
    let conn = race_connect_accept(&endpoint, remote_id, MULTI_ALPN).await?;
    log::info!("Peer connected: {}", conn.remote_id());

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
                                log::warn!("TCP tunnel error for {}: {}", peer_addr, e);
                            }
                        }
                    });
                }
                error = conn.closed() => {
                    log::info!("QUIC connection closed: {}", error);
                    break;
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
        endpoint.close().await;
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
                if let Err(e) = result {
                    log::warn!("UDP to stream error: {}", e);
                }
            }
            result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
                if let Err(e) = result {
                    log::warn!("Stream to UDP error: {}", e);
                }
            }
            error = conn.closed() => {
                log::warn!("QUIC connection closed: {}", error);
            }
        }

        conn.close(0u32.into(), b"done");
        endpoint.close().await;
        log::info!("UDP receiver stopped.");
    }

    Ok(())
}

// ============================================================================
// Iroh-Manual Helpers
// ============================================================================

/// Create an iroh endpoint for manual mode (no relay, no discovery servers)
async fn create_iroh_manual_endpoint(alpn: &[u8]) -> Result<(Endpoint, Arc<StaticProvider>)> {
    let discovery = Arc::new(StaticProvider::new());

    // Configure transport: 5 minute idle timeout with 15s keepalive.
    // Active connections send pings every 15s, so idle timeout only triggers
    // for truly dead/unresponsive connections.
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(15)));

    let endpoint = Endpoint::empty_builder(RelayMode::Disabled)
        .transport_config(transport_config)
        .discovery(discovery.clone())
        .alpns(vec![alpn.to_vec()])
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    Ok((endpoint, discovery))
}

/// Get direct addresses from endpoint for signaling.
///
/// Returns local network interface addresses and optionally STUN-discovered
/// public addresses. This enables both LAN connections and NAT traversal.
async fn get_direct_addresses(endpoint: &Endpoint, stun_servers: &[String]) -> Vec<String> {
    let bound_sockets = endpoint.bound_sockets();
    let mut addrs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Get the actual bound ports from the endpoint
    let ipv4_port = bound_sockets.iter().find(|a| a.is_ipv4()).map(|a| a.port());
    let ipv6_port = bound_sockets.iter().find(|a| a.is_ipv6()).map(|a| a.port());

    // Step 1: Get STUN-discovered public addresses (for NAT traversal)
    if !stun_servers.is_empty() {
        log::info!("Discovering public addresses via STUN...");
        let mut got_ipv4_stun = false;
        let mut got_ipv6_stun = false;

        for stun in stun_servers {
            let servers = match resolve_stun_addrs(stun).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    log::warn!("Failed to resolve STUN server '{}': {}", stun, e);
                    continue;
                }
            };
            for server in servers {
                // Skip if we already have STUN for this address family
                let is_ipv4 = server.is_ipv4();
                if is_ipv4 && got_ipv4_stun {
                    continue;
                }
                if !is_ipv4 && got_ipv6_stun {
                    continue;
                }

                // Create a wildcard socket matching the STUN server's address family
                let bind_addr: SocketAddr = if is_ipv4 {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };

                let stun_socket = match std::net::UdpSocket::bind(bind_addr) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                stun_socket.set_nonblocking(true).ok();

                let tokio_socket = match UdpSocket::from_std(stun_socket) {
                    Ok(s) => Arc::new(s),
                    Err(_) => continue,
                };

                let client = stunclient::StunClient::new(server);
                match client.query_external_address_async(&tokio_socket).await {
                    Ok(external) => {
                        // Use the iroh endpoint's bound port, not the STUN socket's port
                        // This is a heuristic - many NATs use predictable port mapping
                        let port = if is_ipv4 { ipv4_port } else { ipv6_port };
                        if let Some(port) = port {
                            let addr = SocketAddr::new(external.ip(), port);
                            let addr_str = addr.to_string();
                            if seen.insert(addr_str.clone()) {
                                log::info!("  STUN: {} (via {})", addr, stun);
                                addrs.push(addr_str);
                            }
                        }

                        if is_ipv4 {
                            got_ipv4_stun = true;
                        } else {
                            got_ipv6_stun = true;
                        }
                    }
                    Err(e) => {
                        log::warn!("  STUN query failed for {} ({}): {}", stun, server, e);
                    }
                }
            }
        }
    }

    // Step 2: Get local network interface addresses (for LAN connections)
    log::info!("Local addresses:");
    if let Ok(interfaces) = get_if_addrs::get_if_addrs() {
        for iface in interfaces {
            // Skip loopback interfaces
            if iface.is_loopback() {
                continue;
            }

            let ip = iface.ip();
            let port = if ip.is_ipv4() { ipv4_port } else { ipv6_port };

            if let Some(port) = port {
                let addr = SocketAddr::new(ip, port);
                let addr_str = addr.to_string();
                if seen.insert(addr_str.clone()) {
                    log::info!("  - {}", addr);
                    addrs.push(addr_str);
                }
            }
        }
    }

    addrs
}

/// Race between connecting to remote and accepting from remote.
/// This enables NAT hole punching by having both sides send packets simultaneously.
async fn race_connect_accept(
    endpoint: &Endpoint,
    remote_id: EndpointId,
    alpn: &[u8],
) -> Result<iroh::endpoint::Connection> {
    use tokio::time::timeout;

    let connect_timeout = Duration::from_secs(30);

    log::info!("Racing connect vs accept for NAT hole punching...");

    // Race both operations with a timeout
    tokio::select! {
        result = timeout(connect_timeout, async {
            // Small delay before connecting to give the other side time to start accepting
            tokio::time::sleep(Duration::from_millis(100)).await;
            endpoint.connect(EndpointAddr::new(remote_id), alpn).await
        }) => {
            match result {
                Ok(Ok(conn)) => {
                    log::info!("Connected via outbound connection");
                    Ok(conn)
                }
                Ok(Err(e)) => Err(anyhow::anyhow!("Connect failed: {}", e)),
                Err(_) => Err(anyhow::anyhow!("Connect timeout")),
            }
        }
        result = timeout(connect_timeout, async {
            match endpoint.accept().await {
                Some(incoming) => incoming.await.map_err(|e| anyhow::anyhow!("Accept error: {}", e)),
                None => Err(anyhow::anyhow!("Endpoint closed")),
            }
        }) => {
            match result {
                Ok(Ok(conn)) => {
                    log::info!("Connected via inbound connection");
                    Ok(conn)
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!("Accept timeout")),
            }
        }
    }
}

// ============================================================================
// Iroh Stream Helpers
// ============================================================================

/// Open an iroh QUIC bidirectional stream with retry and exponential backoff.
async fn open_bi_with_retry(
    conn: &iroh::endpoint::Connection,
) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    retry_with_backoff(
        || conn.open_bi(),
        STREAM_OPEN_MAX_ATTEMPTS,
        STREAM_OPEN_BASE_DELAY_MS,
        "open QUIC stream",
    )
    .await
}

/// Bridge a QUIC stream bidirectionally with a TCP stream
async fn bridge_streams(
    mut quic_recv: iroh::endpoint::RecvStream,
    mut quic_send: iroh::endpoint::SendStream,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    tokio::select! {
        result = copy_stream(&mut quic_recv, &mut tcp_write) => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    log::warn!("QUIC->TCP error: {}", e);
                }
            }
        }
        result = copy_stream(&mut tcp_read, &mut quic_send) => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    log::warn!("TCP->QUIC error: {}", e);
                }
            }
        }
    }

    // Signal EOF on the QUIC send stream for graceful shutdown
    let _ = quic_send.finish();

    Ok(())
}

/// Read UDP packets from local socket and forward to iroh stream
async fn forward_udp_to_stream(
    udp_socket: Arc<UdpSocket>,
    mut send_stream: iroh::endpoint::SendStream,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, addr) = udp_socket
            .recv_from(&mut buf)
            .await
            .context("Failed to receive UDP packet")?;

        *peer_addr.lock().await = Some(addr);

        let frame_len = (len as u16).to_be_bytes();
        send_stream
            .write_all(&frame_len)
            .await
            .context("Failed to write frame length")?;
        send_stream
            .write_all(&buf[..len])
            .await
            .context("Failed to write frame payload")?;

        log::debug!("-> Forwarded {} bytes from {}", len, addr);
    }
}

/// Read from iroh stream, forward to UDP target, and send responses back (sender mode).
///
/// Supports multiple target addresses with fallback:
/// - Addresses are tried in Happy Eyeballs order (IPv6 first)
/// - On send error, falls back to the next address
/// - Aggregates errors if all addresses fail
async fn forward_stream_to_udp_sender(
    mut recv_stream: iroh::endpoint::RecvStream,
    mut send_stream: iroh::endpoint::SendStream,
    udp_socket: Arc<UdpSocket>,
    target_addrs: Arc<Vec<SocketAddr>>,
) -> Result<()> {
    if target_addrs.is_empty() {
        anyhow::bail!("No target addresses provided for UDP forwarding");
    }

    // Order addresses for connection attempts
    let ordered_addrs = order_udp_addresses(&target_addrs);

    let udp_clone = udp_socket.clone();
    let response_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, _addr)) = udp_clone.recv_from(&mut buf).await {
            let frame_len = (len as u16).to_be_bytes();
            if send_stream.write_all(&frame_len).await.is_err() {
                break;
            }
            if send_stream.write_all(&buf[..len]).await.is_err() {
                break;
            }
            log::debug!("-> Sent {} bytes back to receiver", len);
        }
    });

    let mut active_addr_idx = 0;
    let mut logged_active = false;

    loop {
        // Track errors for each address for aggregate reporting - fresh for each packet
        let mut errors: Vec<(SocketAddr, std::io::Error)> = Vec::new();
        let mut len_buf = [0u8; 2];
        match recv_stream.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(iroh::endpoint::ReadExactError::FinishedEarly(_)) => {
                // Clean EOF - stream finished at frame boundary
                break;
            }
            Err(e) => {
                log::warn!("Failed to read frame length: {}", e);
                break;
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut buf)
            .await
            .context("Failed to read frame payload")?;

        // Try to send to current address, falling back on error
        let mut sent = false;
        while active_addr_idx < ordered_addrs.len() {
            let target_addr = ordered_addrs[active_addr_idx];

            match udp_socket.send_to(&buf, target_addr).await {
                Ok(_) => {
                    if !logged_active {
                        if active_addr_idx > 0 {
                            log::info!(
                                "UDP fallback: using {} after {} failed address(es)",
                                target_addr,
                                active_addr_idx
                            );
                        }
                        logged_active = true;
                    }
                    log::debug!("<- Forwarded {} bytes to {}", len, target_addr);
                    sent = true;
                    break;
                }
                Err(e) => {
                    log::warn!("UDP send to {} failed: {}", target_addr, e);
                    errors.push((target_addr, e));
                    active_addr_idx += 1;
                    logged_active = false;
                }
            }
        }

        if !sent {
            // All addresses failed
            response_task.abort();
            if errors.len() == 1 {
                let (addr, e) = errors.remove(0);
                anyhow::bail!("Failed to send UDP packet to {}: {}", addr, e);
            } else {
                let error_details: Vec<String> = errors
                    .iter()
                    .map(|(addr, e)| format!("{}: {}", addr, e))
                    .collect();
                anyhow::bail!(
                    "Failed to send UDP packet to any address:\n  {}",
                    error_details.join("\n  ")
                );
            }
        }
    }

    response_task.abort();
    Ok(())
}

/// Read from iroh stream and forward to local UDP client (receiver mode)
async fn forward_stream_to_udp_receiver(
    mut recv_stream: iroh::endpoint::RecvStream,
    udp_socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match recv_stream.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(iroh::endpoint::ReadExactError::FinishedEarly(_)) => {
                // Clean EOF - stream finished at frame boundary
                break;
            }
            Err(e) => {
                log::warn!("Failed to read frame length: {}", e);
                break;
            }
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut buf)
            .await
            .context("Failed to read frame payload")?;

        if let Some(addr) = *client_addr.lock().await {
            udp_socket
                .send_to(&buf, addr)
                .await
                .context("Failed to send UDP packet to client")?;
            log::debug!("<- Forwarded {} bytes to client {}", len, addr);
        } else {
            log::debug!("<- Received {} bytes but no client connected yet", len);
        }
    }

    Ok(())
}
