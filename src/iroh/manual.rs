//! Iroh-manual mode tunnel implementations.
//!
//! This module provides the iroh-manual tunnel mode:
//! - Manual signaling with direct STUN/local addresses (no relay)
//! - Client-first pattern where client initiates with source request

use anyhow::{Context, Result};
use iroh::discovery::static_provider::StaticProvider;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use super::endpoint::MULTI_ALPN;
use super::helpers::{
    forward_stream_to_udp_server, forward_udp_to_stream, handle_tcp_client_connection,
    handle_tcp_server_stream, open_bi_with_retry,
};
use crate::signaling::{
    display_iroh_answer, display_iroh_offer, read_iroh_answer_from_stdin,
    read_iroh_offer_from_stdin, IrohManualAnswer, IrohManualOffer, IROH_SIGNAL_VERSION,
};
use crate::tunnel_common::{
    bind_udp_for_targets, check_source_allowed, extract_addr_from_source, resolve_all_target_addrs,
    resolve_stun_addrs,
};

// Re-export the client-side UDP helper from helpers.rs
use super::helpers::forward_stream_to_udp_client;

// ============================================================================
// Iroh-Manual Mode: Client-Initiated Pattern
// ============================================================================

/// Iroh-manual server (client-first pattern).
/// Reads offer from stdin, validates source, generates answer, handles connections.
pub async fn run_iroh_manual_server(
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    stun_servers: Vec<String>,
) -> Result<()> {
    log::info!("Iroh Manual Tunnel - Server Mode (Client-First)");
    log::info!("================================================");
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(MULTI_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    // Read offer from client (includes source)
    log::info!("Paste client offer (include BEGIN/END markers), then press Enter:");
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
        "Offer missing source field. Client must specify --source (e.g., --source tcp://127.0.0.1:22)",
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
    let addr_str = extract_addr_from_source(source).context("Failed to parse source URL")?;
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
    log::info!("\nIroh Manual Answer (copy to client):");
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
    let parsed_count = remote_addrs.len();
    let original_count = offer.direct_addresses.len();
    let remote_addr =
        EndpointAddr::new(remote_id).with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    if parsed_count < original_count {
        log::warn!(
            "Added remote peer: {} ({}/{} addresses parsed, {} failed)",
            remote_id,
            parsed_count,
            original_count,
            original_count - parsed_count
        );
    } else {
        log::info!("Added remote peer: {} ({} addresses)", remote_id, parsed_count);
    }

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
                        if let Err(e) = handle_tcp_server_stream(send_stream, recv_stream, target).await {
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
            .context("Failed to accept stream from client")?;

        let udp_socket = Arc::new(
            bind_udp_for_targets(&target_addrs)
                .await
                .context("Failed to bind UDP socket")?,
        );

        tokio::select! {
            result = forward_stream_to_udp_server(recv_stream, send_stream, udp_socket, Arc::clone(&target_addrs)) => {
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

/// Iroh-manual client (client-first pattern).
/// Generates offer with source, reads answer, listens for local connections.
pub async fn run_iroh_manual_client(
    source: String,
    listen: SocketAddr,
    stun_servers: Vec<String>,
) -> Result<()> {
    let is_tcp = source.starts_with("tcp://");
    let is_udp = source.starts_with("udp://");
    if !is_tcp && !is_udp {
        anyhow::bail!(
            "Invalid source protocol '{}'. Must start with tcp:// or udp://",
            source
        );
    }

    log::info!("Iroh Manual Tunnel - Client Mode (Client-First)");
    log::info!("================================================");
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
    log::info!("\nIroh Manual Offer (copy to server):");
    display_iroh_offer(&offer)?;

    // Read answer from server
    log::info!("Paste server answer (include BEGIN/END markers), then press Enter:");
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
    let parsed_count = remote_addrs.len();
    let original_count = answer.direct_addresses.len();
    let remote_addr =
        EndpointAddr::new(remote_id).with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    if parsed_count < original_count {
        log::warn!(
            "Added remote peer: {} ({}/{} addresses parsed, {} failed)",
            remote_id,
            parsed_count,
            original_count,
            original_count - parsed_count
        );
    } else {
        log::info!("Added remote peer: {} ({} addresses)", remote_id, parsed_count);
    }

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
                        match handle_tcp_client_connection(conn_clone, tcp_stream, peer_addr, established)
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
        log::info!("TCP client stopped.");
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
            result = forward_stream_to_udp_client(recv_stream, udp_socket, client_addr) => {
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
        log::info!("UDP client stopped.");
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
