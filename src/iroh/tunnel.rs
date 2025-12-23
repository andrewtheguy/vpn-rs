//! Iroh-based tunnel implementations.
//!
//! This module provides tunnel implementations using the Iroh networking stack:
//! - **iroh-default**: Fully automated with Iroh relays and discovery
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
    validate_relay_only, TCP_ALPN, UDP_ALPN,
};
use crate::signaling::{
    display_iroh_answer, display_iroh_offer, read_iroh_answer_from_stdin, read_iroh_offer_from_stdin,
    IrohManualAnswer, IrohManualOffer, IROH_SIGNAL_VERSION,
};
use crate::tunnel_common::{
    copy_stream, resolve_stun_addrs, resolve_target_addr, retry_with_backoff,
    STREAM_OPEN_BASE_DELAY_MS, STREAM_OPEN_MAX_ATTEMPTS,
};

// ============================================================================
// Iroh-Default Mode: UDP Tunnel
// ============================================================================

pub async fn run_udp_sender(
    target: String,
    secret: Option<SecretKey>,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    log::info!("UDP Tunnel - Sender Mode");
    log::info!("========================");
    log::info!("Creating iroh endpoint...");

    let endpoint =
        create_sender_endpoint(&relay_urls, relay_only, secret, dns_server.as_deref(), UDP_ALPN)
            .await?;

    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    log::info!("\nEndpointId: {}", endpoint_id);
    log::info!("\nOn the receiver side, run:");
    log::info!(
        "  tunnel-rs receiver --node-id {} --target udp://0.0.0.0:{}\n",
        endpoint_id, target_port
    );
    log::info!("Waiting for receiver to connect...");

    let conn = endpoint
        .accept()
        .await
        .context("No incoming connection")?
        .await
        .context("Failed to accept connection")?;

    let remote_id = conn.remote_id();
    log::info!("Receiver connected from: {}", remote_id);

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

    forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr).await?;

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("Connection closed.");

    Ok(())
}

pub async fn run_udp_receiver(
    node_id: String,
    listen: String,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let listen_addr: SocketAddr = listen.parse().context(
        "Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820",
    )?;

    let sender_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    log::info!("UDP Tunnel - Receiver Mode");
    log::info!("==========================");
    log::info!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only, dns_server.as_deref()).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, UDP_ALPN).await?;

    log::info!("Connected to sender!");
    print_connection_type(&endpoint, conn.remote_id());

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
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("Connection closed.");

    Ok(())
}

// ============================================================================
// Iroh-Default Mode: TCP Tunnel
// ============================================================================

pub async fn run_tcp_sender(
    target: String,
    secret: Option<SecretKey>,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    log::info!("TCP Tunnel - Sender Mode");
    log::info!("========================");
    log::info!("Creating iroh endpoint...");

    let endpoint =
        create_sender_endpoint(&relay_urls, relay_only, secret, dns_server.as_deref(), TCP_ALPN)
            .await?;

    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    log::info!("\nEndpointId: {}", endpoint_id);
    log::info!("\nOn the receiver side, run:");
    log::info!(
        "  tunnel-rs receiver --node-id {} --target tcp://127.0.0.1:{}\n",
        endpoint_id, target_port
    );
    log::info!("Waiting for receiver to connect...");

    loop {
        let conn = match endpoint.accept().await {
            Some(incoming) => match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    log::warn!("Failed to accept connection: {}", e);
                    continue;
                }
            },
            None => {
                log::info!("Endpoint closed");
                break;
            }
        };

        let remote_id = conn.remote_id();
        log::info!("Receiver connected from: {}", remote_id);
        log::info!("Forwarding TCP connections to {}", target_addr);

        let target = target_addr;
        tokio::spawn(async move {
            loop {
                let (send_stream, recv_stream) = match conn.accept_bi().await {
                    Ok(streams) => streams,
                    Err(e) => {
                        log::info!("Receiver disconnected: {}", e);
                        break;
                    }
                };

                log::info!("New TCP connection request received");

                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await
                    {
                        log::warn!("TCP connection error: {}", e);
                    }
                });
            }

            conn.close(0u32.into(), b"done");
            log::info!("Receiver connection closed.");
        });

        log::info!("Waiting for next receiver to connect...");
    }

    endpoint.close().await;
    Ok(())
}

async fn handle_tcp_sender_stream(
    send_stream: iroh::endpoint::SendStream,
    recv_stream: iroh::endpoint::RecvStream,
    target_addr: SocketAddr,
) -> Result<()> {
    let tcp_stream = TcpStream::connect(target_addr)
        .await
        .context("Failed to connect to target TCP service")?;

    log::info!("-> Connected to target {}", target_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    log::info!("<- TCP connection to {} closed", target_addr);
    Ok(())
}

pub async fn run_tcp_receiver(
    node_id: String,
    listen: String,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    let sender_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    log::info!("TCP Tunnel - Receiver Mode");
    log::info!("==========================");
    log::info!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only, dns_server.as_deref()).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, TCP_ALPN).await?;

    print_connection_type(&endpoint, conn.remote_id());

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

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("TCP receiver stopped.");
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
// Iroh-Manual Mode: TCP Tunnel
// ============================================================================

pub async fn run_iroh_manual_tcp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    log::info!("Iroh Manual TCP Tunnel - Sender Mode");
    log::info!("=====================================");
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(TCP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    let conn =
        negotiate_manual_sender(&endpoint, &discovery, node_id, direct_addrs, TCP_ALPN).await?;

    log::info!("Peer connected: {}", conn.remote_id());
    log::info!("Forwarding TCP connections to {}", target_addr);

    loop {
        let (send_stream, recv_stream) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                log::info!("Connection ended: {}", e);
                break;
            }
        };

        let target = target_addr;
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await {
                log::warn!("TCP connection error: {}", e);
            }
        });
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("Connection closed.");

    Ok(())
}

pub async fn run_iroh_manual_tcp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    log::info!("Iroh Manual TCP Tunnel - Receiver Mode");
    log::info!("======================================");
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(TCP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    let conn =
        negotiate_manual_receiver(&endpoint, &discovery, node_id, direct_addrs, TCP_ALPN).await?;

    log::info!("Peer connected: {}", conn.remote_id());

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

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("TCP receiver stopped.");
    Ok(())
}

// ============================================================================
// Iroh-Manual Mode: UDP Tunnel
// ============================================================================

pub async fn run_iroh_manual_udp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    log::info!("Iroh Manual UDP Tunnel - Sender Mode");
    log::info!("=====================================");
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(UDP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    let conn =
        negotiate_manual_sender(&endpoint, &discovery, node_id, direct_addrs, UDP_ALPN).await?;

    log::info!("Peer connected: {}", conn.remote_id());

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

    forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr).await?;

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("Connection closed.");

    Ok(())
}

pub async fn run_iroh_manual_udp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen.parse().context(
        "Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820",
    )?;

    log::info!("Iroh Manual UDP Tunnel - Receiver Mode");
    log::info!("======================================");
    log::info!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(UDP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    let conn =
        negotiate_manual_receiver(&endpoint, &discovery, node_id, direct_addrs, UDP_ALPN).await?;

    log::info!("Peer connected: {}", conn.remote_id());

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
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    log::info!("Connection closed.");

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

/// Complete manual signaling handshake for sender mode.
///
/// Creates and displays offer, reads answer, validates version,
/// adds peer to discovery, and establishes connection via race connect/accept.
async fn negotiate_manual_sender(
    endpoint: &Endpoint,
    discovery: &Arc<StaticProvider>,
    node_id: EndpointId,
    direct_addrs: Vec<String>,
    alpn: &[u8],
) -> Result<iroh::endpoint::Connection> {
    let offer = IrohManualOffer {
        version: IROH_SIGNAL_VERSION,
        node_id: node_id.to_string(),
        direct_addresses: direct_addrs,
    };

    log::info!("\nIroh Manual Offer (copy to receiver):");
    display_iroh_offer(&offer)?;

    log::info!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
    let answer = read_iroh_answer_from_stdin()?;
    if answer.version != IROH_SIGNAL_VERSION {
        anyhow::bail!(
            "Iroh signaling version mismatch (expected {}, got {})",
            IROH_SIGNAL_VERSION,
            answer.version
        );
    }

    // Parse and add remote peer info
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

    // Race connect vs accept for NAT hole punching
    race_connect_accept(endpoint, remote_id, alpn).await
}

/// Complete manual signaling handshake for receiver mode.
///
/// Reads offer, validates version, creates and displays answer,
/// adds peer to discovery, and establishes connection via race connect/accept.
async fn negotiate_manual_receiver(
    endpoint: &Endpoint,
    discovery: &Arc<StaticProvider>,
    node_id: EndpointId,
    direct_addrs: Vec<String>,
    alpn: &[u8],
) -> Result<iroh::endpoint::Connection> {
    log::info!("Paste sender offer (include BEGIN/END markers), then press Enter:");
    let offer = read_iroh_offer_from_stdin()?;
    if offer.version != IROH_SIGNAL_VERSION {
        anyhow::bail!(
            "Iroh signaling version mismatch (expected {}, got {})",
            IROH_SIGNAL_VERSION,
            offer.version
        );
    }

    let answer = IrohManualAnswer {
        version: IROH_SIGNAL_VERSION,
        node_id: node_id.to_string(),
        direct_addresses: direct_addrs,
    };

    log::info!("\nIroh Manual Answer (copy to sender):");
    display_iroh_answer(&answer)?;

    // Parse and add remote peer info
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

    // Race connect vs accept for NAT hole punching
    race_connect_accept(endpoint, remote_id, alpn).await
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

/// Read from iroh stream, forward to UDP target, and send responses back (sender mode)
async fn forward_stream_to_udp_sender(
    mut recv_stream: iroh::endpoint::RecvStream,
    mut send_stream: iroh::endpoint::SendStream,
    udp_socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
) -> Result<()> {
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

        udp_socket
            .send_to(&buf, target_addr)
            .await
            .context("Failed to send UDP packet")?;

        log::debug!("<- Forwarded {} bytes to {}", len, target_addr);
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
