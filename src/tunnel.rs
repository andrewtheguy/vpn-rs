//! TCP and UDP tunnel implementations.

use anyhow::{Context, Result};
use iroh::discovery::static_provider::StaticProvider;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::task::JoinSet;

use crate::endpoint::{
    connect_to_sender, create_receiver_endpoint, create_sender_endpoint, print_connection_type,
    validate_relay_only, TCP_ALPN, UDP_ALPN,
};
use crate::manual::ice::{IceEndpoint, IceRole};
use crate::manual::nostr_signaling::NostrSignaling;
use crate::manual::quic;
use crate::manual::signaling::{
    display_answer, display_iroh_answer, display_iroh_offer, display_offer,
    read_answer_from_stdin, read_iroh_answer_from_stdin, read_iroh_offer_from_stdin,
    read_offer_from_stdin, IrohManualAnswer, IrohManualOffer, ManualAnswer, ManualOffer,
    ManualReject, ManualRequest, IROH_SIGNAL_VERSION, MANUAL_SIGNAL_VERSION,
};

/// Timeout for QUIC connection (matches webrtc crate's 180 second connection timeout)
const QUIC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

/// Maximum age for accepting incoming requests (seconds).
/// Requests older than this are considered stale and ignored.
const MAX_REQUEST_AGE_SECS: u64 = 10;

async fn resolve_target_addr(target: &str) -> Result<SocketAddr> {
    let mut addrs = lookup_host(target)
        .await
        .with_context(|| format!("Failed to resolve '{}'", target))?;
    addrs.next().context("No addresses found for host")
}

/// Generate a random session ID for nostr signaling.
fn generate_session_id() -> String {
    use rand::Rng;
    let random_bytes: [u8; 8] = rand::rng().random();
    hex::encode(random_bytes)
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Publish offer and wait for answer with periodic re-publishing.
///
/// This helper implements the nostr signaling offer/answer exchange with:
/// - Periodic re-publishing of the offer with exponential backoff
/// - Overall timeout of `max_wait_secs`
/// - Session ID validation to filter stale answers
async fn publish_offer_and_wait_for_answer(
    signaling: &NostrSignaling,
    offer: &ManualOffer,
    session_id: &str,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<ManualAnswer> {
    let start_time = std::time::Instant::now();

    // Exponential backoff: start at base interval, double each time, cap at 60s
    let mut current_interval = republish_interval_secs;
    const MAX_INTERVAL: u64 = 60;

    signaling.publish_offer(offer).await?;
    println!(
        "Waiting for answer (re-publishing with backoff, starting {}s, max {}s)...",
        republish_interval_secs, max_wait_secs
    );

    loop {
        if let Some(ans) = signaling
            .try_wait_for_answer_timeout(current_interval)
            .await
        {
            // Verify session ID matches
            if ans.session_id.as_ref() == Some(&session_id.to_string()) {
                return Ok(ans);
            }
            println!("Ignoring answer with mismatched session ID (stale event)");
        }

        // Check overall timeout
        if start_time.elapsed().as_secs() >= max_wait_secs {
            anyhow::bail!(
                "Timeout waiting for answer from peer ({}s)",
                max_wait_secs
            );
        }

        // Exponential backoff
        let next_interval = (current_interval * 2).min(MAX_INTERVAL);

        // Re-publish offer with backoff
        println!("Re-publishing offer (next wait: {}s)...", next_interval);
        signaling.publish_offer(offer).await?;

        current_interval = next_interval;
    }
}

/// Publish request and wait for offer with periodic re-publishing.
///
/// This helper implements the nostr signaling request/offer exchange with:
/// - Periodic re-publishing of the request with exponential backoff
/// - Overall timeout of `max_wait_secs`
/// - Session ID validation to filter stale offers
async fn publish_request_and_wait_for_offer(
    signaling: &NostrSignaling,
    request: &ManualRequest,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<ManualOffer> {
    let start_time = std::time::Instant::now();
    let session_id = &request.session_id;

    // Exponential backoff: start at base interval, double each time, cap at 60s
    let mut current_interval = republish_interval_secs;
    const MAX_INTERVAL: u64 = 60;

    signaling.publish_request(request).await?;
    println!(
        "Waiting for offer (re-publishing with backoff, starting {}s, max {}s)...",
        republish_interval_secs, max_wait_secs
    );

    loop {
        if let Some(offer) = signaling
            .try_wait_for_offer_timeout(current_interval)
            .await
        {
            // Verify session ID matches
            if offer.session_id.as_ref() == Some(session_id) {
                return Ok(offer);
            }
            println!("Ignoring offer with mismatched session ID (stale event)");
        }

        // Check for rejection
        if let Some(reject) = signaling.try_check_for_rejection().await {
            if reject.session_id == *session_id {
                anyhow::bail!("Session rejected by sender: {}", reject.reason);
            }
        }

        // Check overall timeout
        if start_time.elapsed().as_secs() >= max_wait_secs {
            anyhow::bail!(
                "Timeout waiting for offer from peer ({}s)",
                max_wait_secs
            );
        }

        // Exponential backoff
        let next_interval = (current_interval * 2).min(MAX_INTERVAL);

        // Re-publish request with backoff
        println!("Re-publishing request (next wait: {}s)...", next_interval);
        signaling.publish_request(request).await?;

        current_interval = next_interval;
    }
}

// ============================================================================
// UDP Tunnel Implementation
// ============================================================================

pub async fn run_udp_sender(
    target: String,
    secret_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("UDP Tunnel - Sender Mode");
    println!("========================");
    println!("Creating iroh endpoint...");

    let endpoint =
        create_sender_endpoint(&relay_urls, relay_only, secret_file.as_ref(), dns_server.as_deref(), UDP_ALPN).await?;

    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    println!("\nEndpointId: {}", endpoint_id);
    println!("\nOn the receiver side, run:");
    println!(
        "  tunnel-rs receiver --node-id {} --target udp://0.0.0.0:{}\n",
        endpoint_id, target_port
    );
    println!("Waiting for receiver to connect...");

    let conn = endpoint
        .accept()
        .await
        .context("No incoming connection")?
        .await
        .context("Failed to accept connection")?;

    let remote_id = conn.remote_id();
    println!("Receiver connected from: {}", remote_id);

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    println!("Forwarding UDP traffic to {}", target_addr);

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
    println!("Connection closed.");

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

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    let sender_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    println!("UDP Tunnel - Receiver Mode");
    println!("==========================");
    println!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only, dns_server.as_deref()).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, UDP_ALPN).await?;

    println!("Connected to sender!");
    print_connection_type(&endpoint, conn.remote_id());

    let (send_stream, recv_stream) = open_bi_with_retry_iroh(&conn).await?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                eprintln!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                eprintln!("Stream to UDP error: {}", e);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    println!("Connection closed.");

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

        println!("-> Forwarded {} bytes from {}", len, addr);
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
            println!("-> Sent {} bytes back to receiver", len);
        }
    });

    loop {
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            break;
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

        println!("<- Forwarded {} bytes to {}", len, target_addr);
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
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            break;
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
            println!("<- Forwarded {} bytes to client {}", len, addr);
        } else {
            println!("<- Received {} bytes but no client connected yet", len);
        }
    }

    Ok(())
}

// ============================================================================
// TCP Tunnel Implementation
// ============================================================================

pub async fn run_tcp_sender(
    target: String,
    secret_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    relay_only: bool,
    dns_server: Option<String>,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("TCP Tunnel - Sender Mode");
    println!("========================");
    println!("Creating iroh endpoint...");

    let endpoint =
        create_sender_endpoint(&relay_urls, relay_only, secret_file.as_ref(), dns_server.as_deref(), TCP_ALPN).await?;

    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    println!("\nEndpointId: {}", endpoint_id);
    println!("\nOn the receiver side, run:");
    println!(
        "  tunnel-rs receiver --node-id {} --target tcp://127.0.0.1:{}\n",
        endpoint_id, target_port
    );
    println!("Waiting for receiver to connect...");

    loop {
        let conn = match endpoint.accept().await {
            Some(incoming) => match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    continue;
                }
            },
            None => {
                println!("Endpoint closed");
                break;
            }
        };

        let remote_id = conn.remote_id();
        println!("Receiver connected from: {}", remote_id);
        println!("Forwarding TCP connections to {}", target_addr);

        let target = target_addr;
        tokio::spawn(async move {
            loop {
                let (send_stream, recv_stream) = match conn.accept_bi().await {
                    Ok(streams) => streams,
                    Err(e) => {
                        println!("Receiver disconnected: {}", e);
                        break;
                    }
                };

                println!("New TCP connection request received");

                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await
                    {
                        eprintln!("TCP connection error: {}", e);
                    }
                });
            }

            conn.close(0u32.into(), b"done");
            println!("Receiver connection closed.");
        });

        println!("Waiting for next receiver to connect...");
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

    println!("-> Connected to target {}", target_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    println!("<- TCP connection to {} closed", target_addr);
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

    println!("TCP Tunnel - Receiver Mode");
    println!("==========================");
    println!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only, dns_server.as_deref()).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, TCP_ALPN).await?;

    print_connection_type(&endpoint, conn.remote_id());

    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    println!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };

        println!("New local connection from {}", peer_addr);

        let conn_clone = conn.clone();
        let established = tunnel_established.clone();

        tokio::spawn(async move {
            match handle_tcp_receiver_connection(conn_clone, tcp_stream, peer_addr, established).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("TCP tunnel error for {}: {}", peer_addr, e);
                }
            }
        });
    }
}

// ============================================================================
// Manual TCP Tunnel Implementation (ICE + QUIC)
// ============================================================================

pub async fn run_manual_tcp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("Manual TCP Tunnel - Sender Mode");
    println!("================================");

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

    println!("\nManual Offer (copy to receiver):");
    display_offer(&offer)?;

    println!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
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
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;
    println!("Waiting for receiver QUIC connection (timeout: {:?})...", QUIC_CONNECTION_TIMEOUT);

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;
    println!("Receiver connected over QUIC.");

    loop {
        let (send_stream, recv_stream) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                println!("Receiver disconnected: {}", e);
                break;
            }
        };

        println!("New TCP connection request received");
        let target = target_addr;
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_sender_stream_quic(send_stream, recv_stream, target).await {
                eprintln!("TCP connection error: {}", e);
            }
        });
    }

    Ok(())
}

pub async fn run_manual_tcp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    println!("Manual TCP Tunnel - Receiver Mode");
    println!("=================================");

    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    println!("Paste sender offer (include BEGIN/END markers), then press Enter:");
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

    println!("\nManual Answer (copy to sender):");
    display_answer(&answer)?;

    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
    println!("Connecting to sender via QUIC (timeout: {:?})...", QUIC_CONNECTION_TIMEOUT);
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to sender")?;
    println!("Connected to sender over QUIC.");

    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    println!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };

        println!("New local connection from {}", peer_addr);
        let conn_clone = conn.clone();
        let established = tunnel_established.clone();

        tokio::spawn(async move {
            match handle_tcp_receiver_connection_quic(conn_clone, tcp_stream, peer_addr, established).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("TCP tunnel error for {}: {}", peer_addr, e);
                }
            }
        });
    }
}

// ============================================================================
// Manual UDP Tunnel Implementation (ICE + QUIC)
// ============================================================================

pub async fn run_manual_udp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("Manual UDP Tunnel - Sender Mode");
    println!("================================");

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

    println!("\nManual Offer (copy to receiver):");
    display_offer(&offer)?;

    println!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
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
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;
    println!("Waiting for receiver QUIC connection (timeout: {:?})...", QUIC_CONNECTION_TIMEOUT);

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;
    println!("Receiver connected over QUIC.");

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    println!("Forwarding UDP traffic to {}", target_addr);

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

    forward_stream_to_udp_sender_quic(recv_stream, send_stream, udp_socket, target_addr).await?;

    conn.close(0u32.into(), b"done");
    println!("Connection closed.");

    Ok(())
}

pub async fn run_manual_udp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    println!("Manual UDP Tunnel - Receiver Mode");
    println!("=================================");

    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    println!("Paste sender offer (include BEGIN/END markers), then press Enter:");
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

    println!("\nManual Answer (copy to sender):");
    display_answer(&answer)?;

    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
    println!("Connecting to sender via QUIC (timeout: {:?})...", QUIC_CONNECTION_TIMEOUT);
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to sender")?;
    println!("Connected to sender over QUIC.");

    let (send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream_quic(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                eprintln!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_receiver_quic(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                eprintln!("Stream to UDP error: {}", e);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    println!("Connection closed.");

    Ok(())
}

// ============================================================================
// Nostr Sender Loop (shared session management for TCP/UDP)
// ============================================================================

/// Session handler function signature for nostr sender modes.
/// Takes signaling client, request, target address, STUN servers, and timing params.
type SessionHandler = fn(
    Arc<NostrSignaling>,
    ManualRequest,
    SocketAddr,
    Vec<String>,
    u64,
    u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

/// Generic nostr sender loop that handles session management for both TCP and UDP.
///
/// This function encapsulates the common logic for:
/// - Waiting for incoming session requests
/// - Checking session limits and rejecting when at capacity
/// - Spawning session handler tasks
/// - Tracking active sessions and cleaning up completed ones
async fn run_nostr_sender_loop(
    protocol_name: &str,
    target_addr: SocketAddr,
    signaling: Arc<NostrSignaling>,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
    max_sessions: usize,
    session_handler: SessionHandler,
) -> Result<()> {
    // Session tracking
    let active_sessions = Arc::new(AtomicUsize::new(0));
    let mut session_tasks: JoinSet<Result<()>> = JoinSet::new();

    let limit_str = if max_sessions == 0 {
        "unlimited".to_string()
    } else {
        max_sessions.to_string()
    };
    println!("Waiting for tunnel requests (max sessions: {})...", limit_str);

    loop {
        // Clean up completed tasks without blocking
        while let Some(result) = session_tasks.try_join_next() {
            if let Err(e) = result {
                eprintln!("Session task panicked: {:?}", e);
            }
        }

        // Wait for fresh request from receiver (no timeout for multi-session mode)
        let request = match signaling.wait_for_fresh_request_forever(MAX_REQUEST_AGE_SECS).await {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Error waiting for request: {}", e);
                // Brief delay before retrying
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if request.version != MANUAL_SIGNAL_VERSION {
            eprintln!(
                "Ignoring request with version mismatch (expected {}, got {})",
                MANUAL_SIGNAL_VERSION, request.version
            );
            continue;
        }

        let session_id = request.session_id.clone();
        println!("Received {} request for session {}", protocol_name, &session_id[..8.min(session_id.len())]);

        // Check session limit - if at capacity, wait briefly for dead sessions to be cleaned up
        if max_sessions > 0 && active_sessions.load(Ordering::Relaxed) >= max_sessions {
            println!(
                "At capacity ({}/{}), checking for dead sessions...",
                active_sessions.load(Ordering::Relaxed),
                max_sessions
            );

            // Wait briefly for any dying connections to complete, then clean up
            tokio::time::sleep(Duration::from_millis(100)).await;
            while let Some(result) = session_tasks.try_join_next() {
                if let Err(e) = result {
                    eprintln!("Session task panicked: {:?}", e);
                }
            }

            // Recheck after cleanup
            if active_sessions.load(Ordering::Relaxed) >= max_sessions {
                println!(
                    "Rejecting session {} - at capacity ({}/{})",
                    &session_id[..8.min(session_id.len())],
                    active_sessions.load(Ordering::Relaxed),
                    max_sessions
                );

                // Send explicit rejection to receiver
                let reject = ManualReject {
                    version: MANUAL_SIGNAL_VERSION,
                    session_id: session_id.clone(),
                    reason: format!("Sender at capacity ({}/{})", max_sessions, max_sessions),
                };
                if let Err(e) = signaling.publish_reject(&reject).await {
                    eprintln!("Failed to send rejection: {}", e);
                } else {
                    println!("Sent rejection for session {}", &session_id[..8.min(session_id.len())]);
                }
                continue;
            }
            println!("Slot freed up, accepting session");
        }

        // Spawn session handler
        let current = active_sessions.fetch_add(1, Ordering::Relaxed) + 1;
        println!("Active sessions: {}/{}", current, limit_str);

        let sig = signaling.clone();
        let active = active_sessions.clone();
        let stun = stun_servers.clone();
        let limit_str_clone = limit_str.clone();

        session_tasks.spawn(async move {
            let result = session_handler(
                sig,
                request,
                target_addr,
                stun,
                republish_interval_secs,
                max_wait_secs,
            )
            .await;

            let remaining = active.fetch_sub(1, Ordering::Relaxed) - 1;
            println!("Session ended. Active sessions: {}/{}", remaining, limit_str_clone);

            if let Err(ref e) = result {
                eprintln!("Session error: {}", e);
            }
            result
        });
    }
}

// ============================================================================
// Nostr TCP Tunnel Implementation (ICE + QUIC with Nostr signaling)
// ============================================================================

/// Wrapper function for handle_nostr_tcp_session_impl that returns a boxed future.
fn handle_nostr_tcp_session(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    target_addr: SocketAddr,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    Box::pin(handle_nostr_tcp_session_impl(
        signaling,
        request,
        target_addr,
        stun_servers,
        republish_interval_secs,
        max_wait_secs,
    ))
}

/// Handle a single nostr TCP session from request to connection closure.
async fn handle_nostr_tcp_session_impl(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    target_addr: SocketAddr,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    let session_id = request.session_id.clone();
    let short_id = &session_id[..8.min(session_id.len())];
    println!("[{}] Starting TCP session...", short_id);

    // Gather ICE candidates
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();
    println!("[{}] Gathered {} ICE candidates", short_id, local_candidates.len());

    let quic_identity = quic::generate_server_identity()?;

    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: quic_identity.fingerprint.clone(),
        session_id: Some(session_id.clone()),
    };

    // Publish offer and wait for answer
    let answer = publish_offer_and_wait_for_answer(
        &signaling,
        &offer,
        &session_id,
        republish_interval_secs,
        max_wait_secs,
    )
    .await?;

    if answer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "[{}] Manual signaling version mismatch (expected {}, got {})",
            short_id,
            MANUAL_SIGNAL_VERSION,
            answer.version
        );
    }

    // Use receiver's ICE credentials from the REQUEST
    let remote_creds = str0m::IceCreds {
        ufrag: request.ice_ufrag,
        pass: request.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, request.candidates)
        .await?;
    println!("[{}] ICE connection established", short_id);

    // Spawn the ICE keeper
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;
    println!("[{}] QUIC connected, forwarding to {}", short_id, target_addr);

    loop {
        let (send_stream, recv_stream) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                println!("[{}] Session ended: {}", short_id, e);
                break;
            }
        };

        let target = target_addr;
        let sid = short_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_sender_stream_quic(send_stream, recv_stream, target).await {
                eprintln!("[{}] TCP connection error: {}", sid, e);
            }
        });
    }

    Ok(())
}

pub async fn run_nostr_tcp_sender(
    target: String,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
    max_sessions: usize,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("Nostr TCP Tunnel - Sender Mode (Multi-Session)");
    println!("===============================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() { None } else { Some(relays) };
    let signaling = Arc::new(NostrSignaling::new(&nsec, &peer_npub, relay_list).await?);

    println!("Your pubkey: {}", signaling.public_key_bech32());
    println!("Transfer ID: {}", signaling.transfer_id());
    println!("Relays: {:?}", signaling.relay_urls());

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Run the session management loop
    run_nostr_sender_loop(
        "TCP",
        target_addr,
        signaling,
        stun_servers,
        republish_interval_secs,
        max_wait_secs,
        max_sessions,
        handle_nostr_tcp_session,
    )
    .await
}

pub async fn run_nostr_tcp_receiver(
    listen: String,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    println!("Nostr TCP Tunnel - Receiver Mode");
    println!("================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() { None } else { Some(relays) };
    let signaling = NostrSignaling::new(&nsec, &peer_npub, relay_list).await?;

    println!("Your pubkey: {}", signaling.public_key_bech32());
    println!("Transfer ID: {}", signaling.transfer_id());
    println!("Relays: {:?}", signaling.relay_urls());

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Generate session ID to filter stale events
    let session_id = generate_session_id();
    println!("Session ID: {}", session_id);

    // Gather ICE candidates first (before sending request)
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    // Create and publish request to initiate session
    let request = ManualRequest {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates.clone(),
        session_id: session_id.clone(),
        timestamp: current_timestamp(),
    };

    // Publish request and wait for offer (re-publish periodically)
    let offer = publish_request_and_wait_for_offer(
        &signaling,
        &request,
        republish_interval_secs,
        max_wait_secs,
    )
    .await?;

    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    // Create and publish answer (echo session_id)
    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: Some(session_id),
    };

    // Publish answer once - sender already has our ICE credentials from the request,
    // so we can proceed to ICE immediately after publishing
    signaling.publish_answer(&answer).await?;

    // Brief delay to allow answer to propagate to relays
    println!("Waiting briefly for answer to propagate...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Disconnect from Nostr (signaling complete)
    signaling.disconnect().await;

    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
    println!(
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
    println!("Connected to sender over QUIC.");

    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    println!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };

        println!("New local connection from {}", peer_addr);
        let conn_clone = conn.clone();
        let established = tunnel_established.clone();

        tokio::spawn(async move {
            match handle_tcp_receiver_connection_quic(conn_clone, tcp_stream, peer_addr, established)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("TCP tunnel error for {}: {}", peer_addr, e);
                }
            }
        });
    }
}

// ============================================================================
// Nostr UDP Tunnel Implementation (ICE + QUIC with Nostr signaling)
// ============================================================================

/// Wrapper function for handle_nostr_udp_session_impl that returns a boxed future.
fn handle_nostr_udp_session(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    target_addr: SocketAddr,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    Box::pin(handle_nostr_udp_session_impl(
        signaling,
        request,
        target_addr,
        stun_servers,
        republish_interval_secs,
        max_wait_secs,
    ))
}

/// Handle a single nostr UDP session from request to connection closure.
async fn handle_nostr_udp_session_impl(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    target_addr: SocketAddr,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    let session_id = request.session_id.clone();
    let short_id = &session_id[..8.min(session_id.len())];
    println!("[{}] Starting UDP session...", short_id);

    // Gather ICE candidates
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();
    println!("[{}] Gathered {} ICE candidates", short_id, local_candidates.len());

    let quic_identity = quic::generate_server_identity()?;

    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: quic_identity.fingerprint.clone(),
        session_id: Some(session_id.clone()),
    };

    // Publish offer and wait for answer
    let answer = publish_offer_and_wait_for_answer(
        &signaling,
        &offer,
        &session_id,
        republish_interval_secs,
        max_wait_secs,
    )
    .await?;

    if answer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "[{}] Manual signaling version mismatch (expected {}, got {})",
            short_id,
            MANUAL_SIGNAL_VERSION,
            answer.version
        );
    }

    // Use receiver's ICE credentials from the REQUEST
    let remote_creds = str0m::IceCreds {
        ufrag: request.ice_ufrag,
        pass: request.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, request.candidates)
        .await?;
    println!("[{}] ICE connection established", short_id);

    // Spawn the ICE keeper
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;
    println!("[{}] QUIC connected", short_id);

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    println!("[{}] Forwarding UDP traffic to {}", short_id, target_addr);

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

    forward_stream_to_udp_sender_quic(recv_stream, send_stream, udp_socket, target_addr).await?;

    conn.close(0u32.into(), b"done");
    println!("[{}] UDP session closed", short_id);

    Ok(())
}

pub async fn run_nostr_udp_sender(
    target: String,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
    max_sessions: usize,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("Nostr UDP Tunnel - Sender Mode (Multi-Session)");
    println!("===============================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() { None } else { Some(relays) };
    let signaling = Arc::new(NostrSignaling::new(&nsec, &peer_npub, relay_list).await?);

    println!("Your pubkey: {}", signaling.public_key_bech32());
    println!("Transfer ID: {}", signaling.transfer_id());
    println!("Relays: {:?}", signaling.relay_urls());

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Run the session management loop
    run_nostr_sender_loop(
        "UDP",
        target_addr,
        signaling,
        stun_servers,
        republish_interval_secs,
        max_wait_secs,
        max_sessions,
        handle_nostr_udp_session,
    )
    .await
}

pub async fn run_nostr_udp_receiver(
    listen: String,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    println!("Nostr UDP Tunnel - Receiver Mode");
    println!("================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() { None } else { Some(relays) };
    let signaling = NostrSignaling::new(&nsec, &peer_npub, relay_list).await?;

    println!("Your pubkey: {}", signaling.public_key_bech32());
    println!("Transfer ID: {}", signaling.transfer_id());
    println!("Relays: {:?}", signaling.relay_urls());

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Generate session ID to filter stale events
    let session_id = generate_session_id();
    println!("Session ID: {}", session_id);

    // Gather ICE candidates first (before sending request)
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    // Create and publish request to initiate session
    let request = ManualRequest {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates.clone(),
        session_id: session_id.clone(),
        timestamp: current_timestamp(),
    };

    // Publish request and wait for offer (re-publish periodically)
    let offer = publish_request_and_wait_for_offer(
        &signaling,
        &request,
        republish_interval_secs,
        max_wait_secs,
    )
    .await?;

    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    // Create and publish answer (echo session_id)
    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: Some(session_id),
    };

    // Publish answer once - sender already has our ICE credentials from the request,
    // so we can proceed to ICE immediately after publishing
    signaling.publish_answer(&answer).await?;

    // Brief delay to allow answer to propagate to relays
    println!("Waiting briefly for answer to propagate...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Disconnect from Nostr (signaling complete)
    signaling.disconnect().await;

    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
    println!(
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
    println!("Connected to sender over QUIC.");

    let (send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream_quic(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                eprintln!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_receiver_quic(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                eprintln!("Stream to UDP error: {}", e);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    println!("Connection closed.");

    Ok(())
}

async fn handle_tcp_sender_stream_quic(
    send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    target_addr: SocketAddr,
) -> Result<()> {
    // Read and discard the stream marker byte sent by the receiver
    let mut marker = [0u8; 1];
    recv_stream.read_exact(&mut marker).await.context("Failed to read stream marker")?;

    let tcp_stream = TcpStream::connect(target_addr)
        .await
        .context("Failed to connect to target TCP service")?;

    println!("-> Connected to target {}", target_addr);
    bridge_quinn_streams(recv_stream, send_stream, tcp_stream).await?;
    println!("<- TCP connection to {} closed", target_addr);
    Ok(())
}

/// Marker byte sent when opening a new QUIC stream to ensure
/// the STREAM frame is immediately sent to the peer.
const STREAM_OPEN_MARKER: u8 = 0x00;

/// Maximum retry attempts for opening QUIC streams
const STREAM_OPEN_MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (doubles each retry)
const STREAM_OPEN_BASE_DELAY_MS: u64 = 100;

/// Open a QUIC bidirectional stream with retry and exponential backoff.
/// Returns the stream pair on success, or an error after all retries are exhausted.
async fn open_bi_with_retry(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let mut last_error = None;

    for attempt in 0..STREAM_OPEN_MAX_RETRIES {
        match conn.open_bi().await {
            Ok(streams) => return Ok(streams),
            Err(e) => {
                let delay_ms = STREAM_OPEN_BASE_DELAY_MS * (1 << attempt);
                eprintln!(
                    "Failed to open QUIC stream (attempt {}/{}): {}. Retrying in {}ms...",
                    attempt + 1,
                    STREAM_OPEN_MAX_RETRIES,
                    e,
                    delay_ms
                );
                last_error = Some(e);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error
        .map(|e| anyhow::anyhow!("Failed to open QUIC stream after {} attempts: {}", STREAM_OPEN_MAX_RETRIES, e))
        .unwrap_or_else(|| anyhow::anyhow!("Failed to open QUIC stream")))
}

async fn handle_tcp_receiver_connection_quic(
    conn: Arc<quinn::Connection>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    tunnel_established: Arc<AtomicBool>,
) -> Result<()> {
    let (mut send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    // Write a marker byte to ensure the STREAM frame is sent to the peer.
    // QUIC defers sending STREAM frames until actual data is written,
    // and empty writes don't trigger transmission.
    send_stream.write_all(&[STREAM_OPEN_MARKER]).await.context("Failed to write stream marker")?;

    if !tunnel_established.swap(true, Ordering::Relaxed) {
        println!("Tunnel to sender established!");
    }
    println!("-> Opened tunnel for {}", peer_addr);

    bridge_quinn_streams(recv_stream, send_stream, tcp_stream).await?;
    println!("<- Connection from {} closed", peer_addr);
    Ok(())
}

async fn bridge_quinn_streams(
    mut quic_recv: quinn::RecvStream,
    mut quic_send: quinn::SendStream,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let quic_to_tcp = async { copy_stream(&mut quic_recv, &mut tcp_write).await };
    let tcp_to_quic = async { copy_stream(&mut tcp_read, &mut quic_send).await };

    tokio::select! {
        result = quic_to_tcp => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    eprintln!("QUIC->TCP error: {}", e);
                }
            }
        }
        result = tcp_to_quic => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    eprintln!("TCP->QUIC error: {}", e);
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Manual UDP Forwarding Helpers (quinn streams)
// ============================================================================

/// Read UDP packets from local socket and forward to quinn stream
async fn forward_udp_to_stream_quic(
    udp_socket: Arc<UdpSocket>,
    mut send_stream: quinn::SendStream,
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

        println!("-> Forwarded {} bytes from {}", len, addr);
    }
}

/// Read from quinn stream, forward to UDP target, and send responses back (sender mode)
async fn forward_stream_to_udp_sender_quic(
    mut recv_stream: quinn::RecvStream,
    mut send_stream: quinn::SendStream,
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
            println!("-> Sent {} bytes back to receiver", len);
        }
    });

    loop {
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            break;
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

        println!("<- Forwarded {} bytes to {}", len, target_addr);
    }

    response_task.abort();
    Ok(())
}

/// Read from quinn stream and forward to local UDP client (receiver mode)
async fn forward_stream_to_udp_receiver_quic(
    mut recv_stream: quinn::RecvStream,
    udp_socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            break;
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
            println!("<- Forwarded {} bytes to client {}", len, addr);
        } else {
            println!("<- Received {} bytes but no client connected yet", len);
        }
    }

    Ok(())
}

// no longer used: multiline payloads are read via markers in signaling.rs

/// Open an iroh QUIC bidirectional stream with retry and exponential backoff.
async fn open_bi_with_retry_iroh(
    conn: &iroh::endpoint::Connection,
) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    let mut last_error = None;

    for attempt in 0..STREAM_OPEN_MAX_RETRIES {
        match conn.open_bi().await {
            Ok(streams) => return Ok(streams),
            Err(e) => {
                let delay_ms = STREAM_OPEN_BASE_DELAY_MS * (1 << attempt);
                eprintln!(
                    "Failed to open QUIC stream (attempt {}/{}): {}. Retrying in {}ms...",
                    attempt + 1,
                    STREAM_OPEN_MAX_RETRIES,
                    e,
                    delay_ms
                );
                last_error = Some(e);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error
        .map(|e| anyhow::anyhow!("Failed to open QUIC stream after {} attempts: {}", STREAM_OPEN_MAX_RETRIES, e))
        .unwrap_or_else(|| anyhow::anyhow!("Failed to open QUIC stream")))
}

async fn handle_tcp_receiver_connection(
    conn: Arc<iroh::endpoint::Connection>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    tunnel_established: Arc<AtomicBool>,
) -> Result<()> {
    let (send_stream, recv_stream) = open_bi_with_retry_iroh(&conn).await?;

    // Print success message only on first successful stream
    if !tunnel_established.swap(true, Ordering::Relaxed) {
        println!("Tunnel to sender established!");
    }
    println!("-> Opened tunnel for {}", peer_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    println!("<- Connection from {} closed", peer_addr);
    Ok(())
}

/// Bridge a QUIC stream bidirectionally with a TCP stream
async fn bridge_streams(
    mut quic_recv: iroh::endpoint::RecvStream,
    mut quic_send: iroh::endpoint::SendStream,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let quic_to_tcp = async { copy_stream(&mut quic_recv, &mut tcp_write).await };
    let tcp_to_quic = async { copy_stream(&mut tcp_read, &mut quic_send).await };

    tokio::select! {
        result = quic_to_tcp => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    eprintln!("QUIC->TCP error: {}", e);
                }
            }
        }
        result = tcp_to_quic => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    eprintln!("TCP->QUIC error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Copy data from reader to writer
async fn copy_stream<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(reader, writer)
        .await
        .context("Stream copy failed")?;
    Ok(())
}

// ============================================================================
// Iroh Manual Mode - TCP Tunnel Implementation
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

/// Resolve STUN server hostname to socket addresses
fn resolve_stun_addrs(stun: &str) -> Vec<SocketAddr> {
    match stun.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => Vec::new(),
    }
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
    let ipv4_port = bound_sockets.iter()
        .find(|a| a.is_ipv4())
        .map(|a| a.port());
    let ipv6_port = bound_sockets.iter()
        .find(|a| a.is_ipv6())
        .map(|a| a.port());

    // Step 1: Get STUN-discovered public addresses (for NAT traversal)
    if !stun_servers.is_empty() {
        println!("Discovering public addresses via STUN...");
        let mut got_ipv4_stun = false;
        let mut got_ipv6_stun = false;

        for stun in stun_servers {
            for server in resolve_stun_addrs(stun) {
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
                                println!("  STUN: {} (via {})", addr, stun);
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
                        eprintln!("  STUN query failed for {} ({}): {}", stun, server, e);
                    }
                }
            }
        }
    }

    // Step 2: Get local network interface addresses (for LAN connections)
    println!("Local addresses:");
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
                    println!("  - {}", addr);
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

    println!("Racing connect vs accept for NAT hole punching...");

    // Race both operations with a timeout
    tokio::select! {
        result = timeout(connect_timeout, async {
            // Small delay before connecting to give the other side time to start accepting
            tokio::time::sleep(Duration::from_millis(100)).await;
            endpoint.connect(EndpointAddr::new(remote_id), alpn).await
        }) => {
            match result {
                Ok(Ok(conn)) => {
                    println!("Connected via outbound connection");
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
                    println!("Connected via inbound connection");
                    Ok(conn)
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!("Accept timeout")),
            }
        }
    }
}

pub async fn run_iroh_manual_tcp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("Iroh Manual TCP Tunnel - Sender Mode");
    println!("=====================================");
    println!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(TCP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    let offer = IrohManualOffer {
        version: IROH_SIGNAL_VERSION,
        node_id: node_id.to_string(),
        direct_addresses: direct_addrs,
    };

    println!("\nIroh Manual Offer (copy to receiver):");
    display_iroh_offer(&offer)?;

    println!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
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

    let remote_addr = EndpointAddr::new(remote_id)
        .with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    println!("Added remote peer: {} ({} addresses)", remote_id, answer.direct_addresses.len());

    // Race connect vs accept for NAT hole punching
    let conn = race_connect_accept(&endpoint, remote_id, TCP_ALPN).await?;

    let remote_id = conn.remote_id();
    println!("Peer connected: {}", remote_id);
    println!("Forwarding TCP connections to {}", target_addr);

    loop {
        let (send_stream, recv_stream) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                println!("Peer disconnected: {}", e);
                break;
            }
        };

        println!("New TCP connection request received");
        let target = target_addr;
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await {
                eprintln!("TCP connection error: {}", e);
            }
        });
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

pub async fn run_iroh_manual_tcp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    println!("Iroh Manual TCP Tunnel - Receiver Mode");
    println!("======================================");
    println!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(TCP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    println!("Paste sender offer (include BEGIN/END markers), then press Enter:");
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

    println!("\nIroh Manual Answer (copy to sender):");
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

    let remote_addr = EndpointAddr::new(remote_id)
        .with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    println!("Added remote peer: {} ({} addresses)", remote_id, offer.direct_addresses.len());

    // Race connect vs accept for NAT hole punching
    let conn = race_connect_accept(&endpoint, remote_id, TCP_ALPN).await?;

    println!("Peer connected: {}", conn.remote_id());

    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    println!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };

        println!("New local connection from {}", peer_addr);

        let conn_clone = conn.clone();
        let established = tunnel_established.clone();

        tokio::spawn(async move {
            match handle_tcp_receiver_connection(conn_clone, tcp_stream, peer_addr, established)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("TCP tunnel error for {}: {}", peer_addr, e);
                }
            }
        });
    }
}

// ============================================================================
// Iroh Manual Mode - UDP Tunnel Implementation
// ============================================================================

pub async fn run_iroh_manual_udp_sender(target: String, stun_servers: Vec<String>) -> Result<()> {
    let target_addr = resolve_target_addr(&target)
        .await
        .with_context(|| format!("Invalid target address or hostname '{}'", target))?;

    println!("Iroh Manual UDP Tunnel - Sender Mode");
    println!("=====================================");
    println!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(UDP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    let offer = IrohManualOffer {
        version: IROH_SIGNAL_VERSION,
        node_id: node_id.to_string(),
        direct_addresses: direct_addrs,
    };

    println!("\nIroh Manual Offer (copy to receiver):");
    display_iroh_offer(&offer)?;

    println!("Paste receiver answer (include BEGIN/END markers), then press Enter:");
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

    let remote_addr = EndpointAddr::new(remote_id)
        .with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    println!("Added remote peer: {} ({} addresses)", remote_id, answer.direct_addresses.len());

    // Race connect vs accept for NAT hole punching
    let conn = race_connect_accept(&endpoint, remote_id, UDP_ALPN).await?;

    println!("Peer connected: {}", conn.remote_id());

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    println!("Forwarding UDP traffic to {}", target_addr);

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
    println!("Connection closed.");

    Ok(())
}

pub async fn run_iroh_manual_udp_receiver(listen: String, stun_servers: Vec<String>) -> Result<()> {
    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    println!("Iroh Manual UDP Tunnel - Receiver Mode");
    println!("======================================");
    println!("Creating iroh endpoint (no relay)...");

    let (endpoint, discovery) = create_iroh_manual_endpoint(UDP_ALPN).await?;

    let node_id = endpoint.id();
    let direct_addrs = get_direct_addresses(&endpoint, &stun_servers).await;

    println!("Paste sender offer (include BEGIN/END markers), then press Enter:");
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

    println!("\nIroh Manual Answer (copy to sender):");
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

    let remote_addr = EndpointAddr::new(remote_id)
        .with_addrs(remote_addrs.into_iter().map(TransportAddr::Ip));
    discovery.add_endpoint_info(remote_addr);
    println!("Added remote peer: {} ({} addresses)", remote_id, offer.direct_addresses.len());

    // Race connect vs accept for NAT hole punching
    let conn = race_connect_accept(&endpoint, remote_id, UDP_ALPN).await?;

    println!("Peer connected: {}", conn.remote_id());

    let (send_stream, recv_stream) = open_bi_with_retry_iroh(&conn).await?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                eprintln!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                eprintln!("Stream to UDP error: {}", e);
            }
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    println!("Connection closed.");

    Ok(())
}
