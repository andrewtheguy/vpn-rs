//! Shared utilities for tunnel implementations.
//!
//! This module contains common helpers used across all tunnel modes:
//! - Address resolution (DNS, Happy Eyeballs)
//! - Stream copying and bridging
//! - Retry logic with exponential backoff

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpStream};

/// Timeout for QUIC connection (matches webrtc crate's 180 second connection timeout)
pub const QUIC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

/// Maximum age for accepting incoming requests (seconds).
/// Requests older than this are considered stale and ignored.
///
/// Set to 30s to balance:
/// - Nostr relay propagation delays (can take 2-5 seconds across relays)
/// - Clock skew between sender and receiver (assume NTP sync, ~15s max)
/// - Network latency and retransmission timing
/// - Avoid processing stale requests from previous receiver invocations
///
/// Note: Reduced from 60s to 30s to minimize processing of stale events
/// from crashed/restarted receivers.
pub const MAX_REQUEST_AGE_SECS: u64 = 30;

/// Delay between starting connection attempts (Happy Eyeballs style).
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Marker byte sent when opening a new QUIC stream to ensure
/// the STREAM frame is immediately sent to the peer.
pub const STREAM_OPEN_MARKER: u8 = 0x00;

/// Maximum attempts for opening QUIC streams
pub const STREAM_OPEN_MAX_ATTEMPTS: u32 = 3;

/// Base delay for exponential backoff (doubles each attempt)
pub const STREAM_OPEN_BASE_DELAY_MS: u64 = 100;

/// Maximum multiplier for exponential backoff to keep delays bounded.
/// With base delay of 100ms, this caps max delay at ~102 seconds.
pub const BACKOFF_MAX_MULTIPLIER: u64 = 1024;

// ============================================================================
// Address Resolution
// ============================================================================

/// Resolve a target address to a single socket address.
pub async fn resolve_target_addr(target: &str) -> Result<SocketAddr> {
    let mut addrs = lookup_host(target)
        .await
        .with_context(|| format!("Failed to resolve '{}'", target))?;
    addrs.next().context("No addresses found for host")
}

/// Resolve a target address to all available socket addresses.
/// Returns all IPv4 and IPv6 addresses for the hostname.
pub async fn resolve_all_target_addrs(target: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = lookup_host(target)
        .await
        .with_context(|| format!("Failed to resolve '{}'", target))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("No addresses found for host '{}'", target);
    }
    Ok(addrs)
}

/// Resolve a STUN server address asynchronously.
///
/// Returns all resolved socket addresses for the STUN server.
/// The input should be in "host:port" format (e.g., "stun.l.google.com:19302").
pub async fn resolve_stun_addrs(stun: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = lookup_host(stun)
        .await
        .with_context(|| format!("Failed to resolve STUN server '{}'", stun))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("No addresses found for STUN server '{}'", stun);
    }
    Ok(addrs)
}

// ============================================================================
// Happy Eyeballs TCP Connection
// ============================================================================

/// Try to connect to any of the given addresses using Happy Eyeballs algorithm (RFC 8305).
/// - Prefers IPv6 addresses (tried first)
/// - Interleaves IPv6 and IPv4 attempts
/// - Staggers connection attempts with a small delay
/// - Returns first successful connection, cancels remaining attempts
pub async fn try_connect_tcp(addrs: &[SocketAddr]) -> Result<TcpStream> {
    use tokio::sync::mpsc;

    if addrs.is_empty() {
        anyhow::bail!("No addresses to connect to");
    }

    // Separate addresses by family, preferring IPv6
    let (ipv6, ipv4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().copied().partition(|a| a.is_ipv6());

    // Interleave addresses: IPv6 first, then alternate
    let mut ordered = Vec::with_capacity(addrs.len());
    let mut v6_iter = ipv6.into_iter();
    let mut v4_iter = ipv4.into_iter();

    // Start with IPv6 if available
    while ordered.len() < addrs.len() {
        if let Some(addr) = v6_iter.next() {
            ordered.push(addr);
        }
        if let Some(addr) = v4_iter.next() {
            ordered.push(addr);
        }
    }

    // Channel for connection results
    let (tx, mut rx) =
        mpsc::channel::<(SocketAddr, Result<TcpStream, std::io::Error>)>(ordered.len());

    // Spawn staggered connection attempts
    let mut handles = Vec::with_capacity(ordered.len());
    for (i, addr) in ordered.into_iter().enumerate() {
        let tx = tx.clone();
        let handle = tokio::spawn(async move {
            // Stagger attempts: first immediately, then with delay
            if i > 0 {
                tokio::time::sleep(CONNECTION_ATTEMPT_DELAY * i as u32).await;
            }
            let result = TcpStream::connect(addr).await;
            // Ignore send error (receiver may have closed on success)
            let _ = tx.send((addr, result)).await;
        });
        handles.push(handle);
    }
    drop(tx); // Close sender so rx completes when all attempts finish

    // Collect errors for reporting if all fail
    let mut errors: Vec<(SocketAddr, std::io::Error)> = Vec::new();

    // Wait for first success or all failures
    while let Some((addr, result)) = rx.recv().await {
        match result {
            Ok(stream) => {
                // Success! Cancel remaining attempts
                for handle in handles {
                    handle.abort();
                }
                return Ok(stream);
            }
            Err(e) => {
                errors.push((addr, e));
            }
        }
    }

    // All attempts failed - build error message
    if errors.is_empty() {
        anyhow::bail!("No addresses to connect to");
    } else if errors.len() == 1 {
        let (addr, e) = errors.remove(0);
        anyhow::bail!("Failed to connect to {}: {}", addr, e);
    } else {
        let error_details: Vec<String> = errors
            .iter()
            .map(|(addr, e)| format!("{}: {}", addr, e))
            .collect();
        anyhow::bail!(
            "Failed to connect to any address:\n  {}",
            error_details.join("\n  ")
        );
    }
}

// ============================================================================
// URL Parsing Helpers
// ============================================================================

/// Extract address (host:port) from a source URL (protocol://host:port).
pub fn extract_addr_from_source(source: &str) -> Option<String> {
    let url = url::Url::parse(source).ok()?;
    let host = url.host_str()?;
    let port = url.port()?;
    // Re-add brackets for IPv6 addresses
    if host.contains(':') {
        Some(format!("[{}]:{}", host, port))
    } else {
        Some(format!("{}:{}", host, port))
    }
}

/// Extract host from a source URL (protocol://host:port).
pub fn extract_host_from_source(source: &str) -> Option<String> {
    let url = url::Url::parse(source).ok()?;
    url.host_str().map(|s| s.to_string())
}

/// Extract port from a source URL (protocol://host:port).
pub fn extract_port_from_source(source: &str) -> Option<u16> {
    url::Url::parse(source).ok()?.port()
}

// ============================================================================
// Session ID Helpers
// ============================================================================

/// Generate a random session ID for nostr signaling.
pub fn generate_session_id() -> String {
    use rand::Rng;
    let random_bytes: [u8; 8] = rand::rng().random();
    hex::encode(random_bytes)
}

/// Get a short prefix of a session ID for logging (first 8 chars or less).
pub fn short_session_id(session_id: &str) -> &str {
    &session_id[..8.min(session_id.len())]
}

/// Get current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// CIDR Network Validation
// ============================================================================

/// Validate that all entries in allowed_networks are valid CIDR notation.
/// Returns an error with context if any entry fails to parse.
pub fn validate_allowed_networks(allowed_networks: &[String], label: &str) -> Result<()> {
    for network_str in allowed_networks {
        network_str.parse::<ipnet::IpNet>().with_context(|| {
            format!(
                "Invalid CIDR '{}' in {}. Expected format: 192.168.0.0/16 or ::1/128",
                network_str, label
            )
        })?;
    }
    Ok(())
}

/// Check if a source address is allowed by any network in the CIDR list.
/// Supports both IP addresses and hostnames (resolved via DNS).
///
/// The source format is `protocol://host:port` (e.g., `tcp://192.168.1.100:22` or `tcp://myserver.local:22`).
/// The allowed_networks list contains CIDR notation (e.g., `192.168.0.0/16`, `::1/128`).
///
/// Returns true if:
/// - allowed_networks is empty (no restrictions, caller should handle default)
/// - The source IP (or resolved hostname IP) is contained in any of the allowed networks
pub async fn is_source_allowed(source: &str, allowed_networks: &[String]) -> bool {
    use tokio::net::lookup_host;

    if allowed_networks.is_empty() {
        return true; // No restrictions
    }

    // Extract host from source (protocol://host:port)
    let Some(host) = extract_host_from_source(source) else {
        return false;
    };

    // Collect all IPs to check (either the literal IP or all resolved addresses)
    let source_ips: Vec<std::net::IpAddr> = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            // Not an IP - try DNS resolution
            let Some(port) = extract_port_from_source(source) else {
                return false;
            };
            let lookup_target = format!("{}:{}", host, port);
            let addrs = match lookup_host(&lookup_target).await {
                Ok(addrs) => addrs,
                Err(_) => return false,
            };
            let ips: Vec<_> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                return false;
            }
            ips
        }
    };

    // Check if ANY resolved IP matches ANY allowed network
    // This handles cases like localhost resolving to both ::1 and 127.0.0.1
    for source_ip in &source_ips {
        for network_str in allowed_networks {
            // unwrap is safe: networks are validated at startup by validate_allowed_networks
            let network: ipnet::IpNet = network_str.parse().unwrap();
            if network.contains(source_ip) {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Retry with Exponential Backoff
// ============================================================================

/// Generic retry helper with exponential backoff.
///
/// Attempts an async operation up to `max_attempts` times with exponential backoff.
/// The delay doubles each attempt starting from `base_delay_ms`.
///
/// # Arguments
/// * `operation` - Async closure returning `Result<T, E>` to attempt
/// * `max_attempts` - Maximum number of attempts before giving up
/// * `base_delay_ms` - Initial delay in milliseconds (doubles each attempt)
/// * `operation_name` - Name for logging (e.g., "open QUIC stream")
///
/// # Returns
/// The successful result, or an `anyhow::Error` after all attempts are exhausted.
pub async fn retry_with_backoff<T, E, F, Fut>(
    operation: F,
    max_attempts: u32,
    base_delay_ms: u64,
    operation_name: &str,
) -> Result<T>
where
    E: std::fmt::Display,
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if max_attempts == 0 {
        return Err(anyhow::anyhow!(
            "max_attempts must be > 0 for {}",
            operation_name
        ));
    }
    debug_assert!(max_attempts > 0, "max_attempts must be > 0");

    for attempt in 0..max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                let is_last_attempt = attempt + 1 >= max_attempts;
                if is_last_attempt {
                    // Final attempt failed - return error immediately without sleeping
                    return Err(anyhow::anyhow!(
                        "Failed to {} after {} attempts: {}",
                        operation_name,
                        max_attempts,
                        e
                    ));
                }
                // More attempts remaining - log attempt message and sleep
                // Use saturating arithmetic and cap multiplier to keep delays bounded
                let multiplier = 1u64
                    .checked_shl(attempt)
                    .unwrap_or(BACKOFF_MAX_MULTIPLIER)
                    .min(BACKOFF_MAX_MULTIPLIER);
                let delay_ms = base_delay_ms.saturating_mul(multiplier);
                log::warn!(
                    "Failed to {} (attempt {}/{}): {}. Next attempt in {}ms...",
                    operation_name,
                    attempt + 1,
                    max_attempts,
                    e,
                    delay_ms
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    // This should be unreachable if max_attempts > 0, but handle edge case
    Err(anyhow::anyhow!(
        "Failed to {} with no attempts",
        operation_name
    ))
}

// ============================================================================
// Stream Copying
// ============================================================================

/// Copy data from reader to writer
pub async fn copy_stream<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
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
// Quinn Stream Helpers (shared by custom and nostr modes)
// ============================================================================

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Open a QUIC bidirectional stream with retry and exponential backoff.
pub async fn open_bi_with_retry(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    retry_with_backoff(
        || conn.open_bi(),
        STREAM_OPEN_MAX_ATTEMPTS,
        STREAM_OPEN_BASE_DELAY_MS,
        "open QUIC stream",
    )
    .await
}

/// Handle TCP sender stream: read marker, connect to target, bridge streams
pub async fn handle_tcp_sender_stream(
    send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    target_addrs: Arc<Vec<SocketAddr>>,
) -> Result<()> {
    // Read and discard the stream marker byte sent by the receiver
    let mut marker = [0u8; 1];
    recv_stream
        .read_exact(&mut marker)
        .await
        .context("Failed to read stream marker")?;

    let tcp_stream = try_connect_tcp(&target_addrs)
        .await
        .context("Failed to connect to target TCP service")?;

    let local_addr = tcp_stream.peer_addr().ok();
    log::info!("-> Connected to target {:?}", local_addr);
    bridge_quinn_streams(recv_stream, send_stream, tcp_stream).await?;
    log::info!("<- TCP connection to {:?} closed", local_addr);
    Ok(())
}

/// Handle TCP receiver connection: open stream, write marker, bridge streams
pub async fn handle_tcp_receiver_connection(
    conn: Arc<quinn::Connection>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    tunnel_established: Arc<AtomicBool>,
) -> Result<()> {
    let (mut send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    // Write a marker byte to ensure the STREAM frame is sent to the peer.
    send_stream
        .write_all(&[STREAM_OPEN_MARKER])
        .await
        .context("Failed to write stream marker")?;

    if !tunnel_established.swap(true, Ordering::Relaxed) {
        log::info!("Tunnel to sender established!");
    }
    log::info!("-> Opened tunnel for {}", peer_addr);

    bridge_quinn_streams(recv_stream, send_stream, tcp_stream).await?;
    log::info!("<- Connection from {} closed", peer_addr);
    Ok(())
}

/// Bridge QUIC streams with a TCP stream (bidirectional copy)
pub async fn bridge_quinn_streams(
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
                    log::warn!("QUIC->TCP error: {}", e);
                }
            }
        }
        result = tcp_to_quic => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    log::warn!("TCP->QUIC error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Read UDP packets from local socket and forward to quinn stream
pub async fn forward_udp_to_stream(
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

        log::debug!("-> Forwarded {} bytes from {}", len, addr);
    }
}

/// Read from quinn stream, forward to UDP target, and send responses back (sender mode)
pub async fn forward_stream_to_udp_sender(
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
            log::debug!("-> Sent {} bytes back to receiver", len);
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

        log::debug!("<- Forwarded {} bytes to {}", len, target_addr);
    }

    response_task.abort();
    Ok(())
}

/// Read from quinn stream and forward to local UDP client (receiver mode)
pub async fn forward_stream_to_udp_receiver(
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
            log::debug!("<- Forwarded {} bytes to client {}", len, addr);
        } else {
            log::debug!("<- Received {} bytes but no client connected yet", len);
        }
    }

    Ok(())
}
