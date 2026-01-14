//! VPN client implementation.
//!
//! The VPN client connects to a VPN server via iroh, performs handshake
//! to receive IP assignment, configures the TUN device, and manages the
//! IP-over-QUIC tunnel. IP packets are framed and sent directly over the
//! encrypted iroh QUIC connection for automatic NAT traversal.

use crate::config::VpnClientConfig;
use crate::device::{add_routes, add_routes6, Route6Guard, RouteGuard, TunConfig, TunDevice};
use crate::error::{VpnError, VpnResult};
use crate::lock::VpnLock;
use crate::signaling::{
    frame_ip_packet, read_message, write_message, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, HEARTBEAT_PING_BYTE, MAX_HANDSHAKE_SIZE, VPN_ALPN,
};
use bytes::{Bytes, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Maximum IP packet size (MTU + overhead).
const MAX_IP_PACKET_SIZE: usize = 65536;

/// Heartbeat ping interval (how often client sends ping).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Heartbeat timeout (max time to wait for pong before triggering reconnection).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for outbound packets.
///
/// Sized to handle bursts without blocking the TUN reader. Larger buffers
/// improve throughput for bursty traffic but increase memory usage and
/// latency under congestion. The value 1024 matches the server's default
/// client channel size for symmetric buffering.
///
/// Memory impact: ~1024 * ~1500 bytes (typical MTU) = ~1.5 MB worst case.
/// Latency impact: At 100 Mbps, a full 1024-packet buffer adds ~120ms latency.
const OUTBOUND_CHANNEL_SIZE: usize = 1024;

/// VPN client instance.
pub struct VpnClient {
    /// Client configuration.
    config: VpnClientConfig,
    /// Client's unique device ID.
    device_id: u64,
    /// Single-instance lock.
    _lock: VpnLock,
}

/// Information received from the VPN server after successful handshake.
#[non_exhaustive]
pub struct ServerInfo {
    /// Assigned VPN IP for this client (IPv4).
    pub assigned_ip: Ipv4Addr,
    /// VPN network CIDR (IPv4).
    pub network: Ipv4Net,
    /// Server's VPN IP (gateway, IPv4).
    pub server_ip: Ipv4Addr,
    /// Assigned IPv6 VPN address for this client (optional, for dual-stack).
    pub assigned_ip6: Option<Ipv6Addr>,
    /// IPv6 VPN network CIDR (optional, for dual-stack).
    pub network6: Option<Ipv6Net>,
    /// Server's IPv6 VPN address (gateway, optional).
    pub server_ip6: Option<Ipv6Addr>,
}

impl VpnClient {
    /// Create a new VPN client.
    ///
    /// Acquires a single-instance lock (only one VPN client per process) and
    /// generates a random `device_id` (u64) for session identification.
    /// The device_id allows the server to distinguish multiple sessions from
    /// the same iroh endpoint.
    pub fn new(config: VpnClientConfig) -> VpnResult<Self> {
        // Acquire single-instance lock
        let lock = VpnLock::acquire()?;

        // Generate random device ID (unique per session)
        let device_id: u64 = rand::thread_rng().gen();
        log::info!("Generated device ID: {:016x}", device_id);

        Ok(Self {
            config,
            device_id,
            _lock: lock,
        })
    }

    /// Connect to the VPN server and establish the tunnel.
    pub async fn connect(&self, endpoint: &Endpoint) -> VpnResult<()> {
        // Parse server endpoint ID
        let server_id: EndpointId = self.config.server_node_id.parse().map_err(|_| {
            VpnError::Config(format!(
                "Invalid server node ID: {}",
                self.config.server_node_id
            ))
        })?;

        log::info!("Connecting to VPN server: {}", server_id);

        // Connect to server
        let connection = endpoint
            .connect(server_id, VPN_ALPN)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to connect to server: {}", e)))?;

        log::info!("Connected to server, performing handshake...");

        // Perform handshake on first stream
        let server_info = self.perform_handshake(&connection).await?;

        log::info!("Handshake successful:");
        log::info!("  Assigned IP: {}", server_info.assigned_ip);
        log::info!("  Network: {}", server_info.network);
        log::info!("  Gateway: {}", server_info.server_ip);
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Assigned IPv6: {}", ip6);
        }
        if let Some(net6) = server_info.network6 {
            log::info!("  Network6: {}", net6);
        }
        if let Some(gw6) = server_info.server_ip6 {
            log::info!("  Gateway6: {}", gw6);
        }

        // Create TUN device
        let tun_device = self.create_tun_device(&server_info)?;

        // Add custom IPv4 routes through the VPN (guard ensures cleanup on drop)
        let _route_guard: Option<RouteGuard> = if !self.config.routes.is_empty() {
            Some(add_routes(tun_device.name(), &self.config.routes).await?)
        } else {
            None
        };

        // Add custom IPv6 routes through the VPN (guard ensures cleanup on drop)
        // Only add IPv6 routes if server provided IPv6 and client has routes6 configured
        let _route6_guard: Option<Route6Guard> =
            if server_info.assigned_ip6.is_some() && !self.config.routes6.is_empty() {
                Some(add_routes6(tun_device.name(), &self.config.routes6).await?)
            } else {
                None
            };

        // Open data stream for IP packets
        let (data_send, data_recv) = connection
            .open_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to open data stream: {}", e)))?;

        log::info!("VPN data stream opened");

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());
        log::info!("  Client IP: {}", server_info.assigned_ip);
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Client IPv6: {}", ip6);
        }

        // Run the VPN packet loop (tunneled over iroh)
        self.run_vpn_loop(tun_device, data_send, data_recv).await
    }

    /// Perform VPN handshake with the server.
    async fn perform_handshake(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> VpnResult<ServerInfo> {
        // Open bidirectional stream for handshake
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to open stream: {}", e)))?;

        // Send handshake
        let mut handshake = VpnHandshake::new(self.device_id);
        if let Some(ref token) = self.config.auth_token {
            handshake = handshake.with_auth_token(token);
        }

        write_message(&mut send, &handshake.encode()?).await?;

        // Read response
        let response_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE).await?;
        let response = VpnHandshakeResponse::decode(&response_data)?;

        if !response.accepted {
            let reason = response
                .reject_reason
                .unwrap_or_else(|| "Unknown".to_string());
            return Err(VpnError::AuthenticationFailed(reason));
        }

        // Extract server info (IPv4 required)
        let assigned_ip = response
            .assigned_ip
            .ok_or_else(|| VpnError::Signaling("Server response missing assigned IP".into()))?;
        let network = response
            .network
            .ok_or_else(|| VpnError::Signaling("Server response missing network".into()))?;
        let server_ip = response
            .server_ip
            .ok_or_else(|| VpnError::Signaling("Server response missing server IP".into()))?;

        // Extract IPv6 info (optional, for dual-stack)
        // All three must be present together or all absent for consistency
        let (assigned_ip6, network6, server_ip6) = match (
            response.assigned_ip6,
            response.network6,
            response.server_ip6,
        ) {
            (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
            (None, None, None) => (None, None, None),
            _ => {
                return Err(VpnError::Config(
                    "Server response has incomplete IPv6 configuration: \
                     assigned_ip6, network6, and server_ip6 must all be present or all absent"
                        .into(),
                ));
            }
        };

        // Close handshake stream (best-effort, handshake already completed)
        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }
        Ok(ServerInfo {
            assigned_ip,
            network,
            server_ip,
            assigned_ip6,
            network6,
            server_ip6,
        })
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self, server_info: &ServerInfo) -> VpnResult<TunDevice> {
        let mut tun_config = TunConfig::new(
            server_info.assigned_ip,
            server_info.network.netmask(),
            server_info.server_ip,
        )
        .with_mtu(self.config.mtu);

        // Add IPv6 configuration if server provided it
        if let (Some(assigned_ip6), Some(network6)) =
            (server_info.assigned_ip6, server_info.network6)
        {
            tun_config = tun_config.with_ipv6(assigned_ip6, network6.prefix_len())?;
        }

        TunDevice::create(tun_config)
    }

    /// Run the VPN packet processing loop (tunneled over iroh QUIC).
    async fn run_vpn_loop(
        &self,
        tun_device: TunDevice,
        data_send: SendStream,
        data_recv: RecvStream,
    ) -> VpnResult<()> {
        // Split TUN device
        let (mut tun_reader, mut tun_writer) = tun_device.split()?;
        let buffer_size = tun_reader.buffer_size();

        // Create channel for outbound data to decouple packet production from stream writes.
        // The writer task owns the SendStream and performs actual I/O, eliminating
        // per-packet mutex overhead from the TUN reader and heartbeat tasks.
        // Uses Bytes for zero-copy sends (freeze BytesMut instead of cloning Vec).
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_SIZE);
        let outbound_tx_heartbeat = outbound_tx.clone();

        // Spawn dedicated writer task that owns the SendStream.
        // Returns error context if write fails for inclusion in shutdown reason.
        let mut writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let mut data_send = data_send;
            while let Some(data) = outbound_rx.recv().await {
                if let Err(e) = data_send.write_all(&data).await {
                    log::warn!("Failed to write to QUIC stream: {}", e);
                    return Some(format!("QUIC write error: {}", e));
                }
            }
            log::trace!("Writer task exiting");
            None
        });

        // Track last heartbeat pong received (as millis since start_time for atomic access)
        let start_time = Instant::now();
        let last_pong = Arc::new(AtomicU64::new(start_time.elapsed().as_millis() as u64));
        let last_pong_inbound = last_pong.clone();
        let last_pong_heartbeat = last_pong.clone();

        // Spawn outbound task (TUN -> frame IP packet -> channel -> writer task)
        // Returns error reason if task exits due to an error.
        //
        // Memory note: Each packet requires a small allocation (~MTU + 5 bytes for framing).
        // After split().freeze(), the Bytes holds the allocation until consumed by the writer.
        // We size the buffer to MTU (not MAX_IP_PACKET_SIZE) to keep allocations small (~1.5KB).
        // The allocator typically serves these from thread-local caches, making them fast.
        let mut outbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let mut read_buf = vec![0u8; buffer_size];
            // Frame capacity: 1 byte type + 4 byte length + packet data (up to buffer_size/MTU)
            let frame_capacity = 1 + 4 + buffer_size;
            let mut write_buf = BytesMut::with_capacity(frame_capacity);
            loop {
                match tun_reader.read(&mut read_buf).await {
                    Ok(n) if n > 0 => {
                        let packet = &read_buf[..n];

                        // Frame IP packet for transmission (writes into write_buf)
                        if let Err(e) = frame_ip_packet(&mut write_buf, packet) {
                            log::warn!("Failed to frame packet: {}", e);
                            continue;
                        }

                        // Freeze into Bytes for zero-copy send to writer task.
                        // split().freeze() creates a Bytes that references the allocation.
                        // The BytesMut is left empty with no capacity.
                        let bytes = write_buf.split().freeze();

                        // Restore capacity for next packet. Since the Bytes still references
                        // the old allocation (until writer consumes it), this allocates new
                        // memory. With MTU-sized buffers (~1.5KB), this is fast.
                        write_buf.reserve(frame_capacity);

                        // Send via channel to writer task (blocking send to apply backpressure)
                        if outbound_tx.send(bytes).await.is_err() {
                            log::warn!("Outbound channel closed");
                            return None; // Normal exit, channel closed
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("TUN read error: {}", e);
                        return Some(format!("TUN read error: {}", e));
                    }
                }
            }
        });

        // Spawn inbound task (QUIC stream -> TUN)
        // data_recv is moved into this task (no Arc/Mutex needed - single owner)
        // Returns error reason if task exits due to an error.
        let inbound_start_time = start_time;
        let mut inbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            const MAX_TUN_WRITE_FAILURES: u32 = 10;
            let mut data_recv = data_recv;
            let mut type_buf = [0u8; 1];
            let mut len_buf = [0u8; 4];
            let mut data_buf = vec![0u8; MAX_IP_PACKET_SIZE];
            let mut consecutive_tun_failures = 0u32;
            loop {
                // Read message type
                match data_recv.read_exact(&mut type_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read message type: {}", e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }

                let msg_type = match DataMessageType::from_byte(type_buf[0]) {
                    Some(t) => t,
                    None => {
                        // Unknown message type - cannot determine framing, must disconnect
                        // to avoid stream desynchronization
                        log::error!("Unknown message type: 0x{:02x}, disconnecting", type_buf[0]);
                        return Some(format!("Unknown message type: 0x{:02x}", type_buf[0]));
                    }
                };

                match msg_type {
                    DataMessageType::HeartbeatPong => {
                        // Update last pong time
                        let now = inbound_start_time.elapsed().as_millis() as u64;
                        last_pong_inbound.store(now, Ordering::Relaxed);
                        log::trace!("Heartbeat pong received");
                        continue;
                    }
                    DataMessageType::HeartbeatPing => {
                        // Client shouldn't receive pings, ignore
                        log::trace!("Unexpected heartbeat ping received");
                        continue;
                    }
                    DataMessageType::IpPacket => {
                        // Continue to read IP packet below
                    }
                }

                // Read length prefix for IP packet
                match data_recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read IP packet length: {}", e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_IP_PACKET_SIZE {
                    log::error!("IP packet too large: {}", len);
                    return Some(format!("IP packet too large: {}", len));
                }

                // Read packet data
                match data_recv.read_exact(&mut data_buf[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read IP packet: {}", e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }

                let packet = &data_buf[..len];
                // Directly write to TUN (packet is already decrypted/raw IP)
                if let Err(e) = tun_writer.write_all(packet).await {
                    consecutive_tun_failures += 1;
                    if consecutive_tun_failures >= MAX_TUN_WRITE_FAILURES {
                        log::error!(
                            "Too many consecutive TUN write failures ({}), disconnecting: {}",
                            consecutive_tun_failures,
                            e
                        );
                        return Some(format!("TUN write failures exceeded: {}", e));
                    }
                    log::warn!(
                        "Failed to write to TUN ({}/{}): {}",
                        consecutive_tun_failures,
                        MAX_TUN_WRITE_FAILURES,
                        e
                    );
                } else {
                    consecutive_tun_failures = 0;
                }
            }
        });

        // Spawn heartbeat task (sends pings via channel, checks for timeout)
        // Returns error reason if task exits due to timeout.
        let mut heartbeat_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let heartbeat_start = start_time;
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;

                // Check if we've received a pong recently
                let now_ms = heartbeat_start.elapsed().as_millis() as u64;
                let last_pong_ms = last_pong_heartbeat.load(Ordering::Relaxed);
                let elapsed_ms = now_ms.saturating_sub(last_pong_ms);

                if elapsed_ms > HEARTBEAT_TIMEOUT.as_millis() as u64 {
                    log::error!(
                        "Heartbeat timeout: no pong received for {:.1}s (threshold: {:.1}s)",
                        elapsed_ms as f64 / 1000.0,
                        HEARTBEAT_TIMEOUT.as_secs_f64()
                    );
                    return Some(format!(
                        "Heartbeat timeout: no pong for {:.1}s",
                        elapsed_ms as f64 / 1000.0
                    ));
                }

                // Send ping via channel to writer task (static Bytes, zero allocation)
                let ping = Bytes::from_static(HEARTBEAT_PING_BYTE);
                if outbound_tx_heartbeat.send(ping).await.is_err() {
                    log::warn!("Failed to send heartbeat ping: channel closed");
                    return None; // Normal exit, channel closed
                }
                log::trace!("Heartbeat ping sent");
            }
        });

        // Wait for any task to complete (or error), then clean up all tasks
        let (first_task, first_result, remaining) = tokio::select! {
            result = &mut outbound_handle => {
                ("outbound", result, vec![("inbound", inbound_handle), ("heartbeat", heartbeat_handle), ("writer", writer_handle)])
            }
            result = &mut inbound_handle => {
                ("inbound", result, vec![("outbound", outbound_handle), ("heartbeat", heartbeat_handle), ("writer", writer_handle)])
            }
            result = &mut heartbeat_handle => {
                ("heartbeat", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("writer", writer_handle)])
            }
            result = &mut writer_handle => {
                ("writer", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("heartbeat", heartbeat_handle)])
            }
        };

        // Abort remaining tasks to ensure they stop
        for (_, handle) in &remaining {
            handle.abort();
        }

        // Await all remaining handles to ensure cleanup (aborted tasks return Cancelled)
        let mut all_results = vec![(first_task, first_result)];
        for (name, handle) in remaining {
            all_results.push((name, handle.await));
        }

        // Build comprehensive reason from all task results
        let mut reasons = Vec::new();
        for (name, result) in &all_results {
            match result {
                Ok(Some(error_reason)) => {
                    // Task exited with an error reason
                    reasons.push(error_reason.clone());
                }
                Ok(None) => {
                    // Task completed normally (channel closed, etc.)
                    reasons.push(format!("{} task ended", name));
                }
                Err(e) if e.is_cancelled() => {
                    // Expected for aborted tasks, don't include in reason
                }
                Err(e) if e.is_panic() => {
                    reasons.push(format!("{} task panicked: {}", name, e));
                }
                Err(e) => {
                    reasons.push(format!("{} task failed: {}", name, e));
                }
            }
        }

        let reason = if reasons.is_empty() {
            "all tasks cancelled".to_string()
        } else {
            reasons.join("; ")
        };
        log::debug!("VPN loop ended: {}", reason);

        // Any task ending means connection is lost
        Err(VpnError::ConnectionLost(reason))
    }

    /// Connect to the VPN server with automatic reconnection on failure.
    ///
    /// This method wraps `connect()` with a reconnection loop that handles
    /// transient failures using exponential backoff (1s → 2s → 4s → ... → 60s max).
    ///
    /// # Arguments
    /// * `endpoint` - The iroh endpoint to use for connections
    /// * `max_attempts` - Maximum total connection attempts (None = unlimited).
    ///   This counts all attempts including the initial one:
    ///   - `Some(1)` = try once, exit on any failure (no retries)
    ///   - `Some(3)` = try up to 3 times total (initial + 2 retries)
    ///   - `None` = retry indefinitely on recoverable errors
    ///
    /// # Error Handling
    /// Only recoverable errors (see [`VpnError::is_recoverable`]) trigger retries:
    /// - `ConnectionLost`, `Network`, `Signaling` → retry with backoff
    /// - `AuthenticationFailed`, `Config`, `TunDevice`, etc. → exit immediately
    ///
    /// This prevents infinite retry loops on permanent failures like invalid tokens.
    pub async fn run_with_reconnect(
        &self,
        endpoint: &Endpoint,
        max_attempts: Option<NonZeroU32>,
    ) -> VpnResult<()> {
        let mut attempt = 0u32;

        loop {
            attempt = attempt.saturating_add(1);

            if attempt == 1 {
                log::info!("Connecting to VPN server...");
            } else {
                log::info!("VPN reconnection attempt #{}", attempt);
            }

            match self.connect(endpoint).await {
                Ok(()) => {
                    // Graceful exit (shouldn't normally happen)
                    log::info!("VPN connection ended gracefully");
                    return Ok(());
                }
                Err(e) if e.is_recoverable() => {
                    // Reset attempt counter if this was a ConnectionLost (tunnel ran successfully)
                    if matches!(e, VpnError::ConnectionLost(_)) {
                        attempt = 0;
                    }

                    // Check max attempts (None = unlimited)
                    if let Some(max) = max_attempts {
                        if attempt >= max.get() {
                            log::error!("Max reconnection attempts ({}) exceeded", max);
                            return Err(VpnError::MaxReconnectAttemptsExceeded(max));
                        }
                    }

                    // Calculate backoff delay
                    let delay = calculate_backoff(attempt);
                    log::warn!(
                        "Connection lost ({}), reconnecting in {:.1}s{}",
                        e,
                        delay.as_secs_f64(),
                        if let Some(max) = max_attempts {
                            format!(" (attempt {}/{})", attempt, max)
                        } else {
                            String::new()
                        }
                    );

                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    // Fatal error - don't retry
                    log::error!("Fatal VPN error (not retrying): {}", e);
                    return Err(e);
                }
            }
        }
    }
}

/// Builder for VpnClient.
pub struct VpnClientBuilder {
    config: VpnClientConfig,
}

impl VpnClientBuilder {
    /// Create a new builder.
    pub fn new(server_node_id: impl Into<String>) -> Self {
        Self {
            config: VpnClientConfig {
                server_node_id: server_node_id.into(),
                ..Default::default()
            },
        }
    }

    /// Set the authentication token.
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.config.auth_token = Some(token.into());
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.config.mtu = mtu;
        self
    }

    /// Build the client.
    pub fn build(self) -> VpnResult<VpnClient> {
        VpnClient::new(self.config)
    }
}

/// Backoff constants for reconnection delay calculation.
const BACKOFF_BASE_MS: u64 = 1000; // 1 second
const BACKOFF_MAX_MS: u64 = 60000; // 60 seconds
const BACKOFF_JITTER_MS: u64 = 500;

/// Calculate exponential backoff delay with jitter.
///
/// Uses exponential backoff: `base * 2^(attempt-1)`, capped at max.
/// Adds random jitter (0-500ms) to prevent thundering herd.
/// The cap is applied after adding jitter to ensure the total never exceeds MAX_MS.
fn calculate_backoff(attempt: u32) -> Duration {
    calculate_backoff_with_rng(attempt, &mut rand::thread_rng())
}

/// Calculate exponential backoff delay with a custom RNG.
///
/// This is the testable version that accepts an RNG parameter.
/// Production code should use `calculate_backoff()` which uses `thread_rng()`.
///
/// # Arguments
/// * `attempt` - Current attempt number (1-based)
/// * `rng` - Random number generator for jitter
fn calculate_backoff_with_rng(attempt: u32, rng: &mut impl Rng) -> Duration {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, ...
    let multiplier = 2_u64.saturating_pow(attempt.saturating_sub(1));
    let base_delay_ms = BACKOFF_BASE_MS.saturating_mul(multiplier);

    // Add jitter to prevent thundering herd (unbiased via gen_range)
    let jitter_ms = rng.gen_range(0..BACKOFF_JITTER_MS);

    // Cap total delay (base + jitter) to MAX_MS
    let total_ms = base_delay_ms.saturating_add(jitter_ms).min(BACKOFF_MAX_MS);

    Duration::from_millis(total_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_backoff_exponential_growth() {
        // Use seeded RNG for deterministic tests
        let mut rng = ChaCha8Rng::seed_from_u64(12345);

        // Attempt 1: base = 1000ms
        let d1 = calculate_backoff_with_rng(1, &mut rng);
        assert!(d1.as_millis() >= 1000 && d1.as_millis() < 1500);

        // Attempt 2: base = 2000ms
        let d2 = calculate_backoff_with_rng(2, &mut rng);
        assert!(d2.as_millis() >= 2000 && d2.as_millis() < 2500);

        // Attempt 3: base = 4000ms
        let d3 = calculate_backoff_with_rng(3, &mut rng);
        assert!(d3.as_millis() >= 4000 && d3.as_millis() < 4500);

        // Attempt 6: base = 32000ms
        let d6 = calculate_backoff_with_rng(6, &mut rng);
        assert!(d6.as_millis() >= 32000 && d6.as_millis() < 32500);
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);

        // Attempt 7+: base = 64000ms, but capped to 60000ms
        let d7 = calculate_backoff_with_rng(7, &mut rng);
        assert!(d7.as_millis() <= BACKOFF_MAX_MS as u128);

        // Very high attempt still capped
        let d100 = calculate_backoff_with_rng(100, &mut rng);
        assert!(d100.as_millis() <= BACKOFF_MAX_MS as u128);
    }

    #[test]
    fn test_backoff_jitter_within_range() {
        // Run multiple times with same seed to verify jitter is applied
        for seed in 0..10 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let d = calculate_backoff_with_rng(1, &mut rng);
            // Base is 1000ms, jitter is 0-499ms
            assert!(d.as_millis() >= 1000 && d.as_millis() < 1500);
        }
    }

    #[test]
    fn test_backoff_attempt_zero_treated_as_one() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        // Attempt 0 uses saturating_sub(1) = 0, so multiplier = 2^0 = 1
        let d0 = calculate_backoff_with_rng(0, &mut rng);
        assert!(d0.as_millis() >= 1000 && d0.as_millis() < 1500);
    }
}
