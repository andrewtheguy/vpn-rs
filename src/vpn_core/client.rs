//! VPN client implementation.
//!
//! The VPN client connects to a VPN server via iroh, performs handshake
//! to receive IP assignment, configures the TUN device, and manages the
//! IP-over-QUIC tunnel. IP packets are framed and sent directly over the
//! encrypted iroh QUIC connection for automatic NAT traversal.

use crate::vpn_core::buffer::{as_mut_byte_slice, uninitialized_vec};
use crate::vpn_core::config::VpnClientConfig;
use crate::vpn_core::device::{
    add_bypass_route, add_routes, add_routes6_with_src, BypassRouteGuard, Route6Guard, RouteGuard,
    TunConfig, TunDevice,
};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::lock::VpnLock;
use crate::vpn_core::offload::{segment_tcp_gso_packet, split_tun_frame};
use crate::vpn_core::signaling::{
    frame_capabilities_message, frame_ip_packet_v2, parse_ip_packet_v2, read_message,
    write_message, CapabilitiesMessage, DataMessageType, VpnHandshake, VpnHandshakeResponse,
    HEARTBEAT_PING_BYTE, MAX_HANDSHAKE_SIZE, VPN_ALPN,
};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use ipnet::{Ipv4Net, Ipv6Net};
use iroh::endpoint::{PathInfoList, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr, Watcher};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Maximum data-channel IP frame size (IP packet + optional offload metadata).
const MAX_IP_PACKET_SIZE: usize = 65536 + 64;

/// Heartbeat ping interval (how often client sends ping).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Heartbeat timeout (max time to wait for pong before triggering reconnection).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for outbound packets.
///
/// Sized to handle moderate bursts without masking backpressure. Smaller buffers
/// ensure the sender receives timely backpressure signals when the network is
/// congested, preventing excessive memory usage and latency buildup.
///
/// Memory impact (typical): ~1024 * ~1500 bytes (standard MTU) = ~1.5 MB.
/// Latency impact: At 100 Mbps, a full 1024-packet buffer adds ~120ms latency.
const OUTBOUND_CHANNEL_SIZE: usize = 1024;

/// Timeout for resolving relay URLs via DNS.
const RESOLVE_RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum wait for initial bypass route setup before continuing startup.
const INITIAL_BYPASS_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

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
///
/// At least one of IPv4 or IPv6 must be configured:
/// - IPv4-only: `assigned_ip`, `network`, `server_ip` are set; IPv6 fields are None
/// - IPv6-only: `assigned_ip6`, `network6`, `server_ip6` are set; IPv4 fields are None
/// - Dual-stack: Both IPv4 and IPv6 fields are set
#[non_exhaustive]
pub struct ServerInfo {
    /// Assigned VPN IP for this client (IPv4). None for IPv6-only mode.
    pub assigned_ip: Option<Ipv4Addr>,
    /// VPN network CIDR (IPv4). None for IPv6-only mode.
    pub network: Option<Ipv4Net>,
    /// Server's VPN IP (gateway, IPv4). None for IPv6-only mode.
    pub server_ip: Option<Ipv4Addr>,
    /// Assigned IPv6 VPN address for this client. None for IPv4-only mode.
    pub assigned_ip6: Option<Ipv6Addr>,
    /// IPv6 VPN network CIDR. None for IPv4-only mode.
    pub network6: Option<Ipv6Net>,
    /// Server's IPv6 VPN address (gateway). None for IPv4-only mode.
    pub server_ip6: Option<Ipv6Addr>,
    /// Whether server-side Linux TUN GSO is enabled.
    pub server_gso_enabled: bool,
}

impl VpnClient {
    /// Create a new VPN client.
    ///
    /// Acquires a single-instance lock (only one VPN client per process) and
    /// generates a random `device_id` (u64) for session identification.
    /// The device_id allows the server to distinguish multiple sessions from
    /// the same iroh endpoint.
    pub fn new(config: VpnClientConfig) -> VpnResult<Self> {
        config.validate().map_err(VpnError::config)?;

        // Acquire single-instance lock
        let lock = VpnLock::acquire()?;

        // Generate random device ID (unique per session)
        let device_id: u64 = rand::rng().random();
        log::info!("Generated device ID: {:016x}", device_id);

        Ok(Self {
            config,
            device_id,
            _lock: lock,
        })
    }

    /// Connect to the VPN server and establish the tunnel.
    ///
    /// # Arguments
    /// * `endpoint` - The iroh endpoint to use for the connection
    /// * `relay_urls` - Optional relay URLs to use as connection hints. When DNS
    ///   discovery is disabled, relay URLs are required for the connection to succeed.
    ///   iroh will attempt hole punching for direct P2P connections, falling back
    ///   to relay transport if needed.
    pub async fn connect(&self, endpoint: &Endpoint, relay_urls: &[String]) -> VpnResult<()> {
        // Parse server endpoint ID
        let server_id: EndpointId = self.config.server_node_id.parse().map_err(|e| {
            VpnError::config_with_source(
                format!("Invalid server node ID: {}", self.config.server_node_id),
                e,
            )
        })?;

        log::info!("Connecting to VPN server: {}", server_id);

        // Build EndpointAddr with relay hints if available.
        // When DNS discovery is disabled, relay URLs are required for the
        // connection to succeed. iroh uses the relay for initial connection
        // routing while still attempting hole punching for direct P2P.
        let endpoint_addr = if !relay_urls.is_empty() {
            let mut addr = EndpointAddr::new(server_id);
            for relay_url_str in relay_urls {
                let relay_url: RelayUrl = relay_url_str.parse().map_err(|e| {
                    VpnError::config_with_source(format!("Invalid relay URL: {}", relay_url_str), e)
                })?;
                addr = addr.with_relay_url(relay_url);
            }
            log::info!("Using {} relay hint(s) for connection", relay_urls.len());
            addr
        } else {
            EndpointAddr::new(server_id)
        };

        // Connect to server
        let connection = endpoint
            .connect(endpoint_addr, VPN_ALPN)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to connect to server: {}", e)))?;

        log::info!("Connected to server, performing handshake...");

        // Perform handshake on first stream
        let server_info = self.perform_handshake(&connection).await?;

        log::info!("Handshake successful:");
        // Log IPv4 info if provided
        if let Some(ip) = server_info.assigned_ip {
            log::info!("  Assigned IP: {}", ip);
        }
        if let Some(net) = server_info.network {
            log::info!("  Network: {}", net);
        }
        if let Some(gw) = server_info.server_ip {
            log::info!("  Gateway: {}", gw);
        }
        // Log IPv6 info if provided
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Assigned IPv6: {}", ip6);
        }
        if let Some(net6) = server_info.network6 {
            log::info!("  Network6: {}", net6);
        }
        if let Some(gw6) = server_info.server_ip6 {
            log::info!("  Gateway6: {}", gw6);
        }
        // Log mode
        if server_info.assigned_ip.is_none() {
            log::info!("  Mode: IPv6-only");
        } else if server_info.assigned_ip6.is_some() {
            log::info!("  Mode: dual-stack");
        } else {
            log::info!("  Mode: IPv4-only");
        }
        log::info!("  Server GSO enabled: {}", server_info.server_gso_enabled);

        // Create TUN device
        let tun_device = self.create_tun_device(&server_info)?;

        // Add bypass routes for the iroh connection BEFORE adding VPN routes.
        // This ensures the iroh connection (via relay or direct) continues to use
        // the original network path even if VPN routes would otherwise capture it.
        // Without this, VPN routes could black-hole the iroh connection traffic.
        //
        // This spawns a monitoring task that dynamically updates bypass routes as
        // the connection paths change (e.g., relay -> direct, new paths discovered).
        let will_add_routes = (server_info.assigned_ip.is_some() && !self.config.routes.is_empty())
            || (server_info.assigned_ip6.is_some() && !self.config.routes6.is_empty());
        let bypass_route_task: Option<JoinHandle<()>> = if will_add_routes {
            self.add_iroh_bypass_routes(endpoint, &connection, tun_device.name())
                .await
        } else {
            None
        };

        // Add custom IPv4 routes through the VPN (guard ensures cleanup on drop)
        // Only add IPv4 routes if server provided IPv4 and client has routes configured
        let _route_guard: Option<RouteGuard> =
            if server_info.assigned_ip.is_some() && !self.config.routes.is_empty() {
                Some(add_routes(tun_device.name(), &self.config.routes).await?)
            } else {
                None
            };

        // Add custom IPv6 routes through the VPN (guard ensures cleanup on drop)
        // Only add IPv6 routes if server provided IPv6 and client has routes6 configured
        // Use the assigned IPv6 as source to ensure correct source address selection
        // (important when client has multiple IPv6 addresses, e.g., public + VPN)
        let _route6_guard: Option<Route6Guard> =
            if let Some(assigned_ip6) = server_info.assigned_ip6 {
                if !self.config.routes6.is_empty() {
                    Some(
                        add_routes6_with_src(tun_device.name(), &self.config.routes6, assigned_ip6)
                            .await?,
                    )
                } else {
                    None
                }
            } else {
                None
            };

        // Open data stream for IP packets
        let (mut data_send, data_recv) = connection
            .open_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to open data stream: {}", e)))?;

        log::info!("VPN data stream opened");

        let local_gso_enabled = tun_device.offload_status().enabled;
        let negotiated_gso = local_gso_enabled && server_info.server_gso_enabled;
        // Data-channel GSO metadata is supported even when local TUN offload is not,
        // because inbound metadata can be fallback-segmented in software.
        let advertised_gso = true;
        log::info!(
            "GSO status (client): local={}, server={}, negotiated={}, advertised={}",
            local_gso_enabled,
            server_info.server_gso_enabled,
            negotiated_gso,
            advertised_gso
        );
        if !local_gso_enabled {
            let reason = tun_device
                .offload_status()
                .reason
                .as_deref()
                .unwrap_or("unknown reason");
            if server_info.server_gso_enabled {
                log::warn!("Local TUN GSO disabled: {}", reason);
            } else {
                log::info!("Local TUN GSO disabled: {}", reason);
            }
        }

        // Capabilities must be the first data-stream message in protocol v2.
        let mut capabilities_buf = BytesMut::with_capacity(2);
        frame_capabilities_message(
            &mut capabilities_buf,
            CapabilitiesMessage {
                gso_enabled: advertised_gso,
            },
        );
        data_send
            .write_all(&capabilities_buf)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to send capabilities: {}", e)))?;

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());
        if let Some(ip) = server_info.assigned_ip {
            log::info!("  Client IP: {}", ip);
        }
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Client IPv6: {}", ip6);
        }

        // Drop any tunneled UDP packets that target this endpoint's own iroh
        // socket ports. This prevents recursive self-encapsulation loops.
        let local_iroh_udp_ports = Arc::new(collect_local_iroh_udp_ports(endpoint));
        if !local_iroh_udp_ports.is_empty() {
            log::info!(
                "Filtering tunneled traffic for {} local iroh UDP port(s)",
                local_iroh_udp_ports.len()
            );
        }

        // Run the VPN packet loop (tunneled over iroh)
        // Pass the bypass route task so it's aborted when VPN ends
        self.run_vpn_loop(
            tun_device,
            data_send,
            data_recv,
            server_info.server_gso_enabled,
            bypass_route_task,
            local_iroh_udp_ports,
        )
        .await
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

        // Extract IPv4 info (optional, for IPv4-only or dual-stack)
        // All three IPv4 fields must be present together or all absent for consistency
        let (assigned_ip, network, server_ip) =
            match (response.assigned_ip, response.network, response.server_ip) {
                (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
                (None, None, None) => (None, None, None),
                _ => {
                    return Err(VpnError::Signaling(
                        "Server response has incomplete IPv4 configuration: \
                     assigned_ip, network, and server_ip must all be present or all absent"
                            .into(),
                    ));
                }
            };

        // Extract IPv6 info (optional, for IPv6-only or dual-stack)
        // All three IPv6 fields must be present together or all absent for consistency
        let (assigned_ip6, network6, server_ip6) = match (
            response.assigned_ip6,
            response.network6,
            response.server_ip6,
        ) {
            (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
            (None, None, None) => (None, None, None),
            _ => {
                return Err(VpnError::Signaling(
                    "Server response has incomplete IPv6 configuration: \
                     assigned_ip6, network6, and server_ip6 must all be present or all absent"
                        .into(),
                ));
            }
        };

        // At least one of IPv4 or IPv6 must be provided
        if assigned_ip.is_none() && assigned_ip6.is_none() {
            return Err(VpnError::Signaling(
                "Server response missing both IPv4 and IPv6 configuration".into(),
            ));
        }

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
            server_gso_enabled: response.server_gso_enabled,
        })
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self, server_info: &ServerInfo) -> VpnResult<TunDevice> {
        // Build TUN config based on what the server provided.
        // Match includes all fields explicitly to be defensive against future validation changes
        // in perform_handshake and avoid implicit assumptions about grouped fields.
        let mut tun_config = match (
            server_info.assigned_ip,
            server_info.network,
            server_info.server_ip,
            server_info.assigned_ip6,
            server_info.network6,
            server_info.server_ip6,
        ) {
            // Dual-stack: both IPv4 and IPv6
            (Some(ip4), Some(net4), Some(gw4), Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::new(ip4, net4.netmask(), gw4)
                    .with_mtu(self.config.mtu)
                    .with_ipv6(ip6, net6.prefix_len())?
            }
            // IPv4-only
            (Some(ip4), Some(net4), Some(gw4), None, None, None) => {
                TunConfig::new(ip4, net4.netmask(), gw4).with_mtu(self.config.mtu)
            }
            // IPv6-only
            (None, None, None, Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::ipv6_only(ip6, net6.prefix_len(), self.config.mtu)?
            }
            // Invalid: should be caught earlier in perform_handshake
            _ => {
                return Err(VpnError::Signaling(
                    "Invalid server info: need at least one complete IP configuration".into(),
                ))
            }
        };
        tun_config = tun_config.with_gso(server_info.server_gso_enabled);

        TunDevice::create(tun_config)
    }

    /// Add bypass routes for iroh connection addresses and spawn a monitoring task.
    ///
    /// Queries the connection paths from the iroh connection and adds bypass routes for:
    /// - Direct connection addresses (UDP socket addresses)
    /// - Relay server addresses (resolved from relay URLs)
    ///
    /// This function waits for the initial bypass route setup to complete before
    /// returning, ensuring VPN routes are not added until bypass routes are in place.
    /// This prevents the iroh connection from being black-holed by VPN routes.
    ///
    /// Also spawns a background task that monitors path changes and dynamically
    /// updates bypass routes as the connection evolves
    /// (e.g., from relay to direct, or when new paths are discovered).
    ///
    /// Returns:
    /// - A task handle for the monitoring task (caller should abort on shutdown)
    /// - The monitoring task owns all bypass route guards internally
    async fn add_iroh_bypass_routes(
        &self,
        endpoint: &Endpoint,
        connection: &iroh::endpoint::Connection,
        vpn_tun_name: &str,
    ) -> Option<JoinHandle<()>> {
        // Get the paths watcher
        let paths_watcher = connection.paths();

        // Clone endpoint for the spawned task
        let endpoint_clone = endpoint.clone();
        let vpn_tun_name = vpn_tun_name.to_string();
        let initial_routes = HashMap::new();

        // Create oneshot channel to signal when initial setup is complete
        let (setup_done_tx, setup_done_rx) = tokio::sync::oneshot::channel();

        // Spawn a task that manages bypass routes dynamically
        let handle = tokio::spawn(async move {
            run_bypass_route_manager(
                endpoint_clone,
                paths_watcher,
                Some(setup_done_tx),
                vpn_tun_name,
                initial_routes,
            )
            .await;
        });

        // Wait for initial bypass route setup to complete before returning.
        // This ensures VPN routes are not added until bypass routes are in place.
        match tokio::time::timeout(INITIAL_BYPASS_SETUP_TIMEOUT, setup_done_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                log::warn!("Bypass route manager task ended before initial setup completed");
            }
            Err(_) => {
                log::warn!(
                    "Initial bypass setup timed out after {:.1}s, continuing startup",
                    INITIAL_BYPASS_SETUP_TIMEOUT.as_secs_f64()
                );
            }
        }

        Some(handle)
    }

    /// Run the VPN packet processing loop (tunneled over iroh QUIC).
    async fn run_vpn_loop(
        &self,
        tun_device: TunDevice,
        data_send: SendStream,
        data_recv: RecvStream,
        server_gso_enabled: bool,
        bypass_route_task: Option<JoinHandle<()>>,
        local_iroh_udp_ports: Arc<HashSet<u16>>,
    ) -> VpnResult<()> {
        // Split TUN device
        let (mut tun_reader, mut tun_writer) = tun_device.split()?;
        let local_gso_enabled = tun_reader.offload_status().enabled;
        debug_assert_eq!(local_gso_enabled, tun_writer.offload_status().enabled);
        let negotiated_gso = local_gso_enabled && server_gso_enabled;
        let buffer_size = tun_reader.buffer_size();

        // Create channel for outbound data to decouple packet production from stream writes.
        // The writer task owns the SendStream and performs actual I/O, eliminating
        // per-packet mutex overhead from the TUN reader and heartbeat tasks.
        // Uses Bytes for zero-copy sends (freeze BytesMut instead of cloning Vec).
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_SIZE);
        let outbound_tx_heartbeat = outbound_tx.clone();

        // Spawn dedicated writer task that owns the SendStream.
        // Uses batch receives and chunked QUIC writes for better throughput.
        // Returns error context if write fails for inclusion in shutdown reason.
        let mut writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let mut data_send = data_send;
            let mut batch = Vec::with_capacity(64);
            loop {
                let count = outbound_rx.recv_many(&mut batch, 64).await;
                if count == 0 {
                    log::trace!("Writer task exiting");
                    break;
                }
                if let Err(e) = data_send.write_all_chunks(batch.as_mut_slice()).await {
                    log::warn!("Failed to write to QUIC stream: {}", e);
                    return Some(format!("QUIC write error: {}", e));
                }
                batch.clear();
            }
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
        // Memory note: Each packet requires a small allocation (5 bytes framing + packet length).
        // We allocate based on actual packet size to avoid over-allocation for small packets.
        // Most allocations are small and served from thread-local caches, making them fast.
        let mut outbound_handle: tokio::task::JoinHandle<Option<String>> =
            tokio::spawn(async move {
                let mut read_buf = uninitialized_vec(buffer_size);
                // SAFETY: Buffer is immediately overwritten by tun_reader.read(), and only
                // the written portion (&read_slice[..n]) is accessed. Skips zeroing overhead.
                let read_slice = unsafe { as_mut_byte_slice(&mut read_buf) };
                loop {
                    match tun_reader.read(read_slice).await {
                        Ok(n) if n > 0 => {
                            let raw_packet = &read_slice[..n];
                            let (offload, packet) =
                                match split_tun_frame(raw_packet, tun_reader.vnet_hdr_enabled()) {
                                    Ok(parts) => parts,
                                    Err(e) => {
                                        log::warn!("Failed to parse TUN frame: {}", e);
                                        continue;
                                    }
                                };

                            if packet_has_local_iroh_udp_port(packet, &local_iroh_udp_ports) {
                                log::debug!(
                                    "Dropped self-encapsulated iroh UDP packet from TUN ({} bytes)",
                                    n
                                );
                                continue;
                            }

                            if let Some(meta) = offload {
                                if !negotiated_gso {
                                    match segment_tcp_gso_packet(&meta, packet) {
                                        Ok(segments) => {
                                            for seg in segments {
                                                let frame_size = 1 + 4 + 1 + seg.len();
                                                let mut write_buf =
                                                    BytesMut::with_capacity(frame_size);
                                                if let Err(e) =
                                                    frame_ip_packet_v2(&mut write_buf, None, &seg)
                                                {
                                                    log::warn!(
                                                        "Failed to frame segmented packet: {}",
                                                        e
                                                    );
                                                    continue;
                                                }
                                                if outbound_tx
                                                    .send(write_buf.freeze())
                                                    .await
                                                    .is_err()
                                                {
                                                    log::warn!("Outbound channel closed");
                                                    return None;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "Failed to fallback-segment TCP GSO packet: {}",
                                                e
                                            );
                                        }
                                    }
                                    continue;
                                }
                            }

                            // Allocate buffer sized to actual frame
                            let frame_size = 1
                                + 4
                                + 1
                                + offload
                                    .map(|_| crate::vpn_core::offload::VIRTIO_NET_HDR_LEN)
                                    .unwrap_or(0)
                                + packet.len();
                            let mut write_buf = BytesMut::with_capacity(frame_size);
                            if let Err(e) =
                                frame_ip_packet_v2(&mut write_buf, offload.as_ref(), packet)
                            {
                                log::warn!("Failed to frame packet: {}", e);
                                continue;
                            }

                            if outbound_tx.send(write_buf.freeze()).await.is_err() {
                                log::warn!("Outbound channel closed");
                                return None;
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
        let mut inbound_handle: tokio::task::JoinHandle<Option<String>> =
            tokio::spawn(async move {
                const MAX_TUN_WRITE_FAILURES: u32 = 10;
                let mut data_recv = data_recv;
                let mut type_buf = [0u8; 1];
                let mut len_buf = [0u8; 4];
                let mut data_buf = uninitialized_vec(MAX_IP_PACKET_SIZE);
                // SAFETY: Buffer is overwritten by read_exact(&mut data_slice[..len]), and only
                // the written portion (&data_slice[..len]) is accessed. Skips zeroing overhead.
                let data_slice = unsafe { as_mut_byte_slice(&mut data_buf) };
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
                            log::error!(
                                "Unknown message type: 0x{:02x}, disconnecting",
                                type_buf[0]
                            );
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
                        DataMessageType::Capabilities => {
                            // Capabilities are exchanged once at stream setup and should not
                            // appear later in steady-state traffic.
                            log::trace!("Unexpected capabilities message received");
                            continue;
                        }
                    }

                    // Read frame length for IP packet
                    match data_recv.read_exact(&mut len_buf).await {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("Failed to read IP frame length: {}", e);
                            return Some(format!("QUIC read error: {}", e));
                        }
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len > MAX_IP_PACKET_SIZE {
                        log::error!("IP frame too large: {}", len);
                        return Some(format!("IP frame too large: {}", len));
                    }

                    // Read frame payload
                    match data_recv.read_exact(&mut data_slice[..len]).await {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("Failed to read IP frame: {}", e);
                            return Some(format!("QUIC read error: {}", e));
                        }
                    }

                    let frame = &data_slice[..len];
                    let (offload, packet) = match parse_ip_packet_v2(frame) {
                        Ok(parts) => parts,
                        Err(e) => {
                            log::warn!("Invalid IP frame from peer: {}", e);
                            continue;
                        }
                    };

                    let write_result = if let Some(meta) = offload {
                        if !local_gso_enabled {
                            match segment_tcp_gso_packet(&meta, packet) {
                                Ok(segments) => {
                                    let mut result = Ok(());
                                    for seg in segments {
                                        if let Err(e) = tun_writer.write_all(&seg).await {
                                            result = Err(e);
                                            break;
                                        }
                                    }
                                    result
                                }
                                Err(e) => {
                                    log::warn!(
                                        "Dropping packet with unsupported offload metadata: {}",
                                        e
                                    );
                                    continue;
                                }
                            }
                        } else {
                            tun_writer.write_packet(Some(&meta), packet).await
                        }
                    } else {
                        tun_writer.write_all(packet).await
                    };

                    if let Err(e) = write_result {
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
        let mut heartbeat_handle: tokio::task::JoinHandle<Option<String>> =
            tokio::spawn(async move {
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

        // Abort the bypass route monitoring task if it exists
        if let Some(ref task) = bypass_route_task {
            task.abort();
        }

        // Await all remaining handles to ensure cleanup (aborted tasks return Cancelled)
        let mut all_results = vec![(first_task, first_result)];
        for (name, handle) in remaining {
            all_results.push((name, handle.await));
        }

        // Wait for bypass route task to clean up (guards will be dropped)
        if let Some(task) = bypass_route_task {
            let _ = task.await;
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
    /// * `relay_urls` - Optional relay URLs to use as connection hints. When DNS
    ///   discovery is disabled, relay URLs are required for the connection to succeed.
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
        relay_urls: &[String],
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

            match self.connect(endpoint, relay_urls).await {
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

// ============================================================================
// Bypass Route Management
// ============================================================================

/// Manages bypass routes dynamically based on connection path changes.
///
/// Tracks active bypass routes in a HashMap keyed by IP address (not socket address).
/// This is because bypass routes are per-IP, not per-port - multiple socket addresses
/// on the same IP should share a single bypass route.
struct BypassRouteManager {
    /// Currently active bypass route guards, keyed by IP address.
    /// Dropping a guard removes the corresponding route.
    active_routes: HashMap<IpAddr, BypassRouteGuard>,
    /// Name of the VPN TUN interface; bypass routes must never resolve through it.
    vpn_tun_name: String,
}

impl BypassRouteManager {
    fn new(vpn_tun_name: String, active_routes: HashMap<IpAddr, BypassRouteGuard>) -> Self {
        Self {
            active_routes,
            vpn_tun_name,
        }
    }

    /// Update bypass routes based on a new set of required IP addresses.
    ///
    /// - Adds routes for new addresses first
    /// - Removes routes for addresses no longer needed only after successful adds
    ///
    /// If any new route cannot be added, no removals are performed so existing
    /// underlay reachability is preserved.
    async fn update(&mut self, required_ips: HashSet<IpAddr>) {
        // Stage additions first so we don't tear down working routes on partial failures.
        let to_add: Vec<IpAddr> = required_ips
            .iter()
            .filter(|ip| !self.active_routes.contains_key(ip))
            .copied()
            .collect();

        let mut staged_guards = Vec::with_capacity(to_add.len());

        for ip in to_add {
            let socket_addr = SocketAddr::new(ip, 443); // bypass routes are per-IP
            match add_bypass_route(socket_addr, Some(&self.vpn_tun_name)).await {
                Ok(guard) => {
                    log::info!("Added bypass route for iroh address {}", ip);
                    staged_guards.push((ip, guard));
                }
                Err(err) => {
                    log::warn!(
                        "Failed to add bypass route for {} (keeping existing routes): {}",
                        ip,
                        err
                    );
                    return;
                }
            }
        }

        // Commit staged additions now that all new routes succeeded.
        for (ip, guard) in staged_guards {
            self.active_routes.insert(ip, guard);
        }

        // Remove routes for addresses no longer in the required set.
        let to_remove: Vec<IpAddr> = self
            .active_routes
            .keys()
            .filter(|ip| !required_ips.contains(ip))
            .copied()
            .collect();

        for ip in to_remove {
            log::info!("Removing stale bypass route for {}", ip);
            self.active_routes.remove(&ip);
            // Guard is dropped here, which removes the route
        }
    }
}

/// Run the bypass route manager task.
///
/// Monitors path changes via the watcher stream and dynamically
/// updates bypass routes as the connection evolves.
///
/// Returns after initial setup is complete, continuing to monitor in background.
/// The returned oneshot receiver signals when initial setup is done.
async fn run_bypass_route_manager(
    endpoint: Endpoint,
    mut paths_watcher: impl Watcher<Value = PathInfoList> + Send + Unpin + 'static,
    initial_setup_done: Option<tokio::sync::oneshot::Sender<()>>,
    vpn_tun_name: String,
    initial_routes: HashMap<IpAddr, BypassRouteGuard>,
) {
    let mut manager = BypassRouteManager::new(vpn_tun_name, initial_routes);

    // Process initial connection paths.
    let initial_paths = paths_watcher.get();
    let initial_result = collect_addresses_from_paths(&endpoint, &initial_paths).await;
    if initial_result.preserve_routes {
        log::warn!("Initial bypass route update skipped - keeping existing routes");
    } else {
        manager.update(initial_result.ips).await;
    }

    // Watch for changes using stream_updates_only (skips initial value we already processed)
    let mut stream = paths_watcher.stream_updates_only();

    // Ensure initial setup does not report success until we have at least one
    // active bypass route, unless the watcher ends.
    while manager.active_routes.is_empty() {
        let Some(paths) = stream.next().await else {
            break;
        };
        let result = collect_addresses_from_paths(&endpoint, &paths).await;
        if result.preserve_routes {
            log::warn!("Initial bypass route update skipped - keeping existing routes");
            continue;
        }
        manager.update(result.ips).await;
    }

    // Signal that initial setup is complete
    if let Some(tx) = initial_setup_done {
        let _ = tx.send(());
    }

    while let Some(paths) = stream.next().await {
        log::debug!("Connection paths changed: {:?}", paths);
        let result = collect_addresses_from_paths(&endpoint, &paths).await;

        // Skip update if we should preserve existing routes (e.g., no paths yet or DNS failure)
        // to avoid disconnecting the relay during transient outages
        if result.preserve_routes {
            log::debug!("Bypass route update skipped: no paths yet or DNS resolution failed");
            log::warn!("Skipping bypass route update - keeping existing routes");
            continue;
        }

        manager.update(result.ips).await;
    }

    log::debug!("Bypass route manager task ending (watcher disconnected)");
    // When this function returns, manager is dropped, which drops all guards
    // and removes all bypass routes
}

/// Result of collecting addresses from active connection paths.
struct CollectAddressesResult {
    /// Set of unique IP addresses that need bypass routes.
    ips: HashSet<IpAddr>,
    /// Whether to preserve existing routes rather than updating.
    preserve_routes: bool,
}

/// Extract IP addresses from the active iroh paths that need bypass routes.
///
/// Returns a set of unique IP addresses (deduplicated from socket addresses)
/// and a flag indicating whether DNS resolution failed.
async fn collect_addresses_from_paths(
    endpoint: &Endpoint,
    paths: &PathInfoList,
) -> CollectAddressesResult {
    let mut ips = HashSet::new();
    let mut preserve_routes = false;

    if paths.is_empty() {
        log::debug!("iroh connection has no paths yet; preserving existing bypass routes");
        preserve_routes = true;
        return CollectAddressesResult {
            ips,
            preserve_routes,
        };
    }

    for path in paths.iter() {
        let selected = if path.is_selected() {
            " (selected)"
        } else {
            ""
        };
        let remote = path.remote_addr();
        match remote {
            TransportAddr::Ip(addr) => {
                log::debug!("iroh path{} direct {}", selected, addr);
                ips.insert(addr.ip());
            }
            TransportAddr::Relay(relay_url) => {
                log::debug!("iroh path{} relay {}", selected, relay_url);
                match resolve_relay_url(endpoint, relay_url).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            ips.insert(addr.ip());
                        }
                    }
                    Err(()) => {
                        preserve_routes = true;
                    }
                }
            }
            _ => log::debug!("iroh path{} unknown {:?}", selected, remote),
        }
    }

    if ips.is_empty() {
        log::warn!("No usable iroh transport addresses found; preserving existing bypass routes");
        preserve_routes = true;
    }

    CollectAddressesResult {
        ips,
        preserve_routes,
    }
}

/// Resolve a relay URL to socket addresses using the endpoint's DNS resolver.
///
/// Handles both IP-literal URLs (e.g., `https://192.168.1.1:443`) and hostname URLs.
/// IP-literals are returned directly without DNS lookup.
///
/// Returns:
/// - `Ok(addresses)` on successful resolution (may be empty if host has no addresses)
/// - `Err(())` if DNS resolution failed (caller should preserve existing routes)
async fn resolve_relay_url(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
) -> Result<Vec<SocketAddr>, ()> {
    // Extract host from relay URL
    let Some(host) = relay_url.host_str() else {
        log::warn!("Relay URL {} has no host", relay_url);
        return Ok(Vec::new()); // Not a DNS failure, just no host
    };
    let port = relay_url.port().unwrap_or(443);

    // Handle IP-literal URLs without DNS lookup
    if let Ok(ip) = host.parse::<IpAddr>() {
        let socket_addr = SocketAddr::new(ip, port);
        log::debug!("Relay URL {} is IP-literal: {}", relay_url, socket_addr);
        return Ok(vec![socket_addr]);
    }

    // Try to resolve the hostname with a reasonable timeout
    let resolver = endpoint.dns_resolver();
    match resolver.lookup_ipv4_ipv6(host, RESOLVE_RELAY_TIMEOUT).await {
        Ok(addrs) => {
            let socket_addrs: Vec<SocketAddr> = addrs.map(|ip| SocketAddr::new(ip, port)).collect();
            log::debug!(
                "Resolved relay {} to {} address(es)",
                relay_url,
                socket_addrs.len()
            );
            Ok(socket_addrs)
        }
        Err(e) => {
            log::warn!("Failed to resolve relay URL {}: {}", relay_url, e);
            Err(()) // Signal DNS failure
        }
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
    calculate_backoff_with_rng(attempt, &mut rand::rng())
}

/// Calculate exponential backoff delay with a custom RNG.
///
/// This is the testable version that accepts an RNG parameter.
/// Production code should use `calculate_backoff()` which uses `rand::rng()`.
///
/// # Arguments
/// * `attempt` - Current attempt number (1-based)
/// * `rng` - Random number generator for jitter
fn calculate_backoff_with_rng(attempt: u32, rng: &mut impl Rng) -> Duration {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, ...
    let multiplier = 2_u64.saturating_pow(attempt.saturating_sub(1));
    let base_delay_ms = BACKOFF_BASE_MS.saturating_mul(multiplier);

    // Add jitter to prevent thundering herd (unbiased via random_range)
    let jitter_ms = rng.random_range(0..BACKOFF_JITTER_MS);

    // Cap total delay (base + jitter) to MAX_MS
    let total_ms = base_delay_ms.saturating_add(jitter_ms).min(BACKOFF_MAX_MS);

    Duration::from_millis(total_ms)
}

/// Collect local UDP ports bound by the iroh endpoint.
fn collect_local_iroh_udp_ports(endpoint: &Endpoint) -> HashSet<u16> {
    endpoint.addr().ip_addrs().map(|addr| addr.port()).collect()
}

/// Return true if packet is UDP and either source/destination port matches a blocked port.
#[inline]
fn packet_has_local_iroh_udp_port(packet: &[u8], blocked_ports: &HashSet<u16>) -> bool {
    if blocked_ports.is_empty() {
        return false;
    }
    let Some((src_port, dst_port)) = extract_udp_ports(packet) else {
        return false;
    };
    blocked_ports.contains(&src_port) || blocked_ports.contains(&dst_port)
}

/// Extract UDP source/destination ports from an IPv4/IPv6 packet.
///
/// For IPv6, only packets with UDP as the first next-header are parsed.
#[inline]
fn extract_udp_ports(packet: &[u8]) -> Option<(u16, u16)> {
    const IPV4_MIN_HEADER_BYTES: usize = 20;
    const IPV6_MIN_HEADER_BYTES: usize = 40;

    if packet.len() < IPV4_MIN_HEADER_BYTES {
        return None;
    }

    match packet[0] >> 4 {
        4 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER_BYTES || packet.len() < ihl + 8 {
                return None;
            }
            if packet[9] != 17 {
                return None;
            }
            let src = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            Some((src, dst))
        }
        6 => {
            if packet.len() < IPV6_MIN_HEADER_BYTES + 8 {
                return None;
            }
            if packet[6] != 17 {
                return None;
            }
            let src = u16::from_be_bytes([packet[40], packet[41]]);
            let dst = u16::from_be_bytes([packet[42], packet[43]]);
            Some((src, dst))
        }
        _ => None,
    }
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
