//! VPN client implementation.
//!
//! The VPN client connects a loopback UDP socket to a local tunnel endpoint,
//! performs a (retransmitted) handshake to receive its IP assignment, configures
//! the TUN device, and shovels framed IP packets between the TUN device and the
//! UDP socket. The external tunnel forwards the loopback datagrams across the
//! network and provides encryption + authentication.

use crate::vpn_core::buffer::uninitialized_vec;
use crate::vpn_core::config::VpnClientConfig;
use crate::vpn_core::datagram::{
    build_datagrams, build_gro_datagrams, classify, Datagram, FRAME_ARENA_CHUNK,
    MAX_DATAGRAM_PAYLOAD,
};
use crate::vpn_core::device::{
    add_routes, add_routes6_with_src, Route6Guard, RouteGuard, TunConfig, TunDevice,
};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::lock::VpnLock;
use crate::vpn_core::offload::{materialize_offload_into, TcpGroTable, VirtioNetHdr};
use crate::vpn_core::file_config::Transport;
use crate::vpn_core::signaling::{
    encode_capabilities_datagram, frame_capabilities_message, parse_ip_packet_v2, read_message,
    write_message, CapabilitiesMessage, VpnHandshake, VpnHandshakeResponse, HEARTBEAT_PING_BYTE,
    HEARTBEAT_PONG_BYTE, MAX_HANDSHAKE_SIZE,
};
use crate::vpn_core::tcp::connect_tcp_stream;
use crate::vpn_core::tunnel::run_tunnel;
use crate::vpn_core::udp::{connect_client_socket, RECV_BUFFER_SIZE};
use bytes::{Bytes, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Heartbeat ping interval (how often client sends ping).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Heartbeat timeout (max time to wait for pong before triggering reconnection).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-attempt timeout while waiting for the handshake response datagram.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum handshake datagram (re)transmissions before giving up this attempt.
const HANDSHAKE_RETRIES: u32 = 5;

/// Channel buffer size for inbound packets queued to the TUN writer task.
const INBOUND_TUN_CHANNEL_SIZE: usize = 512;

/// Maximum number of inbound writes drained from the channel per batch.
const WRITE_BATCH_SIZE: usize = 256;

/// A decoded inbound packet queued for the dedicated TUN writer task.
struct InboundTunWrite {
    packet: Bytes,
    offload: Option<VirtioNetHdr>,
}

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
    /// MTU dictated by the server for the client TUN device.
    pub mtu: u16,
}

impl VpnClient {
    /// Create a new VPN client.
    ///
    /// Acquires a single-instance lock (only one VPN client per process) and
    /// generates a random `device_id` (u64) for session identification. The
    /// device_id lets the server return the same assigned IP across reconnects
    /// even when the UDP source port changes.
    pub fn new(config: VpnClientConfig) -> VpnResult<Self> {
        config.validate()?;

        let lock = VpnLock::acquire()?;

        let device_id: u64 = rand::rng().random();
        log::info!("Generated device ID: {:016x}", device_id);

        Ok(Self {
            config,
            device_id,
            _lock: lock,
        })
    }

    /// Connect to the VPN server (via the local tunnel) and run the tunnel,
    /// dispatching on the configured transport.
    pub async fn connect(&self) -> VpnResult<()> {
        match self.config.transport {
            Transport::Tcp => self.connect_tcp().await,
            Transport::Udp => self.connect_udp().await,
        }
    }

    /// Connect over a loopback UDP socket and run the UDP pipeline.
    async fn connect_udp(&self) -> VpnResult<()> {
        let socket = connect_client_socket(
            self.config.server_addr,
            self.config.test_mode,
            self.config.recv_buffer_size,
            self.config.send_buffer_size,
        )
        .await?;
        log::info!(
            "Connecting to VPN server via local tunnel at {} (UDP)",
            self.config.server_addr
        );

        let server_info = self.perform_handshake(&socket).await?;
        Self::log_server_info(&server_info);

        let tun_device = self.create_tun_device(&server_info)?;
        let (_route_guard, _route6_guard) = self.add_vpn_routes(&tun_device, &server_info).await?;
        Self::log_gso(&server_info, &tun_device);

        let socket = Arc::new(socket);

        // Advertise our capabilities (a single datagram). UDP is unordered, so
        // the server defaults to GSO-off until this arrives — always safe.
        let caps = encode_capabilities_datagram(CapabilitiesMessage { gso_enabled: true });
        socket
            .send(&caps)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to send capabilities: {}", e)))?;

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());

        run_udp_tunnel(tun_device, socket, server_info.server_gso_enabled).await
    }

    /// Connect over a single TCP stream and run the shared `run_tunnel` pipeline.
    async fn connect_tcp(&self) -> VpnResult<()> {
        let stream = connect_tcp_stream(
            self.config.server_addr,
            self.config.test_mode,
            self.config.recv_buffer_size,
            self.config.send_buffer_size,
        )
        .await?;
        log::info!(
            "Connecting to VPN server via local tunnel at {} (TCP)",
            self.config.server_addr
        );
        let (mut read_half, mut write_half) = stream.into_split();

        // Handshake: TCP is reliable, so a single request/response (no
        // retransmit loop) suffices. The token gates test-mode pairing. The
        // whole exchange is bounded by HANDSHAKE_TIMEOUT so a server that
        // accepts the connection but never replies fails fast (and is retried by
        // the reconnect loop) instead of hanging forever.
        let request = VpnHandshake::new(self.device_id, self.config.test_token.clone()).encode()?;
        let resp_data = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            write_message(&mut write_half, &request).await?;
            read_message(&mut read_half, MAX_HANDSHAKE_SIZE).await
        })
        .await
        .map_err(|_| {
            VpnError::ConnectionLost(format!(
                "no handshake response within {:.0}s",
                HANDSHAKE_TIMEOUT.as_secs_f64()
            ))
        })??;
        let response = VpnHandshakeResponse::decode(&resp_data)?;
        if !response.accepted {
            let reason = response
                .reject_reason
                .unwrap_or_else(|| "Unknown".to_string());
            return Err(VpnError::AuthenticationFailed(reason));
        }
        let server_info = Self::server_info_from_response(response)?;
        Self::log_server_info(&server_info);

        let tun_device = self.create_tun_device(&server_info)?;
        let (_route_guard, _route6_guard) = self.add_vpn_routes(&tun_device, &server_info).await?;
        Self::log_gso(&server_info, &tun_device);

        // Capabilities is the first data-stream message. Advertise GSO: inbound
        // offload metadata can be materialized in software even without local
        // TUN offload.
        let mut caps_buf = BytesMut::with_capacity(3);
        frame_capabilities_message(&mut caps_buf, CapabilitiesMessage { gso_enabled: true });
        write_half
            .write_all(&caps_buf)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to send capabilities: {}", e)))?;

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());

        run_tunnel(tun_device, write_half, read_half, server_info.server_gso_enabled).await
    }

    /// Log the accepted handshake's assigned addresses, mode, GSO, and MTU.
    fn log_server_info(server_info: &ServerInfo) {
        log::info!("Handshake successful:");
        if let Some(ip) = server_info.assigned_ip {
            log::info!("  Assigned IP: {}", ip);
        }
        if let Some(net) = server_info.network {
            log::info!("  Network: {}", net);
        }
        if let Some(gw) = server_info.server_ip {
            log::info!("  Gateway: {}", gw);
        }
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Assigned IPv6: {}", ip6);
        }
        if let Some(net6) = server_info.network6 {
            log::info!("  Network6: {}", net6);
        }
        if let Some(gw6) = server_info.server_ip6 {
            log::info!("  Gateway6: {}", gw6);
        }
        if server_info.assigned_ip.is_none() {
            log::info!("  Mode: IPv6-only");
        } else if server_info.assigned_ip6.is_some() {
            log::info!("  Mode: dual-stack");
        } else {
            log::info!("  Mode: IPv4-only");
        }
        log::info!("  Server GSO enabled: {}", server_info.server_gso_enabled);
        log::info!("  MTU (server-dictated): {}", server_info.mtu);
    }

    /// Add the configured IPv4/IPv6 routes through the VPN, returning guards that
    /// remove the routes on drop. Routes are only added for an assigned family.
    async fn add_vpn_routes(
        &self,
        tun_device: &TunDevice,
        server_info: &ServerInfo,
    ) -> VpnResult<(Option<RouteGuard>, Option<Route6Guard>)> {
        let route_guard: Option<RouteGuard> =
            if server_info.assigned_ip.is_some() && !self.config.routes.is_empty() {
                Some(add_routes(tun_device.name(), &self.config.routes).await?)
            } else {
                None
            };

        // Use the assigned IPv6 as source so source-address selection prefers
        // the VPN address.
        let route6_guard: Option<Route6Guard> = match server_info.assigned_ip6 {
            Some(assigned_ip6) if !self.config.routes6.is_empty() => Some(
                add_routes6_with_src(tun_device.name(), &self.config.routes6, assigned_ip6).await?,
            ),
            _ => None,
        };

        Ok((route_guard, route6_guard))
    }

    /// Log local/server/negotiated GSO status for the established TUN device.
    fn log_gso(server_info: &ServerInfo, tun_device: &TunDevice) {
        let offload_status = tun_device.offload_status();
        let local_gso_enabled = offload_status.enabled;
        let negotiated_gso = local_gso_enabled && server_info.server_gso_enabled;
        // Data-channel GSO metadata is supported even when the local TUN offload
        // is not, because inbound metadata can be materialized in software.
        let advertised_gso = true;
        log::info!(
            "GSO status (client): local={}, server={}, negotiated={}, advertised={}",
            local_gso_enabled,
            server_info.server_gso_enabled,
            negotiated_gso,
            advertised_gso
        );
        if !local_gso_enabled {
            let reason = offload_status.reason.as_deref().unwrap_or("unknown reason");
            log::info!("Local TUN GSO disabled: {}", reason);
        }
    }

    /// Perform the VPN handshake, retransmitting the request until a response
    /// arrives (datagrams may be lost).
    async fn perform_handshake(&self, socket: &UdpSocket) -> VpnResult<ServerInfo> {
        let request =
            VpnHandshake::new(self.device_id, self.config.test_token.clone()).encode()?;
        let mut buf = vec![0u8; RECV_BUFFER_SIZE];

        for attempt in 1..=HANDSHAKE_RETRIES {
            socket
                .send(&request)
                .await
                .map_err(|e| VpnError::Signaling(format!("Failed to send handshake: {}", e)))?;

            match tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    // The handshake response is a raw JSON datagram. Anything
                    // else this early (e.g. an early data datagram, type byte
                    // 0x00..=0x03) is ignored and we retransmit.
                    match VpnHandshakeResponse::decode(&buf[..n]) {
                        Ok(response) => {
                            if !response.accepted {
                                let reason = response
                                    .reject_reason
                                    .unwrap_or_else(|| "Unknown".to_string());
                                return Err(VpnError::AuthenticationFailed(reason));
                            }
                            return Self::server_info_from_response(response);
                        }
                        Err(e) => {
                            log::trace!("Ignoring non-handshake datagram during handshake: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    return Err(VpnError::Network(e));
                }
                Err(_) => {
                    log::debug!(
                        "Handshake response timed out (attempt {}/{}), retransmitting",
                        attempt,
                        HANDSHAKE_RETRIES
                    );
                }
            }
        }

        Err(VpnError::ConnectionLost(format!(
            "no handshake response after {} attempts",
            HANDSHAKE_RETRIES
        )))
    }

    /// Validate and convert an accepted handshake response into [`ServerInfo`].
    fn server_info_from_response(response: VpnHandshakeResponse) -> VpnResult<ServerInfo> {
        let (assigned_ip, network, server_ip) =
            match (response.assigned_ip, response.network, response.server_ip) {
                (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
                (None, None, None) => (None, None, None),
                _ => {
                    return Err(VpnError::Signaling(
                        "Server response has incomplete IPv4 configuration".into(),
                    ));
                }
            };

        let (assigned_ip6, network6, server_ip6) = match (
            response.assigned_ip6,
            response.network6,
            response.server_ip6,
        ) {
            (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
            (None, None, None) => (None, None, None),
            _ => {
                return Err(VpnError::Signaling(
                    "Server response has incomplete IPv6 configuration".into(),
                ));
            }
        };

        if assigned_ip.is_none() && assigned_ip6.is_none() {
            return Err(VpnError::Signaling(
                "Server response missing both IPv4 and IPv6 configuration".into(),
            ));
        }

        Ok(ServerInfo {
            assigned_ip,
            network,
            server_ip,
            assigned_ip6,
            network6,
            server_ip6,
            server_gso_enabled: response.server_gso_enabled,
            mtu: response.mtu,
        })
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self, server_info: &ServerInfo) -> VpnResult<TunDevice> {
        let mut tun_config = match (
            server_info.assigned_ip,
            server_info.network,
            server_info.server_ip,
            server_info.assigned_ip6,
            server_info.network6,
            server_info.server_ip6,
        ) {
            // Dual-stack
            (Some(ip4), Some(net4), Some(gw4), Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::new(ip4, net4.netmask(), gw4)
                    .with_mtu(server_info.mtu)
                    .with_ipv6(ip6, net6.prefix_len())?
            }
            // IPv4-only
            (Some(ip4), Some(net4), Some(gw4), None, None, None) => {
                TunConfig::new(ip4, net4.netmask(), gw4).with_mtu(server_info.mtu)
            }
            // IPv6-only
            (None, None, None, Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::ipv6_only(ip6, net6.prefix_len(), server_info.mtu)?
            }
            _ => {
                return Err(VpnError::Signaling(
                    "Invalid server info: need at least one complete IP configuration".into(),
                ))
            }
        };
        tun_config = tun_config.with_gso(server_info.server_gso_enabled);

        TunDevice::create(tun_config)
    }
}

impl VpnClient {
    /// Connect to the VPN server with automatic reconnection on failure.
    ///
    /// Wraps [`connect`](Self::connect) with exponential backoff (1s → 2s → … →
    /// 60s max). Only recoverable errors (see [`VpnError::is_recoverable`])
    /// trigger retries.
    pub async fn run_with_reconnect(&self, max_attempts: Option<NonZeroU32>) -> VpnResult<()> {
        let mut attempt = 0u32;

        loop {
            attempt = attempt.saturating_add(1);

            if attempt == 1 {
                log::info!("Connecting to VPN server...");
            } else {
                log::info!("VPN reconnection attempt #{}", attempt);
            }

            match self.connect().await {
                Ok(()) => {
                    log::info!("VPN connection ended gracefully");
                    return Ok(());
                }
                Err(e) if e.is_recoverable() => {
                    if matches!(e, VpnError::ConnectionLost(_)) {
                        attempt = 0;
                    }

                    if let Some(max) = max_attempts
                        && attempt >= max.get()
                    {
                        log::error!("Max reconnection attempts ({}) exceeded", max);
                        return Err(VpnError::MaxReconnectAttemptsExceeded(max));
                    }

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
                    log::error!("Fatal VPN error (not retrying): {}", e);
                    return Err(e);
                }
            }
        }
    }
}

/// Run the VPN packet processing loop over a connected loopback UDP socket.
///
/// `server_gso_enabled` is the server's advertised GSO capability.
pub(crate) async fn run_udp_tunnel(
    tun_device: TunDevice,
    socket: Arc<UdpSocket>,
    server_gso_enabled: bool,
) -> VpnResult<()> {
    let (mut tun_reader, mut tun_writer) = tun_device.split()?;
    let local_gso_enabled = tun_reader.offload_status().enabled;
    debug_assert_eq!(local_gso_enabled, tun_writer.offload_status().enabled);
    let negotiated_gso = local_gso_enabled && server_gso_enabled;
    let buffer_size = tun_reader.buffer_size();

    // Track last heartbeat pong received (millis since start for atomic access).
    let start_time = Instant::now();
    let last_pong = Arc::new(AtomicU64::new(0));
    let last_pong_inbound = last_pong.clone();
    let last_pong_heartbeat = last_pong.clone();

    // Outbound task: TUN -> frame -> UDP send.
    let outbound_socket = socket.clone();
    let mut outbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let mut read_storage = uninitialized_vec(buffer_size);
        let mut arena = BytesMut::with_capacity(FRAME_ARENA_CHUNK);
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut pending: Vec<Bytes> = Vec::new();
        // Software GRO: on a non-offload local TUN, coalesce consecutive
        // same-flow TCP segments into offload-tagged super-frames so a
        // GSO-capable peer can hand them to its kernel via TSO.
        let software_gro = !tun_reader.vnet_hdr_enabled();
        if software_gro {
            log::info!("Software GRO enabled for outbound TCP (local TUN has no offload support)");
        }
        let mut gro_table = TcpGroTable::new();
        let mut packet_buf = ReadBuf::uninit(&mut read_storage);
        loop {
            packet_buf.clear();
            let read_result = if software_gro && !gro_table.is_empty() {
                match tun_reader.try_read_buf(&mut packet_buf) {
                    Some(read_result) => read_result,
                    None => {
                        if build_gro_datagrams(
                            &mut arena,
                            &mut seg_scratch,
                            &mut pending,
                            &gro_table.flush_all(),
                            MAX_DATAGRAM_PAYLOAD,
                        )
                        .is_err()
                        {
                            return Some("framing error".to_string());
                        }
                        if !flush_pending(&outbound_socket, &mut pending).await {
                            return Some("UDP send error".to_string());
                        }
                        tun_reader.read_buf(&mut packet_buf).await
                    }
                }
            } else {
                tun_reader.read_buf(&mut packet_buf).await
            };

            match read_result {
                Ok(()) if !packet_buf.filled().is_empty() => {
                    let raw_packet = packet_buf.filled();
                    let (offload, packet) = match tun_reader.split_frame(raw_packet) {
                        Ok(parts) => parts,
                        Err(e) => {
                            log::warn!("Failed to parse TUN frame: {}", e);
                            continue;
                        }
                    };

                    if software_gro {
                        let result = gro_table.push(packet);
                        if build_gro_datagrams(
                            &mut arena,
                            &mut seg_scratch,
                            &mut pending,
                            &result.outputs,
                            MAX_DATAGRAM_PAYLOAD,
                        )
                        .is_err()
                        {
                            return Some("framing error".to_string());
                        }
                        if !flush_pending(&outbound_socket, &mut pending).await {
                            return Some("UDP send error".to_string());
                        }
                        if !result.pass_through {
                            continue;
                        }
                        // Pass-through frames carry no offload metadata.
                    }

                    if let Err(e) = build_datagrams(
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending,
                        offload.as_ref(),
                        packet,
                        negotiated_gso,
                        MAX_DATAGRAM_PAYLOAD,
                    ) {
                        log::warn!("Failed to frame packet: {}", e);
                        continue;
                    }
                    if !flush_pending(&outbound_socket, &mut pending).await {
                        return Some("UDP send error".to_string());
                    }
                }
                Ok(()) => {}
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    let _ = build_gro_datagrams(
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending,
                        &gro_table.flush_all(),
                        MAX_DATAGRAM_PAYLOAD,
                    );
                    let _ = flush_pending(&outbound_socket, &mut pending).await;
                    return Some(format!("TUN read error: {}", e));
                }
            }
        }
    });

    // Channel decoupling UDP recv from TUN write syscalls.
    let (tun_write_tx, mut tun_write_rx) =
        mpsc::channel::<InboundTunWrite>(INBOUND_TUN_CHANNEL_SIZE);

    // TUN writer task: drains the channel and writes to the device, coalescing
    // consecutive plain packets into GSO super-frames where the kernel supports it.
    let mut tun_writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        const MAX_TUN_WRITE_FAILURES: u32 = 10;
        let mut consecutive_tun_failures = 0u32;
        let mut note_write_result = |result: VpnResult<()>| -> Option<String> {
            match result {
                Ok(()) => {
                    consecutive_tun_failures = 0;
                    None
                }
                Err(e) => {
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
                    None
                }
            }
        };
        let mut batch: Vec<InboundTunWrite> = Vec::with_capacity(WRITE_BATCH_SIZE);
        let mut plain_run: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
        loop {
            let count = tun_write_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
            if count == 0 {
                log::trace!("TUN writer task exiting");
                return None;
            }
            for req in batch.drain(..) {
                let Some(meta) = req.offload else {
                    plain_run.push(req.packet);
                    continue;
                };
                if !plain_run.is_empty() {
                    let result = tun_writer.write_batch(&plain_run).await;
                    plain_run.clear();
                    if let Some(reason) = note_write_result(result) {
                        return Some(reason);
                    }
                }
                let result = tun_writer.write_packet(Some(&meta), &req.packet).await;
                if let Some(reason) = note_write_result(result) {
                    return Some(reason);
                }
            }
            if !plain_run.is_empty() {
                let result = tun_writer.write_batch(&plain_run).await;
                plain_run.clear();
                if let Some(reason) = note_write_result(result) {
                    return Some(reason);
                }
            }
        }
    });

    // Inbound task: UDP recv -> classify -> TUN writer channel / heartbeat reply.
    let inbound_socket = socket.clone();
    let inbound_start_time = start_time;
    let mut inbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUFFER_SIZE];
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut seg_arena = BytesMut::new();
        let mut pending_segments: Vec<Bytes> = Vec::new();
        loop {
            let n = match inbound_socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                    return Some(format!("UDP recv error: {}", e));
                }
            };
            let body = match classify(&buf[..n]) {
                Ok(Datagram::Ip(body)) => body,
                Ok(Datagram::Pong) => {
                    let now = inbound_start_time.elapsed().as_millis() as u64;
                    last_pong_inbound.store(now, Ordering::Relaxed);
                    continue;
                }
                Ok(Datagram::Ping) => {
                    if inbound_socket.send(HEARTBEAT_PONG_BYTE).await.is_err() {
                        return Some("UDP send error (pong)".to_string());
                    }
                    continue;
                }
                Ok(Datagram::Capabilities(_)) => continue,
                Err(e) => {
                    log::trace!("Ignoring undecodable datagram: {}", e);
                    continue;
                }
            };

            let (offload, packet) = match parse_ip_packet_v2(body) {
                Ok(parts) => parts,
                Err(e) => {
                    log::warn!("Invalid IP datagram from server: {}", e);
                    continue;
                }
            };

            if let Some(meta) = offload {
                if !local_gso_enabled {
                    let materialized =
                        materialize_offload_into(&meta, packet, &mut seg_scratch, |seg| {
                            seg_arena.extend_from_slice(seg);
                            pending_segments.push(seg_arena.split_to(seg.len()).freeze());
                            Ok(())
                        });
                    if let Err(e) = materialized {
                        pending_segments.clear();
                        log::warn!("Dropping packet with unsupported offload metadata: {}", e);
                        continue;
                    }
                    for packet in pending_segments.drain(..) {
                        let req = InboundTunWrite {
                            packet,
                            offload: None,
                        };
                        if tun_write_tx.send(req).await.is_err() {
                            return None;
                        }
                    }
                } else {
                    let req = InboundTunWrite {
                        packet: Bytes::copy_from_slice(packet),
                        offload: Some(meta),
                    };
                    if tun_write_tx.send(req).await.is_err() {
                        return None;
                    }
                }
            } else {
                let req = InboundTunWrite {
                    packet: Bytes::copy_from_slice(packet),
                    offload: None,
                };
                if tun_write_tx.send(req).await.is_err() {
                    return None;
                }
            }
        }
    });

    // Heartbeat task: periodically ping and check for pong timeout.
    let heartbeat_socket = socket.clone();
    let mut heartbeat_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let heartbeat_start = start_time;
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;

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

            if heartbeat_socket.send(HEARTBEAT_PING_BYTE).await.is_err() {
                log::warn!("Failed to send heartbeat ping");
                return None;
            }
            log::trace!("Heartbeat ping sent");
        }
    });

    // Wait for any task to finish, then tear the rest down.
    let (first_task, first_result, remaining) = tokio::select! {
        result = &mut outbound_handle => {
            ("outbound", result, vec![("inbound", inbound_handle), ("heartbeat", heartbeat_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut inbound_handle => {
            ("inbound", result, vec![("outbound", outbound_handle), ("heartbeat", heartbeat_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut heartbeat_handle => {
            ("heartbeat", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut tun_writer_handle => {
            ("tun-writer", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("heartbeat", heartbeat_handle)])
        }
    };

    for (_, handle) in &remaining {
        handle.abort();
    }

    let mut all_results = vec![(first_task, first_result)];
    for (name, handle) in remaining {
        all_results.push((name, handle.await));
    }

    let mut reasons = Vec::new();
    for (name, result) in &all_results {
        match result {
            Ok(Some(error_reason)) => reasons.push(error_reason.clone()),
            Ok(None) => reasons.push(format!("{} task ended", name)),
            Err(e) if e.is_cancelled() => {}
            Err(e) if e.is_panic() => reasons.push(format!("{} task panicked: {}", name, e)),
            Err(e) => reasons.push(format!("{} task failed: {}", name, e)),
        }
    }

    let reason = if reasons.is_empty() {
        "all tasks cancelled".to_string()
    } else {
        reasons.join("; ")
    };
    log::debug!("VPN loop ended: {}", reason);

    Err(VpnError::ConnectionLost(reason))
}

/// Send and clear all pending datagrams. Returns false if the socket errored.
async fn flush_pending(socket: &UdpSocket, pending: &mut Vec<Bytes>) -> bool {
    for datagram in pending.drain(..) {
        if let Err(e) = socket.send(&datagram).await {
            log::warn!("UDP send error: {}", e);
            return false;
        }
    }
    true
}

/// Backoff constants for reconnection delay calculation.
const BACKOFF_BASE_MS: u64 = 1000;
const BACKOFF_MAX_MS: u64 = 60000;
const BACKOFF_JITTER_MS: u64 = 500;

/// Calculate exponential backoff delay with jitter.
fn calculate_backoff(attempt: u32) -> Duration {
    calculate_backoff_with_rng(attempt, &mut rand::rng())
}

/// Calculate exponential backoff delay with a custom RNG (testable).
fn calculate_backoff_with_rng(attempt: u32, rng: &mut impl Rng) -> Duration {
    let multiplier = 2_u64.saturating_pow(attempt.saturating_sub(1));
    let base_delay_ms = BACKOFF_BASE_MS.saturating_mul(multiplier);
    let jitter_ms = rng.random_range(0..BACKOFF_JITTER_MS);
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
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let d1 = calculate_backoff_with_rng(1, &mut rng);
        assert!(d1.as_millis() >= 1000 && d1.as_millis() < 1500);
        let d2 = calculate_backoff_with_rng(2, &mut rng);
        assert!(d2.as_millis() >= 2000 && d2.as_millis() < 2500);
        let d3 = calculate_backoff_with_rng(3, &mut rng);
        assert!(d3.as_millis() >= 4000 && d3.as_millis() < 4500);
        let d6 = calculate_backoff_with_rng(6, &mut rng);
        assert!(d6.as_millis() >= 32000 && d6.as_millis() < 32500);
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let d7 = calculate_backoff_with_rng(7, &mut rng);
        assert!(d7.as_millis() <= BACKOFF_MAX_MS as u128);
        let d100 = calculate_backoff_with_rng(100, &mut rng);
        assert!(d100.as_millis() <= BACKOFF_MAX_MS as u128);
    }

    #[test]
    fn test_backoff_jitter_within_range() {
        for seed in 0..10 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let d = calculate_backoff_with_rng(1, &mut rng);
            assert!(d.as_millis() >= 1000 && d.as_millis() < 1500);
        }
    }

    #[test]
    fn test_backoff_attempt_zero_treated_as_one() {
        let mut rng = ChaCha8Rng::seed_from_u64(12345);
        let d0 = calculate_backoff_with_rng(0, &mut rng);
        assert!(d0.as_millis() >= 1000 && d0.as_millis() < 1500);
    }
}
