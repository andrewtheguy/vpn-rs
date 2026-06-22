//! VPN server implementation.
//!
//! The VPN server binds a single loopback UDP socket and demultiplexes clients
//! by their source `SocketAddr` (the external tunnel forwards each client from a
//! distinct local port). It assigns IP addresses from per-`device_id` pools,
//! routes TUN packets to the right client, and reaps clients that go silent
//! (UDP has no connection teardown).

use crate::vpn_core::buffer::uninitialized_vec;
use crate::vpn_core::config::VpnServerConfig;
use crate::vpn_core::datagram::{
    build_datagrams, build_gro_datagrams, classify, Datagram, FRAME_ARENA_CHUNK,
};
use crate::vpn_core::device::{TunConfig, TunDevice, TunOffloadStatus, TunReader};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::offload::{materialize_offload_into, TcpGroTable, VirtioNetHdr};
use crate::vpn_core::signaling::{
    parse_ip_packet_v2, CapabilitiesMessage, VpnHandshake, VpnHandshakeResponse,
    HEARTBEAT_PONG_BYTE,
};
use crate::vpn_core::udp::RECV_BUFFER_SIZE;
use crate::vpn_core::udp_offload::{recv_split, send_datagrams};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

/// Maximum number of framed datagrams drained from a channel per batched write.
const WRITE_BATCH_SIZE: usize = 256;

/// Performance statistics for the VPN server.
#[derive(Debug, Default)]
pub struct VpnServerStats {
    /// Total packets read from TUN device.
    pub tun_packets_read: AtomicU64,
    /// Packets successfully sent to clients.
    pub packets_to_clients: AtomicU64,
    /// Packets dropped due to unknown destination IP.
    pub packets_no_route: AtomicU64,
    /// Packets dropped due to unknown IP version.
    pub packets_unknown_version: AtomicU64,
    /// Packets dropped due to outbound channel full (drop_on_full=true).
    pub packets_dropped_full: AtomicU64,
    /// Packets sent via backpressure (slow path, drop_on_full=false).
    pub packets_backpressure: AtomicU64,
    /// Packets received from clients and written to TUN.
    pub packets_from_clients: AtomicU64,
    /// Packets dropped due to TUN write channel full/closed.
    pub packets_tun_write_failed: AtomicU64,
    /// Packets dropped due to invalid source IP (anti-spoofing).
    pub packets_spoofed: AtomicU64,
}

impl VpnServerStats {
    /// Create a new stats instance with all counters zeroed.
    pub fn new() -> Self {
        Self::default()
    }
}

/// State for a connected VPN client (keyed by source `SocketAddr`).
struct ClientState {
    /// Client's device id (key for IP-pool idempotency across reconnects).
    device_id: u64,
    /// Client's assigned VPN IP (IPv4). None for IPv6-only mode.
    assigned_ip: Option<Ipv4Addr>,
    /// Client's assigned IPv6 VPN address. None for IPv4-only mode.
    assigned_ip6: Option<Ipv6Addr>,
    /// Reported client local GSO capability (set when capabilities arrive).
    client_gso_enabled: AtomicBool,
    /// Effective per-connection GSO mode (server local && client reported).
    connection_gso_active: AtomicBool,
    /// Last time any datagram was received from this client (millis since start).
    last_seen: AtomicU64,
}

/// Request to write an IP packet (with optional offload metadata) to the TUN writer task.
struct TunWriteRequest {
    packet: Bytes,
    offload: Option<VirtioNetHdr>,
}

/// Reusable scratch buffers for per-datagram inbound processing.
#[derive(Default)]
struct RecvScratch {
    seg_scratch: Vec<u8>,
    seg_arena: BytesMut,
    pending: Vec<Bytes>,
}

/// IPv4 address pool for assigning addresses to clients (keyed by device id).
struct IpPool {
    network: Ipv4Net,
    server_ip: Ipv4Addr,
    next_ip: u32,
    max_ip: u32,
    in_use: HashMap<u64, Ipv4Addr>,
    released: Vec<Ipv4Addr>,
    reserved: HashSet<Ipv4Addr>,
}

impl IpPool {
    fn new(network: Ipv4Net, server_ip: Option<Ipv4Addr>) -> Self {
        let net_addr: u32 = network.network().into();
        let broadcast: u32 = network.broadcast().into();
        let server_ip = server_ip.unwrap_or_else(|| Ipv4Addr::from(net_addr + 1));
        let server_ip_u32: u32 = server_ip.into();
        let next_ip = server_ip_u32 + 1;
        let max_ip = broadcast - 1; // Exclude broadcast address
        Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            in_use: HashMap::new(),
            released: Vec::new(),
            reserved: HashSet::new(),
        }
    }

    fn server_ip(&self) -> Ipv4Addr {
        self.server_ip
    }

    fn network(&self) -> Ipv4Net {
        self.network
    }

    #[cfg(test)]
    fn reserve_next_available(&mut self) -> Option<Ipv4Addr> {
        let ip = self.next_unreserved_ip()?;
        self.reserved.insert(ip);
        Some(ip)
    }

    fn next_unreserved_ip(&mut self) -> Option<Ipv4Addr> {
        while self.next_ip <= self.max_ip {
            let ip = Ipv4Addr::from(self.next_ip);
            self.next_ip += 1;
            if self.reserved.contains(&ip) {
                continue;
            }
            return Some(ip);
        }
        None
    }

    /// Allocate an IP for a client, idempotent per `device_id`.
    fn allocate(&mut self, device_id: u64) -> Option<Ipv4Addr> {
        if let Some(&ip) = self.in_use.get(&device_id) {
            return Some(ip);
        }
        while let Some(ip) = self.released.pop() {
            if self.reserved.contains(&ip) {
                continue;
            }
            self.in_use.insert(device_id, ip);
            return Some(ip);
        }
        if let Some(ip) = self.next_unreserved_ip() {
            self.in_use.insert(device_id, ip);
            Some(ip)
        } else {
            None
        }
    }

    /// Release an IP when a client is reaped.
    fn release(&mut self, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&device_id) {
            self.released.push(ip);
        }
    }
}

/// IPv6 address pool for assigning /128 addresses to clients (sequential, keyed by device id).
#[derive(Debug)]
struct Ip6Pool {
    network: Ipv6Net,
    server_ip: Ipv6Addr,
    next_ip: u128,
    max_ip: u128,
    released: Vec<Ipv6Addr>,
    in_use: HashMap<u64, Ipv6Addr>,
}

impl Ip6Pool {
    /// Create a new IPv6 pool. Server gets `::1` (or `server_ip`); clients get
    /// subsequent addresses. Requires a /126 or wider network.
    fn new(network: Ipv6Net, server_ip: Option<Ipv6Addr>) -> VpnResult<Self> {
        let prefix_len = network.prefix_len();
        if prefix_len >= 127 {
            return Err(VpnError::config(format!(
                "IPv6 prefix /{} is too small for VPN pool (need at least /126 for 1 client)",
                prefix_len
            )));
        }

        let net_addr: u128 = network.network().into();
        let server_ip = server_ip.unwrap_or_else(|| Ipv6Addr::from(net_addr + 1));
        let server_ip_u128: u128 = server_ip.into();
        let next_ip = server_ip_u128 + 1;
        let host_bits: u32 = 128 - u32::from(prefix_len);
        // host_bits >= 2 here because prefix_len < 127, so the shift is safe.
        let max_ip = net_addr + ((1u128 << host_bits) - 1) - 1; // Exclude last address

        Ok(Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            released: Vec::new(),
            in_use: HashMap::new(),
        })
    }

    fn server_ip(&self) -> Ipv6Addr {
        self.server_ip
    }

    fn network(&self) -> Ipv6Net {
        self.network
    }

    /// Allocate an IPv6 for a client, idempotent per `device_id`.
    fn allocate(&mut self, device_id: u64) -> Option<Ipv6Addr> {
        if let Some(&ip) = self.in_use.get(&device_id) {
            return Some(ip);
        }
        if let Some(ip) = self.released.pop() {
            self.in_use.insert(device_id, ip);
            return Some(ip);
        }
        if self.next_ip <= self.max_ip {
            let ip = Ipv6Addr::from(self.next_ip);
            self.next_ip += 1;
            self.in_use.insert(device_id, ip);
            Some(ip)
        } else {
            None
        }
    }

    /// Release an IPv6 when a client is reaped.
    fn release(&mut self, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&device_id) {
            self.released.push(ip);
        }
    }
}

/// VPN server instance.
pub struct VpnServer {
    config: VpnServerConfig,
    /// IPv4 address pool (None if IPv6-only mode).
    ip_pool: Option<Arc<RwLock<IpPool>>>,
    /// IPv6 address pool (None if IPv4-only mode).
    ip6_pool: Option<Arc<RwLock<Ip6Pool>>>,
    /// Connected clients keyed by source `SocketAddr`.
    clients: Arc<DashMap<SocketAddr, ClientState>>,
    /// Index from device id to its current `SocketAddr` (one entry per client).
    device_to_addr: Arc<DashMap<u64, SocketAddr>>,
    /// Reverse lookup: assigned IPv4 -> client `SocketAddr`.
    ip_to_addr: Arc<DashMap<Ipv4Addr, SocketAddr>>,
    /// Reverse lookup: assigned IPv6 -> client `SocketAddr`.
    ip6_to_addr: Arc<DashMap<Ipv6Addr, SocketAddr>>,
    /// TUN device for VPN traffic (taken in `run`).
    tun_device: Option<TunDevice>,
    /// Server-local TUN offload/GSO status.
    tun_offload_status: TunOffloadStatus,
    /// Performance statistics.
    stats: Arc<VpnServerStats>,
    /// Monotonic base for `last_seen` timestamps.
    start_time: Instant,
}

impl VpnServer {
    /// Create a new VPN server.
    pub async fn new(config: VpnServerConfig) -> VpnResult<Self> {
        config.validate()?;

        let ip_pool = config
            .network
            .map(|network| Arc::new(RwLock::new(IpPool::new(network, config.server_ip))));

        let ip6_pool = match config.network6 {
            Some(network6) => Some(Arc::new(RwLock::new(Ip6Pool::new(
                network6,
                config.server_ip6,
            )?))),
            None => None,
        };

        if let Some(ref pool) = ip6_pool {
            let pool_guard = pool.read().await;
            if ip_pool.is_some() {
                log::info!("IPv6 dual-stack enabled: {}", pool_guard.network());
            } else {
                log::info!("IPv6-only mode enabled: {}", pool_guard.network());
            }
        }

        Ok(Self {
            config,
            ip_pool,
            ip6_pool,
            clients: Arc::new(DashMap::new()),
            device_to_addr: Arc::new(DashMap::new()),
            ip_to_addr: Arc::new(DashMap::new()),
            ip6_to_addr: Arc::new(DashMap::new()),
            tun_device: None,
            tun_offload_status: TunOffloadStatus::disabled("TUN not initialized"),
            stats: Arc::new(VpnServerStats::new()),
            start_time: Instant::now(),
        })
    }

    /// Create and configure the TUN device.
    pub async fn setup_tun(&mut self) -> VpnResult<()> {
        let (server_ip, netmask) = if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            (Some(pool.server_ip()), Some(pool.network().netmask()))
        } else {
            (None, None)
        };

        let (server_ip6, prefix_len6) = if let Some(ref ip6_pool) = self.ip6_pool {
            let pool6 = ip6_pool.read().await;
            (Some(pool6.server_ip()), Some(pool6.network().prefix_len()))
        } else {
            (None, None)
        };

        let tun_config = match (server_ip, netmask, server_ip6, prefix_len6) {
            (Some(ip4), Some(mask), Some(ip6), Some(pl6)) => TunConfig::new(ip4, mask, ip4)
                .with_mtu(self.config.mtu)
                .with_ipv6(ip6, pl6)?,
            (Some(ip4), Some(mask), None, None) => {
                TunConfig::new(ip4, mask, ip4).with_mtu(self.config.mtu)
            }
            (None, None, Some(ip6), Some(pl6)) => TunConfig::ipv6_only(ip6, pl6, self.config.mtu)?,
            _ => {
                return Err(VpnError::config(
                    "No network configured (need at least IPv4 or IPv6)".to_string(),
                ))
            }
        };

        let device = TunDevice::create(tun_config)?;
        self.tun_offload_status = device.offload_status().clone();

        match (server_ip, server_ip6) {
            (Some(ip4), Some(ip6)) => log::info!(
                "Created TUN device: {} with IP {} and IPv6 {}",
                device.name(),
                ip4,
                ip6
            ),
            (Some(ip4), None) => {
                log::info!("Created TUN device: {} with IP {}", device.name(), ip4)
            }
            (None, Some(ip6)) => log::info!(
                "Created TUN device: {} with IPv6 {} (IPv6-only mode)",
                device.name(),
                ip6
            ),
            (None, None) => unreachable!(),
        }

        log::info!(
            "Server local TUN GSO status: enabled={}{}",
            self.tun_offload_status.enabled,
            self.tun_offload_status
                .reason
                .as_deref()
                .map(|r| format!(", reason={}", r))
                .unwrap_or_default()
        );

        self.tun_device = Some(device);
        Ok(())
    }

    /// Milliseconds since the server's monotonic start.
    fn now_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// Run the VPN server on a bound loopback UDP socket.
    pub async fn run(mut self, socket: Arc<UdpSocket>) -> VpnResult<()> {
        self.setup_tun().await?;

        log::info!("VPN Server started:");
        log::info!("  Listen (loopback UDP): {}", socket.local_addr()?);
        if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            log::info!("  Network: {}, Server IP: {}", pool.network(), pool.server_ip());
        }
        if let Some(ref ip6_pool) = self.ip6_pool {
            let pool = ip6_pool.read().await;
            log::info!("  Network6: {}, Server IP6: {}", pool.network(), pool.server_ip());
        }
        log::info!(
            "  Mode: {}",
            match (self.ip_pool.is_some(), self.ip6_pool.is_some()) {
                (true, true) => "dual-stack (IPv4 + IPv6)",
                (true, false) => "IPv4-only",
                (false, true) => "IPv6-only",
                (false, false) => "none",
            }
        );
        log::info!(
            "  Local TUN GSO: {}",
            if self.tun_offload_status.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );

        let tun_device = self.tun_device.take().expect("TUN device not set up");
        let (tun_reader, mut tun_writer) = tun_device.split()?;

        // TUN writer channel + task (client -> TUN).
        let (tun_write_tx, mut tun_write_rx) =
            mpsc::channel::<TunWriteRequest>(self.config.tun_writer_channel_size);
        let tun_writer_stats = self.stats.clone();
        let tun_writer_handle = tokio::spawn(async move {
            log::info!("TUN writer task started");
            let mut batch = Vec::with_capacity(WRITE_BATCH_SIZE);
            let mut plain_run: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
            let log_write_error = |e: VpnError| {
                tun_writer_stats
                    .packets_tun_write_failed
                    .fetch_add(1, Ordering::Relaxed);
                log::warn!("Failed to write to TUN: {}", e);
            };
            loop {
                let count = tun_write_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
                if count == 0 {
                    break;
                }
                for req in batch.drain(..) {
                    let Some(meta) = req.offload else {
                        plain_run.push(req.packet);
                        continue;
                    };
                    if !plain_run.is_empty() {
                        if let Err(e) = tun_writer.write_batch(&plain_run).await {
                            log_write_error(e);
                        }
                        plain_run.clear();
                    }
                    if let Err(e) = tun_writer.write_packet(Some(&meta), &req.packet).await {
                        log_write_error(e);
                    }
                }
                if !plain_run.is_empty() {
                    if let Err(e) = tun_writer.write_batch(&plain_run).await {
                        log_write_error(e);
                    }
                    plain_run.clear();
                }
            }
            log::info!("TUN writer task exiting (channel closed)");
        });

        // Outbound channel + task (TUN -> client): single sender that owns send_to.
        let (outbound_tx, mut outbound_rx) =
            mpsc::channel::<(SocketAddr, Bytes)>(self.config.client_channel_size);
        let outbound_socket = socket.clone();
        let outbound_handle = tokio::spawn(async move {
            let mut batch: Vec<(SocketAddr, Bytes)> = Vec::with_capacity(WRITE_BATCH_SIZE);
            loop {
                let count = outbound_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
                if count == 0 {
                    break;
                }
                // Group consecutive datagrams for the same client and hand each
                // run to send_datagrams, which UDP-GSO batches equal-sized runs
                // (one sendmsg) where the kernel supports it. Per-flow order is
                // preserved within each run.
                let mut start = 0;
                while start < batch.len() {
                    let addr = batch[start].0;
                    let mut end = start + 1;
                    while end < batch.len() && batch[end].0 == addr {
                        end += 1;
                    }
                    let run: Vec<Bytes> =
                        batch[start..end].iter().map(|(_, b)| b.clone()).collect();
                    if let Err(e) = send_datagrams(&outbound_socket, Some(addr), &run).await {
                        log::warn!("UDP send to {} failed: {}", addr, e);
                    }
                    start = end;
                }
                batch.clear();
            }
        });

        let server = Arc::new(self);

        // TUN reader task (TUN -> route -> outbound).
        let server_tun = server.clone();
        let tun_reader_handle = tokio::spawn(async move {
            if let Err(e) = server_tun.run_tun_reader(tun_reader, outbound_tx).await {
                log::error!("TUN reader error: {}", e);
            }
        });

        // Liveness reaper task.
        let server_reaper = server.clone();
        let reaper_handle = tokio::spawn(async move {
            server_reaper.run_reaper().await;
        });

        // Main receive loop: demux by source addr.
        let mut buf = vec![0u8; RECV_BUFFER_SIZE];
        let mut scratch = RecvScratch::default();
        let run_result = loop {
            let (n, seg, peer) = match recv_split(&socket, &mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                    break Err(VpnError::Network(e));
                }
            };
            let Some(peer) = peer else {
                continue; // no source address; cannot route or reply
            };
            // A GRO-coalesced recv may carry several datagrams from the same peer.
            for dgram in buf[..n].chunks(seg) {
                // Handshake datagrams are raw JSON ('{'); data datagrams start with
                // a message-type byte (0x00..=0x03). This cleanly handles retransmits.
                if dgram.first() == Some(&b'{') {
                    server.handle_handshake(peer, dgram, &socket).await;
                } else {
                    server
                        .handle_client_datagram(peer, dgram, &socket, &tun_write_tx, &mut scratch)
                        .await;
                }
            }
        };

        log::info!("Shutting down server tasks...");
        reaper_handle.abort();
        tun_reader_handle.abort();
        drop(tun_write_tx);
        let _ = tun_writer_handle.await;
        // outbound_tx is owned by the TUN reader task (now aborted); dropping our
        // clones lets the outbound task finish.
        let _ = outbound_handle.await;
        log::info!("Server shutdown complete");

        run_result
    }

    /// Handle a handshake datagram (new client, reconnect/move, or retransmit).
    async fn handle_handshake(&self, peer: SocketAddr, dgram: &[u8], socket: &UdpSocket) {
        let handshake = match VpnHandshake::decode(dgram) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("Ignoring bad handshake from {}: {}", peer, e);
                return;
            }
        };

        // Test-mode token gate (before any resource allocation). The equality
        // check also enforces test/non-test mutual exclusion: a test server has
        // `Some(token)` while a non-test client sends `None` (and vice versa),
        // so cross-mode handshakes never match.
        if self.config.test_token != handshake.test_token {
            log::warn!(
                "Rejecting handshake from {}: test token mismatch (test/non-test mismatch or wrong token)",
                peer
            );
            self.send_response(
                socket,
                peer,
                VpnHandshakeResponse::rejected(
                    "test token mismatch",
                    self.tun_offload_status.enabled,
                ),
            )
            .await;
            return;
        }

        let device_id = handshake.device_id;

        let existing_addr = self.device_to_addr.get(&device_id).map(|r| *r);
        let is_new_client = existing_addr.is_none();

        if is_new_client && self.device_to_addr.len() >= self.config.max_clients {
            self.send_response(
                socket,
                peer,
                VpnHandshakeResponse::rejected("Server full", self.tun_offload_status.enabled),
            )
            .await;
            return;
        }

        // Allocate IPs (idempotent per device id).
        let assigned_ip = match self.ip_pool {
            Some(ref pool) => pool.write().await.allocate(device_id),
            None => None,
        };
        let assigned_ip6 = match self.ip6_pool {
            Some(ref pool) => pool.write().await.allocate(device_id),
            None => None,
        };

        if assigned_ip.is_none() && assigned_ip6.is_none() {
            self.send_response(
                socket,
                peer,
                VpnHandshakeResponse::rejected(
                    "All IP pools exhausted",
                    self.tun_offload_status.enabled,
                ),
            )
            .await;
            return;
        }

        // Reconnect/move: a known device arriving from a new addr drops its old
        // entry (the IP stays allocated to the device).
        if let Some(old_addr) = existing_addr
            && old_addr != peer
        {
            self.clients.remove(&old_addr);
        }

        let response = match (assigned_ip, assigned_ip6) {
            (Some(ip4), Some(ip6)) => {
                let ip_pool = self.ip_pool.as_ref().unwrap().read().await;
                let ip6_pool = self.ip6_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted_dual_stack(
                    ip4,
                    ip_pool.network(),
                    ip_pool.server_ip(),
                    ip6,
                    ip6_pool.network(),
                    ip6_pool.server_ip(),
                    self.tun_offload_status.enabled,
                    self.config.mtu,
                    self.config.max_datagram_size,
                )
            }
            (Some(ip4), None) => {
                let ip_pool = self.ip_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted(
                    ip4,
                    ip_pool.network(),
                    ip_pool.server_ip(),
                    self.tun_offload_status.enabled,
                    self.config.mtu,
                    self.config.max_datagram_size,
                )
            }
            (None, Some(ip6)) => {
                let ip6_pool = self.ip6_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted_ipv6_only(
                    ip6,
                    ip6_pool.network(),
                    ip6_pool.server_ip(),
                    self.tun_offload_status.enabled,
                    self.config.mtu,
                    self.config.max_datagram_size,
                )
            }
            (None, None) => unreachable!(),
        };

        // Register (overwrites on retransmit/move).
        let now = self.now_ms();
        self.clients.insert(
            peer,
            ClientState {
                device_id,
                assigned_ip,
                assigned_ip6,
                client_gso_enabled: AtomicBool::new(false),
                connection_gso_active: AtomicBool::new(false),
                last_seen: AtomicU64::new(now),
            },
        );
        self.device_to_addr.insert(device_id, peer);
        if let Some(ip4) = assigned_ip {
            self.ip_to_addr.insert(ip4, peer);
        }
        if let Some(ip6) = assigned_ip6 {
            self.ip6_to_addr.insert(ip6, peer);
        }

        self.send_response(socket, peer, response).await;
        log::info!(
            "Client {} (device {:016x}) connected: ip={:?} ip6={:?}",
            peer,
            device_id,
            assigned_ip,
            assigned_ip6
        );
    }

    /// Encode and send a handshake response datagram.
    async fn send_response(&self, socket: &UdpSocket, peer: SocketAddr, response: VpnHandshakeResponse) {
        match response.encode() {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, peer).await {
                    log::warn!("Failed to send handshake response to {}: {}", peer, e);
                }
            }
            Err(e) => log::error!("Failed to encode handshake response: {}", e),
        }
    }

    /// Handle a data-channel datagram from a known client.
    async fn handle_client_datagram(
        &self,
        peer: SocketAddr,
        dgram: &[u8],
        socket: &UdpSocket,
        tun_write_tx: &mpsc::Sender<TunWriteRequest>,
        scratch: &mut RecvScratch,
    ) {
        // Bump liveness and extract per-client flags; drop the DashMap ref before
        // any await to avoid holding a shard lock across `.await`.
        let (known, connection_gso_active) = match self.clients.get(&peer) {
            Some(c) => {
                c.last_seen.store(self.now_ms(), Ordering::Relaxed);
                (true, c.connection_gso_active.load(Ordering::Relaxed))
            }
            None => (false, false),
        };
        if !known {
            // Data before handshake completed, or from a reaped client. Drop.
            return;
        }

        match classify(dgram) {
            Ok(Datagram::Ping) => {
                if let Err(e) = socket.send_to(HEARTBEAT_PONG_BYTE, peer).await {
                    log::trace!("Failed to send pong to {}: {}", peer, e);
                }
            }
            Ok(Datagram::Pong) => { /* server never pings; ignore */ }
            Ok(Datagram::Capabilities(payload)) => {
                let caps = CapabilitiesMessage::decode_payload(payload);
                if let Some(c) = self.clients.get(&peer) {
                    c.client_gso_enabled.store(caps.gso_enabled, Ordering::Relaxed);
                    c.connection_gso_active.store(
                        self.tun_offload_status.enabled && caps.gso_enabled,
                        Ordering::Relaxed,
                    );
                }
                log::debug!("Client {} capabilities: gso={}", peer, caps.gso_enabled);
            }
            Ok(Datagram::Ip(body)) => {
                self.handle_client_ip(peer, body, connection_gso_active, tun_write_tx, scratch)
                    .await;
            }
            Err(e) => {
                log::trace!("Ignoring undecodable datagram from {}: {}", peer, e);
            }
        }
    }

    /// Validate and forward a client IP datagram to the TUN writer task.
    async fn handle_client_ip(
        &self,
        peer: SocketAddr,
        body: &[u8],
        connection_gso_active: bool,
        tun_write_tx: &mpsc::Sender<TunWriteRequest>,
        scratch: &mut RecvScratch,
    ) {
        let (offload, packet) = match parse_ip_packet_v2(body) {
            Ok(parts) => parts,
            Err(e) => {
                log::warn!("Invalid IP datagram from {}: {}", peer, e);
                return;
            }
        };

        // Anti-spoofing: reject a source IP that belongs to a different client.
        if !self.config.disable_spoofing_check && !self.source_ip_allowed(peer, packet) {
            self.stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let RecvScratch {
            seg_scratch,
            seg_arena,
            pending,
        } = scratch;

        if let Some(meta) = offload {
            if !connection_gso_active || !self.tun_offload_status.enabled {
                pending.clear();
                // Inbound reconstruction: cap each rebuilt segment at the local
                // TUN MTU. Honest peers already segment at/below it, so this is a
                // no-op for them; a hostile peer advertising a huge gso_size is
                // prevented from making us write oversized IP packets to the TUN.
                let materialized = materialize_offload_into(
                    &meta,
                    packet,
                    seg_scratch,
                    self.config.mtu as usize,
                    |seg| {
                        seg_arena.extend_from_slice(seg);
                        pending.push(seg_arena.split_to(seg.len()).freeze());
                        Ok(())
                    },
                );
                if let Err(e) = materialized {
                    pending.clear();
                    log::warn!("Dropping packet with unsupported offload from {}: {}", peer, e);
                    return;
                }
                for packet in pending.drain(..) {
                    let req = TunWriteRequest {
                        packet,
                        offload: None,
                    };
                    if !Self::enqueue_tun_write(tun_write_tx, req, &self.stats).await {
                        break;
                    }
                }
            } else {
                let req = TunWriteRequest {
                    packet: Bytes::copy_from_slice(packet),
                    offload: Some(meta),
                };
                let _ = Self::enqueue_tun_write(tun_write_tx, req, &self.stats).await;
            }
        } else {
            let req = TunWriteRequest {
                packet: Bytes::copy_from_slice(packet),
                offload: None,
            };
            let _ = Self::enqueue_tun_write(tun_write_tx, req, &self.stats).await;
        }
    }

    /// Whether `packet`'s source IP is allowed from `peer` (anti-spoofing).
    ///
    /// A source IP that is not VPN-assigned is allowed (e.g. a client's own
    /// public IP in dual-stack). A VPN-assigned IP is allowed only if it belongs
    /// to `peer`. Link-local IPv6 is always dropped.
    fn source_ip_allowed(&self, peer: SocketAddr, packet: &[u8]) -> bool {
        match extract_source_ip(packet) {
            Some(PacketIp::V4(src)) => match self.ip_to_addr.get(&src) {
                Some(owner) if *owner == peer => true,
                Some(_) => {
                    log::warn!("IPv4 spoofing from {}: source {} owned by another client", peer, src);
                    false
                }
                None => true,
            },
            Some(PacketIp::V6(src)) => {
                let o = src.octets();
                if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                    return false; // link-local, not routable across the VPN
                }
                match self.ip6_to_addr.get(&src) {
                    Some(owner) if *owner == peer => true,
                    Some(_) => {
                        log::warn!("IPv6 spoofing from {}: source {} owned by another client", peer, src);
                        false
                    }
                    None => true,
                }
            }
            None => {
                log::warn!("Failed to parse source IP from {}", peer);
                false
            }
        }
    }

    /// Enqueue a TUN write request to the dedicated TUN writer task.
    async fn enqueue_tun_write(
        tun_write_tx: &mpsc::Sender<TunWriteRequest>,
        req: TunWriteRequest,
        stats: &Arc<VpnServerStats>,
    ) -> bool {
        match tun_write_tx.try_send(req) {
            Ok(()) => {
                stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Full(req)) => {
                if tun_write_tx.send(req).await.is_ok() {
                    stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    stats.packets_tun_write_failed.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                stats.packets_tun_write_failed.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Periodically reap clients that have gone silent past `client_timeout`.
    async fn run_reaper(self: Arc<Self>) {
        let timeout_ms = self.config.client_timeout.as_millis() as u64;
        let interval = (self.config.client_timeout / 2).max(Duration::from_secs(5));
        loop {
            tokio::time::sleep(interval).await;
            let now = self.now_ms();
            let stale: Vec<(SocketAddr, u64)> = self
                .clients
                .iter()
                .filter(|e| now.saturating_sub(e.last_seen.load(Ordering::Relaxed)) > timeout_ms)
                .map(|e| (*e.key(), e.device_id))
                .collect();
            for (addr, device_id) in stale {
                self.reap_client(addr, device_id).await;
            }
        }
    }

    /// Remove a client entry; release its IPs only if it is still the current
    /// addr for its device (a reconnect from a new addr may have taken over).
    async fn reap_client(&self, addr: SocketAddr, device_id: u64) {
        let is_current = self
            .device_to_addr
            .get(&device_id)
            .map(|r| *r == addr)
            .unwrap_or(false);
        let Some((_, state)) = self.clients.remove(&addr) else {
            return;
        };
        if !is_current {
            return; // a newer addr owns this device now
        }
        log::info!("Reaping idle client {} (device {:016x})", addr, device_id);
        self.device_to_addr.remove_if(&device_id, |_, a| *a == addr);
        if let Some(ip) = state.assigned_ip {
            self.ip_to_addr.remove_if(&ip, |_, a| *a == addr);
            if let Some(ref pool) = self.ip_pool {
                pool.write().await.release(device_id);
            }
        }
        if let Some(ip6) = state.assigned_ip6 {
            self.ip6_to_addr.remove_if(&ip6, |_, a| *a == addr);
            if let Some(ref pool) = self.ip6_pool {
                pool.write().await.release(device_id);
            }
        }
    }

    /// Read packets from TUN, route by destination IP, and frame to outbound.
    async fn run_tun_reader(
        &self,
        mut tun_reader: TunReader,
        outbound_tx: mpsc::Sender<(SocketAddr, Bytes)>,
    ) -> VpnResult<()> {
        log::info!("TUN reader started");

        let max_dgram = self.config.max_datagram_size;
        let drop_on_full = self.config.drop_on_full;
        let buffer_size = tun_reader.buffer_size();
        let mut read_storage = uninitialized_vec(buffer_size);
        let mut arena = BytesMut::with_capacity(FRAME_ARENA_CHUNK);
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut pending: Vec<Bytes> = Vec::new();
        let software_gro = !tun_reader.vnet_hdr_enabled();
        if software_gro {
            log::info!("Software GRO enabled for TUN->client TCP (server TUN has no offload support)");
        }
        let mut gro_states: HashMap<SocketAddr, TcpGroTable> = HashMap::new();

        let mut packet_buf = ReadBuf::uninit(&mut read_storage);
        loop {
            packet_buf.clear();
            let gro_pending = software_gro && gro_states.values().any(|t| !t.is_empty());
            let read_result = if gro_pending {
                match tun_reader.try_read_buf(&mut packet_buf) {
                    Some(read_result) => read_result,
                    None => {
                        self.flush_gro_states(
                            &mut gro_states,
                            &mut arena,
                            &mut seg_scratch,
                            &mut pending,
                            &outbound_tx,
                            max_dgram,
                            drop_on_full,
                        )
                        .await;
                        tun_reader.read_buf(&mut packet_buf).await
                    }
                }
            } else {
                tun_reader.read_buf(&mut packet_buf).await
            };

            match read_result {
                Ok(()) if !packet_buf.filled().is_empty() => {}
                Ok(()) => continue,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    self.flush_gro_states(
                        &mut gro_states,
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending,
                        &outbound_tx,
                        max_dgram,
                        drop_on_full,
                    )
                    .await;
                    break;
                }
            }

            let raw_frame = packet_buf.filled();
            self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);

            let (offload, packet_ref) = match tun_reader.split_frame(raw_frame) {
                Ok(parts) => parts,
                Err(e) => {
                    log::warn!("Failed to parse TUN frame from server device: {}", e);
                    continue;
                }
            };

            let addr = match extract_dest_ip(packet_ref) {
                Some(PacketIp::V4(dest_ip)) => match self.ip_to_addr.get(&dest_ip).map(|r| *r) {
                    Some(a) => a,
                    None => {
                        self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                },
                Some(PacketIp::V6(dest_ip)) => match self.ip6_to_addr.get(&dest_ip).map(|r| *r) {
                    Some(a) => a,
                    None => {
                        self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                },
                None => {
                    self.stats.packets_unknown_version.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            let (client_gso_enabled, connection_gso_active) = match self.clients.get(&addr) {
                Some(c) => (
                    c.client_gso_enabled.load(Ordering::Relaxed),
                    c.connection_gso_active.load(Ordering::Relaxed),
                ),
                None => {
                    self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            if software_gro && client_gso_enabled {
                let table = gro_states.entry(addr).or_default();
                let result = table.push(packet_ref);
                if !result.outputs.is_empty() {
                    pending.clear();
                    if build_gro_datagrams(
                        &mut arena,
                        &mut seg_scratch,
                        &mut pending,
                        &result.outputs,
                        max_dgram,
                    )
                    .is_ok()
                    {
                        for d in pending.drain(..) {
                            enqueue_datagram(&outbound_tx, addr, d, &self.stats, drop_on_full, 1)
                                .await;
                        }
                    }
                }
                if !result.pass_through {
                    continue;
                }
                // Pass-through frames carry no offload metadata.
            }

            pending.clear();
            if build_datagrams(
                &mut arena,
                &mut seg_scratch,
                &mut pending,
                offload.as_ref(),
                packet_ref,
                connection_gso_active,
                max_dgram,
            )
            .is_ok()
            {
                for d in pending.drain(..) {
                    enqueue_datagram(&outbound_tx, addr, d, &self.stats, drop_on_full, 1).await;
                }
            }
        }

        Ok(())
    }

    /// Drain all per-client software-GRO tables and evict disconnected clients.
    #[allow(clippy::too_many_arguments)]
    async fn flush_gro_states(
        &self,
        gro_states: &mut HashMap<SocketAddr, TcpGroTable>,
        arena: &mut BytesMut,
        seg_scratch: &mut Vec<u8>,
        pending: &mut Vec<Bytes>,
        outbound_tx: &mpsc::Sender<(SocketAddr, Bytes)>,
        max_dgram: usize,
        drop_on_full: bool,
    ) {
        for (addr, table) in gro_states.iter_mut() {
            let outputs = table.flush_all();
            if outputs.is_empty() {
                continue;
            }
            pending.clear();
            if build_gro_datagrams(arena, seg_scratch, pending, &outputs, max_dgram).is_ok() {
                for d in pending.drain(..) {
                    enqueue_datagram(outbound_tx, *addr, d, &self.stats, drop_on_full, 1).await;
                }
            }
        }
        gro_states.retain(|addr, _| self.clients.contains_key(addr));
    }
}

/// Enqueue a framed datagram for the outbound sender task, applying
/// drop-on-full / backpressure policy.
async fn enqueue_datagram(
    outbound_tx: &mpsc::Sender<(SocketAddr, Bytes)>,
    addr: SocketAddr,
    datagram: Bytes,
    stats: &Arc<VpnServerStats>,
    drop_on_full: bool,
    packet_count: u64,
) {
    match outbound_tx.try_send((addr, datagram)) {
        Ok(()) => {
            stats.packets_to_clients.fetch_add(packet_count, Ordering::Relaxed);
        }
        Err(mpsc::error::TrySendError::Full(item)) => {
            if drop_on_full {
                stats.packets_dropped_full.fetch_add(packet_count, Ordering::Relaxed);
            } else {
                stats.packets_backpressure.fetch_add(packet_count, Ordering::Relaxed);
                if outbound_tx.send(item).await.is_ok() {
                    stats.packets_to_clients.fetch_add(packet_count, Ordering::Relaxed);
                }
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

/// IP address extracted from a packet (source or destination).
enum PacketIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Minimum IPv4 header size (20 bytes, no options).
const IPV4_MIN_HEADER: usize = 20;
/// Minimum IPv6 header size (40 bytes fixed).
const IPV6_MIN_HEADER: usize = 40;
/// IPv4 version nibble.
const IP_VERSION_4: u8 = 4;
/// IPv6 version nibble.
const IP_VERSION_6: u8 = 6;

/// Extract source IP address from an IP packet (IPv4 or IPv6).
#[inline]
fn extract_source_ip(packet: &[u8]) -> Option<PacketIp> {
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }
    let version = packet[0] >> 4;
    if version == IP_VERSION_4 {
        return Some(PacketIp::V4(read_ipv4_addr(packet, 12)));
    }
    if version == IP_VERSION_6 {
        if len < IPV6_MIN_HEADER {
            return None;
        }
        return Some(PacketIp::V6(read_ipv6_addr(packet, 8)));
    }
    None
}

/// Extract destination IP address from an IP packet (IPv4 or IPv6).
#[inline]
fn extract_dest_ip(packet: &[u8]) -> Option<PacketIp> {
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }
    let version = packet[0] >> 4;
    if version == IP_VERSION_4 {
        return Some(PacketIp::V4(read_ipv4_addr(packet, 16)));
    }
    if version == IP_VERSION_6 {
        if len < IPV6_MIN_HEADER {
            return None;
        }
        return Some(PacketIp::V6(read_ipv6_addr(packet, 24)));
    }
    None
}

/// Read an IPv4 address from a packet at the given offset.
#[inline(always)]
fn read_ipv4_addr(packet: &[u8], offset: usize) -> Ipv4Addr {
    let bytes: [u8; 4] = packet[offset..offset + 4]
        .try_into()
        .expect("IPv4 address read: bounds already verified");
    Ipv4Addr::from(bytes)
}

/// Read an IPv6 address from a packet at the given offset.
#[inline(always)]
fn read_ipv6_addr(packet: &[u8], offset: usize) -> Ipv6Addr {
    let bytes: [u8; 16] = packet[offset..offset + 16]
        .try_into()
        .expect("IPv6 address read: bounds already verified");
    Ipv6Addr::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_pool_allocation() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        assert_eq!(pool.server_ip(), Ipv4Addr::new(10, 0, 0, 1));

        let ip1 = pool.allocate(1).unwrap();
        let ip2 = pool.allocate(2).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 3));

        // Re-allocate same device returns same IP (idempotent).
        assert_eq!(pool.allocate(1).unwrap(), ip1);

        // Release and reallocate reuses the released IP.
        pool.release(1);
        let ip3 = pool.allocate(3).unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ip_pool_reserve_next_available() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);
        let reserved = pool.reserve_next_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 2));
        let ip1 = pool.allocate(1).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network, None);
        assert!(pool.allocate(1).is_some());
        assert!(pool.allocate(2).is_none()); // only .2 available for clients
    }

    #[test]
    fn test_ip6_pool_allocation() {
        let network: Ipv6Net = "fd00::/120".parse().unwrap();
        let mut pool = Ip6Pool::new(network, None).unwrap();

        assert_eq!(pool.server_ip(), "fd00::1".parse::<Ipv6Addr>().unwrap());

        let ip1 = pool.allocate(1).unwrap();
        let ip2 = pool.allocate(2).unwrap();
        assert_eq!(ip1, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ip2, "fd00::3".parse::<Ipv6Addr>().unwrap());

        assert_eq!(pool.allocate(1).unwrap(), ip1);

        pool.release(1);
        let ip3 = pool.allocate(3).unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ip6_pool_exhaustion() {
        let network: Ipv6Net = "fd00::/126".parse().unwrap();
        let mut pool = Ip6Pool::new(network, None).unwrap();
        assert!(pool.allocate(1).is_some());
        assert!(pool.allocate(2).is_none());
    }

    #[test]
    fn test_ip6_pool_rejects_slash127_and_128() {
        for prefix in ["fd00::/127", "fd00::/128"] {
            let network: Ipv6Net = prefix.parse().unwrap();
            let result = Ip6Pool::new(network, None);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), VpnError::Config(_)));
        }
    }

    #[test]
    fn test_extract_dest_ip_v4_and_v6() {
        let mut p4 = [0u8; 20];
        p4[0] = 0x45;
        p4[16..20].copy_from_slice(&[10, 0, 0, 5]);
        assert!(matches!(extract_dest_ip(&p4), Some(PacketIp::V4(ip)) if ip == Ipv4Addr::new(10, 0, 0, 5)));

        let mut p6 = [0u8; 40];
        p6[0] = 0x60;
        p6[24..40].copy_from_slice(&"fd00::5".parse::<Ipv6Addr>().unwrap().octets());
        assert!(matches!(extract_dest_ip(&p6), Some(PacketIp::V6(ip)) if ip == "fd00::5".parse::<Ipv6Addr>().unwrap()));

        assert!(extract_dest_ip(&[0x45u8; 10]).is_none());
        assert!(extract_dest_ip(&[]).is_none());
    }

    #[test]
    fn test_extract_source_ip_v4_and_v6() {
        let mut p4 = [0u8; 20];
        p4[0] = 0x45;
        p4[12..16].copy_from_slice(&[192, 168, 1, 100]);
        assert!(matches!(extract_source_ip(&p4), Some(PacketIp::V4(ip)) if ip == Ipv4Addr::new(192, 168, 1, 100)));

        let mut p6 = [0u8; 40];
        p6[0] = 0x60;
        p6[8..24].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        assert!(matches!(extract_source_ip(&p6), Some(PacketIp::V6(ip)) if ip == "fd00::2".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_stats_initial_zero() {
        let stats = VpnServerStats::new();
        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 0);
    }
}
