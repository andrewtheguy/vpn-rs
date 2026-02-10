//! VPN server implementation.
//!
//! The VPN server listens for incoming client connections via iroh,
//! assigns IP addresses from a pool, and manages direct IP-over-QUIC
//! tunnels for each connected client. IP packets are framed and sent
//! directly over the encrypted iroh QUIC connection.

use crate::vpn_core::buffer::{as_mut_byte_slice, uninitialized_vec};
use crate::vpn_core::config::VpnServerConfig;
use crate::vpn_core::device::{TunConfig, TunDevice};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::signaling::{
    frame_ip_packet, read_message, write_message, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, HEARTBEAT_PONG_BYTE, MAX_HANDSHAKE_SIZE,
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use ipnet::{Ipv4Net, Ipv6Net};
use iroh::{Endpoint, EndpointId};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

/// Maximum IP packet size.
const MAX_IP_PACKET_SIZE: usize = 65536;

/// Performance statistics for the VPN server.
///
/// These atomic counters replace per-packet trace logging to eliminate
/// logging overhead in hot paths.
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
    /// Packets dropped due to client channel full (drop_on_full=true).
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

// Channel buffer sizes are now configurable via VpnServerConfig:
// - client_channel_size: per-client outbound buffer (default 1024)
// - tun_writer_channel_size: aggregate TUN writer buffer (default 4096)
// See config.rs for detailed documentation on tradeoffs.

/// State for a connected VPN client.
struct ClientState {
    /// Unique session ID for this connection.
    /// Used to detect stale cleanup operations when a client reconnects quickly.
    session_id: u64,
    /// Client's assigned VPN IP (IPv4). None for IPv6-only mode.
    assigned_ip: Option<Ipv4Addr>,
    /// Client's assigned IPv6 VPN address (optional, for dual-stack or IPv6-only).
    assigned_ip6: Option<Ipv6Addr>,
    /// Channel to send framed packets to the client's dedicated writer task.
    /// The writer task owns the SendStream and performs actual I/O.
    /// Uses Bytes for zero-copy sends (freeze BytesMut instead of cloning Vec).
    packet_tx: mpsc::Sender<Bytes>,
}

/// Per-client context used by the data handler.
struct ClientContext {
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip6: Option<Ipv6Addr>,
    /// Current client's key for identifying self in spoofing checks.
    client_key: (EndpointId, u64),
    /// Reverse lookup: IPv4 address -> client key (for inter-client spoofing detection).
    ip_to_endpoint: Arc<DashMap<Ipv4Addr, (EndpointId, u64)>>,
    /// Reverse lookup: IPv6 address -> client key (for inter-client spoofing detection).
    ip6_to_endpoint: Arc<DashMap<Ipv6Addr, (EndpointId, u64)>>,
    /// Whether to disable all source IP spoofing checks.
    disable_spoofing_check: bool,
}

/// IP address pool for assigning addresses to clients.
struct IpPool {
    /// Network CIDR.
    network: Ipv4Net,
    /// Server's IP (first usable address).
    server_ip: Ipv4Addr,
    /// Next IP to assign.
    next_ip: u32,
    /// Maximum IP in the range.
    max_ip: u32,
    /// IPs currently in use (mapped from (client endpoint ID, device ID)).
    in_use: HashMap<(EndpointId, u64), Ipv4Addr>,
    /// Released IPs available for reuse.
    released: Vec<Ipv4Addr>,
    /// Reserved IPs that should never be assigned to clients.
    reserved: HashSet<Ipv4Addr>,
}

impl IpPool {
    /// Create a new IP pool from a network with optional custom server IP.
    ///
    /// If `server_ip` is None, defaults to first host in network (e.g., .1).
    /// Client IPs start from the address after the server IP.
    fn new(network: Ipv4Net, server_ip: Option<Ipv4Addr>) -> Self {
        let net_addr: u32 = network.network().into();
        let broadcast: u32 = network.broadcast().into();

        // Server gets specified IP or defaults to .1
        let server_ip = server_ip.unwrap_or_else(|| Ipv4Addr::from(net_addr + 1));
        let server_ip_u32: u32 = server_ip.into();

        // Clients start from the address after server IP
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

    /// Get the server's IP address.
    fn server_ip(&self) -> Ipv4Addr {
        self.server_ip
    }

    /// Get the network CIDR.
    fn network(&self) -> Ipv4Net {
        self.network
    }

    /// Reserve a specific IP address so it will not be assigned to clients.
    #[cfg(test)]
    fn reserve_ip(&mut self, ip: Ipv4Addr, label: &str) -> Result<(), String> {
        if !self.network.contains(&ip) {
            return Err(format!(
                "{} {} is not within VPN network {}",
                label, ip, self.network
            ));
        }
        if ip == self.server_ip {
            return Err(format!(
                "{} {} must not equal server_ip {}",
                label, ip, self.server_ip
            ));
        }
        let network_addr = self.network.network();
        let broadcast = self.network.broadcast();
        if ip == network_addr || ip == broadcast {
            return Err(format!(
                "{} {} is not a usable host address in {}",
                label, ip, self.network
            ));
        }
        if self.reserved.contains(&ip) {
            return Ok(());
        }
        // O(n) scan of in_use: small in practice, avoids extra lookup map.
        if self.in_use.values().any(|assigned| *assigned == ip) {
            return Err(format!("{} {} is already assigned to a client", label, ip));
        }
        self.released.retain(|released_ip| *released_ip != ip);
        self.reserved.insert(ip);
        Ok(())
    }

    /// Reserve the next available IP address for internal use.
    #[cfg(test)]
    fn reserve_next_available(&mut self) -> Option<Ipv4Addr> {
        let ip = self.next_unreserved_ip()?;
        self.reserved.insert(ip);
        Some(ip)
    }

    /// Reserve the highest available IP address for internal use.
    #[cfg(test)]
    fn reserve_last_available(&mut self) -> Option<Ipv4Addr> {
        if self.next_ip > self.max_ip {
            return None;
        }

        let mut candidate = None;
        for ip_u32 in (self.next_ip..=self.max_ip).rev() {
            let ip = Ipv4Addr::from(ip_u32);
            if ip == self.server_ip {
                continue;
            }
            if self.reserved.contains(&ip) {
                continue;
            }
            // O(n) scan of in_use: small in practice, avoids extra lookup map.
            if self.in_use.values().any(|assigned| *assigned == ip) {
                continue;
            }
            candidate = Some(ip);
            break;
        }

        let ip = candidate?;
        self.released.retain(|released_ip| *released_ip != ip);
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

    /// Allocate an IP address for a client.
    fn allocate(&mut self, endpoint_id: EndpointId, device_id: u64) -> Option<Ipv4Addr> {
        let key = (endpoint_id, device_id);
        // Check if client already has an IP
        if let Some(&ip) = self.in_use.get(&key) {
            return Some(ip);
        }

        // Try to reuse a released IP first
        while let Some(ip) = self.released.pop() {
            if self.reserved.contains(&ip) {
                continue;
            }
            self.in_use.insert(key, ip);
            return Some(ip);
        }

        // Allocate new IP if available
        if let Some(ip) = self.next_unreserved_ip() {
            self.in_use.insert(key, ip);
            Some(ip)
        } else {
            None // Pool exhausted
        }
    }

    /// Release an IP address when a client disconnects.
    fn release(&mut self, endpoint_id: &EndpointId, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&(*endpoint_id, device_id)) {
            self.released.push(ip);
        }
    }
}

/// IPv6 address pool for assigning /128 addresses to clients.
#[derive(Debug)]
struct Ip6Pool {
    /// Network CIDR (e.g., fd00::/64).
    network: Ipv6Net,
    /// Server's IPv6 (first usable address).
    server_ip: Ipv6Addr,
    /// Next IP to assign (as u128 for arithmetic).
    next_ip: u128,
    /// Maximum IP in the range.
    max_ip: u128,
    /// IPs currently in use (mapped from (client endpoint ID, device ID)).
    in_use: HashMap<(EndpointId, u64), Ipv6Addr>,
    /// Released IPs available for reuse.
    released: Vec<Ipv6Addr>,
}

impl Ip6Pool {
    /// Create a new IPv6 pool from a network with optional custom server IP.
    ///
    /// If `server_ip` is None, defaults to ::1 within the network.
    /// Client IPs start from the address after the server IP.
    ///
    /// Returns an error if the prefix length is >= 127 (/127 or /128), as these
    /// networks have no usable addresses for client allocation.
    fn new(network: Ipv6Net, server_ip: Option<Ipv6Addr>) -> VpnResult<Self> {
        let prefix_len = network.prefix_len();

        // /127 has only 2 addresses (server takes ::1, no room for clients)
        // /128 is a single address (unusable for server + clients)
        if prefix_len >= 127 {
            return Err(VpnError::config(format!(
                "IPv6 prefix /{} is too small for VPN pool (need at least /126 for 1 client)",
                prefix_len
            )));
        }

        let net_addr: u128 = network.network().into();

        // Server gets specified IP or defaults to ::1 within network
        let server_ip = server_ip.unwrap_or_else(|| Ipv6Addr::from(net_addr + 1));
        let server_ip_u128: u128 = server_ip.into();

        // Clients start from address after server IP
        let next_ip = server_ip_u128 + 1;

        // Calculate max_ip based on prefix length
        let host_bits: u32 = 128 - u32::from(prefix_len);
        // host_bits is guaranteed >= 2 here because prefix_len < 127, so the shift is safe
        let max_ip = net_addr + ((1u128 << host_bits) - 1) - 1; // Exclude last address

        Ok(Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            in_use: HashMap::new(),
            released: Vec::new(),
        })
    }

    /// Get the server's IPv6 address.
    fn server_ip(&self) -> Ipv6Addr {
        self.server_ip
    }

    /// Get the network CIDR.
    fn network(&self) -> Ipv6Net {
        self.network
    }

    /// Allocate an IPv6 address for a client.
    fn allocate(&mut self, endpoint_id: EndpointId, device_id: u64) -> Option<Ipv6Addr> {
        let key = (endpoint_id, device_id);
        // Check if client already has an IP
        if let Some(&ip) = self.in_use.get(&key) {
            return Some(ip);
        }

        // Try to reuse a released IP first
        if let Some(ip) = self.released.pop() {
            self.in_use.insert(key, ip);
            return Some(ip);
        }

        // Allocate new IP if available
        if self.next_ip <= self.max_ip {
            let ip = Ipv6Addr::from(self.next_ip);
            self.next_ip += 1;
            self.in_use.insert(key, ip);
            Some(ip)
        } else {
            None // Pool exhausted
        }
    }

    /// Release an IPv6 address when a client disconnects.
    fn release(&mut self, endpoint_id: &EndpointId, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&(*endpoint_id, device_id)) {
            self.released.push(ip);
        }
    }
}

/// VPN server instance.
pub struct VpnServer {
    /// Server configuration.
    config: VpnServerConfig,
    /// IPv4 address pool (None if IPv6-only mode).
    ip_pool: Option<Arc<RwLock<IpPool>>>,
    /// IPv6 address pool (None if IPv4-only mode).
    ip6_pool: Option<Arc<RwLock<Ip6Pool>>>,
    /// Connected clients (by (endpoint ID, device ID)).
    /// Lock-free map for hot-path packet routing.
    clients: Arc<DashMap<(EndpointId, u64), ClientState>>,
    /// Reverse lookup: IPv4 address -> (endpoint ID, device ID).
    /// Lock-free map for hot-path routing lookups.
    ip_to_endpoint: Arc<DashMap<Ipv4Addr, (EndpointId, u64)>>,
    /// Reverse lookup: IPv6 address -> (endpoint ID, device ID).
    /// Lock-free map for hot-path routing lookups.
    ip6_to_endpoint: Arc<DashMap<Ipv6Addr, (EndpointId, u64)>>,
    /// TUN device for VPN traffic.
    tun_device: Option<TunDevice>,
    /// Atomic counter for active connections (prevents race in max_clients check).
    active_connections: AtomicUsize,
    /// Session ID counter for unique connection identification.
    next_session_id: AtomicU64,
    /// Performance statistics (atomic counters, no locking overhead).
    stats: Arc<VpnServerStats>,
}

impl VpnServer {
    /// Create a new VPN server.
    pub async fn new(config: VpnServerConfig) -> VpnResult<Self> {
        // Validate configuration
        config.validate().map_err(VpnError::config)?;

        // Create IPv4 pool if configured
        let ip_pool = match config.network {
            Some(network) => Some(Arc::new(RwLock::new(IpPool::new(
                network,
                config.server_ip,
            )))),
            None => None,
        };

        // Create IPv6 pool if configured (dual-stack or IPv6-only)
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
            ip_to_endpoint: Arc::new(DashMap::new()),
            ip6_to_endpoint: Arc::new(DashMap::new()),
            tun_device: None,
            active_connections: AtomicUsize::new(0),
            next_session_id: AtomicU64::new(1),
            stats: Arc::new(VpnServerStats::new()),
        })
    }

    /// Create and configure the TUN device.
    pub async fn setup_tun(&mut self) -> VpnResult<()> {
        // Get IPv4 configuration if available
        let (server_ip, netmask) = if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            (Some(pool.server_ip()), Some(pool.network().netmask()))
        } else {
            (None, None)
        };

        // Get IPv6 configuration if available
        let (server_ip6, prefix_len6) = if let Some(ref ip6_pool) = self.ip6_pool {
            let pool6 = ip6_pool.read().await;
            (Some(pool6.server_ip()), Some(pool6.network().prefix_len()))
        } else {
            (None, None)
        };

        // Create TUN config based on available protocols
        let tun_config = match (server_ip, netmask, server_ip6, prefix_len6) {
            // Dual-stack: both IPv4 and IPv6
            (Some(ip4), Some(mask), Some(ip6), Some(pl6)) => TunConfig::new(ip4, mask, ip4)
                .with_mtu(self.config.mtu)
                .with_ipv6(ip6, pl6)?,
            // IPv4-only
            (Some(ip4), Some(mask), None, None) => {
                TunConfig::new(ip4, mask, ip4).with_mtu(self.config.mtu)
            }
            // IPv6-only
            (None, None, Some(ip6), Some(pl6)) => TunConfig::ipv6_only(ip6, pl6, self.config.mtu)?,
            // Invalid: no networks configured (should be caught by validate())
            _ => {
                return Err(VpnError::config(
                    "No network configured (need at least IPv4 or IPv6)".to_string(),
                ))
            }
        };

        let device = TunDevice::create(tun_config)?;

        // Log what was created
        match (server_ip, server_ip6) {
            (Some(ip4), Some(ip6)) => {
                log::info!(
                    "Created TUN device: {} with IP {} and IPv6 {}",
                    device.name(),
                    ip4,
                    ip6
                );
            }
            (Some(ip4), None) => {
                log::info!("Created TUN device: {} with IP {}", device.name(), ip4);
            }
            (None, Some(ip6)) => {
                log::info!(
                    "Created TUN device: {} with IPv6 {} (IPv6-only mode)",
                    device.name(),
                    ip6
                );
            }
            (None, None) => unreachable!(), // Caught above
        }

        self.tun_device = Some(device);
        Ok(())
    }

    /// Run the VPN server, accepting connections via iroh.
    pub async fn run(mut self, endpoint: Endpoint) -> VpnResult<()> {
        // Setup TUN device
        self.setup_tun().await?;

        log::info!("VPN Server started:");
        // Log IPv4 info if configured
        if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            log::info!("  Network: {}", pool.network());
            log::info!("  Server IP: {}", pool.server_ip());
        }
        // Log IPv6 info if configured
        if let Some(ref ip6_pool) = self.ip6_pool {
            let pool = ip6_pool.read().await;
            log::info!("  Network6: {}", pool.network());
            log::info!("  Server IP6: {}", pool.server_ip());
        }
        // Log mode
        if self.ip_pool.is_none() {
            log::info!("  Mode: IPv6-only");
        } else if self.ip6_pool.is_some() {
            log::info!("  Mode: dual-stack (IPv4 + IPv6)");
        } else {
            log::info!("  Mode: IPv4-only");
        }
        log::info!("  Node ID: {}", endpoint.id());

        // Take TUN device and split it
        let tun_device = self.tun_device.take().expect("TUN device not set up");
        let (tun_reader, mut tun_writer) = tun_device.split()?;

        // Create channel for TUN writes from all clients.
        // This replaces the Arc<Mutex<TunWriter>> with a dedicated writer task,
        // eliminating mutex contention in the hot path.
        // Channel size is configurable via VpnServerConfig::tun_writer_channel_size.
        let (tun_write_tx, mut tun_write_rx) =
            mpsc::channel::<Bytes>(self.config.tun_writer_channel_size);
        log::debug!(
            "TUN writer channel size: {}",
            self.config.tun_writer_channel_size
        );

        // Spawn dedicated TUN writer task that owns TunWriter exclusively.
        // All clients send validated packets through the channel; this task
        // performs the actual writes without any mutex contention.
        // Store JoinHandle for graceful shutdown.
        let tun_writer_stats = self.stats.clone();
        let tun_writer_handle = tokio::spawn(async move {
            log::info!("TUN writer task started");
            let mut batch = Vec::with_capacity(64);
            loop {
                let count = tun_write_rx.recv_many(&mut batch, 64).await;
                if count == 0 {
                    break;
                }

                for packet in batch.drain(..) {
                    if let Err(e) = tun_writer.write_all(&packet).await {
                        tun_writer_stats
                            .packets_tun_write_failed
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("Failed to write to TUN: {}", e);
                        // Continue processing - individual write failures shouldn't stop the writer
                    }
                }
            }
            log::info!("TUN writer task exiting (channel closed)");
        });

        let server = Arc::new(self);

        // Spawn TUN reader task (reads from TUN, routes to clients)
        // Store JoinHandle for graceful shutdown.
        let server_tun = server.clone();
        let tun_reader_handle = tokio::spawn(async move {
            if let Err(e) = server_tun.run_tun_reader(tun_reader).await {
                log::error!("TUN reader error: {}", e);
            }
        });

        // Accept incoming connections
        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    let server = server.clone();
                    let tun_write_tx = tun_write_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(incoming, tun_write_tx).await {
                            log::error!("Connection error: {}", e);
                        }
                    });
                }
                None => {
                    log::info!("Endpoint closed, shutting down");
                    break;
                }
            }
        }

        // Graceful shutdown: drop channel sender to signal TUN writer to exit,
        // then await both tasks to ensure clean termination.
        log::info!("Shutting down TUN tasks...");
        drop(tun_write_tx);

        // Abort TUN reader (it's blocked on TUN read, won't exit on its own)
        tun_reader_handle.abort();

        // Wait for TUN writer to drain any remaining packets and exit
        if let Err(e) = tun_writer_handle.await {
            if !e.is_cancelled() {
                log::warn!("TUN writer task panicked: {}", e);
            }
        }

        log::info!("TUN tasks shutdown complete");
        Ok(())
    }

    /// Handle an incoming VPN connection.
    async fn handle_connection(
        &self,
        incoming: iroh::endpoint::Incoming,
        tun_write_tx: mpsc::Sender<Bytes>,
    ) -> VpnResult<()> {
        let connection = incoming
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept connection: {}", e)))?;

        let remote_id = connection.remote_id();
        log::info!("New VPN connection from {}", remote_id);

        // Accept handshake stream
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept stream: {}", e)))?;

        // Read handshake
        let handshake_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE).await?;
        let handshake = VpnHandshake::decode(&handshake_data)?;

        log::debug!(
            "Received handshake from {} for device {}",
            remote_id,
            handshake.device_id
        );

        // Validate auth token (required - server must have auth_tokens configured)
        if let Some(ref valid_tokens) = self.config.auth_tokens {
            match &handshake.auth_token {
                Some(client_token) if valid_tokens.contains(client_token) => {
                    log::debug!("Client {} provided valid auth token", remote_id);
                }
                Some(_) => {
                    log::warn!("Client {} provided invalid auth token", remote_id);
                    let response = VpnHandshakeResponse::rejected("Invalid authentication token");
                    write_message(&mut send, &response.encode()?).await?;
                    let _ = send.finish();
                    return Err(VpnError::Signaling("Invalid authentication token".into()));
                }
                None => {
                    log::warn!("Client {} missing required auth token", remote_id);
                    let response = VpnHandshakeResponse::rejected("Authentication token required");
                    write_message(&mut send, &response.encode()?).await?;
                    let _ = send.finish();
                    return Err(VpnError::Signaling("Authentication token required".into()));
                }
            }
        } else {
            // Server misconfigured - should always have auth_tokens
            log::error!("Server has no auth tokens configured - rejecting connection");
            let response = VpnHandshakeResponse::rejected("Server misconfigured");
            write_message(&mut send, &response.encode()?).await?;
            let _ = send.finish();
            return Err(VpnError::Signaling(
                "Server has no auth tokens configured".into(),
            ));
        }

        // Atomically increment connection count and check max_clients
        // fetch_add returns the previous value, so if it was >= max_clients, we're over
        let prev_count = self.active_connections.fetch_add(1, Ordering::SeqCst);
        if prev_count >= self.config.max_clients {
            // We exceeded the limit - decrement and reject
            self.active_connections.fetch_sub(1, Ordering::SeqCst);
            let response = VpnHandshakeResponse::rejected("Server full");
            write_message(&mut send, &response.encode()?).await?;
            let _ = send.finish();
            return Err(VpnError::IpAssignment("Server full".into()));
        }

        // From this point on, we must decrement active_connections on any error
        let result = self
            .handle_connection_inner(
                &mut send,
                remote_id,
                connection,
                tun_write_tx,
                handshake.device_id,
            )
            .await;

        // Always decrement on exit (success or failure)
        self.active_connections.fetch_sub(1, Ordering::SeqCst);

        result
    }

    /// Inner connection handler - separated to ensure atomic counter cleanup.
    async fn handle_connection_inner(
        &self,
        send: &mut iroh::endpoint::SendStream,
        remote_id: EndpointId,
        connection: iroh::endpoint::Connection,
        tun_write_tx: mpsc::Sender<Bytes>,
        device_id: u64,
    ) -> VpnResult<()> {
        // Allocate IPv4 for client (if server has IPv4 configured)
        let assigned_ip = if let Some(ref ip_pool) = self.ip_pool {
            let mut pool = ip_pool.write().await;
            match pool.allocate(remote_id, device_id) {
                Some(ip) => Some(ip),
                None => {
                    // IPv4 pool exhausted - fatal if this is IPv4-only mode
                    if self.ip6_pool.is_none() {
                        return Err(VpnError::IpAssignment("IPv4 pool exhausted".into()));
                    }
                    // Dual-stack: continue with IPv6 only
                    log::warn!(
                        "IPv4 pool exhausted for client {}, using IPv6 only",
                        remote_id
                    );
                    None
                }
            }
        } else {
            None
        };

        // Allocate IPv6 for client (if server has IPv6 configured)
        let assigned_ip6 = if let Some(ref ip6_pool) = self.ip6_pool {
            let mut pool = ip6_pool.write().await;
            match pool.allocate(remote_id, device_id) {
                Some(ip) => Some(ip),
                None => {
                    // IPv6 pool exhausted - fatal if this is IPv6-only mode
                    if self.ip_pool.is_none() {
                        return Err(VpnError::IpAssignment("IPv6 pool exhausted".into()));
                    }
                    // Dual-stack: continue with IPv4 only
                    log::warn!(
                        "IPv6 pool exhausted for client {}, using IPv4 only",
                        remote_id
                    );
                    None
                }
            }
        } else {
            None
        };

        // Must have at least one IP assigned
        if assigned_ip.is_none() && assigned_ip6.is_none() {
            return Err(VpnError::IpAssignment("All IP pools exhausted".into()));
        }

        // Build handshake response based on what was allocated
        let response = match (assigned_ip, assigned_ip6) {
            // Dual-stack: both IPv4 and IPv6
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
                )
            }
            // IPv4-only
            (Some(ip4), None) => {
                let ip_pool = self.ip_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted(ip4, ip_pool.network(), ip_pool.server_ip())
            }
            // IPv6-only
            (None, Some(ip6)) => {
                let ip6_pool = self.ip6_pool.as_ref().unwrap().read().await;
                VpnHandshakeResponse::accepted_ipv6_only(
                    ip6,
                    ip6_pool.network(),
                    ip6_pool.server_ip(),
                )
            }
            // Should not happen - checked above
            (None, None) => unreachable!(),
        };

        write_message(send, &response.encode()?).await?;
        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }

        // Log connection based on what was assigned
        match (assigned_ip, assigned_ip6) {
            (Some(ip4), Some(ip6)) => {
                log::info!(
                    "Client {} connected, assigned IP: {}, IPv6: {}",
                    remote_id,
                    ip4,
                    ip6
                );
            }
            (Some(ip4), None) => {
                log::info!("Client {} connected, assigned IP: {}", remote_id, ip4);
            }
            (None, Some(ip6)) => {
                log::info!(
                    "Client {} connected, assigned IPv6: {} (IPv6-only)",
                    remote_id,
                    ip6
                );
            }
            (None, None) => unreachable!(),
        }

        // Accept data stream for IP packets
        let (data_send, data_recv) = connection
            .accept_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept data stream: {}", e)))?;

        log::info!("Client {} data stream established", remote_id);

        // Create channel for sending framed packets to this client's writer task.
        // The writer task owns the SendStream and performs actual I/O, decoupling
        // packet production from stream writes to reduce locking overhead.
        // Uses Bytes for zero-copy sends (freeze BytesMut instead of cloning Vec).
        // Channel size is configurable via VpnServerConfig::client_channel_size.
        let (packet_tx, mut packet_rx) = mpsc::channel::<Bytes>(self.config.client_channel_size);

        // Create oneshot channel for writer error signaling.
        // When writer fails, it sends the error through this channel to trigger
        // immediate cleanup instead of waiting for heartbeat timeout.
        let (writer_error_tx, writer_error_rx) = oneshot::channel::<String>();

        // Spawn dedicated writer task that owns the SendStream.
        // Returns error through oneshot channel for immediate cleanup propagation.
        // At least one of assigned_ip or assigned_ip6 must be set at this point
        let writer_client_id = assigned_ip
            .map(|ip| ip.to_string())
            .or_else(|| assigned_ip6.map(|ip| ip.to_string()))
            .expect("at least one IP must be assigned");
        let mut data_send = data_send;
        let writer_handle = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(64);
            let error = loop {
                let count = packet_rx.recv_many(&mut batch, 64).await;
                if count == 0 {
                    // Channel closed (normal shutdown) - signal end of stream to peer
                    if let Err(e) = data_send.finish() {
                        log::warn!(
                            "Failed to finish QUIC stream for client {}: {}",
                            writer_client_id,
                            e
                        );
                        break Some(format!("QUIC finish error: {}", e));
                    }
                    break None;
                }

                if let Err(e) = data_send.write_all_chunks(batch.as_mut_slice()).await {
                    log::warn!("Failed to write to client {}: {}", writer_client_id, e);
                    break Some(format!("QUIC write error: {}", e));
                }
                batch.clear();
            };
            log::trace!("Writer task for {} exiting", writer_client_id);
            // Signal error to trigger immediate cleanup (ignore send error if receiver dropped)
            if let Some(err_msg) = error {
                let _ = writer_error_tx.send(err_msg);
            }
        });

        // Generate unique session ID for this connection
        // Used to detect stale cleanup when same client reconnects quickly
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        // Store client state with channel sender for TUN handler to use
        let client_state = ClientState {
            session_id,
            assigned_ip,
            assigned_ip6,
            packet_tx: packet_tx.clone(),
        };

        // Reconnect handling: if a client with the same (EndpointId, DeviceId) exists,
        // we can safely overwrite its entry in the map with the new connection state.
        // The old ClientState's packet_tx sender is dropped, causing its writer task
        // to exit when the channel closes. The session_id check in cleanup prevents
        // stale cleanup tasks from affecting the new connection.
        let client_key = (remote_id, device_id);

        // DashMap operations are lock-free (no async needed)
        self.clients.insert(client_key, client_state);

        // Add IPv4 reverse lookup if assigned
        if let Some(ip4) = assigned_ip {
            self.ip_to_endpoint.insert(ip4, (remote_id, device_id));
        }

        // Add IPv6 reverse lookup if assigned
        if let Some(ip6) = assigned_ip6 {
            self.ip6_to_endpoint.insert(ip6, (remote_id, device_id));
        }

        // Handle client data
        let clients = self.clients.clone();
        let ip_pool = self.ip_pool.clone();
        let ip6_pool = self.ip6_pool.clone();
        let ip_to_endpoint = self.ip_to_endpoint.clone();
        let ip6_to_endpoint = self.ip6_to_endpoint.clone();

        // Run client handler (blocks until client disconnects or writer fails)
        // packet_tx is used for heartbeat responses (sent via the writer task)
        // writer_error_rx triggers immediate cleanup on write failures
        let ctx = ClientContext {
            assigned_ip,
            assigned_ip6,
            client_key,
            ip_to_endpoint: ip_to_endpoint.clone(),
            ip6_to_endpoint: ip6_to_endpoint.clone(),
            disable_spoofing_check: self.config.disable_spoofing_check,
        };
        let result = Self::handle_client_data(
            packet_tx,
            data_recv,
            ctx,
            tun_write_tx,
            writer_error_rx,
            self.stats.clone(),
        )
        .await;

        // Abort writer task if still running (cleanup on any exit path)
        writer_handle.abort();

        if let Err(ref e) = result {
            log::error!("Client {} data error: {}", remote_id, e);
        }

        log::info!("Client {} disconnected", remote_id);

        // Cleanup - use session_id to detect stale cleanup from rapid reconnection.
        // Check-before-remove: verify session_id matches before removing anything.
        // If a newer connection replaced us, do nothing - that connection owns the resources.
        // DashMap remove_if atomically checks and removes if the predicate holds.
        let removed = clients.remove_if(&client_key, |_, state| state.session_id == session_id);

        let (endpoint_to_release, release_ipv4, release_ipv6) =
            if let Some((_, client_state)) = removed {
                // Remove IPv4 mapping if it points to us
                if let Some(ip4) = assigned_ip {
                    ip_to_endpoint
                        .remove_if(&ip4, |_, (ep, dev)| *ep == remote_id && *dev == device_id);
                }

                // Remove IPv6 mapping if it points to us
                if let Some(ip6) = assigned_ip6 {
                    ip6_to_endpoint.remove_if(&ip6, |_, (ep6, dev6)| {
                        *ep6 == remote_id && *dev6 == device_id
                    });
                }

                (
                    Some((remote_id, device_id)),
                    client_state.assigned_ip.is_some(),
                    client_state.assigned_ip6.is_some(),
                )
            } else {
                // Session_id didn't match or client already gone - do nothing
                (None, false, false)
            };

        if let Some((endpoint_id, dev_id)) = endpoint_to_release {
            // Release IPv4 if allocated for this session
            if release_ipv4 {
                if let Some(ref ip_pool) = ip_pool {
                    ip_pool.write().await.release(&endpoint_id, dev_id);
                }
            }

            // Release IPv6 if allocated for this session
            if release_ipv6 {
                if let Some(ref ip6_pool) = ip6_pool {
                    ip6_pool.write().await.release(&endpoint_id, dev_id);
                }
            }
        }

        result
    }

    /// Handle client data stream.
    ///
    /// This function processes incoming data from the client and responds to heartbeats.
    /// It exits when either:
    /// - The client disconnects (inbound stream closes)
    /// - The writer task fails (error received via writer_error_rx)
    ///
    /// TUN writes are sent through the `tun_write_tx` channel to a dedicated writer task,
    /// eliminating mutex contention. Backpressure is applied when the channel is full.
    ///
    /// At least one of `ctx.assigned_ip` (IPv4) or `ctx.assigned_ip6` (IPv6) must be provided.
    async fn handle_client_data(
        packet_tx: mpsc::Sender<Bytes>,
        mut data_recv: iroh::endpoint::RecvStream,
        ctx: ClientContext,
        tun_write_tx: mpsc::Sender<Bytes>,
        writer_error_rx: oneshot::Receiver<String>,
        stats: Arc<VpnServerStats>,
    ) -> VpnResult<()> {
        // Create client identifier string for logging (used both in spawned task and select!)
        // At least one of assigned_ip or assigned_ip6 must be set (enforced by caller)
        let client_id = ctx
            .assigned_ip
            .map(|ip| ip.to_string())
            .or_else(|| ctx.assigned_ip6.map(|ip| ip.to_string()))
            .expect("at least one IP must be assigned");
        let client_id_outer = client_id.clone(); // For use in select! block

        // Spawn inbound task (QUIC stream -> TUN via channel)
        let mut inbound_handle = tokio::spawn(async move {
            let mut type_buf = [0u8; 1];
            let mut len_buf = [0u8; 4];
            let mut data_buf = vec![0u8; MAX_IP_PACKET_SIZE];
            loop {
                // Read message type
                match data_recv.read_exact(&mut type_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Client {} stream closed: {}", client_id, e);
                        break;
                    }
                }

                let msg_type = match DataMessageType::from_byte(type_buf[0]) {
                    Some(t) => t,
                    None => {
                        log::error!(
                            "Unknown message type from {}: 0x{:02x}, closing connection",
                            client_id,
                            type_buf[0]
                        );
                        break;
                    }
                };

                match msg_type {
                    DataMessageType::HeartbeatPing => {
                        // Respond with pong via the writer task channel (static Bytes, zero allocation)
                        log::trace!("Heartbeat ping from {}", client_id);
                        let pong = Bytes::from_static(HEARTBEAT_PONG_BYTE);
                        if packet_tx.send(pong).await.is_err() {
                            log::warn!(
                                "Failed to send heartbeat pong to {}: channel closed",
                                client_id
                            );
                            break;
                        }
                        continue;
                    }
                    DataMessageType::HeartbeatPong => {
                        // Server shouldn't receive pongs, ignore
                        log::trace!("Unexpected heartbeat pong from {}", client_id);
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
                        log::debug!("Failed to read IP packet length from {}: {}", client_id, e);
                        break;
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_IP_PACKET_SIZE {
                    log::error!("IP packet too large from {}: {}", client_id, len);
                    break;
                }

                // Read packet data
                match data_recv.read_exact(&mut data_buf[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Failed to read IP packet from {}: {}", client_id, e);
                        break;
                    }
                }

                let packet = &data_buf[..len];

                // Validate source IP to prevent inter-client IP spoofing.
                // We only reject packets if the source IP belongs to another client,
                // allowing clients to use their own public IPs (useful for dual-stack).
                let source_valid = if ctx.disable_spoofing_check {
                    // Spoofing check disabled - allow all packets
                    true
                } else {
                    match extract_source_ip(packet) {
                        Some(PacketIp::V4(src_ip)) => {
                            // Check if this IP belongs to another client
                            match ctx.ip_to_endpoint.get(&src_ip) {
                                Some(ref owner) if *owner.value() == ctx.client_key => true, // Our own assigned IP
                                Some(_) => {
                                    // IP belongs to another client - actual spoofing
                                    log::warn!(
                                        "IPv4 inter-client spoofing from client {}: source {} belongs to another client",
                                        client_id, src_ip
                                    );
                                    false
                                }
                                None => true, // Not a VPN-assigned IP - allow (e.g., client's public IP)
                            }
                        }
                        Some(PacketIp::V6(src_ip)) => {
                            // Silently drop link-local packets (fe80::/10) - these are normal
                            // OS traffic (neighbor discovery, etc.) that shouldn't be forwarded
                            let src_bytes = src_ip.octets();
                            let is_link_local =
                                src_bytes[0] == 0xfe && (src_bytes[1] & 0xc0) == 0x80;
                            if is_link_local {
                                // Link-local IPv6 packets are dropped (can't route across VPN)
                                false
                            } else {
                                // Check if this IP belongs to another client
                                match ctx.ip6_to_endpoint.get(&src_ip) {
                                    Some(ref owner) if *owner.value() == ctx.client_key => true, // Our own assigned IP
                                    Some(_) => {
                                        // IP belongs to another client - actual spoofing
                                        log::warn!(
                                            "IPv6 inter-client spoofing from client {}: source {} belongs to another client",
                                            client_id, src_ip
                                        );
                                        false
                                    }
                                    None => true, // Not a VPN-assigned IP - allow (e.g., client's public IP)
                                }
                            }
                        }
                        None => {
                            log::warn!(
                                "Failed to parse source IP from packet from client {}",
                                client_id
                            );
                            false
                        }
                    }
                };

                if !source_valid {
                    // Drop spoofed packet
                    stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                let packet_bytes = Bytes::copy_from_slice(packet);

                // Try non-blocking send first to avoid blocking on slow TUN writes
                match tun_write_tx.try_send(packet_bytes) {
                    Ok(()) => {
                        stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Full(data)) => {
                        // Channel full - apply backpressure by blocking until space available.
                        // This naturally rate-limits fast clients when TUN writes are slow.
                        if tun_write_tx.send(data).await.is_ok() {
                            stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats
                                .packets_tun_write_failed
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        stats
                            .packets_tun_write_failed
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        // Wait for either:
        // - Inbound task completes (client disconnection or stream error)
        // - Writer task signals an error (QUIC write failure)
        // This ensures immediate cleanup on writer failure instead of waiting for heartbeat timeout.
        tokio::select! {
            inbound_result = &mut inbound_handle => {
                // Inspect JoinHandle result to catch panics
                match inbound_result {
                    Ok(()) => {
                        // Client disconnected normally or stream error
                        log::trace!("Client {} inbound task completed", client_id_outer);
                    }
                    Err(e) if e.is_panic() => {
                        log::error!("Client {} inbound task panicked: {}", client_id_outer, e);
                        return Err(VpnError::ConnectionLost(format!("inbound task panicked: {}", e)));
                    }
                    Err(e) => {
                        // Cancelled or other JoinError
                        log::debug!("Client {} inbound task failed: {}", client_id_outer, e);
                        return Err(VpnError::ConnectionLost(format!("inbound task failed: {}", e)));
                    }
                }
            }
            writer_err = writer_error_rx => {
                // Writer task failed - abort inbound task and return error
                inbound_handle.abort();
                match writer_err {
                    Ok(err_msg) => {
                        log::debug!("Client {} writer failed: {}", client_id_outer, err_msg);
                        return Err(VpnError::ConnectionLost(err_msg));
                    }
                    Err(_) => {
                        // Sender dropped without error (normal shutdown via channel close)
                        log::trace!("Client {} writer channel closed", client_id_outer);
                    }
                }
            }
        }

        Ok(())
    }

    /// Run the TUN reader - reads packets from TUN and routes to clients.
    ///
    /// Memory note: Each packet requires a small allocation (5 bytes framing + packet length).
    /// We allocate based on actual packet size to avoid over-allocation for small packets.
    /// Most allocations are small and served from thread-local caches, making them fast.
    async fn run_tun_reader(
        &self,
        mut tun_reader: crate::vpn_core::device::TunReader,
    ) -> VpnResult<()> {
        log::info!("TUN reader started");

        let buffer_size = tun_reader.buffer_size();
        let mut buf = uninitialized_vec(buffer_size);
        // SAFETY: Buffer is immediately overwritten by tun_reader.read(), and only
        // the written portion (&buf_slice[..n]) is accessed. Skips zeroing overhead.
        let buf_slice = unsafe { as_mut_byte_slice(&mut buf) };

        loop {
            // Read packet from TUN device
            let n = match tun_reader.read(buf_slice).await {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    break;
                }
            };

            let packet = &buf_slice[..n];
            self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);
            let packet_ref: &[u8] = packet;

            // Extract destination IP from packet (IPv4 or IPv6)
            // DashMap lookups are lock-free - no async await needed
            let (endpoint_id, device_id) = match extract_dest_ip(packet_ref) {
                Some(PacketIp::V4(dest_ip)) => {
                    match self.ip_to_endpoint.get(&dest_ip).map(|r| *r) {
                        Some(res) => res,
                        None => {
                            self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                }
                Some(PacketIp::V6(dest_ip)) => match self.ip6_to_endpoint.get(&dest_ip).map(|r| *r)
                {
                    Some(res) => res,
                    None => {
                        self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                },
                None => {
                    self.stats
                        .packets_unknown_version
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            let client_key = (endpoint_id, device_id);

            // Get client's packet channel sender (DashMap lookup is lock-free)
            let packet_tx = match self.clients.get(&client_key) {
                Some(c) => c.packet_tx.clone(),
                None => {
                    self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            // Allocate buffer sized to actual packet (1 byte type + 4 byte length + packet).
            // Avoids over-allocation for small packets; allocator serves from thread-local caches.
            let packet_len = packet_ref.len();
            let frame_size = 1 + 4 + packet_len;
            let mut write_buf = BytesMut::with_capacity(frame_size);

            // Frame packet for transmission (writes into write_buf)
            if let Err(e) = frame_ip_packet(&mut write_buf, packet_ref) {
                log::warn!(
                    "Failed to frame packet for {} dev {}: {}",
                    endpoint_id,
                    device_id,
                    e
                );
                continue;
            }

            // Freeze into Bytes for send to client's writer task.
            let bytes = write_buf.freeze();

            // Send via channel - try non-blocking first
            match packet_tx.try_send(bytes) {
                Ok(()) => {
                    self.stats
                        .packets_to_clients
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(data)) => {
                    // Buffer full - behavior depends on drop_on_full config
                    if self.config.drop_on_full {
                        // Drop packet to avoid blocking other clients (head-of-line blocking)
                        self.stats
                            .packets_dropped_full
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Apply backpressure - blocks TUN reader until space available
                        self.stats
                            .packets_backpressure
                            .fetch_add(1, Ordering::Relaxed);
                        if packet_tx.send(data).await.is_ok() {
                            self.stats
                                .packets_to_clients
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        // Channel closed is expected during client disconnect, no counter needed
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Channel closed is expected during client disconnect
                }
            }
        }

        Ok(())
    }
}

/// IP address extracted from a packet (source or destination).
enum PacketIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

// =============================================================================
// Optimized packet parsing functions
//
// These functions use safe slice-to-array conversions after validating packet
// length once. The compiler optimizes away redundant bounds checks when it can
// prove the slice is in bounds.
//
// Performance optimizations:
// - Single length check combines empty check + minimum header validation
// - Version byte is extracted once and reused
// - try_into() for fixed-size arrays is optimized by LLVM
// - Fast-path for IPv4 (most common) checked first
// =============================================================================

/// Minimum IPv4 header size (20 bytes, no options).
const IPV4_MIN_HEADER: usize = 20;

/// Minimum IPv6 header size (40 bytes fixed).
const IPV6_MIN_HEADER: usize = 40;

/// IPv4 version nibble.
const IP_VERSION_4: u8 = 4;

/// IPv6 version nibble.
const IP_VERSION_6: u8 = 6;

/// Extract source IP address from an IP packet (IPv4 or IPv6).
///
/// Optimized for the hot path with minimal bounds checks and direct pointer reads.
#[inline]
fn extract_source_ip(packet: &[u8]) -> Option<PacketIp> {
    // Fast-path: check for IPv4 first (most common case).
    // Combined length + version check eliminates separate empty check.
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }

    // Cache version byte to avoid repeated indexing (len >= 20 verified above).
    let version = packet[0] >> 4;

    if version == IP_VERSION_4 {
        // IPv4: source address at bytes 12-15 (len >= 20 verified above).
        let src = read_ipv4_addr(packet, 12);
        return Some(PacketIp::V4(src));
    }

    if version == IP_VERSION_6 {
        // IPv6 requires 40 bytes minimum.
        if len < IPV6_MIN_HEADER {
            return None;
        }
        // IPv6: source address at bytes 8-23 (len >= 40 verified above).
        let src = read_ipv6_addr(packet, 8);
        return Some(PacketIp::V6(src));
    }

    None
}

/// Extract destination IP address from an IP packet (IPv4 or IPv6).
///
/// Optimized for the hot path with early length checks before address reads.
#[inline]
fn extract_dest_ip(packet: &[u8]) -> Option<PacketIp> {
    // Fast-path: check for IPv4 first (most common case).
    // Combined length + version check eliminates separate empty check.
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }

    // Cache version byte to avoid repeated indexing (len >= 20 verified above).
    let version = packet[0] >> 4;

    if version == IP_VERSION_4 {
        // IPv4: destination address at bytes 16-19 (len >= 20 verified above).
        let dest = read_ipv4_addr(packet, 16);
        return Some(PacketIp::V4(dest));
    }

    if version == IP_VERSION_6 {
        // IPv6 requires 40 bytes minimum.
        if len < IPV6_MIN_HEADER {
            return None;
        }
        // IPv6: destination address at bytes 24-39 (len >= 40 verified above).
        let dest = read_ipv6_addr(packet, 24);
        return Some(PacketIp::V6(dest));
    }

    None
}

/// Read an IPv4 address from a packet at the given offset.
///
/// # Panics
/// Panics if `packet.len() < offset + 4`. Callers should verify bounds first.
#[inline(always)]
fn read_ipv4_addr(packet: &[u8], offset: usize) -> Ipv4Addr {
    // Convert slice to fixed-size array. The try_into().unwrap() pattern is
    // optimized by the compiler when bounds are provably valid (which they are
    // after our length checks). This generates the same code as unsafe pointer
    // reads but with memory safety guarantees.
    let bytes: [u8; 4] = packet[offset..offset + 4]
        .try_into()
        .expect("IPv4 address read: bounds already verified");
    Ipv4Addr::from(bytes)
}

/// Read an IPv6 address from a packet at the given offset.
///
/// # Panics
/// Panics if `packet.len() < offset + 16`. Callers should verify bounds first.
#[inline(always)]
fn read_ipv6_addr(packet: &[u8], offset: usize) -> Ipv6Addr {
    // Convert slice to fixed-size array. Same optimization applies as IPv4.
    let bytes: [u8; 16] = packet[offset..offset + 16]
        .try_into()
        .expect("IPv6 address read: bounds already verified");
    Ipv6Addr::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a random EndpointId for testing
    fn random_endpoint_id() -> EndpointId {
        let bytes: [u8; 32] = rand::random();
        let secret = iroh::SecretKey::from_bytes(&bytes);
        secret.public()
    }

    #[test]
    fn test_ip_pool_allocation() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        // Server should get .1
        assert_eq!(pool.server_ip(), Ipv4Addr::new(10, 0, 0, 1));

        // Allocate IPs for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1).unwrap();
        let ip2 = pool.allocate(id2, 1).unwrap();

        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 3));

        // Re-allocate same client should return same IP
        let ip1_again = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, ip1_again);

        // Release and reallocate
        pool.release(&id1, 1);
        let id3 = random_endpoint_id();
        let ip3 = pool.allocate(id3, 1).unwrap();
        assert_eq!(ip3, ip1); // Should reuse released IP
    }

    #[test]
    fn test_ip_pool_reserve_next_available() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved = pool.reserve_next_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 2));

        let id1 = random_endpoint_id();
        let ip1 = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn test_ip_pool_reserve_last_available() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved = pool.reserve_last_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 254));

        let id1 = random_endpoint_id();
        let ip1 = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_ip_pool_reserve_last_available_slash30() {
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved = pool.reserve_last_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 2));

        let id1 = random_endpoint_id();
        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_none());
    }

    #[test]
    fn test_ip_pool_reserve_specific_ip_skips_allocation() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        let reserved_ip = Ipv4Addr::new(10, 0, 0, 5);
        pool.reserve_ip(reserved_ip, "reserved").unwrap();

        let mut assigned = Vec::new();
        for _ in 0..4 {
            let id = random_endpoint_id();
            assigned.push(pool.allocate(id, 1).unwrap());
        }

        assert_eq!(
            assigned,
            vec![
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                Ipv4Addr::new(10, 0, 0, 4),
                Ipv4Addr::new(10, 0, 0, 6),
            ]
        );
    }

    #[test]
    fn test_ip_pool_reserve_ip_validation_and_idempotency() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        assert!(pool.reserve_ip(Ipv4Addr::new(10, 0, 0, 1), "ip").is_err());
        assert!(pool.reserve_ip(Ipv4Addr::new(10, 0, 0, 0), "ip").is_err());
        assert!(pool.reserve_ip(Ipv4Addr::new(10, 0, 0, 255), "ip").is_err());
        assert!(pool
            .reserve_ip(Ipv4Addr::new(192, 168, 1, 1), "ip")
            .is_err());

        let reserved = pool.reserve_next_available().unwrap();
        let id1 = random_endpoint_id();
        let assigned = pool.allocate(id1, 1).unwrap();
        assert!(pool.reserve_ip(assigned, "ip").is_err());

        let free_ip = reserved;
        assert!(pool.reserve_ip(free_ip, "ip").is_ok());
        assert!(pool.reserve_ip(free_ip, "ip").is_ok());
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        // Use a tiny /30 network (2 usable hosts)
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        // Server uses .1, only .2 available for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2, 1);
        assert!(ip2.is_none()); // Pool exhausted
    }

    #[test]
    fn test_extract_dest_ip_v4() {
        // Valid IPv4 packet header (minimal)
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 5;

        match extract_dest_ip(&packet) {
            Some(PacketIp::V4(ip)) => {
                assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 5));
            }
            _ => panic!("Expected IPv4 destination"),
        }

        // Too short for IPv4
        assert!(extract_dest_ip(&[0x45u8; 10]).is_none());
    }

    #[test]
    fn test_extract_dest_ip_v6() {
        // Valid IPv6 packet header (40 bytes minimum)
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // Version 6
                          // Destination at bytes 24-39
        packet[24..40].copy_from_slice(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05,
        ]);

        match extract_dest_ip(&packet) {
            Some(PacketIp::V6(ip)) => {
                assert_eq!(ip, "fd00::5".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected IPv6 destination"),
        }

        // Too short for IPv6
        let mut short_packet = [0u8; 20];
        short_packet[0] = 0x60;
        assert!(extract_dest_ip(&short_packet).is_none());
    }

    #[test]
    fn test_extract_dest_ip_unknown_version() {
        // Empty packet
        assert!(extract_dest_ip(&[]).is_none());

        // Unknown version
        let mut packet = [0u8; 40];
        packet[0] = 0x50; // Version 5 (invalid)
        assert!(extract_dest_ip(&packet).is_none());
    }

    #[test]
    fn test_extract_source_ip_v4() {
        // Valid IPv4 packet header (minimal)
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
                          // Source at bytes 12-15
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 100;

        match extract_source_ip(&packet) {
            Some(PacketIp::V4(ip)) => {
                assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
            }
            _ => panic!("Expected IPv4 source"),
        }

        // Too short for IPv4
        assert!(extract_source_ip(&[0x45u8; 10]).is_none());
    }

    #[test]
    fn test_extract_source_ip_v6() {
        // Valid IPv6 packet header (40 bytes minimum)
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // Version 6
                          // Source at bytes 8-23
        packet[8..24].copy_from_slice(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        match extract_source_ip(&packet) {
            Some(PacketIp::V6(ip)) => {
                assert_eq!(ip, "fd00::2".parse::<Ipv6Addr>().unwrap());
            }
            _ => panic!("Expected IPv6 source"),
        }

        // Too short for IPv6
        let mut short_packet = [0u8; 20];
        short_packet[0] = 0x60;
        assert!(extract_source_ip(&short_packet).is_none());
    }

    #[test]
    fn test_extract_source_ip_unknown_version() {
        // Empty packet
        assert!(extract_source_ip(&[]).is_none());

        // Unknown version
        let mut packet = [0u8; 40];
        packet[0] = 0x50; // Version 5 (invalid)
        assert!(extract_source_ip(&packet).is_none());
    }

    #[test]
    fn test_ip6_pool_allocation() {
        let network: Ipv6Net = "fd00::/120".parse().unwrap();
        let mut pool = Ip6Pool::new(network, None).unwrap();

        // Server should get ::1
        assert_eq!(pool.server_ip(), "fd00::1".parse::<Ipv6Addr>().unwrap());

        // Allocate IPs for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1).unwrap();
        let ip2 = pool.allocate(id2, 1).unwrap();

        assert_eq!(ip1, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ip2, "fd00::3".parse::<Ipv6Addr>().unwrap());

        // Re-allocate same client should return same IP
        let ip1_again = pool.allocate(id1, 1).unwrap();
        assert_eq!(ip1, ip1_again);

        // Release and reallocate
        pool.release(&id1, 1);
        let id3 = random_endpoint_id();
        let ip3 = pool.allocate(id3, 1).unwrap();
        assert_eq!(ip3, ip1); // Should reuse released IP
    }

    #[test]
    fn test_ip6_pool_exhaustion() {
        // Use a tiny /126 network (4 addresses: ::0 network, ::1 server, ::2 client, ::3 last)
        let network: Ipv6Net = "fd00::/126".parse().unwrap();
        let mut pool = Ip6Pool::new(network, None).unwrap();

        // Server uses ::1, only ::2 available for clients (::3 is excluded as last address)
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2, 1);
        assert!(ip2.is_none()); // Pool exhausted
    }

    #[test]
    fn test_ip6_pool_rejects_slash127() {
        // /127 network has only 2 addresses - too small for server + clients
        let network: Ipv6Net = "fd00::/127".parse().unwrap();
        let result = Ip6Pool::new(network, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, VpnError::Config(_)),
            "Expected Config error, got {:?}",
            err
        );
    }

    #[test]
    fn test_ip6_pool_rejects_slash128() {
        // /128 is a single-address network - unusable for VPN pool
        let network: Ipv6Net = "fd00::/128".parse().unwrap();
        let result = Ip6Pool::new(network, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, VpnError::Config(_)),
            "Expected Config error, got {:?}",
            err
        );
    }

    // =========================================================================
    // VpnServerStats tests
    // =========================================================================

    #[test]
    fn test_stats_initial_zero() {
        let stats = VpnServerStats::new();

        // All counters should be zero on initialization
        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_from_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stats_counters_increment() {
        let stats = VpnServerStats::new();

        // Increment some counters
        stats.tun_packets_read.fetch_add(100, Ordering::Relaxed);
        stats.packets_to_clients.fetch_add(90, Ordering::Relaxed);
        stats.packets_no_route.fetch_add(5, Ordering::Relaxed);
        stats.packets_spoofed.fetch_add(3, Ordering::Relaxed);
        stats.packets_backpressure.fetch_add(2, Ordering::Relaxed);

        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 100);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 90);
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 5);
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 2);
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_from_clients.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stats_no_route_simulation() {
        // Simulate the no-route counter being incremented when routing fails
        let stats = VpnServerStats::new();
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let ip_to_endpoint: DashMap<Ipv4Addr, (EndpointId, u64)> = DashMap::new();

        // Register one client
        let client_id = random_endpoint_id();
        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        ip_to_endpoint.insert(client_ip, (client_id, 1));

        // Create packet destined for registered client - should find route
        let mut packet_to_client = [0u8; 20];
        packet_to_client[0] = 0x45; // IPv4
        packet_to_client[16..20].copy_from_slice(&client_ip.octets());

        if let Some(PacketIp::V4(dest)) = extract_dest_ip(&packet_to_client) {
            if ip_to_endpoint.get(&dest).is_none() {
                stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
            }
        }
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 0);

        // Create packet destined for unknown IP - should increment no_route
        let unknown_ip = Ipv4Addr::new(10, 0, 0, 99);
        let mut packet_to_unknown = [0u8; 20];
        packet_to_unknown[0] = 0x45; // IPv4
        packet_to_unknown[16..20].copy_from_slice(&unknown_ip.octets());

        if let Some(PacketIp::V4(dest)) = extract_dest_ip(&packet_to_unknown) {
            if ip_to_endpoint.get(&dest).is_none() {
                stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
            }
        }
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 1);

        // Packet destined outside network entirely
        let external_ip = Ipv4Addr::new(192, 168, 1, 1);
        let mut packet_external = [0u8; 20];
        packet_external[0] = 0x45;
        packet_external[16..20].copy_from_slice(&external_ip.octets());

        if let Some(PacketIp::V4(dest)) = extract_dest_ip(&packet_external) {
            if !network.contains(&dest) || ip_to_endpoint.get(&dest).is_none() {
                stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
            }
        }
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_stats_unknown_version_simulation() {
        let stats = VpnServerStats::new();

        // Valid IPv4 packet - should not increment unknown_version
        let ipv4_packet = [0x45u8; 20];
        if extract_dest_ip(&ipv4_packet).is_none() {
            stats
                .packets_unknown_version
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 0);

        // Invalid version (5) packet - should increment unknown_version
        let mut invalid_packet = [0u8; 40];
        invalid_packet[0] = 0x50; // Version 5
        if extract_dest_ip(&invalid_packet).is_none() {
            stats
                .packets_unknown_version
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 1);

        // Empty packet - should increment unknown_version
        if extract_dest_ip(&[]).is_none() {
            stats
                .packets_unknown_version
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_unknown_version.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_stats_spoofing_detection_simulation() {
        // Simulate IP spoofing detection logic from handle_client_data
        let stats = VpnServerStats::new();

        // Client is assigned 10.0.0.2
        let assigned_ip = Ipv4Addr::new(10, 0, 0, 2);

        // Packet with correct source IP - not spoofed
        let mut valid_packet = [0u8; 20];
        valid_packet[0] = 0x45; // IPv4
        valid_packet[12..16].copy_from_slice(&assigned_ip.octets());

        let source_valid = match extract_source_ip(&valid_packet) {
            Some(PacketIp::V4(src)) => src == assigned_ip,
            _ => false,
        };
        if !source_valid {
            stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 0);

        // Packet with wrong source IP - spoofed!
        let spoofed_ip = Ipv4Addr::new(10, 0, 0, 99);
        let mut spoofed_packet = [0u8; 20];
        spoofed_packet[0] = 0x45; // IPv4
        spoofed_packet[12..16].copy_from_slice(&spoofed_ip.octets());

        let source_valid = match extract_source_ip(&spoofed_packet) {
            Some(PacketIp::V4(src)) => src == assigned_ip,
            _ => false,
        };
        if !source_valid {
            stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 1);

        // Packet with unparseable source - also treated as spoofed
        let bad_packet = [0x45u8; 10]; // Too short
        let source_valid = match extract_source_ip(&bad_packet) {
            Some(PacketIp::V4(src)) => src == assigned_ip,
            _ => false,
        };
        if !source_valid {
            stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_spoofed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_stats_backpressure_and_drop_simulation() {
        // Simulate the backpressure/drop logic from run_tun_reader
        let stats = VpnServerStats::new();

        // Create a tiny channel that will fill up immediately
        let (tx, mut rx) = mpsc::channel::<u8>(1);

        // First send succeeds
        if tx.try_send(1).is_ok() {
            stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 1);

        // Second send fails (channel full) - simulate drop_on_full=true
        let drop_on_full = true;
        match tx.try_send(2) {
            Ok(()) => {
                stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if drop_on_full {
                    stats.packets_dropped_full.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.packets_backpressure.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 1);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 0);

        // Drain the channel
        let _ = rx.try_recv();

        // Simulate drop_on_full=false (backpressure mode)
        let _ = tx.try_send(3); // Fill the channel again

        let drop_on_full = false;
        match tx.try_send(4) {
            Ok(()) => {
                stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if drop_on_full {
                    stats.packets_dropped_full.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.packets_backpressure.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
        assert_eq!(stats.packets_dropped_full.load(Ordering::Relaxed), 1);
        assert_eq!(stats.packets_backpressure.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_tun_write_failed_simulation() {
        let stats = VpnServerStats::new();

        // Simulate TUN write failures being tracked
        // In real code this happens in handle_client_data when tun_write_tx fails

        // Successful write (channel open)
        stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.packets_from_clients.load(Ordering::Relaxed), 1);

        // Failed write (channel closed)
        stats
            .packets_tun_write_failed
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 1);

        // Multiple failures
        stats
            .packets_tun_write_failed
            .fetch_add(1, Ordering::Relaxed);
        stats
            .packets_tun_write_failed
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.packets_tun_write_failed.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_stats_concurrent_increments() {
        use std::thread;

        // Test that atomic counters work correctly under concurrent access
        let stats = Arc::new(VpnServerStats::new());
        let mut handles = vec![];

        // Spawn multiple threads incrementing different counters
        for _ in 0..10 {
            let stats = stats.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);
                    stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
                    stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Each of 10 threads incremented 1000 times = 10000 total
        assert_eq!(stats.tun_packets_read.load(Ordering::Relaxed), 10000);
        assert_eq!(stats.packets_to_clients.load(Ordering::Relaxed), 10000);
        assert_eq!(stats.packets_no_route.load(Ordering::Relaxed), 10000);
    }
}
