//! VPN server implementation.
//!
//! The VPN server listens for incoming client connections via iroh,
//! performs WireGuard key exchange, assigns IP addresses, and manages
//! WireGuard tunnels for each connected client.
//!
//! WireGuard packets are tunneled through the iroh QUIC connection to handle
//! NAT traversal automatically.

use crate::config::VpnServerConfig;
use crate::device::{TunConfig, TunDevice, TunWriter};
use crate::error::{VpnError, VpnResult};
use crate::signaling::{
    frame_ip_packet, read_message, write_message, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, MAX_HANDSHAKE_SIZE,
};
// Removed WgTunnel, WgTunnelBuilder import
// use crate::tunnel::{PacketResult, WgTunnel, WgTunnelBuilder};
use ipnet::{Ipv4Net, Ipv6Net};
use iroh::endpoint::SendStream;
use iroh::{Endpoint, EndpointId};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Maximum IP packet size.
const MAX_IP_PACKET_SIZE: usize = 65536;

/// State for a connected VPN client.
struct ClientState {
    /// Unique session ID for this connection.
    /// Used to detect stale cleanup operations when a client reconnects quickly.
    session_id: u64,
    /// Client's assigned VPN IP (IPv4).
    #[allow(dead_code)]
    assigned_ip: Ipv4Addr,
    /// Client's assigned IPv6 VPN address (optional, for dual-stack).
    #[allow(dead_code)]
    assigned_ip6: Option<Ipv6Addr>,
    /// Client's device ID.
    #[allow(dead_code)]
    device_id: u64,
    /// Client's iroh endpoint ID.
    #[allow(dead_code)]
    endpoint_id: EndpointId,
    /// Send stream to client (for sending encrypted packets).
    send_stream: Arc<Mutex<SendStream>>,
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

    /// Allocate an IP address for a client.
    fn allocate(&mut self, endpoint_id: EndpointId, device_id: u64) -> Option<Ipv4Addr> {
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
            let ip = Ipv4Addr::from(self.next_ip);
            self.next_ip += 1;
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
    fn new(network: Ipv6Net, server_ip: Option<Ipv6Addr>) -> Self {
        let net_addr: u128 = network.network().into();

        // Server gets specified IP or defaults to ::1 within network
        let server_ip = server_ip.unwrap_or_else(|| Ipv6Addr::from(net_addr + 1));
        let server_ip_u128: u128 = server_ip.into();

        // Clients start from address after server IP
        let next_ip = server_ip_u128 + 1;

        // Calculate max_ip based on prefix length
        let host_bits: u32 = 128 - u32::from(network.prefix_len());
        let max_ip = if host_bits > 127 {
            u128::MAX
        } else {
            net_addr + ((1u128 << host_bits) - 1) - 1 // Exclude last address
        };

        Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            in_use: HashMap::new(),
            released: Vec::new(),
        }
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
    // Removed keypair
    // keypair: WgKeyPair,
    /// IPv4 address pool.
    ip_pool: Arc<RwLock<IpPool>>,
    /// IPv6 address pool (None if IPv4-only mode).
    ip6_pool: Option<Arc<RwLock<Ip6Pool>>>,
    /// Connected clients (by (endpoint ID, device ID)).
    clients: Arc<RwLock<HashMap<(EndpointId, u64), ClientState>>>,
    /// Reverse lookup: IPv4 address -> (endpoint ID, device ID).
    /// Used for routing.
    ip_to_endpoint: Arc<RwLock<HashMap<Ipv4Addr, (EndpointId, u64)>>>,
    /// Reverse lookup: IPv6 address -> (endpoint ID, device ID).
    ip6_to_endpoint: Arc<RwLock<HashMap<Ipv6Addr, (EndpointId, u64)>>>,
    /// TUN device for VPN traffic.
    tun_device: Option<TunDevice>,
    /// Atomic counter for active connections (prevents race in max_clients check).
    active_connections: AtomicUsize,
    /// Session ID counter for unique connection identification.
    next_session_id: AtomicU64,
}

impl VpnServer {
    /// Create a new VPN server.
    ///
    /// WireGuard keypair is always ephemeral (generated fresh each server start).
    /// This allows clients to use ephemeral keys without conflicts.
    pub async fn new(config: VpnServerConfig) -> VpnResult<Self> {
        // No WG keypair needed
        // let keypair = WgKeyPair::generate();

        // Create IPv4 pool
        let ip_pool = Arc::new(RwLock::new(IpPool::new(config.network, config.server_ip)));

        // Create IPv6 pool if configured (dual-stack)
        let ip6_pool = config.network6.map(|network6| {
            Arc::new(RwLock::new(Ip6Pool::new(network6, config.server_ip6)))
        });

        if let Some(ref pool) = ip6_pool {
            let pool_guard = pool.read().await;
            log::info!("IPv6 dual-stack enabled: {}", pool_guard.network());
        }

        Ok(Self {
            config,
            // keypair,
            ip_pool,
            ip6_pool,
            clients: Arc::new(RwLock::new(HashMap::new())),
            ip_to_endpoint: Arc::new(RwLock::new(HashMap::new())),
            ip6_to_endpoint: Arc::new(RwLock::new(HashMap::new())),
            tun_device: None,
            active_connections: AtomicUsize::new(0),
            next_session_id: AtomicU64::new(1),
        })
    }


    /// Get the server's VPN IP address.
    pub async fn server_ip(&self) -> Ipv4Addr {
        self.ip_pool.read().await.server_ip()
    }

    /// Get the VPN network.
    pub async fn network(&self) -> Ipv4Net {
        self.ip_pool.read().await.network()
    }

    /// Create and configure the TUN device.
    pub async fn setup_tun(&mut self) -> VpnResult<()> {
        let pool = self.ip_pool.read().await;
        let server_ip = pool.server_ip();
        let netmask = pool.network().netmask();
        drop(pool);

        let mut tun_config =
            TunConfig::new(server_ip, netmask, server_ip).with_mtu(self.config.mtu);

        // Configure IPv6 if dual-stack is enabled
        let server_ip6 = if let Some(ref ip6_pool) = self.ip6_pool {
            let pool6 = ip6_pool.read().await;
            let server_ip6 = pool6.server_ip();
            let prefix_len6 = pool6.network().prefix_len();
            tun_config = tun_config.with_ipv6(server_ip6, prefix_len6)?;
            Some(server_ip6)
        } else {
            None
        };

        let device = TunDevice::create(tun_config)?;
        if let Some(ip6) = server_ip6 {
            log::info!(
                "Created TUN device: {} with IP {} and IPv6 {}",
                device.name(),
                server_ip,
                ip6
            );
        } else {
            log::info!(
                "Created TUN device: {} with IP {}",
                device.name(),
                server_ip
            );
        }
        self.tun_device = Some(device);
        Ok(())
    }

    /// Run the VPN server, accepting connections via iroh.
    pub async fn run(mut self, endpoint: Endpoint) -> VpnResult<()> {
        // Setup TUN device
        self.setup_tun().await?;

        let server_ip = self.server_ip().await;
        let network = self.network().await;
        // let public_key = self.public_key();

        log::info!("VPN Server started:");
        log::info!("  Network: {}", network);
        log::info!("  Server IP: {}", server_ip);
        if let Some(ref ip6_pool) = self.ip6_pool {
            let pool = ip6_pool.read().await;
            log::info!("  Network6: {}", pool.network());
            log::info!("  Server IP6: {}", pool.server_ip());
        }
        // log::info!("  Public key: {}", public_key.to_base64());
        log::info!("  Node ID: {}", endpoint.id());

        // Take TUN device and split it
        let tun_device = self.tun_device.take().expect("TUN device not set up");
        let (tun_reader, tun_writer) = tun_device.split()?;
        let tun_writer = Arc::new(Mutex::new(tun_writer));

        let server = Arc::new(self);

        // Spawn TUN reader task (reads from TUN, routes to clients)
        let server_tun = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_tun.run_tun_reader(tun_reader).await {
                log::error!("TUN reader error: {}", e);
            }
        });

        // Accept incoming connections
        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    let server = server.clone();
                    let tun_writer = tun_writer.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(incoming, tun_writer).await {
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

        Ok(())
    }

    /// Handle an incoming VPN connection.
    async fn handle_connection(
        &self,
        incoming: iroh::endpoint::Incoming,
        tun_writer: Arc<Mutex<TunWriter>>,
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
            return Err(VpnError::Signaling("Server has no auth tokens configured".into()));
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
                tun_writer,
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
        tun_writer: Arc<Mutex<TunWriter>>,
        device_id: u64,
    ) -> VpnResult<()> {
        // Allocate IPv4 for client (required)
        let assigned_ip = {
            let mut pool = self.ip_pool.write().await;
            pool.allocate(remote_id, device_id)
                .ok_or_else(|| VpnError::IpAssignment("IPv4 pool exhausted".into()))?
        };

        // Allocate IPv6 for client (optional, if server has IPv6 configured)
        let assigned_ip6 = if let Some(ref ip6_pool) = self.ip6_pool {
            let mut pool = ip6_pool.write().await;
            match pool.allocate(remote_id, device_id) {
                Some(ip) => Some(ip),
                None => {
                    // IPv6 allocation failure is not fatal - client just won't have IPv6
                    log::warn!("IPv6 pool exhausted for client {}", remote_id);
                    None
                }
            }
        } else {
            None
        };

        // Get server info for response
        let pool = self.ip_pool.read().await;
        let server_ip = pool.server_ip();
        let network = pool.network();
        drop(pool);

        // Create WireGuard tunnel for this client - REMOVED
        /* let peer_public_key = client_wg_public_key.to_public_key();
        let dummy_endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let tunnel = WgTunnelBuilder::new()
            .keypair(self.keypair.clone())
            .peer_public_key(peer_public_key)
            .peer_endpoint(dummy_endpoint)
            .keepalive_secs(Some(self.config.keepalive_secs))
            .build()?;

        let tunnel = Arc::new(Mutex::new(tunnel)); */

        // Send response - include IPv6 info if allocated
        let response = if let Some(ip6) = assigned_ip6 {
            let ip6_pool = self.ip6_pool.as_ref().unwrap().read().await;
            VpnHandshakeResponse::accepted_dual_stack(
                assigned_ip,
                network,
                server_ip,
                ip6,
                ip6_pool.network(),
                ip6_pool.server_ip(),
            )
        } else {
            VpnHandshakeResponse::accepted(
                assigned_ip,
                network,
                server_ip,
            )
        };

        write_message(send, &response.encode()?).await?;
        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }

        if let Some(ip6) = assigned_ip6 {
            log::info!(
                "Client {} connected, assigned IP: {}, IPv6: {}",
                remote_id,
                assigned_ip,
                ip6
            );
        } else {
            log::info!(
                "Client {} connected, assigned IP: {}",
                remote_id,
                assigned_ip
            );
        }

        // Accept data stream for WireGuard packets
        let (wg_send, wg_recv) = connection
            .accept_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept data stream: {}", e)))?;

        log::info!("Client {} data stream established", remote_id);

        let wg_send = Arc::new(Mutex::new(wg_send));

        // Generate unique session ID for this connection
        // Used to detect stale cleanup when same client reconnects quickly
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        // Store client state (including send stream for TUN handler to use)
        // Store client state (including send stream for TUN handler to use)
        let client_state = ClientState {
            session_id,
            assigned_ip,
            assigned_ip6,
            // wg_public_key: peer_public_key, // Removed
            device_id,
            endpoint_id: remote_id,
            // tunnel: tunnel.clone(), // Removed
            send_stream: wg_send.clone(),
        };

        // Reconnect handling: if a client with the same (EndpointId, DeviceId) exists,
        // we should remove it first, or overwrite it.
        // Overwriting in the map is atomic for the map itself, but we should make sure
        // resources are cleaned up.
        // Since we are using session_id for cleanup safety, overwriting is fine.
        // The old connection's cleanup will see a different session_id in the map and will NOT remove the new one.
        
        let client_key = (remote_id, device_id);

        self.clients.write().await.insert(client_key, client_state);
        self.ip_to_endpoint
            .write()
            .await
            .insert(assigned_ip, (remote_id, device_id));

        if let Some(ip6) = assigned_ip6 {
            self.ip6_to_endpoint
                .write()
                .await
                .insert(ip6, (remote_id, device_id));
        }

        // Handle client data
        let clients = self.clients.clone();
        let ip_pool = self.ip_pool.clone();
        let ip6_pool = self.ip6_pool.clone();
        let ip_to_endpoint = self.ip_to_endpoint.clone();
        let ip6_to_endpoint = self.ip6_to_endpoint.clone();

        // Run client handler (blocks until client disconnects)
        let result = Self::handle_client_data(
            // tunnel,
            wg_send,
            wg_recv,
            assigned_ip,
            assigned_ip6,
            tun_writer,
        )
        .await;

        if let Err(ref e) = result {
            log::error!("Client {} data error: {}", remote_id, e);
        }

        log::info!("Client {} disconnected", remote_id);

        // Cleanup - use session_id to detect stale cleanup from rapid reconnection.
        // Only remove entries if they still belong to this specific connection, and
        // ensure that clients, IPv4 mappings, and IPv6 mappings are updated atomically
        // with respect to each other to avoid races with rapid reconnects.
        let mut endpoint_to_release = None;
        let mut release_ipv6 = false;
        {
            let mut clients_map = clients.write().await;
            let mut ip_map = ip_to_endpoint.write().await;
            let mut ip6_map = ip6_to_endpoint.write().await;

            let removed_client = clients_map.remove(&client_key);
            // We don't remove IP mappings here strictly by key if we assume IPs are unique
            // But let's check.
            // Actually, we should check if the currently mapped (Endpoint, Device) for this IP is us.
            
            // Check IP mapping
            let ip_belongs_to_us = if let Some((ep, dev)) = ip_map.get(&assigned_ip) {
                 *ep == remote_id && *dev == device_id
            } else {
                false
            };

            if ip_belongs_to_us {
                // Only remove if it points to us
                 ip_map.remove(&assigned_ip);
            }

            match (removed_client, ip_belongs_to_us) {
                // Both entries existed and belonged to us
                (Some(client_state), true) => {
                    if client_state.session_id == session_id {
                        // Belongs to this session; remember endpoint for IP release
                        // (We need strict cleanup logic here)
                        endpoint_to_release = Some((remote_id, device_id));
                        release_ipv6 = client_state.assigned_ip6.is_some();
                        
                        // Clean up IPv6 mapping
                        if let Some(ip6) = assigned_ip6 {
                            if let Some((ep6, dev6)) = ip6_map.get(&ip6) {
                                if *ep6 == remote_id && *dev6 == device_id {
                                    ip6_map.remove(&ip6);
                                }
                            }
                        }
                    } else {
                        // The removed client state belonged to a different session (e.g. newer one)?
                        // Wait, if we removed it from clients_map using client_key, and client_key matches...
                        // If session_id mismatches, it means we removed a NEWER session (if session IDs increase).
                        // Or we removed an OLDER session?
                        // Actually, if we just overwrote it in insert, then remove here returns the current one.
                        // If current state's session_id != our session_id, it means someone else replaced us.
                        // So we should PUT IT BACK.
                        clients_map.insert(client_key, client_state);
                        
                        // And if we removed IP mapping but it wasn't ours... wait, we checked ip_belongs_to_us.
                        // If ip_belongs_to_us was true, it means IP map pointed to (remote_id, device_id).
                        // Since (remote_id, device_id) is unique key, checking session_id on client_state is enough to know if it's THIS session.
                        // If client_state.session_id != session_id, then it is NOT this session, so we should restore everything.
                        
                        // Restore IP map
                        ip_map.insert(assigned_ip, (remote_id, device_id));
                    }
                }
                (Some(client_state), false) => {
                     // Client state existed but IP mapping didn't point to us? Weird.
                     // Check session id.
                     if client_state.session_id != session_id {
                         clients_map.insert(client_key, client_state);
                     }
                }
                (None, _) => {
                    // Client state already gone. Nothing to do.
                }
            }
        }

        if let Some((endpoint_id, dev_id)) = endpoint_to_release {
            ip_pool.write().await.release(&endpoint_id, dev_id);

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
    async fn handle_client_data(
        // tunnel: Arc<Mutex<WgTunnel>>,
        wg_send: Arc<Mutex<SendStream>>,
        mut wg_recv: iroh::endpoint::RecvStream,
        assigned_ip: Ipv4Addr,
        assigned_ip6: Option<Ipv6Addr>,
        tun_writer: Arc<Mutex<TunWriter>>,
    ) -> VpnResult<()> {
        // let tunnel_inbound = tunnel.clone();
        // let tunnel_timers = tunnel.clone();
        // let send_inbound = wg_send.clone();
        let send_heartbeat = wg_send.clone();

        // Spawn inbound task (iroh stream -> TUN)
        let inbound_handle = tokio::spawn(async move {
            let mut type_buf = [0u8; 1];
            let mut len_buf = [0u8; 4];
            let mut data_buf = vec![0u8; MAX_IP_PACKET_SIZE];
            // let mut write_buf = Vec::with_capacity(1 + 4 + MAX_IP_PACKET_SIZE);
            loop {
                // Read message type
                match wg_recv.read_exact(&mut type_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Client {} stream closed: {}", assigned_ip, e);
                        break;
                    }
                }

                let msg_type = match DataMessageType::from_byte(type_buf[0]) {
                    Some(t) => t,
                    None => {
                        log::error!("Unknown message type from {}: 0x{:02x}, closing connection", assigned_ip, type_buf[0]);
                        break;
                    }
                };

                match msg_type {
                    DataMessageType::HeartbeatPing => {
                        // Respond with pong
                        log::trace!("Heartbeat ping from {}", assigned_ip);
                        let mut send = send_heartbeat.lock().await;
                        if let Err(e) = send.write_all(&[DataMessageType::HeartbeatPong.as_byte()]).await {
                            log::warn!("Failed to send heartbeat pong to {}: {}", assigned_ip, e);
                            break;
                        }
                        continue;
                    }
                    DataMessageType::HeartbeatPong => {
                        // Server shouldn't receive pongs, ignore
                        log::trace!("Unexpected heartbeat pong from {}", assigned_ip);
                        continue;
                    }
                    DataMessageType::IpPacket => {
                        // Continue to read IP packet below
                    }
                }

                // Read length prefix for IP packet
                match wg_recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Failed to read IP packet length from {}: {}", assigned_ip, e);
                        break;
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_IP_PACKET_SIZE {
                    log::error!("IP packet too large from {}: {}", assigned_ip, len);
                    break;
                }

                // Read packet data
                match wg_recv.read_exact(&mut data_buf[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Failed to read IP packet from {}: {}", assigned_ip, e);
                        break;
                    }
                }

                let packet = &data_buf[..len];

                // Validate source IP to prevent IP spoofing
                let source_valid = match extract_source_ip(packet) {
                    Some(PacketIp::V4(src_ip)) => {
                        if src_ip == assigned_ip {
                            true
                        } else {
                            log::warn!(
                                "IP spoofing attempt from client {}: expected source {}, got {}",
                                assigned_ip, assigned_ip, src_ip
                            );
                            false
                        }
                    }
                    Some(PacketIp::V6(src_ip)) => {
                        match assigned_ip6 {
                            Some(expected_ip6) if src_ip == expected_ip6 => true,
                            Some(expected_ip6) => {
                                log::warn!(
                                    "IPv6 spoofing attempt from client {}: expected source {}, got {}",
                                    assigned_ip, expected_ip6, src_ip
                                );
                                false
                            }
                            None => {
                                log::warn!(
                                    "IPv6 packet from client {} without assigned IPv6 address, source: {}",
                                    assigned_ip, src_ip
                                );
                                false
                            }
                        }
                    }
                    None => {
                        log::warn!("Failed to parse source IP from packet from client {}", assigned_ip);
                        false
                    }
                };

                if !source_valid {
                    // Drop spoofed packet
                    continue;
                }

                // Write validated packet to TUN
                let mut writer = tun_writer.lock().await;
                if let Err(e) = writer.write_all(packet).await {
                     log::warn!("Failed to write to TUN: {}", e);
                }
                log::trace!("Wrote {} bytes to TUN from client {}", packet.len(), assigned_ip);
            }
        });

        // Timer task is now just a placeholder/cleanup since we don't have WG timers
        let timer_handle = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });

        // Wait for either task to complete
        tokio::select! {
            _ = inbound_handle => {}
            _ = timer_handle => {}
        }

        Ok(())
    }

    /// Run the TUN reader - reads packets from TUN and routes to clients.
    async fn run_tun_reader(&self, mut tun_reader: crate::device::TunReader) -> VpnResult<()> {
        log::info!("TUN reader started");

        let buffer_size = tun_reader.buffer_size();
        let mut buf = vec![0u8; buffer_size];
        let mut write_buf = Vec::with_capacity(1 + 4 + buffer_size);

        loop {
            // Read packet from TUN device
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    break;
                }
            };

            let packet = &buf[..n];

            // Extract destination IP from packet (IPv4 or IPv6)
            let (endpoint_id, device_id) = match extract_dest_ip(packet) {
                Some(PacketIp::V4(dest_ip)) => {
                    let ip_map = self.ip_to_endpoint.read().await;
                    match ip_map.get(&dest_ip).map(|&(id, dev)| (id, dev)) {
                        Some(res) => res,
                        None => {
                            log::trace!("No client for destination IPv4 {}", dest_ip);
                            continue;
                        }
                    }
                }
                Some(PacketIp::V6(dest_ip)) => {
                    let ip6_map = self.ip6_to_endpoint.read().await;
                    match ip6_map.get(&dest_ip).map(|&(id, dev)| (id, dev)) {
                        Some(res) => res,
                        None => {
                            log::trace!("No client for destination IPv6 {}", dest_ip);
                            continue;
                        }
                    }
                }
                None => {
                    log::trace!("Unknown IP version packet from TUN, skipping");
                    continue;
                }
            };
            
            let client_key = (endpoint_id, device_id);

            // Get client state
            let clients = self.clients.read().await;
            let client = match clients.get(&client_key) {
                Some(c) => c,
                None => {
                    log::trace!("Client {} dev {} not found", endpoint_id, device_id);
                    continue;
                }
            };

            // Directly frame and send packet
            if let Err(e) = frame_ip_packet(&mut write_buf, packet) {
                 log::warn!("Failed to frame packet for {} dev {}: {}", endpoint_id, device_id, e);
                 continue;
            }
            let mut send = client.send_stream.lock().await;
            if let Err(e) = send.write_all(&write_buf).await {
                log::warn!("Failed to send to client {} dev {}: {}", endpoint_id, device_id, e);
                continue;
            }
            log::trace!("Sent {} bytes to client {} dev {}", packet.len(), endpoint_id, device_id);
            // Ignore logic for encryption below
            /*
            // Encrypt packet with client's WireGuard tunnel
            let mut tunnel = client.tunnel.lock().await;
            match tunnel.encapsulate(packet) { ... }
            */
        }

        Ok(())
    }
}

/// IP address extracted from a packet (source or destination).
enum PacketIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Extract source IP address from an IP packet (IPv4 or IPv6).
fn extract_source_ip(packet: &[u8]) -> Option<PacketIp> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;

    match version {
        4 => {
            // IPv4: minimum header is 20 bytes, source at bytes 12-15
            if packet.len() < 20 {
                return None;
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            Some(PacketIp::V4(src))
        }
        6 => {
            // IPv6: minimum header is 40 bytes, source at bytes 8-23
            if packet.len() < 40 {
                return None;
            }
            let src = Ipv6Addr::from([
                packet[8], packet[9], packet[10], packet[11],
                packet[12], packet[13], packet[14], packet[15],
                packet[16], packet[17], packet[18], packet[19],
                packet[20], packet[21], packet[22], packet[23],
            ]);
            Some(PacketIp::V6(src))
        }
        _ => None,
    }
}

/// Extract destination IP address from an IP packet (IPv4 or IPv6).
fn extract_dest_ip(packet: &[u8]) -> Option<PacketIp> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;

    match version {
        4 => {
            // IPv4: minimum header is 20 bytes, dest at bytes 16-19
            if packet.len() < 20 {
                return None;
            }
            let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Some(PacketIp::V4(dest))
        }
        6 => {
            // IPv6: minimum header is 40 bytes, dest at bytes 24-39
            if packet.len() < 40 {
                return None;
            }
            let dest = Ipv6Addr::from([
                packet[24], packet[25], packet[26], packet[27],
                packet[28], packet[29], packet[30], packet[31],
                packet[32], packet[33], packet[34], packet[35],
                packet[36], packet[37], packet[38], packet[39],
            ]);
            Some(PacketIp::V6(dest))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// Helper to create a random EndpointId for testing
    fn random_endpoint_id() -> EndpointId {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
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
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
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
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
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
        let mut pool = Ip6Pool::new(network, None);

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
        let mut pool = Ip6Pool::new(network, None);

        // Server uses ::1, only ::2 available for clients (::3 is excluded as last address)
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1, 1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2, 1);
        assert!(ip2.is_none()); // Pool exhausted
    }
}
