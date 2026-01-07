//! VPN server implementation.
//!
//! The VPN server listens for incoming client connections via iroh,
//! performs WireGuard key exchange, assigns IP addresses, and manages
//! WireGuard tunnels for each connected client.

use crate::config::VpnServerConfig;
use crate::device::{TunConfig, TunDevice};
use crate::error::{VpnError, VpnResult};
use crate::keys::{WgKeyPair, WgPublicKey};
use crate::signaling::{
    read_message, write_message, VpnHandshake, VpnHandshakeResponse, MAX_HANDSHAKE_SIZE,
};
use crate::tunnel::{PacketResult, WgTunnel, WgTunnelBuilder};
use boringtun::x25519::PublicKey;
use ipnet::Ipv4Net;
use iroh::{Endpoint, EndpointId};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{Mutex, RwLock};

/// State for a connected VPN client.
#[allow(dead_code)]
struct ClientState {
    /// Client's assigned VPN IP.
    assigned_ip: Ipv4Addr,
    /// Client's WireGuard public key.
    wg_public_key: PublicKey,
    /// Client's iroh endpoint ID.
    endpoint_id: EndpointId,
    /// WireGuard tunnel for this client.
    tunnel: Arc<Mutex<WgTunnel>>,
    /// Client's UDP endpoint (for WireGuard traffic).
    wg_endpoint: Option<SocketAddr>,
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
    /// IPs currently in use (mapped from client endpoint ID).
    in_use: HashMap<EndpointId, Ipv4Addr>,
    /// Released IPs available for reuse.
    released: Vec<Ipv4Addr>,
}

impl IpPool {
    /// Create a new IP pool from a network.
    fn new(network: Ipv4Net) -> Self {
        let net_addr: u32 = network.network().into();
        let broadcast: u32 = network.broadcast().into();

        // Server gets .1, clients start from .2
        let server_ip = Ipv4Addr::from(net_addr + 1);
        let next_ip = net_addr + 2;
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
    fn allocate(&mut self, endpoint_id: EndpointId) -> Option<Ipv4Addr> {
        // Check if client already has an IP
        if let Some(&ip) = self.in_use.get(&endpoint_id) {
            return Some(ip);
        }

        // Try to reuse a released IP first
        if let Some(ip) = self.released.pop() {
            self.in_use.insert(endpoint_id, ip);
            return Some(ip);
        }

        // Allocate new IP if available
        if self.next_ip <= self.max_ip {
            let ip = Ipv4Addr::from(self.next_ip);
            self.next_ip += 1;
            self.in_use.insert(endpoint_id, ip);
            Some(ip)
        } else {
            None // Pool exhausted
        }
    }

    /// Release an IP address when a client disconnects.
    fn release(&mut self, endpoint_id: &EndpointId) {
        if let Some(ip) = self.in_use.remove(endpoint_id) {
            self.released.push(ip);
        }
    }

    /// Get the number of connected clients.
    #[allow(dead_code)]
    fn client_count(&self) -> usize {
        self.in_use.len()
    }
}

/// VPN server instance.
pub struct VpnServer {
    /// Server configuration.
    config: VpnServerConfig,
    /// Server's WireGuard keypair.
    keypair: WgKeyPair,
    /// IP address pool.
    ip_pool: Arc<RwLock<IpPool>>,
    /// Connected clients (by endpoint ID).
    clients: Arc<RwLock<HashMap<EndpointId, ClientState>>>,
    /// UDP socket for WireGuard traffic.
    wg_socket: Arc<TokioUdpSocket>,
    /// TUN device for VPN traffic.
    tun_device: Option<TunDevice>,
}

impl VpnServer {
    /// Create a new VPN server.
    pub async fn new(config: VpnServerConfig) -> VpnResult<Self> {
        // Load or generate keypair
        let keypair = if let Some(ref path) = config.private_key_file {
            WgKeyPair::load_from_file_sync(path)?
        } else {
            let kp = WgKeyPair::generate();
            log::info!("Generated new WireGuard keypair");
            kp
        };

        // Create IP pool
        let ip_pool = Arc::new(RwLock::new(IpPool::new(config.network)));

        // Bind UDP socket for WireGuard
        let std_socket = UdpSocket::bind(format!("0.0.0.0:{}", config.wg_port)).map_err(|e| {
            VpnError::Network(std::io::Error::new(
                e.kind(),
                format!("Failed to bind WireGuard socket on port {}: {}", config.wg_port, e),
            ))
        })?;
        std_socket.set_nonblocking(true)?;
        let wg_socket = Arc::new(TokioUdpSocket::from_std(std_socket)?);

        log::info!("WireGuard listening on UDP port {}", config.wg_port);

        Ok(Self {
            config,
            keypair,
            ip_pool,
            clients: Arc::new(RwLock::new(HashMap::new())),
            wg_socket,
            tun_device: None,
        })
    }

    /// Get the server's WireGuard public key.
    pub fn public_key(&self) -> WgPublicKey {
        WgPublicKey::from(self.keypair.public_key())
    }

    /// Get the server's VPN IP address.
    pub async fn server_ip(&self) -> Ipv4Addr {
        self.ip_pool.read().await.server_ip()
    }

    /// Get the VPN network.
    pub async fn network(&self) -> Ipv4Net {
        self.ip_pool.read().await.network()
    }

    /// Get the number of connected clients.
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Create and configure the TUN device.
    pub fn setup_tun(&mut self) -> VpnResult<()> {
        let pool = futures::executor::block_on(self.ip_pool.read());
        let server_ip = pool.server_ip();
        let netmask = pool.network().netmask();
        drop(pool);

        let tun_config = TunConfig::new(server_ip, netmask, server_ip)
            .with_mtu(self.config.mtu);

        let device = TunDevice::create(tun_config)?;
        log::info!("Created TUN device: {} with IP {}", device.name(), server_ip);
        self.tun_device = Some(device);
        Ok(())
    }

    /// Run the VPN server, accepting connections via iroh.
    pub async fn run(mut self, endpoint: Endpoint) -> VpnResult<()> {
        // Setup TUN device
        self.setup_tun()?;

        let server_ip = self.server_ip().await;
        let network = self.network().await;
        let wg_port = self.config.wg_port;
        let public_key = self.public_key();

        log::info!("VPN Server started:");
        log::info!("  Network: {}", network);
        log::info!("  Server IP: {}", server_ip);
        log::info!("  WireGuard port: {}", wg_port);
        log::info!("  Public key: {}", public_key.to_base64());
        log::info!("  Node ID: {}", endpoint.id());

        let server = Arc::new(self);

        // Spawn WireGuard packet handler
        let server_clone = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_clone.run_wg_receiver().await {
                log::error!("WireGuard receiver error: {}", e);
            }
        });

        // Spawn TUN packet handler
        let server_clone = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_clone.run_tun_handler().await {
                log::error!("TUN handler error: {}", e);
            }
        });

        // Accept incoming connections
        loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    let server = server.clone();
                    let endpoint_clone = endpoint.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(incoming, &endpoint_clone).await {
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
        _endpoint: &Endpoint,
    ) -> VpnResult<()> {
        let connection = incoming
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept connection: {}", e)))?;

        let remote_id = connection.remote_id();
        log::info!("New VPN connection from {}", remote_id);

        // Accept bidirectional stream for handshake
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept stream: {}", e)))?;

        // Read handshake
        let handshake_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE).await?;
        let handshake = VpnHandshake::decode(&handshake_data)?;

        log::debug!(
            "Received handshake from {} with WG key: {}",
            remote_id,
            handshake.wg_public_key.to_base64()
        );

        // Check max clients
        let client_count = self.clients.read().await.len();
        if client_count >= self.config.max_clients {
            let response = VpnHandshakeResponse::rejected("Server full");
            write_message(&mut send, &response.encode()?).await?;
            let _ = send.finish();
            return Err(VpnError::IpAssignment("Server full".into()));
        }

        // Allocate IP for client
        let assigned_ip = {
            let mut pool = self.ip_pool.write().await;
            pool.allocate(remote_id).ok_or_else(|| {
                VpnError::IpAssignment("IP pool exhausted".into())
            })?
        };

        // Get server info for response
        let pool = self.ip_pool.read().await;
        let server_ip = pool.server_ip();
        let network = pool.network();
        drop(pool);

        // WireGuard endpoint will be determined when we receive the first UDP packet
        // from the client, since iroh doesn't expose the direct remote address
        let wg_endpoint: Option<SocketAddr> = None;

        // Create WireGuard tunnel for this client
        let peer_public_key = handshake.wg_public_key.to_public_key();
        let tunnel = WgTunnelBuilder::new()
            .keypair(self.keypair.clone())
            .peer_public_key(peer_public_key)
            .keepalive_secs(Some(self.config.keepalive_secs))
            .build()?;

        let tunnel = Arc::new(Mutex::new(tunnel));

        // Store client state
        let client_state = ClientState {
            assigned_ip,
            wg_public_key: peer_public_key,
            endpoint_id: remote_id,
            tunnel,
            wg_endpoint,
        };

        self.clients.write().await.insert(remote_id, client_state);

        // Send response
        let response = VpnHandshakeResponse::accepted(
            self.public_key(),
            SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                self.config.wg_port,
            ),
            assigned_ip,
            network,
            server_ip,
        );

        write_message(&mut send, &response.encode()?).await?;
        let _ = send.finish();

        log::info!(
            "Client {} connected, assigned IP: {}",
            remote_id,
            assigned_ip
        );

        // Keep connection alive for signaling updates
        // The actual VPN traffic goes through the UDP socket
        let clients = self.clients.clone();
        let ip_pool = self.ip_pool.clone();
        tokio::spawn(async move {
            // Wait for connection to close
            connection.closed().await;
            log::info!("Client {} disconnected", remote_id);

            // Cleanup
            clients.write().await.remove(&remote_id);
            ip_pool.write().await.release(&remote_id);
        });

        Ok(())
    }

    /// Run the WireGuard UDP packet receiver.
    async fn run_wg_receiver(&self) -> VpnResult<()> {
        let mut buf = vec![0u8; 2048];

        loop {
            let (len, src_addr) = self.wg_socket.recv_from(&mut buf).await?;
            let packet = &buf[..len];

            // Find the client by source address
            let clients = self.clients.read().await;
            let client = clients.values().find(|c| c.wg_endpoint == Some(src_addr));

            if let Some(client) = client {
                let mut tunnel = client.tunnel.lock().await;
                match tunnel.decapsulate(Some(src_addr.ip()), packet)? {
                    PacketResult::WriteToTunV4(data, _) | PacketResult::WriteToTunV6(data, _) => {
                        // Write to TUN device
                        // This would need the TUN writer
                        log::trace!("Decrypted {} bytes from {}", data.len(), src_addr);
                    }
                    PacketResult::WriteToNetwork(data) => {
                        // Send response back to client
                        self.wg_socket.send_to(&data, src_addr).await?;
                    }
                    PacketResult::Done => {}
                    PacketResult::Error(e) => {
                        log::warn!("Decapsulation error from {}: {}", src_addr, e);
                    }
                }
            } else {
                log::trace!("Received packet from unknown source: {}", src_addr);
            }
        }
    }

    /// Run the TUN device packet handler.
    async fn run_tun_handler(&self) -> VpnResult<()> {
        // This is a placeholder - actual implementation would read from TUN
        // and route packets to the appropriate client's WireGuard tunnel
        log::debug!("TUN handler started (placeholder)");

        // The actual implementation would:
        // 1. Read IP packets from TUN
        // 2. Look up destination IP to find target client
        // 3. Encapsulate with client's WgTunnel
        // 4. Send via UDP to client's endpoint

        // For now, just keep the task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }
}

/// Builder for VpnServer.
pub struct VpnServerBuilder {
    config: VpnServerConfig,
}

impl VpnServerBuilder {
    /// Create a new builder with default config.
    pub fn new() -> Self {
        Self {
            config: VpnServerConfig::default(),
        }
    }

    /// Set the VPN network.
    pub fn network(mut self, network: Ipv4Net) -> Self {
        self.config.network = network;
        self
    }

    /// Set the WireGuard port.
    pub fn wg_port(mut self, port: u16) -> Self {
        self.config.wg_port = port;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.config.mtu = mtu;
        self
    }

    /// Set the max clients.
    pub fn max_clients(mut self, max: usize) -> Self {
        self.config.max_clients = max;
        self
    }

    /// Set the keepalive interval.
    pub fn keepalive_secs(mut self, secs: u16) -> Self {
        self.config.keepalive_secs = secs;
        self
    }

    /// Build the server.
    pub async fn build(self) -> VpnResult<VpnServer> {
        VpnServer::new(self.config).await
    }
}

impl Default for VpnServerBuilder {
    fn default() -> Self {
        Self::new()
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
        let mut pool = IpPool::new(network);

        // Server should get .1
        assert_eq!(pool.server_ip(), Ipv4Addr::new(10, 0, 0, 1));

        // Allocate IPs for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1).unwrap();
        let ip2 = pool.allocate(id2).unwrap();

        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 3));

        // Re-allocate same client should return same IP
        let ip1_again = pool.allocate(id1).unwrap();
        assert_eq!(ip1, ip1_again);

        // Release and reallocate
        pool.release(&id1);
        let id3 = random_endpoint_id();
        let ip3 = pool.allocate(id3).unwrap();
        assert_eq!(ip3, ip1); // Should reuse released IP
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        // Use a tiny /30 network (2 usable hosts)
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network);

        // Server uses .1, only .2 available for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2);
        assert!(ip2.is_none()); // Pool exhausted
    }
}
