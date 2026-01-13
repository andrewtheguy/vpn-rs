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
use crate::keys::{WgKeyPair, WgPublicKey};
use crate::signaling::{
    frame_wireguard_packet, read_message, write_message, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, MAX_HANDSHAKE_SIZE,
};
use crate::tunnel::{PacketResult, WgTunnel, WgTunnelBuilder};
use boringtun::x25519::PublicKey;
use ipnet::Ipv4Net;
use iroh::endpoint::SendStream;
use iroh::{Endpoint, EndpointId};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Maximum WireGuard packet size.
const MAX_WG_PACKET_SIZE: usize = 65536;

/// State for a connected VPN client.
struct ClientState {
    /// Client's assigned VPN IP.
    #[allow(dead_code)]
    assigned_ip: Ipv4Addr,
    /// Client's WireGuard public key.
    #[allow(dead_code)]
    wg_public_key: PublicKey,
    /// Client's iroh endpoint ID.
    #[allow(dead_code)]
    endpoint_id: EndpointId,
    /// WireGuard tunnel for this client.
    tunnel: Arc<Mutex<WgTunnel>>,
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
    /// IPs currently in use (mapped from client endpoint ID).
    in_use: HashMap<EndpointId, Ipv4Addr>,
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
    /// Reverse lookup: IP address -> endpoint ID.
    ip_to_endpoint: Arc<RwLock<HashMap<Ipv4Addr, EndpointId>>>,
    /// TUN device for VPN traffic.
    tun_device: Option<TunDevice>,
    /// Atomic counter for active connections (prevents race in max_clients check).
    active_connections: AtomicUsize,
}

impl VpnServer {
    /// Create a new VPN server.
    ///
    /// WireGuard keypair is always ephemeral (generated fresh each server start).
    /// This allows clients to use ephemeral keys without conflicts.
    pub async fn new(config: VpnServerConfig) -> VpnResult<Self> {
        // Generate ephemeral WireGuard keypair
        let keypair = WgKeyPair::generate();
        log::info!(
            "Generated ephemeral server WireGuard keypair: {}",
            keypair.public_key_base64()
        );

        // Create IP pool
        let ip_pool = Arc::new(RwLock::new(IpPool::new(config.network, config.server_ip)));

        Ok(Self {
            config,
            keypair,
            ip_pool,
            clients: Arc::new(RwLock::new(HashMap::new())),
            ip_to_endpoint: Arc::new(RwLock::new(HashMap::new())),
            tun_device: None,
            active_connections: AtomicUsize::new(0),
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

    /// Create and configure the TUN device.
    pub async fn setup_tun(&mut self) -> VpnResult<()> {
        let pool = self.ip_pool.read().await;
        let server_ip = pool.server_ip();
        let netmask = pool.network().netmask();
        drop(pool);

        let tun_config = TunConfig::new(server_ip, netmask, server_ip).with_mtu(self.config.mtu);

        let device = TunDevice::create(tun_config)?;
        log::info!(
            "Created TUN device: {} with IP {}",
            device.name(),
            server_ip
        );
        self.tun_device = Some(device);
        Ok(())
    }

    /// Run the VPN server, accepting connections via iroh.
    pub async fn run(mut self, endpoint: Endpoint) -> VpnResult<()> {
        // Setup TUN device
        self.setup_tun().await?;

        let server_ip = self.server_ip().await;
        let network = self.network().await;
        let public_key = self.public_key();

        log::info!("VPN Server started:");
        log::info!("  Network: {}", network);
        log::info!("  Server IP: {}", server_ip);
        log::info!("  Public key: {}", public_key.to_base64());
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
            "Received handshake from {} with WG key: {}",
            remote_id,
            handshake.wg_public_key.to_base64()
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
                handshake.wg_public_key,
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
        client_wg_public_key: WgPublicKey,
    ) -> VpnResult<()> {
        // Allocate IP for client
        let assigned_ip = {
            let mut pool = self.ip_pool.write().await;
            pool.allocate(remote_id)
                .ok_or_else(|| VpnError::IpAssignment("IP pool exhausted".into()))?
        };

        // Get server info for response
        let pool = self.ip_pool.read().await;
        let server_ip = pool.server_ip();
        let network = pool.network();
        drop(pool);

        // Create WireGuard tunnel for this client
        let peer_public_key = client_wg_public_key.to_public_key();
        let dummy_endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let tunnel = WgTunnelBuilder::new()
            .keypair(self.keypair.clone())
            .peer_public_key(peer_public_key)
            .peer_endpoint(dummy_endpoint)
            .keepalive_secs(Some(self.config.keepalive_secs))
            .build()?;

        let tunnel = Arc::new(Mutex::new(tunnel));

        // Send response (no wg_endpoint needed since we tunnel over iroh)
        let response = VpnHandshakeResponse::accepted(
            self.public_key(),
            assigned_ip,
            network,
            server_ip,
        );

        write_message(send, &response.encode()?).await?;
        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }

        log::info!(
            "Client {} connected, assigned IP: {}",
            remote_id,
            assigned_ip
        );

        // Accept data stream for WireGuard packets
        let (wg_send, wg_recv) = connection
            .accept_bi()
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to accept data stream: {}", e)))?;

        log::info!("Client {} data stream established", remote_id);

        let wg_send = Arc::new(Mutex::new(wg_send));

        // Store client state (including send stream for TUN handler to use)
        let client_state = ClientState {
            assigned_ip,
            wg_public_key: peer_public_key,
            endpoint_id: remote_id,
            tunnel: tunnel.clone(),
            send_stream: wg_send.clone(),
        };

        self.clients.write().await.insert(remote_id, client_state);
        self.ip_to_endpoint.write().await.insert(assigned_ip, remote_id);

        // Handle client data
        let clients = self.clients.clone();
        let ip_pool = self.ip_pool.clone();
        let ip_to_endpoint = self.ip_to_endpoint.clone();

        // Run client handler (blocks until client disconnects)
        let result = Self::handle_client_data(
            tunnel,
            wg_send,
            wg_recv,
            assigned_ip,
            tun_writer,
        )
        .await;

        if let Err(ref e) = result {
            log::error!("Client {} data error: {}", remote_id, e);
        }

        log::info!("Client {} disconnected", remote_id);

        // Cleanup
        clients.write().await.remove(&remote_id);
        ip_to_endpoint.write().await.remove(&assigned_ip);
        ip_pool.write().await.release(&remote_id);

        result
    }

    /// Handle client WireGuard data stream.
    async fn handle_client_data(
        tunnel: Arc<Mutex<WgTunnel>>,
        wg_send: Arc<Mutex<SendStream>>,
        mut wg_recv: iroh::endpoint::RecvStream,
        assigned_ip: Ipv4Addr,
        tun_writer: Arc<Mutex<TunWriter>>,
    ) -> VpnResult<()> {
        let tunnel_inbound = tunnel.clone();
        let tunnel_timers = tunnel.clone();
        let send_inbound = wg_send.clone();
        let send_heartbeat = wg_send.clone();

        // Spawn inbound task (iroh stream -> WireGuard -> TUN)
        let inbound_handle = tokio::spawn(async move {
            let mut type_buf = [0u8; 1];
            let mut len_buf = [0u8; 4];
            let mut data_buf = vec![0u8; MAX_WG_PACKET_SIZE];
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
                    DataMessageType::WireGuard => {
                        // Continue to read WireGuard packet below
                    }
                }

                // Read length prefix for WireGuard packet
                match wg_recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Failed to read WG packet length from {}: {}", assigned_ip, e);
                        break;
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_WG_PACKET_SIZE {
                    log::error!("WG packet too large from {}: {}", assigned_ip, len);
                    break;
                }

                // Read packet data
                match wg_recv.read_exact(&mut data_buf[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::debug!("Failed to read WG packet from {}: {}", assigned_ip, e);
                        break;
                    }
                }

                let packet = &data_buf[..len];
                let mut tunnel = tunnel_inbound.lock().await;
                match tunnel.decapsulate(None, packet) {
                    Ok(PacketResult::WriteToTunV4(data, _))
                    | Ok(PacketResult::WriteToTunV6(data, _)) => {
                        // Write decrypted packet to TUN device
                        let mut writer = tun_writer.lock().await;
                        if let Err(e) = writer.write_all(&data).await {
                            log::warn!("Failed to write to TUN: {}", e);
                        }
                        log::trace!("Wrote {} bytes to TUN from client {}", data.len(), assigned_ip);
                    }
                    Ok(PacketResult::WriteToNetwork(data)) => {
                        // Send WireGuard response back to client atomically
                        drop(tunnel);
                        let buf = frame_wireguard_packet(&data);
                        let mut send = send_inbound.lock().await;
                        if let Err(e) = send.write_all(&buf).await {
                            log::warn!("Failed to send response to {}: {}", assigned_ip, e);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("Decapsulation error from {}: {}", assigned_ip, e);
                    }
                }
            }
        });

        // Spawn timer task for WireGuard keepalives
        let timer_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let mut tunnel = tunnel_timers.lock().await;
                let results = tunnel.update_timers();
                drop(tunnel);

                for result in results {
                    match result {
                        PacketResult::WriteToNetwork(data) => {
                            let buf = frame_wireguard_packet(&data);
                            let mut send = wg_send.lock().await;
                            if let Err(e) = send.write_all(&buf).await {
                                log::warn!("Failed to send timer packet: {}", e);
                                return;
                            }
                        }
                        PacketResult::Error(e) => {
                            log::warn!("Timer error: {}", e);
                        }
                        _ => {}
                    }
                }
            }
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

            // Extract destination IP from IPv4 header
            let dest_ip = match extract_dest_ip(packet) {
                Some(ip) => ip,
                None => {
                    log::trace!("Non-IPv4 packet from TUN, skipping");
                    continue;
                }
            };

            // Look up which client owns this destination IP
            let endpoint_id = {
                let ip_map = self.ip_to_endpoint.read().await;
                ip_map.get(&dest_ip).copied()
            };

            let endpoint_id = match endpoint_id {
                Some(id) => id,
                None => {
                    log::trace!("No client for destination IP {}", dest_ip);
                    continue;
                }
            };

            // Get client state
            let clients = self.clients.read().await;
            let client = match clients.get(&endpoint_id) {
                Some(c) => c,
                None => {
                    log::trace!("Client {} not found", endpoint_id);
                    continue;
                }
            };

            // Encrypt packet with client's WireGuard tunnel
            let mut tunnel = client.tunnel.lock().await;
            match tunnel.encapsulate(packet) {
                Ok(PacketResult::WriteToNetwork(data)) => {
                    // Send encrypted packet to client via iroh stream atomically
                    let buf = frame_wireguard_packet(&data);
                    let mut send = client.send_stream.lock().await;
                    if let Err(e) = send.write_all(&buf).await {
                        log::warn!("Failed to send to client {}: {}", dest_ip, e);
                        continue;
                    }
                    log::trace!("Sent {} bytes to client {}", data.len(), dest_ip);
                }
                Ok(_) => {}
                Err(e) => {
                    log::warn!("Encapsulation error for {}: {}", dest_ip, e);
                }
            }
        }

        Ok(())
    }
}

/// Extract destination IPv4 address from an IP packet.
fn extract_dest_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    // Minimum IPv4 header is 20 bytes
    if packet.len() < 20 {
        return None;
    }

    // Check IP version (should be 4)
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    // Destination IP is at bytes 16-19
    let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some(dest_ip)
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
        let mut pool = IpPool::new(network, None);

        // Server uses .1, only .2 available for clients
        let id1 = random_endpoint_id();
        let id2 = random_endpoint_id();

        let ip1 = pool.allocate(id1);
        assert!(ip1.is_some());

        let ip2 = pool.allocate(id2);
        assert!(ip2.is_none()); // Pool exhausted
    }

    #[test]
    fn test_extract_dest_ip() {
        // Valid IPv4 packet header (minimal)
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 5;

        let ip = extract_dest_ip(&packet);
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 5)));

        // Too short
        assert_eq!(extract_dest_ip(&[0u8; 10]), None);

        // Wrong version (IPv6)
        packet[0] = 0x60;
        assert_eq!(extract_dest_ip(&packet), None);
    }
}
