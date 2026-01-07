//! VPN client implementation.
//!
//! The VPN client connects to a VPN server via iroh, performs WireGuard
//! key exchange, configures the TUN device, and manages the VPN tunnel.
//!
//! WireGuard packets are tunneled through the iroh QUIC connection to handle
//! NAT traversal automatically.

use crate::config::VpnClientConfig;
use crate::device::{add_routes, RouteGuard, TunConfig, TunDevice};
use crate::error::{VpnError, VpnResult};
use crate::keys::{WgKeyPair, WgPublicKey};
use crate::lock::VpnLock;
use crate::signaling::{
    read_message, write_message, VpnHandshake, VpnHandshakeResponse, MAX_HANDSHAKE_SIZE, VPN_ALPN,
};
use crate::tunnel::{PacketResult, WgTunnel, WgTunnelBuilder};
use ipnet::Ipv4Net;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum WireGuard packet size (MTU + overhead).
const MAX_WG_PACKET_SIZE: usize = 65536;

/// VPN client instance.
pub struct VpnClient {
    /// Client configuration.
    config: VpnClientConfig,
    /// Client's WireGuard keypair.
    keypair: WgKeyPair,
    /// Single-instance lock.
    _lock: VpnLock,
}

/// Information received from the VPN server after successful handshake.
pub struct ServerInfo {
    /// Server's WireGuard public key.
    pub wg_public_key: WgPublicKey,
    /// Assigned VPN IP for this client.
    pub assigned_ip: Ipv4Addr,
    /// VPN network CIDR.
    pub network: Ipv4Net,
    /// Server's VPN IP (gateway).
    pub server_ip: Ipv4Addr,
}

impl VpnClient {
    /// Create a new VPN client.
    ///
    /// WireGuard keypair is always ephemeral (generated fresh each session).
    /// This allows multiple clients to connect without key conflicts.
    pub fn new(config: VpnClientConfig) -> VpnResult<Self> {
        // Acquire single-instance lock
        let lock = VpnLock::acquire()?;

        // Generate ephemeral WireGuard keypair (unique per session)
        let keypair = WgKeyPair::generate();
        log::info!(
            "Generated ephemeral WireGuard keypair: {}",
            keypair.public_key_base64()
        );

        Ok(Self {
            config,
            keypair,
            _lock: lock,
        })
    }

    /// Get the client's WireGuard public key.
    pub fn public_key(&self) -> WgPublicKey {
        WgPublicKey::from(self.keypair.public_key())
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

        // Create TUN device
        let tun_device = self.create_tun_device(&server_info)?;

        // Add custom routes through the VPN (guard ensures cleanup on drop)
        let _route_guard: Option<RouteGuard> = if !self.config.routes.is_empty() {
            Some(add_routes(tun_device.name(), &self.config.routes).await?)
        } else {
            None
        };

        // Open data stream for WireGuard packets
        let (wg_send, wg_recv) = connection.open_bi().await.map_err(|e| {
            VpnError::Signaling(format!("Failed to open data stream: {}", e))
        })?;

        log::info!("Opened WireGuard data stream");

        // Create WireGuard tunnel (using dummy endpoint since we tunnel over iroh)
        let peer_public_key = server_info.wg_public_key.to_public_key();
        let dummy_endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let tunnel = WgTunnelBuilder::new()
            .keypair(self.keypair.clone())
            .peer_public_key(peer_public_key)
            .peer_endpoint(dummy_endpoint)
            .keepalive_secs(Some(self.config.keepalive_secs))
            .build()?;

        let tunnel = Arc::new(Mutex::new(tunnel));

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());
        log::info!("  Client IP: {}", server_info.assigned_ip);

        // Run the VPN packet loop (tunneled over iroh)
        self.run_vpn_loop(tun_device, tunnel, wg_send, wg_recv).await
    }

    /// Perform VPN handshake with the server.
    async fn perform_handshake(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> VpnResult<ServerInfo> {
        // Open bidirectional stream for handshake
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            VpnError::Signaling(format!("Failed to open stream: {}", e))
        })?;

        // Send handshake
        let mut handshake = VpnHandshake::new(self.public_key());
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
            return Err(VpnError::Signaling(format!("Server rejected: {}", reason)));
        }

        // Extract server info
        let wg_public_key = response.wg_public_key.ok_or_else(|| {
            VpnError::Signaling("Server response missing WG public key".into())
        })?;
        let assigned_ip = response.assigned_ip.ok_or_else(|| {
            VpnError::Signaling("Server response missing assigned IP".into())
        })?;
        let network = response.network.ok_or_else(|| {
            VpnError::Signaling("Server response missing network".into())
        })?;
        let server_ip = response.server_ip.ok_or_else(|| {
            VpnError::Signaling("Server response missing server IP".into())
        })?;

        // Close handshake stream (best-effort, handshake already completed)
        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }
        Ok(ServerInfo {
            wg_public_key,
            assigned_ip,
            network,
            server_ip,
        })
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self, server_info: &ServerInfo) -> VpnResult<TunDevice> {
        let tun_config = TunConfig::new(
            server_info.assigned_ip,
            server_info.network.netmask(),
            server_info.server_ip,
        )
        .with_mtu(self.config.mtu);

        TunDevice::create(tun_config)
    }

    /// Run the VPN packet processing loop (tunneled over iroh QUIC).
    async fn run_vpn_loop(
        &self,
        tun_device: TunDevice,
        tunnel: Arc<Mutex<WgTunnel>>,
        wg_send: SendStream,
        wg_recv: RecvStream,
    ) -> VpnResult<()> {
        // Split TUN device
        let (mut tun_reader, mut tun_writer) = tun_device.split()?;
        let buffer_size = tun_reader.buffer_size();

        // Wrap streams in Arc<Mutex> for sharing
        let wg_send = Arc::new(Mutex::new(wg_send));
        let wg_recv = Arc::new(Mutex::new(wg_recv));

        // Clone for tasks
        let tunnel_outbound = tunnel.clone();
        let tunnel_inbound = tunnel.clone();
        let tunnel_timers = tunnel.clone();
        let send_outbound = wg_send.clone();
        let send_timers = wg_send.clone();

        // Spawn outbound task (TUN -> WireGuard -> iroh stream)
        let outbound_handle = tokio::spawn(async move {
            let mut read_buf = vec![0u8; buffer_size];
            let mut write_buf = Vec::with_capacity(4 + MAX_WG_PACKET_SIZE);
            loop {
                match tun_reader.read(&mut read_buf).await {
                    Ok(n) if n > 0 => {
                        let packet = &read_buf[..n];
                        let mut tunnel = tunnel_outbound.lock().await;
                        match tunnel.encapsulate(packet) {
                            Ok(PacketResult::WriteToNetwork(data)) => {
                                let mut send = send_outbound.lock().await;
                                // Write length-prefixed packet atomically (reuse buffer)
                                write_buf.clear();
                                write_buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                                write_buf.extend_from_slice(&data);
                                if let Err(e) = send.write_all(&write_buf).await {
                                    log::warn!("Failed to write WG packet: {}", e);
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!("Encapsulation error: {}", e);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Spawn inbound task (iroh stream -> WireGuard -> TUN)
        let inbound_handle = tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            let mut data_buf = vec![0u8; MAX_WG_PACKET_SIZE];
            let mut write_buf = Vec::with_capacity(4 + MAX_WG_PACKET_SIZE);
            loop {
                let mut recv = wg_recv.lock().await;
                // Read length prefix
                match recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read WG packet length: {}", e);
                        break;
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_WG_PACKET_SIZE {
                    log::error!("WG packet too large: {}", len);
                    break;
                }

                // Read packet data
                match recv.read_exact(&mut data_buf[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read WG packet: {}", e);
                        break;
                    }
                }
                drop(recv); // Release lock before processing

                let packet = &data_buf[..len];
                let mut tunnel = tunnel_inbound.lock().await;
                match tunnel.decapsulate(None, packet) {
                    Ok(PacketResult::WriteToTunV4(data, _))
                    | Ok(PacketResult::WriteToTunV6(data, _)) => {
                        if let Err(e) = tun_writer.write_all(&data).await {
                            log::warn!("Failed to write to TUN: {}", e);
                        }
                    }
                    Ok(PacketResult::WriteToNetwork(data)) => {
                        // Need to send response back through stream atomically (reuse buffer)
                        drop(tunnel);
                        let mut send = send_timers.lock().await;
                        write_buf.clear();
                        write_buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                        write_buf.extend_from_slice(&data);
                        if let Err(e) = send.write_all(&write_buf).await {
                            log::warn!("Failed to send response packet: {}", e);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("Decapsulation error: {}", e);
                    }
                }
            }
        });

        // Spawn timer task
        let timer_handle = tokio::spawn(async move {
            let mut write_buf = Vec::with_capacity(4 + MAX_WG_PACKET_SIZE);
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let mut tunnel = tunnel_timers.lock().await;
                let results = tunnel.update_timers();
                drop(tunnel);

                for result in results {
                    match result {
                        PacketResult::WriteToNetwork(data) => {
                            let mut send = wg_send.lock().await;
                            // Write length-prefixed packet atomically (reuse buffer)
                            write_buf.clear();
                            write_buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                            write_buf.extend_from_slice(&data);
                            if let Err(e) = send.write_all(&write_buf).await {
                                log::warn!("Failed to send timer packet: {}", e);
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

        // Wait for any task to complete (or error)
        tokio::select! {
            _ = outbound_handle => {
                log::info!("Outbound task ended");
            }
            _ = inbound_handle => {
                log::info!("Inbound task ended");
            }
            _ = timer_handle => {
                log::info!("Timer task ended");
            }
        }

        Ok(())
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

    /// Set the keepalive interval.
    pub fn keepalive_secs(mut self, secs: u16) -> Self {
        self.config.keepalive_secs = secs;
        self
    }

    /// Build the client.
    pub fn build(self) -> VpnResult<VpnClient> {
        VpnClient::new(self.config)
    }
}
