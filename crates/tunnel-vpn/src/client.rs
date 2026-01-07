//! VPN client implementation.
//!
//! The VPN client connects to a VPN server via iroh, performs WireGuard
//! key exchange, configures the TUN device, and manages the VPN tunnel.

use crate::config::VpnClientConfig;
use crate::device::{TunConfig, TunDevice};
use crate::error::{VpnError, VpnResult};
use crate::keys::{WgKeyPair, WgPublicKey};
use crate::lock::VpnLock;
use crate::signaling::{
    read_message, write_message, VpnHandshake, VpnHandshakeResponse, MAX_HANDSHAKE_SIZE, VPN_ALPN,
};
use crate::tunnel::{PacketResult, WgTunnel, WgTunnelBuilder};
use ipnet::Ipv4Net;
use iroh::{Endpoint, EndpointId};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::Mutex;

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
    /// Server's WireGuard endpoint.
    pub wg_endpoint: SocketAddr,
    /// Assigned VPN IP for this client.
    pub assigned_ip: Ipv4Addr,
    /// VPN network CIDR.
    pub network: Ipv4Net,
    /// Server's VPN IP (gateway).
    pub server_ip: Ipv4Addr,
}

impl VpnClient {
    /// Create a new VPN client.
    pub fn new(config: VpnClientConfig) -> VpnResult<Self> {
        // Acquire single-instance lock
        let lock = VpnLock::acquire()?;

        // Load or generate keypair
        let keypair = if let Some(ref path) = config.private_key_file {
            WgKeyPair::load_from_file_sync(path)?
        } else {
            let kp = WgKeyPair::generate();
            log::info!("Generated new WireGuard keypair");
            kp
        };

        log::info!(
            "VPN Client initialized, public key: {}",
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

        // Perform handshake
        let server_info = self.perform_handshake(&connection).await?;

        log::info!("Handshake successful:");
        log::info!("  Assigned IP: {}", server_info.assigned_ip);
        log::info!("  Network: {}", server_info.network);
        log::info!("  Gateway: {}", server_info.server_ip);
        log::info!("  Server WG endpoint: {}", server_info.wg_endpoint);

        // Create TUN device
        let tun_device = self.create_tun_device(&server_info)?;

        // Bind UDP socket for WireGuard
        let std_socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            VpnError::Network(std::io::Error::new(
                e.kind(),
                format!("Failed to bind WireGuard socket: {}", e),
            ))
        })?;
        std_socket.set_nonblocking(true)?;
        let wg_socket = Arc::new(TokioUdpSocket::from_std(std_socket)?);

        // Create WireGuard tunnel
        let peer_public_key = server_info.wg_public_key.to_public_key();
        let mut tunnel = WgTunnelBuilder::new()
            .keypair(self.keypair.clone())
            .peer_public_key(peer_public_key)
            .peer_endpoint(server_info.wg_endpoint)
            .keepalive_secs(Some(self.config.keepalive_secs))
            .build()?;

        tunnel.set_peer_endpoint(server_info.wg_endpoint);
        let tunnel = Arc::new(Mutex::new(tunnel));

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());
        log::info!("  Client IP: {}", server_info.assigned_ip);

        // Run the VPN packet loop
        self.run_vpn_loop(tun_device, tunnel, wg_socket, server_info.wg_endpoint)
            .await
    }

    /// Perform VPN handshake with the server.
    async fn perform_handshake(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> VpnResult<ServerInfo> {
        // Open bidirectional stream
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
        let wg_endpoint = response.wg_endpoint.ok_or_else(|| {
            VpnError::Signaling("Server response missing WG endpoint".into())
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

        Ok(ServerInfo {
            wg_public_key,
            wg_endpoint,
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

    /// Run the VPN packet processing loop.
    async fn run_vpn_loop(
        &self,
        tun_device: TunDevice,
        tunnel: Arc<Mutex<WgTunnel>>,
        wg_socket: Arc<TokioUdpSocket>,
        peer_endpoint: SocketAddr,
    ) -> VpnResult<()> {
        // Split TUN device
        let (mut tun_reader, mut tun_writer) = tun_device.split()?;
        let buffer_size = tun_reader.buffer_size();

        // Clone for tasks
        let tunnel_outbound = tunnel.clone();
        let tunnel_inbound = tunnel.clone();
        let tunnel_timers = tunnel.clone();
        let socket_outbound = wg_socket.clone();
        let socket_inbound = wg_socket.clone();
        let socket_timers = wg_socket.clone();

        // Spawn outbound task (TUN -> WireGuard -> UDP)
        let outbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; buffer_size];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let packet = &buf[..n];
                        let mut tunnel = tunnel_outbound.lock().await;
                        match tunnel.encapsulate(packet) {
                            Ok(PacketResult::WriteToNetwork(data)) => {
                                if let Err(e) = socket_outbound.send_to(&data, peer_endpoint).await
                                {
                                    log::warn!("Failed to send WG packet: {}", e);
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

        // Spawn inbound task (UDP -> WireGuard -> TUN)
        let inbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match socket_inbound.recv_from(&mut buf).await {
                    Ok((n, src_addr)) => {
                        let packet = &buf[..n];
                        let mut tunnel = tunnel_inbound.lock().await;
                        match tunnel.decapsulate(Some(src_addr.ip()), packet) {
                            Ok(PacketResult::WriteToTunV4(data, _))
                            | Ok(PacketResult::WriteToTunV6(data, _)) => {
                                if let Err(e) = tun_writer.write_all(&data).await {
                                    log::warn!("Failed to write to TUN: {}", e);
                                }
                            }
                            Ok(PacketResult::WriteToNetwork(data)) => {
                                if let Err(e) = socket_inbound.send_to(&data, src_addr).await {
                                    log::warn!("Failed to send WG response: {}", e);
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!("Decapsulation error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });

        // Spawn timer task
        let timer_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let mut tunnel = tunnel_timers.lock().await;
                for result in tunnel.update_timers() {
                    match result {
                        PacketResult::WriteToNetwork(data) => {
                            if let Err(e) = socket_timers.send_to(&data, peer_endpoint).await {
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
