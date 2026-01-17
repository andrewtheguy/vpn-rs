//! VPN server implementation using ICE/Nostr transport.
//!
//! The VPN server listens for Nostr signaling requests, establishes ICE+QUIC
//! connections, performs VPN handshake to assign IPs, and manages the
//! IP-over-QUIC tunnel for connected clients.

use crate::config::VpnIceServerConfig;
use crate::error::{VpnIceError, VpnIceResult};
use bytes::{Bytes, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use etherparse::{Ipv4Header, Ipv4HeaderSlice, Ipv6Header, Ipv6HeaderSlice};
use quinn::{RecvStream, SendStream};
use tunnel_ice::signaling::{
    ManualOffer, ManualRequest, NostrSignaling, SignalingError, MANUAL_SIGNAL_VERSION,
};
use tunnel_ice::transport::ice::{IceEndpoint, IceRole};
use tunnel_ice::transport::quic;
use tunnel_ice::tunnel_common::{short_session_id, MAX_REQUEST_AGE_SECS};
use tunnel_vpn::buffer::{as_mut_byte_slice, uninitialized_vec};
use tunnel_vpn::device::{TunConfig, TunDevice};
use tunnel_vpn::signaling::{
    frame_ip_packet, read_message, write_message, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, MAX_HANDSHAKE_SIZE,
};

/// Maximum IP packet size (MTU + overhead).
const MAX_IP_PACKET_SIZE: usize = 65536;

/// Heartbeat ping interval (how often server checks for client activity).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Heartbeat timeout (max time to wait for ping before disconnecting client).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);

/// Channel buffer size for outbound packets.
const OUTBOUND_CHANNEL_SIZE: usize = 1024;

/// QUIC connection timeout.
const QUIC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Simple IPv4 address pool for VPN clients.
struct SimpleIpPool {
    network: Ipv4Net,
    server_ip: Ipv4Addr,
    next_host: u32,
    max_host: u32,
    allocated: HashSet<Ipv4Addr>,
}

impl SimpleIpPool {
    fn new(network: Ipv4Net, server_ip: Option<Ipv4Addr>) -> Self {
        let server = server_ip.unwrap_or_else(|| default_server_ip4(network));
        let network_u32 = u32::from(network.network());
        let broadcast_u32 = u32::from(network.broadcast());
        let server_u32 = u32::from(server);
        
        // Start from after the server IP
        let mut next_host = server_u32.saturating_add(1);
        if next_host >= broadcast_u32 {
            next_host = network_u32.saturating_add(1);
        }
        
        Self {
            network,
            server_ip: server,
            next_host,
            max_host: broadcast_u32,
            allocated: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> Option<Ipv4Addr> {
        let start = self.next_host;
        loop {
            let candidate = Ipv4Addr::from(self.next_host);
            self.next_host = self.next_host.saturating_add(1);
            if self.next_host >= self.max_host {
                self.next_host = u32::from(self.network.network()).saturating_add(1);
            }
            
            // Skip network address, broadcast, and server IP
            if candidate != self.network.network() 
                && candidate != self.network.broadcast()
                && candidate != self.server_ip
                && !self.allocated.contains(&candidate)
            {
                self.allocated.insert(candidate);
                return Some(candidate);
            }
            
            // Wrapped around - no available IPs
            if self.next_host == start {
                return None;
            }
        }
    }

    fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.remove(&ip);
    }

}

/// Simple IPv6 address pool for VPN clients.
struct SimpleIp6Pool {
    network: Ipv6Net,
    server_ip: Ipv6Addr,
    next_suffix: u128,
    allocated: HashSet<Ipv6Addr>,
}

impl SimpleIp6Pool {
    fn new(network: Ipv6Net, server_ip: Option<Ipv6Addr>) -> Self {
        let server = server_ip.unwrap_or_else(|| default_server_ip6(network));
        
        Self {
            network,
            server_ip: server,
            next_suffix: 1, // Start from ::1 and skip server IP as needed.
            allocated: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> Option<Ipv6Addr> {
        let base = self.network.network();
        let host_bits = 128u32.saturating_sub(self.network.prefix_len() as u32);
        let max_offset = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits).saturating_sub(1)
        };
        let max_attempts = max_offset.saturating_add(1);
        let mut attempts = 0u128;
        let base_u128 = u128::from(base);

        while attempts < max_attempts {
            if self.next_suffix >= max_attempts {
                return None;
            }
            let offset = self.next_suffix;
            self.next_suffix = self.next_suffix.saturating_add(1);
            attempts = attempts.saturating_add(1);

            let addr_u128 = base_u128.checked_add(offset)?;
            let ip = Ipv6Addr::from(addr_u128);
            if ip != self.server_ip && !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Some(ip);
            }
        }

        None
    }

    fn release(&mut self, ip: Ipv6Addr) {
        self.allocated.remove(&ip);
    }

}

struct IpAllocationGuard<'a> {
    ip_pool: Option<&'a mut SimpleIpPool>,
    ip6_pool: Option<&'a mut SimpleIp6Pool>,
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip6: Option<Ipv6Addr>,
    armed: bool,
}

impl<'a> IpAllocationGuard<'a> {
    fn new(
        ip_pool: &'a mut Option<SimpleIpPool>,
        ip6_pool: &'a mut Option<SimpleIp6Pool>,
        assigned_ip: Option<Ipv4Addr>,
        assigned_ip6: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            ip_pool: ip_pool.as_mut(),
            ip6_pool: ip6_pool.as_mut(),
            assigned_ip,
            assigned_ip6,
            armed: true,
        }
    }

    fn release(&mut self) {
        if let Some(ip) = self.assigned_ip {
            if let Some(pool) = self.ip_pool.as_mut() {
                pool.release(ip);
            }
        }
        if let Some(ip6) = self.assigned_ip6 {
            if let Some(pool) = self.ip6_pool.as_mut() {
                pool.release(ip6);
            }
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn release_and_disarm(&mut self) {
        self.release();
        self.disarm();
    }
}

impl Drop for IpAllocationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.release();
        }
    }
}

/// VPN server using ICE/Nostr transport.
pub struct VpnIceServer {
    /// Server configuration.
    config: VpnIceServerConfig,
}


impl VpnIceServer {
    /// Create a new VPN ICE server.
    pub async fn new(config: VpnIceServerConfig) -> VpnIceResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| VpnIceError::Config(e.to_string()))?;

        Ok(Self { config })
    }

    /// Run the VPN server.
    pub async fn run(&self) -> VpnIceResult<()> {
        // Ensure crypto provider is installed
        quic::ensure_crypto_provider();

        let nsec = self.config.get_nsec()?;

        log::info!("VPN ICE Server - Nostr Mode");
        log::info!("===========================");

        // Initialize IP pools
        let mut ip_pool =
            self.config
                .network
                .map(|network| SimpleIpPool::new(network, self.config.server_ip));

        let mut ip6_pool =
            self.config
                .network6
                .map(|network6| SimpleIp6Pool::new(network6, self.config.server_ip6));

        // Initialize Nostr signaling
        let relay_list = self.config.relays.clone();
        let signaling = Arc::new(
            NostrSignaling::new(&nsec, &self.config.peer_npub, relay_list)
                .await
                .map_err(|e| VpnIceError::Signaling(e.to_string()))?,
        );

        log::info!("Server pubkey: {}", signaling.public_key_bech32());
        log::info!("Transfer ID: {}", signaling.transfer_id());
        log::info!("Relays: {:?}", signaling.relay_urls());
        log::info!("Peer npub: {}", self.config.peer_npub);

        if let Some(network) = self.config.network {
            log::info!("IPv4 network: {}", network);
        }
        if let Some(network6) = self.config.network6 {
            log::info!("IPv6 network: {}", network6);
        }

        signaling
            .subscribe()
            .await
            .map_err(|e| VpnIceError::Signaling(e.to_string()))?;

        log::info!(
            "Waiting for VPN client requests (max clients: {})...",
            self.config.max_clients
        );

        // Track processed sessions to avoid duplicates
        let mut processed_sessions: HashMap<String, Instant> = HashMap::new();
        const MAX_PROCESSED_SESSIONS: usize = 1000;
        let session_ttl = Duration::from_secs(MAX_REQUEST_AGE_SECS * 2);

        loop {
            // Wait for request from client
            let request = match signaling
                .wait_for_fresh_request_forever(MAX_REQUEST_AGE_SECS)
                .await
            {
                Ok(req) => req,
                Err(e) => {
                    if e.downcast_ref::<SignalingError>()
                        .map(|se| se.is_channel_closed())
                        .unwrap_or(false)
                    {
                        return Err(VpnIceError::Signaling(
                            "Nostr signaling channel closed".to_string(),
                        ));
                    }
                    log::warn!("Error waiting for request: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if request.version != MANUAL_SIGNAL_VERSION {
                log::warn!(
                    "Ignoring request with version mismatch (expected {}, got {})",
                    MANUAL_SIGNAL_VERSION,
                    request.version
                );
                continue;
            }

            // Check if this is a VPN request (source = "vpn://connect")
            let source = request.source.as_deref().unwrap_or("");
            if source != "vpn://connect" {
                log::debug!("Ignoring non-VPN request: source={}", source);
                continue;
            }

            let session_id = request.session_id.clone();
            let now = Instant::now();

            // Skip duplicate requests
            if processed_sessions.contains_key(&session_id) {
                log::debug!(
                    "Ignoring duplicate request for session {}",
                    short_session_id(&session_id)
                );
                continue;
            }

            // Evict expired entries
            if processed_sessions.len() >= MAX_PROCESSED_SESSIONS {
                processed_sessions
                    .retain(|_, timestamp| now.duration_since(*timestamp) < session_ttl);
            }
            processed_sessions.insert(session_id.clone(), now);

            log::info!(
                "Received VPN request for session {}",
                short_session_id(&session_id)
            );

            // Handle the VPN session (single client for now)
            // In a multi-client scenario, this would spawn a task
            match self
                .handle_vpn_session(
                    signaling.clone(),
                    request,
                    &mut ip_pool,
                    &mut ip6_pool,
                )
                .await
            {
                Ok(()) => {
                    log::info!("VPN session ended normally");
                }
                Err(e) => {
                    log::warn!("VPN session error: {}", e);
                }
            }

            log::info!("Waiting for next VPN client request...");
        }
    }

    /// Handle a VPN session from a connected client.
    async fn handle_vpn_session(
        &self,
        signaling: Arc<NostrSignaling>,
        request: ManualRequest,
        ip_pool: &mut Option<SimpleIpPool>,
        ip6_pool: &mut Option<SimpleIp6Pool>,
    ) -> VpnIceResult<()> {
        let session_id = request.session_id.clone();
        let short_id = short_session_id(&session_id).to_string();

        log::info!("[{}] Starting VPN session...", short_id);

        // Create TUN device
        let tun_device = self.create_tun_device()?;
        log::info!("[{}] Created TUN device: {}", short_id, tun_device.name());

        // Gather ICE candidates
        let ice = IceEndpoint::gather(&self.config.stun_servers)
            .await
            .map_err(|e| VpnIceError::Ice(e.to_string()))?;
        let local_creds = ice.local_credentials();
        let local_candidates = ice.local_candidates();
        log::info!(
            "[{}] Gathered {} ICE candidates",
            short_id,
            local_candidates.len()
        );

        // Generate QUIC identity
        let quic_identity =
            quic::generate_server_identity().map_err(|e| VpnIceError::Quic(e.to_string()))?;

        // Publish offer
        let offer = ManualOffer {
            version: MANUAL_SIGNAL_VERSION,
            ice_ufrag: local_creds.ufrag.clone(),
            ice_pwd: local_creds.pass.clone(),
            candidates: local_candidates,
            quic_fingerprint: quic_identity.fingerprint.clone(),
            session_id: Some(session_id.clone()),
            source: None,
        };

        signaling
            .publish_offer(&offer)
            .await
            .map_err(|e| VpnIceError::Signaling(e.to_string()))?;
        log::info!("[{}] Published offer, starting ICE...", short_id);

        // Use client's ICE credentials from the request
        let remote_creds = str0m::IceCreds {
            ufrag: request.ice_ufrag,
            pass: request.ice_pwd,
        };

        let ice_conn = ice
            .connect(IceRole::Controlling, remote_creds, request.candidates)
            .await
            .map_err(|e| VpnIceError::Ice(e.to_string()))?;

        log::info!(
            "[{}] ICE connected: -> {}",
            short_id,
            ice_conn.remote_addr
        );

        // Spawn ICE keeper
        let ice_disconnect_rx = ice_conn.disconnect_rx.clone();
        let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

        // Create QUIC endpoint
        let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)
            .map_err(|e| VpnIceError::Quic(e.to_string()))?;

        // Accept QUIC connection
        let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
            .await
            .map_err(|_| VpnIceError::Timeout("Timeout waiting for QUIC connection".to_string()))?
            .ok_or_else(|| VpnIceError::Quic("No incoming QUIC connection".to_string()))?;

        let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
            .await
            .map_err(|_| VpnIceError::Timeout("Timeout during QUIC handshake".to_string()))?
            .map_err(|e| VpnIceError::Quic(format!("Failed to accept QUIC connection: {}", e)))?;

        log::info!("[{}] QUIC connected", short_id);

        // Perform VPN handshake
        let (handshake_result, _device_id) =
            self.perform_handshake(&conn, ip_pool, ip6_pool).await?;
        let mut allocation_guard = IpAllocationGuard::new(
            ip_pool,
            ip6_pool,
            handshake_result.assigned_ip,
            handshake_result.assigned_ip6,
        );

        log::info!("[{}] VPN handshake complete:", short_id);
        if let Some(ip) = handshake_result.assigned_ip {
            log::info!("[{}]   Assigned IP: {}", short_id, ip);
        }
        if let Some(ip6) = handshake_result.assigned_ip6 {
            log::info!("[{}]   Assigned IPv6: {}", short_id, ip6);
        }

        // Accept data stream
        let (data_send, data_recv) = conn
            .accept_bi()
            .await
            .map_err(|e| VpnIceError::Quic(format!("Failed to accept data stream: {}", e)))?;

        log::info!("[{}] Data stream opened, starting VPN tunnel", short_id);

        // Run VPN loop
        let result = self
            .run_vpn_loop(RunVpnLoopParams {
                short_id: short_id.clone(),
                tun_device,
                data_send,
                data_recv,
                client_ip: handshake_result.assigned_ip,
                client_ip6: handshake_result.assigned_ip6,
                ice_disconnect_rx: ice_disconnect_rx.clone(),
            })
            .await;

        // Cleanup
        ice_keeper_handle.abort();
        let _ = ice_keeper_handle.await;

        if result.is_ok() {
            allocation_guard.release_and_disarm();
        }

        log::info!("[{}] VPN session ended", short_id);
        result
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self) -> VpnIceResult<TunDevice> {
        let tun_config = match (
            self.config.network,
            self.config.network6,
            self.config.server_ip,
            self.config.server_ip6,
        ) {
            // Dual-stack
            (Some(net4), Some(net6), server_ip4, server_ip6) => {
                let ip4 = server_ip4.unwrap_or_else(|| default_server_ip4(net4));
                let ip6 = server_ip6.unwrap_or_else(|| default_server_ip6(net6));
                TunConfig::new(ip4, net4.netmask(), ip4)
                    .with_mtu(self.config.mtu)
                    .with_ipv6(ip6, net6.prefix_len())
                    .map_err(|e| VpnIceError::Tun(e.to_string()))?
            }
            // IPv4-only
            (Some(net4), None, server_ip4, _) => {
                let ip4 = server_ip4.unwrap_or_else(|| default_server_ip4(net4));
                TunConfig::new(ip4, net4.netmask(), ip4).with_mtu(self.config.mtu)
            }
            // IPv6-only
            (None, Some(net6), _, server_ip6) => {
                let ip6 = server_ip6.unwrap_or_else(|| default_server_ip6(net6));
                TunConfig::ipv6_only(ip6, net6.prefix_len(), self.config.mtu)
                    .map_err(|e| VpnIceError::Tun(e.to_string()))?
            }
            // No network configured (should be caught by validation)
            (None, None, _, _) => {
                return Err(VpnIceError::Config(
                    "No network configured".to_string(),
                ))
            }
        };

        TunDevice::create(tun_config).map_err(|e| VpnIceError::Tun(e.to_string()))
    }

    /// Perform VPN handshake with the client.
    async fn perform_handshake(
        &self,
        conn: &quinn::Connection,
        ip_pool: &mut Option<SimpleIpPool>,
        ip6_pool: &mut Option<SimpleIp6Pool>,
    ) -> VpnIceResult<(HandshakeResult, u64)> {
        // Accept handshake stream
        let (mut send, mut recv): (SendStream, RecvStream) = conn
            .accept_bi()
            .await
            .map_err(|e| VpnIceError::Quic(format!("Failed to accept handshake stream: {}", e)))?;

        // Read handshake
        let handshake_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE)
            .await
            .map_err(|e| VpnIceError::Handshake(e.to_string()))?;
        let handshake = VpnHandshake::decode(&handshake_data)?;

        let device_id = handshake.device_id;

        // For nostr mode, the peer npub is the authentication
        // (we're already only accepting requests from the configured peer)

        // Allocate IP addresses
        let assigned_ip = ip_pool
            .as_mut()
            .and_then(|pool| pool.allocate());

        let assigned_ip6 = ip6_pool
            .as_mut()
            .and_then(|pool| pool.allocate());

        let mut allocation_guard =
            IpAllocationGuard::new(ip_pool, ip6_pool, assigned_ip, assigned_ip6);

        // At least one IP must be assigned
        if assigned_ip.is_none() && assigned_ip6.is_none() {
            let response = VpnHandshakeResponse::rejected("No IP addresses available");
            write_message::<SendStream>(&mut send, &response.encode()?)
                .await
                .map_err(|e| VpnIceError::Handshake(e.to_string()))?;
            return Err(VpnIceError::Rejected("No IP addresses available".to_string()));
        }

        // Build response based on what was allocated
        let response = match (
            assigned_ip,
            self.config.network,
            self.config.server_ip,
            assigned_ip6,
            self.config.network6,
            self.config.server_ip6,
        ) {
            // Dual-stack
            (Some(ip4), Some(net4), server_ip4, Some(ip6), Some(net6), server_ip6) => {
                let server4 = server_ip4.unwrap_or_else(|| default_server_ip4(net4));
                let server6 = server_ip6.unwrap_or_else(|| default_server_ip6(net6));
                VpnHandshakeResponse::accepted_dual_stack(ip4, net4, server4, ip6, net6, server6)
            }
            // IPv4-only
            (Some(ip4), Some(net4), server_ip4, None, _, _) => {
                let server4 = server_ip4.unwrap_or_else(|| default_server_ip4(net4));
                VpnHandshakeResponse::accepted(ip4, net4, server4)
            }
            // IPv6-only
            (None, _, _, Some(ip6), Some(net6), server_ip6) => {
                let server6 = server_ip6.unwrap_or_else(|| default_server_ip6(net6));
                VpnHandshakeResponse::accepted_ipv6_only(ip6, net6, server6)
            }
            _ => {
                let response = VpnHandshakeResponse::rejected("Configuration error");
                write_message::<SendStream>(&mut send, &response.encode()?)
                    .await
                    .map_err(|e| VpnIceError::Handshake(e.to_string()))?;
                return Err(VpnIceError::Config("Invalid network configuration".to_string()));
            }
        };

        write_message::<SendStream>(&mut send, &response.encode()?)
            .await
            .map_err(|e| VpnIceError::Handshake(e.to_string()))?;

        if let Err(e) = send.finish() {
            log::debug!("Failed to finish handshake stream: {}", e);
        }

        allocation_guard.disarm();

        Ok((
            HandshakeResult {
                assigned_ip,
                assigned_ip6,
            },
            device_id,
        ))
    }

    /// Run the VPN packet processing loop for a client.
    async fn run_vpn_loop(&self, params: RunVpnLoopParams) -> VpnIceResult<()> {
        let RunVpnLoopParams {
            short_id,
            tun_device,
            data_send,
            data_recv,
            client_ip,
            client_ip6,
            mut ice_disconnect_rx,
        } = params;
        let (mut tun_reader, mut tun_writer) = tun_device
            .split()
            .map_err(|e| VpnIceError::Tun(e.to_string()))?;
        let buffer_size = tun_reader.buffer_size();

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_SIZE);

        // Writer task
        let mut writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let mut data_send = data_send;
            while let Some(data) = outbound_rx.recv().await {
                if let Err(e) = data_send.write_all(&data).await {
                    log::warn!("QUIC write error: {}", e);
                    return Some(format!("QUIC write error: {}", e));
                }
            }
            None
        });

        // Heartbeat tracking
        let start_time = Instant::now();
        let last_ping = Arc::new(AtomicU64::new(start_time.elapsed().as_millis() as u64));
        let last_ping_inbound = last_ping.clone();
        let last_ping_heartbeat = last_ping.clone();

        // Inbound task (QUIC -> TUN)
        // Filter packets to only those destined for this client
        let inbound_short_id = short_id.clone();
        let outbound_tx_pong = outbound_tx.clone();
        let inbound_client_ip = client_ip;
        let inbound_client_ip6 = client_ip6;
        let inbound_disable_spoofing_check = self.config.disable_spoofing_check;
        let mut inbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            const MAX_TUN_WRITE_FAILURES: u32 = 10;
            let mut data_recv = data_recv;
            let mut type_buf = [0u8; 1];
            let mut len_buf = [0u8; 4];
            let mut data_buf = uninitialized_vec(MAX_IP_PACKET_SIZE);
            let data_slice = unsafe { as_mut_byte_slice(&mut data_buf) };
            let mut consecutive_tun_failures = 0u32;
            let inbound_start_time = start_time;

            loop {
                match data_recv.read_exact(&mut type_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::info!("[{}] Client disconnected: {}", inbound_short_id, e);
                        return Some(format!("Client disconnected: {}", e));
                    }
                }

                let msg_type = match DataMessageType::from_byte(type_buf[0]) {
                    Some(t) => t,
                    None => {
                        log::error!("[{}] Unknown message type: 0x{:02x}", inbound_short_id, type_buf[0]);
                        return Some(format!("Unknown message type: 0x{:02x}", type_buf[0]));
                    }
                };

                match msg_type {
                    DataMessageType::HeartbeatPing => {
                        let now = inbound_start_time.elapsed().as_millis() as u64;
                        last_ping_inbound.store(now, Ordering::Relaxed);
                        // Send Pong
                        let pong = Bytes::copy_from_slice(&[DataMessageType::HeartbeatPong.as_byte()]);
                        if outbound_tx_pong.send(pong).await.is_err() {
                            return Some("Failed to send Pong".to_string());
                        }
                        continue;
                    }
                    DataMessageType::HeartbeatPong => {
                        continue;
                    }
                    DataMessageType::IpPacket => {}
                }

                match data_recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("[{}] Failed to read length: {}", inbound_short_id, e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_IP_PACKET_SIZE {
                    log::error!("[{}] Packet too large: {}", inbound_short_id, len);
                    return Some(format!("Packet too large: {}", len));
                }

                match data_recv.read_exact(&mut data_slice[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("[{}] Failed to read packet: {}", inbound_short_id, e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }

                let packet = &data_slice[..len];
                if !inbound_disable_spoofing_check {
                    match extract_source_ip(packet) {
                        Some(IpAddr::V4(src)) => {
                            if inbound_client_ip != Some(src) {
                                log::warn!(
                                    "[{}] Dropping spoofed IPv4 packet: source {} not assigned",
                                    inbound_short_id,
                                    src
                                );
                                continue;
                            }
                        }
                        Some(IpAddr::V6(src)) => {
                            if inbound_client_ip6 != Some(src) {
                                log::warn!(
                                    "[{}] Dropping spoofed IPv6 packet: source {} not assigned",
                                    inbound_short_id,
                                    src
                                );
                                continue;
                            }
                        }
                        None => {
                            log::warn!(
                                "[{}] Dropping packet with unparseable IP header",
                                inbound_short_id
                            );
                            continue;
                        }
                    }
                }
                if let Err(e) = tun_writer.write_all(packet).await {
                    consecutive_tun_failures += 1;
                    if consecutive_tun_failures >= MAX_TUN_WRITE_FAILURES {
                        log::error!("[{}] Too many TUN write failures: {}", inbound_short_id, e);
                        return Some(format!("TUN write failures: {}", e));
                    }
                    log::warn!("[{}] TUN write error: {}", inbound_short_id, e);
                } else {
                    consecutive_tun_failures = 0;
                }
            }
        });

        // Outbound task (TUN -> QUIC)
        // Filter packets from this client's IP
        let outbound_short_id = short_id.clone();
        let outbound_tx_clone = outbound_tx.clone();
        let mut outbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let mut read_buf = uninitialized_vec(buffer_size);
            let read_slice = unsafe { as_mut_byte_slice(&mut read_buf) };
            loop {
                match tun_reader.read(read_slice).await {
                    Ok(n) if n > 0 => {
                        let packet = &read_slice[..n];

                        // Check if this packet is destined for our client
                        let should_send = match (client_ip, client_ip6) {
                            (Some(ip4), Some(ip6)) => {
                                is_packet_for_ip(packet, ip4) || is_packet_for_ipv6(packet, ip6)
                            }
                            (Some(ip4), None) => is_packet_for_ip(packet, ip4),
                            (None, Some(ip6)) => is_packet_for_ipv6(packet, ip6),
                            (None, None) => false,
                        };

                        if !should_send {
                            continue;
                        }

                        let frame_size = 1 + 4 + n;
                        let mut write_buf = BytesMut::with_capacity(frame_size);
                        if let Err(e) = frame_ip_packet(&mut write_buf, packet) {
                            log::warn!("[{}] Failed to frame packet: {}", outbound_short_id, e);
                            continue;
                        }
                        let bytes = write_buf.freeze();
                        if outbound_tx_clone.send(bytes).await.is_err() {
                            return None;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("[{}] TUN read error: {}", outbound_short_id, e);
                        return Some(format!("TUN read error: {}", e));
                    }
                }
            }
        });

        // Heartbeat checker task (send pong in response to ping, check for timeout)
        let heartbeat_short_id = short_id.clone();
        let mut heartbeat_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let heartbeat_start = start_time;
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;

                let now_ms = heartbeat_start.elapsed().as_millis() as u64;
                let last_ping_ms = last_ping_heartbeat.load(Ordering::Relaxed);
                let elapsed_ms = now_ms.saturating_sub(last_ping_ms);

                // Only timeout if we've been running for a while and haven't received pings
                if now_ms > HEARTBEAT_TIMEOUT.as_millis() as u64
                    && elapsed_ms > HEARTBEAT_TIMEOUT.as_millis() as u64
                {
                    log::error!(
                        "[{}] Heartbeat timeout: no ping for {:.1}s",
                        heartbeat_short_id,
                        elapsed_ms as f64 / 1000.0
                    );
                    return Some(format!("Heartbeat timeout: {:.1}s", elapsed_ms as f64 / 1000.0));
                }
            }
        });

        // ICE disconnect watcher
        let ice_short_id = short_id.clone();
        let mut ice_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            loop {
                if ice_disconnect_rx.changed().await.is_ok() {
                    if *ice_disconnect_rx.borrow() {
                        log::warn!("[{}] ICE disconnected", ice_short_id);
                        return Some("ICE disconnected".to_string());
                    }
                } else {
                    log::warn!("[{}] ICE watcher closed", ice_short_id);
                    return Some("ICE watcher closed".to_string());
                }
            }
        });

        // Wait for any task to complete
        let result = tokio::select! {
            r = &mut inbound_handle => ("inbound", r),
            r = &mut outbound_handle => ("outbound", r),
            r = &mut writer_handle => ("writer", r),
            r = &mut heartbeat_handle => ("heartbeat", r),
            r = &mut ice_handle => ("ice", r),
        };

        // Abort all tasks
        inbound_handle.abort();
        outbound_handle.abort();
        writer_handle.abort();
        heartbeat_handle.abort();
        ice_handle.abort();

        let reason = match result.1 {
            Ok(Some(r)) => r,
            Ok(None) => format!("{} task ended", result.0),
            Err(e) if e.is_cancelled() => format!("{} cancelled", result.0),
            Err(e) => format!("{} failed: {}", result.0, e),
        };

        log::debug!("[{}] VPN loop ended: {}", short_id, reason);
        Err(VpnIceError::Internal(format!("Connection ended: {}", reason)))
    }
}

struct RunVpnLoopParams {
    short_id: String,
    tun_device: TunDevice,
    data_send: quinn::SendStream,
    data_recv: quinn::RecvStream,
    client_ip: Option<Ipv4Addr>,
    client_ip6: Option<Ipv6Addr>,
    ice_disconnect_rx: tokio::sync::watch::Receiver<bool>,
}

fn default_server_ip4(net: Ipv4Net) -> Ipv4Addr {
    net.hosts().next().unwrap_or_else(|| net.network())
}

fn default_server_ip6(net: Ipv6Net) -> Ipv6Addr {
    let base = net.network();
    if net.prefix_len() == 128 {
        return base;
    }
    let segments = base.segments();
    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7].saturating_add(1),
    )
}

fn extract_source_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => Ipv4HeaderSlice::from_slice(packet)
            .ok()
            .map(|hdr| IpAddr::V4(hdr.source_addr())),
        6 => Ipv6HeaderSlice::from_slice(packet)
            .ok()
            .map(|hdr| IpAddr::V6(hdr.source_addr())),
        _ => None,
    }
}

/// Result of VPN handshake.
struct HandshakeResult {
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip6: Option<Ipv6Addr>,
}

/// Check if an IP packet is destined for the given IPv4 address.
fn is_packet_for_ip(packet: &[u8], client_ip: Ipv4Addr) -> bool {
    if packet.is_empty() || (packet[0] >> 4) != 4 {
        return false;
    }
    let (header, _) = match Ipv4Header::from_slice(packet) {
        Ok(value) => value,
        Err(_) => return false,
    };
    header.destination == client_ip.octets()
}

/// Check if an IP packet is destined for the given IPv6 address.
fn is_packet_for_ipv6(packet: &[u8], client_ip: Ipv6Addr) -> bool {
    if packet.is_empty() || (packet[0] >> 4) != 6 {
        return false;
    }
    let (header, _) = match Ipv6Header::from_slice(packet) {
        Ok(value) => value,
        Err(_) => return false,
    };
    header.destination == client_ip.octets()
}
