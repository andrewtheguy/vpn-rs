//! VPN client implementation using ICE/Nostr transport.
//!
//! The VPN client connects to a VPN server via ICE+QUIC with Nostr signaling,
//! performs VPN handshake to receive IP assignment, configures the TUN device,
//! and manages the IP-over-QUIC tunnel.

use crate::config::VpnIceClientConfig;
use crate::error::{VpnIceError, VpnIceResult};
use bytes::{Bytes, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use quinn::{RecvStream, SendStream};
use tunnel_ice::signaling::{
    ManualAnswer, ManualOffer, ManualRequest, NostrSignaling, OfferWaitError, MANUAL_SIGNAL_VERSION,
};
use tunnel_ice::transport::ice::{IceEndpoint, IceRole};
use tunnel_ice::transport::quic;
use tunnel_ice::tunnel_common::{current_timestamp, generate_session_id};
use tunnel_vpn::buffer::{as_mut_byte_slice, uninitialized_vec};
use tunnel_vpn::device::{
    add_routes, add_routes6_with_src, Route6Guard, RouteGuard, TunConfig, TunDevice,
};
use tunnel_vpn::lock::VpnLock;
use tunnel_vpn::signaling::{
    frame_ip_packet, read_message, write_message, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, HEARTBEAT_PING_BYTE, MAX_HANDSHAKE_SIZE,
};

/// Maximum IP packet size (MTU + overhead).
const MAX_IP_PACKET_SIZE: usize = 65536;

/// Heartbeat ping interval (how often client sends ping).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Heartbeat timeout (max time to wait for pong before triggering reconnection).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for outbound packets.
const OUTBOUND_CHANNEL_SIZE: usize = 1024;

/// QUIC connection timeout.
const QUIC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// VPN client using ICE/Nostr transport.
pub struct VpnIceClient {
    /// Client configuration.
    config: VpnIceClientConfig,
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
}

impl VpnIceClient {
    /// Create a new VPN ICE client.
    ///
    /// Acquires a single-instance lock (only one VPN client per process) and
    /// generates a random `device_id` (u64) for session identification.
    pub fn new(config: VpnIceClientConfig) -> VpnIceResult<Self> {
        // Acquire single-instance lock
        let lock = VpnLock::acquire().map_err(|e| VpnIceError::Lock(e.to_string()))?;

        // Generate random device ID (unique per session)
        let device_id: u64 = rand::thread_rng().gen();
        log::info!("Generated device ID: {:016x}", device_id);

        Ok(Self {
            config,
            device_id,
            _lock: lock,
        })
    }

    /// Connect to the VPN server and establish the tunnel.
    pub async fn connect(&self) -> VpnIceResult<()> {
        // Ensure crypto provider is installed
        quic::ensure_crypto_provider();

        let nsec = self.config.get_nsec()?;

        log::info!("VPN ICE Client - Nostr Mode");
        log::info!("===========================");

        // Initialize Nostr signaling
        let relay_list = if self.config.relays.is_some() {
            self.config.relays.clone()
        } else {
            None
        };
        let signaling = NostrSignaling::new(&nsec, &self.config.peer_npub, relay_list)
            .await
            .map_err(|e| VpnIceError::Signaling(e.to_string()))?;

        log::info!("Your pubkey: {}", signaling.public_key_bech32());
        log::info!("Transfer ID: {}", signaling.transfer_id());
        log::info!("Relays: {:?}", signaling.relay_urls());

        signaling
            .subscribe()
            .await
            .map_err(|e| VpnIceError::Signaling(e.to_string()))?;

        // Generate session ID
        let session_id = generate_session_id();
        log::info!("Session ID: {}", session_id);

        // Gather ICE candidates
        log::info!("Gathering ICE candidates...");
        let ice = IceEndpoint::gather(&self.config.stun_servers)
            .await
            .map_err(|e| VpnIceError::Ice(e.to_string()))?;
        let local_creds = ice.local_credentials();
        let local_candidates = ice.local_candidates();
        log::info!("Gathered {} ICE candidate(s)", local_candidates.len());

        // Create VPN request (use source field to indicate VPN mode)
        let request = ManualRequest {
            version: MANUAL_SIGNAL_VERSION,
            ice_ufrag: local_creds.ufrag.clone(),
            ice_pwd: local_creds.pass.clone(),
            candidates: local_candidates.clone(),
            session_id: session_id.clone(),
            timestamp: current_timestamp(),
            source: Some("vpn://connect".to_string()), // VPN mode indicator
        };

        // Publish request and wait for offer
        let offer = self
            .publish_request_and_wait_for_offer(&signaling, &request)
            .await?;

        if offer.version != MANUAL_SIGNAL_VERSION {
            return Err(VpnIceError::Signaling(format!(
                "Version mismatch (expected {}, got {})",
                MANUAL_SIGNAL_VERSION, offer.version
            )));
        }

        // Create and publish answer
        let answer = ManualAnswer {
            version: MANUAL_SIGNAL_VERSION,
            ice_ufrag: local_creds.ufrag.clone(),
            ice_pwd: local_creds.pass.clone(),
            candidates: local_candidates,
            session_id: Some(session_id),
            quic_fingerprint: None, // Nostr mode: fingerprint is in the offer
        };

        signaling
            .publish_answer(&answer)
            .await
            .map_err(|e| VpnIceError::Signaling(e.to_string()))?;
        log::info!("Published answer, starting ICE...");

        // Disconnect from Nostr in background
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            signaling.disconnect().await;
            log::debug!("Nostr signaling disconnected");
        });

        // ICE connectivity
        let remote_creds = str0m::IceCreds {
            ufrag: offer.ice_ufrag,
            pass: offer.ice_pwd,
        };

        let ice_conn = ice
            .connect(IceRole::Controlled, remote_creds, offer.candidates)
            .await
            .map_err(|e| VpnIceError::Ice(e.to_string()))?;

        log::info!(
            "ICE connected: -> {}",
            ice_conn.remote_addr
        );

        // Spawn ICE keeper
        let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
        let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

        // Connect QUIC
        let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)
            .map_err(|e| VpnIceError::Quic(e.to_string()))?;

        log::info!(
            "Connecting to server via QUIC (timeout: {:?})...",
            QUIC_CONNECTION_TIMEOUT
        );

        let connecting = endpoint
            .connect(ice_conn.remote_addr, "vpn-ice")
            .map_err(|e| VpnIceError::Quic(format!("Failed to start QUIC connection: {}", e)))?;

        let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
            .await
            .map_err(|_| VpnIceError::Timeout("QUIC connection timeout".to_string()))?
            .map_err(|e| VpnIceError::Quic(format!("Failed to connect: {}", e)))?;

        log::info!("QUIC connected to server");

        // Perform VPN handshake
        let server_info = self.perform_handshake(&conn).await?;

        log::info!("VPN handshake successful:");
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

        // Create TUN device
        let tun_device = self.create_tun_device(&server_info)?;

        // Add routes
        let _route_guard: Option<RouteGuard> =
            if server_info.assigned_ip.is_some() && !self.config.routes.is_empty() {
                Some(
                    add_routes(tun_device.name(), &self.config.routes)
                        .await
                        .map_err(|e| VpnIceError::Tun(e.to_string()))?,
                )
            } else {
                None
            };

        let _route6_guard: Option<Route6Guard> =
            if let Some(assigned_ip6) = server_info.assigned_ip6 {
                if !self.config.routes6.is_empty() {
                    Some(
                        add_routes6_with_src(tun_device.name(), &self.config.routes6, assigned_ip6)
                            .await
                            .map_err(|e| VpnIceError::Tun(e.to_string()))?,
                    )
                } else {
                    None
                }
            } else {
                None
            };

        // Open data stream
        let (data_send, data_recv): (SendStream, RecvStream) = conn
            .open_bi()
            .await
            .map_err(|e| VpnIceError::Quic(format!("Failed to open data stream: {}", e)))?;

        log::info!("VPN tunnel established!");
        log::info!("  TUN device: {}", tun_device.name());
        if let Some(ip) = server_info.assigned_ip {
            log::info!("  Client IP: {}", ip);
        }
        if let Some(ip6) = server_info.assigned_ip6 {
            log::info!("  Client IPv6: {}", ip6);
        }

        // Run VPN loop with ICE disconnect monitoring
        let result =
            self.run_vpn_loop(tun_device, data_send, data_recv, ice_disconnect_rx.clone());

        // Wait for either VPN loop to end or ICE to disconnect
        tokio::select! {
            res = result => {
                ice_keeper_handle.abort();
                res
            }
            _ = async {
                loop {
                    if ice_disconnect_rx.changed().await.is_ok() {
                        if *ice_disconnect_rx.borrow() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } => {
                ice_keeper_handle.abort();
                Err(VpnIceError::Ice("ICE disconnected".to_string()))
            }
        }
    }

    /// Publish request and wait for offer with periodic re-publishing.
    async fn publish_request_and_wait_for_offer(
        &self,
        signaling: &NostrSignaling,
        request: &ManualRequest,
    ) -> VpnIceResult<ManualOffer> {
        const REPUBLISH_INTERVAL_SECS: u64 = 5;
        const MAX_WAIT_SECS: u64 = 120;
        const MAX_INTERVAL: u64 = 60;

        let start_time = Instant::now();
        let session_id = &request.session_id;
        let mut current_interval = REPUBLISH_INTERVAL_SECS;

        signaling
            .publish_request(request)
            .await
            .map_err(|e| VpnIceError::Signaling(e.to_string()))?;

        log::info!(
            "Waiting for offer (re-publishing every {}s, max {}s)...",
            REPUBLISH_INTERVAL_SECS,
            MAX_WAIT_SECS
        );

        loop {
            match signaling
                .try_wait_for_offer_or_rejection(session_id, current_interval)
                .await
            {
                Ok(Some(offer)) => return Ok(offer),
                Err(OfferWaitError::Rejected(reject)) => {
                    return Err(VpnIceError::Rejected(reject.reason));
                }
                Err(OfferWaitError::ChannelClosed) => {
                    return Err(VpnIceError::Signaling(
                        "Nostr channel closed while waiting for offer".to_string(),
                    ));
                }
                Ok(None) => {
                    // Timeout - continue
                }
            }

            if start_time.elapsed().as_secs() >= MAX_WAIT_SECS {
                return Err(VpnIceError::Timeout(format!(
                    "Timeout waiting for offer ({}s)",
                    MAX_WAIT_SECS
                )));
            }

            let next_interval = (current_interval * 2).min(MAX_INTERVAL);
            log::info!("Re-publishing request (next wait: {}s)...", next_interval);
            signaling
                .publish_request(request)
                .await
                .map_err(|e| VpnIceError::Signaling(e.to_string()))?;
            current_interval = next_interval;
        }
    }

    /// Perform VPN handshake with the server.
    async fn perform_handshake(
        &self,
        connection: &quinn::Connection,
    ) -> VpnIceResult<ServerInfo> {
        let (mut send, mut recv): (SendStream, RecvStream) = connection
            .open_bi()
            .await
            .map_err(|e| VpnIceError::Quic(format!("Failed to open stream: {}", e)))?;

        // Send handshake (no auth token for nostr mode - npub is the auth)
        let handshake = VpnHandshake::new(self.device_id);
        write_message::<SendStream>(&mut send, &handshake.encode()?)
            .await
            .map_err(|e| VpnIceError::Handshake(e.to_string()))?;

        // Read response
        let response_data = read_message(&mut recv, MAX_HANDSHAKE_SIZE)
            .await
            .map_err(|e| VpnIceError::Handshake(e.to_string()))?;
        let response = VpnHandshakeResponse::decode(&response_data)?;

        if !response.accepted {
            let reason = response
                .reject_reason
                .unwrap_or_else(|| "Unknown".to_string());
            return Err(VpnIceError::Rejected(reason));
        }

        // Extract IPv4/IPv6 info
        let (assigned_ip, network, server_ip) = match (
            response.assigned_ip,
            response.network,
            response.server_ip,
        ) {
            (Some(ip), Some(net), Some(gw)) => (Some(ip), Some(net), Some(gw)),
            (None, None, None) => (None, None, None),
            _ => {
                return Err(VpnIceError::Handshake(
                    "Incomplete IPv4 configuration".to_string(),
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
                return Err(VpnIceError::Handshake(
                    "Incomplete IPv6 configuration".to_string(),
                ));
            }
        };

        if assigned_ip.is_none() && assigned_ip6.is_none() {
            return Err(VpnIceError::Handshake(
                "Server provided no IP configuration".to_string(),
            ));
        }

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
        })
    }

    /// Create and configure the TUN device.
    fn create_tun_device(&self, server_info: &ServerInfo) -> VpnIceResult<TunDevice> {
        let tun_config = match (
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
                    .with_mtu(self.config.mtu)
                    .with_ipv6(ip6, net6.prefix_len())
                    .map_err(|e| VpnIceError::Tun(e.to_string()))?
            }
            // IPv4-only
            (Some(ip4), Some(net4), Some(gw4), None, None, None) => {
                TunConfig::new(ip4, net4.netmask(), gw4).with_mtu(self.config.mtu)
            }
            // IPv6-only
            (None, None, None, Some(ip6), Some(net6), Some(_gw6)) => {
                TunConfig::ipv6_only(ip6, net6.prefix_len(), self.config.mtu)
                    .map_err(|e| VpnIceError::Tun(e.to_string()))?
            }
            _ => {
                return Err(VpnIceError::Tun(
                    "Invalid server info: need at least one complete IP configuration".to_string(),
                ))
            }
        };

        TunDevice::create(tun_config).map_err(|e| VpnIceError::Tun(e.to_string()))
    }

    /// Run the VPN packet processing loop.
    async fn run_vpn_loop(
        &self,
        tun_device: TunDevice,
        data_send: quinn::SendStream,
        data_recv: quinn::RecvStream,
        _ice_disconnect_rx: tokio::sync::watch::Receiver<bool>,
    ) -> VpnIceResult<()> {
        let (mut tun_reader, mut tun_writer) = tun_device
            .split()
            .map_err(|e| VpnIceError::Tun(e.to_string()))?;
        let buffer_size = tun_reader.buffer_size();

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_SIZE);
        let outbound_tx_heartbeat = outbound_tx.clone();

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
        let last_pong = Arc::new(AtomicU64::new(start_time.elapsed().as_millis() as u64));
        let last_pong_inbound = last_pong.clone();
        let last_pong_heartbeat = last_pong.clone();

        // Outbound task (TUN -> QUIC)
        let mut outbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let mut read_buf = uninitialized_vec(buffer_size);
            let read_slice = unsafe { as_mut_byte_slice(&mut read_buf) };
            loop {
                match tun_reader.read(read_slice).await {
                    Ok(n) if n > 0 => {
                        let packet = &read_slice[..n];
                        let frame_size = 1 + 4 + n;
                        let mut write_buf = BytesMut::with_capacity(frame_size);
                        if let Err(e) = frame_ip_packet(&mut write_buf, packet) {
                            log::warn!("Failed to frame packet: {}", e);
                            continue;
                        }
                        let bytes = write_buf.freeze();
                        if outbound_tx.send(bytes).await.is_err() {
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

        // Inbound task (QUIC -> TUN)
        let inbound_start_time = start_time;
        let mut inbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            const MAX_TUN_WRITE_FAILURES: u32 = 10;
            let mut data_recv = data_recv;
            let mut type_buf = [0u8; 1];
            let mut len_buf = [0u8; 4];
            let mut data_buf = uninitialized_vec(MAX_IP_PACKET_SIZE);
            let data_slice = unsafe { as_mut_byte_slice(&mut data_buf) };
            let mut consecutive_tun_failures = 0u32;

            loop {
                match data_recv.read_exact(&mut type_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("QUIC read error: {}", e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }

                let msg_type = match DataMessageType::from_byte(type_buf[0]) {
                    Some(t) => t,
                    None => {
                        log::error!("Unknown message type: 0x{:02x}", type_buf[0]);
                        return Some(format!("Unknown message type: 0x{:02x}", type_buf[0]));
                    }
                };

                match msg_type {
                    DataMessageType::HeartbeatPong => {
                        let now = inbound_start_time.elapsed().as_millis() as u64;
                        last_pong_inbound.store(now, Ordering::Relaxed);
                        continue;
                    }
                    DataMessageType::HeartbeatPing => {
                        continue;
                    }
                    DataMessageType::IpPacket => {}
                }

                match data_recv.read_exact(&mut len_buf).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read length: {}", e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_IP_PACKET_SIZE {
                    log::error!("Packet too large: {}", len);
                    return Some(format!("Packet too large: {}", len));
                }

                match data_recv.read_exact(&mut data_slice[..len]).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to read packet: {}", e);
                        return Some(format!("QUIC read error: {}", e));
                    }
                }

                let packet = &data_slice[..len];
                if let Err(e) = tun_writer.write_all(packet).await {
                    consecutive_tun_failures += 1;
                    if consecutive_tun_failures >= MAX_TUN_WRITE_FAILURES {
                        log::error!("Too many TUN write failures: {}", e);
                        return Some(format!("TUN write failures: {}", e));
                    }
                    log::warn!("TUN write error: {}", e);
                } else {
                    consecutive_tun_failures = 0;
                }
            }
        });

        // Heartbeat task
        let mut heartbeat_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
            let heartbeat_start = start_time;
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;

                let now_ms = heartbeat_start.elapsed().as_millis() as u64;
                let last_pong_ms = last_pong_heartbeat.load(Ordering::Relaxed);
                let elapsed_ms = now_ms.saturating_sub(last_pong_ms);

                if elapsed_ms > HEARTBEAT_TIMEOUT.as_millis() as u64 {
                    log::error!("Heartbeat timeout: no pong for {:.1}s", elapsed_ms as f64 / 1000.0);
                    return Some(format!("Heartbeat timeout: {:.1}s", elapsed_ms as f64 / 1000.0));
                }

                let ping = Bytes::from_static(HEARTBEAT_PING_BYTE);
                if outbound_tx_heartbeat.send(ping).await.is_err() {
                    return None;
                }
            }
        });

        // Wait for any task to complete
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

        // Abort remaining tasks
        for (_, handle) in &remaining {
            handle.abort();
        }

        // Collect results
        let mut reasons = Vec::new();
        match first_result {
            Ok(Some(reason)) => reasons.push(reason),
            Ok(None) => reasons.push(format!("{} task ended", first_task)),
            Err(e) if !e.is_cancelled() => reasons.push(format!("{} task failed: {}", first_task, e)),
            _ => {}
        }

        for (name, handle) in remaining {
            match handle.await {
                Ok(Some(reason)) => reasons.push(reason),
                Err(e) if !e.is_cancelled() => reasons.push(format!("{} task failed: {}", name, e)),
                _ => {}
            }
        }

        let reason = if reasons.is_empty() {
            "all tasks cancelled".to_string()
        } else {
            reasons.join("; ")
        };

        log::debug!("VPN loop ended: {}", reason);
        Err(VpnIceError::Internal(format!("Connection lost: {}", reason)))
    }
}
