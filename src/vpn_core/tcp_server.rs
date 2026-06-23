//! Multi-client TCP VPN server.
//!
//! Connection-oriented sibling of the UDP server ([`crate::vpn_core::server`]).
//! Where the UDP server multiplexes every client onto one loopback socket and
//! demultiplexes by source `SocketAddr`, this server accepts one TCP connection
//! per client and demultiplexes by connection. It shares the same multiplexing
//! machinery — IP pools, destination-IP routing, anti-spoofing, and an idle
//! reaper — and the same stream framing as the client's
//! [`run_tunnel`](crate::vpn_core::tunnel::run_tunnel) pipeline.
//!
//! ```text
//!  TUN ──(route by dest IP)──▶ per-connection outbound channel ──▶ TCP write
//!  TUN ◀──(shared TUN writer)── per-connection frame reader     ◀── TCP read
//! ```
//!
//! In production the listener is loopback-only (an external tunnel forwards the
//! connection and provides crypto/auth); test mode relaxes that and gates
//! clients on a shared token.

use crate::vpn_core::buffer::uninitialized_vec;
use crate::vpn_core::chunked_write::ChunkedWrite;
use crate::vpn_core::config::VpnServerConfig;
use crate::vpn_core::device::{TunConfig, TunDevice, TunOffloadStatus, TunReader};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::frame_reader::{FrameError, FrameEvent, FrameReader};
use crate::vpn_core::ip_pool::{Ip6Pool, IpPool};
use crate::vpn_core::offload::{
    materialize_offload_into, CoalescedOutput, TcpGroTable, VirtioNetHdr, VIRTIO_NET_HDR_LEN,
};
use crate::vpn_core::packet::{extract_dest_ip, extract_source_ip, PacketIp};
use crate::vpn_core::server::VpnServerStats;
use crate::vpn_core::signaling::{
    append_ip_packet_v2, parse_ip_packet_v2, write_message, CapabilitiesMessage, DataMessageType,
    VpnHandshake, VpnHandshakeResponse, HEARTBEAT_PONG_BYTE, MAX_CAPABILITIES_PAYLOAD,
    MAX_HANDSHAKE_SIZE,
};
use crate::vpn_core::tcp::prepare_stream;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, RwLock};

/// Maximum number of frames drained from a channel per batched write.
const WRITE_BATCH_SIZE: usize = 256;

/// Reserve granularity for the outbound framing arena.
const FRAME_ARENA_CHUNK: usize = 64 * 1024;

/// Maximum accepted inbound IP frame length (guards `FrameReader` allocation).
const MAX_IP_FRAME_SIZE: usize = 65536 + 64;

/// A decoded inbound packet queued for the shared TUN writer task.
struct TunWriteRequest {
    packet: Bytes,
    offload: Option<VirtioNetHdr>,
}

/// State for one connected TCP client (keyed by connection id).
///
/// The connection's device id and assigned addresses live with the connection
/// task (see [`Registration`]); this entry holds only what other tasks need to
/// reach into: the outbound channel, GSO flags, liveness, and the cancel handle.
struct ClientConn {
    /// Outbound channel to this connection's writer task (framed packets).
    outbound: mpsc::Sender<Bytes>,
    /// Reported client local GSO capability.
    client_gso_enabled: AtomicBool,
    /// Effective per-connection GSO mode (server local && client reported).
    connection_gso_active: AtomicBool,
    /// Last time any frame was received from this client (millis since start).
    last_seen: AtomicU64,
    /// Fired to tear the connection down (reconnect takeover or reaper).
    cancel: Arc<Notify>,
}

/// Multi-client TCP VPN server.
pub struct TcpVpnServer {
    config: VpnServerConfig,
    /// IPv4 address pool (None if IPv6-only mode).
    ip_pool: Option<Arc<RwLock<IpPool>>>,
    /// IPv6 address pool (None if IPv4-only mode).
    ip6_pool: Option<Arc<RwLock<Ip6Pool>>>,
    /// Connected clients keyed by connection id.
    clients: Arc<DashMap<u64, ClientConn>>,
    /// Index from device id to its current connection id.
    device_to_conn: Arc<DashMap<u64, u64>>,
    /// Reverse lookup: assigned IPv4 -> connection id.
    ip_to_conn: Arc<DashMap<Ipv4Addr, u64>>,
    /// Reverse lookup: assigned IPv6 -> connection id.
    ip6_to_conn: Arc<DashMap<Ipv6Addr, u64>>,
    /// Server-local TUN offload/GSO status.
    tun_offload_status: TunOffloadStatus,
    /// TUN device (taken in `run`).
    tun_device: Option<TunDevice>,
    /// Performance statistics.
    stats: Arc<VpnServerStats>,
    /// Monotonic base for `last_seen` timestamps.
    start_time: Instant,
    /// Monotonically increasing connection id allocator.
    next_conn_id: AtomicU64,
}

impl TcpVpnServer {
    /// Create a new TCP VPN server.
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

        Ok(Self {
            config,
            ip_pool,
            ip6_pool,
            clients: Arc::new(DashMap::new()),
            device_to_conn: Arc::new(DashMap::new()),
            ip_to_conn: Arc::new(DashMap::new()),
            ip6_to_conn: Arc::new(DashMap::new()),
            tun_offload_status: TunOffloadStatus::disabled("TUN not initialized"),
            tun_device: None,
            stats: Arc::new(VpnServerStats::new()),
            start_time: Instant::now(),
            next_conn_id: AtomicU64::new(1),
        })
    }

    /// Create and configure the shared TUN device (dual-stack aware).
    async fn setup_tun(&mut self) -> VpnResult<()> {
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
        log::info!("Created TUN device: {}", device.name());
        log::info!(
            "Server local TUN GSO status: enabled={}",
            self.tun_offload_status.enabled
        );
        self.tun_device = Some(device);
        Ok(())
    }

    /// Milliseconds since the server's monotonic start.
    fn now_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// Run the TCP VPN server on a bound listener.
    pub async fn run(mut self, listener: TcpListener) -> VpnResult<()> {
        self.setup_tun().await?;

        log::info!("TCP VPN Server started:");
        log::info!("  Listen (TCP): {}", listener.local_addr()?);
        log::info!(
            "  Mode: {}",
            match (self.ip_pool.is_some(), self.ip6_pool.is_some()) {
                (true, true) => "dual-stack (IPv4 + IPv6)",
                (true, false) => "IPv4-only",
                (false, true) => "IPv6-only",
                (false, false) => "none",
            }
        );

        let tun_device = self.tun_device.take().expect("TUN device not set up");
        let (tun_reader, tun_writer) = tun_device.split()?;

        // Shared TUN writer channel + task (clients -> TUN).
        let (tun_write_tx, tun_write_rx) =
            mpsc::channel::<TunWriteRequest>(self.config.tun_writer_channel_size);
        let tun_writer_stats = self.stats.clone();
        let tun_writer_handle =
            tokio::spawn(run_tun_writer(tun_writer, tun_write_rx, tun_writer_stats));

        let server = Arc::new(self);

        // Shared TUN reader task (TUN -> route -> per-connection outbound).
        let reader_server = server.clone();
        let tun_reader_handle = tokio::spawn(async move {
            reader_server.run_tun_reader(tun_reader).await;
        });

        // Idle reaper.
        let reaper_server = server.clone();
        let reaper_handle = tokio::spawn(async move {
            reaper_server.run_reaper().await;
        });

        // Accept loop.
        let run_result = loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::error!("TCP accept error: {}", e);
                    break Err(VpnError::Network(e));
                }
            };
            log::info!("Client connected from {}", peer);
            let conn_server = server.clone();
            let conn_tun_write_tx = tun_write_tx.clone();
            tokio::spawn(async move {
                conn_server.handle_connection(stream, conn_tun_write_tx).await;
            });
        };

        log::info!("Shutting down TCP server tasks...");
        reaper_handle.abort();
        tun_reader_handle.abort();
        drop(tun_write_tx);
        let _ = tun_writer_handle.await;
        log::info!("TCP server shutdown complete");

        run_result
    }

    /// Drive one accepted connection: handshake, register, then pump frames
    /// until the stream ends or the connection is torn down.
    async fn handle_connection(
        self: Arc<Self>,
        stream: TcpStream,
        tun_write_tx: mpsc::Sender<TunWriteRequest>,
    ) {
        prepare_stream(
            &stream,
            self.config.recv_buffer_size,
            self.config.send_buffer_size,
        );
        let (mut read_half, mut write_half) = stream.into_split();

        // Read the client handshake (length-prefixed).
        let hs_data = match crate::vpn_core::signaling::read_message(
            &mut read_half,
            MAX_HANDSHAKE_SIZE,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                log::debug!("Failed to read handshake: {}", e);
                return;
            }
        };
        let handshake = match VpnHandshake::decode(&hs_data) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("Ignoring bad handshake: {}", e);
                return;
            }
        };

        // Register (allocate IPs, send response). On rejection, the response is
        // sent and the connection closed.
        let Some(reg) = self.register_client(handshake, &mut write_half).await else {
            return;
        };
        let Registration {
            conn_id,
            device_id,
            assigned_ip,
            assigned_ip6,
            outbound_tx,
            mut outbound_rx,
            cancel,
        } = reg;

        // The client's capabilities message is the first data-stream message.
        match read_client_capabilities(&mut read_half).await {
            Ok(caps) => {
                if let Some(c) = self.clients.get(&conn_id) {
                    c.client_gso_enabled.store(caps.gso_enabled, Ordering::Relaxed);
                    c.connection_gso_active.store(
                        self.tun_offload_status.enabled && caps.gso_enabled,
                        Ordering::Relaxed,
                    );
                }
                log::debug!(
                    "Client (device {:016x}) capabilities: gso={}",
                    device_id,
                    caps.gso_enabled
                );
            }
            Err(e) => {
                log::warn!("Failed to read client capabilities: {}", e);
                self.cleanup_conn(conn_id, device_id, assigned_ip, assigned_ip6)
                    .await;
                return;
            }
        }

        // Spawn the per-connection writer task (outbound channel -> TCP write).
        let mut writer_handle = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(WRITE_BATCH_SIZE);
            loop {
                let count = outbound_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
                if count == 0 {
                    break;
                }
                if let Err(e) = write_half.write_all_chunks(batch.as_mut_slice()).await {
                    log::warn!("conn {} write error: {}", conn_id, e);
                    break;
                }
                batch.clear();
            }
        });

        let reader = FrameReader::new(read_half, MAX_IP_FRAME_SIZE);
        let pong_tx = outbound_tx.clone();

        // Run until the stream closes, the writer dies, or we are torn down.
        tokio::select! {
            _ = self.run_conn_reader(conn_id, reader, &tun_write_tx, &pong_tx) => {}
            _ = &mut writer_handle => {}
            _ = cancel.notified() => {
                log::debug!("conn {} torn down (reconnect or reaped)", conn_id);
            }
        }

        writer_handle.abort();
        self.cleanup_conn(conn_id, device_id, assigned_ip, assigned_ip6)
            .await;
        log::info!("Client (device {:016x}) disconnected", device_id);
    }

    /// Apply the test-mode token gate, allocate IPs, register routing entries,
    /// and send the handshake response. Returns the registration on success.
    async fn register_client(
        &self,
        handshake: VpnHandshake,
        write_half: &mut OwnedWriteHalf,
    ) -> Option<Registration> {
        // Test-mode token gate (also enforces test/non-test mutual exclusion).
        if self.config.test_token != handshake.test_token {
            log::warn!("Rejecting handshake: test token mismatch");
            self.send_response(
                write_half,
                VpnHandshakeResponse::rejected("test token mismatch", self.tun_offload_status.enabled),
            )
            .await;
            return None;
        }

        let device_id = handshake.device_id;
        let existing_conn = self.device_to_conn.get(&device_id).map(|r| *r);
        let is_new_client = existing_conn.is_none();

        if is_new_client && self.device_to_conn.len() >= self.config.max_clients {
            self.send_response(
                write_half,
                VpnHandshakeResponse::rejected("Server full", self.tun_offload_status.enabled),
            )
            .await;
            return None;
        }

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
                write_half,
                VpnHandshakeResponse::rejected(
                    "All IP pools exhausted",
                    self.tun_offload_status.enabled,
                ),
            )
            .await;
            return None;
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
                )
            }
            (None, None) => unreachable!("rejected above when both pools are empty"),
        };

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (outbound_tx, outbound_rx) =
            mpsc::channel::<Bytes>(self.config.client_channel_size);
        let cancel = Arc::new(Notify::new());

        // Point routing at the new connection BEFORE tearing down any old one,
        // so the old connection's cleanup (which is guarded by `remove_if` /
        // current-connection checks) never clobbers the new entries or releases
        // the still-in-use IP.
        let now = self.now_ms();
        self.clients.insert(
            conn_id,
            ClientConn {
                outbound: outbound_tx.clone(),
                client_gso_enabled: AtomicBool::new(false),
                connection_gso_active: AtomicBool::new(false),
                last_seen: AtomicU64::new(now),
                cancel: cancel.clone(),
            },
        );
        self.device_to_conn.insert(device_id, conn_id);
        if let Some(ip4) = assigned_ip {
            self.ip_to_conn.insert(ip4, conn_id);
        }
        if let Some(ip6) = assigned_ip6 {
            self.ip6_to_conn.insert(ip6, conn_id);
        }

        // Reconnect/move: signal the previous connection to tear down. The IP
        // stays allocated to the device (idempotent `allocate` above returned
        // the same address).
        if let Some(old_conn_id) = existing_conn
            && old_conn_id != conn_id
            && let Some(old) = self.clients.get(&old_conn_id)
        {
            old.cancel.notify_one();
        }

        self.send_response(write_half, response).await;
        log::info!(
            "Client (device {:016x}) connected: conn={} ip={:?} ip6={:?}",
            device_id,
            conn_id,
            assigned_ip,
            assigned_ip6
        );

        Some(Registration {
            conn_id,
            device_id,
            assigned_ip,
            assigned_ip6,
            outbound_tx,
            outbound_rx,
            cancel,
        })
    }

    /// Encode and send a handshake response on the connection's write half.
    async fn send_response(&self, write_half: &mut OwnedWriteHalf, response: VpnHandshakeResponse) {
        match response.encode() {
            Ok(bytes) => {
                if let Err(e) = write_message(write_half, &bytes).await {
                    log::warn!("Failed to send handshake response: {}", e);
                }
            }
            Err(e) => log::error!("Failed to encode handshake response: {}", e),
        }
    }

    /// Read frames from one connection: forward IP packets to the shared TUN
    /// writer (with anti-spoofing), reply to pings, and absorb capabilities.
    /// Returns when the stream closes or errors.
    async fn run_conn_reader(
        &self,
        conn_id: u64,
        mut reader: FrameReader<OwnedReadHalf>,
        tun_write_tx: &mpsc::Sender<TunWriteRequest>,
        pong_tx: &mpsc::Sender<Bytes>,
    ) {
        let local_gso_enabled = self.tun_offload_status.enabled;
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut seg_arena = BytesMut::new();
        let mut pending_segments: Vec<Bytes> = Vec::new();

        loop {
            let frame = match reader.next_frame().await {
                Ok(Some(FrameEvent::IpFrame(frame))) => frame,
                Ok(Some(FrameEvent::HeartbeatPing)) => {
                    self.bump_last_seen(conn_id);
                    if pong_tx
                        .send(Bytes::from_static(HEARTBEAT_PONG_BYTE))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                Ok(Some(FrameEvent::HeartbeatPong)) => {
                    self.bump_last_seen(conn_id);
                    continue;
                }
                Ok(Some(FrameEvent::Capabilities)) => {
                    // Capabilities are exchanged once at setup; ignore later ones.
                    continue;
                }
                Ok(None) => {
                    log::debug!("conn {} closed by peer", conn_id);
                    return;
                }
                Err(FrameError::Read(e)) => {
                    log::debug!("conn {} read ended: {}", conn_id, e);
                    return;
                }
                Err(e) => {
                    log::warn!("conn {} framing error: {}", conn_id, e);
                    return;
                }
            };

            self.bump_last_seen(conn_id);

            let (offload, packet) = match parse_ip_packet_v2(&frame) {
                Ok(parts) => parts,
                Err(e) => {
                    log::warn!("conn {} invalid IP frame: {}", conn_id, e);
                    continue;
                }
            };

            // Anti-spoofing: reject a source IP owned by a different client.
            if !self.config.disable_spoofing_check && !self.source_ip_allowed(conn_id, packet) {
                self.stats.packets_spoofed.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            if let Some(meta) = offload {
                if !local_gso_enabled {
                    pending_segments.clear();
                    let materialized =
                        materialize_offload_into(&meta, packet, &mut seg_scratch, |seg| {
                            seg_arena.extend_from_slice(seg);
                            pending_segments.push(seg_arena.split_to(seg.len()).freeze());
                            Ok(())
                        });
                    if let Err(e) = materialized {
                        pending_segments.clear();
                        log::warn!("conn {} dropping unsupported offload: {}", conn_id, e);
                        continue;
                    }
                    for packet in pending_segments.drain(..) {
                        if !self
                            .enqueue_tun_write(tun_write_tx, TunWriteRequest { packet, offload: None })
                            .await
                        {
                            return;
                        }
                    }
                } else {
                    let req = TunWriteRequest {
                        packet: frame.slice_ref(packet),
                        offload: Some(meta),
                    };
                    if !self.enqueue_tun_write(tun_write_tx, req).await {
                        return;
                    }
                }
            } else {
                let req = TunWriteRequest {
                    packet: frame.slice_ref(packet),
                    offload: None,
                };
                if !self.enqueue_tun_write(tun_write_tx, req).await {
                    return;
                }
            }
        }
    }

    /// Update a connection's liveness timestamp.
    fn bump_last_seen(&self, conn_id: u64) {
        if let Some(c) = self.clients.get(&conn_id) {
            c.last_seen.store(self.now_ms(), Ordering::Relaxed);
        }
    }

    /// Whether `packet`'s source IP is allowed from connection `conn_id`.
    ///
    /// A non-VPN source IP is allowed; a VPN-assigned IP is allowed only if it
    /// belongs to `conn_id`. Link-local IPv6 is always dropped.
    fn source_ip_allowed(&self, conn_id: u64, packet: &[u8]) -> bool {
        match extract_source_ip(packet) {
            Some(PacketIp::V4(src)) => match self.ip_to_conn.get(&src) {
                Some(owner) if *owner == conn_id => true,
                Some(_) => {
                    log::warn!("IPv4 spoofing on conn {}: source {} owned by another client", conn_id, src);
                    false
                }
                None => true,
            },
            Some(PacketIp::V6(src)) => {
                let o = src.octets();
                if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                    return false; // link-local, not routable across the VPN
                }
                match self.ip6_to_conn.get(&src) {
                    Some(owner) if *owner == conn_id => true,
                    Some(_) => {
                        log::warn!("IPv6 spoofing on conn {}: source {} owned by another client", conn_id, src);
                        false
                    }
                    None => true,
                }
            }
            None => {
                log::warn!("Failed to parse source IP on conn {}", conn_id);
                false
            }
        }
    }

    /// Enqueue a TUN write request, applying backpressure. Returns false if the
    /// TUN writer channel is gone.
    async fn enqueue_tun_write(
        &self,
        tun_write_tx: &mpsc::Sender<TunWriteRequest>,
        req: TunWriteRequest,
    ) -> bool {
        match tun_write_tx.try_send(req) {
            Ok(()) => {
                self.stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Full(req)) => {
                if tun_write_tx.send(req).await.is_ok() {
                    self.stats.packets_from_clients.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    self.stats.packets_tun_write_failed.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.packets_tun_write_failed.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Read packets from the shared TUN, route by destination IP, frame, and
    /// enqueue to the owning connection's outbound channel.
    async fn run_tun_reader(self: Arc<Self>, mut tun_reader: TunReader) {
        log::info!("TUN reader started");
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
        let mut gro_states: HashMap<u64, TcpGroTable> = HashMap::new();

        let mut packet_buf = ReadBuf::uninit(&mut read_storage);
        loop {
            packet_buf.clear();
            let gro_pending = software_gro && gro_states.values().any(|t| !t.is_empty());
            let read_result = if gro_pending {
                match tun_reader.try_read_buf(&mut packet_buf) {
                    Some(read_result) => read_result,
                    None => {
                        self.flush_gro_states(&mut gro_states, &mut arena, &mut pending, drop_on_full)
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
                    self.flush_gro_states(&mut gro_states, &mut arena, &mut pending, drop_on_full)
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

            let conn_id = match extract_dest_ip(packet_ref) {
                Some(PacketIp::V4(dest_ip)) => match self.ip_to_conn.get(&dest_ip).map(|r| *r) {
                    Some(c) => c,
                    None => {
                        self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                },
                Some(PacketIp::V6(dest_ip)) => match self.ip6_to_conn.get(&dest_ip).map(|r| *r) {
                    Some(c) => c,
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

            let (client_gso_enabled, connection_gso_active, outbound) = match self.clients.get(&conn_id) {
                Some(c) => (
                    c.client_gso_enabled.load(Ordering::Relaxed),
                    c.connection_gso_active.load(Ordering::Relaxed),
                    c.outbound.clone(),
                ),
                None => {
                    self.stats.packets_no_route.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            if software_gro && client_gso_enabled {
                let table = gro_states.entry(conn_id).or_default();
                let result = table.push(packet_ref);
                if !result.outputs.is_empty() {
                    pending.clear();
                    if build_gro_frames(&mut arena, &mut pending, &result.outputs).is_ok() {
                        for f in pending.drain(..) {
                            enqueue_frame(&outbound, f, &self.stats, drop_on_full).await;
                        }
                    }
                }
                if !result.pass_through {
                    continue;
                }
                // Pass-through frames carry no offload metadata.
            }

            pending.clear();
            if build_frames(&mut arena, &mut seg_scratch, &mut pending, offload.as_ref(), packet_ref, connection_gso_active)
                .is_ok()
            {
                for f in pending.drain(..) {
                    enqueue_frame(&outbound, f, &self.stats, drop_on_full).await;
                }
            }
        }
    }

    /// Drain all per-connection software-GRO tables and evict gone connections.
    async fn flush_gro_states(
        &self,
        gro_states: &mut HashMap<u64, TcpGroTable>,
        arena: &mut BytesMut,
        pending: &mut Vec<Bytes>,
        drop_on_full: bool,
    ) {
        for (conn_id, table) in gro_states.iter_mut() {
            let outputs = table.flush_all();
            if outputs.is_empty() {
                continue;
            }
            let Some(outbound) = self.clients.get(conn_id).map(|c| c.outbound.clone()) else {
                continue;
            };
            pending.clear();
            if build_gro_frames(arena, pending, &outputs).is_ok() {
                for f in pending.drain(..) {
                    enqueue_frame(&outbound, f, &self.stats, drop_on_full).await;
                }
            }
        }
        gro_states.retain(|conn_id, _| self.clients.contains_key(conn_id));
    }

    /// Periodically tear down connections that have gone silent.
    async fn run_reaper(self: Arc<Self>) {
        let timeout_ms = self.config.client_timeout.as_millis() as u64;
        let interval = (self.config.client_timeout / 2).max(Duration::from_secs(5));
        loop {
            tokio::time::sleep(interval).await;
            let now = self.now_ms();
            let stale: Vec<Arc<Notify>> = self
                .clients
                .iter()
                .filter(|e| now.saturating_sub(e.last_seen.load(Ordering::Relaxed)) > timeout_ms)
                .map(|e| e.cancel.clone())
                .collect();
            for cancel in stale {
                cancel.notify_one();
            }
        }
    }

    /// Remove a connection's routing entries and release its IPs, but only if it
    /// is still the current connection for its device (a reconnect may have
    /// taken over).
    async fn cleanup_conn(
        &self,
        conn_id: u64,
        device_id: u64,
        assigned_ip: Option<Ipv4Addr>,
        assigned_ip6: Option<Ipv6Addr>,
    ) {
        let is_current = self
            .device_to_conn
            .get(&device_id)
            .map(|r| *r == conn_id)
            .unwrap_or(false);
        self.clients.remove(&conn_id);
        if !is_current {
            return; // a newer connection owns this device now
        }
        self.device_to_conn.remove_if(&device_id, |_, c| *c == conn_id);
        if let Some(ip) = assigned_ip {
            self.ip_to_conn.remove_if(&ip, |_, c| *c == conn_id);
            if let Some(ref pool) = self.ip_pool {
                pool.write().await.release(device_id);
            }
        }
        if let Some(ip6) = assigned_ip6 {
            self.ip6_to_conn.remove_if(&ip6, |_, c| *c == conn_id);
            if let Some(ref pool) = self.ip6_pool {
                pool.write().await.release(device_id);
            }
        }
    }
}

/// Per-connection registration handed from `register_client` to the connection
/// task (the receiver half is owned by the writer task).
struct Registration {
    conn_id: u64,
    device_id: u64,
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip6: Option<Ipv6Addr>,
    outbound_tx: mpsc::Sender<Bytes>,
    outbound_rx: mpsc::Receiver<Bytes>,
    cancel: Arc<Notify>,
}

/// Shared TUN writer task (clients -> TUN), coalescing consecutive plain
/// packets into GSO super-frames where the kernel supports it.
async fn run_tun_writer(
    mut tun_writer: crate::vpn_core::device::TunWriter,
    mut tun_write_rx: mpsc::Receiver<TunWriteRequest>,
    stats: Arc<VpnServerStats>,
) {
    log::info!("TUN writer task started");
    let mut batch = Vec::with_capacity(WRITE_BATCH_SIZE);
    let mut plain_run: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
    let log_write_error = |e: VpnError| {
        stats.packets_tun_write_failed.fetch_add(1, Ordering::Relaxed);
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
}

/// Append one stream frame (type + length-prefixed) to `arena`, splitting it off
/// as a `Bytes` view appended to `pending`.
fn append_frame(
    arena: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    pending: &mut Vec<Bytes>,
) -> VpnResult<()> {
    let frame_size = 1 + 4 + 1 + offload.map(|_| VIRTIO_NET_HDR_LEN).unwrap_or(0) + packet.len();
    if arena.capacity() - arena.len() < frame_size {
        arena.reserve(FRAME_ARENA_CHUNK.max(frame_size));
    }
    let written = append_ip_packet_v2(arena, offload, packet)?;
    pending.push(arena.split_to(written).freeze());
    Ok(())
}

/// Frame a TUN packet for the stream transport, segmenting an offload super-frame
/// into individual frames when the connection did not negotiate GSO.
fn build_frames(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    connection_gso_active: bool,
) -> VpnResult<()> {
    if let Some(meta) = offload {
        if connection_gso_active {
            append_frame(arena, Some(meta), packet, pending)
        } else {
            materialize_offload_into(meta, packet, seg_scratch, |seg| {
                append_frame(arena, None, seg, pending).map_err(|e| e.to_string())
            })
            .map_err(VpnError::Signaling)
        }
    } else {
        append_frame(arena, None, packet, pending)
    }
}

/// Frame software-GRO outputs (coalesced offload super-frames or plain packets).
fn build_gro_frames(
    arena: &mut BytesMut,
    pending: &mut Vec<Bytes>,
    outputs: &[CoalescedOutput],
) -> VpnResult<()> {
    for output in outputs {
        let (offload, packet): (Option<&VirtioNetHdr>, &[u8]) = match output {
            CoalescedOutput::Coalesced(hdr, packet) => (Some(hdr), packet.as_slice()),
            CoalescedOutput::Single(packet) => (None, packet.as_slice()),
        };
        append_frame(arena, offload, packet, pending)?;
    }
    Ok(())
}

/// Enqueue a framed packet for a connection's writer task, applying
/// drop-on-full / backpressure policy.
async fn enqueue_frame(
    outbound: &mpsc::Sender<Bytes>,
    frame: Bytes,
    stats: &Arc<VpnServerStats>,
    drop_on_full: bool,
) {
    match outbound.try_send(frame) {
        Ok(()) => {
            stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
        }
        Err(mpsc::error::TrySendError::Full(item)) => {
            if drop_on_full {
                stats.packets_dropped_full.fetch_add(1, Ordering::Relaxed);
            } else {
                stats.packets_backpressure.fetch_add(1, Ordering::Relaxed);
                if outbound.send(item).await.is_ok() {
                    stats.packets_to_clients.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

/// Read and decode the client's first data-stream message, which must be a
/// capabilities message: `[type=0x03][len:u8][payload]`.
async fn read_client_capabilities<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> VpnResult<CapabilitiesMessage> {
    let mut type_byte = [0u8; 1];
    reader.read_exact(&mut type_byte).await?;
    if DataMessageType::from_byte(type_byte[0]) != Some(DataMessageType::Capabilities) {
        return Err(VpnError::Signaling(format!(
            "expected capabilities as first data message, got type 0x{:02x}",
            type_byte[0]
        )));
    }

    let mut len_buf = [0u8; 1];
    reader.read_exact(&mut len_buf).await?;
    let len = usize::from(len_buf[0]);
    if len > MAX_CAPABILITIES_PAYLOAD {
        return Err(VpnError::Signaling(format!(
            "capabilities payload too large: {}",
            len
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(CapabilitiesMessage::decode_payload(&payload))
}
