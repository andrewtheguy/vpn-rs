//! Packet processing utilities for VPN traffic.
//!
//! This module provides the main packet processing loop that coordinates
//! reading from TUN, encrypting via WireGuard, and sending over UDP.

use crate::device::{TunReader, TunWriter};
use crate::error::{VpnError, VpnResult};
use crate::tunnel::{PacketResult, WgTunnel};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::interval;

/// Maximum WireGuard packet size (MTU + WireGuard overhead).
/// Standard MTU (1500) + WireGuard transport overhead (~60 bytes for safety).
const MAX_PACKET_SIZE: usize = 1560;

/// Timer interval for WireGuard keepalives and handshakes.
const TIMER_INTERVAL: Duration = Duration::from_millis(100);

/// Packet processor that handles the TUN ↔ WireGuard ↔ UDP flow.
pub struct PacketProcessor {
    /// WireGuard tunnel (wrapped in Arc<Mutex> for shared access).
    tunnel: Arc<Mutex<WgTunnel>>,
    /// UDP socket for WireGuard traffic.
    socket: Arc<UdpSocket>,
    /// Peer's endpoint address.
    peer_endpoint: SocketAddr,
}

impl PacketProcessor {
    /// Create a new packet processor.
    pub fn new(tunnel: WgTunnel, socket: UdpSocket, peer_endpoint: SocketAddr) -> Self {
        Self {
            tunnel: Arc::new(Mutex::new(tunnel)),
            socket: Arc::new(socket),
            peer_endpoint,
        }
    }

    /// Run the outbound packet processing loop (TUN → WireGuard → UDP).
    ///
    /// Reads IP packets from the TUN device, encrypts them via WireGuard,
    /// and sends them to the peer over UDP.
    pub async fn run_outbound(&self, mut tun_reader: TunReader) -> VpnResult<()> {
        let mut buf = vec![0u8; tun_reader.buffer_size()];

        loop {
            let len = tun_reader.read(&mut buf).await?;
            if len == 0 {
                continue;
            }

            let ip_packet = &buf[..len];
            let mut tunnel = self.tunnel.lock().await;

            match tunnel.encapsulate(ip_packet)? {
                PacketResult::WriteToNetwork(data) => {
                    self.socket.send_to(&data, self.peer_endpoint).await?;
                }
                PacketResult::Done => {}
                PacketResult::Error(e) => {
                    log::warn!("Outbound packet error: {}", e);
                }
                _ => {}
            }
        }
    }

    /// Run the inbound packet processing loop (UDP → WireGuard → TUN).
    ///
    /// Receives WireGuard packets from UDP, decrypts them,
    /// and writes the IP packets to the TUN device.
    pub async fn run_inbound(&self, mut tun_writer: TunWriter) -> VpnResult<()> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            let (len, src_addr) = self.socket.recv_from(&mut buf).await?;
            if len == 0 {
                continue;
            }

            let wg_packet = &buf[..len];
            let mut tunnel = self.tunnel.lock().await;

            match tunnel.decapsulate(Some(src_addr.ip()), wg_packet)? {
                PacketResult::WriteToTunV4(data, _) | PacketResult::WriteToTunV6(data, _) => {
                    tun_writer.write_all(&data).await?;
                }
                PacketResult::WriteToNetwork(data) => {
                    // Response packet (e.g., handshake response)
                    drop(tunnel); // Release lock before async send
                    self.socket.send_to(&data, self.peer_endpoint).await?;
                }
                PacketResult::Done => {}
                PacketResult::Error(e) => {
                    log::warn!("Inbound packet error: {}", e);
                }
            }
        }
    }

    /// Run the timer processing loop.
    ///
    /// Periodically processes WireGuard timers for keepalives and handshakes.
    pub async fn run_timers(&self) -> VpnResult<()> {
        let mut timer = interval(TIMER_INTERVAL);

        loop {
            timer.tick().await;

            let mut tunnel = self.tunnel.lock().await;
            let results = tunnel.update_timers();
            drop(tunnel); // Release lock before async operations

            for result in results {
                match result {
                    PacketResult::WriteToNetwork(data) => {
                        self.socket.send_to(&data, self.peer_endpoint).await?;
                    }
                    PacketResult::Error(e) => {
                        log::warn!("Timer error: {}", e);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Get a reference to the tunnel.
    pub fn tunnel(&self) -> &Arc<Mutex<WgTunnel>> {
        &self.tunnel
    }

    /// Get a reference to the UDP socket.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

/// Run the complete VPN packet processing.
///
/// This spawns three tasks:
/// 1. Outbound: TUN → WireGuard → UDP
/// 2. Inbound: UDP → WireGuard → TUN
/// 3. Timers: WireGuard keepalives and handshakes
pub async fn run_vpn_loop(
    tunnel: WgTunnel,
    socket: UdpSocket,
    peer_endpoint: SocketAddr,
    tun_reader: TunReader,
    tun_writer: TunWriter,
) -> VpnResult<()> {
    let processor = Arc::new(PacketProcessor::new(tunnel, socket, peer_endpoint));

    let outbound = {
        let proc = processor.clone();
        tokio::spawn(async move { proc.run_outbound(tun_reader).await })
    };

    let inbound = {
        let proc = processor.clone();
        tokio::spawn(async move { proc.run_inbound(tun_writer).await })
    };

    let timers = {
        let proc = processor.clone();
        tokio::spawn(async move { proc.run_timers().await })
    };

    // Wait for any task to complete (or fail)
    tokio::select! {
        res = outbound => {
            handle_join_result(res, "outbound")?;
        }
        res = inbound => {
            handle_join_result(res, "inbound")?;
        }
        res = timers => {
            handle_join_result(res, "timers")?;
        }
    }

    Ok(())
}

/// Handle a JoinResult, propagating panics and converting other errors.
fn handle_join_result(
    res: Result<VpnResult<()>, tokio::task::JoinError>,
    task_name: &str,
) -> VpnResult<()> {
    match res {
        Ok(inner) => inner,
        Err(e) if e.is_panic() => {
            // Propagate panics from spawned tasks
            std::panic::resume_unwind(e.into_panic())
        }
        Err(e) => {
            // Task was cancelled or other non-panic error
            Err(VpnError::Network(std::io::Error::other(format!(
                "{} task failed: {}",
                task_name, e
            ))))
        }
    }
}
