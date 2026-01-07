//! WireGuard tunnel using boringtun.
//!
//! This module wraps boringtun's `Tunn` struct to provide a higher-level
//! API for WireGuard encryption and decryption.

use crate::error::{VpnError, VpnResult};
use crate::keys::WgKeyPair;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::PublicKey;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Default buffer size for WireGuard packets.
pub const WG_BUFFER_SIZE: usize = 2048;

/// Result of processing a packet through the tunnel.
#[derive(Debug)]
pub enum PacketResult {
    /// No action needed.
    Done,
    /// Send encrypted packet to network.
    WriteToNetwork(Vec<u8>),
    /// Write decrypted packet to TUN device (IPv4).
    WriteToTunV4(Vec<u8>, IpAddr),
    /// Write decrypted packet to TUN device (IPv6).
    WriteToTunV6(Vec<u8>, IpAddr),
    /// An error occurred.
    Error(String),
}

/// A WireGuard tunnel wrapping boringtun.
pub struct WgTunnel {
    /// The inner boringtun tunnel.
    inner: Tunn,
    /// Our keypair.
    keypair: WgKeyPair,
    /// Peer's public key.
    peer_public_key: PublicKey,
    /// Peer's endpoint (UDP address).
    peer_endpoint: Option<SocketAddr>,
    /// Reusable buffer for packet processing.
    buf: Vec<u8>,
}

impl WgTunnel {
    /// Create a new WireGuard tunnel.
    ///
    /// # Arguments
    /// * `keypair` - Our WireGuard keypair
    /// * `peer_public_key` - Peer's public key
    /// * `keepalive_secs` - Optional persistent keepalive interval
    pub fn new(
        keypair: WgKeyPair,
        peer_public_key: PublicKey,
        keepalive_secs: Option<u16>,
    ) -> VpnResult<Self> {
        let inner = Tunn::new(
            keypair.private_key().clone(),
            peer_public_key,
            None,             // preshared_key
            keepalive_secs,   // persistent_keepalive
            0,                // index
            None,             // rate_limiter
        )
        .map_err(|e| VpnError::WireGuard(format!("Failed to create tunnel: {}", e)))?;

        Ok(Self {
            inner,
            keypair,
            peer_public_key,
            peer_endpoint: None,
            buf: vec![0u8; WG_BUFFER_SIZE],
        })
    }

    /// Set the peer's endpoint address.
    pub fn set_peer_endpoint(&mut self, endpoint: SocketAddr) {
        self.peer_endpoint = Some(endpoint);
    }

    /// Get the peer's endpoint address.
    pub fn peer_endpoint(&self) -> Option<SocketAddr> {
        self.peer_endpoint
    }

    /// Get our public key.
    pub fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }

    /// Get the peer's public key.
    pub fn peer_public_key(&self) -> &PublicKey {
        &self.peer_public_key
    }

    /// Encapsulate an IP packet for sending through the tunnel.
    ///
    /// Returns the encrypted WireGuard packet to send to the peer.
    pub fn encapsulate(&mut self, ip_packet: &[u8]) -> VpnResult<PacketResult> {
        match self.inner.encapsulate(ip_packet, &mut self.buf) {
            TunnResult::Done => Ok(PacketResult::Done),
            TunnResult::WriteToNetwork(data) => {
                Ok(PacketResult::WriteToNetwork(data.to_vec()))
            }
            TunnResult::WriteToTunnelV4(_, _) => {
                // WriteToTunnel variants should never occur during encapsulation
                // (encryption produces network packets, not tunnel packets)
                Ok(PacketResult::Done)
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                // WriteToTunnel variants should never occur during encapsulation
                Ok(PacketResult::Done)
            }
            TunnResult::Err(e) => Err(VpnError::WireGuard(format!(
                "Encapsulation failed: {:?}",
                e
            ))),
        }
    }

    /// Decapsulate a WireGuard packet received from the network.
    ///
    /// Returns the decrypted IP packet (if any) to write to the TUN device.
    pub fn decapsulate(
        &mut self,
        src_addr: Option<IpAddr>,
        wg_packet: &[u8],
    ) -> VpnResult<PacketResult> {
        match self.inner.decapsulate(src_addr, wg_packet, &mut self.buf) {
            TunnResult::Done => Ok(PacketResult::Done),
            TunnResult::WriteToNetwork(data) => {
                Ok(PacketResult::WriteToNetwork(data.to_vec()))
            }
            TunnResult::WriteToTunnelV4(data, addr) => {
                Ok(PacketResult::WriteToTunV4(data.to_vec(), IpAddr::V4(addr)))
            }
            TunnResult::WriteToTunnelV6(data, addr) => {
                Ok(PacketResult::WriteToTunV6(data.to_vec(), IpAddr::V6(addr)))
            }
            TunnResult::Err(e) => Err(VpnError::WireGuard(format!(
                "Decapsulation failed: {:?}",
                e
            ))),
        }
    }

    /// Process pending timers and return any packets that need to be sent.
    ///
    /// This should be called periodically (e.g., every 100ms) to handle
    /// keepalives, handshake timeouts, etc.
    pub fn update_timers(&mut self) -> Vec<PacketResult> {
        let mut results = Vec::new();

        loop {
            match self.inner.update_timers(&mut self.buf) {
                TunnResult::Done => break,
                TunnResult::WriteToNetwork(data) => {
                    // Copy data out before next iteration reuses the buffer
                    results.push(PacketResult::WriteToNetwork(data.to_vec()));
                }
                TunnResult::WriteToTunnelV4(_, _) => {
                    // WriteToTunnel variants should never occur during timer updates
                    // (timers produce keepalives/handshakes, not decrypted packets)
                    break;
                }
                TunnResult::WriteToTunnelV6(_, _) => {
                    // WriteToTunnel variants should never occur during timer updates
                    break;
                }
                TunnResult::Err(e) => {
                    results.push(PacketResult::Error(format!("Timer error: {:?}", e)));
                    break;
                }
            }
        }

        results
    }

    /// Get the current time-to-next-timer duration.
    pub fn time_to_next_timer(&self) -> Duration {
        // boringtun's Tunn doesn't expose this directly, so we use a conservative default
        Duration::from_millis(100)
    }
}

/// Builder for creating WgTunnel instances.
pub struct WgTunnelBuilder {
    keypair: Option<WgKeyPair>,
    peer_public_key: Option<PublicKey>,
    peer_endpoint: Option<SocketAddr>,
    keepalive_secs: Option<u16>,
}

impl WgTunnelBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            keypair: None,
            peer_public_key: None,
            peer_endpoint: None,
            keepalive_secs: Some(25), // Default keepalive
        }
    }

    /// Set our keypair.
    pub fn keypair(mut self, keypair: WgKeyPair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set the peer's public key.
    pub fn peer_public_key(mut self, key: PublicKey) -> Self {
        self.peer_public_key = Some(key);
        self
    }

    /// Set the peer's endpoint.
    pub fn peer_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.peer_endpoint = Some(endpoint);
        self
    }

    /// Set the keepalive interval.
    pub fn keepalive_secs(mut self, secs: Option<u16>) -> Self {
        self.keepalive_secs = secs;
        self
    }

    /// Build the tunnel.
    pub fn build(self) -> VpnResult<WgTunnel> {
        let keypair = self
            .keypair
            .ok_or_else(|| VpnError::Config("Keypair is required".into()))?;
        let peer_public_key = self
            .peer_public_key
            .ok_or_else(|| VpnError::Config("Peer public key is required".into()))?;

        let mut tunnel = WgTunnel::new(keypair, peer_public_key, self.keepalive_secs)?;

        if let Some(endpoint) = self.peer_endpoint {
            tunnel.set_peer_endpoint(endpoint);
        }

        Ok(tunnel)
    }
}

impl Default for WgTunnelBuilder {
    fn default() -> Self {
        Self::new()
    }
}
