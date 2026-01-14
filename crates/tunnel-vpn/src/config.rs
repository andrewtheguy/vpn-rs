//! VPN configuration types.

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Default MTU for VPN tunnel (1500 - 60 bytes overhead for QUIC/TLS + framing).
pub const DEFAULT_MTU: u16 = 1440;

/// VPN server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnServerConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24").
    /// Server gets .1 by default, clients get subsequent addresses.
    pub network: Ipv4Net,

    /// IPv6 VPN network CIDR (e.g., "fd00::/64"). Optional for dual-stack.
    /// Server gets ::1 by default, clients get subsequent addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network6: Option<Ipv6Net>,

    /// Server's VPN IP address (defaults to first host in network, e.g., .1).
    pub server_ip: Option<Ipv4Addr>,

    /// Server's IPv6 VPN address (defaults to first host in network6, e.g., ::1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip6: Option<Ipv6Addr>,

    /// MTU for the TUN device.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Maximum number of connected clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Valid authentication tokens (clients must provide one to connect).
    /// Uses tunnel-auth format (i + 16 chars + checksum).
    #[serde(default)]
    pub auth_tokens: Option<HashSet<String>>,

    /// Whether to drop packets when a client's send buffer is full.
    ///
    /// When `true`: drops packets for slow clients instead of blocking,
    /// preventing one slow client from affecting packet delivery to other clients.
    /// Best for real-time traffic (VoIP, gaming) where latency matters more than
    /// guaranteed delivery.
    ///
    /// When `false` (default): applies backpressure by awaiting the send, which blocks the
    /// TUN reader and delays packets to all clients until the slow client's buffer
    /// has space. Best for bulk transfers where packet loss is unacceptable.
    #[serde(default = "default_drop_on_full")]
    pub drop_on_full: bool,

    /// Channel buffer size for outbound packets to each client (default: 1024).
    ///
    /// Controls how many packets can be queued for each client before backpressure
    /// or packet drops occur (depending on `drop_on_full` setting).
    ///
    /// **Tradeoffs:**
    /// - **Higher values (e.g., 2048-4096):** Better burst handling and throughput,
    ///   but increases memory usage per client and adds latency under congestion.
    ///   At 1 Gbps with 1500-byte packets, a 4096-packet buffer adds ~50ms latency.
    /// - **Lower values (e.g., 256-512):** Lower memory footprint and latency,
    ///   but may cause more packet drops or backpressure during traffic bursts.
    ///
    /// **Memory impact:** `client_channel_size * max_clients * ~1500 bytes`
    /// - Default (1024 * 254 clients): ~370 MB worst case
    /// - Conservative (256 * 254 clients): ~93 MB worst case
    ///
    /// **Recommendations:**
    /// - High-bandwidth server with few clients: 2048-4096
    /// - Many clients with limited memory: 256-512
    /// - Balanced default: 1024
    #[serde(default = "default_client_channel_size")]
    pub client_channel_size: usize,

    /// Channel buffer size for TUN writer task (default: 512).
    ///
    /// This is the aggregate buffer for all client -> TUN traffic. Since all
    /// clients share this channel, it should be larger than per-client buffers.
    ///
    /// **Tradeoffs:**
    /// - **Higher values (e.g., 2048-4096):** Better burst absorption from multiple clients,
    ///   prevents TUN write backpressure from affecting individual clients, but risks
    ///   high memory usage if TUN writes stall (~4096 * 1500 bytes = ~6MB).
    /// - **Lower values (e.g., 256-512):** Faster backpressure propagation to clients,
    ///   bounded memory usage, but may cause more backpressure during bursts.
    ///
    /// **Memory impact:** `tun_writer_channel_size * ~1500 bytes`
    /// - Default (512): ~750 KB worst case
    /// - High (4096): ~6 MB worst case
    ///
    /// **Recommendation:** 512 is a safe default for memory-constrained hosts.
    /// Increase to 2048-4096 for high-bandwidth servers with many active clients.
    #[serde(default = "default_tun_writer_channel_size")]
    pub tun_writer_channel_size: usize,
}

/// VPN client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnClientConfig {
    /// Server's iroh node ID.
    pub server_node_id: String,

    /// Authentication token (tunnel-auth format).
    pub auth_token: Option<String>,

    /// MTU for the TUN device.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// IPv4 routes to send through the VPN (CIDRs).
    /// At least one route is required (e.g., 0.0.0.0/0 for full tunnel).
    pub routes: Vec<Ipv4Net>,

    /// IPv6 routes to send through the VPN (CIDRs). Optional for dual-stack.
    #[serde(default)]
    pub routes6: Vec<Ipv6Net>,
}

impl Default for VpnClientConfig {
    fn default() -> Self {
        Self {
            server_node_id: String::new(),
            auth_token: None,
            mtu: DEFAULT_MTU,
            routes: vec![],
            routes6: vec![],
        }
    }
}

/// Combined VPN configuration (for config file).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role")]
pub enum VpnConfig {
    /// Server configuration.
    #[serde(rename = "server")]
    Server(VpnServerConfig),

    /// Client configuration.
    #[serde(rename = "client")]
    Client(VpnClientConfig),
}

// Default value functions for serde
fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_max_clients() -> usize {
    254
}

fn default_drop_on_full() -> bool {
    false
}

fn default_client_channel_size() -> usize {
    1024
}

fn default_tun_writer_channel_size() -> usize {
    512
}
