//! VPN configuration types.

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Default MTU for VPN tunnel (1500 - 80 bytes overhead for QUIC/TLS).
pub const DEFAULT_MTU: u16 = 1420;

/// Default keepalive interval in seconds.
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;

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

    /// Keepalive/heartbeat interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u16,

    /// Maximum number of connected clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Valid authentication tokens (clients must provide one to connect).
    /// Uses tunnel-auth format (i + 16 chars + checksum).
    #[serde(default)]
    pub auth_tokens: Option<HashSet<String>>,
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

    /// Keepalive/heartbeat interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u16,

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
            keepalive_secs: DEFAULT_KEEPALIVE_SECS,
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

fn default_keepalive() -> u16 {
    DEFAULT_KEEPALIVE_SECS
}

fn default_max_clients() -> usize {
    254
}
