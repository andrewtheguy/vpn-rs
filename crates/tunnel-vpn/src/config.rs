//! VPN configuration types.

use crate::keys::WgPublicKey;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Default VPN network (10.0.0.0/24).
pub const DEFAULT_VPN_NETWORK: &str = "10.0.0.0/24";

/// Default WireGuard listen port.
pub const DEFAULT_WG_PORT: u16 = 51820;

/// Default MTU for WireGuard (1500 - 80 bytes overhead).
pub const DEFAULT_WG_MTU: u16 = 1420;

/// Default keepalive interval in seconds.
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;

/// VPN server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnServerConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24").
    /// Server gets .1 by default, clients get subsequent addresses.
    #[serde(default = "default_vpn_network")]
    pub network: Ipv4Net,

    /// Server's VPN IP address (defaults to first host in network, e.g., .1).
    pub server_ip: Option<Ipv4Addr>,

    /// WireGuard UDP listen port.
    #[serde(default = "default_wg_port")]
    pub wg_port: u16,

    /// MTU for the TUN device.
    #[serde(default = "default_wg_mtu")]
    pub mtu: u16,

    /// Path to private key file (optional, generates if not specified).
    pub private_key_file: Option<PathBuf>,

    /// WireGuard keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u16,

    /// Maximum number of connected clients.
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    /// Enable IP forwarding / NAT for internet access.
    #[serde(default)]
    pub enable_nat: bool,

    /// Valid authentication tokens (clients must provide one to connect).
    /// Uses tunnel-auth format (i + 16 chars + checksum).
    #[serde(default)]
    pub auth_tokens: Option<HashSet<String>>,
}

impl Default for VpnServerConfig {
    fn default() -> Self {
        Self {
            network: default_vpn_network(),
            server_ip: None, // Defaults to first host in network
            wg_port: DEFAULT_WG_PORT,
            mtu: DEFAULT_WG_MTU,
            private_key_file: None,
            keepalive_secs: DEFAULT_KEEPALIVE_SECS,
            max_clients: 254, // /24 network
            enable_nat: false,
            auth_tokens: None,
        }
    }
}

/// VPN client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnClientConfig {
    /// Server's iroh node ID.
    pub server_node_id: String,

    /// Authentication token (tunnel-auth format).
    pub auth_token: Option<String>,

    /// MTU for the TUN device.
    #[serde(default = "default_wg_mtu")]
    pub mtu: u16,

    /// WireGuard keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u16,

    /// Routes to send through the VPN (CIDRs).
    /// Empty = route all traffic (full tunnel).
    #[serde(default)]
    pub routes: Vec<Ipv4Net>,

    /// DNS servers to use when connected.
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
}

impl Default for VpnClientConfig {
    fn default() -> Self {
        Self {
            server_node_id: String::new(),
            auth_token: None,
            mtu: DEFAULT_WG_MTU,
            keepalive_secs: DEFAULT_KEEPALIVE_SECS,
            routes: vec![],
            dns_servers: vec![],
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

/// Peer information exchanged via signaling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnPeerInfo {
    /// WireGuard public key.
    pub wg_public_key: WgPublicKey,

    /// Direct UDP endpoint (if known via ICE/discovery).
    pub endpoint: Option<SocketAddr>,

    /// Assigned VPN IP address (server → client).
    pub assigned_ip: Option<Ipv4Addr>,

    /// Allowed IPs for this peer (what traffic to route through tunnel).
    #[serde(default)]
    pub allowed_ips: Vec<Ipv4Net>,
}

// Default value functions for serde
fn default_vpn_network() -> Ipv4Net {
    DEFAULT_VPN_NETWORK.parse().unwrap()
}

fn default_wg_port() -> u16 {
    DEFAULT_WG_PORT
}

fn default_wg_mtu() -> u16 {
    DEFAULT_WG_MTU
}

fn default_keepalive() -> u16 {
    DEFAULT_KEEPALIVE_SECS
}

fn default_max_clients() -> usize {
    254
}
