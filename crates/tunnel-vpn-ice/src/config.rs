//! Configuration types for VPN ICE mode.

use crate::error::VpnIceError;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Default MTU for VPN tunnel.
pub const DEFAULT_MTU: u16 = 1420;

/// Default STUN servers.
pub fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun.services.mozilla.com:3478".to_string(),
    ]
}

/// VPN server configuration for ICE/Nostr mode.
#[derive(Clone, Serialize, Deserialize)]
pub struct VpnIceServerConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24"). Optional for IPv6-only mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Ipv4Net>,

    /// IPv6 VPN network CIDR (e.g., "fd00::/64"). Optional for dual-stack or IPv6-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network6: Option<Ipv6Net>,

    /// Server's VPN IP address (defaults to first host in network, e.g., .1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

    /// Nostr private key (nsec format).
    /// Use only one of `nsec` or `nsec_file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,

    /// Path to file containing Nostr private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec_file: Option<PathBuf>,

    /// Authorized client's Nostr public key (npub format).
    /// Currently supports single-peer VPN connections.
    pub peer_npub: String,

    /// Nostr relay URLs for signaling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,

    /// STUN server addresses for ICE.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,

    /// NAT64 configuration (optional, for IPv6-only with IPv4 access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat64: Option<tunnel_vpn::config::Nat64Config>,

    /// Disable inter-client IP spoofing checks (default: false).
    ///
    /// When `false` (default): The server rejects packets whose source IP does not
    /// match the assigned client address. This prevents a client from spoofing.
    ///
    /// When `true`: All source IP validation is disabled. Any source IP is accepted,
    /// which may allow clients to spoof other clients' addresses. Use with caution.
    #[serde(default)]
    pub disable_spoofing_check: bool,
}

impl fmt::Debug for VpnIceServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nsec = self.nsec.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("VpnIceServerConfig")
            .field("network", &self.network)
            .field("network6", &self.network6)
            .field("server_ip", &self.server_ip)
            .field("server_ip6", &self.server_ip6)
            .field("mtu", &self.mtu)
            .field("max_clients", &self.max_clients)
            .field("nsec", &nsec)
            .field("nsec_file", &self.nsec_file)
            .field("peer_npub", &self.peer_npub)
            .field("relays", &self.relays)
            .field("stun_servers", &self.stun_servers)
            .field("nat64", &self.nat64)
            .field("disable_spoofing_check", &self.disable_spoofing_check)
            .finish()
    }
}

impl VpnIceServerConfig {
    /// Validate the VPN server configuration.
    pub fn validate(&self) -> Result<(), String> {
        // At least one network must be configured
        if self.network.is_none() && self.network6.is_none() {
            return Err(
                "At least one of 'network' (IPv4) or 'network6' (IPv6) must be configured"
                    .to_string(),
            );
        }

        // server_ip requires network
        if self.server_ip.is_some() && self.network.is_none() {
            return Err("'server_ip' requires 'network' to be set".to_string());
        }

        // server_ip6 requires network6
        if self.server_ip6.is_some() && self.network6.is_none() {
            return Err("'server_ip6' requires 'network6' to be set".to_string());
        }

        if let Some(network) = self.network {
            if network.prefix_len() > 30 {
                return Err(format!(
                    "'network' {} is too small; IPv4 networks must be /30 or larger",
                    network
                ));
            }

            let server_ip = self.server_ip.unwrap_or_else(|| default_server_ip4(network));
            if !network.contains(&server_ip) {
                return Err(format!(
                    "'server_ip' {} is not within 'network' {}",
                    server_ip, network
                ));
            }
            if server_ip == network.network() || server_ip == network.broadcast() {
                return Err(format!(
                    "'server_ip' {} cannot be the network or broadcast address for 'network' {}",
                    server_ip, network
                ));
            }

            let capacity = ipv4_client_capacity(network, server_ip);
            if capacity == 0 {
                return Err(format!(
                    "'network' {} has no usable client IPv4 addresses after excluding server {}",
                    network, server_ip
                ));
            }
            if (self.max_clients as u64) > capacity {
                return Err(format!(
                    "'network' {} only has {} usable IPv4 client addresses, but max_clients is {}",
                    network, capacity, self.max_clients
                ));
            }
        }

        if let Some(network6) = self.network6 {
            if network6.prefix_len() > 126 {
                return Err(format!(
                    "'network6' {} is too small; IPv6 networks must be /126 or larger",
                    network6
                ));
            }

            let server_ip6 = self.server_ip6.unwrap_or_else(|| default_server_ip6(network6));
            if !network6.contains(&server_ip6) {
                return Err(format!(
                    "'server_ip6' {} is not within 'network6' {}",
                    server_ip6, network6
                ));
            }
            if server_ip6 == network6.network() {
                return Err(format!(
                    "'server_ip6' {} cannot be the network address for 'network6' {}",
                    server_ip6, network6
                ));
            }

            let capacity = ipv6_client_capacity(network6, server_ip6);
            if capacity == 0 {
                return Err(format!(
                    "'network6' {} has no usable client IPv6 addresses after excluding server {}",
                    network6, server_ip6
                ));
            }
            if (self.max_clients as u128) > capacity {
                return Err(format!(
                    "'network6' {} only has {} usable IPv6 client addresses, but max_clients is {}",
                    network6, capacity, self.max_clients
                ));
            }
        }

        // Nostr identity required (either nsec or nsec_file)
        if self.nsec.is_none() && self.nsec_file.is_none() {
            return Err("Either 'nsec' or 'nsec_file' is required for Nostr identity".to_string());
        }
        if self.nsec.is_some() && self.nsec_file.is_some() {
            return Err("Both 'nsec' and 'nsec_file' are set; they are mutually exclusive".to_string());
        }

        // Peer npub required
        if self.peer_npub.is_empty() {
            return Err("'peer_npub' is required".to_string());
        }

        Ok(())
    }

    /// Get the Nostr private key, reading from file if necessary.
    pub fn get_nsec(&self) -> Result<String, VpnIceError> {
        read_nsec(&self.nsec, &self.nsec_file)
    }
}

/// VPN client configuration for ICE/Nostr mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnIceClientConfig {
    /// Nostr private key (nsec format).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,

    /// Path to file containing Nostr private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec_file: Option<PathBuf>,

    /// Server's Nostr public key (npub format).
    pub peer_npub: String,

    /// Nostr relay URLs for signaling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,

    /// STUN server addresses for ICE.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,

    /// MTU for the TUN device.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// IPv4 routes to send through the VPN (CIDRs).
    #[serde(default)]
    pub routes: Vec<Ipv4Net>,

    /// IPv6 routes to send through the VPN (CIDRs).
    #[serde(default)]
    pub routes6: Vec<Ipv6Net>,
}

impl VpnIceClientConfig {
    /// Validate the VPN client configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Nostr identity required
        if self.nsec.is_none() && self.nsec_file.is_none() {
            return Err("Either 'nsec' or 'nsec_file' is required for Nostr identity".to_string());
        }
        if self.nsec.is_some() && self.nsec_file.is_some() {
            return Err("Both 'nsec' and 'nsec_file' are set; they are mutually exclusive".to_string());
        }

        // Peer npub required
        if self.peer_npub.is_empty() {
            return Err("'peer_npub' is required".to_string());
        }

        Ok(())
    }

    /// Get the Nostr private key, reading from file if necessary.
    pub fn get_nsec(&self) -> Result<String, VpnIceError> {
        read_nsec(&self.nsec, &self.nsec_file)
    }
}

fn read_nsec(nsec: &Option<String>, nsec_file: &Option<PathBuf>) -> Result<String, VpnIceError> {
    if let Some(ref nsec) = nsec {
        return Ok(nsec.clone());
    }
    if let Some(ref path) = nsec_file {
        let expanded = tunnel_common::config::expand_tilde(path.as_path());
        let content = std::fs::read_to_string(&expanded).map_err(|e| {
            VpnIceError::Config(format!(
                "Failed to read nsec file '{}': {}",
                path.display(),
                e
            ))
        })?;
        return Ok(content.trim().to_string());
    }
    Err(VpnIceError::Config(
        "No nsec or nsec_file configured".to_string(),
    ))
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

fn ipv4_client_capacity(net: Ipv4Net, server_ip: Ipv4Addr) -> u64 {
    let host_bits = 32u32.saturating_sub(net.prefix_len() as u32);
    let total = if host_bits >= 32 {
        1u64 << 32
    } else {
        1u64 << host_bits
    };
    let reserved = if total >= 2 { 2 } else { total };
    let mut available = total.saturating_sub(reserved);
    if server_ip != net.network() && server_ip != net.broadcast() {
        available = available.saturating_sub(1);
    }
    available
}

fn ipv6_client_capacity(net: Ipv6Net, server_ip: Ipv6Addr) -> u128 {
    let host_bits = 128u32.saturating_sub(net.prefix_len() as u32);
    let total = if host_bits >= 128 {
        u128::MAX
    } else {
        1u128 << host_bits
    };
    let mut available = total.saturating_sub(1);
    if server_ip != net.network() {
        available = available.saturating_sub(1);
    }
    available
}

impl Default for VpnIceClientConfig {
    fn default() -> Self {
        Self {
            nsec: None,
            nsec_file: None,
            peer_npub: String::new(),
            relays: None,
            stun_servers: default_stun_servers(),
            mtu: DEFAULT_MTU,
            routes: vec![],
            routes6: vec![],
        }
    }
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_max_clients() -> usize {
    253
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_server_config() -> VpnIceServerConfig {
        VpnIceServerConfig {
            network: Some("10.0.0.0/24".parse().unwrap()),
            network6: None,
            server_ip: None,
            server_ip6: None,
            mtu: DEFAULT_MTU,
            max_clients: 253,
            nsec: Some("nsec1test".to_string()),
            nsec_file: None,
            peer_npub: "npub1test".to_string(),
            relays: None,
            stun_servers: default_stun_servers(),
            nat64: None,
            disable_spoofing_check: false,
        }
    }

    #[test]
    fn test_server_config_validation_no_network() {
        let config = VpnIceServerConfig {
            network: None,
            network6: None,
            server_ip: None,
            server_ip6: None,
            mtu: DEFAULT_MTU,
            max_clients: 253,
            nsec: Some("nsec1test".to_string()),
            nsec_file: None,
            peer_npub: "npub1test".to_string(),
            relays: None,
            stun_servers: default_stun_servers(),
            nat64: None,
            disable_spoofing_check: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_config_server_ip_without_network() {
        let config = VpnIceServerConfig {
            network: None,
            network6: Some("fd00::/64".parse().unwrap()),
            server_ip: Some("10.0.0.1".parse().unwrap()),
            server_ip6: None,
            mtu: DEFAULT_MTU,
            max_clients: 253,
            nsec: Some("nsec1test".to_string()),
            nsec_file: None,
            peer_npub: "npub1test".to_string(),
            relays: None,
            stun_servers: default_stun_servers(),
            nat64: None,
            disable_spoofing_check: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_config_server_ip6_without_network6() {
        let config = VpnIceServerConfig {
            network: Some("10.0.0.0/24".parse().unwrap()),
            network6: None,
            server_ip: None,
            server_ip6: Some("fd00::1".parse().unwrap()),
            mtu: DEFAULT_MTU,
            max_clients: 253,
            nsec: Some("nsec1test".to_string()),
            nsec_file: None,
            peer_npub: "npub1test".to_string(),
            relays: None,
            stun_servers: default_stun_servers(),
            nat64: None,
            disable_spoofing_check: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_config_validation_ok() {
        let config = base_server_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_server_config_validation_network_too_small() {
        let mut config = base_server_config();
        config.network = Some("10.0.0.0/31".parse().unwrap());
        assert!(config.validate().is_err());

        let mut config6 = base_server_config();
        config6.network = None;
        config6.network6 = Some("fd00::/127".parse().unwrap());
        assert!(config6.validate().is_err());
    }

    #[test]
    fn test_server_config_validation_server_ip_outside() {
        let mut config = base_server_config();
        config.server_ip = Some("10.0.1.1".parse().unwrap());
        assert!(config.validate().is_err());

        let mut config6 = base_server_config();
        config6.network = None;
        config6.network6 = Some("fd00::/64".parse().unwrap());
        config6.server_ip6 = Some("fd01::1".parse().unwrap());
        assert!(config6.validate().is_err());
    }

    #[test]
    fn test_server_config_validation_server_ip_at_network_or_broadcast() {
        let mut config = base_server_config();
        config.server_ip = Some("10.0.0.0".parse().unwrap());
        assert!(config.validate().is_err());

        let mut config_broadcast = base_server_config();
        config_broadcast.server_ip = Some("10.0.0.255".parse().unwrap());
        assert!(config_broadcast.validate().is_err());

        let mut config6 = base_server_config();
        config6.network = None;
        config6.network6 = Some("fd00::/64".parse().unwrap());
        config6.server_ip6 = Some("fd00::".parse().unwrap());
        assert!(config6.validate().is_err());
    }

    #[test]
    fn test_server_config_validation_capacity_exhaustion() {
        let mut config = base_server_config();
        config.network = Some("10.0.0.0/30".parse().unwrap());
        config.server_ip = Some("10.0.0.1".parse().unwrap());
        config.max_clients = 2;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_client_config_validation_ok() {
        let config = VpnIceClientConfig {
            nsec: Some("nsec1test".to_string()),
            peer_npub: "npub1test".to_string(),
            routes: vec!["0.0.0.0/0".parse().unwrap()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_client_config_validation_no_routes() {
        let config = VpnIceClientConfig {
            nsec: Some("nsec1test".to_string()),
            peer_npub: "npub1test".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_client_config_empty_peer_npub() {
        let config = VpnIceClientConfig {
            nsec: Some("nsec1test".to_string()),
            peer_npub: String::new(),
            routes: vec!["10.0.0.0/24".parse().unwrap()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_nsec_and_nsec_file_conflict() {
        let server_config = VpnIceServerConfig {
            network: Some("10.0.0.0/24".parse().unwrap()),
            network6: None,
            server_ip: None,
            server_ip6: None,
            mtu: DEFAULT_MTU,
            max_clients: 253,
            nsec: Some("nsec1test".to_string()),
            nsec_file: Some(PathBuf::from("nsec.txt")),
            peer_npub: "npub1test".to_string(),
            relays: None,
            stun_servers: default_stun_servers(),
            nat64: None,
            disable_spoofing_check: false,
        };
        assert!(server_config.validate().is_err());

        let client_config = VpnIceClientConfig {
            nsec: Some("nsec1test".to_string()),
            nsec_file: Some(PathBuf::from("nsec.txt")),
            peer_npub: "npub1test".to_string(),
            routes: vec!["10.0.0.0/24".parse().unwrap()],
            ..Default::default()
        };
        assert!(client_config.validate().is_err());
    }
}
