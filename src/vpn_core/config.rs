//! VPN configuration types.

use ipnet::{Ipv4Net, Ipv6Net};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Default MTU for VPN tunnel (1500 - 60 bytes overhead for QUIC/TLS + framing).
pub const DEFAULT_MTU: u16 = 1440;

/// VPN server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnServerConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24"). Optional for IPv6-only mode.
    /// Server gets .1 by default, clients get subsequent addresses.
    /// At least one of `network` (IPv4) or `network6` (IPv6) must be configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Ipv4Net>,

    /// IPv6 VPN network CIDR (e.g., "fd00::/64"). Optional for dual-stack or IPv6-only.
    /// Server gets ::1 by default, clients get subsequent addresses.
    /// At least one of `network` (IPv4) or `network6` (IPv6) must be configured.
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

    /// Valid authentication tokens (clients must provide one to connect).
    /// Uses vpn-auth format (i + 16 chars + checksum).
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

    /// Disable inter-client IP spoofing checks (default: false).
    ///
    /// When `false` (default): The server rejects packets whose source IP matches
    /// another client's assigned VPN IP. This prevents one client from impersonating
    /// another. Packets with non-VPN source IPs (e.g., a client's public IPv6) are
    /// still allowed, supporting dual-stack scenarios.
    ///
    /// When `true`: All source IP validation is disabled. Any source IP is accepted,
    /// which may allow clients to spoof other clients' addresses. Use with caution.
    #[serde(default)]
    pub disable_spoofing_check: bool,
}

impl VpnServerConfig {
    /// Validate the VPN server configuration.
    ///
    /// Returns an error if:
    /// - Neither `network` (IPv4) nor `network6` (IPv6) is configured
    /// - `server_ip` is set but `network` is not (orphaned IPv4 server IP)
    /// - `server_ip6` is set but `network6` is not (orphaned IPv6 server IP)
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

        // server_ip must be within network
        if let (Some(server_ip), Some(network)) = (self.server_ip, self.network) {
            if !network.contains(&server_ip) {
                return Err(format!(
                    "'server_ip' {} is not within 'network' {}",
                    server_ip, network
                ));
            }
        }

        // server_ip6 requires network6
        if self.server_ip6.is_some() && self.network6.is_none() {
            return Err("'server_ip6' requires 'network6' to be set".to_string());
        }

        // server_ip6 must be within network6
        if let (Some(server_ip6), Some(network6)) = (self.server_ip6, self.network6) {
            if !network6.contains(&server_ip6) {
                return Err(format!(
                    "'server_ip6' {} is not within 'network6' {}",
                    server_ip6, network6
                ));
            }
        }

        Ok(())
    }
}

/// VPN client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnClientConfig {
    /// Server's iroh node ID.
    pub server_node_id: String,

    /// Authentication token (vpn-auth format).
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

impl VpnClientConfig {
    /// Validate the VPN client configuration.
    ///
    /// Returns an error if:
    /// - `server_node_id` is empty
    /// - Both `routes` and `routes6` are empty (at least one route required)
    pub fn validate(&self) -> Result<(), String> {
        if self.server_node_id.is_empty() {
            return Err("'server_node_id' is required and cannot be empty".to_string());
        }
        if self.server_node_id.parse::<EndpointId>().is_err() {
            return Err("'server_node_id' is not a valid iroh node ID".to_string());
        }

        if self.routes.is_empty() && self.routes6.is_empty() {
            return Err(
                "At least one route is required: 'routes' (IPv4) or 'routes6' (IPv6)".to_string(),
            );
        }

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_server_config() -> VpnServerConfig {
        VpnServerConfig {
            network: Some("10.0.0.0/24".parse().unwrap()),
            network6: None,
            server_ip: None,
            server_ip6: None,
            mtu: DEFAULT_MTU,
            max_clients: 254,
            auth_tokens: None,
            drop_on_full: false,
            client_channel_size: 1024,
            tun_writer_channel_size: 512,
            disable_spoofing_check: false,
        }
    }

    fn random_server_node_id() -> String {
        let bytes: [u8; 32] = rand::random();
        let secret = iroh::SecretKey::from_bytes(&bytes);
        secret.public().to_string()
    }

    #[test]
    fn test_validate_ipv4_only_ok() {
        let config = minimal_server_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_ipv6_only_ok() {
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_dual_stack_ok() {
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/64".parse().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_no_network_fails() {
        let mut config = minimal_server_config();
        config.network = None;
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one of"));
    }

    #[test]
    fn test_validate_server_ip_requires_network() {
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip = Some("10.0.0.1".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("'server_ip' requires 'network'"));
    }

    #[test]
    fn test_validate_server_ip6_requires_network6() {
        let mut config = minimal_server_config();
        config.server_ip6 = Some("fd00::1".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("'server_ip6' requires 'network6'"));
    }

    #[test]
    fn test_validate_server_ip_within_network() {
        let mut config = minimal_server_config();
        config.server_ip = Some("192.168.1.1".parse().unwrap()); // Not in 10.0.0.0/24
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not within 'network'"));
    }

    #[test]
    fn test_validate_server_ip6_within_network6() {
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip6 = Some("fd01::1".parse().unwrap()); // Not in fd00::/64
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not within 'network6'"));
    }

    #[test]
    fn test_validate_client_requires_server_node_id() {
        let mut config = VpnClientConfig::default();
        config.routes.push("0.0.0.0/0".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'server_node_id' is required"));
    }

    #[test]
    fn test_validate_client_ok() {
        let config = VpnClientConfig {
            server_node_id: random_server_node_id(),
            routes: vec!["0.0.0.0/0".parse().unwrap()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_client_requires_routes() {
        let config = VpnClientConfig {
            server_node_id: random_server_node_id(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one route"));
    }
}
