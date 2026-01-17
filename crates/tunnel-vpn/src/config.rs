//! VPN configuration types.

use ipnet::{Ipv4Net, Ipv6Net};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Default MTU for VPN tunnel (1500 - 60 bytes overhead for QUIC/TLS + framing).
pub const DEFAULT_MTU: u16 = 1440;

/// NAT64 configuration for IPv6-only clients to access IPv4 resources.
///
/// When enabled, the VPN server translates IPv6 packets destined for the
/// well-known NAT64 prefix `64:ff9b::/96` to IPv4 packets, performs NAPT
/// (Network Address Port Translation), and routes them to the IPv4 destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nat64Config {
    /// Enable NAT64 translation.
    #[serde(default)]
    pub enabled: bool,

    /// IPv4 source address for translated packets (optional).
    ///
    /// If not set, the server's VPN IPv4 address is used (requires `network` to be configured).
    /// Set this to allow NAT64 in IPv6-only VPN configurations where the host has
    /// dual-stack connectivity but no IPv4 VPN network is needed.
    ///
    /// This should be a routable IPv4 address on the host that can receive return traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<Ipv4Addr>,

    /// Port range for NAPT (default: 32768-65535).
    /// The first value is the start port, the second is the end port (inclusive).
    #[serde(default = "default_nat64_port_range")]
    pub port_range: (u16, u16),

    /// TCP connection timeout in seconds (default: 300).
    /// TCP connections without activity for this duration are removed.
    #[serde(default = "default_nat64_tcp_timeout")]
    pub tcp_timeout_secs: u64,

    /// UDP session timeout in seconds (default: 30).
    /// UDP sessions without activity for this duration are removed.
    #[serde(default = "default_nat64_udp_timeout")]
    pub udp_timeout_secs: u64,

    /// ICMP session timeout in seconds (default: 30).
    /// ICMP sessions without activity for this duration are removed.
    #[serde(default = "default_nat64_icmp_timeout")]
    pub icmp_timeout_secs: u64,
}

impl Default for Nat64Config {
    fn default() -> Self {
        Self {
            enabled: false,
            source_ip: None,
            port_range: default_nat64_port_range(),
            tcp_timeout_secs: default_nat64_tcp_timeout(),
            udp_timeout_secs: default_nat64_udp_timeout(),
            icmp_timeout_secs: default_nat64_icmp_timeout(),
        }
    }
}

impl Nat64Config {
    /// Validate the NAT64 configuration.
    ///
    /// Returns an error if:
    /// - `port_range.0 > port_range.1` (start port greater than end port)
    /// - `port_range.0 == 0` (port 0 is reserved and cannot be used)
    /// - Any timeout field is 0 (sessions would expire immediately)
    pub fn validate(&self) -> Result<(), String> {
        if self.port_range.0 == 0 {
            return Err("NAT64 port_range start must be > 0 (port 0 is reserved)".to_string());
        }
        if self.port_range.0 > self.port_range.1 {
            return Err(format!(
                "NAT64 port_range start ({}) must be <= end ({})",
                self.port_range.0, self.port_range.1
            ));
        }
        if self.tcp_timeout_secs == 0 {
            return Err(
                "NAT64 tcp_timeout_secs must be > 0 (sessions would expire immediately)"
                    .to_string(),
            );
        }
        if self.udp_timeout_secs == 0 {
            return Err(
                "NAT64 udp_timeout_secs must be > 0 (sessions would expire immediately)"
                    .to_string(),
            );
        }
        if self.icmp_timeout_secs == 0 {
            return Err(
                "NAT64 icmp_timeout_secs must be > 0 (sessions would expire immediately)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl From<tunnel_common::config::Nat64Config> for Nat64Config {
    fn from(cfg: tunnel_common::config::Nat64Config) -> Self {
        Self {
            enabled: cfg.enabled,
            source_ip: cfg.source_ip,
            port_range: cfg.port_range,
            tcp_timeout_secs: cfg.tcp_timeout_secs,
            udp_timeout_secs: cfg.udp_timeout_secs,
            icmp_timeout_secs: cfg.icmp_timeout_secs,
        }
    }
}

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

    /// NAT64 configuration for IPv6-only clients to access IPv4 resources.
    /// When enabled, clients can access IPv4 addresses via the `64:ff9b::/96` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat64: Option<Nat64Config>,
}

impl VpnServerConfig {
    /// Validate the VPN server configuration.
    ///
    /// Returns an error if:
    /// - Neither `network` (IPv4) nor `network6` (IPv6) is configured
    /// - `server_ip` is set but `network` is not (orphaned IPv4 server IP)
    /// - `server_ip6` is set but `network6` is not (orphaned IPv6 server IP)
    /// - NAT64 is enabled but `network6` is not configured
    /// - NAT64 configuration is invalid (delegates to `Nat64Config::validate()`)
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

        // NAT64 validation
        if let Some(ref nat64) = self.nat64 {
            if nat64.enabled {
                // NAT64 requires network6 (only makes sense for IPv6-capable networks)
                if self.network6.is_none() {
                    return Err("NAT64 requires 'network6' to be configured".to_string());
                }
                // NAT64 requires an IPv4 source address for translated packets.
                // This can come from either:
                // 1. The VPN network (server_ip from the IPv4 pool)
                // 2. An explicit nat64.source_ip configuration
                if self.network.is_none() && nat64.source_ip.is_none() {
                    return Err(
                        "NAT64 requires either 'network' (IPv4) or 'nat64.source_ip' to be configured"
                            .to_string(),
                    );
                }
                nat64.validate()?;
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

fn default_nat64_port_range() -> (u16, u16) {
    (32768, 65535)
}

fn default_nat64_tcp_timeout() -> u64 {
    300
}

fn default_nat64_udp_timeout() -> u64 {
    30
}

fn default_nat64_icmp_timeout() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

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
            nat64: None,
        }
    }

    fn random_server_node_id() -> String {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
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
    fn test_validate_nat64_requires_network6() {
        let mut config = minimal_server_config();
        config.nat64 = Some(Nat64Config {
            enabled: true,
            ..Default::default()
        });
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("network6"));
    }

    #[test]
    fn test_validate_nat64_requires_ipv4_source() {
        // NAT64 without network and without source_ip should fail
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.nat64 = Some(Nat64Config {
            enabled: true,
            ..Default::default()
        });
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("NAT64 requires either 'network' (IPv4) or 'nat64.source_ip'"),
            "Expected NAT64 source IP error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_nat64_dual_stack_ok() {
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.nat64 = Some(Nat64Config {
            enabled: true,
            ..Default::default()
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_nat64_ipv6_only_with_source_ip_ok() {
        // NAT64 with IPv6-only + explicit source_ip should succeed
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.nat64 = Some(Nat64Config {
            enabled: true,
            source_ip: Some("192.168.1.1".parse().unwrap()),
            ..Default::default()
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_nat64_disabled_ipv6_only_ok() {
        // NAT64 disabled should allow IPv6-only
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.nat64 = Some(Nat64Config {
            enabled: false,
            ..Default::default()
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_server_ip_requires_network() {
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip = Some("10.0.0.1".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'server_ip' requires 'network'"));
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
    fn test_validate_nat64_port_range_invalid() {
        let nat64 = Nat64Config {
            port_range: (100, 50),
            ..Default::default()
        };
        let result = nat64.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("port_range start"));
    }

    #[test]
    fn test_validate_nat64_port_zero_start_invalid() {
        let nat64 = Nat64Config {
            port_range: (0, 100),
            ..Default::default()
        };
        let result = nat64.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("port_range start must be > 0"));
    }

    #[test]
    fn test_validate_nat64_zero_timeouts_invalid() {
        let nat64 = Nat64Config {
            tcp_timeout_secs: 0,
            udp_timeout_secs: 0,
            icmp_timeout_secs: 0,
            ..Default::default()
        };
        let result = nat64.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("timeout"));
    }

    #[test]
    fn test_validate_client_requires_server_node_id() {
        let mut config = VpnClientConfig::default();
        config.routes.push("0.0.0.0/0".parse().unwrap());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("'server_node_id' is required"));
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
