//! VPN runtime configuration types.

use crate::vpn_core::datagram::MAX_DATAGRAM_PAYLOAD;
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::udp::ensure_loopback;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Default time without any datagram from a client before it is reaped.
///
/// Must comfortably exceed the client heartbeat interval (10s) so a briefly
/// idle client is not reaped; the client's own heartbeat timeout is 30s.
pub const DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Validate the combination of VPN networks and server addresses.
///
/// Single source of truth shared by the TOML config layer ([`file_config`])
/// and the runtime config ([`VpnServerConfig::validate`]).
///
/// [`file_config`]: crate::vpn_core::file_config
pub fn validate_vpn_networks(
    network: Option<Ipv4Net>,
    server_ip: Option<Ipv4Addr>,
    network6: Option<Ipv6Net>,
    server_ip6: Option<Ipv6Addr>,
) -> Result<(), String> {
    // At least one network must be configured
    if network.is_none() && network6.is_none() {
        return Err(
            "At least one of 'network' (IPv4) or 'network6' (IPv6) must be configured".to_string(),
        );
    }

    // server_ip requires network
    if server_ip.is_some() && network.is_none() {
        return Err("'server_ip' requires 'network' to be set".to_string());
    }

    // server_ip must be within network
    if let (Some(server_ip), Some(network)) = (server_ip, network)
        && !network.contains(&server_ip)
    {
        return Err(format!(
            "'server_ip' {} is not within 'network' {}",
            server_ip, network
        ));
    }

    // server_ip6 requires network6
    if server_ip6.is_some() && network6.is_none() {
        return Err("'server_ip6' requires 'network6' to be set".to_string());
    }

    // server_ip6 must be within network6
    if let (Some(server_ip6), Some(network6)) = (server_ip6, network6)
        && !network6.contains(&server_ip6)
    {
        return Err(format!(
            "'server_ip6' {} is not within 'network6' {}",
            server_ip6, network6
        ));
    }

    Ok(())
}

/// VPN server configuration.
#[derive(Debug, Clone)]
pub struct VpnServerConfig {
    /// Loopback UDP address the server binds to (the local tunnel forwards to it).
    pub listen: SocketAddr,

    /// VPN network CIDR (e.g., "10.0.0.0/24"). Optional for IPv6-only mode.
    pub network: Option<Ipv4Net>,

    /// IPv6 VPN network CIDR (e.g., "fd00::/64"). Optional for dual-stack or IPv6-only.
    pub network6: Option<Ipv6Net>,

    /// Server's VPN IP address (defaults to first host in network, e.g., .1).
    pub server_ip: Option<Ipv4Addr>,

    /// Server's IPv6 VPN address (defaults to first host in network6, e.g., ::1).
    pub server_ip6: Option<Ipv6Addr>,

    /// MTU for the TUN device.
    pub mtu: u16,

    /// Maximum number of connected clients.
    pub max_clients: usize,

    /// Time without any datagram from a client before the server reaps it.
    pub client_timeout: Duration,

    /// Maximum UDP datagram payload to emit. Offload super-frames larger than
    /// this are segmented before sending (kept ≤ [`MAX_DATAGRAM_PAYLOAD`]).
    pub max_datagram_size: usize,

    /// Whether to drop packets when a client's send buffer is full.
    ///
    /// When `true`: drops packets for slow clients instead of blocking.
    /// When `false` (default): applies backpressure by awaiting the send.
    pub drop_on_full: bool,

    /// Channel buffer size for outbound packets to each client (default: 1024).
    pub client_channel_size: usize,

    /// Channel buffer size for the TUN writer task (default: 512).
    pub tun_writer_channel_size: usize,

    /// Disable inter-client IP spoofing checks (default: false).
    ///
    /// When `false` (default): the server rejects packets whose source IP
    /// matches another client's assigned VPN IP. With no transport-level auth
    /// this check is the only inter-client protection, so keep it on unless the
    /// tunnel already isolates clients.
    pub disable_spoofing_check: bool,
}

impl VpnServerConfig {
    /// Validate the VPN server configuration.
    pub fn validate(&self) -> VpnResult<()> {
        ensure_loopback(self.listen)?;
        validate_vpn_networks(self.network, self.server_ip, self.network6, self.server_ip6)
            .map_err(VpnError::config)?;
        if self.max_datagram_size > MAX_DATAGRAM_PAYLOAD {
            return Err(VpnError::config(format!(
                "max_datagram_size {} exceeds the UDP payload limit of {}",
                self.max_datagram_size, MAX_DATAGRAM_PAYLOAD
            )));
        }
        Ok(())
    }
}

/// VPN client configuration.
#[derive(Debug, Clone)]
pub struct VpnClientConfig {
    /// Loopback UDP address of the local tunnel endpoint to connect to.
    pub server_addr: SocketAddr,

    /// IPv4 routes to send through the VPN (CIDRs), e.g., 0.0.0.0/0 for full tunnel.
    pub routes: Vec<Ipv4Net>,

    /// IPv6 routes to send through the VPN (CIDRs). Optional for dual-stack.
    pub routes6: Vec<Ipv6Net>,
}

impl VpnClientConfig {
    /// Validate the VPN client configuration.
    pub fn validate(&self) -> VpnResult<()> {
        ensure_loopback(self.server_addr)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_server_config() -> VpnServerConfig {
        VpnServerConfig {
            listen: "127.0.0.1:5555".parse().unwrap(),
            network: Some("10.0.0.0/24".parse().unwrap()),
            network6: None,
            server_ip: None,
            server_ip6: None,
            mtu: 1440,
            max_clients: 254,
            client_timeout: DEFAULT_CLIENT_TIMEOUT,
            max_datagram_size: MAX_DATAGRAM_PAYLOAD,
            drop_on_full: false,
            client_channel_size: 1024,
            tun_writer_channel_size: 512,
            disable_spoofing_check: false,
        }
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
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("At least one of"));
    }

    #[test]
    fn test_validate_rejects_non_loopback_listen() {
        let mut config = minimal_server_config();
        config.listen = "0.0.0.0:5555".parse().unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not loopback"));
    }

    #[test]
    fn test_validate_server_ip_requires_network() {
        let mut config = minimal_server_config();
        config.network = None;
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip = Some("10.0.0.1".parse().unwrap());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("'server_ip' requires 'network'"));
    }

    #[test]
    fn test_validate_server_ip6_requires_network6() {
        let mut config = minimal_server_config();
        config.server_ip6 = Some("fd00::1".parse().unwrap());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("'server_ip6' requires 'network6'"));
    }

    #[test]
    fn test_validate_server_ip_within_network() {
        let mut config = minimal_server_config();
        config.server_ip = Some("192.168.1.1".parse().unwrap()); // Not in 10.0.0.0/24
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not within 'network'"));
    }

    #[test]
    fn test_validate_server_ip6_within_network6() {
        let mut config = minimal_server_config();
        config.network6 = Some("fd00::/64".parse().unwrap());
        config.server_ip6 = Some("fd01::1".parse().unwrap()); // Not in fd00::/64
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not within 'network6'"));
    }

    #[test]
    fn test_validate_rejects_oversized_datagram_cap() {
        let mut config = minimal_server_config();
        config.max_datagram_size = MAX_DATAGRAM_PAYLOAD + 1;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("exceeds the UDP payload limit"));
    }

    #[test]
    fn test_validate_client_ok() {
        let config = VpnClientConfig {
            server_addr: "127.0.0.1:5555".parse().unwrap(),
            routes: vec!["0.0.0.0/0".parse().unwrap()],
            routes6: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_client_rejects_non_loopback_target() {
        let config = VpnClientConfig {
            server_addr: "192.0.2.1:5555".parse().unwrap(),
            routes: vec![],
            routes6: vec![],
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not loopback"));
    }
}
