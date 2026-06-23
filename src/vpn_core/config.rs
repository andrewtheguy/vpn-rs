//! VPN runtime configuration types.

use crate::vpn_core::datagram::MAX_DATAGRAM_PAYLOAD;
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::file_config::{MAX_SOCKET_BUFFER_SIZE, MIN_SOCKET_BUFFER_SIZE};
use crate::vpn_core::udp::ensure_loopback;
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Minimum permitted `max_datagram_size`. Matches the minimum VPN MTU so a
/// segmented datagram can always carry at least one minimum-size IP packet.
pub const MIN_DATAGRAM_SIZE: usize = 576;

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

/// Range-check a kernel socket buffer size (`SO_RCVBUF` / `SO_SNDBUF`).
fn validate_socket_buffer(size: usize, field: &str) -> VpnResult<()> {
    if !(MIN_SOCKET_BUFFER_SIZE..=MAX_SOCKET_BUFFER_SIZE).contains(&size) {
        return Err(VpnError::config(format!(
            "{field} {size} is out of range ({MIN_SOCKET_BUFFER_SIZE}..={MAX_SOCKET_BUFFER_SIZE})"
        )));
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

    /// Kernel UDP socket receive buffer (`SO_RCVBUF`) in bytes (default 4 MiB).
    ///
    /// Sized to absorb bursts that briefly outpace the userspace receiver. The
    /// kernel caps the request at `net.core.rmem_max`.
    pub recv_buffer_size: usize,

    /// Kernel UDP socket send buffer (`SO_SNDBUF`) in bytes (default 4 MiB).
    ///
    /// The kernel caps the request at `net.core.wmem_max`.
    pub send_buffer_size: usize,

    /// Disable inter-client IP spoofing checks (default: false).
    ///
    /// When `false` (default): the server rejects packets whose source IP
    /// matches another client's assigned VPN IP. With no transport-level auth
    /// this check is the only inter-client protection, so keep it on unless the
    /// tunnel already isolates clients.
    pub disable_spoofing_check: bool,

    /// Test mode: allow binding a non-loopback `listen` address (default: false).
    ///
    /// Only set via `--test-mode`. Relaxes the loopback security boundary for
    /// direct host-to-host testing without an external tunnel.
    pub test_mode: bool,

    /// Test-mode token a client must present in its handshake (test mode only).
    ///
    /// Randomly generated at startup and printed. A handshake whose token does
    /// not match is rejected; this also makes test and non-test instances
    /// mutually incompatible (a non-test server has `None` here).
    pub test_token: Option<String>,
}

impl VpnServerConfig {
    /// Validate the VPN server configuration.
    pub fn validate(&self) -> VpnResult<()> {
        if !self.test_mode {
            ensure_loopback(self.listen)?;
        }
        validate_vpn_networks(self.network, self.server_ip, self.network6, self.server_ip6)
            .map_err(VpnError::config)?;
        if !(MIN_DATAGRAM_SIZE..=MAX_DATAGRAM_PAYLOAD).contains(&self.max_datagram_size) {
            return Err(VpnError::config(format!(
                "max_datagram_size {} is out of range ({}..={})",
                self.max_datagram_size, MIN_DATAGRAM_SIZE, MAX_DATAGRAM_PAYLOAD
            )));
        }
        validate_socket_buffer(self.recv_buffer_size, "recv_buffer_size")?;
        validate_socket_buffer(self.send_buffer_size, "send_buffer_size")?;
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

    /// Kernel UDP socket receive buffer (`SO_RCVBUF`) in bytes (default 4 MiB).
    /// The kernel caps the request at `net.core.rmem_max`.
    pub recv_buffer_size: usize,

    /// Kernel UDP socket send buffer (`SO_SNDBUF`) in bytes (default 4 MiB).
    /// The kernel caps the request at `net.core.wmem_max`.
    pub send_buffer_size: usize,

    /// Test mode: allow connecting to a non-loopback `server_addr` (default: false).
    ///
    /// Only set via `--test-mode`. Relaxes the loopback security boundary for
    /// direct host-to-host testing without an external tunnel.
    pub test_mode: bool,

    /// Test-mode token sent in the handshake (test mode only).
    ///
    /// Supplied via `--test-token` and must match the server's randomly
    /// generated token. A non-test client leaves this `None`.
    pub test_token: Option<String>,
}

impl VpnClientConfig {
    /// Validate the VPN client configuration.
    pub fn validate(&self) -> VpnResult<()> {
        if !self.test_mode {
            ensure_loopback(self.server_addr)?;
        }
        validate_socket_buffer(self.recv_buffer_size, "recv_buffer_size")?;
        validate_socket_buffer(self.send_buffer_size, "send_buffer_size")?;
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
            recv_buffer_size: crate::vpn_core::udp::DEFAULT_SOCKET_RECV_BUFFER_SIZE,
            send_buffer_size: crate::vpn_core::udp::DEFAULT_SOCKET_SEND_BUFFER_SIZE,
            disable_spoofing_check: false,
            test_mode: false,
            test_token: None,
        }
    }

    fn minimal_client_config() -> VpnClientConfig {
        VpnClientConfig {
            server_addr: "127.0.0.1:5555".parse().unwrap(),
            routes: vec![],
            routes6: vec![],
            recv_buffer_size: crate::vpn_core::udp::DEFAULT_SOCKET_RECV_BUFFER_SIZE,
            send_buffer_size: crate::vpn_core::udp::DEFAULT_SOCKET_SEND_BUFFER_SIZE,
            test_mode: false,
            test_token: None,
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
    fn test_validate_test_mode_allows_non_loopback_listen() {
        let mut config = minimal_server_config();
        config.listen = "0.0.0.0:5555".parse().unwrap();
        config.test_mode = true;
        assert!(config.validate().is_ok());
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
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_validate_rejects_undersized_datagram_cap() {
        let mut config = minimal_server_config();
        config.max_datagram_size = MIN_DATAGRAM_SIZE - 1;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_validate_rejects_undersized_recv_buffer() {
        let mut config = minimal_server_config();
        config.recv_buffer_size = MIN_SOCKET_BUFFER_SIZE - 1;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("recv_buffer_size"));
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_validate_rejects_oversized_send_buffer() {
        let mut config = minimal_server_config();
        config.send_buffer_size = MAX_SOCKET_BUFFER_SIZE + 1;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("send_buffer_size"));
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_validate_client_ok() {
        let mut config = minimal_client_config();
        config.routes = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_client_rejects_non_loopback_target() {
        let mut config = minimal_client_config();
        config.server_addr = "192.0.2.1:5555".parse().unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not loopback"));
    }

    #[test]
    fn test_validate_client_test_mode_allows_non_loopback_target() {
        let mut config = minimal_client_config();
        config.server_addr = "192.0.2.1:5555".parse().unwrap();
        config.test_mode = true;
        config.test_token = Some("token".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_client_rejects_oversized_recv_buffer() {
        let mut config = minimal_client_config();
        config.recv_buffer_size = MAX_SOCKET_BUFFER_SIZE + 1;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("recv_buffer_size"));
        assert!(err.contains("out of range"));
    }
}
