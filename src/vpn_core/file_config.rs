//! TOML config-file support: file-level structs, loading, and resolution
//! into the runtime configuration ([`super::config`]).

use crate::vpn_core::config::{DEFAULT_CLIENT_TIMEOUT, MIN_DATAGRAM_SIZE};
use crate::vpn_core::datagram::MAX_DATAGRAM_PAYLOAD;
use crate::vpn_core::udp::ensure_loopback;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default loopback listen/connect address as a string.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:5555";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[serde(rename = "vpnserver")]
    VpnServer,
    #[serde(rename = "vpnclient")]
    VpnClient,
    /// Test-mode server role; only valid together with `--test-mode`.
    #[serde(rename = "testvpnserver")]
    TestVpnServer,
    /// Test-mode client role; only valid together with `--test-mode`.
    #[serde(rename = "testvpnclient")]
    TestVpnClient,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnServerSettings {
    /// Loopback UDP address to bind (default `127.0.0.1:5555`).
    pub listen: Option<String>,
    pub network: Option<String>,
    pub server_ip: Option<String>,
    pub network6: Option<String>,
    pub server_ip6: Option<String>,
    pub mtu: Option<u16>,
    pub max_clients: Option<usize>,
    /// Seconds without any datagram before a client is reaped.
    pub client_timeout_secs: Option<u64>,
    /// Max UDP datagram payload to emit (offload super-frames above this are segmented).
    pub max_datagram_size: Option<usize>,
    #[serde(default)]
    pub drop_on_full: bool,
    pub client_channel_size: Option<usize>,
    pub tun_writer_channel_size: Option<usize>,
    #[serde(default)]
    pub disable_spoofing_check: bool,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnClientSettings {
    /// Loopback UDP address of the local tunnel endpoint (default `127.0.0.1:5555`).
    pub server_addr: Option<String>,
    pub routes: Option<Vec<String>>,
    pub routes6: Option<Vec<String>>,
    pub auto_reconnect: Option<bool>,
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnServerConfig {
    pub role: Option<Role>,
    pub server: Option<VpnServerSettings>,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnClientConfig {
    pub role: Option<Role>,
    pub client: Option<VpnClientSettings>,
}

/// Default MTU for VPN packets (1500 - ~60 bytes overhead).
pub const DEFAULT_VPN_MTU: u16 = 1440;

/// Default channel buffer size for outbound packets to each client.
pub const DEFAULT_CLIENT_CHANNEL_SIZE: usize = 1024;

/// Default channel buffer size for TUN writer task.
pub const DEFAULT_TUN_WRITER_CHANNEL_SIZE: usize = 512;

/// Default maximum number of connected clients.
pub const DEFAULT_MAX_CLIENTS: usize = 254;

/// Minimum VPN tunnel MTU.
pub(crate) const MIN_VPN_MTU: u16 = 576;

/// Maximum VPN tunnel MTU. Jumbo frames are allowed because throughput on
/// per-packet-syscall-bound platforms (notably macOS `utun`, which has no GSO
/// and reads one packet per syscall) scales ~linearly with MTU. The transport
/// re-segments oversized offload frames to fit a UDP datagram, so a large
/// *inner* MTU needs no jumbo physical frames.
pub(crate) const MAX_VPN_MTU: u16 = 9216;

pub(crate) fn validate_mtu(mtu: u16, section: &str) -> Result<()> {
    if !(MIN_VPN_MTU..=MAX_VPN_MTU).contains(&mtu) {
        anyhow::bail!(
            "[{}] MTU {} is out of range. Valid range: {}-{}",
            section,
            mtu,
            MIN_VPN_MTU,
            MAX_VPN_MTU
        );
    }
    Ok(())
}

fn validate_channel_size(size: usize, field_name: &str, section: &str) -> Result<()> {
    if size == 0 {
        anyhow::bail!("[{}] {} must be at least 1", section, field_name);
    }
    if size > 65536 {
        anyhow::bail!(
            "[{}] {} value {} exceeds maximum of 65536",
            section,
            field_name,
            size
        );
    }
    Ok(())
}

fn validate_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::IpNet>().with_context(|| {
        format!(
            "Invalid CIDR network '{}'. Expected format: 192.168.0.0/16 or ::1/128",
            cidr
        )
    })?;
    Ok(())
}

fn validate_ipv6_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::Ipv6Net>().with_context(|| {
        format!(
            "Invalid IPv6 CIDR '{}'. Expected format: fd00::/64 or ::/0",
            cidr
        )
    })?;
    Ok(())
}

fn route6_context(route: &str, section: Option<&str>) -> String {
    let msg = format!("Invalid route6 CIDR '{}' (must be IPv6, e.g., ::/0)", route);
    match section {
        Some(s) => format!("[{}] {}", s, msg),
        None => msg,
    }
}

/// Parse a UDP address string (default applied by the caller).
///
/// Enforces a loopback address unless `allow_non_loopback` is set (test mode).
fn parse_loopback_addr(
    addr: &str,
    section: &str,
    field: &str,
    allow_non_loopback: bool,
) -> Result<SocketAddr> {
    let parsed: SocketAddr = addr.parse().with_context(|| {
        format!(
            "[{}] Invalid {} '{}'. Expected host:port, e.g. {}",
            section, field, addr, DEFAULT_LISTEN_ADDR
        )
    })?;
    if !allow_non_loopback {
        ensure_loopback(parsed).map_err(|e| anyhow::anyhow!("[{}] {}", section, e))?;
    }
    Ok(parsed)
}

fn validate_vpn_networks(
    network: Option<&str>,
    server_ip: Option<&str>,
    network6: Option<&str>,
    server_ip6: Option<&str>,
    section: &str,
) -> Result<()> {
    // Parse the raw strings, then delegate the semantic rules to the shared
    // validator in super::config (single source of truth with the runtime config).
    let network: Option<ipnet::Ipv4Net> = network
        .map(|n| {
            n.parse().with_context(|| {
                format!(
                    "[{}] Invalid network CIDR '{}'. Expected format: 10.0.0.0/24",
                    section, n
                )
            })
        })
        .transpose()?;

    let server_ip: Option<std::net::Ipv4Addr> = server_ip
        .map(|ip| {
            ip.parse().with_context(|| {
                format!(
                    "[{}] Invalid server_ip '{}'. Expected IPv4 address",
                    section, ip
                )
            })
        })
        .transpose()?;

    let network6: Option<ipnet::Ipv6Net> = network6
        .map(|n| {
            n.parse().with_context(|| {
                format!(
                    "[{}] Invalid network6 CIDR '{}'. Expected format: fd00::/64",
                    section, n
                )
            })
        })
        .transpose()?;

    let server_ip6: Option<std::net::Ipv6Addr> = server_ip6
        .map(|ip| {
            ip.parse().with_context(|| {
                format!(
                    "[{}] Invalid server_ip6 '{}'. Expected IPv6 address",
                    section, ip
                )
            })
        })
        .transpose()?;

    super::config::validate_vpn_networks(network, server_ip, network6, server_ip6)
        .map_err(|e| anyhow::anyhow!("[{}] {}", section, e))
}

impl VpnServerConfig {
    pub fn settings(&self) -> Option<&VpnServerSettings> {
        self.server.as_ref()
    }

    pub fn validate(&self, test_mode: bool) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnserver\"")?;
        let expected = if test_mode {
            Role::TestVpnServer
        } else {
            Role::VpnServer
        };
        if role != expected {
            if test_mode {
                anyhow::bail!(
                    "Config file has wrong role for a test-mode server. Expected role = \"testvpnserver\" (running with --test-mode)"
                );
            } else {
                anyhow::bail!(
                    "Config file has wrong role for server. Expected role = \"vpnserver\" (use --test-mode for role = \"testvpnserver\")"
                );
            }
        }

        if let Some(ref s) = self.server {
            if let Some(ref listen) = s.listen {
                parse_loopback_addr(listen, "server", "listen", test_mode)?;
            }
            validate_vpn_networks(
                s.network.as_deref(),
                s.server_ip.as_deref(),
                s.network6.as_deref(),
                s.server_ip6.as_deref(),
                "server",
            )?;
            if let Some(mtu) = s.mtu {
                validate_mtu(mtu, "server")?;
            }
        }

        Ok(())
    }
}

impl VpnClientConfig {
    pub fn settings(&self) -> Option<&VpnClientSettings> {
        self.client.as_ref()
    }

    pub fn validate(&self, test_mode: bool) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnclient\"")?;
        let expected = if test_mode {
            Role::TestVpnClient
        } else {
            Role::VpnClient
        };
        if role != expected {
            if test_mode {
                anyhow::bail!(
                    "Config file has wrong role for a test-mode client. Expected role = \"testvpnclient\" (running with --test-mode)"
                );
            } else {
                anyhow::bail!(
                    "Config file has wrong role for client. Expected role = \"vpnclient\" (use --test-mode for role = \"testvpnclient\")"
                );
            }
        }

        if let Some(ref c) = self.client {
            if let Some(ref server_addr) = c.server_addr {
                parse_loopback_addr(server_addr, "client", "server_addr", test_mode)?;
            }
            if let Some(ref routes) = c.routes {
                for route in routes {
                    validate_cidr(route)
                        .with_context(|| format!("[client] Invalid route CIDR '{}'", route))?;
                }
            }
            if let Some(ref routes6) = c.routes6 {
                for route6 in routes6 {
                    validate_ipv6_cidr(route6)
                        .with_context(|| route6_context(route6, Some("client")))?;
                }
            }
        }

        Ok(())
    }
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    } else if path_str == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    path.to_path_buf()
}

fn load_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

fn default_vpn_server_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("vpn-rs").join("vpn_server.toml"))
}

fn default_vpn_client_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("vpn-rs").join("vpn_client.toml"))
}

pub fn load_vpn_server_config(path: Option<&Path>) -> Result<VpnServerConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_vpn_server_config_path().ok_or_else(|| {
            anyhow::anyhow!(
                "Could not resolve default config path. Use -c to specify a config file."
            )
        })?,
    };
    load_config(&config_path)
}

pub fn load_vpn_client_config(path: Option<&Path>) -> Result<VpnClientConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_vpn_client_config_path().ok_or_else(|| {
            anyhow::anyhow!(
                "Could not resolve default config path. Use -c to specify a config file."
            )
        })?,
    };
    load_config(&config_path)
}

#[derive(Debug, Clone)]
pub struct ResolvedVpnServerConfig {
    pub listen: SocketAddr,
    pub network: Option<String>,
    pub server_ip: Option<String>,
    pub network6: Option<String>,
    pub server_ip6: Option<String>,
    pub mtu: u16,
    pub max_clients: usize,
    pub client_timeout: Duration,
    pub max_datagram_size: usize,
    pub drop_on_full: bool,
    pub client_channel_size: usize,
    pub tun_writer_channel_size: usize,
    pub disable_spoofing_check: bool,
    /// Test mode: non-loopback `listen` allowed (set via `--test-mode`).
    pub test_mode: bool,
}

impl ResolvedVpnServerConfig {
    pub fn from_config(cfg: &VpnServerSettings, test_mode: bool) -> Result<Self> {
        let listen = parse_loopback_addr(
            cfg.listen.as_deref().unwrap_or(DEFAULT_LISTEN_ADDR),
            "server",
            "listen",
            test_mode,
        )?;

        validate_vpn_networks(
            cfg.network.as_deref(),
            cfg.server_ip.as_deref(),
            cfg.network6.as_deref(),
            cfg.server_ip6.as_deref(),
            "server",
        )?;

        let mtu = cfg.mtu.unwrap_or(DEFAULT_VPN_MTU);
        validate_mtu(mtu, "server")?;

        let max_clients = cfg.max_clients.unwrap_or(DEFAULT_MAX_CLIENTS);
        if max_clients == 0 {
            anyhow::bail!("[server] max_clients must be at least 1");
        }

        let client_channel_size = cfg
            .client_channel_size
            .unwrap_or(DEFAULT_CLIENT_CHANNEL_SIZE);
        validate_channel_size(client_channel_size, "client_channel_size", "server")?;

        let tun_writer_channel_size = cfg
            .tun_writer_channel_size
            .unwrap_or(DEFAULT_TUN_WRITER_CHANNEL_SIZE);
        validate_channel_size(tun_writer_channel_size, "tun_writer_channel_size", "server")?;

        let client_timeout = match cfg.client_timeout_secs {
            Some(secs) => {
                if secs < 15 {
                    anyhow::bail!(
                        "[server] client_timeout_secs must be at least 15 (clients heartbeat every 10s)"
                    );
                }
                Duration::from_secs(secs)
            }
            None => DEFAULT_CLIENT_TIMEOUT,
        };

        let max_datagram_size = cfg.max_datagram_size.unwrap_or(MAX_DATAGRAM_PAYLOAD);
        if !(MIN_DATAGRAM_SIZE..=MAX_DATAGRAM_PAYLOAD).contains(&max_datagram_size) {
            anyhow::bail!(
                "[server] max_datagram_size {} is out of range ({}..={})",
                max_datagram_size,
                MIN_DATAGRAM_SIZE,
                MAX_DATAGRAM_PAYLOAD
            );
        }

        Ok(Self {
            listen,
            network: cfg.network.clone(),
            server_ip: cfg.server_ip.clone(),
            network6: cfg.network6.clone(),
            server_ip6: cfg.server_ip6.clone(),
            mtu,
            max_clients,
            client_timeout,
            max_datagram_size,
            drop_on_full: cfg.drop_on_full,
            client_channel_size,
            tun_writer_channel_size,
            disable_spoofing_check: cfg.disable_spoofing_check,
            test_mode,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedVpnClientConfig {
    pub server_addr: SocketAddr,
    pub routes: Vec<String>,
    pub routes6: Vec<String>,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: Option<NonZeroU32>,
    /// Test mode: non-loopback `server_addr` allowed (set via `--test-mode`).
    pub test_mode: bool,
    /// Test-mode token sent in the handshake (set via `--test-token`).
    pub test_token: Option<String>,
}

#[derive(Default)]
pub struct VpnClientConfigBuilder {
    server_addr: Option<String>,
    routes: Option<Vec<String>>,
    routes6: Option<Vec<String>>,
    auto_reconnect: Option<bool>,
    max_reconnect_attempts: Option<NonZeroU32>,
    test_mode: bool,
    test_token: Option<String>,
}

impl VpnClientConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_defaults(mut self) -> Self {
        self.routes = Some(vec![]);
        self.routes6 = Some(vec![]);
        self
    }

    pub fn apply_config(mut self, config: Option<&VpnClientSettings>) -> Self {
        if let Some(cfg) = config {
            if cfg.server_addr.is_some() {
                self.server_addr = cfg.server_addr.clone();
            }
            if cfg.routes.is_some() {
                self.routes = cfg.routes.clone();
            }
            if cfg.routes6.is_some() {
                self.routes6 = cfg.routes6.clone();
            }
            if cfg.auto_reconnect.is_some() {
                self.auto_reconnect = cfg.auto_reconnect;
            }
            if cfg.max_reconnect_attempts.is_some() {
                self.max_reconnect_attempts = cfg.max_reconnect_attempts;
            }
        }
        self
    }

    pub fn apply_cli(
        mut self,
        server_addr: Option<String>,
        routes: Vec<String>,
        routes6: Vec<String>,
        auto_reconnect: Option<bool>,
        max_reconnect_attempts: Option<NonZeroU32>,
    ) -> Self {
        if server_addr.is_some() {
            self.server_addr = server_addr;
        }
        if !routes.is_empty() {
            self.routes = Some(routes);
        }
        if !routes6.is_empty() {
            self.routes6 = Some(routes6);
        }
        if auto_reconnect.is_some() {
            self.auto_reconnect = auto_reconnect;
        }
        if max_reconnect_attempts.is_some() {
            self.max_reconnect_attempts = max_reconnect_attempts;
        }
        self
    }

    /// Apply test-mode settings (only set via `--test-mode` / `--test-token`).
    pub fn apply_test_mode(mut self, test_mode: bool, test_token: Option<String>) -> Self {
        self.test_mode = test_mode;
        self.test_token = test_token;
        self
    }

    pub fn build(self) -> Result<ResolvedVpnClientConfig> {
        let server_addr = parse_loopback_addr(
            self.server_addr.as_deref().unwrap_or(DEFAULT_LISTEN_ADDR),
            "client",
            "server_addr",
            self.test_mode,
        )?;

        let routes = self.routes.unwrap_or_default();
        for route in &routes {
            validate_cidr(route)
                .with_context(|| format!("Invalid route CIDR '{}' (e.g., 0.0.0.0/0)", route))?;
        }

        let routes6 = self.routes6.unwrap_or_default();
        for route6 in &routes6 {
            validate_ipv6_cidr(route6).with_context(|| route6_context(route6, Some("config")))?;
        }

        Ok(ResolvedVpnClientConfig {
            server_addr,
            routes,
            routes6,
            auto_reconnect: self.auto_reconnect.unwrap_or(true),
            max_reconnect_attempts: self.max_reconnect_attempts,
            test_mode: self.test_mode,
            test_token: self.test_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_toml(extra: &str) -> String {
        format!(
            r#"
role = "vpnserver"

[server]
network6 = "fd00::/64"
{extra}
"#
        )
    }

    #[test]
    fn test_server_config_defaults_listen_to_loopback() {
        let config: VpnServerConfig = toml::from_str(&server_toml("")).unwrap();
        assert!(config.validate(false).is_ok());
        let resolved =
            ResolvedVpnServerConfig::from_config(config.settings().unwrap(), false).unwrap();
        assert_eq!(resolved.listen.to_string(), DEFAULT_LISTEN_ADDR);
        assert_eq!(resolved.max_datagram_size, MAX_DATAGRAM_PAYLOAD);
        assert_eq!(resolved.client_timeout, DEFAULT_CLIENT_TIMEOUT);
    }

    #[test]
    fn test_server_config_rejects_non_loopback_listen() {
        let config: VpnServerConfig =
            toml::from_str(&server_toml(r#"listen = "0.0.0.0:5555""#)).unwrap();
        let err = config.validate(false).unwrap_err().to_string();
        assert!(err.contains("not loopback"), "unexpected error: {err}");
    }

    #[test]
    fn test_server_config_reads_mtu_and_listen() {
        let config: VpnServerConfig = toml::from_str(&server_toml(
            "listen = \"127.0.0.1:6000\"\nmtu = 1400\nmax_datagram_size = 1400",
        ))
        .unwrap();
        let resolved =
            ResolvedVpnServerConfig::from_config(config.settings().unwrap(), false).unwrap();
        assert_eq!(resolved.mtu, 1400);
        assert_eq!(resolved.listen.port(), 6000);
        assert_eq!(resolved.max_datagram_size, 1400);
    }

    #[test]
    fn test_server_config_rejects_short_client_timeout() {
        let config: VpnServerConfig =
            toml::from_str(&server_toml("client_timeout_secs = 5")).unwrap();
        let err = ResolvedVpnServerConfig::from_config(config.settings().unwrap(), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("client_timeout_secs"));
    }

    #[test]
    fn test_client_config_parses_and_resolves() {
        let config: VpnClientConfig = toml::from_str(
            r#"
role = "vpnclient"

[client]
server_addr = "127.0.0.1:6000"
routes = ["0.0.0.0/0"]
routes6 = ["::/0"]
auto_reconnect = false
"#,
        )
        .unwrap();
        config.validate(false).unwrap();
        let settings = config.settings().unwrap();
        let resolved = VpnClientConfigBuilder::new()
            .apply_defaults()
            .apply_config(Some(settings))
            .build()
            .unwrap();
        assert_eq!(resolved.server_addr.port(), 6000);
        assert_eq!(resolved.routes, ["0.0.0.0/0"]);
        assert_eq!(resolved.routes6, ["::/0"]);
        assert!(!resolved.auto_reconnect);
    }

    #[test]
    fn test_client_config_rejects_non_loopback_server_addr() {
        let config: VpnClientConfig = toml::from_str(
            r#"
role = "vpnclient"

[client]
server_addr = "192.0.2.1:5555"
"#,
        )
        .unwrap();
        let err = config.validate(false).unwrap_err().to_string();
        assert!(err.contains("not loopback"), "unexpected error: {err}");
    }

    #[test]
    fn test_client_builder_cli_overrides_config() {
        let resolved = VpnClientConfigBuilder::new()
            .apply_defaults()
            .apply_cli(
                Some("127.0.0.1:7000".to_string()),
                vec!["10.0.0.0/8".to_string()],
                vec![],
                Some(false),
                None,
            )
            .build()
            .unwrap();
        assert_eq!(resolved.server_addr.port(), 7000);
        assert_eq!(resolved.routes, ["10.0.0.0/8"]);
        assert!(!resolved.auto_reconnect);
    }

    #[test]
    fn test_server_test_mode_requires_test_role() {
        // Normal role with --test-mode is rejected.
        let config: VpnServerConfig = toml::from_str(&server_toml("")).unwrap();
        let err = config.validate(true).unwrap_err().to_string();
        assert!(err.contains("testvpnserver"), "unexpected error: {err}");
    }

    #[test]
    fn test_server_test_role_requires_test_mode() {
        // Test role without --test-mode is rejected.
        let toml_str = r#"
role = "testvpnserver"

[server]
network6 = "fd00::/64"
"#;
        let config: VpnServerConfig = toml::from_str(toml_str).unwrap();
        let err = config.validate(false).unwrap_err().to_string();
        assert!(err.contains("vpnserver"), "unexpected error: {err}");
    }

    #[test]
    fn test_server_test_mode_allows_non_loopback_listen() {
        let toml_str = r#"
role = "testvpnserver"

[server]
network6 = "fd00::/64"
listen = "0.0.0.0:5555"
"#;
        let config: VpnServerConfig = toml::from_str(toml_str).unwrap();
        config.validate(true).expect("test-mode server should validate");
        let resolved =
            ResolvedVpnServerConfig::from_config(config.settings().unwrap(), true).unwrap();
        assert!(resolved.test_mode);
        assert_eq!(resolved.listen.to_string(), "0.0.0.0:5555");
    }

    #[test]
    fn test_client_test_mode_requires_test_role() {
        let toml_str = r#"
role = "vpnclient"

[client]
server_addr = "127.0.0.1:6000"
"#;
        let config: VpnClientConfig = toml::from_str(toml_str).unwrap();
        let err = config.validate(true).unwrap_err().to_string();
        assert!(err.contains("testvpnclient"), "unexpected error: {err}");
    }

    #[test]
    fn test_client_test_role_requires_test_mode() {
        // Test role without --test-mode is rejected.
        let toml_str = r#"
role = "testvpnclient"

[client]
server_addr = "127.0.0.1:6000"
"#;
        let config: VpnClientConfig = toml::from_str(toml_str).unwrap();
        let err = config.validate(false).unwrap_err().to_string();
        assert!(err.contains("vpnclient"), "unexpected error: {err}");
    }

    #[test]
    fn test_client_test_mode_allows_non_loopback_and_carries_token() {
        let toml_str = r#"
role = "testvpnclient"

[client]
server_addr = "192.0.2.1:5555"
"#;
        let config: VpnClientConfig = toml::from_str(toml_str).unwrap();
        config.validate(true).expect("test-mode client should validate");
        let resolved = VpnClientConfigBuilder::new()
            .apply_defaults()
            .apply_config(config.settings())
            .apply_test_mode(true, Some("the-token".to_string()))
            .build()
            .unwrap();
        assert!(resolved.test_mode);
        assert_eq!(resolved.server_addr.to_string(), "192.0.2.1:5555");
        assert_eq!(resolved.test_token.as_deref(), Some("the-token"));
    }
}
