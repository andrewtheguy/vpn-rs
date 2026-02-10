//! VPN-specific configuration support for vpn-rs.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[serde(rename = "vpnserver")]
    VpnServer,
    #[serde(rename = "vpnclient")]
    VpnClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Iroh,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Iroh => "iroh",
        }
    }
}

/// Congestion controller algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionController {
    /// CUBIC - default loss-based controller.
    #[default]
    Cubic,
    /// BBR model-based controller.
    Bbr,
    /// NewReno classic TCP-like controller.
    #[serde(alias = "new_reno")]
    NewReno,
}

/// Default QUIC receive window size (8 MB).
pub const DEFAULT_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;

/// Transport tuning for QUIC connections.
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
pub struct TransportTuning {
    #[serde(default)]
    pub congestion_controller: CongestionController,
    pub receive_window: Option<u32>,
    pub send_window: Option<u32>,
}

/// Shared VPN iroh configuration fields (used by both server and client).
#[derive(Deserialize, Default, Clone)]
pub struct VpnIrohSharedConfig {
    pub mtu: Option<u16>,
    pub relay_urls: Option<Vec<String>>,
    pub dns_server: Option<String>,
    #[serde(default)]
    pub transport: TransportTuning,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnServerIrohConfig {
    pub network: Option<String>,
    pub server_ip: Option<String>,
    pub network6: Option<String>,
    pub server_ip6: Option<String>,
    pub secret_file: Option<PathBuf>,
    pub auth_tokens: Option<Vec<String>>,
    pub auth_tokens_file: Option<PathBuf>,
    #[serde(default = "default_drop_on_full")]
    pub drop_on_full: bool,
    pub client_channel_size: Option<usize>,
    pub tun_writer_channel_size: Option<usize>,
    #[serde(default)]
    pub disable_spoofing_check: bool,
    #[serde(flatten)]
    pub shared: VpnIrohSharedConfig,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnClientIrohConfig {
    pub server_node_id: Option<String>,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
    pub routes: Option<Vec<String>>,
    pub routes6: Option<Vec<String>>,
    pub auto_reconnect: Option<bool>,
    pub max_reconnect_attempts: Option<NonZeroU32>,
    #[serde(flatten)]
    pub shared: VpnIrohSharedConfig,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnServerConfig {
    pub role: Option<Role>,
    pub mode: Option<Mode>,
    pub iroh: Option<VpnServerIrohConfig>,
}

#[derive(Deserialize, Default, Clone)]
pub struct VpnClientConfig {
    pub role: Option<Role>,
    pub mode: Option<Mode>,
    pub iroh: Option<VpnClientIrohConfig>,
}

/// Default MTU for VPN packets (1500 - ~60 bytes overhead).
pub const DEFAULT_VPN_MTU: u16 = 1440;

/// Default channel buffer size for outbound packets to each client.
pub const DEFAULT_CLIENT_CHANNEL_SIZE: usize = 1024;

/// Default channel buffer size for TUN writer task.
pub const DEFAULT_TUN_WRITER_CHANNEL_SIZE: usize = 512;

/// Minimum QUIC window size (1 KB).
const MIN_WINDOW_SIZE: u32 = 1024;

/// Maximum QUIC window size (16 MB).
const MAX_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

fn validate_window_size(size: u32, field_name: &str, section: &str) -> Result<()> {
    if size < MIN_WINDOW_SIZE {
        anyhow::bail!(
            "[{}] {} value {} is below minimum of {} bytes (1KB)",
            section,
            field_name,
            size,
            MIN_WINDOW_SIZE
        );
    }
    if size > MAX_WINDOW_SIZE {
        anyhow::bail!(
            "[{}] {} value {} exceeds maximum of {} bytes (16MB)",
            section,
            field_name,
            size,
            MAX_WINDOW_SIZE
        );
    }
    Ok(())
}

pub fn validate_transport_tuning(tuning: &TransportTuning, section: &str) -> Result<()> {
    if let Some(recv) = tuning.receive_window {
        validate_window_size(recv, "receive_window", section)?;
    }
    if let Some(send) = tuning.send_window {
        validate_window_size(send, "send_window", section)?;
    }
    Ok(())
}

fn validate_mtu(mtu: u16, section: &str) -> Result<()> {
    if !(576..=1500).contains(&mtu) {
        anyhow::bail!(
            "[{}] MTU {} is out of range. Valid range: 576-1500",
            section,
            mtu
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

fn validate_vpn_network(
    network: &str,
    server_ip: Option<&str>,
    section: &str,
) -> Result<ipnet::Ipv4Net> {
    let net: ipnet::Ipv4Net = network.parse().with_context(|| {
        format!(
            "[{}] Invalid network CIDR '{}'. Expected format: 10.0.0.0/24",
            section, network
        )
    })?;

    if let Some(server_ip_str) = server_ip {
        let server_ip: std::net::Ipv4Addr = server_ip_str.parse().with_context(|| {
            format!(
                "[{}] Invalid server_ip '{}'. Expected IPv4 address",
                section, server_ip_str
            )
        })?;
        if !net.contains(&server_ip) {
            anyhow::bail!(
                "[{}] server_ip '{}' is not within network '{}'",
                section,
                server_ip,
                network
            );
        }
    }

    Ok(net)
}

fn validate_vpn_network6(
    network6: &str,
    server_ip6: Option<&str>,
    section: &str,
) -> Result<ipnet::Ipv6Net> {
    let net: ipnet::Ipv6Net = network6.parse().with_context(|| {
        format!(
            "[{}] Invalid network6 CIDR '{}'. Expected format: fd00::/64",
            section, network6
        )
    })?;

    if let Some(server_ip6_str) = server_ip6 {
        let server_ip6: std::net::Ipv6Addr = server_ip6_str.parse().with_context(|| {
            format!(
                "[{}] Invalid server_ip6 '{}'. Expected IPv6 address",
                section, server_ip6_str
            )
        })?;
        if !net.contains(&server_ip6) {
            anyhow::bail!(
                "[{}] server_ip6 '{}' is not within network6 '{}'",
                section,
                server_ip6,
                network6
            );
        }
    }

    Ok(net)
}

fn validate_vpn_networks(
    network: Option<&str>,
    server_ip: Option<&str>,
    network6: Option<&str>,
    server_ip6: Option<&str>,
    section: &str,
) -> Result<()> {
    if network.is_none() && network6.is_none() {
        anyhow::bail!(
            "[{}] At least one of 'network' (IPv4) or 'network6' (IPv6) is required.",
            section
        );
    }

    if server_ip.is_some() && network.is_none() {
        anyhow::bail!("[{}] 'server_ip' requires 'network' to be set.", section);
    }
    if let Some(net) = network {
        validate_vpn_network(net, server_ip, section)?;
    }

    if server_ip6.is_some() && network6.is_none() {
        anyhow::bail!("[{}] 'server_ip6' requires 'network6' to be set.", section);
    }
    if let Some(net6) = network6 {
        validate_vpn_network6(net6, server_ip6, section)?;
    }

    Ok(())
}

fn default_drop_on_full() -> bool {
    false
}

impl VpnServerConfig {
    pub fn iroh(&self) -> Option<&VpnServerIrohConfig> {
        self.iroh.as_ref()
    }

    pub fn validate(&self) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnserver\"")?;
        if role != Role::VpnServer {
            anyhow::bail!("Config file has wrong role for server. Expected role = \"vpnserver\"");
        }

        let mode = self
            .mode
            .context("Config file missing required 'mode' field. Add: mode = \"iroh\"")?;
        if mode != Mode::Iroh {
            anyhow::bail!(
                "Config file has mode = '{}' but this binary only supports iroh mode",
                mode.as_str()
            );
        }

        if let Some(ref iroh) = self.iroh {
            if iroh.secret_file.is_none() {
                anyhow::bail!(
                    "[iroh] 'secret_file' is required for server identity. Generate with: vpn-rs generate-server-key -o ./vpn-server.key"
                );
            }

            let has_inline_tokens = iroh.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
            if has_inline_tokens && iroh.auth_tokens_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'auth_tokens' or 'auth_tokens_file'.");
            }

            validate_vpn_networks(
                iroh.network.as_deref(),
                iroh.server_ip.as_deref(),
                iroh.network6.as_deref(),
                iroh.server_ip6.as_deref(),
                "iroh",
            )?;

            if let Some(mtu) = iroh.shared.mtu {
                validate_mtu(mtu, "iroh")?;
            }
        }

        Ok(())
    }
}

impl VpnClientConfig {
    pub fn iroh(&self) -> Option<&VpnClientIrohConfig> {
        self.iroh.as_ref()
    }

    pub fn validate(&self) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnclient\"")?;
        if role != Role::VpnClient {
            anyhow::bail!("Config file has wrong role for client. Expected role = \"vpnclient\"");
        }

        let mode = self
            .mode
            .context("Config file missing required 'mode' field. Add: mode = \"iroh\"")?;
        if mode != Mode::Iroh {
            anyhow::bail!(
                "Config file has mode = '{}' but this binary only supports iroh mode",
                mode.as_str()
            );
        }

        if let Some(ref iroh) = self.iroh {
            if iroh.server_node_id.is_none() {
                anyhow::bail!("[iroh] 'server_node_id' is required for client config.");
            }

            if iroh.auth_token.is_some() && iroh.auth_token_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'auth_token' or 'auth_token_file'.");
            }

            if let Some(ref routes) = iroh.routes {
                for route in routes {
                    validate_cidr(route)
                        .with_context(|| format!("[iroh] Invalid route CIDR '{}'", route))?;
                }
            }

            if let Some(ref routes6) = iroh.routes6 {
                for route6 in routes6 {
                    validate_ipv6_cidr(route6)
                        .with_context(|| route6_context(route6, Some("iroh")))?;
                }
            }

            if let Some(mtu) = iroh.shared.mtu {
                validate_mtu(mtu, "iroh")?;
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
    } else if path_str == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
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
    pub network: Option<String>,
    pub server_ip: Option<String>,
    pub network6: Option<String>,
    pub server_ip6: Option<String>,
    pub mtu: u16,
    pub secret_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub auth_tokens: Vec<String>,
    pub auth_tokens_file: Option<PathBuf>,
    pub drop_on_full: bool,
    pub client_channel_size: usize,
    pub tun_writer_channel_size: usize,
    pub transport: TransportTuning,
    pub disable_spoofing_check: bool,
}

impl ResolvedVpnServerConfig {
    pub fn from_config(cfg: &VpnServerIrohConfig) -> Result<Self> {
        if cfg.secret_file.is_none() {
            anyhow::bail!(
                "[config] 'secret_file' is required for server identity. Generate with: vpn-rs generate-server-key -o ./vpn-server.key"
            );
        }

        validate_vpn_networks(
            cfg.network.as_deref(),
            cfg.server_ip.as_deref(),
            cfg.network6.as_deref(),
            cfg.server_ip6.as_deref(),
            "config",
        )?;

        let mtu = cfg.shared.mtu.unwrap_or(DEFAULT_VPN_MTU);
        validate_mtu(mtu, "config")?;

        let has_tokens = cfg.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
        if has_tokens && cfg.auth_tokens_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_tokens and auth_tokens_file. Use exactly one source."
            );
        }

        let client_channel_size = cfg
            .client_channel_size
            .unwrap_or(DEFAULT_CLIENT_CHANNEL_SIZE);
        validate_channel_size(client_channel_size, "client_channel_size", "config")?;

        let tun_writer_channel_size = cfg
            .tun_writer_channel_size
            .unwrap_or(DEFAULT_TUN_WRITER_CHANNEL_SIZE);
        validate_channel_size(tun_writer_channel_size, "tun_writer_channel_size", "config")?;

        validate_transport_tuning(&cfg.shared.transport, "iroh.transport")?;

        Ok(Self {
            network: cfg.network.clone(),
            server_ip: cfg.server_ip.clone(),
            network6: cfg.network6.clone(),
            server_ip6: cfg.server_ip6.clone(),
            mtu,
            secret_file: cfg.secret_file.clone(),
            relay_urls: cfg.shared.relay_urls.clone().unwrap_or_default(),
            dns_server: cfg.shared.dns_server.clone(),
            auth_tokens: cfg.auth_tokens.clone().unwrap_or_default(),
            auth_tokens_file: cfg.auth_tokens_file.clone(),
            drop_on_full: cfg.drop_on_full,
            client_channel_size,
            tun_writer_channel_size,
            transport: cfg.shared.transport.clone(),
            disable_spoofing_check: cfg.disable_spoofing_check,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedVpnClientConfig {
    pub server_node_id: String,
    pub mtu: u16,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
    pub routes: Vec<String>,
    pub routes6: Vec<String>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: Option<NonZeroU32>,
    pub transport: TransportTuning,
}

#[derive(Default)]
pub struct VpnClientConfigBuilder {
    server_node_id: Option<String>,
    mtu: Option<u16>,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    routes: Option<Vec<String>>,
    routes6: Option<Vec<String>>,
    relay_urls: Option<Vec<String>>,
    dns_server: Option<String>,
    auto_reconnect: Option<bool>,
    max_reconnect_attempts: Option<NonZeroU32>,
    transport: Option<TransportTuning>,
}

impl VpnClientConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_defaults(mut self) -> Self {
        self.mtu = Some(DEFAULT_VPN_MTU);
        self.routes = Some(vec![]);
        self.routes6 = Some(vec![]);
        self.relay_urls = Some(vec![]);
        self
    }

    pub fn apply_config(mut self, config: Option<&VpnClientIrohConfig>) -> Self {
        if let Some(cfg) = config {
            if cfg.server_node_id.is_some() {
                self.server_node_id = cfg.server_node_id.clone();
            }
            if cfg.shared.mtu.is_some() {
                self.mtu = cfg.shared.mtu;
            }
            if cfg.auth_token.is_some() {
                self.auth_token = cfg.auth_token.clone();
            }
            if cfg.auth_token_file.is_some() {
                self.auth_token_file = cfg.auth_token_file.clone();
            }
            if cfg.routes.is_some() {
                self.routes = cfg.routes.clone();
            }
            if cfg.routes6.is_some() {
                self.routes6 = cfg.routes6.clone();
            }
            if cfg.shared.relay_urls.is_some() {
                self.relay_urls = cfg.shared.relay_urls.clone();
            }
            if cfg.shared.dns_server.is_some() {
                self.dns_server = cfg.shared.dns_server.clone();
            }
            if cfg.auto_reconnect.is_some() {
                self.auto_reconnect = cfg.auto_reconnect;
            }
            if cfg.max_reconnect_attempts.is_some() {
                self.max_reconnect_attempts = cfg.max_reconnect_attempts;
            }
            if cfg.shared.transport != TransportTuning::default() {
                self.transport = Some(cfg.shared.transport.clone());
            }
        }
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_cli(
        mut self,
        server_node_id: Option<String>,
        mtu: Option<u16>,
        auth_token: Option<String>,
        auth_token_file: Option<PathBuf>,
        routes: Vec<String>,
        routes6: Vec<String>,
        relay_urls: Vec<String>,
        dns_server: Option<String>,
        auto_reconnect: Option<bool>,
        max_reconnect_attempts: Option<NonZeroU32>,
    ) -> Self {
        if server_node_id.is_some() {
            self.server_node_id = server_node_id;
        }
        if mtu.is_some() {
            self.mtu = mtu;
        }
        if auth_token.is_some() {
            self.auth_token = auth_token;
        }
        if auth_token_file.is_some() {
            self.auth_token_file = auth_token_file;
        }
        if !routes.is_empty() {
            self.routes = Some(routes);
        }
        if !routes6.is_empty() {
            self.routes6 = Some(routes6);
        }
        if !relay_urls.is_empty() {
            self.relay_urls = Some(relay_urls);
        }
        if dns_server.is_some() {
            self.dns_server = dns_server;
        }
        if auto_reconnect.is_some() {
            self.auto_reconnect = auto_reconnect;
        }
        if max_reconnect_attempts.is_some() {
            self.max_reconnect_attempts = max_reconnect_attempts;
        }
        self
    }

    pub fn build(self) -> Result<ResolvedVpnClientConfig> {
        let server_node_id = self.server_node_id.ok_or_else(|| {
            anyhow::anyhow!(
                "Server node ID is required. Provide --server-node-id or set server_node_id in config."
            )
        })?;

        let mtu = self.mtu.unwrap_or(DEFAULT_VPN_MTU);
        validate_mtu(mtu, "config")?;

        let routes = self.routes.unwrap_or_default();
        for route in &routes {
            validate_cidr(route)
                .with_context(|| format!("Invalid route CIDR '{}' (e.g., 0.0.0.0/0)", route))?;
        }

        let routes6 = self.routes6.unwrap_or_default();
        for route6 in &routes6 {
            validate_ipv6_cidr(route6).with_context(|| route6_context(route6, Some("config")))?;
        }

        if self.auth_token.is_some() && self.auth_token_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_token and auth_token_file. Use one source for auth."
            );
        }

        if let Some(ref transport) = self.transport {
            validate_transport_tuning(transport, "iroh.transport")?;
        }

        Ok(ResolvedVpnClientConfig {
            server_node_id,
            mtu,
            auth_token: self.auth_token,
            auth_token_file: self.auth_token_file,
            routes,
            routes6,
            relay_urls: self.relay_urls.unwrap_or_default(),
            dns_server: self.dns_server,
            auto_reconnect: self.auto_reconnect.unwrap_or(true),
            max_reconnect_attempts: self.max_reconnect_attempts,
            transport: self.transport.unwrap_or_default(),
        })
    }
}
