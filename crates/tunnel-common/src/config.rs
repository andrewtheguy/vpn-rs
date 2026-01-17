//! Configuration file support for tunnel-rs.
//!
//! Configuration structure:
//! - `role` and `mode` fields for validation
//! - Mode-specific sections: [iroh], [manual], [nostr]
//! - All modes use client-initiated source requests
//!
//! Role-based field semantics are enforced by `validate()` at parse time:
//! - Server-only fields are rejected when role=client
//! - Client-only fields are rejected when role=server
//! - CIDR networks and source URLs are validated for correct format

use anyhow::{Context, Result};
use serde::Deserialize;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

// ============================================================================
// Configuration Structures
// ============================================================================

/// iroh mode configuration (multi-source).
///
/// Some fields are role-specific (enforced by validate()):
/// - Server-only: `allowed_sources`, `max_sessions`, `auth_tokens`, `auth_tokens_file`, `secret`, `secret_file`
/// - Client-only: `request_source`, `target`, `server_node_id`, `auth_token`, `auth_token_file`
#[derive(Deserialize, Default, Clone)]
pub struct IrohConfig {
    /// Path to secret key file for persistent server identity (server only)
    pub secret_file: Option<PathBuf>,
    /// Base64-encoded secret key for persistent server identity (server only).
    /// Prefer `secret_file` in production; inline secrets are best kept to testing or
    /// special cases due to VCS/log exposure risk. Secret files should be 0600 on Unix.
    pub secret: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub dns_server: Option<String>,
    /// NodeId of the server to connect to (client only)
    pub server_node_id: Option<String>,
    /// Allowed source networks in CIDR notation (server only).
    /// Clients must request sources within these networks.
    pub allowed_sources: Option<AllowedSources>,
    /// Maximum concurrent sessions (server only, default: 100)
    pub max_sessions: Option<usize>,
    /// Authentication tokens (server only).
    /// Clients must provide one of these tokens to authenticate.
    /// Prefer `auth_tokens_file` in production; inline tokens are best kept to testing or
    /// special cases due to VCS/log exposure risk.
    pub auth_tokens: Option<Vec<String>>,
    /// Path to file containing authentication tokens (server only).
    /// One token per line, # comments allowed.
    pub auth_tokens_file: Option<PathBuf>,
    /// Authentication token to send to server (client only).
    /// Prefer `auth_token_file` in production to avoid exposing tokens in config files.
    pub auth_token: Option<String>,
    /// Path to file containing authentication token (client only).
    pub auth_token_file: Option<PathBuf>,
    /// Source URL to request from server (client only).
    /// Format: tcp://host:port or udp://host:port
    #[serde(alias = "source")]
    pub request_source: Option<String>,
    /// Local address to listen on (client only).
    /// Format: host:port
    pub target: Option<String>,
    /// Transport layer tuning (congestion control, buffer sizes).
    #[serde(default)]
    pub transport: TransportTuning,
}

/// manual mode configuration.
///
/// Some fields are role-specific (enforced by validate()):
/// - Server-only: `allowed_sources`
/// - Client-only: `request_source`, `target`
#[derive(Deserialize, Default, Clone)]
pub struct CustomManualConfig {
    pub stun_servers: Option<Vec<String>>,
    /// Allowed source networks in CIDR notation (server only).
    /// Clients must request sources within these networks.
    pub allowed_sources: Option<AllowedSources>,
    /// Source URL to request from server (client only, required).
    /// Format: tcp://host:port or udp://host:port
    #[serde(alias = "source")]
    pub request_source: Option<String>,
    /// Local address to listen on (client only, required).
    /// Format: host:port (no protocol prefix)
    pub target: Option<String>,
}

/// Allowed source networks for client-requested source feature.
/// Separate CIDR lists for TCP and UDP protocols.
#[derive(Deserialize, Default, Clone)]
pub struct AllowedSources {
    /// Allowed TCP source networks (CIDR notation, e.g., "127.0.0.0/8", "::1/128")
    #[serde(default)]
    pub tcp: Vec<String>,
    /// Allowed UDP source networks (CIDR notation)
    #[serde(default)]
    pub udp: Vec<String>,
}

/// nostr mode configuration (TOML section: `[nostr]`).
///
/// nostr provides full ICE with automated Nostr relay signaling for static peer key exchange.
///
/// Some fields are role-specific (enforced by validate()):
/// - Server-only: `allowed_sources`, `max_sessions`
/// - Client-only: `request_source`, `target`
#[derive(Deserialize, Default, Clone)]
pub struct NostrConfig {
    /// Nostr relay URLs for signaling
    pub relays: Option<Vec<String>>,
    /// Your Nostr private key (nsec or hex)
    pub nsec: Option<String>,
    /// Path to file containing your Nostr private key (nsec or hex)
    pub nsec_file: Option<PathBuf>,
    /// Peer's Nostr public key (npub or hex)
    pub peer_npub: Option<String>,
    /// STUN servers for ICE candidate gathering
    pub stun_servers: Option<Vec<String>>,
    /// Maximum concurrent sessions (server only, default: 10)
    pub max_sessions: Option<usize>,
    /// Allowed source networks in CIDR notation (server only).
    /// Clients must request sources within these networks.
    pub allowed_sources: Option<AllowedSources>,
    /// Source URL to request from server (client only, required).
    /// Format: tcp://host:port or udp://host:port
    #[serde(alias = "source")]
    pub request_source: Option<String>,
    /// Local address to listen on (client only, required).
    /// Format: host:port (no protocol prefix)
    pub target: Option<String>,
}

/// NAT64 configuration for IPv6-only clients to access IPv4 resources.
///
/// When enabled, the VPN server translates IPv6 packets destined for the
/// well-known NAT64 prefix `64:ff9b::/96` to IPv4 packets, performs NAPT
/// (Network Address Port Translation), and routes them to the IPv4 destination.
///
/// Note: The NAT64 prefix is fixed at `64:ff9b::/96` (RFC 6052 well-known prefix).
#[derive(Deserialize, Default, Clone, Debug)]
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
    #[serde(default)]
    pub source_ip: Option<std::net::Ipv4Addr>,

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

fn default_nat64_port_range() -> (u16, u16) {
    (32768, 65535)
}

impl Nat64Config {
    /// Validate the NAT64 configuration.
    ///
    /// Returns an error if:
    /// - `port_range.0 > port_range.1` (start port greater than end port)
    /// - `port_range.0 == 0` (port 0 is reserved and cannot be used)
    /// - Any timeout value is 0 (tcp_timeout_secs, udp_timeout_secs, icmp_timeout_secs)
    pub fn validate(&self) -> Result<()> {
        if self.port_range.0 == 0 {
            anyhow::bail!(
                "[nat64] port_range start must be > 0 (port 0 is reserved)"
            );
        }
        if self.port_range.0 > self.port_range.1 {
            anyhow::bail!(
                "[nat64] port_range start ({}) must be <= end ({})",
                self.port_range.0,
                self.port_range.1
            );
        }
        if self.tcp_timeout_secs == 0 {
            anyhow::bail!("[nat64] tcp_timeout_secs must be > 0");
        }
        if self.udp_timeout_secs == 0 {
            anyhow::bail!("[nat64] udp_timeout_secs must be > 0");
        }
        if self.icmp_timeout_secs == 0 {
            anyhow::bail!("[nat64] icmp_timeout_secs must be > 0");
        }
        Ok(())
    }
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

/// Shared VPN iroh configuration fields (used by both server and client).
#[derive(Deserialize, Default, Clone)]
pub struct VpnIrohSharedConfig {
    /// MTU for VPN packets (576-1500, default: 1440)
    pub mtu: Option<u16>,
    /// Custom relay server URLs.
    /// - `None`: not specified (use defaults or CLI)
    /// - `Some([])`: explicitly cleared (override defaults)
    /// - `Some([...])`: custom relay URLs
    pub relay_urls: Option<Vec<String>>,
    /// Custom DNS server URL for peer discovery
    pub dns_server: Option<String>,
    /// Transport layer tuning (congestion control, buffer sizes).
    #[serde(default)]
    pub transport: TransportTuning,
}

/// VPN server iroh configuration (TOML section: `[iroh]` in vpn_server.toml).
///
/// VPN mode uses iroh for P2P connectivity with TLS 1.3/QUIC encryption.
#[derive(Deserialize, Default, Clone)]
pub struct VpnServerIrohConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24")
    pub network: Option<String>,
    /// Server's VPN IP address within the network (defaults to first IP)
    pub server_ip: Option<String>,
    /// IPv6 VPN network CIDR (e.g., "fd00::/64"). Optional for dual-stack.
    pub network6: Option<String>,
    /// Server's IPv6 VPN address within the network (defaults to first IP)
    pub server_ip6: Option<String>,
    /// Path to secret key file for persistent server identity
    pub secret_file: Option<PathBuf>,
    /// Authentication tokens.
    /// - `None`: not specified (use defaults or CLI)
    /// - `Some([])`: explicitly cleared (no auth required)
    /// - `Some([...])`: required tokens
    pub auth_tokens: Option<Vec<String>>,
    /// Path to file containing authentication tokens
    pub auth_tokens_file: Option<PathBuf>,
    /// Drop packets when a client's buffer is full (default: false).
    /// - `true`: Drop packets for slow clients (avoids head-of-line blocking)
    /// - `false`: Apply backpressure (blocks TUN reader until space available)
    #[serde(default = "default_drop_on_full")]
    pub drop_on_full: bool,
    /// Channel buffer size for outbound packets to each client (default: 1024).
    /// Controls how many packets can be queued per client before backpressure/drops.
    pub client_channel_size: Option<usize>,
    /// Channel buffer size for TUN writer task (default: 512).
    /// Aggregate buffer for all client -> TUN traffic. Lower values bound memory usage.
    pub tun_writer_channel_size: Option<usize>,
    /// NAT64 configuration for IPv6-only clients to access IPv4 resources.
    /// When enabled, clients can access IPv4 addresses via the `64:ff9b::/96` prefix.
    pub nat64: Option<Nat64Config>,
    /// Disable source IP spoofing checks (default: false).
    /// When false, only packets with source IPs that don't belong to other clients are allowed.
    /// When true, all source IP validation is disabled.
    #[serde(default)]
    pub disable_spoofing_check: bool,
    /// Shared configuration fields
    #[serde(flatten)]
    pub shared: VpnIrohSharedConfig,
}

/// VPN client iroh configuration (TOML section: `[iroh]` in vpn_client.toml).
#[derive(Deserialize, Default, Clone)]
pub struct VpnClientIrohConfig {
    /// NodeId of the VPN server to connect to
    pub server_node_id: Option<String>,
    /// Authentication token to send to server
    pub auth_token: Option<String>,
    /// Path to file containing authentication token
    pub auth_token_file: Option<PathBuf>,
    /// IPv4 CIDRs to route through VPN (e.g., ["192.168.1.0/24", "0.0.0.0/0"]).
    /// - `None`: not specified (use defaults or CLI)
    /// - `Some([])`: explicitly cleared (validation will fail - routes required)
    /// - `Some([...])`: route CIDRs
    pub routes: Option<Vec<String>>,
    /// IPv6 CIDRs to route through VPN (e.g., ["::/0", "fd00::/64"]).
    /// - `None`: not specified (use defaults or CLI)
    /// - `Some([])`: explicitly cleared (no IPv6 routes)
    /// - `Some([...])`: route CIDRs
    pub routes6: Option<Vec<String>>,
    /// Enable auto-reconnect on connection loss.
    /// - `None`: not specified (use defaults or CLI)
    /// - `Some(true)`: enable reconnect (default behavior)
    /// - `Some(false)`: disable reconnect (exit on first disconnection)
    pub auto_reconnect: Option<bool>,
    /// Maximum reconnect attempts (None = unlimited)
    pub max_reconnect_attempts: Option<NonZeroU32>,
    /// Shared configuration fields
    #[serde(flatten)]
    pub shared: VpnIrohSharedConfig,
}

/// VPN server configuration.
#[derive(Deserialize, Default, Clone)]
pub struct VpnServerConfig {
    pub role: Option<Role>,
    pub mode: Option<Mode>,
    pub iroh: Option<VpnServerIrohConfig>,
}

/// VPN client configuration.
#[derive(Deserialize, Default, Clone)]
pub struct VpnClientConfig {
    pub role: Option<Role>,
    pub mode: Option<Mode>,
    pub iroh: Option<VpnClientIrohConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Server,
    Client,
    #[serde(rename = "vpnserver")]
    VpnServer,
    #[serde(rename = "vpnclient")]
    VpnClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Iroh,
    Manual,
    Nostr,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Iroh => "iroh",
            Mode::Manual => "manual",
            Mode::Nostr => "nostr",
        }
    }
}

/// Congestion controller algorithm selection.
///
/// Controls how the QUIC connection manages congestion and adjusts sending rates.
/// Default is Cubic, which is the most widely tested algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CongestionController {
    /// CUBIC - Default. Loss-based congestion control, widely deployed.
    /// Best for general internet conditions.
    #[default]
    Cubic,
    /// BBR (Bottleneck Bandwidth and RTT) - Model-based congestion control.
    /// May perform better on high-bandwidth, high-latency links.
    /// Experimental - may not be fair to Cubic/NewReno flows.
    Bbr,
    /// NewReno - Classic TCP-like congestion control.
    /// Most conservative, good for compatibility.
    #[serde(alias = "new_reno")]
    NewReno,
}

/// Default QUIC receive window size (2 MB).
pub const DEFAULT_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;

/// Default QUIC send window size (2 MB).
pub const DEFAULT_SEND_WINDOW: u32 = 2 * 1024 * 1024;

/// Transport tuning configuration for QUIC connections.
///
/// These settings affect performance and memory usage of the QUIC transport layer.
#[derive(Deserialize, Default, Clone, Debug, PartialEq)]
pub struct TransportTuning {
    /// Congestion controller algorithm (default: cubic).
    /// Options: cubic, bbr, newreno
    #[serde(default)]
    pub congestion_controller: CongestionController,

    /// QUIC receive window size in bytes (default: 2097152 = 2MB).
    /// Controls flow control - larger values allow more in-flight data.
    /// Valid range: 1024 to 16777216 (16MB).
    pub receive_window: Option<u32>,

    /// QUIC send window size in bytes (default: 2097152 = 2MB).
    /// Controls how much data can be sent before acknowledgment.
    /// Valid range: 1024 to 16777216 (16MB).
    pub send_window: Option<u32>,
}

fn parse_expected_mode(expected_mode: &str) -> Result<Mode> {
    match expected_mode {
        "iroh" => Ok(Mode::Iroh),
        "manual" => Ok(Mode::Manual),
        "nostr" => Ok(Mode::Nostr),
        _ => anyhow::bail!(
            "Unknown mode '{}'. Valid modes: iroh, manual, nostr",
            expected_mode
        ),
    }
}

/// Unified server configuration.
#[derive(Deserialize, Default)]
pub struct ServerConfig {
    // Validation fields
    pub role: Option<Role>,
    pub mode: Option<Mode>,

    // Shared options
    pub source: Option<String>,

    // Mode-specific sections
    pub iroh: Option<IrohConfig>,
    pub manual: Option<CustomManualConfig>,
    pub nostr: Option<NostrConfig>,
}

/// Unified client configuration.
#[derive(Deserialize, Default)]
pub struct ClientConfig {
    // Validation fields
    pub role: Option<Role>,
    pub mode: Option<Mode>,

    // Mode-specific sections (each mode has its own target field)
    pub iroh: Option<IrohConfig>,
    pub manual: Option<CustomManualConfig>,
    pub nostr: Option<NostrConfig>,
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate that a string is a valid CIDR network (IPv4 or IPv6).
fn validate_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::IpNet>().with_context(|| {
        format!(
            "Invalid CIDR network '{}'. Expected format: 192.168.0.0/16 or ::1/128",
            cidr
        )
    })?;
    Ok(())
}

/// Validate that a string is a valid IPv6-only CIDR network.
fn validate_ipv6_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::Ipv6Net>().with_context(|| {
        format!(
            "Invalid IPv6 CIDR '{}'. Expected format: fd00::/64 or ::/0",
            cidr
        )
    })?;
    Ok(())
}

/// Generate context message for invalid route6 CIDR errors.
///
/// If `section` is provided, prefixes the message with `[section]`.
fn route6_context(route: &str, section: Option<&str>) -> String {
    let msg = format!("Invalid route6 CIDR '{}' (must be IPv6, e.g., ::/0)", route);
    match section {
        Some(s) => format!("[{}] {}", s, msg),
        None => msg,
    }
}

/// Validate that a string is a valid tcp:// or udp:// URL with host and port.
fn validate_tcp_udp_url(value: &str, field_name: &str) -> Result<()> {
    let url = url::Url::parse(value).with_context(|| {
        format!(
            "Invalid {} '{}'. Expected format: tcp://host:port or udp://host:port",
            field_name, value
        )
    })?;

    let scheme = url.scheme();
    if scheme != "tcp" && scheme != "udp" {
        anyhow::bail!(
            "Invalid {} scheme '{}'. Must be 'tcp' or 'udp'",
            field_name,
            scheme
        );
    }

    if url.host_str().is_none() {
        anyhow::bail!("{} '{}' missing host", field_name, value);
    }

    if url.port().is_none() {
        anyhow::bail!("{} '{}' missing port", field_name, value);
    }

    Ok(())
}

/// Validate that a string is a valid host:port address.
fn validate_host_port(value: &str, field_name: &str) -> Result<()> {
    if !value.contains(':') {
        anyhow::bail!(
            "{} '{}' missing port. Expected format: host:port",
            field_name,
            value
        );
    }

    // Use rsplitn to split from the right (handles IPv6 addresses like [::1]:8080)
    let parts: Vec<&str> = value.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "{} '{}' has invalid format. Expected format: host:port",
            field_name,
            value
        );
    }

    let port_str = parts[0];
    let host = parts[1];

    if host.is_empty() {
        anyhow::bail!("{} '{}' missing host", field_name, value);
    }

    port_str
        .parse::<u16>()
        .with_context(|| format!("{} '{}' has invalid port number", field_name, value))?;

    Ok(())
}

/// Validate AllowedSources CIDR lists.
fn validate_allowed_sources(allowed: &AllowedSources) -> Result<()> {
    for cidr in &allowed.tcp {
        validate_cidr(cidr).context("Invalid TCP allowed_sources")?;
    }
    for cidr in &allowed.udp {
        validate_cidr(cidr).context("Invalid UDP allowed_sources")?;
    }
    Ok(())
}

/// Validate MTU value is within acceptable range (576-1500).
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

/// Validate channel buffer size is within acceptable range (1-65536).
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

/// Minimum QUIC window size (1 KB).
const MIN_WINDOW_SIZE: u32 = 1024;

/// Maximum QUIC window size (16 MB).
const MAX_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

/// Validate QUIC window size is within acceptable range (1024-16777216 bytes).
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

/// Validate TransportTuning window sizes if specified.
pub fn validate_transport_tuning(tuning: &TransportTuning, section: &str) -> Result<()> {
    if let Some(recv) = tuning.receive_window {
        validate_window_size(recv, "receive_window", section)?;
    }
    if let Some(send) = tuning.send_window {
        validate_window_size(send, "send_window", section)?;
    }
    Ok(())
}

/// Validate IPv4 network CIDR and optional server IP within network.
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

/// Validate IPv6 network CIDR and optional server IP within network.
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

/// Validate VPN server network configuration.
///
/// This is a shared helper that validates:
/// - At least one of network (IPv4) or network6 (IPv6) is configured
/// - server_ip is not orphaned without network
/// - server_ip6 is not orphaned without network6
/// - Network CIDRs are valid and server IPs are within their respective networks
fn validate_vpn_networks(
    network: Option<&str>,
    server_ip: Option<&str>,
    network6: Option<&str>,
    server_ip6: Option<&str>,
    section: &str,
) -> Result<()> {
    // Require at least one of network (IPv4) or network6 (IPv6)
    if network.is_none() && network6.is_none() {
        anyhow::bail!(
            "[{}] At least one of 'network' (IPv4) or 'network6' (IPv6) is required for VPN server configuration.",
            section
        );
    }

    // Validate IPv4: server_ip requires network
    if server_ip.is_some() && network.is_none() {
        anyhow::bail!("[{}] 'server_ip' requires 'network' to be set.", section);
    }
    if let Some(net) = network {
        validate_vpn_network(net, server_ip, section)?;
    }

    // Validate IPv6: server_ip6 requires network6
    if server_ip6.is_some() && network6.is_none() {
        anyhow::bail!(
            "[{}] 'server_ip6' requires 'network6' to be set.",
            section
        );
    }
    if let Some(net6) = network6 {
        validate_vpn_network6(net6, server_ip6, section)?;
    }

    Ok(())
}

// ============================================================================
// Config Accessor Methods
// ============================================================================

impl ServerConfig {
    /// Get iroh config section (multi-source mode).
    pub fn iroh(&self) -> Option<&IrohConfig> {
        self.iroh.as_ref()
    }

    /// Get nostr config section.
    pub fn nostr(&self) -> Option<&NostrConfig> {
        self.nostr.as_ref()
    }

    /// Validate that config matches expected role and mode.
    ///
    /// Enforces:
    /// - Role must be "server"
    /// - Mode must match expected_mode
    /// - Multi-source modes (iroh, nostr): rejects client-only fields (request_source)
    /// - Multi-source modes: validates CIDR format in allowed_sources
    /// - Single-target modes: validates source URL format if present
    pub fn validate(&self, expected_mode: &str) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"server\"")?;
        if role != Role::Server {
            anyhow::bail!("Config file has role = \"client\", but running as server");
        }

        let mode = self.mode.context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\" (or \"manual\", \"nostr\")",
        )?;
        let expected_mode = parse_expected_mode(expected_mode)?;
        if mode != expected_mode {
            anyhow::bail!(
                "Config file has mode = \"{}\", but running with {}",
                mode.as_str(),
                expected_mode.as_str()
            );
        }

        // Mode-specific validation
        if expected_mode == Mode::Iroh {
            if let Some(ref iroh) = self.iroh {
                if iroh.secret.is_some() && iroh.secret_file.is_some() {
                    anyhow::bail!("[iroh] Use only one of 'secret' or 'secret_file'.");
                }
                // Validate auth_tokens mutual exclusion
                if iroh.auth_tokens.is_some() && iroh.auth_tokens_file.is_some() {
                    anyhow::bail!("[iroh] Use only one of 'auth_tokens' or 'auth_tokens_file'.");
                }
                // Reject client-only fields (auth_token is for clients)
                if iroh.auth_token.is_some() || iroh.auth_token_file.is_some() {
                    anyhow::bail!(
                        "[iroh] 'auth_token' and 'auth_token_file' are client-only fields."
                    );
                }
                // Reject client-only fields
                if iroh.request_source.is_some() || iroh.target.is_some() {
                    anyhow::bail!(
                        "[iroh] 'source' / 'request_source' / 'target' are client-only fields. \
                        Servers use 'allowed_sources' to restrict what clients can request."
                    );
                }
                if iroh.server_node_id.is_some() {
                    anyhow::bail!("[iroh] 'server_node_id' is a client-only field.");
                }
                // Validate CIDR format
                if let Some(ref allowed) = iroh.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
            }
            // Server iroh mode should not have top-level source
            if self.source.is_some() {
                anyhow::bail!(
                    "Top-level 'source' is not allowed for iroh server mode. \
                    Use [iroh.allowed_sources] to restrict what clients can request."
                );
            }
        }
        if expected_mode == Mode::Nostr {
            if let Some(ref nostr) = self.nostr {
                if nostr.nsec.is_some() && nostr.nsec_file.is_some() {
                    anyhow::bail!("[nostr] Use only one of 'nsec' or 'nsec_file'.");
                }
                // Reject client-only fields
                if nostr.request_source.is_some() || nostr.target.is_some() {
                    anyhow::bail!(
                        "[nostr] 'source' / 'request_source' / 'target' are client-only fields. \
                        Servers use 'allowed_sources' to restrict what clients can request."
                    );
                }
                // Validate CIDR format
                if let Some(ref allowed) = nostr.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
            }
            // Server nostr mode should not have top-level source
            if self.source.is_some() {
                anyhow::bail!(
                    "Top-level 'source' is not allowed for nostr server mode. \
                    Use [nostr.allowed_sources] to restrict what clients can request."
                );
            }
        }
        if expected_mode == Mode::Manual {
            if let Some(ref manual) = self.manual {
                // Reject client-only fields
                if manual.request_source.is_some() || manual.target.is_some() {
                    anyhow::bail!(
                        "[manual] 'source' / 'request_source' / 'target' are client-only fields. \
                        Servers use 'allowed_sources' to restrict what clients can request."
                    );
                }
                // Validate CIDR format
                if let Some(ref allowed) = manual.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
            }
            // Reject top-level source for manual server
            if self.source.is_some() {
                anyhow::bail!(
                    "Top-level 'source' is not allowed for manual server mode. \
                    Use [manual.allowed_sources] to restrict what clients can request."
                );
            }
        }

        Ok(())
    }
}

impl ClientConfig {
    /// Get iroh config section (multi-source mode).
    pub fn iroh(&self) -> Option<&IrohConfig> {
        self.iroh.as_ref()
    }

    /// Get nostr config section.
    pub fn nostr(&self) -> Option<&NostrConfig> {
        self.nostr.as_ref()
    }

    /// Validate that config matches expected role and mode.
    ///
    /// Enforces:
    /// - Role must be "client"
    /// - Mode must match expected_mode
    /// - Multi-source modes (iroh, nostr): rejects server-only fields (allowed_sources, max_sessions)
    /// - Multi-source modes: validates request_source URL format if present
    /// - Single-target modes: validates target URL format if present
    pub fn validate(&self, expected_mode: &str) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"client\"")?;
        if role != Role::Client {
            anyhow::bail!("Config file has role = \"server\", but running as client");
        }

        let mode = self.mode.context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\" (or \"manual\", \"nostr\")",
        )?;
        let expected_mode = parse_expected_mode(expected_mode)?;
        if mode != expected_mode {
            anyhow::bail!(
                "Config file has mode = \"{}\", but running with {}",
                mode.as_str(),
                expected_mode.as_str()
            );
        }

        // Mode-specific validation
        if expected_mode == Mode::Iroh {
            if let Some(ref iroh) = self.iroh {
                // Validate auth_token mutual exclusion
                if iroh.auth_token.is_some() && iroh.auth_token_file.is_some() {
                    anyhow::bail!("[iroh] Use only one of 'auth_token' or 'auth_token_file'.");
                }
                // Reject server-only fields
                if iroh.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[iroh] 'allowed_sources' is a server-only field. \
                        Clients use 'source' to specify what to request from server."
                    );
                }
                if iroh.max_sessions.is_some() {
                    anyhow::bail!("[iroh] 'max_sessions' is a server-only field.");
                }
                if iroh.auth_tokens.is_some() || iroh.auth_tokens_file.is_some() {
                    anyhow::bail!(
                        "[iroh] 'auth_tokens' and 'auth_tokens_file' are server-only fields."
                    );
                }
                if iroh.secret.is_some() || iroh.secret_file.is_some() {
                    anyhow::bail!(
                        "[iroh] 'secret' and 'secret_file' are server-only fields. \
                        Clients use ephemeral identities with token authentication."
                    );
                }
                // Validate request_source URL format
                if let Some(ref source) = iroh.request_source {
                    validate_tcp_udp_url(source, "request_source")?;
                }
                // Validate target format (host:port)
                if let Some(ref target) = iroh.target {
                    validate_host_port(target, "target")?;
                }
            }
        }
        if expected_mode == Mode::Nostr {
            if let Some(ref nostr) = self.nostr {
                if nostr.nsec.is_some() && nostr.nsec_file.is_some() {
                    anyhow::bail!("[nostr] Use only one of 'nsec' or 'nsec_file'.");
                }
                // Reject server-only fields
                if nostr.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[nostr] 'allowed_sources' is a server-only field. \
                        Clients use 'source' to specify what to request from server."
                    );
                }
                if nostr.max_sessions.is_some() {
                    anyhow::bail!("[nostr] 'max_sessions' is a server-only field.");
                }
                // Validate request_source URL format
                if let Some(ref source) = nostr.request_source {
                    validate_tcp_udp_url(source, "request_source")?;
                }
                // Validate target format (host:port)
                if let Some(ref target) = nostr.target {
                    validate_host_port(target, "target")?;
                }
            }
        }

        if expected_mode == Mode::Manual {
            if let Some(ref manual) = self.manual {
                // Reject server-only fields
                if manual.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[manual] 'allowed_sources' is a server-only field. \
                        Clients use 'source' to specify what to request from server."
                    );
                }
                // Validate request_source URL format
                if let Some(ref source) = manual.request_source {
                    validate_tcp_udp_url(source, "request_source")?;
                }
                // Validate target format (host:port)
                if let Some(ref target) = manual.target {
                    validate_host_port(target, "target")?;
                }
            }
        }

        Ok(())
    }
}

impl VpnServerConfig {
    /// Get VPN iroh config section.
    pub fn iroh(&self) -> Option<&VpnServerIrohConfig> {
        self.iroh.as_ref()
    }

    /// Validate VPN server configuration.
    ///
    /// Enforces:
    /// - Role must be "vpnserver"
    /// - Mode must be "iroh"
    /// - Validates network CIDR format
    /// - Validates server_ip is within network if specified
    /// - Validates MTU range
    pub fn validate(&self) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnserver\"")?;
        if role != Role::VpnServer {
            anyhow::bail!(
                "Config file has wrong role for VPN server. Expected role = \"vpnserver\""
            );
        }

        let mode = self
            .mode
            .context("Config file missing required 'mode' field. Add: mode = \"iroh\"")?;
        if mode != Mode::Iroh {
            anyhow::bail!(
                "Config file has mode = \"{}\", but VPN only supports iroh mode",
                mode.as_str()
            );
        }

        if let Some(ref iroh) = self.iroh {
            // Validate auth_tokens mutual exclusion
            let has_inline_tokens = iroh.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
            if has_inline_tokens && iroh.auth_tokens_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'auth_tokens' or 'auth_tokens_file'.");
            }

            // Validate network configuration (presence, containment, format)
            validate_vpn_networks(
                iroh.network.as_deref(),
                iroh.server_ip.as_deref(),
                iroh.network6.as_deref(),
                iroh.server_ip6.as_deref(),
                "iroh",
            )?;

            // Validate MTU range
            if let Some(mtu) = iroh.shared.mtu {
                validate_mtu(mtu, "iroh")?;
            }
        }

        Ok(())
    }
}

impl VpnClientConfig {
    /// Get VPN iroh config section.
    pub fn iroh(&self) -> Option<&VpnClientIrohConfig> {
        self.iroh.as_ref()
    }

    /// Validate VPN client configuration.
    ///
    /// Enforces:
    /// - Role must be "vpnclient"
    /// - Mode must be "iroh"
    /// - Validates routes CIDR format
    /// - Validates MTU range
    pub fn validate(&self) -> Result<()> {
        let role = self
            .role
            .context("Config file missing required 'role' field. Add: role = \"vpnclient\"")?;
        if role != Role::VpnClient {
            anyhow::bail!(
                "Config file has wrong role for VPN client. Expected role = \"vpnclient\""
            );
        }

        let mode = self
            .mode
            .context("Config file missing required 'mode' field. Add: mode = \"iroh\"")?;
        if mode != Mode::Iroh {
            anyhow::bail!(
                "Config file has mode = \"{}\", but VPN only supports iroh mode",
                mode.as_str()
            );
        }

        if let Some(ref iroh) = self.iroh {
            // Require server_node_id for VPN client
            if iroh.server_node_id.is_none() {
                anyhow::bail!("[iroh] 'server_node_id' is required for VPN client configuration.");
            }

            // Validate auth_token mutual exclusion
            if iroh.auth_token.is_some() && iroh.auth_token_file.is_some() {
                anyhow::bail!("[iroh] Use only one of 'auth_token' or 'auth_token_file'.");
            }

            // Validate routes: valid CIDR format (optional - VPN subnet routed by default)
            if let Some(ref routes) = iroh.routes {
                for route in routes {
                    validate_cidr(route)
                        .with_context(|| format!("[iroh] Invalid route CIDR '{}'", route))?;
                }
            }

            // Validate routes6: valid IPv6 CIDR format (optional)
            if let Some(ref routes6) = iroh.routes6 {
                for route6 in routes6 {
                    validate_ipv6_cidr(route6)
                        .with_context(|| route6_context(route6, Some("iroh")))?;
                }
            }

            // Validate MTU range
            if let Some(mtu) = iroh.shared.mtu {
                validate_mtu(mtu, "iroh")?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// Path Expansion
// ============================================================================

/// Expand tilde (~) in paths to the user's home directory.
///
/// - `~/...` expands to the user's home directory
/// - `~` alone expands to the home directory
/// - Other paths are returned unchanged
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

// ============================================================================
// Config Loading
// ============================================================================

/// Load configuration from a TOML file.
fn load_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// Default value for `drop_on_full` in VPN server config.
/// Defaults to false (apply backpressure) for development/homelab use.
fn default_drop_on_full() -> bool {
    false
}

/// Resolve the default server config path (~/.config/tunnel-rs/server.toml).
fn default_server_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("tunnel-rs").join("server.toml"))
}

/// Resolve the default client config path (~/.config/tunnel-rs/client.toml).
fn default_client_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("tunnel-rs").join("client.toml"))
}

/// Load server configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path (tilde-expanded)
/// - `path`: None loads from the default path (~/.config/tunnel-rs/server.toml)
pub fn load_server_config(path: Option<&Path>) -> Result<ServerConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_server_config_path().ok_or_else(|| {
            anyhow::anyhow!("Could not find default config path. Use -c to specify a config file.")
        })?,
    };
    load_config(&config_path)
}

/// Load client configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path (tilde-expanded)
/// - `path`: None loads from the default path (~/.config/tunnel-rs/client.toml)
pub fn load_client_config(path: Option<&Path>) -> Result<ClientConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_client_config_path().ok_or_else(|| {
            anyhow::anyhow!("Could not find default config path. Use -c to specify a config file.")
        })?,
    };
    load_config(&config_path)
}

/// Resolve the default VPN server config path (~/.config/tunnel-rs/vpn_server.toml).
fn default_vpn_server_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| {
        home.join(".config")
            .join("tunnel-rs")
            .join("vpn_server.toml")
    })
}

/// Resolve the default VPN client config path (~/.config/tunnel-rs/vpn_client.toml).
fn default_vpn_client_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| {
        home.join(".config")
            .join("tunnel-rs")
            .join("vpn_client.toml")
    })
}

/// Load VPN server configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path (tilde-expanded)
/// - `path`: None loads from the default path (~/.config/tunnel-rs/vpn_server.toml)
pub fn load_vpn_server_config(path: Option<&Path>) -> Result<VpnServerConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_vpn_server_config_path().ok_or_else(|| {
            anyhow::anyhow!("Could not find default config path. Use -c to specify a config file.")
        })?,
    };
    load_config(&config_path)
}

/// Load VPN client configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path (tilde-expanded)
/// - `path`: None loads from the default path (~/.config/tunnel-rs/vpn_client.toml)
pub fn load_vpn_client_config(path: Option<&Path>) -> Result<VpnClientConfig> {
    let config_path = match path {
        Some(p) => expand_tilde(p),
        None => default_vpn_client_config_path().ok_or_else(|| {
            anyhow::anyhow!("Could not find default config path. Use -c to specify a config file.")
        })?,
    };
    load_config(&config_path)
}

// ============================================================================
// Defaults
// ============================================================================

/// Default public STUN servers for ICE mode.
pub fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
    ]
}

/// Default public Nostr relays for signaling.
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    //"wss://relay.damus.io", // acceptable for index queries; not recommended for high-volume operations due to rate limiting
    //"wss://relay.nostr.band",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

/// Default public Nostr relays for signaling.
pub fn default_nostr_relays() -> &'static [&'static str] {
    DEFAULT_NOSTR_RELAYS
}

// ============================================================================
// VPN Config Builders
// ============================================================================

/// Default MTU for VPN packets (1500 - 60 bytes for QUIC/TLS + framing overhead).
pub const DEFAULT_VPN_MTU: u16 = 1440;

/// Default channel buffer size for outbound packets to each client.
pub const DEFAULT_CLIENT_CHANNEL_SIZE: usize = 1024;

/// Default channel buffer size for TUN writer task.
/// Conservative default to bound memory usage on constrained hosts.
pub const DEFAULT_TUN_WRITER_CHANNEL_SIZE: usize = 512;

/// Resolved VPN server configuration (all values finalized).
///
/// Created from a TOML config file via `from_config()`.
///
/// # Example
/// ```rust
/// use tunnel_common::config::{ResolvedVpnServerConfig, VpnServerIrohConfig};
///
/// fn main() -> anyhow::Result<()> {
///     let toml_config = VpnServerIrohConfig {
///         network: Some("10.0.0.0/24".to_string()),
///         ..Default::default()
///     };
///
///     let config = ResolvedVpnServerConfig::from_config(&toml_config)?;
///     assert_eq!(config.network, Some("10.0.0.0/24".to_string()));
///     Ok(())
/// }
/// ```
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
    pub nat64: Option<Nat64Config>,
    pub disable_spoofing_check: bool,
}

impl ResolvedVpnServerConfig {
    /// Create resolved config from TOML config, applying defaults for missing values.
    ///
    /// This method performs defensive validation of all fields, so callers do not need
    /// to call `VpnServerConfig::validate()` beforehand. This is intentional because
    /// `from_config` accepts a `VpnServerIrohConfig` directly (which can be constructed
    /// without going through `VpnServerConfig::validate()`).
    ///
    /// Validation includes:
    /// - Network configuration (at least one of IPv4/IPv6 required, server IPs within networks)
    /// - NAT64 configuration (port range validity, IPv4 source requirement when enabled)
    /// - MTU range, channel sizes, transport tuning window sizes
    /// - Auth tokens mutual exclusion
    pub fn from_config(cfg: &VpnServerIrohConfig) -> Result<Self> {
        // Validate network configuration (presence, containment, format)
        validate_vpn_networks(
            cfg.network.as_deref(),
            cfg.server_ip.as_deref(),
            cfg.network6.as_deref(),
            cfg.server_ip6.as_deref(),
            "config",
        )?;

        // Validate NAT64 configuration
        if let Some(ref nat64) = cfg.nat64 {
            // Validate port_range and other NAT64 fields
            nat64.validate()?;

            // NAT64 requires an IPv4 source address for translated packets.
            // This can come from either the VPN network (server_ip) or explicit nat64.source_ip
            if nat64.enabled && nat64.source_ip.is_none() && cfg.network.is_none() {
                anyhow::bail!(
                    "[config] NAT64 requires an IPv4 source address for translated packets.\n\
                     Either set 'network' (IPv4 VPN network) or 'nat64.source_ip' (explicit IPv4 address)."
                );
            }
        }

        // Apply defaults for optional fields
        let mtu = cfg.shared.mtu.unwrap_or(DEFAULT_VPN_MTU);
        validate_mtu(mtu, "config")?;

        // Validate auth_tokens mutual exclusion
        let has_tokens = cfg.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
        if has_tokens && cfg.auth_tokens_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_tokens and auth_tokens_file.\n\
                 Use auth_tokens = [...] or auth_tokens_file = \"...\", not both."
            );
        }

        // Apply defaults and validate channel sizes
        let client_channel_size = cfg
            .client_channel_size
            .unwrap_or(DEFAULT_CLIENT_CHANNEL_SIZE);
        validate_channel_size(client_channel_size, "client_channel_size", "config")?;

        let tun_writer_channel_size = cfg
            .tun_writer_channel_size
            .unwrap_or(DEFAULT_TUN_WRITER_CHANNEL_SIZE);
        validate_channel_size(tun_writer_channel_size, "tun_writer_channel_size", "config")?;

        // Validate transport tuning window sizes
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
            nat64: cfg.nat64.clone(),
            disable_spoofing_check: cfg.disable_spoofing_check,
        })
    }
}

/// Resolved VPN client configuration (all values finalized).
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

/// Builder for VPN client configuration with layered overrides.
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
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply default values (lowest priority).
    pub fn apply_defaults(mut self) -> Self {
        self.mtu = Some(DEFAULT_VPN_MTU);
        self.routes = Some(vec![]);
        self.routes6 = Some(vec![]);
        self.relay_urls = Some(vec![]);
        // auto_reconnect defaults to None (resolved to true in build())
        // max_reconnect_attempts defaults to None (unlimited)
        self
    }

    /// Apply values from TOML config (middle priority).
    ///
    /// For `Option<Vec<T>>` fields:
    /// - `None` in config: don't override (use defaults/CLI)
    /// - `Some([])` in config: explicitly set to empty (override defaults)
    /// - `Some([...])` in config: set to these values
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
            // routes: None = not set, Some([]) = explicitly empty (will fail validation)
            if cfg.routes.is_some() {
                self.routes = cfg.routes.clone();
            }
            // routes6: None = not set, Some([]) = explicitly empty (no IPv6 routes)
            if cfg.routes6.is_some() {
                self.routes6 = cfg.routes6.clone();
            }
            // relay_urls: None = not set, Some([]) = explicitly empty
            if cfg.shared.relay_urls.is_some() {
                self.relay_urls = cfg.shared.relay_urls.clone();
            }
            if cfg.shared.dns_server.is_some() {
                self.dns_server = cfg.shared.dns_server.clone();
            }
            // auto_reconnect: None = not set, Some(true/false) = explicit value
            if cfg.auto_reconnect.is_some() {
                self.auto_reconnect = cfg.auto_reconnect;
            }
            if cfg.max_reconnect_attempts.is_some() {
                self.max_reconnect_attempts = cfg.max_reconnect_attempts;
            }
            // Transport tuning: only override if config differs from default
            if cfg.shared.transport != TransportTuning::default() {
                self.transport = Some(cfg.shared.transport.clone());
            }
        }
        self
    }

    /// Apply CLI arguments (highest priority).
    ///
    /// For `auto_reconnect`:
    /// - `None`: CLI flag not specified (use config/default)
    /// - `Some(true)`: `--auto-reconnect` specified
    /// - `Some(false)`: `--no-auto-reconnect` specified (overrides config's true)
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
        // auto_reconnect: None = not specified, Some(bool) = explicit override
        if auto_reconnect.is_some() {
            self.auto_reconnect = auto_reconnect;
        }
        if max_reconnect_attempts.is_some() {
            self.max_reconnect_attempts = max_reconnect_attempts;
        }
        self
    }

    /// Build the final resolved configuration.
    pub fn build(self) -> Result<ResolvedVpnClientConfig> {
        let server_node_id = self.server_node_id.ok_or_else(|| {
            anyhow::anyhow!(
                "Server node ID is required.\n\
                 Specify via CLI: --server-node-id <ID>\n\
                 Or in config: server_node_id = \"...\""
            )
        })?;

        // Validate MTU range
        let mtu = self.mtu.unwrap_or(DEFAULT_VPN_MTU);
        validate_mtu(mtu, "config")?;

        // Routes are optional - VPN subnet is always routed by default
        let routes = self.routes.unwrap_or_default();

        // Validate route CIDR format
        for route in &routes {
            validate_cidr(route)
                .with_context(|| format!("Invalid route CIDR '{}' (e.g., 0.0.0.0/0)", route))?;
        }

        // Validate routes6 CIDR format (optional, must be IPv6)
        let routes6 = self.routes6.unwrap_or_default();
        for route6 in &routes6 {
            validate_ipv6_cidr(route6).with_context(|| route6_context(route6, Some("config")))?;
        }

        // Validate auth_token mutual exclusion
        if self.auth_token.is_some() && self.auth_token_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_token and auth_token_file.\n\
                 Use --auth-token <TOKEN> or --auth-token-file <FILE>, not both."
            );
        }

        // Validate transport tuning window sizes if configured
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
