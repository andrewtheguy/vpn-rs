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
    /// SOCKS5 proxy URL for relay connections (e.g., socks5://127.0.0.1:9050).
    /// Required when using .onion relay URLs with Tor.
    pub socks5_proxy: Option<String>,
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

/// Shared VPN iroh configuration fields (used by both server and client).
#[derive(Deserialize, Default, Clone)]
pub struct VpnIrohSharedConfig {
    /// MTU for VPN packets (576-1500, default: 1420)
    pub mtu: Option<u16>,
    /// WireGuard keepalive interval in seconds (10-300, default: 25)
    pub keepalive_secs: Option<u16>,
    /// Custom relay server URLs
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Custom DNS server URL for peer discovery
    pub dns_server: Option<String>,
}

/// VPN server iroh configuration (TOML section: `[iroh]` in vpn_server.toml).
///
/// VPN mode uses iroh for P2P connectivity with WireGuard encryption.
#[derive(Deserialize, Default, Clone)]
pub struct VpnServerIrohConfig {
    /// VPN network CIDR (e.g., "10.0.0.0/24")
    pub network: Option<String>,
    /// Server's VPN IP address within the network (defaults to first IP)
    pub server_ip: Option<String>,
    /// Path to secret key file for persistent server identity
    pub secret_file: Option<PathBuf>,
    /// Authentication tokens
    #[serde(default)]
    pub auth_tokens: Vec<String>,
    /// Path to file containing authentication tokens
    pub auth_tokens_file: Option<PathBuf>,
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
    /// CIDRs to route through VPN (e.g., ["192.168.1.0/24", "0.0.0.0/0"])
    #[serde(default)]
    pub routes: Vec<String>,
    /// Disable auto-reconnect on connection loss
    #[serde(default)]
    pub no_reconnect: bool,
    /// Maximum reconnect attempts (0 = unlimited)
    pub max_reconnect_attempts: Option<u32>,
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

/// Validate keepalive_secs value is within acceptable range (10-300).
fn validate_keepalive(keepalive: u16, section: &str) -> Result<()> {
    if !(10..=300).contains(&keepalive) {
        anyhow::bail!(
            "[{}] keepalive_secs {} is out of range. Valid range: 10-300",
            section,
            keepalive
        );
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

/// Validate that a string is a valid SOCKS5 proxy URL.
///
/// SOCKS5 proxy is only supported for Tor hidden services:
/// - ALL relay URLs must be `.onion` addresses
/// - Requires `socks5h://` scheme for DNS resolution through Tor
fn validate_socks5_proxy(value: &str, relay_urls: Option<&Vec<String>>) -> Result<()> {
    let url = url::Url::parse(value).with_context(|| {
        format!(
            "Invalid socks5_proxy '{}'. Expected format: socks5h://host:port",
            value
        )
    })?;

    let scheme = url.scheme();

    // SOCKS5 proxy requires socks5h:// scheme for Tor
    if scheme != "socks5h" {
        anyhow::bail!(
            "Invalid socks5_proxy scheme '{}'. \
             SOCKS5 proxy requires socks5h:// scheme for Tor DNS resolution. \
             Change socks5_proxy to use 'socks5h://host:port' format.",
            scheme
        );
    }

    if url.host_str().is_none() {
        anyhow::bail!("socks5_proxy '{}' missing host", value);
    }

    if url.port().is_none() {
        anyhow::bail!("socks5_proxy '{}' missing port", value);
    }

    // Validate that ALL relay URLs are .onion addresses
    if let Some(urls) = relay_urls {
        for relay_url in urls {
            let parsed = url::Url::parse(relay_url)
                .with_context(|| format!("Invalid relay URL '{}'", relay_url))?;
            let host = parsed.host_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "Relay URL '{}' missing host; SOCKS5 proxy requires .onion relay URLs",
                    relay_url
                )
            })?;
            if !host.ends_with(".onion") {
                anyhow::bail!(
                    "SOCKS5 proxy is only supported for Tor hidden service (.onion) relay URLs. \
                     Relay URL '{}' host '{}' is not a .onion address. \
                     All relay URLs must end with '.onion' when using --socks5-proxy.",
                    relay_url,
                    host
                );
            }
        }
    } else {
        // No relay URLs specified - this is an error when using SOCKS5 proxy
        anyhow::bail!(
            "SOCKS5 proxy requires .onion relay URLs. \
             Specify relay URLs with --relay-url or in config file."
        );
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
                    anyhow::bail!(
                        "[iroh] Use only one of 'auth_tokens' or 'auth_tokens_file'."
                    );
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
                // Validate SOCKS5 proxy: cannot use with dns_server
                if let Some(ref proxy) = iroh.socks5_proxy {
                    if iroh.dns_server.is_some() {
                        anyhow::bail!(
                            "[iroh] Cannot use 'dns_server' with 'socks5_proxy'. \
                             When using a Tor hidden service relay, the relay handles peer discovery. \
                             Remove 'dns_server' to proceed."
                        );
                    }
                    validate_socks5_proxy(proxy, iroh.relay_urls.as_ref())
                        .context("[iroh] Invalid SOCKS5 proxy URL")?;
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
                // Validate SOCKS5 proxy: cannot use with dns_server
                if let Some(ref proxy) = iroh.socks5_proxy {
                    if iroh.dns_server.is_some() {
                        anyhow::bail!(
                            "[iroh] Cannot use 'dns_server' with 'socks5_proxy'. \
                             When using a Tor hidden service relay, the relay handles peer discovery. \
                             Remove 'dns_server' to proceed."
                        );
                    }
                    validate_socks5_proxy(proxy, iroh.relay_urls.as_ref())
                        .context("[iroh] Invalid SOCKS5 proxy URL")?;
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
    /// - Validates MTU and keepalive ranges
    pub fn validate(&self) -> Result<()> {
        let role = self.role.context(
            "Config file missing required 'role' field. Add: role = \"vpnserver\"",
        )?;
        if role != Role::VpnServer {
            anyhow::bail!(
                "Config file has wrong role for VPN server. Expected role = \"vpnserver\""
            );
        }

        let mode = self.mode.context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\"",
        )?;
        if mode != Mode::Iroh {
            anyhow::bail!(
                "Config file has mode = \"{}\", but VPN only supports iroh mode",
                mode.as_str()
            );
        }

        if let Some(ref iroh) = self.iroh {
            // Validate auth_tokens mutual exclusion
            if !iroh.auth_tokens.is_empty() && iroh.auth_tokens_file.is_some() {
                anyhow::bail!(
                    "[iroh] Use only one of 'auth_tokens' or 'auth_tokens_file'."
                );
            }

            // Require network for VPN server
            let network = iroh.network.as_ref().ok_or_else(|| {
                anyhow::anyhow!("[iroh] 'network' is required for VPN server configuration.")
            })?;

            // Validate network CIDR and server_ip
            validate_vpn_network(network, iroh.server_ip.as_deref(), "iroh")?;

            // Validate MTU and keepalive ranges
            if let Some(mtu) = iroh.shared.mtu {
                validate_mtu(mtu, "iroh")?;
            }
            if let Some(keepalive) = iroh.shared.keepalive_secs {
                validate_keepalive(keepalive, "iroh")?;
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
    /// - Validates MTU and keepalive ranges
    pub fn validate(&self) -> Result<()> {
        let role = self.role.context(
            "Config file missing required 'role' field. Add: role = \"vpnclient\"",
        )?;
        if role != Role::VpnClient {
            anyhow::bail!(
                "Config file has wrong role for VPN client. Expected role = \"vpnclient\""
            );
        }

        let mode = self.mode.context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\"",
        )?;
        if mode != Mode::Iroh {
            anyhow::bail!(
                "Config file has mode = \"{}\", but VPN only supports iroh mode",
                mode.as_str()
            );
        }

        if let Some(ref iroh) = self.iroh {
            // Require server_node_id for VPN client
            if iroh.server_node_id.is_none() {
                anyhow::bail!(
                    "[iroh] 'server_node_id' is required for VPN client configuration."
                );
            }

            // Validate auth_token mutual exclusion
            if iroh.auth_token.is_some() && iroh.auth_token_file.is_some() {
                anyhow::bail!(
                    "[iroh] Use only one of 'auth_token' or 'auth_token_file'."
                );
            }

            // Validate routes: at least one required, valid CIDR format
            if iroh.routes.is_empty() {
                anyhow::bail!(
                    "[iroh] At least one route is required.\n\
                     Example: routes = [\"0.0.0.0/0\"] for full tunnel"
                );
            }
            for route in &iroh.routes {
                validate_cidr(route).with_context(|| {
                    format!("[iroh] Invalid route CIDR '{}'", route)
                })?;
            }

            // Validate MTU and keepalive ranges
            if let Some(mtu) = iroh.shared.mtu {
                validate_mtu(mtu, "iroh")?;
            }
            if let Some(keepalive) = iroh.shared.keepalive_secs {
                validate_keepalive(keepalive, "iroh")?;
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
    dirs::home_dir().map(|home| home.join(".config").join("tunnel-rs").join("vpn_server.toml"))
}

/// Resolve the default VPN client config path (~/.config/tunnel-rs/vpn_client.toml).
fn default_vpn_client_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("tunnel-rs").join("vpn_client.toml"))
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

/// Default MTU for VPN packets.
pub const DEFAULT_VPN_MTU: u16 = 1420;

/// Default WireGuard keepalive interval in seconds.
pub const DEFAULT_VPN_KEEPALIVE_SECS: u16 = 25;

/// Resolved VPN server configuration (all values finalized).
#[derive(Debug, Clone)]
pub struct ResolvedVpnServerConfig {
    pub network: String,
    pub server_ip: Option<String>,
    pub mtu: u16,
    pub keepalive_secs: u16,
    pub secret_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub auth_tokens: Vec<String>,
    pub auth_tokens_file: Option<PathBuf>,
}

/// Builder for VPN server configuration with layered overrides.
///
/// Usage:
/// ```ignore
/// let config = VpnServerConfigBuilder::new()
///     .apply_defaults()
///     .apply_config(toml_config.as_ref())
///     .apply_cli(network, server_ip, mtu, ...)
///     .build()?;
/// ```
#[derive(Default)]
pub struct VpnServerConfigBuilder {
    network: Option<String>,
    server_ip: Option<String>,
    mtu: Option<u16>,
    keepalive_secs: Option<u16>,
    secret_file: Option<PathBuf>,
    relay_urls: Option<Vec<String>>,
    dns_server: Option<String>,
    auth_tokens: Option<Vec<String>>,
    auth_tokens_file: Option<PathBuf>,
}

impl VpnServerConfigBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply default values (lowest priority).
    pub fn apply_defaults(mut self) -> Self {
        self.mtu = Some(DEFAULT_VPN_MTU);
        self.keepalive_secs = Some(DEFAULT_VPN_KEEPALIVE_SECS);
        self.relay_urls = Some(vec![]);
        self.auth_tokens = Some(vec![]);
        self
    }

    /// Apply values from TOML config (middle priority).
    pub fn apply_config(mut self, config: Option<&VpnServerIrohConfig>) -> Self {
        if let Some(cfg) = config {
            if cfg.network.is_some() {
                self.network = cfg.network.clone();
            }
            if cfg.server_ip.is_some() {
                self.server_ip = cfg.server_ip.clone();
            }
            if cfg.shared.mtu.is_some() {
                self.mtu = cfg.shared.mtu;
            }
            if cfg.shared.keepalive_secs.is_some() {
                self.keepalive_secs = cfg.shared.keepalive_secs;
            }
            if cfg.secret_file.is_some() {
                self.secret_file = cfg.secret_file.clone();
            }
            if !cfg.shared.relay_urls.is_empty() {
                self.relay_urls = Some(cfg.shared.relay_urls.clone());
            }
            if cfg.shared.dns_server.is_some() {
                self.dns_server = cfg.shared.dns_server.clone();
            }
            if !cfg.auth_tokens.is_empty() {
                self.auth_tokens = Some(cfg.auth_tokens.clone());
            }
            if cfg.auth_tokens_file.is_some() {
                self.auth_tokens_file = cfg.auth_tokens_file.clone();
            }
        }
        self
    }

    /// Apply CLI arguments (highest priority).
    /// Only non-None/non-empty values override.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_cli(
        mut self,
        network: Option<String>,
        server_ip: Option<String>,
        mtu: Option<u16>,
        keepalive_secs: Option<u16>,
        secret_file: Option<PathBuf>,
        relay_urls: Vec<String>,
        dns_server: Option<String>,
        auth_tokens: Vec<String>,
        auth_tokens_file: Option<PathBuf>,
    ) -> Self {
        if network.is_some() {
            self.network = network;
        }
        if server_ip.is_some() {
            self.server_ip = server_ip;
        }
        if mtu.is_some() {
            self.mtu = mtu;
        }
        if keepalive_secs.is_some() {
            self.keepalive_secs = keepalive_secs;
        }
        if secret_file.is_some() {
            self.secret_file = secret_file;
        }
        if !relay_urls.is_empty() {
            self.relay_urls = Some(relay_urls);
        }
        if dns_server.is_some() {
            self.dns_server = dns_server;
        }
        if !auth_tokens.is_empty() {
            self.auth_tokens = Some(auth_tokens);
        }
        if auth_tokens_file.is_some() {
            self.auth_tokens_file = auth_tokens_file;
        }
        self
    }

    /// Build the final resolved configuration.
    pub fn build(self) -> Result<ResolvedVpnServerConfig> {
        let network = self.network.ok_or_else(|| {
            anyhow::anyhow!(
                "VPN network CIDR is required.\n\
                 Specify via CLI: --network <CIDR>\n\
                 Or in config: network = \"10.0.0.0/24\""
            )
        })?;

        // Validate network CIDR format
        validate_vpn_network(&network, self.server_ip.as_deref(), "config")?;

        // Validate MTU and keepalive ranges
        let mtu = self.mtu.unwrap_or(DEFAULT_VPN_MTU);
        let keepalive_secs = self.keepalive_secs.unwrap_or(DEFAULT_VPN_KEEPALIVE_SECS);
        validate_mtu(mtu, "config")?;
        validate_keepalive(keepalive_secs, "config")?;

        // Validate auth_tokens mutual exclusion
        let has_tokens = self.auth_tokens.as_ref().is_some_and(|t| !t.is_empty());
        if has_tokens && self.auth_tokens_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_tokens and auth_tokens_file.\n\
                 Use --auth-tokens <TOKEN> or --auth-tokens-file <FILE>, not both."
            );
        }

        Ok(ResolvedVpnServerConfig {
            network,
            server_ip: self.server_ip,
            mtu,
            keepalive_secs,
            secret_file: self.secret_file,
            relay_urls: self.relay_urls.unwrap_or_default(),
            dns_server: self.dns_server,
            auth_tokens: self.auth_tokens.unwrap_or_default(),
            auth_tokens_file: self.auth_tokens_file,
        })
    }
}

/// Resolved VPN client configuration (all values finalized).
#[derive(Debug, Clone)]
pub struct ResolvedVpnClientConfig {
    pub server_node_id: String,
    pub mtu: u16,
    pub keepalive_secs: u16,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
    pub routes: Vec<String>,
    pub relay_urls: Vec<String>,
    pub dns_server: Option<String>,
    pub no_reconnect: bool,
    pub max_reconnect_attempts: u32,
}

/// Builder for VPN client configuration with layered overrides.
#[derive(Default)]
pub struct VpnClientConfigBuilder {
    server_node_id: Option<String>,
    mtu: Option<u16>,
    keepalive_secs: Option<u16>,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    routes: Option<Vec<String>>,
    relay_urls: Option<Vec<String>>,
    dns_server: Option<String>,
    no_reconnect: Option<bool>,
    max_reconnect_attempts: Option<u32>,
}

impl VpnClientConfigBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply default values (lowest priority).
    pub fn apply_defaults(mut self) -> Self {
        self.mtu = Some(DEFAULT_VPN_MTU);
        self.keepalive_secs = Some(DEFAULT_VPN_KEEPALIVE_SECS);
        self.routes = Some(vec![]);
        self.relay_urls = Some(vec![]);
        self.no_reconnect = Some(false);
        self.max_reconnect_attempts = Some(0); // 0 = unlimited
        self
    }

    /// Apply values from TOML config (middle priority).
    pub fn apply_config(mut self, config: Option<&VpnClientIrohConfig>) -> Self {
        if let Some(cfg) = config {
            if cfg.server_node_id.is_some() {
                self.server_node_id = cfg.server_node_id.clone();
            }
            if cfg.shared.mtu.is_some() {
                self.mtu = cfg.shared.mtu;
            }
            if cfg.shared.keepalive_secs.is_some() {
                self.keepalive_secs = cfg.shared.keepalive_secs;
            }
            if cfg.auth_token.is_some() {
                self.auth_token = cfg.auth_token.clone();
            }
            if cfg.auth_token_file.is_some() {
                self.auth_token_file = cfg.auth_token_file.clone();
            }
            if !cfg.routes.is_empty() {
                self.routes = Some(cfg.routes.clone());
            }
            if !cfg.shared.relay_urls.is_empty() {
                self.relay_urls = Some(cfg.shared.relay_urls.clone());
            }
            if cfg.shared.dns_server.is_some() {
                self.dns_server = cfg.shared.dns_server.clone();
            }
            if cfg.no_reconnect {
                self.no_reconnect = Some(true);
            }
            if cfg.max_reconnect_attempts.is_some() {
                self.max_reconnect_attempts = cfg.max_reconnect_attempts;
            }
        }
        self
    }

    /// Apply CLI arguments (highest priority).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_cli(
        mut self,
        server_node_id: Option<String>,
        mtu: Option<u16>,
        keepalive_secs: Option<u16>,
        auth_token: Option<String>,
        auth_token_file: Option<PathBuf>,
        routes: Vec<String>,
        relay_urls: Vec<String>,
        dns_server: Option<String>,
        no_reconnect: bool,
        max_reconnect_attempts: Option<u32>,
    ) -> Self {
        if server_node_id.is_some() {
            self.server_node_id = server_node_id;
        }
        if mtu.is_some() {
            self.mtu = mtu;
        }
        if keepalive_secs.is_some() {
            self.keepalive_secs = keepalive_secs;
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
        if !relay_urls.is_empty() {
            self.relay_urls = Some(relay_urls);
        }
        if dns_server.is_some() {
            self.dns_server = dns_server;
        }
        if no_reconnect {
            self.no_reconnect = Some(true);
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

        // Validate MTU and keepalive ranges
        let mtu = self.mtu.unwrap_or(DEFAULT_VPN_MTU);
        let keepalive_secs = self.keepalive_secs.unwrap_or(DEFAULT_VPN_KEEPALIVE_SECS);
        validate_mtu(mtu, "config")?;
        validate_keepalive(keepalive_secs, "config")?;

        // Require at least one route (like WireGuard AllowedIPs)
        let routes = self.routes.unwrap_or_default();
        if routes.is_empty() {
            anyhow::bail!(
                "At least one route is required.\n\
                 Specify via CLI: --route 0.0.0.0/0 (full tunnel) or --route 10.0.0.0/24 (split tunnel)\n\
                 Or in config: routes = [\"0.0.0.0/0\"]"
            );
        }

        // Validate route CIDR format
        for route in &routes {
            validate_cidr(route)
                .with_context(|| format!("Invalid route CIDR '{}' (e.g., 0.0.0.0/0)", route))?;
        }

        // Validate auth_token mutual exclusion
        if self.auth_token.is_some() && self.auth_token_file.is_some() {
            anyhow::bail!(
                "Cannot specify both auth_token and auth_token_file.\n\
                 Use --auth-token <TOKEN> or --auth-token-file <FILE>, not both."
            );
        }

        Ok(ResolvedVpnClientConfig {
            server_node_id,
            mtu,
            keepalive_secs,
            auth_token: self.auth_token,
            auth_token_file: self.auth_token_file,
            routes,
            relay_urls: self.relay_urls.unwrap_or_default(),
            dns_server: self.dns_server,
            no_reconnect: self.no_reconnect.unwrap_or(false),
            max_reconnect_attempts: self.max_reconnect_attempts.unwrap_or(0),
        })
    }
}
