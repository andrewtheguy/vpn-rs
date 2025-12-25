//! Configuration file support for tunnel-rs.
//!
//! Configuration structure:
//! - `role` and `mode` fields for validation
//! - Mode-specific sections: [iroh], [ice-manual], [ice-nostr]
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
/// - Server-only: `allowed_sources`, `max_sessions`, `secret`, `secret_file`
/// - Client-only: `request_source`, `target`, `node_id`
#[derive(Deserialize, Default, Clone)]
pub struct IrohConfig {
    /// Path to secret key file for persistent identity (server only)
    pub secret_file: Option<PathBuf>,
    /// Base64-encoded secret key for persistent identity (server only).
    /// Prefer `secret_file` in production; inline secrets are best kept to testing or
    /// special cases due to VCS/log exposure risk. Secret files should be 0600 on Unix.
    pub secret: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub dns_server: Option<String>,
    /// NodeId of the server to connect to (client only)
    pub node_id: Option<String>,
    /// Allowed source networks in CIDR notation (server only).
    /// Clients must request sources within these networks.
    pub allowed_sources: Option<AllowedSources>,
    /// Maximum concurrent sessions (server only, default: 100)
    pub max_sessions: Option<usize>,
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

/// ice-manual mode configuration.
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

/// nostr mode configuration.
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

/// Unified server configuration.
#[derive(Deserialize, Default)]
pub struct ServerConfig {
    // Validation fields
    pub role: Option<String>,
    pub mode: Option<String>,

    // Shared options
    pub source: Option<String>,

    // Mode-specific sections
    pub iroh: Option<IrohConfig>,
    #[serde(rename = "ice-manual")]
    pub ice_manual: Option<CustomManualConfig>,
    #[serde(rename = "ice-nostr")]
    pub nostr: Option<NostrConfig>,
}

/// Unified client configuration.
#[derive(Deserialize, Default)]
pub struct ClientConfig {
    // Validation fields
    pub role: Option<String>,
    pub mode: Option<String>,

    // Mode-specific sections (each mode has its own target field)
    pub iroh: Option<IrohConfig>,
    #[serde(rename = "ice-manual")]
    pub ice_manual: Option<CustomManualConfig>,
    #[serde(rename = "ice-nostr")]
    pub nostr: Option<NostrConfig>,
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate that a string is a valid CIDR network (IPv4 or IPv6).
fn validate_cidr(cidr: &str) -> Result<()> {
    cidr.parse::<ipnet::IpNet>()
        .with_context(|| format!("Invalid CIDR network '{}'. Expected format: 192.168.0.0/16 or ::1/128", cidr))?;
    Ok(())
}

/// Validate that a string is a valid tcp:// or udp:// URL with host and port.
fn validate_tcp_udp_url(value: &str, field_name: &str) -> Result<()> {
    let url = url::Url::parse(value)
        .with_context(|| format!("Invalid {} '{}'. Expected format: tcp://host:port or udp://host:port", field_name, value))?;

    let scheme = url.scheme();
    if scheme != "tcp" && scheme != "udp" {
        anyhow::bail!("Invalid {} scheme '{}'. Must be 'tcp' or 'udp'", field_name, scheme);
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

/// Validate that a string is a valid SOCKS5 proxy URL.
///
/// - When relay_urls contain `.onion` addresses, requires `socks5h://` scheme for DNS resolution through proxy
/// - Otherwise, accepts both `socks5://` and `socks5h://` schemes:
///   - `socks5://host:port` - Basic SOCKS5 proxy
///   - `socks5h://host:port` - SOCKS5 with remote DNS resolution (recommended for .onion addresses)
fn validate_socks5_proxy(value: &str, relay_urls: Option<&Vec<String>>) -> Result<()> {
    let url = url::Url::parse(value)
        .with_context(|| format!("Invalid socks5_proxy '{}'. Expected format: socks5://host:port or socks5h://host:port", value))?;

    let scheme = url.scheme();

    // Check if any relay URLs contain .onion addresses
    let has_onion_relay = relay_urls.map_or(false, |urls| {
        urls.iter().any(|u| u.contains(".onion"))
    });

    if has_onion_relay {
        // For .onion relays, socks5h:// is required for DNS resolution through proxy
        if scheme != "socks5h" {
            anyhow::bail!(
                "Invalid socks5_proxy scheme '{}'. When using .onion relay URLs, \
                 socks5h:// scheme (with remote DNS resolution) is required. \
                 Change socks5_proxy to use 'socks5h://host:port' format.",
                scheme
            );
        }
    } else {
        // For non-.onion relays, both schemes are acceptable
        if scheme != "socks5" && scheme != "socks5h" {
            anyhow::bail!(
                "Invalid socks5_proxy scheme '{}'. Must be 'socks5' or 'socks5h'",
                scheme
            );
        }
    }

    if url.host_str().is_none() {
        anyhow::bail!("socks5_proxy '{}' missing host", value);
    }

    if url.port().is_none() {
        anyhow::bail!("socks5_proxy '{}' missing port", value);
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
        let role = self.role.as_deref().context(
            "Config file missing required 'role' field. Add: role = \"server\"",
        )?;
        if role != "server" {
            anyhow::bail!(
                "Config file has role = \"{}\", but running as server",
                role
            );
        }

        let mode = self.mode.as_deref().context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\" (or \"ice-manual\", \"ice-nostr\")",
        )?;
        if mode != expected_mode {
            anyhow::bail!(
                "Config file has mode = \"{}\", but running with {}",
                mode,
                expected_mode
            );
        }

        // Validate mode is known
        match expected_mode {
            "iroh" | "ice-manual" | "ice-nostr" => {}
            _ => anyhow::bail!("Unknown mode '{}'. Valid modes: iroh, ice-manual, ice-nostr", expected_mode),
        }

        // Mode-specific validation
        if expected_mode == "iroh" {
            if let Some(ref iroh) = self.iroh {
                if iroh.secret.is_some() && iroh.secret_file.is_some() {
                    anyhow::bail!(
                        "[iroh] Use only one of 'secret' or 'secret_file'."
                    );
                }
                // Reject client-only fields
                if iroh.request_source.is_some() || iroh.target.is_some() {
                    anyhow::bail!(
                        "[iroh] 'source' / 'request_source' / 'target' are client-only fields. \
                        Servers use 'allowed_sources' to restrict what clients can request."
                    );
                }
                if iroh.node_id.is_some() {
                    anyhow::bail!(
                        "[iroh] 'node_id' is a client-only field."
                    );
                }
                // Validate CIDR format
                if let Some(ref allowed) = iroh.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
                // Validate SOCKS5 proxy URL format if present
                if let Some(ref proxy) = iroh.socks5_proxy {
                    validate_socks5_proxy(proxy, iroh.relay_urls.as_ref()).context("[iroh] Invalid SOCKS5 proxy URL")?;
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
        if expected_mode == "ice-nostr" {
            if let Some(ref nostr) = self.nostr {
                if nostr.nsec.is_some() && nostr.nsec_file.is_some() {
                    anyhow::bail!("[ice-nostr] Use only one of 'nsec' or 'nsec_file'.");
                }
                // Reject client-only fields
                if nostr.request_source.is_some() {
                    anyhow::bail!(
                        "[ice-nostr] 'source' / 'request_source' is a client-only field. \
                        Servers use 'allowed_sources' to restrict what clients can request."
                    );
                }
                // Validate CIDR format
                if let Some(ref allowed) = nostr.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
            }
            // Server ice-nostr mode should not have top-level source
            if self.source.is_some() {
                anyhow::bail!(
                    "Top-level 'source' is not allowed for ice-nostr server mode. \
                    Use [ice-nostr.allowed_sources] to restrict what clients can request."
                );
            }
        }
        if expected_mode == "ice-manual" {
            if let Some(ref ice_manual) = self.ice_manual {
                // Reject client-only fields
                if ice_manual.request_source.is_some() || ice_manual.target.is_some() {
                    anyhow::bail!(
                        "[ice-manual] 'source' / 'request_source' / 'target' are client-only fields. \
                        Servers use 'allowed_sources' to restrict what clients can request."
                    );
                }
                // Validate CIDR format
                if let Some(ref allowed) = ice_manual.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
            }
            // Reject top-level source for ice-manual server
            if self.source.is_some() {
                anyhow::bail!(
                    "Top-level 'source' is not allowed for ice-manual server mode. \
                    Use [ice-manual.allowed_sources] to restrict what clients can request."
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
        let role = self.role.as_deref().context(
            "Config file missing required 'role' field. Add: role = \"client\"",
        )?;
        if role != "client" {
            anyhow::bail!(
                "Config file has role = \"{}\", but running as client",
                role
            );
        }

        let mode = self.mode.as_deref().context(
            "Config file missing required 'mode' field. Add: mode = \"iroh\" (or \"ice-manual\", \"ice-nostr\")",
        )?;
        if mode != expected_mode {
            anyhow::bail!(
                "Config file has mode = \"{}\", but running with {}",
                mode,
                expected_mode
            );
        }

        // Validate mode is known
        match expected_mode {
            "iroh" | "ice-manual" | "ice-nostr" => {}
            _ => anyhow::bail!("Unknown mode '{}'. Valid modes: iroh, ice-manual, ice-nostr", expected_mode),
        }

        // Mode-specific validation
        if expected_mode == "iroh" {
            if let Some(ref iroh) = self.iroh {
                if iroh.secret.is_some() || iroh.secret_file.is_some() {
                    anyhow::bail!(
                        "[iroh] 'secret' and 'secret_file' are server-only fields."
                    );
                }
                // Reject server-only fields
                if iroh.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[iroh] 'allowed_sources' is a server-only field. \
                        Clients use 'source' to specify what to request from server."
                    );
                }
                if iroh.max_sessions.is_some() {
                    anyhow::bail!(
                        "[iroh] 'max_sessions' is a server-only field."
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
                // Validate SOCKS5 proxy URL format if present
                if let Some(ref proxy) = iroh.socks5_proxy {
                    validate_socks5_proxy(proxy, iroh.relay_urls.as_ref()).context("[iroh] Invalid SOCKS5 proxy URL")?;
                }
            }
        }
        if expected_mode == "ice-nostr" {
            if let Some(ref nostr) = self.nostr {
                if nostr.nsec.is_some() && nostr.nsec_file.is_some() {
                    anyhow::bail!("[ice-nostr] Use only one of 'nsec' or 'nsec_file'.");
                }
                // Reject server-only fields
                if nostr.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[ice-nostr] 'allowed_sources' is a server-only field. \
                        Clients use 'source' to specify what to request from server."
                    );
                }
                if nostr.max_sessions.is_some() {
                    anyhow::bail!(
                        "[ice-nostr] 'max_sessions' is a server-only field."
                    );
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

        if expected_mode == "ice-manual" {
            if let Some(ref ice_manual) = self.ice_manual {
                // Reject server-only fields
                if ice_manual.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[ice-manual] 'allowed_sources' is a server-only field. \
                        Clients use 'source' to specify what to request from server."
                    );
                }
                // Validate request_source URL format
                if let Some(ref source) = ice_manual.request_source {
                    validate_tcp_udp_url(source, "request_source")?;
                }
                // Validate target format (host:port)
                if let Some(ref target) = ice_manual.target {
                    validate_host_port(target, "target")?;
                }
            }
        }

        Ok(())
    }
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
/// - `path`: Some(path) loads from the specified path
/// - `path`: None loads from the default path (~/.config/tunnel-rs/server.toml)
pub fn load_server_config(path: Option<&Path>) -> Result<ServerConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => default_server_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not find default config path. Use -c to specify a config file."))?,
    };
    load_config(&config_path)
}

/// Load client configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path
/// - `path`: None loads from the default path (~/.config/tunnel-rs/client.toml)
pub fn load_client_config(path: Option<&Path>) -> Result<ClientConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => default_client_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not find default config path. Use -c to specify a config file."))?,
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
pub fn default_nostr_relays() -> Vec<String> {
    vec![
        "wss://relay.damus.io".to_string(),
        "wss://nos.lol".to_string(),
        "wss://relay.nostr.band".to_string(),
        "wss://relay.primal.net".to_string(),
        "wss://nostr.mom".to_string(),
        "wss://relay.snort.social".to_string(),
    ]
}
