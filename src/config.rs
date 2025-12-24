//! Configuration file support for tunnel-rs.
//!
//! Configuration structure:
//! - `role` and `mode` fields for validation
//! - Shared options at top level (source/target)
//! - Mode-specific sections: [iroh-default], [iroh-manual], [custom], [nostr]
//!
//! Role-based field semantics are enforced by `validate()` at parse time:
//! - Sender-only fields are rejected when role=receiver
//! - Receiver-only fields are rejected when role=sender
//! - CIDR networks and source URLs are validated for correct format

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

// ============================================================================
// Configuration Structures
// ============================================================================

/// iroh-default mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct IrohDefaultConfig {
    /// Path to secret key file for persistent identity (sender only)
    pub secret_file: Option<PathBuf>,
    /// Base64-encoded secret key for persistent identity (sender only).
    /// Prefer `secret_file` in production; inline secrets are best kept to testing or
    /// special cases due to VCS/log exposure risk. Secret files should be 0600 on Unix.
    pub secret: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,
    /// NodeId of the sender to connect to (receiver only)
    pub node_id: Option<String>,
}

/// iroh-manual mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct IrohManualConfig {
    pub stun_servers: Option<Vec<String>>,
}

/// custom mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct CustomConfig {
    pub stun_servers: Option<Vec<String>>,
}

/// Allowed source networks for receiver-requested source feature.
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
/// - Sender-only: `allowed_sources`, `max_sessions`
/// - Receiver-only: `request_source`
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
    /// Maximum concurrent sessions (sender only, default: 10)
    pub max_sessions: Option<usize>,
    /// Allowed source networks in CIDR notation (sender only).
    /// Receivers must request sources within these networks.
    pub allowed_sources: Option<AllowedSources>,
    /// Source URL to request from sender (receiver only, required).
    /// Format: tcp://host:port or udp://host:port
    #[serde(alias = "source")]
    pub request_source: Option<String>,
}

/// Unified sender configuration.
#[derive(Deserialize, Default)]
pub struct SenderConfig {
    // Validation fields
    pub role: Option<String>,
    pub mode: Option<String>,

    // Shared options
    pub source: Option<String>,

    // Mode-specific sections
    #[serde(rename = "iroh-default")]
    pub iroh_default: Option<IrohDefaultConfig>,
    #[serde(rename = "iroh-manual")]
    pub iroh_manual: Option<IrohManualConfig>,
    pub custom: Option<CustomConfig>,
    pub nostr: Option<NostrConfig>,
}

/// Unified receiver configuration.
#[derive(Deserialize, Default)]
pub struct ReceiverConfig {
    // Validation fields
    pub role: Option<String>,
    pub mode: Option<String>,

    // Shared options
    pub target: Option<String>,

    // Mode-specific sections
    #[serde(rename = "iroh-default")]
    pub iroh_default: Option<IrohDefaultConfig>,
    #[serde(rename = "iroh-manual")]
    pub iroh_manual: Option<IrohManualConfig>,
    pub custom: Option<CustomConfig>,
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

// ============================================================================
// Config Accessor Methods
// ============================================================================

impl SenderConfig {
    /// Get iroh-default config section.
    pub fn iroh_default(&self) -> Option<&IrohDefaultConfig> {
        self.iroh_default.as_ref()
    }

    /// Get iroh-manual config section.
    pub fn iroh_manual(&self) -> Option<&IrohManualConfig> {
        self.iroh_manual.as_ref()
    }

    /// Get custom config section.
    pub fn custom(&self) -> Option<&CustomConfig> {
        self.custom.as_ref()
    }

    /// Get nostr config section.
    pub fn nostr(&self) -> Option<&NostrConfig> {
        self.nostr.as_ref()
    }

    /// Validate that config matches expected role and mode.
    ///
    /// Enforces:
    /// - Role must be "sender"
    /// - Mode must match expected_mode
    /// - Nostr mode: rejects receiver-only fields (request_source)
    /// - Nostr mode: validates CIDR format in allowed_sources
    /// - Non-nostr modes: validates source URL format if present
    pub fn validate(&self, expected_mode: &str) -> Result<()> {
        let role = self.role.as_deref().context(
            "Config file missing required 'role' field. Add: role = \"sender\"",
        )?;
        if role != "sender" {
            anyhow::bail!(
                "Config file has role = \"{}\", but running as sender",
                role
            );
        }

        let mode = self.mode.as_deref().context(
            "Config file missing required 'mode' field. Add: mode = \"iroh-default\" (or iroh-manual, custom, nostr)",
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
            "iroh-default" | "iroh-manual" | "custom" | "nostr" => {}
            _ => anyhow::bail!("Unknown mode '{}'. Valid modes: iroh-default, iroh-manual, custom, nostr", expected_mode),
        }

        // Mode-specific validation
        if expected_mode == "iroh-default" {
            if let Some(ref iroh) = self.iroh_default {
                if iroh.secret.is_some() && iroh.secret_file.is_some() {
                    anyhow::bail!(
                        "[iroh-default] Use only one of 'secret' or 'secret_file'."
                    );
                }
            }
        }
        if expected_mode == "nostr" {
            if let Some(ref nostr) = self.nostr {
                if nostr.nsec.is_some() && nostr.nsec_file.is_some() {
                    anyhow::bail!("[nostr] Use only one of 'nsec' or 'nsec_file'.");
                }
                // Reject receiver-only fields
                if nostr.request_source.is_some() {
                    anyhow::bail!(
                        "[nostr] 'source' / 'request_source' is a receiver-only field. \
                        Senders use 'allowed_sources' to restrict what receivers can request."
                    );
                }
                // Validate CIDR format
                if let Some(ref allowed) = nostr.allowed_sources {
                    validate_allowed_sources(allowed)?;
                }
            }
            // Sender nostr mode should not have top-level source
            if self.source.is_some() {
                anyhow::bail!(
                    "Top-level 'source' is not allowed for nostr sender mode. \
                    Use [nostr.allowed_sources] to restrict what receivers can request."
                );
            }
        } else {
            // Non-nostr modes: validate source URL format if present
            if let Some(ref source) = self.source {
                validate_tcp_udp_url(source, "source")?;
            }
        }

        Ok(())
    }
}

impl ReceiverConfig {
    /// Get iroh-default config section.
    pub fn iroh_default(&self) -> Option<&IrohDefaultConfig> {
        self.iroh_default.as_ref()
    }

    /// Get iroh-manual config section.
    pub fn iroh_manual(&self) -> Option<&IrohManualConfig> {
        self.iroh_manual.as_ref()
    }

    /// Get custom config section.
    pub fn custom(&self) -> Option<&CustomConfig> {
        self.custom.as_ref()
    }

    /// Get nostr config section.
    pub fn nostr(&self) -> Option<&NostrConfig> {
        self.nostr.as_ref()
    }

    /// Validate that config matches expected role and mode.
    ///
    /// Enforces:
    /// - Role must be "receiver"
    /// - Mode must match expected_mode
    /// - Nostr mode: rejects sender-only fields (allowed_sources, max_sessions)
    /// - Nostr mode: validates request_source URL format if present
    /// - Non-nostr modes: validates target URL format if present
    pub fn validate(&self, expected_mode: &str) -> Result<()> {
        let role = self.role.as_deref().context(
            "Config file missing required 'role' field. Add: role = \"receiver\"",
        )?;
        if role != "receiver" {
            anyhow::bail!(
                "Config file has role = \"{}\", but running as receiver",
                role
            );
        }

        let mode = self.mode.as_deref().context(
            "Config file missing required 'mode' field. Add: mode = \"iroh-default\" (or iroh-manual, custom, nostr)",
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
            "iroh-default" | "iroh-manual" | "custom" | "nostr" => {}
            _ => anyhow::bail!("Unknown mode '{}'. Valid modes: iroh-default, iroh-manual, custom, nostr", expected_mode),
        }

        // Mode-specific validation
        if expected_mode == "iroh-default" {
            if let Some(ref iroh) = self.iroh_default {
                if iroh.secret.is_some() || iroh.secret_file.is_some() {
                    anyhow::bail!(
                        "[iroh-default] 'secret' and 'secret_file' are sender-only fields."
                    );
                }
            }
        }
        if expected_mode == "nostr" {
            if let Some(ref nostr) = self.nostr {
                if nostr.nsec.is_some() && nostr.nsec_file.is_some() {
                    anyhow::bail!("[nostr] Use only one of 'nsec' or 'nsec_file'.");
                }
                // Reject sender-only fields
                if nostr.allowed_sources.is_some() {
                    anyhow::bail!(
                        "[nostr] 'allowed_sources' is a sender-only field. \
                        Receivers use 'source' to specify what to request from sender."
                    );
                }
                if nostr.max_sessions.is_some() {
                    anyhow::bail!(
                        "[nostr] 'max_sessions' is a sender-only field."
                    );
                }
                // Validate request_source URL format
                if let Some(ref source) = nostr.request_source {
                    validate_tcp_udp_url(source, "request_source")?;
                }
            }
        }

        // Validate target URL format if present
        if let Some(ref target) = self.target {
            validate_tcp_udp_url(target, "target")?;
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

/// Resolve the default sender config path (~/.config/tunnel-rs/sender.toml).
fn default_sender_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("tunnel-rs").join("sender.toml"))
}

/// Resolve the default receiver config path (~/.config/tunnel-rs/receiver.toml).
fn default_receiver_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("tunnel-rs").join("receiver.toml"))
}

/// Load sender configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path
/// - `path`: None loads from the default path (~/.config/tunnel-rs/sender.toml)
pub fn load_sender_config(path: Option<&Path>) -> Result<SenderConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => default_sender_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not find default config path. Use -c to specify a config file."))?,
    };
    load_config(&config_path)
}

/// Load receiver configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path
/// - `path`: None loads from the default path (~/.config/tunnel-rs/receiver.toml)
pub fn load_receiver_config(path: Option<&Path>) -> Result<ReceiverConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => default_receiver_config_path()
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
