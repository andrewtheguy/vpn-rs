//! Configuration file support for tunnel-rs.
//!
//! Configuration structure:
//! - `role` and `mode` fields for validation
//! - Shared options at top level (source/target)
//! - Mode-specific sections: [iroh-default], [iroh-manual], [custom]

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

/// nostr mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct NostrConfig {
    pub relays: Option<Vec<String>>,
    pub nsec: Option<String>,
    pub peer_npub: Option<String>,
    pub stun_servers: Option<Vec<String>>,
    pub max_sessions: Option<usize>,
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
        "stun.services.mozilla.com:3478".to_string(),
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
