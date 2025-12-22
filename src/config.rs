//! Configuration file support for tunnel-rs.
//!
//! Hierarchical configuration with explicit mode selection:
//! - mode: "iroh.default", "iroh.manual", or "custom"
//! - Shared options at top level (protocol, target/listen, stun_servers)
//! - [iroh.default] section for iroh default mode options
//! - [iroh.manual] section for iroh manual mode options
//! - [custom] section for custom mode options

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

// ============================================================================
// Hierarchical Configuration Structures
// ============================================================================

/// Iroh default mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct IrohDefaultConfig {
    pub secret_file: Option<PathBuf>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,
    pub node_id: Option<String>, // receiver only
}

/// Iroh manual mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct IrohManualConfig {
    // Currently uses stun_servers from top level
    // Reserved for future iroh-manual-specific options
}

/// Iroh section containing default and manual subsections.
#[derive(Deserialize, Default, Clone)]
pub struct IrohConfig {
    pub default: Option<IrohDefaultConfig>,
    pub manual: Option<IrohManualConfig>,
}

/// Custom mode configuration.
#[derive(Deserialize, Default, Clone)]
pub struct CustomConfig {
    // Currently uses stun_servers from top level
    // Reserved for future custom-mode-specific options
}

/// Unified sender configuration with hierarchical structure.
#[derive(Deserialize, Default)]
pub struct SenderConfig {
    // Mode selector: "iroh.default", "iroh.manual", or "custom"
    pub mode: Option<String>,

    // Shared options
    pub protocol: Option<String>,
    pub target: Option<String>,
    pub stun_servers: Option<Vec<String>>,

    // Mode-specific sections
    pub iroh: Option<IrohConfig>,
    pub custom: Option<CustomConfig>,
}

/// Unified receiver configuration with hierarchical structure.
#[derive(Deserialize, Default)]
pub struct ReceiverConfig {
    // Mode selector: "iroh.default", "iroh.manual", or "custom"
    pub mode: Option<String>,

    // Shared options
    pub protocol: Option<String>,
    pub listen: Option<String>,
    pub stun_servers: Option<Vec<String>>,

    // Mode-specific sections
    pub iroh: Option<IrohConfig>,
    pub custom: Option<CustomConfig>,
}

// ============================================================================
// Config Accessor Methods
// ============================================================================

impl SenderConfig {
    /// Get iroh default config, with defaults.
    pub fn iroh_default(&self) -> IrohDefaultConfig {
        self.iroh
            .as_ref()
            .and_then(|i| i.default.clone())
            .unwrap_or_default()
    }

    /// Get iroh manual config, with defaults.
    pub fn iroh_manual(&self) -> IrohManualConfig {
        self.iroh
            .as_ref()
            .and_then(|i| i.manual.clone())
            .unwrap_or_default()
    }

    /// Get custom config, with defaults.
    pub fn custom(&self) -> CustomConfig {
        self.custom.clone().unwrap_or_default()
    }
}

impl ReceiverConfig {
    /// Get iroh default config, with defaults.
    pub fn iroh_default(&self) -> IrohDefaultConfig {
        self.iroh
            .as_ref()
            .and_then(|i| i.default.clone())
            .unwrap_or_default()
    }

    /// Get iroh manual config, with defaults.
    pub fn iroh_manual(&self) -> IrohManualConfig {
        self.iroh
            .as_ref()
            .and_then(|i| i.manual.clone())
            .unwrap_or_default()
    }

    /// Get custom config, with defaults.
    pub fn custom(&self) -> CustomConfig {
        self.custom.clone().unwrap_or_default()
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
    dirs::config_dir().map(|dir| dir.join("tunnel-rs").join("sender.toml"))
}

/// Resolve the default receiver config path (~/.config/tunnel-rs/receiver.toml).
fn default_receiver_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("tunnel-rs").join("receiver.toml"))
}

/// Load sender configuration from an explicit path, or from default location.
///
/// - `path`: Some(path) loads from the specified path
/// - `path`: None loads from the default path (~/.config/tunnel-rs/sender.toml)
pub fn load_sender_config(path: Option<&Path>) -> Result<SenderConfig> {
    let config_path = match path {
        Some(p) => p.to_path_buf(),
        None => default_sender_config_path()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?,
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
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?,
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
