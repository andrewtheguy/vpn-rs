//! Configuration file support for tunnel-rs.
//!
//! Unified configuration shared across all modes:
//! - Iroh default mode: Uses iroh P2P discovery (supports TCP and UDP)
//! - Iroh manual mode: Uses manual signaling with iroh transport (TCP and UDP)
//! - Custom mode: Uses manual ICE signaling with str0m+quinn (TCP only)

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

// ============================================================================
// Unified Configurations
// ============================================================================

/// Unified sender configuration for all modes.
#[derive(Deserialize, Default)]
pub struct SenderConfig {
    // Common fields
    pub protocol: Option<String>,
    pub target: Option<String>,

    // Iroh default mode
    pub secret_file: Option<PathBuf>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,

    // Custom mode
    pub stun_servers: Option<Vec<String>>,
}

/// Unified receiver configuration for all modes.
#[derive(Deserialize, Default)]
pub struct ReceiverConfig {
    // Common fields
    pub protocol: Option<String>,
    pub listen: Option<String>,

    // Iroh default mode
    pub node_id: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,

    // Custom mode
    pub stun_servers: Option<Vec<String>>,
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
