//! Configuration file support for tunnel-rs.
//!
//! Supports mode-specific configuration:
//! - Iroh mode: Uses iroh P2P discovery (supports TCP and UDP)
//! - ICE mode: Uses manual signaling with copy-paste (TCP only)

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

// ============================================================================
// Iroh Mode Configurations
// ============================================================================

/// Iroh mode sender configuration.
#[derive(Deserialize, Default)]
pub struct IrohSenderConfig {
    pub protocol: Option<String>,
    pub target: Option<String>,
    pub secret_file: Option<PathBuf>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,
}

/// Iroh mode receiver configuration.
#[derive(Deserialize, Default)]
pub struct IrohReceiverConfig {
    pub protocol: Option<String>,
    pub node_id: Option<String>,
    pub listen: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>,
}

// ============================================================================
// ICE Mode Configurations
// ============================================================================

/// ICE mode sender configuration (TCP only).
#[derive(Deserialize, Default)]
pub struct IceSenderConfig {
    pub target: Option<String>,
    pub stun_servers: Option<Vec<String>>,
}

/// ICE mode receiver configuration (TCP only).
#[derive(Deserialize, Default)]
pub struct IceReceiverConfig {
    pub listen: Option<String>,
    pub stun_servers: Option<Vec<String>>,
}

// ============================================================================
// Config Loading
// ============================================================================

/// Load configuration from a TOML file.
fn load_config<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// Resolve the default config path (~/.config/tunnel-rs/config.toml).
fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("tunnel-rs").join("config.toml"))
}

/// Load configuration from an explicit path, or fall back to default if present.
fn load_config_or_default<T: for<'de> Deserialize<'de> + Default>(
    path: Option<&Path>,
) -> Result<T> {
    if let Some(path) = path {
        return load_config(path);
    }

    if let Some(default_path) = default_config_path() {
        if default_path.exists() {
            return load_config(&default_path);
        }
    }

    Ok(T::default())
}

// Mode-specific config loaders

/// Load Iroh sender configuration.
pub fn load_iroh_sender_config(path: Option<&Path>) -> Result<IrohSenderConfig> {
    load_config_or_default(path)
}

/// Load Iroh receiver configuration.
pub fn load_iroh_receiver_config(path: Option<&Path>) -> Result<IrohReceiverConfig> {
    load_config_or_default(path)
}

/// Load ICE sender configuration.
pub fn load_ice_sender_config(path: Option<&Path>) -> Result<IceSenderConfig> {
    load_config_or_default(path)
}

/// Load ICE receiver configuration.
pub fn load_ice_receiver_config(path: Option<&Path>) -> Result<IceReceiverConfig> {
    load_config_or_default(path)
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
