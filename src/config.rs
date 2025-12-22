//! Configuration file support for tunnel-rs.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Sender configuration from TOML file.
#[derive(Deserialize, Default)]
pub struct SenderConfig {
    pub protocol: Option<String>,
    pub target: Option<String>,
    pub secret_file: Option<std::path::PathBuf>, // path to secret key file
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub direct_only: Option<bool>,
    pub dns_server: Option<String>, // custom iroh-dns-server URL
    pub manual: Option<bool>,
    pub stun_servers: Option<Vec<String>>,
    #[allow(dead_code)]
    pub manual_secret_key: Option<String>,
}

/// Receiver configuration from TOML file.
#[derive(Deserialize, Default)]
pub struct ReceiverConfig {
    pub protocol: Option<String>,
    pub node_id: Option<String>,
    pub listen: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
    pub dns_server: Option<String>, // custom iroh-dns-server URL
    pub manual: Option<bool>,
    pub stun_servers: Option<Vec<String>>,
    #[allow(dead_code)]
    pub manual_secret_key: Option<String>,
}

/// Load configuration from a TOML file.
pub fn load_config<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// Resolve the default config path (~/.config/tunnel-rs/config.toml).
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("tunnel-rs").join("config.toml"))
}

/// Load configuration from an explicit path, or fall back to the default config path if present.
pub fn load_config_or_default<T: for<'de> Deserialize<'de> + Default>(
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

/// Default public STUN servers for manual mode.
pub fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun.services.mozilla.com:3478".to_string(),
    ]
}
