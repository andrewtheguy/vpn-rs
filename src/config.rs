//! Configuration file support for tunnel-rs.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Sender configuration from TOML file.
#[derive(Deserialize, Default)]
pub struct SenderConfig {
    pub protocol: Option<String>,
    pub target: Option<String>,
    pub secret_file: Option<std::path::PathBuf>, // path to secret key file
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
}

/// Receiver configuration from TOML file.
#[derive(Deserialize, Default)]
pub struct ReceiverConfig {
    pub protocol: Option<String>,
    pub node_id: Option<String>,
    pub listen: Option<String>,
    pub relay_urls: Option<Vec<String>>,
    pub relay_only: Option<bool>,
}

/// Load configuration from a TOML file.
pub fn load_config<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}
