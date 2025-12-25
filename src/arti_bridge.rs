//! Embedded Arti (Tor) bridge for routing relay connections.
//!
//! This module provides a local TCP proxy that forwards connections through
//! an embedded Arti Tor client. Unlike the SOCKS5 bridge, this doesn't require
//! an external Tor daemon - the Tor client is embedded directly.
//!
//! Architecture:
//! ```text
//! iroh -> localhost:random_port -> Arti bridge -> tor_client.connect() -> .onion:port
//! ```
//!
//! This module is only available when the `embedded-tor` feature is enabled.

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use arti_client::{config::TorClientConfigBuilder, ErrorKind, HasKind, TorClient};
use tor_rtcompat::PreferredRuntime;

/// Maximum retry attempts for Tor connections
const MAX_RETRIES: u32 = 5;
/// Delay between retry attempts in seconds
const RETRY_DELAY_SECS: u64 = 5;

/// Check if an Arti error is retryable (temporary network issues).
fn is_retryable(e: &arti_client::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::TorNetworkTimeout
            | ErrorKind::RemoteNetworkTimeout
            | ErrorKind::TransientFailure
            | ErrorKind::LocalNetworkError
    )
}

/// Get the Arti data directory for persistent state.
fn get_arti_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tunnel-rs")
        .join("arti")
}

/// Bootstrap and return an Arti Tor client with persistent state.
///
/// State is stored in:
/// - Linux: ~/.local/share/tunnel-rs/arti/
/// - macOS: ~/Library/Application Support/tunnel-rs/arti/
/// - Windows: %APPDATA%/tunnel-rs/arti/
pub async fn create_arti_client() -> Result<TorClient<PreferredRuntime>> {
    let data_dir = get_arti_data_dir();
    let state_dir = data_dir.join("state");
    let cache_dir = data_dir.join("cache");

    // Create directories if they don't exist
    std::fs::create_dir_all(&state_dir).context("Failed to create Arti state directory")?;
    std::fs::create_dir_all(&cache_dir).context("Failed to create Arti cache directory")?;

    info!(
        "Bootstrapping Tor client (state: {})...",
        state_dir.display()
    );

    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir).build()?;
    let client = TorClient::create_bootstrapped(config).await?;

    info!("Tor client bootstrapped successfully!");
    Ok(client)
}

/// A running Arti bridge that forwards connections through embedded Tor.
pub struct ArtiBridge {
    /// Local address the bridge is listening on
    pub local_addr: SocketAddr,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Handle to the bridge task
    _handle: tokio::task::JoinHandle<()>,
}

impl ArtiBridge {
    /// Start a new Arti bridge for the given target.
    ///
    /// The bridge will:
    /// 1. Listen on a random local port
    /// 2. Accept connections from iroh
    /// 3. Forward them through Tor to the target .onion address
    pub async fn start(
        tor_client: Arc<TorClient<PreferredRuntime>>,
        target_host: String,
        target_port: u16,
    ) -> Result<Self> {
        // Bind to a random local port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("Failed to bind Arti bridge listener")?;
        let local_addr = listener.local_addr()?;

        info!(
            "Arti bridge started on {} -> {}:{}",
            local_addr, target_host, target_port
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            Self::run_bridge(listener, tor_client, target_host, target_port, shutdown_rx).await;
        });

        Ok(Self {
            local_addr,
            shutdown_tx,
            _handle: handle,
        })
    }

    /// Run the bridge, accepting connections and forwarding them through Tor.
    async fn run_bridge(
        listener: TcpListener,
        tor_client: Arc<TorClient<PreferredRuntime>>,
        target_host: String,
        target_port: u16,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            debug!("Arti bridge: accepted connection from {}", peer_addr);
                            let client = tor_client.clone();
                            let host = target_host.clone();
                            let port = target_port;
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, client, &host, port).await {
                                    warn!("Arti bridge connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Arti bridge accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Arti bridge shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Handle a single connection by forwarding it through Tor.
    async fn handle_connection(
        mut local_stream: TcpStream,
        tor_client: Arc<TorClient<PreferredRuntime>>,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        debug!(
            "Arti bridge: connecting to {}:{} via Tor",
            target_host, target_port
        );

        // Connect through Tor with retry logic
        let mut tor_stream = None;
        let mut last_error = None;

        for attempt in 1..=MAX_RETRIES {
            match tor_client.connect((target_host, target_port)).await {
                Ok(stream) => {
                    tor_stream = Some(stream);
                    break;
                }
                Err(e) => {
                    debug!(
                        "Arti bridge: connection attempt {}/{} failed: {}",
                        attempt, MAX_RETRIES, e
                    );

                    if !is_retryable(&e) {
                        return Err(e.into());
                    }

                    last_error = Some(e);
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS))
                            .await;
                    }
                }
            }
        }

        let mut tor_stream = tor_stream.ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to connect through Tor after {} attempts: {}",
                MAX_RETRIES,
                last_error.map(|e| e.to_string()).unwrap_or_default()
            )
        })?;

        debug!("Arti bridge: connected to {}:{}", target_host, target_port);

        // Forward data bidirectionally using tokio's copy_bidirectional
        // This is more efficient than manual split() and handles the Arti stream properly
        match tokio::io::copy_bidirectional(&mut local_stream, &mut tor_stream).await {
            Ok((to_tor, from_tor)) => {
                debug!(
                    "Arti bridge: connection closed (sent {} bytes, received {} bytes)",
                    to_tor, from_tor
                );
            }
            Err(e) => {
                debug!("Arti bridge: bidirectional copy error: {}", e);
            }
        }

        Ok(())
    }

    /// Shutdown the bridge.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for ArtiBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Set up Arti bridges for .onion relay URLs.
///
/// This function is the embedded Tor equivalent of `socks5_bridge::setup_relay_bridges()`.
/// It bootstraps a single Arti client and creates bridges for all .onion URLs.
///
/// Returns:
/// - The list of relay URLs with .onion URLs rewritten to local bridge addresses
/// - A list of bridge handles that must be kept alive
pub async fn setup_relay_bridges_arti(
    relay_urls: Vec<String>,
) -> Result<(Vec<String>, Vec<ArtiBridge>)> {
    use crate::socks5_bridge::{is_onion_url, parse_relay_url};
    use url::Url;

    // Check if any URLs are .onion
    let has_onion = relay_urls.iter().any(|url| is_onion_url(url));

    if !has_onion {
        // No .onion URLs, return as-is
        return Ok((relay_urls, Vec::new()));
    }

    // Bootstrap Arti client once for all bridges
    info!("Bootstrapping embedded Tor client for .onion relay connections...");
    let tor_client = Arc::new(create_arti_client().await?);

    let mut rewritten_urls = Vec::new();
    let mut bridges = Vec::new();

    for url in relay_urls {
        if is_onion_url(&url) {
            let (target_host, target_port) = parse_relay_url(&url)?;

            let bridge = ArtiBridge::start(tor_client.clone(), target_host, target_port).await?;
            let local_addr = bridge.local_addr;

            // Rewrite the URL to use the local bridge
            let parsed = Url::parse(&url)?;
            let new_url = format!("{}://127.0.0.1:{}", parsed.scheme(), local_addr.port());
            info!("Rewriting relay URL: {} -> {} (via embedded Tor)", url, new_url);

            rewritten_urls.push(new_url);
            bridges.push(bridge);
        } else {
            // Non-.onion URLs pass through unchanged
            rewritten_urls.push(url);
        }
    }

    Ok((rewritten_urls, bridges))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_arti_data_dir() {
        let dir = get_arti_data_dir();
        assert!(dir.ends_with("tunnel-rs/arti"));
    }
}
