//! SOCKS5 proxy bridge for routing relay connections through Tor.
//!
//! This module provides a local TCP proxy that forwards connections through a SOCKS5 proxy.
//! It's used to connect to .onion relay URLs when iroh doesn't natively support SOCKS5.
//!
//! Architecture:
//! ```text
//! iroh -> localhost:random_port -> SOCKS5 proxy -> .onion:port -> iroh-relay
//! ```

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_socks::tcp::Socks5Stream;
use url::Url;

/// Configuration for the SOCKS5 bridge.
#[derive(Clone, Debug)]
pub struct Socks5BridgeConfig {
    /// SOCKS5 proxy address (e.g., "127.0.0.1:9050")
    pub proxy_addr: String,
    /// Target host (e.g., "abc123.onion")
    pub target_host: String,
    /// Target port
    pub target_port: u16,
}

/// A running SOCKS5 bridge that forwards connections.
pub struct Socks5Bridge {
    /// Local address the bridge is listening on
    pub local_addr: SocketAddr,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Handle to the bridge task
    _handle: tokio::task::JoinHandle<()>,
}

impl Socks5Bridge {
    /// Start a new SOCKS5 bridge.
    ///
    /// Returns the bridge instance which includes the local address to connect to.
    pub async fn start(config: Socks5BridgeConfig) -> Result<Self> {
        // Bind to a random local port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("Failed to bind SOCKS5 bridge listener")?;
        let local_addr = listener.local_addr()?;

        info!(
            "SOCKS5 bridge started on {} -> {}:{} via {}",
            local_addr, config.target_host, config.target_port, config.proxy_addr
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let config = Arc::new(config);

        let handle = tokio::spawn(async move {
            Self::run_bridge(listener, config, shutdown_rx).await;
        });

        Ok(Self {
            local_addr,
            shutdown_tx,
            _handle: handle,
        })
    }

    /// Run the bridge, accepting connections and forwarding them through SOCKS5.
    async fn run_bridge(
        listener: TcpListener,
        config: Arc<Socks5BridgeConfig>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            debug!("SOCKS5 bridge: accepted connection from {}", peer_addr);
                            let config = config.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, config).await {
                                    warn!("SOCKS5 bridge connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("SOCKS5 bridge accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("SOCKS5 bridge shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Handle a single connection by forwarding it through SOCKS5.
    async fn handle_connection(
        mut local_stream: TcpStream,
        config: Arc<Socks5BridgeConfig>,
    ) -> Result<()> {
        // Connect through SOCKS5 to the target
        let target = format!("{}:{}", config.target_host, config.target_port);
        debug!("SOCKS5 bridge: connecting to {} via {}", target, config.proxy_addr);

        let socks_stream = Socks5Stream::connect(
            config.proxy_addr.as_str(),
            (config.target_host.as_str(), config.target_port),
        )
        .await
        .with_context(|| {
            format!(
                "Failed to connect through SOCKS5 proxy {} to {}",
                config.proxy_addr, target
            )
        })?;

        debug!("SOCKS5 bridge: connected to {}", target);

        let mut remote_stream = socks_stream.into_inner();

        // Forward data bidirectionally
        let (mut local_read, mut local_write) = local_stream.split();
        let (mut remote_read, mut remote_write) = remote_stream.split();

        let local_to_remote = async {
            let mut buf = [0u8; 8192];
            loop {
                let n = local_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                remote_write.write_all(&buf[..n]).await?;
            }
            remote_write.shutdown().await?;
            Ok::<_, std::io::Error>(())
        };

        let remote_to_local = async {
            let mut buf = [0u8; 8192];
            loop {
                let n = remote_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                local_write.write_all(&buf[..n]).await?;
            }
            local_write.shutdown().await?;
            Ok::<_, std::io::Error>(())
        };

        let (r1, r2) = tokio::join!(local_to_remote, remote_to_local);
        if let Err(e) = r1 {
            debug!("SOCKS5 bridge: local->remote error: {}", e);
        }
        if let Err(e) = r2 {
            debug!("SOCKS5 bridge: remote->local error: {}", e);
        }

        debug!("SOCKS5 bridge: connection closed");
        Ok(())
    }

    /// Shutdown the bridge.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for Socks5Bridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Parse a SOCKS5 proxy URL and return the address.
///
/// Supports formats:
/// - socks5://host:port
/// - socks5h://host:port (with DNS resolution through proxy)
/// - host:port (assumes SOCKS5)
pub fn parse_socks5_url(url: &str) -> Result<String> {
    if url.starts_with("socks5://") || url.starts_with("socks5h://") {
        let parsed = Url::parse(url).context("Invalid SOCKS5 URL")?;
        let host = parsed.host_str().context("SOCKS5 URL missing host")?;
        let port = parsed.port().unwrap_or(1080);
        Ok(format!("{}:{}", host, port))
    } else if url.contains(':') {
        // Assume it's already host:port
        Ok(url.to_string())
    } else {
        anyhow::bail!("Invalid SOCKS5 proxy URL: {}. Expected format: socks5://host:port or host:port", url)
    }
}

/// Check if a URL is a .onion address.
///
/// Parses the URL and checks only the hostname (not paths or other URL parts).
/// Returns false if the URL is invalid or has no host.
pub fn is_onion_url(url: &str) -> bool {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|h| h.ends_with(".onion")))
        .unwrap_or(false)
}

/// Parse a relay URL and extract host and port.
pub fn parse_relay_url(url: &str) -> Result<(String, u16)> {
    let parsed = Url::parse(url).context("Invalid relay URL")?;
    let host = parsed.host_str().context("Relay URL missing host")?.to_string();
    let port = parsed.port().unwrap_or_else(|| {
        match parsed.scheme() {
            "https" | "wss" => 443,
            _ => 80,
        }
    });
    Ok((host, port))
}

/// Set up SOCKS5 bridges for .onion relay URLs.
///
/// Returns:
/// - The list of relay URLs with .onion URLs rewritten to local bridge addresses
/// - A list of bridge handles that must be kept alive
pub async fn setup_relay_bridges(
    relay_urls: Vec<String>,
    socks5_proxy: Option<&str>,
) -> Result<(Vec<String>, Vec<Socks5Bridge>)> {
    let mut rewritten_urls = Vec::new();
    let mut bridges = Vec::new();

    for url in relay_urls {
        if is_onion_url(&url) {
            // Require SOCKS5 proxy for .onion URLs
            let proxy = socks5_proxy.context(
                "SOCKS5 proxy required for .onion relay URLs"
            )?;
            let proxy_addr = parse_socks5_url(proxy)?;
            let (target_host, target_port) = parse_relay_url(&url)?;

            let config = Socks5BridgeConfig {
                proxy_addr,
                target_host,
                target_port,
            };

            let bridge = Socks5Bridge::start(config).await?;
            let local_addr = bridge.local_addr;

            // Rewrite the URL to use the local bridge
            let parsed = Url::parse(&url)?;
            let new_url = format!("{}://127.0.0.1:{}", parsed.scheme(), local_addr.port());
            info!("Rewriting relay URL: {} -> {}", url, new_url);

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
    fn test_parse_socks5_url() {
        assert_eq!(parse_socks5_url("socks5://127.0.0.1:9050").unwrap(), "127.0.0.1:9050");
        assert_eq!(parse_socks5_url("socks5h://localhost:1080").unwrap(), "localhost:1080");
        assert_eq!(parse_socks5_url("127.0.0.1:9050").unwrap(), "127.0.0.1:9050");
    }

    #[test]
    fn test_is_onion_url() {
        assert!(is_onion_url("http://abc123.onion"));
        assert!(is_onion_url("http://abc123.onion:80"));
        assert!(!is_onion_url("http://example.com"));
    }

    #[test]
    fn test_parse_relay_url() {
        let (host, port) = parse_relay_url("http://abc123.onion").unwrap();
        assert_eq!(host, "abc123.onion");
        assert_eq!(port, 80);

        let (host, port) = parse_relay_url("https://relay.example.com:8443").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 8443);
    }
}
