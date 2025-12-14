//! Common endpoint helpers for iroh tunnel connections.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::{PkarrPublisher, PkarrResolver}},
    endpoint::{Builder as EndpointBuilder, ConnectionType, PathSelection},
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, Watcher,
};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

pub const UDP_ALPN: &[u8] = b"udp-forward/1";
pub const TCP_ALPN: &[u8] = b"tcp-forward/1";
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Load secret key from file (base64 encoded).
pub fn load_secret(path: &Path) -> Result<SecretKey> {
    if !path.exists() {
        anyhow::bail!(
            "Secret key file not found: {}\nGenerate one with: tunnel-rs generate-secret --output {}",
            path.display(),
            path.display()
        );
    }

    let content = std::fs::read_to_string(path).context("Failed to read secret key file")?;
    load_secret_from_string(content.trim())
}

/// Load secret key from a base64-encoded string.
pub fn load_secret_from_string(base64_key: &str) -> Result<SecretKey> {
    let bytes = BASE64
        .decode(base64_key)
        .context("Invalid base64 in secret key")?;

    SecretKey::try_from(&bytes[..]).context("Invalid secret key (must be 32 bytes)")
}

/// Get public key (EndpointId) from secret key.
pub fn secret_to_endpoint_id(secret: &SecretKey) -> EndpointId {
    secret.public()
}

/// Parse relay URL strings into a RelayMode.
pub fn parse_relay_mode(relay_urls: &[String]) -> Result<RelayMode> {
    if relay_urls.is_empty() {
        Ok(RelayMode::Default)
    } else {
        let parsed_urls: Vec<RelayUrl> = relay_urls
            .iter()
            .map(|url| url.parse().context(format!("Invalid relay URL: {}", url)))
            .collect::<Result<Vec<_>>>()?;
        let relay_map = RelayMap::from_iter(parsed_urls);
        Ok(RelayMode::Custom(relay_map))
    }
}

/// Validate that relay-only mode is used correctly.
pub fn validate_relay_only(relay_only: bool, relay_urls: &[String]) -> Result<()> {
    if relay_only && relay_urls.is_empty() {
        anyhow::bail!(
            "--relay-only requires at least one --relay-url to be specified.\n\
            The default public relay is rate-limited and cannot be used for relay-only mode."
        );
    }
    Ok(())
}

/// Print relay configuration status messages.
pub fn print_relay_status(relay_urls: &[String], relay_only: bool, using_custom_relay: bool) {
    if using_custom_relay {
        if relay_urls.len() == 1 {
            println!("Using custom relay server");
        } else {
            println!("Using {} custom relay servers (with failover)", relay_urls.len());
        }
    }
    if relay_only {
        println!("Relay-only mode: all traffic will go through the relay server");
    }
}

/// Create a base endpoint builder with common configuration.
///
/// # Arguments
/// * `relay_mode` - The relay mode to use
/// * `relay_only` - If true, only use relay connections (no direct P2P)
/// * `dns_server` - Optional custom DNS server URL (e.g., "https://dns.example.com")
/// * `secret_key` - Optional secret key (required for publishing to custom DNS server)
pub fn create_endpoint_builder(
    relay_mode: RelayMode,
    relay_only: bool,
    dns_server: Option<&str>,
    secret_key: Option<&SecretKey>,
) -> Result<EndpointBuilder> {
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.max_idle_timeout(None);

    let mut builder = Endpoint::empty_builder(relay_mode)
        .transport_config(transport_config);

    if relay_only {
        builder = builder.path_selection(PathSelection::RelayOnly);
    } else {
        match (dns_server, secret_key) {
            (Some(dns_url), Some(secret)) => {
                // Custom DNS server with publishing and resolving via HTTP (pkarr)
                let pkarr_url: Url = dns_url.parse().context("Invalid DNS server URL")?;
                println!("Using custom DNS server: {}", dns_url);
                builder = builder
                    .discovery(PkarrPublisher::builder(pkarr_url.clone()).build(secret.clone()))
                    .discovery(PkarrResolver::builder(pkarr_url));
            }
            (Some(dns_url), None) => {
                // Custom DNS server, resolve only via HTTP (no secret = can't publish)
                let pkarr_url: Url = dns_url.parse().context("Invalid DNS server URL")?;
                println!("Using custom DNS server (resolve only): {}", dns_url);
                builder = builder.discovery(PkarrResolver::builder(pkarr_url));
            }
            (None, _) => {
                // Default n0 DNS
                builder = builder
                    .discovery(PkarrPublisher::n0_dns())
                    .discovery(DnsDiscovery::n0_dns());
            }
        }
        // mDNS always enabled for local network discovery
        builder = builder.discovery(MdnsDiscovery::builder());
    }

    Ok(builder)
}

/// Create a sender endpoint with optional persistent identity.
pub async fn create_sender_endpoint(
    relay_urls: &[String],
    relay_only: bool,
    secret_file: Option<&PathBuf>,
    dns_server: Option<&str>,
    alpn: &[u8],
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, relay_only, using_custom_relay);

    // Load secret key first (needed for both identity and DNS publishing)
    let secret = if let Some(secret_path) = secret_file {
        let secret = load_secret(secret_path)?;
        let endpoint_id = secret_to_endpoint_id(&secret);
        println!("Loaded identity from: {}", secret_path.display());
        println!("EndpointId: {}", endpoint_id);
        Some(secret)
    } else {
        None
    };

    let mut builder = create_endpoint_builder(
        relay_mode,
        relay_only,
        dns_server,
        secret.as_ref(),
    )?
    .alpns(vec![alpn.to_vec()]);

    if let Some(secret) = secret {
        builder = builder.secret_key(secret);
    }

    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;

    // Wait for endpoint to come online with timeout
    println!("Waiting for endpoint to come online (timeout: {}s)...", RELAY_CONNECT_TIMEOUT.as_secs());
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => {}
        Err(_) => anyhow::bail!("Endpoint failed to come online after {}s - check relay server connectivity", RELAY_CONNECT_TIMEOUT.as_secs()),
    }

    Ok(endpoint)
}

/// Create a receiver endpoint.
pub async fn create_receiver_endpoint(
    relay_urls: &[String],
    relay_only: bool,
    dns_server: Option<&str>,
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, relay_only, using_custom_relay);

    // Receiver doesn't have a secret key, so can only resolve (not publish) from custom DNS
    let builder = create_endpoint_builder(relay_mode, relay_only, dns_server, None)?;
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;

    // Wait for endpoint to come online with timeout
    println!("Waiting for endpoint to come online (timeout: {}s)...", RELAY_CONNECT_TIMEOUT.as_secs());
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => {}
        Err(_) => anyhow::bail!("Endpoint failed to come online after {}s - check relay server connectivity", RELAY_CONNECT_TIMEOUT.as_secs()),
    }

    Ok(endpoint)
}

/// Connect to a sender endpoint with relay failover support.
pub async fn connect_to_sender(
    endpoint: &Endpoint,
    sender_id: EndpointId,
    relay_urls: &[String],
    relay_only: bool,
    alpn: &[u8],
) -> Result<iroh::endpoint::Connection> {
    println!("Connecting to sender {}...", sender_id);

    if relay_only {
        // Try each relay URL until one works
        let mut last_error = None;
        for relay_url_str in relay_urls {
            let relay_url: RelayUrl = relay_url_str.parse().context("Invalid relay URL")?;
            let endpoint_addr = EndpointAddr::new(sender_id).with_relay_url(relay_url.clone());
            println!("Trying relay: {} (timeout: {}s)", relay_url, RELAY_CONNECT_TIMEOUT.as_secs());

            match tokio::time::timeout(
                RELAY_CONNECT_TIMEOUT,
                endpoint.connect(endpoint_addr, alpn),
            ).await {
                Ok(Ok(conn)) => {
                    println!("Connected via relay: {}", relay_url);
                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    eprintln!("Failed to connect via {}: {}", relay_url, e);
                    last_error = Some(e.to_string());
                }
                Err(_) => {
                    eprintln!("Connection to {} timed out", relay_url);
                    last_error = Some(format!("Connection to {} timed out", relay_url));
                }
            }
        }
        anyhow::bail!(
            "Failed to connect via any relay: {}",
            last_error.unwrap_or_else(|| "No relay URLs provided".to_string())
        )
    } else {
        let endpoint_addr = EndpointAddr::new(sender_id);
        println!("Connecting (timeout: {}s)...", RELAY_CONNECT_TIMEOUT.as_secs());
        match tokio::time::timeout(
            RELAY_CONNECT_TIMEOUT,
            endpoint.connect(endpoint_addr, alpn),
        ).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(e).context("Failed to connect to sender"),
            Err(_) => anyhow::bail!("Connection timed out after {}s", RELAY_CONNECT_TIMEOUT.as_secs()),
        }
    }
}

/// Print connection type information.
pub fn print_connection_type(endpoint: &Endpoint, remote_id: EndpointId) {
    if let Some(mut conn_type_watcher) = endpoint.conn_type(remote_id) {
        let conn_type = conn_type_watcher.get();
        println!("Connection type: {:?}", conn_type);
    }
}

pub const DIRECT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Validate that direct-only and relay-only are mutually exclusive.
pub fn validate_direct_only(direct_only: bool, relay_only: bool) -> Result<()> {
    if direct_only && relay_only {
        anyhow::bail!("--direct-only and --relay-only are mutually exclusive");
    }
    Ok(())
}

/// Result of waiting for a direct connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectConnectionResult {
    /// Direct P2P connection was established
    Direct,
    /// Connection is still using relay (hole-punching failed or timed out)
    StillRelay,
}

/// Wait for connection type to stabilize.
/// Gives time for hole-punching to establish direct connection.
/// Uses async notifications from the Watcher to react immediately to changes.
pub async fn wait_for_direct_connection(
    endpoint: &Endpoint,
    remote_id: EndpointId,
) -> DirectConnectionResult {
    let Some(mut watcher) = endpoint.conn_type(remote_id) else {
        return DirectConnectionResult::StillRelay; // Unknown = treat as non-direct
    };

    // Check initial state - if already direct, accept immediately
    if matches!(watcher.get(), ConnectionType::Direct(_)) {
        return DirectConnectionResult::Direct;
    }

    // Wait for connection type updates with timeout
    let result = tokio::time::timeout(DIRECT_WAIT_TIMEOUT, async {
        loop {
            match watcher.updated().await {
                Ok(ConnectionType::Direct(_)) => {
                    return DirectConnectionResult::Direct;
                }
                Ok(_) => {
                    // Still Relay or Mixed, continue waiting for next update
                }
                Err(_) => {
                    return DirectConnectionResult::StillRelay;
                }
            }
        }
    })
    .await;

    match result {
        Ok(conn_result) => conn_result,
        Err(_timeout) => DirectConnectionResult::StillRelay,
    }
}
