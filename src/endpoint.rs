//! Common endpoint helpers for iroh tunnel connections.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::{PkarrPublisher, PkarrResolver}},
    endpoint::{Builder as EndpointBuilder, PathSelection},
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey, Watcher,
};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

pub const UDP_ALPN: &[u8] = b"udp-forward/1";
pub const TCP_ALPN: &[u8] = b"tcp-forward/1";
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC keep-alive interval for tunnel connections.
///
/// Active connections send pings at this interval to prevent idle timeout.
/// This value matches iroh's relay ping interval (15s), which is designed to be
/// well under half common QUIC idle timeout defaults (30s is typical in many
/// implementations and protocol discussions). This codebase uses a more generous
/// [`QUIC_IDLE_TIMEOUT`] of 300s for long-running tunnels, but 15s keep-alive
/// remains appropriate for NAT traversal and prompt dead-connection detection.
///
/// For long-running tunnels, 15s is a good balance between:
/// - Keeping NAT mappings alive (most NAT timeouts are 30-120s)
/// - Not wasting bandwidth with excessive pings
/// - Detecting dead connections reasonably quickly
///
/// Reference: iroh uses 1s for endpoint default, 15s for relay pings.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout for tunnel connections.
///
/// Connections without activity (no data or keep-alive pings) for this duration
/// are considered dead and closed. With QUIC_KEEP_ALIVE_INTERVAL enabled,
/// this timeout only triggers for truly unresponsive connections.
///
/// 5 minutes is generous for tunnels where the underlying TCP/UDP connection
/// may have long idle periods between bursts of activity.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

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
    // Configure transport with keep-alive and idle timeout.
    // See QUIC_KEEP_ALIVE_INTERVAL and QUIC_IDLE_TIMEOUT constants for rationale.
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));

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
    secret: Option<SecretKey>,
    dns_server: Option<&str>,
    alpn: &[u8],
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, relay_only, using_custom_relay);

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
