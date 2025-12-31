//! tunnel-rs (iroh-only)
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.

use ::iroh::SecretKey;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use tunnel_common::config::{
    expand_tilde, load_client_config, load_server_config, ClientConfig, ServerConfig,
};
use tunnel_iroh::iroh_mode::endpoint::{
    load_secret, load_secret_from_string, secret_to_endpoint_id,
};
use tunnel_iroh::{auth, iroh_mode, secret, socks5_bridge};

#[derive(Parser)]
#[command(name = "tunnel-rs")]
#[command(version)]
#[command(about = "Forward TCP/UDP traffic through iroh P2P connections")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as server (accepts connections and forwards to source)
    Server {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/server.toml)
        #[arg(long)]
        default_config: bool,

        /// Allowed TCP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-tcp 127.0.0.0/8 --allowed-tcp 192.168.0.0/16
        #[arg(long = "allowed-tcp")]
        allowed_tcp: Vec<String>,

        /// Allowed UDP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-udp 10.0.0.0/8 --allowed-udp ::1/128
        #[arg(long = "allowed-udp")]
        allowed_udp: Vec<String>,

        /// Maximum concurrent sessions (default: 100)
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Base64-encoded secret key for persistent identity
        #[arg(long)]
        secret: Option<String>,

        /// Path to secret key file for persistent identity
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P).
        /// Only available with the 'test-utils' feature: cargo build --features test-utils
        #[cfg(feature = "test-utils")]
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,

        /// [Experimental] SOCKS5 proxy for relay connections (required for .onion URLs).
        /// Tor support is experimental and might not work reliably.
        /// E.g., socks5://127.0.0.1:9050 for Tor
        #[arg(long)]
        socks5_proxy: Option<String>,

        /// Allowed client NodeIds (repeatable). Only clients with these NodeIds can connect.
        /// Required for authentication. Use with --allowed-clients-file for file-based config.
        #[arg(long = "allowed-clients", value_name = "NODE_ID")]
        allowed_clients: Vec<String>,

        /// Path to file containing allowed client NodeIds (one per line, # comments allowed).
        /// Can be combined with --allowed-clients for additional inline NodeIds.
        #[arg(long, value_name = "FILE")]
        allowed_clients_file: Option<PathBuf>,
    },
    /// Run as client (connects to server and exposes local port)
    Client {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/client.toml)
        #[arg(long)]
        default_config: bool,

        /// EndpointId of the server to connect to
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,

        /// Source address to request from server (tcp://host:port or udp://host:port)
        /// The server must have this in its --allowed-tcp or --allowed-udp list
        #[arg(short, long)]
        source: Option<String>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        target: Option<String>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P).
        /// Only available with the 'test-utils' feature: cargo build --features test-utils
        #[cfg(feature = "test-utils")]
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,

        /// [Experimental] SOCKS5 proxy for relay connections (required for .onion URLs).
        /// Tor support is experimental and might not work reliably.
        /// E.g., socks5://127.0.0.1:9050 for Tor
        #[arg(long)]
        socks5_proxy: Option<String>,

        /// Base64-encoded secret key for persistent identity (for authentication)
        #[arg(long)]
        secret: Option<String>,

        /// Path to secret key file for persistent identity (for authentication)
        #[arg(long)]
        secret_file: Option<PathBuf>,
    },
    /// Generate a new iroh secret key file (for automation/setup)
    GenerateIrohKey {
        /// Path where to save the secret key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Show the iroh node ID (EndpointId) for an existing secret key file
    ShowIrohNodeId {
        /// Path to the secret key file
        #[arg(short, long)]
        secret_file: PathBuf,
    },
}

fn normalize_optional_endpoint(value: Option<String>) -> Option<String> {
    value.and_then(|v| if v.trim().is_empty() { None } else { Some(v) })
}

/// Resolved parameters for iroh server mode.
/// CLI values take precedence over config file values.
struct ServerIrohParams {
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    max_sessions: Option<usize>,
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    dns_server: Option<String>,
    socks5_proxy: Option<String>,
    allowed_clients: Vec<String>,
    allowed_clients_file: Option<PathBuf>,
}

/// Resolve iroh server parameters from CLI and config.
/// CLI values take precedence; empty CLI vectors fall back to config.
fn resolve_server_iroh_params(
    cli: &Command,
    iroh_cfg: Option<&tunnel_common::config::IrohConfig>,
) -> ServerIrohParams {
    let cfg = iroh_cfg.cloned().unwrap_or_default();
    let cfg_allowed = cfg.allowed_sources.clone().unwrap_or_default();

    let Command::Server {
        allowed_tcp,
        allowed_udp,
        max_sessions,
        secret,
        secret_file,
        relay_urls,
        dns_server,
        socks5_proxy,
        allowed_clients,
        allowed_clients_file,
        ..
    } = cli
    else {
        unreachable!("resolve_server_iroh_params called with non-server command");
    };

    let (secret, secret_file) = if secret.is_some() || secret_file.is_some() {
        (secret.clone(), secret_file.clone())
    } else {
        (cfg.secret.clone(), cfg.secret_file.clone())
    };

    ServerIrohParams {
        allowed_tcp: if allowed_tcp.is_empty() {
            cfg_allowed.tcp.clone()
        } else {
            allowed_tcp.clone()
        },
        allowed_udp: if allowed_udp.is_empty() {
            cfg_allowed.udp.clone()
        } else {
            allowed_udp.clone()
        },
        max_sessions: max_sessions.or(cfg.max_sessions),
        secret,
        secret_file,
        relay_urls: if relay_urls.is_empty() {
            cfg.relay_urls.clone().unwrap_or_default()
        } else {
            relay_urls.clone()
        },
        dns_server: dns_server.clone().or(cfg.dns_server.clone()),
        socks5_proxy: socks5_proxy.clone().or(cfg.socks5_proxy.clone()),
        allowed_clients: if allowed_clients.is_empty() {
            cfg.allowed_clients.clone().unwrap_or_default()
        } else {
            allowed_clients.clone()
        },
        allowed_clients_file: allowed_clients_file
            .clone()
            .or(cfg.allowed_clients_file.clone()),
    }
}

/// Resolved parameters for iroh client mode.
/// CLI values take precedence over config file values.
struct ClientIrohParams {
    server_node_id: Option<String>,
    source: Option<String>,
    target: Option<String>,
    relay_urls: Vec<String>,
    dns_server: Option<String>,
    socks5_proxy: Option<String>,
    secret: Option<String>,
    secret_file: Option<PathBuf>,
}

/// Resolve iroh client parameters from CLI and config.
/// CLI values take precedence; empty CLI vectors fall back to config.
fn resolve_client_iroh_params(
    cli: &Command,
    iroh_cfg: Option<&tunnel_common::config::IrohConfig>,
) -> ClientIrohParams {
    let cfg = iroh_cfg.cloned().unwrap_or_default();

    let Command::Client {
        server_node_id,
        source,
        target,
        relay_urls,
        dns_server,
        socks5_proxy,
        secret,
        secret_file,
        ..
    } = cli
    else {
        unreachable!("resolve_client_iroh_params called with non-client command");
    };

    let (secret, secret_file) = if secret.is_some() || secret_file.is_some() {
        (secret.clone(), secret_file.clone())
    } else {
        (cfg.secret.clone(), cfg.secret_file.clone())
    };

    ClientIrohParams {
        server_node_id: server_node_id.clone().or(cfg.server_node_id.clone()),
        source: normalize_optional_endpoint(source.clone()).or(cfg.request_source.clone()),
        target: target.clone().or(cfg.target.clone()),
        relay_urls: if relay_urls.is_empty() {
            cfg.relay_urls.clone().unwrap_or_default()
        } else {
            relay_urls.clone()
        },
        dns_server: dns_server.clone().or(cfg.dns_server.clone()),
        socks5_proxy: socks5_proxy.clone().or(cfg.socks5_proxy.clone()),
        secret,
        secret_file,
    }
}

fn resolve_iroh_secret(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
) -> Result<Option<SecretKey>> {
    match (secret, secret_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "Cannot combine --secret with --secret-file (or secret and secret_file in config)."
            );
        }
        (Some(secret), None) => {
            let trimmed = secret.trim();
            if trimmed.is_empty() {
                anyhow::bail!("Inline secret is empty. Provide a base64-encoded secret key.");
            }
            let secret = load_secret_from_string(trimmed)
                .context("Invalid inline secret key (expected base64)")?;
            let endpoint_id = secret_to_endpoint_id(&secret);
            log::info!("Loaded identity from inline secret");
            log::info!("EndpointId: {}", endpoint_id);
            Ok(Some(secret))
        }
        (None, Some(path)) => {
            let expanded = expand_tilde(&path);
            let secret = load_secret(&expanded)?;
            let endpoint_id = secret_to_endpoint_id(&secret);
            log::info!("Loaded identity from: {}", expanded.display());
            log::info!("EndpointId: {}", endpoint_id);
            Ok(Some(secret))
        }
        (None, None) => Ok(None),
    }
}

/// Load server config based on flags. Returns (config, was_loaded_from_file).
fn resolve_server_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(ServerConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_server_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_server_config(None)?, true))
    } else {
        Ok((ServerConfig::default(), false))
    }
}

/// Load client config based on flags. Returns (config, was_loaded_from_file).
fn resolve_client_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(ClientConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_client_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_client_config(None)?, true))
    } else {
        Ok((ClientConfig::default(), false))
    }
}

/// Validate that the SOCKS5 proxy is a Tor proxy, if one is specified.
async fn validate_socks5_proxy_if_present(socks5_proxy: &Option<String>) -> Result<()> {
    if let Some(ref proxy) = socks5_proxy {
        socks5_bridge::validate_tor_proxy(proxy).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .filter_module("tunnel_rs", log::LevelFilter::Info)
        .filter_module("tunnel_iroh", log::LevelFilter::Info)
        .try_init();
    let args = Args::parse();
    let command = args.command;

    match &command {
        Command::Server {
            config,
            default_config,
            ..
        } => {
            let (cfg, from_file) = resolve_server_config(config.clone(), *default_config)?;

            if from_file {
                cfg.validate("iroh")?;
            }

            let iroh_cfg = cfg.iroh();
            let ServerIrohParams {
                allowed_tcp,
                allowed_udp,
                max_sessions,
                secret,
                secret_file,
                relay_urls,
                dns_server,
                socks5_proxy,
                allowed_clients,
                allowed_clients_file,
            } = resolve_server_iroh_params(&command, iroh_cfg);

            #[cfg(feature = "test-utils")]
            let relay_only = match &command {
                Command::Server { relay_only, .. } => *relay_only,
                _ => false,
            };
            #[cfg(not(feature = "test-utils"))]
            let relay_only = false;

            let secret = resolve_iroh_secret(secret, secret_file)?;

            // Load allowed clients for authentication
            let allowed_clients_file_expanded =
                allowed_clients_file.as_ref().map(|p| expand_tilde(p));
            let allowed_clients = auth::load_allowed_clients(
                &allowed_clients,
                allowed_clients_file_expanded.as_deref(),
            )?;

            if allowed_clients.is_empty() {
                anyhow::bail!(
                    "Authentication required: specify --allowed-clients or --allowed-clients-file.\n\
                    Clients need to provide their NodeId, which can be generated with:\n\
                    tunnel-rs generate-iroh-key --output <key-file>\n\
                    tunnel-rs show-iroh-node-id --secret-file <key-file>"
                );
            }

            log::info!(
                "Allowed clients: {} NodeId(s) configured",
                allowed_clients.len()
            );

            validate_socks5_proxy_if_present(&socks5_proxy).await?;

            // Set up SOCKS5 bridges for .onion relay URLs
            let (relay_urls, _relay_bridges) =
                socks5_bridge::setup_relay_bridges(relay_urls, socks5_proxy.as_deref()).await?;

            iroh_mode::run_multi_source_server(
                allowed_tcp,
                allowed_udp,
                max_sessions,
                secret,
                relay_urls,
                relay_only,
                dns_server,
                allowed_clients,
            )
            .await
        }
        Command::Client {
            config,
            default_config,
            ..
        } => {
            let (cfg, from_file) = resolve_client_config(config.clone(), *default_config)?;

            if from_file {
                cfg.validate("iroh")?;
            }

            let iroh_cfg = cfg.iroh();
            let ClientIrohParams {
                server_node_id,
                source,
                target,
                relay_urls,
                dns_server,
                socks5_proxy,
                secret,
                secret_file,
            } = resolve_client_iroh_params(&command, iroh_cfg);

            #[cfg(feature = "test-utils")]
            let relay_only = match &command {
                Command::Client { relay_only, .. } => *relay_only,
                _ => false,
            };
            #[cfg(not(feature = "test-utils"))]
            let relay_only = false;

            let server_node_id = server_node_id.context(
                "server_node_id is required. Provide via --server-node-id or in config file.",
            )?;
            let source = source.context(
                "--source is required for iroh client mode. Specify the source to request from server (e.g., --source tcp://127.0.0.1:22)",
            )?;
            let target = target.context(
                "--target is required. Provide the local address to listen on (e.g., --target 127.0.0.1:2222)",
            )?;

            let secret = resolve_iroh_secret(secret, secret_file)?;

            validate_socks5_proxy_if_present(&socks5_proxy).await?;

            let (relay_urls, _relay_bridges) =
                socks5_bridge::setup_relay_bridges(relay_urls, socks5_proxy.as_deref()).await?;

            iroh_mode::run_multi_source_client(
                server_node_id,
                source,
                target,
                relay_urls,
                relay_only,
                dns_server,
                secret,
            )
            .await
        }
        Command::GenerateIrohKey { output, force } => {
            secret::generate_secret(expand_tilde(output), *force)
        }
        Command::ShowIrohNodeId { secret_file } => secret::show_id(expand_tilde(secret_file)),
    }
}
