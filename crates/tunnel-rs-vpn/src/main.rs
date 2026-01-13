//! tunnel-rs-vpn
//!
//! WireGuard-based VPN tunnel via iroh P2P connections.
//! Uses ephemeral WireGuard keys with tunnel-auth tokens for access control.

#[cfg(not(unix))]
compile_error!("tunnel-rs-vpn only supports Linux and macOS");

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::path::PathBuf;

use tunnel_common::config::{
    expand_tilde, load_vpn_client_config, load_vpn_server_config, ResolvedVpnClientConfig,
    ResolvedVpnServerConfig, VpnClientConfigBuilder, VpnServerConfigBuilder,
    VpnClientConfig as TomlClientConfig, VpnServerConfig as TomlServerConfig,
};
use tunnel_iroh::auth;
use tunnel_iroh::iroh_mode::endpoint::{create_client_endpoint, create_server_endpoint, load_secret};
use tunnel_iroh::secret;
// Runtime config types from tunnel-vpn (different from TOML config types)
use tunnel_vpn::config::{VpnClientConfig, VpnServerConfig};
use tunnel_vpn::signaling::VPN_ALPN;
use tunnel_vpn::{VpnClient, VpnServer};

#[derive(Parser)]
#[command(name = "tunnel-rs-vpn")]
#[command(version)]
#[command(about = "WireGuard-based VPN tunnel via iroh P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as VPN server (accepts connections and assigns IPs)
    Server {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/tunnel-rs/vpn_server.toml)
        #[arg(long)]
        default_config: bool,

        /// VPN network CIDR (e.g., 10.0.0.0/24)
        #[arg(short, long)]
        network: Option<String>,

        /// Server's VPN IP address (gateway). Defaults to first IP in network.
        #[arg(long)]
        server_ip: Option<String>,

        /// MTU for VPN packets (default: 1420, valid range: 576-1500)
        #[arg(long, value_parser = clap::value_parser!(u16).range(576..=1500))]
        mtu: Option<u16>,

        /// WireGuard keepalive interval in seconds (default: 25, valid range: 10-300)
        #[arg(long, value_parser = clap::value_parser!(u16).range(10..=300))]
        keepalive_secs: Option<u16>,

        /// Path to secret key file for persistent iroh identity (same EndpointId across restarts)
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,

        /// Authentication tokens (repeatable). Clients must provide one of these to connect.
        #[arg(long = "auth-tokens", value_name = "TOKEN")]
        auth_tokens: Vec<String>,

        /// Path to file containing authentication tokens (one per line, # comments allowed).
        #[arg(long, value_name = "FILE")]
        auth_tokens_file: Option<PathBuf>,
    },
    /// Run as VPN client (connects to server and establishes tunnel)
    Client {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/tunnel-rs/vpn_client.toml)
        #[arg(long)]
        default_config: bool,

        /// EndpointId of the VPN server to connect to
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,

        /// MTU for VPN packets (default: 1420, valid range: 576-1500)
        #[arg(long, value_parser = clap::value_parser!(u16).range(576..=1500))]
        mtu: Option<u16>,

        /// WireGuard keepalive interval in seconds (default: 25, valid range: 10-300)
        #[arg(long, value_parser = clap::value_parser!(u16).range(10..=300))]
        keepalive_secs: Option<u16>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,

        /// Authentication token to send to server
        #[arg(long)]
        auth_token: Option<String>,

        /// Path to file containing authentication token
        #[arg(long)]
        auth_token_file: Option<PathBuf>,

        /// Route CIDRs through the VPN (at least one required, repeatable)
        /// Full tunnel: --route 0.0.0.0/0
        /// Split tunnel: --route 192.168.1.0/24 --route 10.0.0.0/8
        #[arg(long = "route")]
        routes: Vec<String>,

        /// Enable auto-reconnect (override config's auto_reconnect = false)
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        auto_reconnect: bool,

        /// Disable auto-reconnect (exit on first disconnection)
        #[arg(long, conflicts_with = "auto_reconnect")]
        no_auto_reconnect: bool,

        /// Maximum reconnect attempts (unlimited if not specified)
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        max_reconnect_attempts: Option<NonZeroU32>,
    },
    /// Generate a new private key for persistent server identity
    ///
    /// Creates a secret key file that can be used with --secret-file.
    /// The server's EndpointId remains constant when using the same key.
    GenerateServerKey {
        /// Path where to save the private key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Show the server's public EndpointId derived from a private key
    ///
    /// Clients use this EndpointId with --server-node-id to connect.
    ShowServerId {
        /// Path to the private key file
        #[arg(short, long)]
        secret_file: PathBuf,
    },
    /// Generate a client authentication token
    ///
    /// Tokens are shared with clients for authentication (like API keys).
    /// Server configures accepted tokens via --auth-tokens or --auth-tokens-file.
    GenerateToken {
        /// Number of tokens to generate (default: 1)
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
}

/// Resolve VPN server config from CLI and/or config file.
fn resolve_server_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(Option<TomlServerConfig>, bool)> {
    if let Some(path) = config {
        let cfg = load_vpn_server_config(Some(path.as_path()))?;
        Ok((Some(cfg), true))
    } else if default_config {
        let cfg = load_vpn_server_config(None)?;
        Ok((Some(cfg), true))
    } else {
        Ok((None, false))
    }
}

/// Resolve VPN client config from CLI and/or config file.
fn resolve_client_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(Option<TomlClientConfig>, bool)> {
    if let Some(path) = config {
        let cfg = load_vpn_client_config(Some(path.as_path()))?;
        Ok((Some(cfg), true))
    } else if default_config {
        let cfg = load_vpn_client_config(None)?;
        Ok((Some(cfg), true))
    } else {
        Ok((None, false))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    match args.command {
        Command::Server {
            config,
            default_config,
            network,
            server_ip,
            mtu,
            keepalive_secs,
            secret_file,
            relay_urls,
            dns_server,
            auth_tokens,
            auth_tokens_file,
        } => {
            // Load config file if specified
            let (cfg, from_file) = resolve_server_config(config, default_config)?;
            if from_file {
                if let Some(ref c) = cfg {
                    c.validate()?;
                }
            }

            // Build resolved config: defaults -> config file -> CLI
            let resolved = VpnServerConfigBuilder::new()
                .apply_defaults()
                .apply_config(cfg.as_ref().and_then(|c| c.iroh()))
                .apply_cli(
                    network,
                    server_ip,
                    mtu,
                    keepalive_secs,
                    secret_file.map(|p| expand_tilde(&p)),
                    relay_urls,
                    dns_server,
                    auth_tokens,
                    auth_tokens_file.map(|p| expand_tilde(&p)),
                )
                .build()?;

            run_vpn_server(resolved).await
        }
        Command::Client {
            config,
            default_config,
            server_node_id,
            mtu,
            keepalive_secs,
            relay_urls,
            dns_server,
            auth_token,
            auth_token_file,
            routes,
            auto_reconnect,
            no_auto_reconnect,
            max_reconnect_attempts,
        } => {
            // Load config file if specified
            let (cfg, from_file) = resolve_client_config(config, default_config)?;
            if from_file {
                if let Some(ref c) = cfg {
                    c.validate()?;
                }
            }

            // Convert mutually exclusive flags to Option<bool>
            // --auto-reconnect => Some(true), --no-auto-reconnect => Some(false), neither => None
            debug_assert!(
                !(auto_reconnect && no_auto_reconnect),
                "auto_reconnect and no_auto_reconnect must not both be set"
            );
            let auto_reconnect_opt = match (auto_reconnect, no_auto_reconnect) {
                (true, false) => Some(true),   // --auto-reconnect: enable reconnect
                (false, true) => Some(false),  // --no-auto-reconnect: disable reconnect
                (false, false) => None,        // neither: use config/default
                (true, true) => unreachable!("clap conflicts_with prevents both flags"),
            };

            // Build resolved config: defaults -> config file -> CLI
            let resolved = VpnClientConfigBuilder::new()
                .apply_defaults()
                .apply_config(cfg.as_ref().and_then(|c| c.iroh()))
                .apply_cli(
                    server_node_id,
                    mtu,
                    keepalive_secs,
                    auth_token,
                    auth_token_file.map(|p| expand_tilde(&p)),
                    routes,
                    relay_urls,
                    dns_server,
                    auto_reconnect_opt,
                    max_reconnect_attempts,
                )
                .build()?;

            run_vpn_client(resolved).await
        }
        Command::GenerateServerKey { output, force } => {
            secret::generate_secret(expand_tilde(&output), force)
        }
        Command::ShowServerId { secret_file } => secret::show_id(expand_tilde(&secret_file)),
        Command::GenerateToken { count } => {
            for _ in 0..count {
                println!("{}", auth::generate_token());
            }
            Ok(())
        }
    }
}

/// Run VPN server.
async fn run_vpn_server(resolved: ResolvedVpnServerConfig) -> Result<()> {
    // Parse network CIDR (already validated by builder)
    let network: Ipv4Net = resolved
        .network
        .parse()
        .context("Invalid VPN network CIDR")?;

    // Parse server IP if provided
    let server_ip: Option<Ipv4Addr> = resolved
        .server_ip
        .as_ref()
        .map(|ip_str| ip_str.parse())
        .transpose()
        .context("Invalid server IP address")?;

    // Load and validate auth tokens (required for VPN server)
    let valid_tokens = auth::load_auth_tokens(
        &resolved.auth_tokens,
        resolved.auth_tokens_file.as_deref(),
    )
    .context("Failed to load authentication tokens")?;

    if valid_tokens.is_empty() {
        anyhow::bail!(
            "VPN server requires at least one authentication token.\n\
             Generate one with: tunnel-rs-vpn generate-token\n\
             Then start server with: tunnel-rs-vpn server --auth-tokens <TOKEN>"
        );
    }

    log::info!("Loaded {} authentication token(s)", valid_tokens.len());

    // Load secret key for persistent iroh identity (optional)
    let secret_key = if let Some(ref path) = resolved.secret_file {
        Some(load_secret(path).context("Failed to load secret key")?)
    } else {
        None
    };

    // Create VPN server config (WireGuard keys are ephemeral, generated per-client)
    let config = VpnServerConfig {
        network,
        server_ip,
        mtu: resolved.mtu,
        keepalive_secs: resolved.keepalive_secs,
        max_clients: 254,
        auth_tokens: Some(valid_tokens),
    };

    // Create iroh endpoint for signaling.
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    let endpoint = create_server_endpoint(
        &resolved.relay_urls,
        false, // relay_only - direct P2P preferred for VPN performance
        secret_key,
        resolved.dns_server.as_deref(),
        VPN_ALPN,
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Server Node ID: {}", endpoint.id());
    log::info!(
        "Clients connect with: tunnel-rs-vpn client --server-node-id {} --auth-token <TOKEN>",
        endpoint.id()
    );

    // Create and run VPN server
    let server = VpnServer::new(config)
        .await
        .context("Failed to create VPN server")?;

    server
        .run(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("VPN server error: {}", e))
}

/// Run VPN client.
async fn run_vpn_client(resolved: ResolvedVpnClientConfig) -> Result<()> {
    // Load auth token (from CLI or file)
    let token = if let Some(ref token) = resolved.auth_token {
        auth::validate_token(token).context("Invalid authentication token from CLI")?;
        token.clone()
    } else if let Some(ref path) = resolved.auth_token_file {
        auth::load_auth_token_from_file(path)
            .context("Failed to load authentication token from file")?
    } else {
        anyhow::bail!(
            "VPN client requires an authentication token.\n\
             Use --auth-token <TOKEN> or --auth-token-file <FILE>"
        );
    };

    // Parse routes
    let parsed_routes: Vec<Ipv4Net> = resolved
        .routes
        .iter()
        .map(|r| r.parse::<Ipv4Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route CIDR (e.g., 192.168.1.0/24)")?;

    log::info!("Routing {} CIDR(s) through VPN:", parsed_routes.len());
    for route in &parsed_routes {
        log::info!("  {}", route);
    }

    // Create VPN client config (WireGuard key is ephemeral, auto-generated)
    let config = VpnClientConfig {
        server_node_id: resolved.server_node_id.clone(),
        mtu: resolved.mtu,
        keepalive_secs: resolved.keepalive_secs,
        auth_token: Some(token),
        routes: parsed_routes,
    };

    // Create iroh endpoint for signaling (ephemeral identity).
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    let endpoint = create_client_endpoint(
        &resolved.relay_urls,
        false, // relay_only - direct P2P preferred for VPN performance
        resolved.dns_server.as_deref(),
        None, // No persistent secret key - ephemeral
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Client Node ID: {}", endpoint.id());

    // Create VPN client
    let client = VpnClient::new(config)
        .map_err(|e| anyhow::anyhow!("Failed to create VPN client: {}", e))?;

    // Connect with or without auto-reconnect
    if resolved.auto_reconnect {
        client
            .run_with_reconnect(&endpoint, resolved.max_reconnect_attempts)
            .await
            .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
    } else {
        log::info!("Auto-reconnect disabled, single connection attempt");
        client
            .connect(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
    }
}
