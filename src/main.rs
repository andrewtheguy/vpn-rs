//! vpn-rs
//!
//! IP-over-QUIC VPN tunnel via iroh P2P connections.
//! Uses vpn-auth tokens for access control and TLS 1.3/QUIC for encryption.

#[cfg(not(any(unix, target_os = "windows")))]
compile_error!("vpn-rs only supports Unix-like systems (Linux, macOS, BSD) and Windows");

mod vpn_common;
mod vpn_core;
mod vpn_iroh;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::path::PathBuf;

use crate::vpn_common::config::{
    expand_tilde, load_vpn_client_config, load_vpn_server_config, ResolvedVpnClientConfig,
    ResolvedVpnServerConfig, VpnClientConfig as TomlClientConfig, VpnClientConfigBuilder,
    VpnServerConfig as TomlServerConfig,
};
use crate::vpn_iroh::auth;
use crate::vpn_iroh::iroh_mode::endpoint::{
    create_client_endpoint, create_server_endpoint, load_secret,
};
use crate::vpn_iroh::secret;
// Runtime config types from vpn-core (different from TOML config types)
use crate::vpn_core::config::{VpnClientConfig, VpnServerConfig};
use crate::vpn_core::signaling::VPN_ALPN;
use crate::vpn_core::{VpnClient, VpnServer};

#[derive(Parser)]
#[command(name = "vpn-rs")]
#[command(version)]
#[command(about = "IP-over-QUIC VPN tunnel via iroh P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as VPN server (accepts connections and assigns IPs).
    ///
    /// Requires a config file. Use -c to specify a path or --default-config for
    /// ~/.config/vpn-rs/vpn_server.toml. See vpn_server.toml.example for format.
    Server {
        /// Config file path (required unless --default-config is used)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/vpn-rs/vpn_server.toml)
        #[arg(long)]
        default_config: bool,
    },
    /// Run as VPN client (connects to server and establishes tunnel)
    Client {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/vpn-rs/vpn_client.toml)
        #[arg(long)]
        default_config: bool,

        /// EndpointId of the VPN server to connect to
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,

        /// MTU for VPN packets (default: 1440, valid range: 576-1500)
        #[arg(long, value_parser = clap::value_parser!(u16).range(576..=1500))]
        mtu: Option<u16>,

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

        /// Additional IPv4 route CIDRs through the VPN (optional, repeatable).
        /// The VPN subnet is always routed by default.
        /// Full tunnel: --route 0.0.0.0/0
        /// Split tunnel: --route 192.168.1.0/24 --route 10.0.0.0/8
        #[arg(long = "route")]
        routes: Vec<String>,

        /// IPv6 route CIDRs through the VPN (optional, repeatable)
        /// Full tunnel: --route6 ::/0
        /// Split tunnel: --route6 fd00::/64
        #[arg(long = "route6")]
        routes6: Vec<String>,

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
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,iroh=warn,tracing=warn"),
    )
    .init();

    let args = Args::parse();

    match args.command {
        Command::Server {
            config,
            default_config,
        } => {
            // Config file is required for VPN server
            if config.is_none() && !default_config {
                anyhow::bail!(
                    "VPN server requires a config file.\n\
                     Use -c <FILE> or --default-config (~/.config/vpn-rs/vpn_server.toml)\n\
                     See vpn_server.toml.example for format."
                );
            }

            // Load and validate config file
            let (cfg, _from_file) = resolve_server_config(config, default_config)?;
            let cfg = cfg
                .expect("resolve_server_config returns Some when config or default_config is set");
            cfg.validate()?;

            // Build resolved config from config file
            let iroh_cfg = cfg
                .iroh()
                .ok_or_else(|| anyhow::anyhow!("Missing [iroh] section in config file"))?;
            let resolved = ResolvedVpnServerConfig::from_config(iroh_cfg)?;

            run_vpn_server(resolved).await
        }
        Command::Client {
            config,
            default_config,
            server_node_id,
            mtu,
            relay_urls,
            dns_server,
            auth_token,
            auth_token_file,
            routes,
            routes6,
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
            assert!(
                !(auto_reconnect && no_auto_reconnect),
                "both --auto-reconnect and --no-auto-reconnect were set (clap conflicts_with should prevent this)"
            );
            let auto_reconnect_opt = match (auto_reconnect, no_auto_reconnect) {
                (true, false) => Some(true),    // --auto-reconnect: enable reconnect
                (false, true) => Some(false),   // --no-auto-reconnect: disable reconnect
                (false, false) => None,         // neither: use config/default
                (true, true) => unreachable!(), // guarded by assert above
            };

            // Build resolved config: defaults -> config file -> CLI
            let resolved = VpnClientConfigBuilder::new()
                .apply_defaults()
                .apply_config(cfg.as_ref().and_then(|c| c.iroh()))
                .apply_cli(
                    server_node_id,
                    mtu,
                    auth_token,
                    auth_token_file.map(|p| expand_tilde(&p)),
                    routes,
                    routes6,
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
    // Parse IPv4 network CIDR (optional, for IPv6-only servers)
    let network: Option<Ipv4Net> = resolved
        .network
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid VPN network CIDR")?;

    // Parse server IP if provided
    let server_ip: Option<Ipv4Addr> = resolved
        .server_ip
        .as_ref()
        .map(|ip_str| ip_str.parse())
        .transpose()
        .context("Invalid server IP address")?;

    // Parse IPv6 network CIDR (optional, for dual-stack)
    let network6: Option<Ipv6Net> = resolved
        .network6
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid IPv6 VPN network CIDR")?;

    // Parse server IPv6 if provided
    let server_ip6: Option<Ipv6Addr> = resolved
        .server_ip6
        .as_ref()
        .map(|ip_str| ip_str.parse())
        .transpose()
        .context("Invalid server IPv6 address")?;

    // Load and validate auth tokens (required for VPN server)
    let valid_tokens =
        auth::load_auth_tokens(&resolved.auth_tokens, resolved.auth_tokens_file.as_deref())
            .context("Failed to load authentication tokens")?;

    if valid_tokens.is_empty() {
        anyhow::bail!(
            "VPN server requires at least one authentication token.\n\
             Generate one with: vpn-rs generate-token\n\
             Then add to config file: auth_tokens = [\"<TOKEN>\"]"
        );
    }

    log::info!("Loaded {} authentication token(s)", valid_tokens.len());

    // Load secret key for persistent iroh identity (required for server)
    let secret_key = if let Some(ref path) = resolved.secret_file {
        load_secret(path).context("Failed to load secret key")?
    } else {
        anyhow::bail!(
            "VPN server requires a secret key file for persistent identity.\n\
             Generate one with: vpn-rs generate-server-key -o <FILE>\n\
             Then add to config file: secret_file = \"<FILE>\""
        );
    };

    // Create VPN server config
    let config = VpnServerConfig {
        network,
        network6,
        server_ip,
        server_ip6,
        mtu: resolved.mtu,
        max_clients: 254,
        auth_tokens: Some(valid_tokens),
        drop_on_full: resolved.drop_on_full,
        client_channel_size: resolved.client_channel_size,
        tun_writer_channel_size: resolved.tun_writer_channel_size,
        disable_spoofing_check: resolved.disable_spoofing_check,
    };

    // Create iroh endpoint for signaling.
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    let endpoint = create_server_endpoint(
        &resolved.relay_urls,
        false, // relay_only - direct P2P preferred for VPN performance
        Some(secret_key),
        resolved.dns_server.as_deref(),
        VPN_ALPN,
        Some(&resolved.transport),
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Server Node ID: {}", endpoint.id());
    log::info!(
        "Clients connect with: vpn-rs client --server-node-id {} --auth-token <TOKEN>",
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

    // Parse IPv4 routes (optional - VPN subnet is always routed by default)
    let parsed_routes: Vec<Ipv4Net> = resolved
        .routes
        .iter()
        .map(|r| r.parse::<Ipv4Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route CIDR (e.g., 192.168.1.0/24)")?;

    // Parse IPv6 routes (optional)
    let parsed_routes6: Vec<Ipv6Net> = resolved
        .routes6
        .iter()
        .map(|r| r.parse::<Ipv6Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route6 CIDR (e.g., ::/0 or fd00::/64)")?;

    log::info!("Routing {} IPv4 CIDR(s) through VPN:", parsed_routes.len());
    for route in &parsed_routes {
        log::info!("  {}", route);
    }
    if !parsed_routes6.is_empty() {
        log::info!("Routing {} IPv6 CIDR(s) through VPN:", parsed_routes6.len());
        for route6 in &parsed_routes6 {
            log::info!("  {}", route6);
        }
    }

    // Create VPN client config
    let config = VpnClientConfig {
        server_node_id: resolved.server_node_id.clone(),
        mtu: resolved.mtu,
        auth_token: Some(token),
        routes: parsed_routes,
        routes6: parsed_routes6,
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
        Some(&resolved.transport),
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
            .run_with_reconnect(
                &endpoint,
                &resolved.relay_urls,
                resolved.max_reconnect_attempts,
            )
            .await
            .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
    } else {
        log::info!("Auto-reconnect disabled, single connection attempt");
        client
            .connect(&endpoint, &resolved.relay_urls)
            .await
            .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
    }
}
