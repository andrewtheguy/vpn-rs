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
use std::path::PathBuf;

use tunnel_common::config::expand_tilde;
use tunnel_iroh::auth;
use tunnel_iroh::iroh_mode::endpoint::{create_client_endpoint, create_server_endpoint, load_secret};
use tunnel_iroh::secret;
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
        /// VPN network CIDR (e.g., 10.0.0.0/24)
        #[arg(short, long, default_value = "10.0.0.0/24")]
        network: String,

        /// Server's VPN IP address (gateway). Defaults to first IP in network.
        #[arg(long)]
        server_ip: Option<String>,

        /// MTU for VPN packets (default: 1420, valid range: 576-1500)
        #[arg(long, default_value = "1420", value_parser = clap::value_parser!(u16).range(576..=1500))]
        mtu: u16,

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
        /// EndpointId of the VPN server to connect to
        #[arg(short = 'n', long)]
        server_node_id: String,

        /// MTU for VPN packets (default: 1420, valid range: 576-1500)
        #[arg(long, default_value = "1420", value_parser = clap::value_parser!(u16).range(576..=1500))]
        mtu: u16,

        /// WireGuard keepalive interval in seconds (default: 25, valid range: 10-300)
        #[arg(long, default_value = "25", value_parser = clap::value_parser!(u16).range(10..=300))]
        keepalive_secs: u16,

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

        /// Route specific CIDRs through the VPN (repeatable)
        /// E.g., --route 192.168.1.0/24 --route 10.0.0.0/8
        /// If not specified, only VPN network traffic is routed.
        #[arg(long = "route")]
        routes: Vec<String>,
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    match &args.command {
        Command::Server {
            network,
            server_ip,
            mtu,
            secret_file,
            relay_urls,
            dns_server,
            auth_tokens,
            auth_tokens_file,
        } => {
            run_vpn_server(
                network,
                server_ip.as_deref(),
                *mtu,
                secret_file.as_ref().map(|p| expand_tilde(p)),
                relay_urls,
                dns_server.as_deref(),
                auth_tokens,
                auth_tokens_file.as_ref().map(|p| expand_tilde(p)).as_deref(),
            )
            .await
        }
        Command::Client {
            server_node_id,
            mtu,
            keepalive_secs,
            relay_urls,
            dns_server,
            auth_token,
            auth_token_file,
            routes,
        } => {
            run_vpn_client(
                server_node_id,
                *mtu,
                *keepalive_secs,
                relay_urls,
                dns_server.as_deref(),
                auth_token.as_deref(),
                auth_token_file.as_ref().map(|p| expand_tilde(p)).as_deref(),
                routes,
            )
            .await
        }
        Command::GenerateServerKey { output, force } => {
            secret::generate_secret(expand_tilde(output), *force)
        }
        Command::ShowServerId { secret_file } => secret::show_id(expand_tilde(secret_file)),
        Command::GenerateToken { count } => {
            for _ in 0..*count {
                println!("{}", auth::generate_token());
            }
            Ok(())
        }
    }
}

/// Run VPN server.
#[allow(clippy::too_many_arguments)]
async fn run_vpn_server(
    network: &str,
    server_ip: Option<&str>,
    mtu: u16,
    secret_file: Option<PathBuf>,
    relay_urls: &[String],
    dns_server: Option<&str>,
    auth_tokens: &[String],
    auth_tokens_file: Option<&std::path::Path>,
) -> Result<()> {
    // Parse network CIDR
    let network: Ipv4Net = network
        .parse()
        .context("Invalid VPN network CIDR (e.g., 10.0.0.0/24)")?;

    // Parse server IP if provided (otherwise IpPool will use default .1)
    let server_ip: Option<Ipv4Addr> = server_ip
        .map(|ip_str| ip_str.parse())
        .transpose()
        .context("Invalid server IP address")?;

    // Validate server IP is within network if provided
    if let Some(ip) = server_ip {
        if !network.contains(&ip) {
            anyhow::bail!(
                "Server IP {} is not within network CIDR {}",
                ip,
                network
            );
        }
    }

    // Load and validate auth tokens (required for VPN server)
    let valid_tokens = auth::load_auth_tokens(auth_tokens, auth_tokens_file)
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
    let secret_key = if let Some(ref path) = secret_file {
        Some(load_secret(path).context("Failed to load secret key")?)
    } else {
        None
    };

    // Create VPN server config (WireGuard keys are ephemeral, generated per-client)
    let config = VpnServerConfig {
        network,
        server_ip,
        mtu,
        auth_tokens: Some(valid_tokens),
        ..Default::default()
    };

    // Create iroh endpoint for signaling.
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    let endpoint = create_server_endpoint(
        relay_urls,
        false, // relay_only - direct P2P preferred for VPN performance
        secret_key,
        dns_server,
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
#[allow(clippy::too_many_arguments)]
async fn run_vpn_client(
    server_node_id: &str,
    mtu: u16,
    keepalive_secs: u16,
    relay_urls: &[String],
    dns_server: Option<&str>,
    auth_token: Option<&str>,
    auth_token_file: Option<&std::path::Path>,
    routes: &[String],
) -> Result<()> {
    // Load auth token (from CLI or file)
    let token = if let Some(token) = auth_token {
        auth::validate_token(token).context("Invalid authentication token from CLI")?;
        token.to_string()
    } else if let Some(path) = auth_token_file {
        auth::load_auth_token_from_file(path)
            .context("Failed to load authentication token from file")?
    } else {
        anyhow::bail!(
            "VPN client requires an authentication token.\n\
             Use --auth-token <TOKEN> or --auth-token-file <FILE>"
        );
    };

    // Parse routes
    let parsed_routes: Vec<Ipv4Net> = routes
        .iter()
        .map(|r| r.parse::<Ipv4Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route CIDR (e.g., 192.168.1.0/24)")?;

    if !parsed_routes.is_empty() {
        log::info!("Will add {} route(s) through VPN", parsed_routes.len());
        for route in &parsed_routes {
            log::info!("  Route: {}", route);
        }
    }

    // Create VPN client config (WireGuard key is ephemeral, auto-generated)
    let config = VpnClientConfig {
        server_node_id: server_node_id.to_string(),
        mtu,
        keepalive_secs,
        auth_token: Some(token),
        routes: parsed_routes,
        ..Default::default()
    };

    // Create iroh endpoint for signaling (ephemeral identity).
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    let endpoint = create_client_endpoint(
        relay_urls,
        false, // relay_only - direct P2P preferred for VPN performance
        dns_server,
        None,  // No persistent secret key - ephemeral
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Client Node ID: {}", endpoint.id());
    log::info!("Connecting to VPN server: {}", server_node_id);

    // Create and connect VPN client
    let client = VpnClient::new(config)
        .map_err(|e| anyhow::anyhow!("Failed to create VPN client: {}", e))?;

    client
        .connect(&endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
}
