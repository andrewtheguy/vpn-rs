//! VPN command handlers.
//!
//! Implements CLI handlers for VPN server and client modes.
//! Uses ephemeral WireGuard keys (auto-generated each session) with
//! tunnel-auth tokens for access control.

use crate::VpnCommand;
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tunnel_common::config::expand_tilde;
use tunnel_iroh::auth;
use tunnel_iroh::iroh_mode::endpoint::{create_client_endpoint, create_server_endpoint, load_secret};
use tunnel_vpn::config::{VpnClientConfig, VpnServerConfig};
use tunnel_vpn::signaling::VPN_ALPN;
use tunnel_vpn::{VpnClient, VpnServer};

/// Run the VPN command.
pub async fn run_vpn_command(cmd: &VpnCommand) -> Result<()> {
    match cmd {
        VpnCommand::Server {
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
        VpnCommand::Client {
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

    // Load and validate auth tokens (required for VPN server)
    let valid_tokens = auth::load_auth_tokens(auth_tokens, auth_tokens_file)
        .context("Failed to load authentication tokens")?;

    if valid_tokens.is_empty() {
        anyhow::bail!(
            "VPN server requires at least one authentication token.\n\
             Generate one with: tunnel-rs generate-token\n\
             Then start server with: tunnel-rs vpn server --auth-tokens <TOKEN>"
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

    // Create iroh endpoint for signaling
    let endpoint = create_server_endpoint(
        relay_urls,
        false, // relay_only
        secret_key,
        dns_server,
        VPN_ALPN,
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Server Node ID: {}", endpoint.id());
    log::info!(
        "Clients connect with: tunnel-rs vpn client --server-node-id {} --auth-token <TOKEN>",
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
        auth::load_auth_token_from_file(path).context("Failed to load authentication token from file")?
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

    // Create iroh endpoint for signaling (ephemeral identity)
    let endpoint = create_client_endpoint(
        relay_urls,
        false, // relay_only
        dns_server,
        None, // No persistent secret key - ephemeral
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Client Node ID: {}", endpoint.id());
    log::info!("Connecting to VPN server: {}", server_node_id);

    // Create and connect VPN client
    let client =
        VpnClient::new(config).map_err(|e| anyhow::anyhow!("Failed to create VPN client: {}", e))?;

    client
        .connect(&endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
}
