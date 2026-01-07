//! VPN command handlers.
//!
//! Implements CLI handlers for VPN server and client modes.

use crate::VpnCommand;
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::path::Path;
use tunnel_common::config::expand_tilde;
use tunnel_iroh::iroh_mode::endpoint::{create_client_endpoint, create_server_endpoint};
use tunnel_vpn::config::{VpnClientConfig, VpnServerConfig};
use tunnel_vpn::signaling::VPN_ALPN;
use tunnel_vpn::{VpnClient, VpnServer, WgKeyPair};

/// Run the VPN command.
pub async fn run_vpn_command(cmd: &VpnCommand) -> Result<()> {
    match cmd {
        VpnCommand::Server {
            network,
            server_ip,
            wg_port,
            mtu,
            private_key_file,
            relay_urls,
            dns_server,
            auth_token,
        } => {
            run_vpn_server(
                network,
                server_ip.as_deref(),
                *wg_port,
                *mtu,
                private_key_file.as_ref().map(|p| expand_tilde(p)),
                relay_urls,
                dns_server.as_deref(),
                auth_token.as_deref(),
            )
            .await
        }
        VpnCommand::Client {
            server_node_id,
            mtu,
            keepalive_secs,
            private_key_file,
            relay_urls,
            dns_server,
            auth_token,
        } => {
            run_vpn_client(
                server_node_id,
                *mtu,
                *keepalive_secs,
                private_key_file.as_ref().map(|p| expand_tilde(p)),
                relay_urls,
                dns_server.as_deref(),
                auth_token.as_deref(),
            )
            .await
        }
        VpnCommand::GenerateKey { output, force } => {
            generate_wg_key(&expand_tilde(output), *force)
        }
        VpnCommand::ShowPublicKey { private_key_file } => {
            show_wg_public_key(&expand_tilde(private_key_file))
        }
    }
}

/// Run VPN server.
#[allow(clippy::too_many_arguments)]
async fn run_vpn_server(
    network: &str,
    server_ip: Option<&str>,
    wg_port: u16,
    mtu: u16,
    private_key_file: Option<std::path::PathBuf>,
    relay_urls: &[String],
    dns_server: Option<&str>,
    _auth_token: Option<&str>,
) -> Result<()> {
    // Parse network CIDR
    let network: Ipv4Net = network
        .parse()
        .context("Invalid VPN network CIDR (e.g., 10.0.0.0/24)")?;

    // Parse or calculate server IP
    let _server_ip: Ipv4Addr = if let Some(ip_str) = server_ip {
        ip_str.parse().context("Invalid server IP address")?
    } else {
        // Default to first host in network (.1)
        let net_addr: u32 = network.network().into();
        Ipv4Addr::from(net_addr + 1)
    };

    // Load or generate WireGuard keypair for iroh identity
    let secret_key = if let Some(ref path) = private_key_file {
        let keypair = WgKeyPair::load_from_file_sync(path)
            .context("Failed to load WireGuard private key")?;
        // Convert WireGuard key to iroh SecretKey
        let bytes = keypair.private_key_bytes();
        Some(iroh::SecretKey::from_bytes(&bytes))
    } else {
        None
    };

    // Create VPN server config
    let config = VpnServerConfig {
        network,
        wg_port,
        mtu,
        private_key_file,
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
    log::info!("Clients connect with: tunnel-rs vpn client --server-node-id {}", endpoint.id());

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
    private_key_file: Option<std::path::PathBuf>,
    relay_urls: &[String],
    dns_server: Option<&str>,
    auth_token: Option<&str>,
) -> Result<()> {
    // Load or generate WireGuard keypair for iroh identity
    let secret_key = if let Some(ref path) = private_key_file {
        let keypair = WgKeyPair::load_from_file_sync(path)
            .context("Failed to load WireGuard private key")?;
        let bytes = keypair.private_key_bytes();
        Some(iroh::SecretKey::from_bytes(&bytes))
    } else {
        None
    };

    // Create VPN client config
    let config = VpnClientConfig {
        server_node_id: server_node_id.to_string(),
        mtu,
        keepalive_secs,
        private_key_file,
        auth_token: auth_token.map(String::from),
        ..Default::default()
    };

    // Create iroh endpoint for signaling
    let endpoint = create_client_endpoint(
        relay_urls,
        false, // relay_only
        dns_server,
        secret_key.as_ref(),
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Client Node ID: {}", endpoint.id());
    log::info!("Connecting to VPN server: {}", server_node_id);

    // Create and connect VPN client
    let client = VpnClient::new(config).map_err(|e| anyhow::anyhow!("Failed to create VPN client: {}", e))?;

    client
        .connect(&endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
}

/// Generate a new WireGuard private key and save to file.
fn generate_wg_key(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}\nUse --force to overwrite",
            output.display()
        );
    }

    let keypair = WgKeyPair::generate();

    // Save private key (base64 encoded)
    std::fs::write(output, keypair.private_key_base64())
        .context("Failed to write private key file")?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o600))
            .context("Failed to set key file permissions")?;
    }

    log::info!("Generated WireGuard key pair");
    log::info!("Private key saved to: {}", output.display());
    log::info!("Public key: {}", keypair.public_key_base64());

    Ok(())
}

/// Show the WireGuard public key derived from a private key file.
fn show_wg_public_key(private_key_file: &Path) -> Result<()> {
    let keypair = WgKeyPair::load_from_file_sync(private_key_file)
        .context("Failed to load private key")?;

    println!("{}", keypair.public_key_base64());

    Ok(())
}
