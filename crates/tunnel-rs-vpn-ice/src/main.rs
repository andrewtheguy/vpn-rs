//! tunnel-rs-vpn-ice
//!
//! IP-over-QUIC VPN tunnel via ICE/Nostr P2P connections.
//! Uses Nostr relays for signaling and STUN for NAT traversal.

#[cfg(not(any(unix, target_os = "windows")))]
compile_error!("tunnel-rs-vpn-ice only supports Unix-like systems (Linux, macOS, BSD) and Windows");

// Use jemalloc for better multi-threaded allocation performance
#[cfg(all(feature = "jemalloc", not(target_env = "musl"), not(target_os = "windows")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::{Ipv4Net, Ipv6Net};
use nostr_sdk::prelude::*;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use tunnel_common::config::expand_tilde;
use tunnel_vpn_ice::config::{default_stun_servers, VpnIceClientConfig, VpnIceServerConfig, DEFAULT_MTU};
use tunnel_vpn_ice::{VpnIceClient, VpnIceServer};

#[derive(Parser)]
#[command(name = "tunnel-rs-vpn-ice")]
#[command(version)]
#[command(about = "IP-over-QUIC VPN tunnel via ICE/Nostr P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as VPN server (accepts connections and assigns IPs)
    ///
    /// Requires a config file. Use -c to specify a path or --default-config for
    /// ~/.config/tunnel-rs/vpn_server_ice.toml
    Server {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/tunnel-rs/vpn_server_ice.toml)
        #[arg(long)]
        default_config: bool,
    },

    /// Run as VPN client (connects to server and establishes tunnel)
    Client {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/tunnel-rs/vpn_client_ice.toml)
        #[arg(long)]
        default_config: bool,

        /// Nostr private key (nsec format)
        #[arg(long)]
        nsec: Option<String>,

        /// Path to file containing Nostr private key
        #[arg(long)]
        nsec_file: Option<PathBuf>,

        /// Server's Nostr public key (npub format)
        #[arg(long)]
        peer_npub: Option<String>,

        /// Nostr relay URLs for signaling (repeatable)
        #[arg(long = "relay")]
        relays: Vec<String>,

        /// STUN server addresses (repeatable)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// MTU for VPN packets (default: 1420)
        #[arg(long, value_parser = clap::value_parser!(u16).range(576..=1500))]
        mtu: Option<u16>,

        /// IPv4 routes through VPN (CIDR notation, repeatable)
        /// Full tunnel: --route 0.0.0.0/0
        /// Split tunnel: --route 192.168.1.0/24
        #[arg(long = "route")]
        routes: Vec<String>,

        /// IPv6 routes through VPN (CIDR notation, repeatable)
        /// Full tunnel: --route6 ::/0
        #[arg(long = "route6")]
        routes6: Vec<String>,
    },

    /// Generate a Nostr keypair for server/client identity
    GenerateNostrKey {
        /// Output file path for the nsec (private key)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show the npub (public key) for an existing nsec
    ShowPubkey {
        /// Path to the nsec file
        #[arg(short, long)]
        nsec_file: PathBuf,
    },
}

/// TOML configuration for VPN ICE client.
#[derive(Debug, Deserialize)]
struct TomlClientConfig {
    #[serde(default)]
    nostr: Option<NostrClientSection>,
}

#[derive(Debug, Deserialize)]
struct NostrClientSection {
    nsec: Option<String>,
    nsec_file: Option<PathBuf>,
    peer_npub: Option<String>,
    relays: Option<Vec<String>>,
    stun_servers: Option<Vec<String>>,
    mtu: Option<u16>,
    routes: Option<Vec<String>>,
    routes6: Option<Vec<String>>,
}

/// TOML configuration for VPN ICE server.
#[derive(Debug, Deserialize)]
struct TomlServerConfig {
    #[serde(default)]
    nostr: Option<NostrServerSection>,
}

#[derive(Debug, Deserialize)]
struct NostrServerSection {
    network: Option<String>,
    network6: Option<String>,
    server_ip: Option<String>,
    server_ip6: Option<String>,
    mtu: Option<u16>,
    max_clients: Option<usize>,
    nsec: Option<String>,
    nsec_file: Option<PathBuf>,
    peer_npub: Option<String>,
    relays: Option<Vec<String>>,
    stun_servers: Option<Vec<String>>,
    disable_spoofing_check: Option<bool>,
}

fn load_client_config(path: &std::path::Path) -> Result<TomlClientConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let config: TomlClientConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
    Ok(config)
}

fn load_server_config(path: &std::path::Path) -> Result<TomlServerConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let config: TomlServerConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
    Ok(config)
}

fn default_client_config_path() -> PathBuf {
    dirs::config_dir()
        .map(|p| p.join("tunnel-rs").join("vpn_client_ice.toml"))
        .unwrap_or_else(|| PathBuf::from("vpn_client_ice.toml"))
}

fn default_server_config_path() -> PathBuf {
    dirs::config_dir()
        .map(|p| p.join("tunnel-rs").join("vpn_server_ice.toml"))
        .unwrap_or_else(|| PathBuf::from("vpn_server_ice.toml"))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,str0m=warn,nostr=warn"),
    )
    .init();

    let args = Args::parse();

    match args.command {
        Command::Server {
            config,
            default_config,
        } => {
            // Config file is required for server
            if config.is_none() && !default_config {
                anyhow::bail!(
                    "VPN server requires a config file.\n\
                     Use -c <FILE> or --default-config (~/.config/tunnel-rs/vpn_server_ice.toml)\n\
                     See vpn_server_ice.toml.example for format."
                );
            }

            let config_path = if let Some(path) = config {
                expand_tilde(&path)
            } else {
                default_server_config_path()
            };

            run_vpn_server(&config_path).await
        }

        Command::Client {
            config,
            default_config,
            nsec,
            nsec_file,
            peer_npub,
            relays,
            stun_servers,
            mtu,
            routes,
            routes6,
        } => {
            // Load config file if specified
            let toml_config = if let Some(path) = config {
                Some(load_client_config(&expand_tilde(&path))?)
            } else if default_config {
                let path = default_client_config_path();
                if path.exists() {
                    Some(load_client_config(&path)?)
                } else {
                    anyhow::bail!(
                        "Default config file not found: {}\n\
                         Create it or use -c <FILE> to specify a config file.",
                        path.display()
                    );
                }
            } else {
                None
            };

            // Build config: defaults -> config file -> CLI
            let nostr_section = toml_config.as_ref().and_then(|c| c.nostr.as_ref());

            // Resolve nsec
            let final_nsec = nsec
                .or_else(|| nostr_section.and_then(|s| s.nsec.clone()));
            let final_nsec_file = nsec_file
                .map(|p| expand_tilde(&p))
                .or_else(|| nostr_section.and_then(|s| s.nsec_file.as_ref().map(|p| expand_tilde(p))));

            // Resolve peer_npub
            let final_peer_npub = peer_npub
                .or_else(|| nostr_section.and_then(|s| s.peer_npub.clone()))
                .ok_or_else(|| anyhow::anyhow!("peer_npub is required (--peer-npub or config)"))?;

            // Resolve relays
            let final_relays = if !relays.is_empty() {
                Some(relays)
            } else {
                nostr_section.and_then(|s| s.relays.clone())
            };

            // Resolve stun_servers
            let final_stun_servers = if !stun_servers.is_empty() {
                stun_servers
            } else {
                nostr_section
                    .and_then(|s| s.stun_servers.clone())
                    .unwrap_or_else(default_stun_servers)
            };

            // Resolve mtu
            let final_mtu = mtu
                .or_else(|| nostr_section.and_then(|s| s.mtu))
                .unwrap_or(DEFAULT_MTU);

            // Resolve routes
            let route_strings = if !routes.is_empty() {
                routes
            } else {
                nostr_section
                    .and_then(|s| s.routes.clone())
                    .unwrap_or_default()
            };
            let final_routes: Vec<Ipv4Net> = route_strings
                .iter()
                .map(|r| r.parse())
                .collect::<Result<Vec<_>, _>>()
                .context("Invalid route CIDR")?;

            // Resolve routes6
            let route6_strings = if !routes6.is_empty() {
                routes6
            } else {
                nostr_section
                    .and_then(|s| s.routes6.clone())
                    .unwrap_or_default()
            };
            let final_routes6: Vec<Ipv6Net> = route6_strings
                .iter()
                .map(|r| r.parse())
                .collect::<Result<Vec<_>, _>>()
                .context("Invalid route6 CIDR")?;

            let client_config = VpnIceClientConfig {
                nsec: final_nsec,
                nsec_file: final_nsec_file,
                peer_npub: final_peer_npub,
                relays: final_relays,
                stun_servers: final_stun_servers,
                mtu: final_mtu,
                routes: final_routes,
                routes6: final_routes6,
            };

            client_config
                .validate()
                .map_err(|e| anyhow::anyhow!("Invalid configuration: {}", e))?;

            run_vpn_client(client_config).await
        }

        Command::GenerateNostrKey { output } => {
            let keys = Keys::generate();
            let nsec = keys.secret_key().to_bech32()?;
            let npub = keys.public_key().to_bech32()?;

            if let Some(path) = output {
                let expanded = expand_tilde(&path);
                let mut options = OpenOptions::new();
                options.create(true).write(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }

                let mut file = options
                    .open(&expanded)
                    .with_context(|| format!("Failed to write to {}", expanded.display()))?;
                file.write_all(format!("{}\n", nsec).as_bytes())
                    .with_context(|| format!("Failed to write to {}", expanded.display()))?;
                #[cfg(not(unix))]
                {
                    // Note: read-only on Windows only prevents modification, not reading.
                    // Users should ensure the file is in a directory with appropriate ACLs.
                    let perms = std::fs::Permissions::from_readonly(true);
                    std::fs::set_permissions(&expanded, perms).with_context(|| {
                        format!("Failed to set permissions on {}", expanded.display())
                    })?;
                }
                println!("Private key saved to: {}", expanded.display());
                println!("Public key (npub): {}", npub);
                println!("\nShare the npub with your peer, keep the nsec file secret!");
            } else {
                println!("Private key (nsec): {}", nsec);
                println!("Public key (npub):  {}", npub);
                println!("\nSave the nsec to a file and share the npub with your peer.");
            }

            Ok(())
        }

        Command::ShowPubkey { nsec_file } => {
            let expanded = expand_tilde(&nsec_file);
            let content = std::fs::read_to_string(&expanded)
                .with_context(|| format!("Failed to read nsec file: {}", expanded.display()))?;
            let nsec = content.trim();

            let keys = Keys::parse(nsec).context("Failed to parse nsec")?;
            let npub = keys.public_key().to_bech32()?;

            println!("Public key (npub): {}", npub);
            Ok(())
        }
    }
}

async fn run_vpn_server(config_path: &std::path::Path) -> Result<()> {
    let toml_config = load_server_config(config_path)?;
    let nostr = toml_config
        .nostr
        .ok_or_else(|| anyhow::anyhow!("Missing [nostr] section in config file"))?;

    // Parse network
    let network: Option<Ipv4Net> = nostr
        .network
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid network CIDR")?;

    let network6: Option<Ipv6Net> = nostr
        .network6
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid network6 CIDR")?;

    let server_ip: Option<Ipv4Addr> = nostr
        .server_ip
        .as_ref()
        .map(|ip| ip.parse())
        .transpose()
        .context("Invalid server_ip")?;

    let server_ip6: Option<Ipv6Addr> = nostr
        .server_ip6
        .as_ref()
        .map(|ip| ip.parse())
        .transpose()
        .context("Invalid server_ip6")?;

    let peer_npub = nostr
        .peer_npub
        .ok_or_else(|| anyhow::anyhow!("peer_npub is required in config"))?;

    let server_config = VpnIceServerConfig {
        network,
        network6,
        server_ip,
        server_ip6,
        mtu: nostr.mtu.unwrap_or(DEFAULT_MTU),
        max_clients: nostr.max_clients.unwrap_or(254),
        nsec: nostr.nsec,
        nsec_file: nostr.nsec_file,
        peer_npub,
        relays: nostr.relays,
        stun_servers: nostr.stun_servers.unwrap_or_else(default_stun_servers),
        nat64: None, // NAT64 not yet supported in ICE mode
        disable_spoofing_check: nostr.disable_spoofing_check.unwrap_or(false),
    };

    server_config
        .validate()
        .map_err(|e| anyhow::anyhow!("Invalid configuration: {}", e))?;

    let server = VpnIceServer::new(server_config).await?;
    server
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("VPN server error: {}", e))
}

async fn run_vpn_client(config: VpnIceClientConfig) -> Result<()> {
    log::info!("Routes configured:");
    for route in &config.routes {
        log::info!("  {}", route);
    }
    for route6 in &config.routes6 {
        log::info!("  {}", route6);
    }

    let client = VpnIceClient::new(config)?;
    client
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
}
