//! tunnel-rs
//!
//! Forwards TCP or UDP traffic through P2P connections.
//!
//! Two modes are available:
//!   - iroh: Uses iroh P2P discovery (supports TCP and UDP)
//!   - ice:  Uses manual ICE signaling with copy-paste (TCP only)
//!
//! Usage:
//!   tunnel-rs sender iroh --target 127.0.0.1:22
//!   tunnel-rs sender ice --target 127.0.0.1:22
//!   tunnel-rs receiver iroh --node-id <NODE_ID> --listen 127.0.0.1:2222
//!   tunnel-rs receiver ice --listen 127.0.0.1:2222

mod config;
mod endpoint;
mod manual;
mod secret;
mod tunnel;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use config::{
    default_stun_servers, load_ice_receiver_config, load_ice_sender_config,
    load_iroh_receiver_config, load_iroh_sender_config,
};
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum, Default, Debug, PartialEq)]
pub enum Protocol {
    /// TCP tunneling
    #[default]
    Tcp,
    /// UDP tunneling
    Udp,
}

impl Protocol {
    fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        }
    }
}

#[derive(Parser)]
#[command(name = "tunnel-rs")]
#[command(version)]
#[command(about = "Forward TCP/UDP traffic through P2P connections")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as sender (accepts connections and forwards to target)
    Sender {
        #[command(subcommand)]
        mode: SenderMode,
    },
    /// Run as receiver (connects to sender and exposes local port)
    Receiver {
        #[command(subcommand)]
        mode: ReceiverMode,
    },
    /// Generate a new secret key file (for automation/setup)
    GenerateSecret {
        /// Path where to save the secret key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Show the EndpointId (node ID) for an existing secret key file
    ShowId {
        /// Path to the secret key file
        #[arg(short, long)]
        secret_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum SenderMode {
    /// Use iroh transport (supports TCP and UDP)
    Iroh {
        #[command(subcommand)]
        mode: IrohSenderMode,
    },
    /// Use custom QUIC with manual signaling (TCP only, str0m+quinn)
    Custom {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Target address to forward traffic to
        #[arg(short, long)]
        target: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,
    },
}

#[derive(Subcommand)]
enum IrohSenderMode {
    /// Use iroh discovery servers (Pkarr/DNS/mDNS) with relay fallback
    Default {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Target address to forward traffic to
        #[arg(short, long)]
        target: Option<String>,

        /// Path to secret key file for persistent identity
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P)
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Use manual signaling (copy-paste), no servers, direct-only
    Manual {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Target address to forward traffic to
        #[arg(short, long)]
        target: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReceiverMode {
    /// Use iroh transport (supports TCP and UDP)
    Iroh {
        #[command(subcommand)]
        mode: IrohReceiverMode,
    },
    /// Use custom QUIC with manual signaling (TCP only, str0m+quinn)
    Custom {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        listen: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,
    },
}

#[derive(Subcommand)]
enum IrohReceiverMode {
    /// Use iroh discovery servers (Pkarr/DNS/mDNS) with relay fallback
    Default {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// EndpointId of the sender to connect to
        #[arg(short, long)]
        node_id: Option<String>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        listen: Option<String>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P)
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Use manual signaling (copy-paste), no servers, direct-only
    Manual {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        listen: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Sender { mode } => match mode {
            SenderMode::Iroh { mode: iroh_mode } => match iroh_mode {
                IrohSenderMode::Default {
                    config,
                    protocol,
                    target,
                    secret_file,
                    relay_urls,
                    relay_only,
                    dns_server,
                } => {
                    let cfg = load_iroh_sender_config(config.as_deref())?;

                    // Merge: CLI > Config > Default
                    let protocol = protocol
                        .or_else(|| cfg.protocol.as_deref().and_then(Protocol::from_str_opt))
                        .unwrap_or_default();
                    let target = target
                        .or(cfg.target)
                        .unwrap_or_else(|| "127.0.0.1:22".to_string());
                    let secret_file = secret_file.or(cfg.secret_file);
                    let relay_urls = if relay_urls.is_empty() {
                        cfg.relay_urls.unwrap_or_default()
                    } else {
                        relay_urls
                    };
                    let relay_only = relay_only || cfg.relay_only.unwrap_or(false);
                    let dns_server = dns_server.or(cfg.dns_server);

                    match protocol {
                        Protocol::Udp => {
                            tunnel::run_udp_sender(
                                target,
                                secret_file,
                                relay_urls,
                                relay_only,
                                dns_server,
                            )
                            .await
                        }
                        Protocol::Tcp => {
                            tunnel::run_tcp_sender(
                                target,
                                secret_file,
                                relay_urls,
                                relay_only,
                                dns_server,
                            )
                            .await
                        }
                    }
                }
                IrohSenderMode::Manual {
                    config,
                    protocol,
                    target,
                } => {
                    let cfg = load_iroh_sender_config(config.as_deref())?;

                    let protocol = protocol
                        .or_else(|| cfg.protocol.as_deref().and_then(Protocol::from_str_opt))
                        .unwrap_or_default();
                    let target = target
                        .or(cfg.target)
                        .unwrap_or_else(|| "127.0.0.1:22".to_string());

                    match protocol {
                        Protocol::Udp => {
                            tunnel::run_iroh_manual_udp_sender(target).await
                        }
                        Protocol::Tcp => {
                            tunnel::run_iroh_manual_tcp_sender(target).await
                        }
                    }
                }
            },
            SenderMode::Custom {
                config,
                target,
                stun_servers,
            } => {
                let cfg = load_ice_sender_config(config.as_deref())?;

                let target = target
                    .or(cfg.target)
                    .unwrap_or_else(|| "127.0.0.1:22".to_string());
                let stun_servers = if stun_servers.is_empty() {
                    cfg.stun_servers.unwrap_or_else(default_stun_servers)
                } else {
                    stun_servers
                };

                tunnel::run_manual_tcp_sender(target, stun_servers).await
            }
        },
        Command::Receiver { mode } => match mode {
            ReceiverMode::Iroh { mode: iroh_mode } => match iroh_mode {
                IrohReceiverMode::Default {
                    config,
                    protocol,
                    node_id,
                    listen,
                    relay_urls,
                    relay_only,
                    dns_server,
                } => {
                    let cfg = load_iroh_receiver_config(config.as_deref())?;

                    // Merge: CLI > Config > Default
                    let protocol = protocol
                        .or_else(|| cfg.protocol.as_deref().and_then(Protocol::from_str_opt))
                        .unwrap_or_default();
                    let node_id = node_id.or(cfg.node_id).context(
                        "node_id is required. Provide via --node-id or in config file.",
                    )?;
                    let listen = listen.or(cfg.listen).context(
                        "listen is required. Provide via --listen or in config file.",
                    )?;
                    let relay_urls = if relay_urls.is_empty() {
                        cfg.relay_urls.unwrap_or_default()
                    } else {
                        relay_urls
                    };
                    let relay_only = relay_only || cfg.relay_only.unwrap_or(false);
                    let dns_server = dns_server.or(cfg.dns_server);

                    match protocol {
                        Protocol::Udp => {
                            tunnel::run_udp_receiver(node_id, listen, relay_urls, relay_only, dns_server)
                                .await
                        }
                        Protocol::Tcp => {
                            tunnel::run_tcp_receiver(node_id, listen, relay_urls, relay_only, dns_server)
                                .await
                        }
                    }
                }
                IrohReceiverMode::Manual {
                    config,
                    protocol,
                    listen,
                } => {
                    let cfg = load_iroh_receiver_config(config.as_deref())?;

                    let protocol = protocol
                        .or_else(|| cfg.protocol.as_deref().and_then(Protocol::from_str_opt))
                        .unwrap_or_default();
                    let listen = listen.or(cfg.listen).context(
                        "listen is required. Provide via --listen or in config file.",
                    )?;

                    match protocol {
                        Protocol::Udp => {
                            tunnel::run_iroh_manual_udp_receiver(listen).await
                        }
                        Protocol::Tcp => {
                            tunnel::run_iroh_manual_tcp_receiver(listen).await
                        }
                    }
                }
            },
            ReceiverMode::Custom {
                config,
                listen,
                stun_servers,
            } => {
                let cfg = load_ice_receiver_config(config.as_deref())?;

                let listen = listen.or(cfg.listen).context(
                    "listen is required. Provide via --listen or in config file.",
                )?;
                let stun_servers = if stun_servers.is_empty() {
                    cfg.stun_servers.unwrap_or_else(default_stun_servers)
                } else {
                    stun_servers
                };

                tunnel::run_manual_tcp_receiver(listen, stun_servers).await
            }
        },
        Command::GenerateSecret { output, force } => secret::generate_secret(output, force),
        Command::ShowId { secret_file } => secret::show_id(secret_file),
    }
}
