//! tunnel-rs
//!
//! Forwards TCP or UDP traffic through P2P connections.
//!
//! Three modes are available:
//!   - iroh-default: Uses iroh P2P discovery with relay fallback
//!   - iroh-manual:  Uses iroh with STUN-based manual signaling
//!   - custom:       Uses full ICE with manual signaling (best NAT traversal)
//!
//! Usage:
//!   tunnel-rs sender iroh-default --target 127.0.0.1:22
//!   tunnel-rs sender iroh-manual --target 127.0.0.1:22
//!   tunnel-rs sender custom --target 127.0.0.1:22
//!   tunnel-rs receiver iroh-default --node-id <NODE_ID> --listen 127.0.0.1:2222
//!   tunnel-rs receiver iroh-manual --listen 127.0.0.1:2222
//!   tunnel-rs receiver custom --listen 127.0.0.1:2222

mod config;
mod endpoint;
mod manual;
mod secret;
mod tunnel;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use config::{default_stun_servers, load_receiver_config, load_sender_config, ReceiverConfig, SenderConfig};
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
    #[command(subcommand_negates_reqs = true)]
    Sender {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/sender.toml)
        #[arg(long)]
        default_config: bool,

        #[command(subcommand)]
        mode: Option<SenderMode>,
    },
    /// Run as receiver (connects to sender and exposes local port)
    #[command(subcommand_negates_reqs = true)]
    Receiver {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/receiver.toml)
        #[arg(long)]
        default_config: bool,

        #[command(subcommand)]
        mode: Option<ReceiverMode>,
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
    /// Use iroh with automatic discovery (Pkarr/DNS/mDNS) and relay fallback
    #[command(name = "iroh-default")]
    IrohDefault {
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
    /// Use iroh with STUN-based manual signaling (may fail on symmetric NAT)
    #[command(name = "iroh-manual")]
    IrohManual {
        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Target address to forward traffic to
        #[arg(short, long)]
        target: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,
    },
    /// Full ICE with manual signaling - best NAT traversal (str0m+quinn)
    Custom {
        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Target address to forward traffic to
        #[arg(short, long)]
        target: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ReceiverMode {
    /// Use iroh with automatic discovery (Pkarr/DNS/mDNS) and relay fallback
    #[command(name = "iroh-default")]
    IrohDefault {
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
    /// Use iroh with STUN-based manual signaling (may fail on symmetric NAT)
    #[command(name = "iroh-manual")]
    IrohManual {
        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        listen: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,
    },
    /// Full ICE with manual signaling - best NAT traversal (str0m+quinn)
    Custom {
        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        listen: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,
    },
}

/// Load sender config based on flags. Returns (config, was_loaded_from_file).
fn resolve_sender_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(SenderConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_sender_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_sender_config(None)?, true))
    } else {
        Ok((SenderConfig::default(), false))
    }
}

/// Load receiver config based on flags. Returns (config, was_loaded_from_file).
fn resolve_receiver_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(ReceiverConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_receiver_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_receiver_config(None)?, true))
    } else {
        Ok((ReceiverConfig::default(), false))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Sender {
            config,
            default_config,
            mode,
        } => {
            let (cfg, from_file) = resolve_sender_config(config.clone(), default_config)?;

            // Determine effective mode: CLI mode takes precedence, else read from config
            let effective_mode = match (&mode, &cfg.mode) {
                (Some(_), _) => mode.as_ref().map(|m| match m {
                    SenderMode::IrohDefault { .. } => "iroh-default",
                    SenderMode::IrohManual { .. } => "iroh-manual",
                    SenderMode::Custom { .. } => "custom",
                }),
                (None, Some(m)) => Some(m.as_str()),
                (None, None) => None,
            };

            let effective_mode = effective_mode.context(
                "No mode specified. Either use a subcommand (iroh-default, iroh-manual, custom) or provide a config file with 'mode' field.",
            )?;

            // Validate config if loaded from file
            if from_file {
                cfg.validate(effective_mode)?;
            }

            // Get common values from config
            let protocol = cfg.protocol.as_deref().and_then(Protocol::from_str_opt).unwrap_or_default();
            let target = cfg.target.clone().unwrap_or_else(|| "127.0.0.1:22".to_string());

            match effective_mode {
                "iroh-default" => {
                    // Override with CLI values if provided
                    let (protocol, target, secret_file, relay_urls, relay_only, dns_server) = match &mode {
                        Some(SenderMode::IrohDefault { protocol: p, target: t, secret_file: s, relay_urls: r, relay_only: ro, dns_server: d }) => {
                            let iroh_cfg = cfg.iroh_default();
                            (
                                p.unwrap_or(protocol),
                                t.clone().unwrap_or(target),
                                s.clone().or(iroh_cfg.secret_file),
                                if r.is_empty() { iroh_cfg.relay_urls.unwrap_or_default() } else { r.clone() },
                                *ro || iroh_cfg.relay_only.unwrap_or(false),
                                d.clone().or(iroh_cfg.dns_server),
                            )
                        }
                        _ => {
                            let iroh_cfg = cfg.iroh_default();
                            (protocol, target, iroh_cfg.secret_file, iroh_cfg.relay_urls.unwrap_or_default(), iroh_cfg.relay_only.unwrap_or(false), iroh_cfg.dns_server)
                        }
                    };

                    match protocol {
                        Protocol::Udp => tunnel::run_udp_sender(target, secret_file, relay_urls, relay_only, dns_server).await,
                        Protocol::Tcp => tunnel::run_tcp_sender(target, secret_file, relay_urls, relay_only, dns_server).await,
                    }
                }
                "iroh-manual" => {
                    let (protocol, target, stun_servers) = match &mode {
                        Some(SenderMode::IrohManual { protocol: p, target: t, stun_servers: s }) => (
                            p.unwrap_or(protocol),
                            t.clone().unwrap_or(target),
                            if s.is_empty() { cfg.iroh_manual().stun_servers.unwrap_or_else(default_stun_servers) } else { s.clone() },
                        ),
                        _ => (protocol, target, cfg.iroh_manual().stun_servers.unwrap_or_else(default_stun_servers)),
                    };

                    match protocol {
                        Protocol::Udp => tunnel::run_iroh_manual_udp_sender(target, stun_servers).await,
                        Protocol::Tcp => tunnel::run_iroh_manual_tcp_sender(target, stun_servers).await,
                    }
                }
                "custom" => {
                    let (protocol, target, stun_servers) = match &mode {
                        Some(SenderMode::Custom { protocol: p, target: t, stun_servers: s }) => (
                            p.unwrap_or(protocol),
                            t.clone().unwrap_or(target),
                            if s.is_empty() { cfg.custom().stun_servers.unwrap_or_else(default_stun_servers) } else { s.clone() },
                        ),
                        _ => (protocol, target, cfg.custom().stun_servers.unwrap_or_else(default_stun_servers)),
                    };

                    match protocol {
                        Protocol::Udp => tunnel::run_manual_udp_sender(target, stun_servers).await,
                        Protocol::Tcp => tunnel::run_manual_tcp_sender(target, stun_servers).await,
                    }
                }
                _ => anyhow::bail!("Invalid mode '{}'. Use: iroh-default, iroh-manual, or custom", effective_mode),
            }
        }
        Command::Receiver {
            config,
            default_config,
            mode,
        } => {
            let (cfg, from_file) = resolve_receiver_config(config, default_config)?;

            // Determine effective mode: CLI mode takes precedence, else read from config
            let effective_mode = match (&mode, &cfg.mode) {
                (Some(_), _) => mode.as_ref().map(|m| match m {
                    ReceiverMode::IrohDefault { .. } => "iroh-default",
                    ReceiverMode::IrohManual { .. } => "iroh-manual",
                    ReceiverMode::Custom { .. } => "custom",
                }),
                (None, Some(m)) => Some(m.as_str()),
                (None, None) => None,
            };

            let effective_mode = effective_mode.context(
                "No mode specified. Either use a subcommand (iroh-default, iroh-manual, custom) or provide a config file with 'mode' field.",
            )?;

            // Validate config if loaded from file
            if from_file {
                cfg.validate(effective_mode)?;
            }

            // Get common values from config
            let protocol = cfg.protocol.as_deref().and_then(Protocol::from_str_opt).unwrap_or_default();
            let listen = cfg.listen.clone();

            match effective_mode {
                "iroh-default" => {
                    // Override with CLI values if provided
                    let (protocol, node_id, listen, relay_urls, relay_only, dns_server) = match &mode {
                        Some(ReceiverMode::IrohDefault { protocol: p, node_id: n, listen: l, relay_urls: r, relay_only: ro, dns_server: d }) => {
                            let iroh_cfg = cfg.iroh_default();
                            (
                                p.unwrap_or(protocol),
                                n.clone().or(iroh_cfg.node_id),
                                l.clone().or(listen),
                                if r.is_empty() { iroh_cfg.relay_urls.unwrap_or_default() } else { r.clone() },
                                *ro || iroh_cfg.relay_only.unwrap_or(false),
                                d.clone().or(iroh_cfg.dns_server),
                            )
                        }
                        _ => {
                            let iroh_cfg = cfg.iroh_default();
                            (protocol, iroh_cfg.node_id.clone(), listen, iroh_cfg.relay_urls.unwrap_or_default(), iroh_cfg.relay_only.unwrap_or(false), iroh_cfg.dns_server.clone())
                        }
                    };

                    let node_id = node_id.context(
                        "node_id is required. Provide via --node-id or in config file.",
                    )?;
                    let listen = listen.context(
                        "listen is required. Provide via --listen or in config file.",
                    )?;

                    match protocol {
                        Protocol::Udp => tunnel::run_udp_receiver(node_id, listen, relay_urls, relay_only, dns_server).await,
                        Protocol::Tcp => tunnel::run_tcp_receiver(node_id, listen, relay_urls, relay_only, dns_server).await,
                    }
                }
                "iroh-manual" => {
                    let (protocol, listen, stun_servers) = match &mode {
                        Some(ReceiverMode::IrohManual { protocol: p, listen: l, stun_servers: s }) => (
                            p.unwrap_or(protocol),
                            l.clone().or(listen),
                            if s.is_empty() { cfg.iroh_manual().stun_servers.unwrap_or_else(default_stun_servers) } else { s.clone() },
                        ),
                        _ => (protocol, listen, cfg.iroh_manual().stun_servers.unwrap_or_else(default_stun_servers)),
                    };

                    let listen: String = listen.context(
                        "listen is required. Provide via --listen or in config file.",
                    )?;

                    match protocol {
                        Protocol::Udp => tunnel::run_iroh_manual_udp_receiver(listen, stun_servers).await,
                        Protocol::Tcp => tunnel::run_iroh_manual_tcp_receiver(listen, stun_servers).await,
                    }
                }
                "custom" => {
                    let (protocol, listen, stun_servers) = match &mode {
                        Some(ReceiverMode::Custom { protocol: p, listen: l, stun_servers: s }) => (
                            p.unwrap_or(protocol),
                            l.clone().or(listen),
                            if s.is_empty() { cfg.custom().stun_servers.unwrap_or_else(default_stun_servers) } else { s.clone() },
                        ),
                        _ => (protocol, listen, cfg.custom().stun_servers.unwrap_or_else(default_stun_servers)),
                    };

                    let listen: String = listen.context(
                        "listen is required. Provide via --listen or in config file.",
                    )?;

                    match protocol {
                        Protocol::Udp => tunnel::run_manual_udp_receiver(listen, stun_servers).await,
                        Protocol::Tcp => tunnel::run_manual_tcp_receiver(listen, stun_servers).await,
                    }
                }
                _ => anyhow::bail!("Invalid mode '{}'. Use: iroh-default, iroh-manual, or custom", effective_mode),
            }
        }
        Command::GenerateSecret { output, force } => secret::generate_secret(output, force),
        Command::ShowId { secret_file } => secret::show_id(secret_file),
    }
}
