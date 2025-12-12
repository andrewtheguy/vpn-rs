//! tunnel-rs
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.
//!
//! Usage:
//!   TCP sender:    tunnel-rs sender --target 127.0.0.1:22
//!   TCP receiver:  tunnel-rs receiver --node-id <NODE_ID> --listen 127.0.0.1:2222
//!   UDP sender:    tunnel-rs sender --protocol udp --target 127.0.0.1:51820
//!   UDP receiver:  tunnel-rs receiver --protocol udp --node-id <NODE_ID> --listen 0.0.0.0:51820

mod config;
mod endpoint;
mod secret;
mod tunnel;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use config::{load_config, ReceiverConfig, SenderConfig};
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
#[command(about = "Forward TCP/UDP traffic through iroh P2P connections")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as sender (accepts connections and forwards to target)
    Sender {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// Target address to forward traffic to
        #[arg(short, long)]
        target: Option<String>,

        /// Path to secret key file for persistent identity (optional)
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) (e.g., http://localhost:3340 for local dev relay)
        /// Can be specified multiple times for failover. If not provided, uses iroh's default public relays
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P)
        /// Requires --relay-url to be specified (default relay is rate-limited)
        #[arg(long)]
        relay_only: bool,
    },
    /// Run as receiver (connects to sender and exposes local port)
    Receiver {
        /// Path to TOML config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long)]
        protocol: Option<Protocol>,

        /// NodeId of the sender to connect to
        #[arg(short, long)]
        node_id: Option<String>,

        /// Local address to listen on (e.g., 127.0.0.1:2222 or [::]:2222)
        #[arg(short, long)]
        listen: Option<String>,

        /// Custom relay server URL(s) (e.g., http://localhost:3340 for local dev relay)
        /// Can be specified multiple times for failover. If not provided, uses iroh's default public relays
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P)
        /// Requires --relay-url to be specified (default relay is rate-limited)
        #[arg(long)]
        relay_only: bool,
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.mode {
        Mode::Sender {
            config,
            protocol,
            target,
            secret_file,
            relay_urls,
            relay_only,
        } => {
            // Load config if provided
            let cfg: SenderConfig = if let Some(config_path) = &config {
                load_config(config_path)?
            } else {
                SenderConfig::default()
            };

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
            let relay_only = if relay_only { true } else { cfg.relay_only.unwrap_or(false) };

            match protocol {
                Protocol::Udp => {
                    tunnel::run_udp_sender(target, secret_file, relay_urls, relay_only).await
                }
                Protocol::Tcp => {
                    tunnel::run_tcp_sender(target, secret_file, relay_urls, relay_only).await
                }
            }
        }
        Mode::Receiver {
            config,
            protocol,
            node_id,
            listen,
            relay_urls,
            relay_only,
        } => {
            // Load config if provided
            let cfg: ReceiverConfig = if let Some(config_path) = &config {
                load_config(config_path)?
            } else {
                ReceiverConfig::default()
            };

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
            let relay_only = if relay_only { true } else { cfg.relay_only.unwrap_or(false) };

            match protocol {
                Protocol::Udp => tunnel::run_udp_receiver(node_id, listen, relay_urls, relay_only).await,
                Protocol::Tcp => tunnel::run_tcp_receiver(node_id, listen, relay_urls, relay_only).await,
            }
        }
        Mode::GenerateSecret { output, force } => secret::generate_secret(output, force),
        Mode::ShowId { secret_file } => secret::show_id(secret_file),
    }
}
