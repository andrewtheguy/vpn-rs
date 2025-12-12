//! tunnel-rs
//!
//! Forwards TCP or UDP traffic through iroh P2P connections.
//!
//! Usage:
//!   TCP sender:    tunnel-rs sender --target 127.0.0.1:22
//!   TCP receiver:  tunnel-rs receiver --node-id <NODE_ID> --listen 127.0.0.1:2222
//!   UDP sender:    tunnel-rs sender --protocol udp --target 127.0.0.1:51820
//!   UDP receiver:  tunnel-rs receiver --protocol udp --node-id <NODE_ID> --listen 0.0.0.0:51820

mod endpoint;
mod secret;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum, Default)]
enum Protocol {
    /// TCP tunneling
    #[default]
    Tcp,
    /// UDP tunneling
    Udp,
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
        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long, default_value = "tcp")]
        protocol: Protocol,

        /// Target address to forward traffic to
        #[arg(short, long, default_value = "127.0.0.1:22")]
        target: String,

        /// Path to secret key file for persistent identity (optional)
        /// If provided and file doesn't exist, a new key will be generated and saved
        /// If provided and file exists, the existing key will be loaded
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
        /// Protocol to tunnel (tcp or udp)
        #[arg(short, long, default_value = "tcp")]
        protocol: Protocol,

        /// NodeId of the sender to connect to
        #[arg(short, long)]
        node_id: String,

        /// Local address to listen on (e.g., 127.0.0.1:2222 or [::]:2222)
        #[arg(short, long)]
        listen: String,

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
            protocol,
            target,
            secret_file,
            relay_urls,
            relay_only,
        } => match protocol {
            Protocol::Udp => tunnel::run_udp_sender(target, secret_file, relay_urls, relay_only).await,
            Protocol::Tcp => tunnel::run_tcp_sender(target, secret_file, relay_urls, relay_only).await,
        },
        Mode::Receiver {
            protocol,
            node_id,
            listen,
            relay_urls,
            relay_only,
        } => match protocol {
            Protocol::Udp => tunnel::run_udp_receiver(node_id, listen, relay_urls, relay_only).await,
            Protocol::Tcp => tunnel::run_tcp_receiver(node_id, listen, relay_urls, relay_only).await,
        },
        Mode::GenerateSecret { output, force } => secret::generate_secret(output, force),
        Mode::ShowId { secret_file } => secret::show_id(secret_file),
    }
}
