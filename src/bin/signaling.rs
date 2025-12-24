//! DCUtR-style signaling server binary.
//!
//! Usage:
//! ```bash
//! tunnel-signaling --bind 0.0.0.0:9999
//! ```

use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;

// Import from the library crate
use tunnel_rs::signaling::dcutr::run_signaling_server;

#[derive(Parser, Debug)]
#[command(name = "tunnel-signaling")]
#[command(about = "DCUtR-style signaling server for coordinated NAT hole punching")]
#[command(version)]
struct Args {
    /// Address to bind the signaling server
    #[arg(short, long, default_value = "0.0.0.0:9999")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    log::info!("Starting DCUtR signaling server on {}", args.bind);

    run_signaling_server(args.bind).await
}
