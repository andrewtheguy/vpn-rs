//! UDP Sender
//!
//! Forwards UDP traffic from a local port through iroh to a connected receiver.
//! Run this on the machine with the UDP service (e.g., WireGuard server).
//!
//! Usage:
//!   cargo run --bin udp-sender -- --listen-port 51821 --target 127.0.0.1:51820

use anyhow::{Context, Result};
use clap::Parser;
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    Endpoint,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const ALPN: &[u8] = b"udp-forward/1";

#[derive(Parser)]
#[command(name = "udp-sender")]
#[command(about = "Forward local UDP port through iroh P2P connection")]
struct Args {
    /// Local UDP port to listen on (receives traffic to forward)
    #[arg(short, long, default_value = "51821")]
    listen_port: u16,

    /// Target UDP address to forward traffic to (e.g., WireGuard server)
    #[arg(short, long, default_value = "127.0.0.1:51820")]
    target: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let target_addr: SocketAddr = args
        .target
        .parse()
        .context("Invalid target address format")?;

    println!("UDP Sender - Forward UDP through iroh");
    println!("======================================");

    // Create iroh endpoint with discovery
    println!("Creating iroh endpoint...");
    let endpoint = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    // Wait for endpoint to be online
    endpoint.online().await;

    // Print connection info
    let endpoint_id = endpoint.id();
    println!("\nEndpointId: {}", endpoint_id);
    println!("\nOn the receiver side, run:");
    println!(
        "  cargo run --bin udp-receiver -- --node-id {} --listen-port 51820\n",
        endpoint_id
    );
    println!("Waiting for receiver to connect...");

    // Accept incoming connection
    let conn = endpoint
        .accept()
        .await
        .context("No incoming connection")?
        .await
        .context("Failed to accept connection")?;

    println!("Receiver connected from: {}", conn.remote_id());

    // Open bidirectional stream
    let (send_stream, recv_stream) = conn.open_bi().await.context("Failed to open stream")?;

    // Bind local UDP socket
    let udp_socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{}", args.listen_port))
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening for UDP on port {}, forwarding to {}",
        args.listen_port, target_addr
    );

    // Track the last peer address for responses from the target
    let peer_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Run bidirectional forwarding
    let udp_clone = udp_socket.clone();
    let peer_clone = peer_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, peer_clone) => {
            if let Err(e) = result {
                eprintln!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp(recv_stream, udp_socket, target_addr, peer_addr) => {
            if let Err(e) = result {
                eprintln!("Stream to UDP error: {}", e);
            }
        }
    }

    // Cleanup
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    println!("Connection closed.");

    Ok(())
}

/// Read UDP packets from local socket and forward to iroh stream
async fn forward_udp_to_stream(
    udp_socket: Arc<UdpSocket>,
    mut send_stream: iroh::endpoint::SendStream,
    peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, addr) = udp_socket
            .recv_from(&mut buf)
            .await
            .context("Failed to receive UDP packet")?;

        // Remember peer address for responses
        *peer_addr.lock().await = Some(addr);

        // Frame: [length: u16 BE][payload]
        let frame_len = (len as u16).to_be_bytes();
        send_stream
            .write_all(&frame_len)
            .await
            .context("Failed to write frame length")?;
        send_stream
            .write_all(&buf[..len])
            .await
            .context("Failed to write frame payload")?;

        println!("-> Forwarded {} bytes from {}", len, addr);
    }
}

/// Read from iroh stream and forward to local UDP target
async fn forward_stream_to_udp(
    mut recv_stream: iroh::endpoint::RecvStream,
    udp_socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
    _peer_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    loop {
        // Read frame length (2 bytes, big-endian)
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            // Stream closed
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read payload
        let mut buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut buf)
            .await
            .context("Failed to read frame payload")?;

        // Forward to target (WireGuard server)
        udp_socket
            .send_to(&buf, target_addr)
            .await
            .context("Failed to send UDP packet")?;

        println!("<- Forwarded {} bytes to {}", len, target_addr);
    }

    Ok(())
}
