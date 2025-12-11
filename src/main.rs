//! UDP Tunnel
//!
//! Forwards UDP traffic through iroh P2P connections.
//!
//! Usage:
//!   Sender mode:  cargo run -- sender --listen-port 51821 --target 127.0.0.1:51820
//!   Receiver mode: cargo run -- receiver --node-id <NODE_ID> --listen-port 51820

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    Endpoint, EndpointAddr, EndpointId,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const ALPN: &[u8] = b"udp-forward/1";

#[derive(Parser)]
#[command(name = "udp-tunnel")]
#[command(about = "Forward UDP traffic through iroh P2P connections")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as sender (accepts connections and forwards local UDP port)
    Sender {
        /// Local UDP port to listen on (receives traffic to forward)
        #[arg(short, long, default_value = "51821")]
        listen_port: u16,

        /// Target UDP address to forward traffic to (e.g., WireGuard server)
        #[arg(short, long, default_value = "127.0.0.1:51820")]
        target: String,
    },
    /// Run as receiver (connects to sender and exposes local UDP port)
    Receiver {
        /// NodeId of the sender to connect to
        #[arg(short, long)]
        node_id: String,

        /// Local UDP port to expose (client connects here)
        #[arg(short, long, default_value = "51820")]
        listen_port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.mode {
        Mode::Sender {
            listen_port,
            target,
        } => run_sender(listen_port, target).await,
        Mode::Receiver {
            node_id,
            listen_port,
        } => run_receiver(node_id, listen_port).await,
    }
}

async fn run_sender(listen_port: u16, target: String) -> Result<()> {
    let target_addr: SocketAddr = target
        .parse()
        .context("Invalid target address format")?;

    println!("UDP Tunnel - Sender Mode");
    println!("========================");

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
        "  cargo run -- receiver --node-id {} --listen-port 51820\n",
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
        UdpSocket::bind(format!("0.0.0.0:{}", listen_port))
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening for UDP on port {}, forwarding to {}",
        listen_port, target_addr
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

async fn run_receiver(node_id: String, listen_port: u16) -> Result<()> {
    // Parse EndpointId
    let endpoint_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    println!("UDP Tunnel - Receiver Mode");
    println!("==========================");

    // Create iroh endpoint with discovery
    println!("Creating iroh endpoint...");
    let endpoint = Endpoint::builder()
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    // Connect to sender
    println!("Connecting to sender {}...", endpoint_id);
    let endpoint_addr = EndpointAddr::new(endpoint_id);
    let conn = endpoint
        .connect(endpoint_addr, ALPN)
        .await
        .context("Failed to connect to sender")?;

    println!("Connected to sender!");

    // Accept bidirectional stream (sender opens it)
    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from sender")?;

    // Bind local UDP socket for clients to connect to
    let bind_addr = format!("127.0.0.1:{}", listen_port);
    let udp_socket = Arc::new(
        UdpSocket::bind(&bind_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening on UDP {} - configure your client to connect here",
        bind_addr
    );

    // Track the client address for sending responses back
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Run bidirectional forwarding
    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                eprintln!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
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

/// Read from iroh stream and forward to local UDP target (sender mode)
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

        // Forward to target
        udp_socket
            .send_to(&buf, target_addr)
            .await
            .context("Failed to send UDP packet")?;

        println!("<- Forwarded {} bytes to {}", len, target_addr);
    }

    Ok(())
}

/// Read from iroh stream and forward to local UDP client (receiver mode)
async fn forward_stream_to_udp_receiver(
    mut recv_stream: iroh::endpoint::RecvStream,
    udp_socket: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
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

        // Forward to the last known client address
        if let Some(addr) = *client_addr.lock().await {
            udp_socket
                .send_to(&buf, addr)
                .await
                .context("Failed to send UDP packet to client")?;
            println!("<- Forwarded {} bytes to client {}", len, addr);
        } else {
            println!("<- Received {} bytes but no client connected yet", len);
        }
    }

    Ok(())
}
