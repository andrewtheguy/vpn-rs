//! UDP Tunnel
//!
//! Forwards UDP traffic through iroh P2P connections.
//!
//! Usage:
//!   Sender mode (ephemeral):  cargo run -- sender --target 127.0.0.1:51820
//!   Sender mode (persistent): cargo run -- sender --target 127.0.0.1:51820 --secret-file ./sender.key
//!   Receiver mode:            cargo run -- receiver --node-id <NODE_ID> --listen-port 51820

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::{
    discovery::{dns::DnsDiscovery, mdns::MdnsDiscovery, pkarr::PkarrPublisher},
    Endpoint, EndpointAddr, EndpointId, SecretKey,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    /// Run as sender (accepts connections and forwards to target)
    Sender {
        /// Target UDP address to forward traffic to (e.g., WireGuard server)
        #[arg(short, long, default_value = "127.0.0.1:51820")]
        target: String,

        /// Path to secret key file for persistent identity (optional)
        /// If provided and file doesn't exist, a new key will be generated and saved
        /// If provided and file exists, the existing key will be loaded
        #[arg(long)]
        secret_file: Option<PathBuf>,
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
    /// Generate a new secret key file (for automation/setup)
    GenerateSecret {
        /// Path where to save the secret key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.mode {
        Mode::Sender {
            target,
            secret_file,
        } => run_sender(target, secret_file).await,
        Mode::Receiver {
            node_id,
            listen_port,
        } => run_receiver(node_id, listen_port).await,
        Mode::GenerateSecret { output, force } => generate_secret_command(output, force),
    }
}

/// Load secret key from file, or generate new one if file doesn't exist
fn load_or_generate_secret(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        // Load existing key
        let bytes = std::fs::read(path).context("Failed to read secret key file")?;
        SecretKey::try_from(&bytes[..]).context("Invalid secret key file")
    } else {
        // Generate new key
        let secret = SecretKey::generate(&mut rand::rng());

        // Save to file
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
        }
        std::fs::write(path, secret.to_bytes()).context("Failed to write secret key file")?;

        // Set file permissions to 0600 (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(secret)
    }
}

/// Get public key (EndpointId) from secret key
fn secret_to_endpoint_id(secret: &SecretKey) -> EndpointId {
    secret.public()
}

async fn run_sender(target: String, secret_file: Option<PathBuf>) -> Result<()> {
    let target_addr: SocketAddr = target
        .parse()
        .context("Invalid target address format")?;

    println!("UDP Tunnel - Sender Mode");
    println!("========================");

    // Create iroh endpoint with discovery
    println!("Creating iroh endpoint...");
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    // Disable idle timeout - UDP traffic can be sporadic
    transport_config.max_idle_timeout(None);

    let mut endpoint_builder = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .transport_config(transport_config);

    // If secret file is provided, use persistent identity
    if let Some(secret_path) = &secret_file {
        let key_existed = secret_path.exists();
        let secret = load_or_generate_secret(secret_path)?;
        let endpoint_id = secret_to_endpoint_id(&secret);

        if key_existed {
            println!("Loaded persistent identity from: {}", secret_path.display());
        } else {
            println!(
                "Generated new persistent identity, saved to: {}",
                secret_path.display()
            );
        }
        println!("Fixed EndpointId: {}", endpoint_id);

        endpoint_builder = endpoint_builder.secret_key(secret);
    }

    let endpoint = endpoint_builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    // Wait for endpoint to be online
    endpoint.online().await;

    // Print connection info
    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    println!("\nEndpointId: {}", endpoint_id);
    println!("\nOn the receiver side, run:");
    println!(
        "  udp-tunnel receiver --node-id {} --listen-port {}\n",
        endpoint_id, target_port
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

    // Accept bidirectional stream (receiver will open it)
    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    println!("Forwarding UDP traffic to {}", target_addr);

    // Create a UDP socket for sending to target
    let udp_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?,
    );

    // Forward stream to UDP target
    forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr).await?;

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
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    // Disable idle timeout - UDP traffic can be sporadic
    transport_config.max_idle_timeout(None);

    let endpoint = Endpoint::builder()
        .discovery(PkarrPublisher::n0_dns())
        .discovery(DnsDiscovery::n0_dns())
        .discovery(MdnsDiscovery::builder())
        .transport_config(transport_config)
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

    // Open bidirectional stream
    let (send_stream, recv_stream) = conn.open_bi().await.context("Failed to open stream")?;

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

/// Read from iroh stream, forward to UDP target, and send responses back (sender mode)
async fn forward_stream_to_udp_sender(
    mut recv_stream: iroh::endpoint::RecvStream,
    mut send_stream: iroh::endpoint::SendStream,
    udp_socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
) -> Result<()> {
    let udp_clone = udp_socket.clone();

    // Spawn task to read responses from target and send back through tunnel
    let response_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match udp_clone.recv_from(&mut buf).await {
                Ok((len, _addr)) => {
                    // Frame: [length: u16 BE][payload]
                    let frame_len = (len as u16).to_be_bytes();
                    if send_stream.write_all(&frame_len).await.is_err() {
                        break;
                    }
                    if send_stream.write_all(&buf[..len]).await.is_err() {
                        break;
                    }
                    println!("-> Sent {} bytes back to receiver", len);
                }
                Err(_) => break,
            }
        }
    });

    // Read from tunnel and forward to target
    loop {
        // Read frame length (2 bytes, big-endian)
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
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

    response_task.abort();
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

/// Generate a new secret key file and output the EndpointId to stdout
fn generate_secret_command(output: PathBuf, force: bool) -> Result<()> {
    // Generate secret key
    let secret = SecretKey::generate(&mut rand::rng());

    // Check if output is stdout (-)
    if output.to_str() == Some("-") {
        // Only output the EndpointId to stdout, don't save to file
        let endpoint_id = secret_to_endpoint_id(&secret);
        println!("{}", endpoint_id);
    } else {
        // Check if file exists
        if output.exists() && !force {
            anyhow::bail!(
                "File already exists: {}. Use --force to overwrite.",
                output.display()
            );
        }

        // Save to file with proper permissions
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create parent directory")?;
        }
        std::fs::write(&output, secret.to_bytes())
            .context("Failed to write secret key file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&output)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&output, perms)?;
        }

        // Output EndpointId to stdout for automation (like wg pubkey)
        let endpoint_id = secret_to_endpoint_id(&secret);
        println!("{}", endpoint_id);
    }

    Ok(())
}
