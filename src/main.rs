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

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Parser, Subcommand, ValueEnum};
use iroh::{EndpointId, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use endpoint::{
    connect_to_sender, create_receiver_endpoint, create_sender_endpoint, load_secret,
    print_connection_type, secret_to_endpoint_id, validate_relay_only, TCP_ALPN, UDP_ALPN,
};

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
            Protocol::Udp => run_udp_sender(target, secret_file, relay_urls, relay_only).await,
            Protocol::Tcp => run_tcp_sender(target, secret_file, relay_urls, relay_only).await,
        },
        Mode::Receiver {
            protocol,
            node_id,
            listen,
            relay_urls,
            relay_only,
        } => match protocol {
            Protocol::Udp => run_udp_receiver(node_id, listen, relay_urls, relay_only).await,
            Protocol::Tcp => run_tcp_receiver(node_id, listen, relay_urls, relay_only).await,
        },
        Mode::GenerateSecret { output, force } => generate_secret_command(output, force),
        Mode::ShowId { secret_file } => show_id_command(secret_file),
    }
}

// ============================================================================
// UDP Tunnel Implementation
// ============================================================================

async fn run_udp_sender(
    target: String,
    secret_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    relay_only: bool,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let target_addr: SocketAddr = target.parse().context("Invalid target address format")?;

    println!("UDP Tunnel - Sender Mode");
    println!("========================");
    println!("Creating iroh endpoint...");

    let endpoint = create_sender_endpoint(&relay_urls, relay_only, secret_file.as_ref(), UDP_ALPN).await?;

    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    println!("\nEndpointId: {}", endpoint_id);
    println!("\nOn the receiver side, run:");
    println!(
        "  tunnel-rs receiver --protocol udp --node-id {} --listen 0.0.0.0:{}\n",
        endpoint_id, target_port
    );
    println!("Waiting for receiver to connect...");

    let conn = endpoint
        .accept()
        .await
        .context("No incoming connection")?
        .await
        .context("Failed to accept connection")?;

    println!("Receiver connected from: {}", conn.remote_id());

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    println!("Forwarding UDP traffic to {}", target_addr);

    let udp_socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?,
    );

    forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr).await?;

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    println!("Connection closed.");

    Ok(())
}

async fn run_udp_receiver(
    node_id: String,
    listen: String,
    relay_urls: Vec<String>,
    relay_only: bool,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    let sender_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    println!("UDP Tunnel - Receiver Mode");
    println!("==========================");
    println!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, UDP_ALPN).await?;

    println!("Connected to sender!");
    print_connection_type(&endpoint, conn.remote_id());

    let (send_stream, recv_stream) = conn.open_bi().await.context("Failed to open stream")?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    println!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

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

        *peer_addr.lock().await = Some(addr);

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

    let response_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match udp_clone.recv_from(&mut buf).await {
                Ok((len, _addr)) => {
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

    loop {
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut buf)
            .await
            .context("Failed to read frame payload")?;

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
        let mut len_buf = [0u8; 2];
        if recv_stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        recv_stream
            .read_exact(&mut buf)
            .await
            .context("Failed to read frame payload")?;

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

// ============================================================================
// TCP Tunnel Implementation
// ============================================================================

async fn run_tcp_sender(
    target: String,
    secret_file: Option<PathBuf>,
    relay_urls: Vec<String>,
    relay_only: bool,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let target_addr: SocketAddr = target.parse().context("Invalid target address format")?;

    println!("TCP Tunnel - Sender Mode");
    println!("========================");
    println!("Creating iroh endpoint...");

    let endpoint = create_sender_endpoint(&relay_urls, relay_only, secret_file.as_ref(), TCP_ALPN).await?;

    let endpoint_id = endpoint.id();
    let target_port = target_addr.port();
    println!("\nEndpointId: {}", endpoint_id);
    println!("\nOn the receiver side, run:");
    println!(
        "  tunnel-rs receiver --node-id {} --listen 127.0.0.1:{}\n",
        endpoint_id, target_port
    );
    println!("Waiting for receiver to connect...");

    loop {
        let conn = match endpoint.accept().await {
            Some(incoming) => match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    continue;
                }
            },
            None => {
                println!("Endpoint closed");
                break;
            }
        };

        println!("Receiver connected from: {}", conn.remote_id());
        println!("Forwarding TCP connections to {}", target_addr);

        let target = target_addr;
        tokio::spawn(async move {
            loop {
                let (send_stream, recv_stream) = match conn.accept_bi().await {
                    Ok(streams) => streams,
                    Err(e) => {
                        println!("Receiver disconnected: {}", e);
                        break;
                    }
                };

                println!("New TCP connection request received");

                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await {
                        eprintln!("TCP connection error: {}", e);
                    }
                });
            }

            conn.close(0u32.into(), b"done");
            println!("Receiver connection closed.");
        });

        println!("Waiting for next receiver to connect...");
    }

    endpoint.close().await;
    Ok(())
}

async fn handle_tcp_sender_stream(
    send_stream: iroh::endpoint::SendStream,
    recv_stream: iroh::endpoint::RecvStream,
    target_addr: SocketAddr,
) -> Result<()> {
    let tcp_stream = TcpStream::connect(target_addr)
        .await
        .context("Failed to connect to target TCP service")?;

    println!("-> Connected to target {}", target_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    println!("<- TCP connection to {} closed", target_addr);
    Ok(())
}

async fn run_tcp_receiver(
    node_id: String,
    listen: String,
    relay_urls: Vec<String>,
    relay_only: bool,
) -> Result<()> {
    validate_relay_only(relay_only, &relay_urls)?;

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    let sender_id: EndpointId = node_id
        .parse()
        .context("Invalid EndpointId format. Should be a 52-character base32 string.")?;

    println!("TCP Tunnel - Receiver Mode");
    println!("==========================");
    println!("Creating iroh endpoint...");

    let endpoint = create_receiver_endpoint(&relay_urls, relay_only).await?;

    let conn = connect_to_sender(&endpoint, sender_id, &relay_urls, relay_only, TCP_ALPN).await?;

    println!("Connected to sender!");
    print_connection_type(&endpoint, conn.remote_id());

    let conn = Arc::new(conn);

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    println!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };

        println!("New local connection from {}", peer_addr);

        let conn_clone = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_receiver_connection(conn_clone, tcp_stream, peer_addr).await {
                eprintln!("TCP tunnel error for {}: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_tcp_receiver_connection(
    conn: Arc<iroh::endpoint::Connection>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
) -> Result<()> {
    let (send_stream, recv_stream) = conn.open_bi().await.context("Failed to open QUIC stream")?;

    println!("-> Opened tunnel for {}", peer_addr);

    bridge_streams(recv_stream, send_stream, tcp_stream).await?;

    println!("<- Connection from {} closed", peer_addr);
    Ok(())
}

/// Bridge a QUIC stream bidirectionally with a TCP stream
async fn bridge_streams(
    mut quic_recv: iroh::endpoint::RecvStream,
    mut quic_send: iroh::endpoint::SendStream,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let quic_to_tcp = async { copy_stream(&mut quic_recv, &mut tcp_write).await };
    let tcp_to_quic = async { copy_stream(&mut tcp_read, &mut quic_send).await };

    tokio::select! {
        result = quic_to_tcp => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    eprintln!("QUIC->TCP error: {}", e);
                }
            }
        }
        result = tcp_to_quic => {
            if let Err(e) = result {
                if !e.to_string().contains("reset") {
                    eprintln!("TCP->QUIC error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Copy data from reader to writer
async fn copy_stream<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(reader, writer)
        .await
        .context("Stream copy failed")?;
    Ok(())
}

// ============================================================================
// Secret Key Commands
// ============================================================================

/// Generate a new secret key file (base64 encoded) and output the EndpointId to stdout
fn generate_secret_command(output: PathBuf, force: bool) -> Result<()> {
    let secret = SecretKey::generate(&mut rand::rng());
    let secret_base64 = BASE64.encode(secret.to_bytes());
    let endpoint_id = secret_to_endpoint_id(&secret);

    if output.to_str() == Some("-") {
        println!("{}", secret_base64);
        eprintln!("EndpointId: {}", endpoint_id);
    } else {
        if output.exists() && !force {
            anyhow::bail!(
                "File already exists: {}. Use --force to overwrite.",
                output.display()
            );
        }

        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
        }
        std::fs::write(&output, &secret_base64).context("Failed to write secret key file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&output)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&output, perms)?;
        }

        eprintln!("Secret key saved to: {}", output.display());
        println!("{}", endpoint_id);
    }

    Ok(())
}

/// Show the EndpointId for an existing secret key file
fn show_id_command(secret_file: PathBuf) -> Result<()> {
    let secret = load_secret(&secret_file)?;
    let endpoint_id = secret_to_endpoint_id(&secret);
    println!("{}", endpoint_id);
    Ok(())
}
