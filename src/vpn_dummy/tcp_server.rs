//! Dummy plain-TCP VPN server (benchmark transport).
//!
//! Accepts one client at a time over plain TCP, performs the same
//! length-prefixed handshake the iroh server uses (auth skipped), assigns a
//! static IPv4, then runs the shared [`run_tunnel`] pipeline. Because
//! [`run_tunnel`] takes no `self` and only shovels packets between the TUN
//! device and the transport, the dummy server is the exact mirror of the dummy
//! client — the same production hot path on both ends.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ipnet::Ipv4Net;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

use crate::vpn_core::client::run_tunnel;
use crate::vpn_core::device::{TunConfig, TunDevice};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::signaling::{
    read_message, write_message, CapabilitiesMessage, DataMessageType, VpnHandshake,
    VpnHandshakeResponse, WireTransport, MAX_CAPABILITIES_PAYLOAD, MAX_HANDSHAKE_SIZE,
};

/// Bind a dummy TCP listener and serve one client at a time. The server takes
/// the first usable host of `network` as its own IP and assigns the second to
/// the client.
pub async fn run_dummy_server(listen: SocketAddr, network: Ipv4Net, mtu: u16) -> VpnResult<()> {
    let mut hosts = network.hosts();
    let server_ip = hosts
        .next()
        .ok_or_else(|| VpnError::config(format!("network {} has no usable hosts", network)))?;
    let client_ip = hosts
        .next()
        .ok_or_else(|| VpnError::config(format!("network {} too small for a client", network)))?;

    let listener = TcpListener::bind(listen).await?;
    log::info!(
        "Dummy TCP server listening on {} (network {}, server {}, client {})",
        listen,
        network,
        server_ip,
        client_ip
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        log::info!("Dummy client connected from {}", peer);
        if let Err(e) = handle_connection(stream, network, server_ip, client_ip, mtu).await {
            log::error!("Dummy connection from {} ended: {}", peer, e);
        }
        log::info!("Dummy client {} disconnected; waiting for next client", peer);
    }
}

async fn handle_connection(
    stream: TcpStream,
    network: Ipv4Net,
    server_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    mtu: u16,
) -> VpnResult<()> {
    stream.set_nodelay(true)?;
    let (mut read_half, mut write_half) = stream.into_split();

    // Read the client handshake; device id and any auth token are ignored.
    let hs_data = read_message(&mut read_half, MAX_HANDSHAKE_SIZE).await?;
    let handshake = VpnHandshake::decode(&hs_data)?;
    log::debug!("Dummy handshake from device {:016x}", handshake.device_id);

    // Create the server's own TUN (its address is the gateway). Mirrors the
    // iroh server's setup_tun (no explicit with_gso; default offload behavior).
    let tun_config = TunConfig::new(server_ip, network.netmask(), server_ip).with_mtu(mtu);
    let tun = TunDevice::create(tun_config)?;
    let server_gso = tun.offload_status().enabled;
    log::info!(
        "Dummy server TUN {} up (ip {} mtu {} GSO {})",
        tun.name(),
        server_ip,
        mtu,
        server_gso
    );

    // Accept the static client IP (IPv4-only).
    let response = VpnHandshakeResponse::accepted(
        client_ip,
        network,
        server_ip,
        server_gso,
        WireTransport::default(),
        mtu,
    );
    write_message(&mut write_half, &response.encode()?).await?;

    // The client's capabilities message is the first data-stream message.
    let client_caps = read_client_capabilities(&mut read_half).await?;
    log::info!(
        "Dummy client capabilities: GSO {} (server GSO {})",
        client_caps.gso_enabled,
        server_gso
    );

    // Run the shared pipeline. The peer's advertised GSO is the client's.
    run_tunnel(
        tun,
        write_half,
        read_half,
        client_caps.gso_enabled,
        None,
        Arc::new(HashSet::new()),
    )
    .await
}

/// Read and decode the client's first data-stream message, which must be a
/// capabilities message: `[type=0x03][len:u8][payload]`.
async fn read_client_capabilities<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> VpnResult<CapabilitiesMessage> {
    let mut type_byte = [0u8; 1];
    reader.read_exact(&mut type_byte).await?;
    if DataMessageType::from_byte(type_byte[0]) != Some(DataMessageType::Capabilities) {
        return Err(VpnError::Signaling(format!(
            "expected capabilities as first data message, got type 0x{:02x}",
            type_byte[0]
        )));
    }

    let mut len_buf = [0u8; 1];
    reader.read_exact(&mut len_buf).await?;
    let len = usize::from(len_buf[0]);
    if len > MAX_CAPABILITIES_PAYLOAD {
        return Err(VpnError::Signaling(format!(
            "capabilities payload too large: {}",
            len
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(CapabilitiesMessage::decode_payload(&payload))
}
