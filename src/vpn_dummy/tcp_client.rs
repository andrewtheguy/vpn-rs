//! Dummy plain-TCP VPN client (benchmark transport).
//!
//! Connects to a [`run_dummy_server`](super::run_dummy_server) over plain TCP,
//! performs the length-prefixed handshake, then runs the shared [`run_tunnel`]
//! pipeline over the TCP socket.

use std::net::SocketAddr;

use bytes::BytesMut;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::vpn_core::device::{TunConfig, TunDevice};
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::signaling::{
    frame_capabilities_message, read_message, write_message, CapabilitiesMessage, VpnHandshake,
    VpnHandshakeResponse, MAX_HANDSHAKE_SIZE,
};
use crate::vpn_core::tunnel::run_tunnel;

/// Connect to a dummy TCP server, handshake, and run the VPN pipeline over a
/// plain TCP connection. `mtu_override` forces the TUN MTU; when `None` the
/// server-dictated MTU is used.
pub async fn run_dummy_client(server: SocketAddr, mtu_override: Option<u16>) -> VpnResult<()> {
    log::info!("Dummy TCP client connecting to {}", server);
    let stream = TcpStream::connect(server).await?;
    // Disable Nagle so per-batch latency does not skew the benchmark.
    stream.set_nodelay(true)?;
    let (mut read_half, mut write_half) = stream.into_split();

    // Handshake: random device id, no auth (the dummy server ignores both).
    let device_id: u64 = rand::rng().random();
    let handshake = VpnHandshake::new(device_id, None);
    write_message(&mut write_half, &handshake.encode()?).await?;

    let resp_data = read_message(&mut read_half, MAX_HANDSHAKE_SIZE).await?;
    let response = VpnHandshakeResponse::decode(&resp_data)?;
    if !response.accepted {
        let reason = response
            .reject_reason
            .unwrap_or_else(|| "unknown".to_string());
        return Err(VpnError::AuthenticationFailed(reason));
    }

    // Dummy mode is IPv4-only.
    let (assigned_ip, network, server_ip) =
        match (response.assigned_ip, response.network, response.server_ip) {
            (Some(ip), Some(net), Some(gw)) => (ip, net, gw),
            _ => {
                return Err(VpnError::Signaling(
                    "dummy server did not assign an IPv4 address".into(),
                ));
            }
        };
    let mtu = mtu_override.unwrap_or(response.mtu);

    let tun_config = TunConfig::new(assigned_ip, network.netmask(), server_ip)
        .with_mtu(mtu)
        .with_gso(response.server_gso_enabled);
    let tun = TunDevice::create(tun_config)?;
    log::info!(
        "Dummy tunnel established: TUN {} ip {} gateway {} mtu {} (server GSO {})",
        tun.name(),
        assigned_ip,
        server_ip,
        mtu,
        response.server_gso_enabled
    );

    // Capabilities is the first data-stream message. Advertise GSO: inbound
    // offload metadata can be materialized in software even without local TUN
    // offload.
    let mut caps_buf = BytesMut::with_capacity(3);
    frame_capabilities_message(&mut caps_buf, CapabilitiesMessage { gso_enabled: true });
    write_half
        .write_all(&caps_buf)
        .await
        .map_err(|e| VpnError::Signaling(format!("failed to send capabilities: {}", e)))?;

    run_tunnel(tun, write_half, read_half, response.server_gso_enabled).await
}
