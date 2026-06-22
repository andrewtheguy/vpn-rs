//! Loopback-only UDP transport setup for the VPN.
//!
//! The VPN never talks to the network directly: an external tunnel process
//! (e.g. tunnel-rs / duopipe) runs on the same host and forwards loopback UDP
//! across the network, providing encryption and authentication. Accordingly the
//! server bind address and the client's connect target are **hard-locked to
//! loopback** (`127.0.0.1` / `::1`) with no override.
//!
//! The sole exception is test mode (`--test-mode`), which threads an
//! `allow_non_loopback` flag through these functions to bind/connect arbitrary
//! interfaces for direct host-to-host testing without a tunnel.

use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::udp_offload::enable_udp_gro;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Receive buffer size for a single datagram.
///
/// Sized to hold a full offload super-frame (max IP packet plus framing), so
/// the kernel never truncates an inbound datagram.
pub const RECV_BUFFER_SIZE: usize = 65535 + 64;

/// Return an error unless `addr` is a loopback address (`127.0.0.0/8` for IPv4,
/// `::1` for IPv6, including IPv4-mapped loopback). This is the security
/// boundary: the VPN must only be reachable through the local tunnel.
pub fn ensure_loopback(addr: SocketAddr) -> VpnResult<()> {
    let is_loopback = match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|m| m.is_loopback())
        }
    };
    if !is_loopback {
        return Err(VpnError::config(format!(
            "address {addr} is not loopback; vpn-rs only binds/connects to 127.0.0.1 or ::1 \
             (the external tunnel forwards loopback traffic across the network)"
        )));
    }
    Ok(())
}

/// Bind the server's UDP socket, enforcing a loopback listen address.
///
/// When `allow_non_loopback` is `true` (test mode) the loopback check is
/// skipped so the server can bind an arbitrary interface.
pub async fn bind_server_socket(
    listen: SocketAddr,
    allow_non_loopback: bool,
) -> VpnResult<Arc<UdpSocket>> {
    if !allow_non_loopback {
        ensure_loopback(listen)?;
    }
    let socket = UdpSocket::bind(listen).await?;
    // Coalesce inbound packets into fewer recvmsg calls (best-effort, Linux).
    enable_udp_gro(&socket);
    Ok(Arc::new(socket))
}

/// Create the client's connected UDP socket, enforcing a loopback target.
///
/// Binds an ephemeral local socket on the same address family as `server`, then
/// `connect`s it so subsequent `send`/`recv` go to/from the server only.
///
/// When `allow_non_loopback` is `true` (test mode) the loopback check is skipped
/// and the local socket is bound to the unspecified address of the matching
/// family (`0.0.0.0` / `::`) so it can reach a remote server.
pub async fn connect_client_socket(
    server: SocketAddr,
    allow_non_loopback: bool,
) -> VpnResult<UdpSocket> {
    if !allow_non_loopback {
        ensure_loopback(server)?;
    }
    let bind: SocketAddr = match (server, allow_non_loopback) {
        (SocketAddr::V4(_), false) => "127.0.0.1:0".parse().expect("valid loopback addr"),
        (SocketAddr::V6(_), false) => "[::1]:0".parse().expect("valid loopback addr"),
        (SocketAddr::V4(_), true) => "0.0.0.0:0".parse().expect("valid unspecified addr"),
        (SocketAddr::V6(_), true) => "[::]:0".parse().expect("valid unspecified addr"),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    // Coalesce inbound packets into fewer recvmsg calls (best-effort, Linux).
    enable_udp_gro(&socket);
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_loopback_accepts_loopback() {
        for addr in [
            "127.0.0.1:5555",
            "127.5.5.5:0",
            "[::1]:5555",
            "[::ffff:127.0.0.1]:5555",
        ] {
            assert!(
                ensure_loopback(addr.parse().unwrap()).is_ok(),
                "{addr} should be accepted"
            );
        }
    }

    #[test]
    fn test_ensure_loopback_rejects_non_loopback() {
        for addr in [
            "0.0.0.0:5555",
            "192.0.2.1:5555",
            "10.0.0.1:5555",
            "[::]:5555",
            "[2001:db8::1]:5555",
        ] {
            let err = ensure_loopback(addr.parse().unwrap())
                .expect_err(&format!("{addr} should be rejected"));
            assert!(err.to_string().contains("not loopback"));
        }
    }

    #[tokio::test]
    async fn test_bind_server_socket_rejects_non_loopback() {
        let err = bind_server_socket("0.0.0.0:0".parse().unwrap(), false)
            .await
            .expect_err("non-loopback bind must fail");
        assert!(err.to_string().contains("not loopback"));
    }

    #[tokio::test]
    async fn test_bind_server_socket_allows_non_loopback_in_test_mode() {
        // 127.0.0.1 is loopback, so to prove the check is skipped we bind a
        // non-loopback unspecified address with allow_non_loopback = true.
        let socket = bind_server_socket("0.0.0.0:0".parse().unwrap(), true)
            .await
            .expect("non-loopback bind must succeed in test mode");
        assert!(!socket.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn test_bind_and_connect_loopback_roundtrip() {
        let server = bind_server_socket("127.0.0.1:0".parse().unwrap(), false)
            .await
            .expect("bind server");
        let server_addr = server.local_addr().unwrap();

        let client = connect_client_socket(server_addr, false)
            .await
            .expect("connect");
        client.send(b"hello").await.expect("send");

        let mut buf = [0u8; 16];
        let (n, peer) = server.recv_from(&mut buf).await.expect("recv");
        assert_eq!(&buf[..n], b"hello");

        server.send_to(b"world", peer).await.expect("reply");
        let n = client.recv(&mut buf).await.expect("recv reply");
        assert_eq!(&buf[..n], b"world");
    }
}
