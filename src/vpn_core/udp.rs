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

/// Default kernel socket receive buffer size (`SO_RCVBUF`), applied
/// unconditionally so users get burst tolerance without any configuration.
///
/// This is the *socket-wide* queue depth (distinct from [`RECV_BUFFER_SIZE`],
/// the per-datagram read buffer). A few MB lets the kernel absorb a multi-Gbit
/// burst that briefly outpaces the userspace receiver instead of silently
/// dropping datagrams (which surface as inner-TCP retransmits).
pub const DEFAULT_SOCKET_RECV_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Default kernel socket send buffer size (`SO_SNDBUF`); see
/// [`DEFAULT_SOCKET_RECV_BUFFER_SIZE`].
pub const DEFAULT_SOCKET_SEND_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Apply large kernel socket buffers (`SO_RCVBUF` / `SO_SNDBUF`) to `socket`.
///
/// Best-effort: a failure to set or read back a buffer is logged and otherwise
/// ignored (the socket keeps the kernel default). Linux doubles the requested
/// size internally and caps it at `net.core.rmem_max` / `net.core.wmem_max`, so
/// we read the value back and warn when the applied size lands well below the
/// request — the fix is to raise those sysctls (out of scope here).
fn set_socket_buffers(socket: &UdpSocket, recv_buffer_size: usize, send_buffer_size: usize) {
    let sock = socket2::SockRef::from(socket);

    match sock.set_recv_buffer_size(recv_buffer_size) {
        Ok(()) => match sock.recv_buffer_size() {
            Ok(applied) => {
                log::info!("SO_RCVBUF requested {recv_buffer_size}, applied {applied}");
                // Linux reports the doubled value, so `applied >= requested`
                // whenever the request is honored; below it means a cap hit.
                if applied < recv_buffer_size {
                    log::warn!(
                        "SO_RCVBUF applied {applied} far below requested {recv_buffer_size}; \
                         raise net.core.rmem_max to allow larger receive buffers"
                    );
                }
            }
            Err(e) => log::debug!("could not read back SO_RCVBUF: {e}"),
        },
        Err(e) => log::warn!("failed to set SO_RCVBUF to {recv_buffer_size}: {e}"),
    }

    match sock.set_send_buffer_size(send_buffer_size) {
        Ok(()) => match sock.send_buffer_size() {
            Ok(applied) => {
                log::info!("SO_SNDBUF requested {send_buffer_size}, applied {applied}");
                if applied < send_buffer_size {
                    log::warn!(
                        "SO_SNDBUF applied {applied} far below requested {send_buffer_size}; \
                         raise net.core.wmem_max to allow larger send buffers"
                    );
                }
            }
            Err(e) => log::debug!("could not read back SO_SNDBUF: {e}"),
        },
        Err(e) => log::warn!("failed to set SO_SNDBUF to {send_buffer_size}: {e}"),
    }
}

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
    recv_buffer_size: usize,
    send_buffer_size: usize,
) -> VpnResult<Arc<UdpSocket>> {
    if !allow_non_loopback {
        ensure_loopback(listen)?;
    }
    let socket = UdpSocket::bind(listen).await?;
    // Coalesce inbound packets into fewer recvmsg calls (best-effort, Linux).
    enable_udp_gro(&socket);
    // Enlarge the kernel socket queues so bursts are not silently dropped.
    set_socket_buffers(&socket, recv_buffer_size, send_buffer_size);
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
    recv_buffer_size: usize,
    send_buffer_size: usize,
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
    // Enlarge the kernel socket queues so bursts are not silently dropped.
    set_socket_buffers(&socket, recv_buffer_size, send_buffer_size);
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
        let err = bind_server_socket(
            "0.0.0.0:0".parse().unwrap(),
            false,
            DEFAULT_SOCKET_RECV_BUFFER_SIZE,
            DEFAULT_SOCKET_SEND_BUFFER_SIZE,
        )
        .await
        .expect_err("non-loopback bind must fail");
        assert!(err.to_string().contains("not loopback"));
    }

    #[tokio::test]
    async fn test_bind_server_socket_allows_non_loopback_in_test_mode() {
        // 127.0.0.1 is loopback, so to prove the check is skipped we bind a
        // non-loopback unspecified address with allow_non_loopback = true.
        let socket = bind_server_socket(
            "0.0.0.0:0".parse().unwrap(),
            true,
            DEFAULT_SOCKET_RECV_BUFFER_SIZE,
            DEFAULT_SOCKET_SEND_BUFFER_SIZE,
        )
        .await
        .expect("non-loopback bind must succeed in test mode");
        assert!(!socket.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn test_bind_and_connect_loopback_roundtrip() {
        let server = bind_server_socket(
            "127.0.0.1:0".parse().unwrap(),
            false,
            DEFAULT_SOCKET_RECV_BUFFER_SIZE,
            DEFAULT_SOCKET_SEND_BUFFER_SIZE,
        )
        .await
        .expect("bind server");
        let server_addr = server.local_addr().unwrap();

        let client = connect_client_socket(
            server_addr,
            false,
            DEFAULT_SOCKET_RECV_BUFFER_SIZE,
            DEFAULT_SOCKET_SEND_BUFFER_SIZE,
        )
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

    #[tokio::test]
    async fn test_set_socket_buffers_applies_over_loopback() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let sock = socket2::SockRef::from(&socket);

        // Capture the kernel defaults before applying our larger request, so the
        // assertions detect a no-op set rather than just the read-back path.
        let default_recv = sock.recv_buffer_size().expect("read default SO_RCVBUF");
        let default_send = sock.send_buffer_size().expect("read default SO_SNDBUF");

        // 256 KiB exceeds the default buffer (so a no-op would be caught) yet is
        // small enough that the applied value — `2 * min(request, rmem_max)` on
        // Linux — stays >= the request on any host with rmem_max >= 128 KiB (the
        // Linux default is ~208 KiB).
        let requested = 256 * 1024;
        set_socket_buffers(&socket, requested, requested);

        let applied_recv = sock.recv_buffer_size().expect("read SO_RCVBUF");
        let applied_send = sock.send_buffer_size().expect("read SO_SNDBUF");
        assert!(
            applied_recv >= requested,
            "SO_RCVBUF should grow to >= {requested} (default {default_recv}, got {applied_recv})"
        );
        assert!(
            applied_send >= requested,
            "SO_SNDBUF should grow to >= {requested} (default {default_send}, got {applied_send})"
        );
    }
}
