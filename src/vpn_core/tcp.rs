//! Loopback-locked TCP transport setup for the VPN.
//!
//! The TCP transport carries each client over a single TCP connection. Like the
//! UDP path, it is **hard-locked to loopback** (`127.0.0.0/8`, `::1`, or
//! IPv4-mapped loopback) in normal mode — an external tunnel forwards loopback
//! traffic across the network and provides encryption + authentication. Test
//! mode (`--test-mode`) threads an `allow_non_loopback` flag through to
//! bind/connect arbitrary interfaces for direct host-to-host testing.

use crate::vpn_core::error::VpnResult;
use crate::vpn_core::udp::ensure_loopback;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

/// Apply large kernel socket buffers (`SO_RCVBUF` / `SO_SNDBUF`) to a TCP
/// stream and disable Nagle (`TCP_NODELAY`).
///
/// Best-effort: failures are logged and otherwise ignored. See
/// [`crate::vpn_core::udp`] for why the receive buffer is the one that matters
/// (it absorbs bursty inbound traffic) and why the kernel caps the request at
/// `net.core.rmem_max` / `net.core.wmem_max`.
pub fn prepare_stream(stream: &TcpStream, recv_buffer_size: usize, send_buffer_size: usize) {
    if let Err(e) = stream.set_nodelay(true) {
        log::warn!("failed to set TCP_NODELAY: {e}");
    }

    let sock = socket2::SockRef::from(stream);

    match sock.set_recv_buffer_size(recv_buffer_size) {
        Ok(()) => match sock.recv_buffer_size() {
            Ok(applied) => {
                log::info!("SO_RCVBUF requested {recv_buffer_size}, applied {applied}");
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
                        "SO_SNDBUF applied {applied} below requested {send_buffer_size} \
                         (capped by net.core.wmem_max)"
                    );
                }
            }
            Err(e) => log::debug!("could not read back SO_SNDBUF: {e}"),
        },
        Err(e) => log::warn!("failed to set SO_SNDBUF to {send_buffer_size}: {e}"),
    }
}

/// Bind the server's TCP listener, enforcing a loopback listen address.
///
/// When `allow_non_loopback` is `true` (test mode) the loopback check is
/// skipped so the server can listen on an arbitrary interface.
pub async fn bind_tcp_listener(
    listen: SocketAddr,
    allow_non_loopback: bool,
) -> VpnResult<TcpListener> {
    if !allow_non_loopback {
        ensure_loopback(listen)?;
    }
    let listener = TcpListener::bind(listen).await?;
    Ok(listener)
}

/// Connect the client's TCP stream, enforcing a loopback target.
///
/// When `allow_non_loopback` is `true` (test mode) the loopback check is
/// skipped so the client can reach a remote server. Applies `TCP_NODELAY` and
/// the requested socket buffers.
pub async fn connect_tcp_stream(
    server: SocketAddr,
    allow_non_loopback: bool,
    recv_buffer_size: usize,
    send_buffer_size: usize,
) -> VpnResult<TcpStream> {
    if !allow_non_loopback {
        ensure_loopback(server)?;
    }
    let stream = TcpStream::connect(server).await?;
    prepare_stream(&stream, recv_buffer_size, send_buffer_size);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_tcp_listener_rejects_non_loopback() {
        let err = bind_tcp_listener("0.0.0.0:0".parse().unwrap(), false)
            .await
            .expect_err("non-loopback bind must fail");
        assert!(err.to_string().contains("not loopback"));
    }

    #[tokio::test]
    async fn test_bind_tcp_listener_allows_non_loopback_in_test_mode() {
        let listener = bind_tcp_listener("0.0.0.0:0".parse().unwrap(), true)
            .await
            .expect("non-loopback bind must succeed in test mode");
        assert!(!listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn test_connect_rejects_non_loopback() {
        let err = connect_tcp_stream("192.0.2.1:5555".parse().unwrap(), false, 65536, 65536)
            .await
            .expect_err("non-loopback connect must fail");
        assert!(err.to_string().contains("not loopback"));
    }

    #[tokio::test]
    async fn test_bind_and_connect_loopback_roundtrip() {
        let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap(), false)
            .await
            .expect("bind server");
        let server_addr = listener.local_addr().unwrap();

        let accept = tokio::spawn(async move { listener.accept().await });
        let client = connect_tcp_stream(server_addr, false, 256 * 1024, 256 * 1024)
            .await
            .expect("connect");
        let (server_stream, _) = accept.await.unwrap().expect("accept");

        prepare_stream(&server_stream, 256 * 1024, 256 * 1024);
        drop(client);
    }
}
