//! Dummy plain-TCP VPN transport (benchmark / test baseline).
//!
//! This is the standalone counterpart to the production UDP path: instead of
//! framing IP packets onto a loopback UDP socket for an external tunnel to
//! carry, it connects client and server **directly over a single plain TCP
//! socket** and runs the shared [`run_tunnel`](crate::vpn_core::tunnel::run_tunnel)
//! pipeline over it. It exists to benchmark that pipeline against a baseline
//! "TCP tunnel like an SSH tunnel": one direct connection with end-to-end
//! backpressure and no datagram drop point.
//!
//! It is intentionally minimal: IPv4-only, single client at a time, static IP
//! assignment, **no encryption or authentication** (the handshake's device id /
//! token are ignored). Do not use it as a production transport — it binds a real
//! interface and carries plaintext.

mod tcp_client;
mod tcp_server;

pub use tcp_client::run_dummy_client;
pub use tcp_server::run_dummy_server;
