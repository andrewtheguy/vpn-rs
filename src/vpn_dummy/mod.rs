//! Plain-TCP benchmark transport ("dummy tunnel").
//!
//! This module reuses the *entire* VPN packet pipeline — the TUN device,
//! framing, GSO/GRO offload, and the shared [`run_tunnel`] hot loop — but
//! replaces iroh's encrypted QUIC connection with a single plain TCP socket.
//! There is no encryption, authentication, relay, or NAT traversal: it is a
//! deliberately dumb transport whose only purpose is to A/B benchmark the VPN
//! pipeline against the iroh transport. If `dummy-client`/`dummy-server`
//! throughput is much higher than the iroh `client`/`server`, the bottleneck is
//! iroh (QUIC/TLS/relay); if it is similar, the bottleneck is the packet
//! pipeline itself.
//!
//! Scope is intentionally minimal: IPv4-only, a single connected client at a
//! time, and static IP assignment (server takes the first host of the network,
//! the client the second). Both ends run the same [`run_tunnel`] loop, so the
//! dummy server is simply the mirror image of the dummy client.
//!
//! [`run_tunnel`]: crate::vpn_core::client::run_tunnel

mod tcp_client;
mod tcp_server;

pub use tcp_client::run_dummy_client;
pub use tcp_server::run_dummy_server;
