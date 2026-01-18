//! IP-over-QUIC VPN mode with ICE/Nostr transport.
//!
//! This crate provides VPN functionality using:
//! - **str0m**: ICE candidate gathering and connectivity
//! - **quinn**: QUIC transport with TLS 1.3
//! - **nostr-sdk**: Decentralized signaling via Nostr relays
//!
//! # Comparison with tunnel-vpn (iroh mode)
//!
//! | Feature | tunnel-vpn (iroh) | tunnel-vpn-ice (nostr) |
//! |---------|-------------------|------------------------|
//! | Transport | iroh QUIC | quinn QUIC over ICE |
//! | Signaling | Automatic (Pkarr/DNS) | Nostr relays |
//! | NAT Traversal | Relay fallback | STUN only |
//! | Identity | Ed25519 EndpointId | Nostr npub/nsec |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      tunnel-vpn-ice                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TUN Device ◄──► QUIC Stream (quinn) ◄──► ICE ◄──► Peer    │
//! │                         ▲                                    │
//! │                         │                                    │
//! │                  Nostr Signaling                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("tunnel-vpn-ice only supports Linux, macOS, and Windows");

pub mod client;
pub mod config;
pub mod error;
pub mod server;

// Re-exports for convenience
pub use client::VpnIceClient;
pub use config::{VpnIceClientConfig, VpnIceServerConfig};
pub use error::{VpnIceError, VpnIceResult};
pub use server::VpnIceServer;
