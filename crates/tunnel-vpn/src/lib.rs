//! WireGuard-based VPN mode for tunnel-rs.
//!
//! This crate provides full VPN functionality using:
//! - **tun**: Cross-platform TUN device creation and async I/O
//! - **iroh**: Peer discovery, signaling, NAT traversal, and QUIC encryption
//!
//! # Direct IP over QUIC
//!
//! This crate implements a direct VPN where raw IP packets from the TUN device
//! are framed and sent directly over Iroh's encrypted QUIC streams.
//! No additional WireGuard layer is used.
//!
//! # Platform Support
//!
//! This crate only supports Linux and macOS for now.
//!
//! # Architecture
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        tunnel-vpn                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TUN Device ◄──► QUIC Stream (iroh) ◄──► Peer              │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("tunnel-vpn only supports Linux and macOS");

pub mod client;
pub mod config;
pub mod device;
pub mod error;
pub mod lock;
pub mod server;
pub mod signaling;

// Re-exports for convenience
pub use client::{VpnClient, VpnClientBuilder};
pub use config::VpnConfig;
pub use error::{VpnError, VpnResult};
pub use lock::VpnLock;
pub use server::VpnServer;
pub use signaling::{VpnHandshake, VpnHandshakeResponse};
