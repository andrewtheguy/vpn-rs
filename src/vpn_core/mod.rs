//! IP-over-QUIC VPN mode for vpn-rs.
//!
//! This crate provides full VPN functionality using:
//! - **tun**: Cross-platform TUN device creation and async I/O
//! - **iroh**: Peer discovery, signaling, NAT traversal, and TLS 1.3/QUIC encryption
//!
//! # Direct IP over QUIC
//!
//! This crate implements a direct VPN where raw IP packets from the TUN device
//! are framed and sent directly over iroh's encrypted QUIC streams (TLS 1.3).
//!
//! # Platform Support
//!
//! This crate supports Linux, macOS, and Windows.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        vpn-core                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TUN Device ◄──► QUIC Stream (iroh) ◄──► Peer              │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("vpn-core only supports Linux, macOS, and Windows");

pub mod buffer;
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
pub use server::{VpnServer, VpnServerStats, VpnServerStatsSnapshot};
pub use signaling::{VpnHandshake, VpnHandshakeResponse};
