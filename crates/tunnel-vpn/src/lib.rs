//! WireGuard-based VPN mode for tunnel-rs.
//!
//! This crate provides full VPN functionality using:
//! - **boringtun**: Cloudflare's userspace WireGuard implementation for encryption
//! - **tun**: Cross-platform TUN device creation and async I/O
//! - **iroh**: Peer discovery, signaling, and NAT traversal
//!
//! # Platform Support
//!
//! This crate only supports Linux and macOS for now.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        tunnel-vpn                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TUN Device ◄──► boringtun Tunn ◄──► UDP Socket ◄──► Peer  │
//! ├─────────────────────────────────────────────────────────────┤
//! │        iroh: WG key exchange + endpoint discovery           │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("tunnel-vpn only supports Linux and macOS");

pub mod client;
pub mod config;
pub mod device;
pub mod error;
pub mod keys;
pub mod lock;
pub mod packet;
pub mod server;
pub mod signaling;
pub mod tunnel;

// Re-exports for convenience
pub use client::{VpnClient, VpnClientBuilder};
pub use config::VpnConfig;
pub use error::{VpnError, VpnResult};
pub use keys::WgKeyPair;
pub use lock::VpnLock;
pub use server::{VpnServer, VpnServerBuilder};
pub use signaling::{VpnHandshake, VpnHandshakeResponse};
