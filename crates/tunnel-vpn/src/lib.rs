//! WireGuard-based VPN mode for tunnel-rs.
//!
//! This crate provides full VPN functionality using:
//! - **boringtun**: Cloudflare's userspace WireGuard implementation for encryption
//! - **tun**: Cross-platform TUN device creation and async I/O
//! - **iroh**: Peer discovery, signaling, and NAT traversal
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

#[cfg(unix)]
pub mod client;
pub mod config;
pub mod device;
pub mod error;
pub mod keys;
#[cfg(unix)]
pub mod lock;
pub mod packet;
#[cfg(unix)]
pub mod server;
pub mod signaling;
pub mod tunnel;

// Re-exports for convenience
#[cfg(unix)]
pub use client::{VpnClient, VpnClientBuilder};
pub use config::VpnConfig;
pub use error::{VpnError, VpnResult};
pub use keys::WgKeyPair;
#[cfg(unix)]
pub use lock::VpnLock;
#[cfg(unix)]
pub use server::{VpnServer, VpnServerBuilder};
pub use signaling::{VpnHandshake, VpnHandshakeResponse};
