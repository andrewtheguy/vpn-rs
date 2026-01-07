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

pub mod config;
pub mod device;
pub mod error;
pub mod keys;
pub mod packet;
pub mod tunnel;

// Re-exports for convenience
pub use config::VpnConfig;
pub use error::{VpnError, VpnResult};
pub use keys::WgKeyPair;
