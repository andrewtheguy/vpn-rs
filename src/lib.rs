//! tunnel-rs library
//!
//! Provides P2P tunneling functionality with multiple signaling modes.
//!
//! # Feature Flags
//!
//! - **`ice`** (enabled by default): Enables ICE/STUN-based NAT traversal and additional
//!   signaling modes. When disabled, only iroh-based tunneling is available.
//!
//! # Modules
//!
//! The following modules require the `ice` feature:
//! - [`custom`] - Custom signaling mode implementation
//! - [`nostr`] - Nostr-based signaling for peer discovery
//! - [`transport`] - ICE transport layer using str0m

pub mod config;
#[cfg(feature = "ice")]
pub mod custom;
pub mod iroh;
#[cfg(feature = "ice")]
pub mod nostr;
pub mod secret;
pub mod signaling;
pub mod socks5_bridge;
#[cfg(feature = "ice")]
pub mod transport;
pub mod tunnel_common;
