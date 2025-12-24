//! Nostr mode networking components (ICE + QUIC with Nostr signaling).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn)
//! with Nostr relay-based automated signaling:
//! - `sender`: Multi-session sender with TCP/UDP support
//! - `receiver`: TCP and UDP receiver implementations

mod receiver;
mod sender;

// Re-export public API
pub use receiver::{run_nostr_tcp_receiver, run_nostr_udp_receiver};
pub use sender::run_nostr_sender;
