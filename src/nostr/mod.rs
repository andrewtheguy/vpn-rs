//! Nostr mode networking components (ICE + QUIC with Nostr signaling).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn)
//! with Nostr relay-based automated signaling.

pub mod tunnel;

// Re-export commonly used items
pub use tunnel::{run_nostr_sender, run_nostr_tcp_receiver, run_nostr_udp_receiver};
