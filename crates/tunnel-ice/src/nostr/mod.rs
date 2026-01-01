//! Nostr mode networking components (ICE + QUIC with Nostr signaling).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn)
//! with Nostr relay-based automated signaling:
//! - `server`: Multi-session server with TCP/UDP support
//! - `client`: TCP and UDP client implementations

mod client;
mod server;

// Re-export public API
pub use client::{run_nostr_tcp_client, run_nostr_udp_client, NostrClientConfig};
pub use server::{run_nostr_server, NostrServerConfig};
