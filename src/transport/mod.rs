//! Transport layer for ICE+QUIC connectivity.
//!
//! This module provides the low-level transport components used by custom and nostr modes:
//! - ICE candidate gathering and connection establishment
//! - QUIC endpoint setup with self-signed certificates
//! - STUN/QUIC packet demultiplexing on a single UDP port

pub mod ice;
pub mod mux;
pub mod quic;

// Re-exports available for use (currently accessed directly via submodules)
