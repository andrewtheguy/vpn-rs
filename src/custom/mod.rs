//! Custom mode networking components (ICE + QUIC).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn)
//! with manual stdin/stdout signaling or DCUtR signaling server.

pub mod dcutr_client;
pub mod dcutr_server;
pub mod tunnel;

// Re-export commonly used items
pub use dcutr_client::{run_dcutr_tcp_client, run_dcutr_udp_client};
pub use dcutr_server::{run_dcutr_tcp_server, run_dcutr_udp_server};
pub use tunnel::{run_manual_client, run_manual_server};
