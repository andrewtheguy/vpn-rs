//! Custom mode networking components (ICE + QUIC).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn)
//! with manual stdin/stdout signaling.

pub mod tunnel;

// Re-export commonly used items
pub use tunnel::{
    run_manual_tcp_receiver, run_manual_tcp_sender, run_manual_udp_receiver, run_manual_udp_sender,
};
