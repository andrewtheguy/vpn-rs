//! Iroh-based networking components.
//!
//! This module provides:
//! - `endpoint`: Iroh endpoint creation and connection helpers
//! - `tunnel`: Iroh-based tunnel implementations (iroh and iroh-manual modes)

pub mod endpoint;
pub mod tunnel;

// Re-export commonly used items
pub use tunnel::{
    run_iroh_manual_tcp_receiver, run_iroh_manual_tcp_sender, run_iroh_manual_udp_receiver,
    run_iroh_manual_udp_sender, run_multi_source_receiver, run_multi_source_sender,
};
