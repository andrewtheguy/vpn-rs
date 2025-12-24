//! Iroh-based networking components.
//!
//! This module provides:
//! - `endpoint`: Iroh endpoint creation and connection helpers
//! - `multi_source`: Multi-source mode with Iroh relays (receiver requests source)
//! - `manual`: Manual signaling mode with direct STUN/local addresses (no relay)
//! - `helpers`: Shared stream and connection helpers (internal)

pub mod endpoint;
mod helpers;
mod manual;
mod multi_source;

// Re-export public API
pub use manual::{run_iroh_manual_receiver, run_iroh_manual_sender};
pub use multi_source::{run_multi_source_receiver, run_multi_source_sender};
