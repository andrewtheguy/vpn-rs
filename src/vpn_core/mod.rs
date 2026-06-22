//! Single-purpose IP-over-UDP VPN core for vpn-rs.
//!
//! This module provides VPN functionality using:
//! - **tun**: Cross-platform TUN device creation and async I/O
//! - plain **UDP datagrams to a localhost endpoint**: the VPN talks to a local
//!   tunnel process which provides the encrypted cross-network transport and
//!   authentication. The VPN itself only moves framed IP packets between the
//!   TUN device and a loopback UDP socket.
//!
//! # Direct IP over UDP
//!
//! Raw IP packets from the TUN device are framed (one datagram per message) and
//! sent over a plain UDP socket bound to loopback. The server is hard-locked to
//! `127.0.0.1`/`::1`; an external tunnel forwards traffic to it.
//!
//! # Platform Support
//!
//! This module supports Linux, macOS, and Windows.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        vpn-core                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  TUN Device ◄──► UDP datagrams (loopback) ◄──► local tunnel │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("vpn-core only supports Linux, macOS, and Windows");

pub mod buffer;
pub mod client;
pub mod config;
pub mod datagram;
pub mod device;
pub mod error;
pub mod file_config;
pub mod lock;
pub mod offload;
pub mod server;
pub mod signaling;
pub mod udp;

// Re-exports for convenience
pub use client::VpnClient;
pub use server::VpnServer;
