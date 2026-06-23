//! Single-purpose IP-over-TCP/UDP VPN core for vpn-rs.
//!
//! This module provides VPN functionality using:
//! - **tun**: Cross-platform TUN device creation and async I/O
//! - a plain **loopback socket to a localhost endpoint**: the VPN talks to a
//!   local tunnel process which provides the encrypted cross-network transport
//!   and authentication. The VPN itself only moves framed IP packets between the
//!   TUN device and a loopback socket.
//!
//! # Transport
//!
//! Raw IP packets from the TUN device are framed and carried over either a
//! **TCP** connection (default; length-prefixed frames via
//! [`tcp_server`] / [`tunnel`]) or **UDP** datagrams (one message per datagram
//! via [`server`] / [`client`]). In normal mode the server is hard-locked to
//! `127.0.0.0/8`, `::1`, or IPv4-mapped loopback; an external tunnel forwards
//! traffic to it. Test mode explicitly relaxes this for direct host-to-host
//! testing.
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
//! │  TUN Device ◄──► TCP/UDP (loopback) ◄──► local tunnel       │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("vpn-core only supports Linux, macOS, and Windows");

pub mod buffer;
pub mod chunked_write;
pub mod client;
pub mod config;
pub mod datagram;
pub mod device;
pub mod error;
pub mod file_config;
pub mod frame_reader;
pub mod ip_pool;
pub mod lock;
pub mod offload;
pub mod packet;
pub mod server;
pub mod signaling;
pub mod tcp;
pub mod tcp_server;
pub mod tunnel;
pub mod udp;

// Re-exports for convenience
pub use client::VpnClient;
pub use server::VpnServer;
pub use tcp_server::TcpVpnServer;
