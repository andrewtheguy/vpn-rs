//! DCUtR-style signaling module for coordinated NAT hole punching.
//!
//! This module provides:
//! - JSON-RPC 2.0 protocol types for signaling
//! - Length-prefixed message framing
//! - Signaling server implementation with RTT-based timing coordination
//!
//! # Protocol
//!
//! Messages are framed with a 4-byte big-endian length prefix followed by JSON-RPC 2.0 content.
//!
//! ## Methods
//!
//! - `register` - Register client with server
//! - `ping` - RTT measurement (client sends timestamp, server echoes with its timestamp)
//! - `connect_request` - Request coordinated hole punch with target peer
//! - `connect_result` - Report hole punch result
//!
//! ## Notifications (server → client)
//!
//! - `sync_connect` - Coordinated hole punch timing with peer addresses and start time

pub mod client;
pub mod framing;
pub mod protocol;
pub mod server;

// Re-export commonly used types
pub use client::DCUtRSignaling;
pub use framing::{read_message, write_message};
pub use protocol::{
    ConnectRequestParams, ConnectRequestResult, ConnectResultParams, JsonRpcError,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PingParams, PingResult, RegisterParams,
    RegisterResult, SyncConnectParams, JSONRPC_VERSION,
};
pub use server::{run_signaling_server, SignalingServer};
