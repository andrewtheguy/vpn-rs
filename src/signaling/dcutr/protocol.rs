//! JSON-RPC 2.0 protocol types for DCUtR-style signaling.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// JSON-RPC version string
pub const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC request envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
}

/// JSON-RPC success response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: u64,
}

/// JSON-RPC error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// JSON-RPC notification (no id, no response expected)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

// Standard JSON-RPC error codes
impl JsonRpcError {
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: msg.into(),
            data: None,
        }
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: msg.into(),
            data: None,
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {}", method),
            data: None,
        }
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: msg.into(),
            data: None,
        }
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: msg.into(),
            data: None,
        }
    }

    /// Peer not found (application-specific error)
    pub fn peer_not_found(peer_id: &str) -> Self {
        Self {
            code: -32000,
            message: format!("Peer not found: {}", peer_id),
            data: None,
        }
    }

    /// Already registered (application-specific error)
    pub fn already_registered(client_id: &str) -> Self {
        Self {
            code: -32001,
            message: format!("Client already registered: {}", client_id),
            data: None,
        }
    }
}

// ============================================================================
// Method-specific parameter and result types
// ============================================================================

/// Parameters for "register" method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterParams {
    pub client_id: String,
}

/// Result for "register" method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResult {
    pub success: bool,
}

/// Parameters for "ping" method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingParams {
    pub seq: u32,
    pub timestamp: u64,
}

/// Result for "ping" method (pong)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub seq: u32,
    pub client_ts: u64,
    pub server_ts: u64,
}

/// Parameters for "connect_request" method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequestParams {
    pub target_id: String,
    pub my_addrs: Vec<SocketAddr>,
}

/// Result for "connect_request" method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequestResult {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Parameters for "sync_connect" notification (server → client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConnectParams {
    pub peer_addrs: Vec<SocketAddr>,
    pub start_at_ms: u64,
}

/// Parameters for "connect_result" notification (client → server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResultParams {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

// ============================================================================
// Helper constructors
// ============================================================================

impl JsonRpcRequest {
    pub fn new(method: impl Into<String>, params: Option<serde_json::Value>, id: u64) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
            id: Some(id),
        }
    }
}

impl JsonRpcResponse {
    pub fn success(id: u64, result: impl Serialize) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: Some(serde_json::to_value(result).unwrap()),
            error: None,
            id,
        }
    }

    pub fn error(id: u64, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

impl JsonRpcNotification {
    pub fn new(method: impl Into<String>, params: impl Serialize) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params: Some(serde_json::to_value(params).unwrap()),
        }
    }
}
