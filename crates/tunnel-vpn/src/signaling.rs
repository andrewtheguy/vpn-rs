//! VPN signaling protocol for WireGuard key exchange over iroh.
//!
//! This module defines the handshake messages exchanged between VPN
//! client and server to establish WireGuard tunnels.

use crate::error::{VpnError, VpnResult};
use crate::keys::WgPublicKey;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

/// VPN protocol version.
pub const VPN_PROTOCOL_VERSION: u16 = 1;

/// ALPN identifier for VPN mode.
pub const VPN_ALPN: &[u8] = b"tunnel-vpn/1";

/// VPN handshake request from client to server.
///
/// Sent over the iroh QUIC connection to initiate VPN setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshake {
    /// Protocol version.
    pub version: u16,
    /// Client's WireGuard public key.
    pub wg_public_key: WgPublicKey,
    /// Client's preferred UDP port for WireGuard (0 = any).
    pub wg_port: u16,
    /// Authentication token (optional, for token-based auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

impl VpnHandshake {
    /// Create a new handshake request.
    pub fn new(wg_public_key: WgPublicKey) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            wg_public_key,
            wg_port: 0,
            auth_token: None,
        }
    }

    /// Set the WireGuard port preference.
    pub fn with_port(mut self, port: u16) -> Self {
        self.wg_port = port;
        self
    }

    /// Set the authentication token.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Encode to bytes for transmission.
    pub fn encode(&self) -> VpnResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| VpnError::Signaling(format!("Failed to encode handshake: {}", e)))
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> VpnResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode handshake: {}", e)))
    }
}

/// VPN handshake response from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshakeResponse {
    /// Protocol version.
    pub version: u16,
    /// Whether the handshake was accepted.
    pub accepted: bool,
    /// Server's WireGuard public key (if accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_public_key: Option<WgPublicKey>,
    /// Server's WireGuard endpoint (UDP address for WG traffic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_endpoint: Option<SocketAddr>,
    /// Assigned VPN IP address for the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<Ipv4Addr>,
    /// VPN network CIDR (e.g., 10.0.0.0/24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Ipv4Net>,
    /// Server's VPN IP (gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<Ipv4Addr>,
    /// Rejection reason (if not accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

impl VpnHandshakeResponse {
    /// Create an accepted response.
    pub fn accepted(
        wg_public_key: WgPublicKey,
        wg_endpoint: SocketAddr,
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            wg_public_key: Some(wg_public_key),
            wg_endpoint: Some(wg_endpoint),
            assigned_ip: Some(assigned_ip),
            network: Some(network),
            server_ip: Some(server_ip),
            reject_reason: None,
        }
    }

    /// Create a rejected response.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: false,
            wg_public_key: None,
            wg_endpoint: None,
            assigned_ip: None,
            network: None,
            server_ip: None,
            reject_reason: Some(reason.into()),
        }
    }

    /// Encode to bytes for transmission.
    pub fn encode(&self) -> VpnResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| VpnError::Signaling(format!("Failed to encode response: {}", e)))
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> VpnResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode response: {}", e)))
    }
}

/// Helper to write a length-prefixed message.
pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> VpnResult<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| VpnError::Signaling(format!("Message too large: {} bytes", data.len())))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Helper to read a length-prefixed message.
pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> VpnResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > max_size {
        return Err(VpnError::Signaling(format!(
            "Message too large: {} > {}",
            len, max_size
        )));
    }

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

/// Maximum handshake message size (16 KB).
pub const MAX_HANDSHAKE_SIZE: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let key = WgPublicKey([1u8; 32]);
        let handshake = VpnHandshake::new(key.clone())
            .with_port(51820)
            .with_auth_token("test-token");

        let encoded = handshake.encode().unwrap();
        let decoded = VpnHandshake::decode(&encoded).unwrap();

        assert_eq!(decoded.version, VPN_PROTOCOL_VERSION);
        assert_eq!(decoded.wg_public_key, key);
        assert_eq!(decoded.wg_port, 51820);
        assert_eq!(decoded.auth_token, Some("test-token".to_string()));
    }

    #[test]
    fn test_response_accepted_roundtrip() {
        let key = WgPublicKey([2u8; 32]);
        let response = VpnHandshakeResponse::accepted(
            key.clone(),
            "192.168.1.1:51820".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.0/24".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        );

        let encoded = response.encode().unwrap();
        let decoded = VpnHandshakeResponse::decode(&encoded).unwrap();

        assert!(decoded.accepted);
        assert_eq!(decoded.wg_public_key, Some(key));
        assert_eq!(decoded.assigned_ip, Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_response_rejected_roundtrip() {
        let response = VpnHandshakeResponse::rejected("Server full");

        let encoded = response.encode().unwrap();
        let decoded = VpnHandshakeResponse::decode(&encoded).unwrap();

        assert!(!decoded.accepted);
        assert_eq!(decoded.reject_reason, Some("Server full".to_string()));
    }
}
