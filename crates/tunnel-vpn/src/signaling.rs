//! VPN signaling protocol for WireGuard key exchange over iroh.
//!
//! This module defines the handshake messages exchanged between VPN
//! client and server to establish WireGuard tunnels.

use crate::error::{VpnError, VpnResult};
use crate::keys::WgPublicKey;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

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
            auth_token: None,
        }
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
    /// Assigned VPN IP address for the client (IPv4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<Ipv4Addr>,
    /// VPN network CIDR (e.g., 10.0.0.0/24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Ipv4Net>,
    /// Server's VPN IP (gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<Ipv4Addr>,
    /// Assigned IPv6 VPN address for the client (optional, for dual-stack).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip6: Option<Ipv6Addr>,
    /// IPv6 VPN network CIDR (e.g., fd00::/64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network6: Option<Ipv6Net>,
    /// Server's IPv6 VPN address (gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip6: Option<Ipv6Addr>,
    /// Rejection reason (if not accepted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

impl VpnHandshakeResponse {
    /// Create an accepted response (IPv4 only).
    pub fn accepted(
        wg_public_key: WgPublicKey,
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            wg_public_key: Some(wg_public_key),
            assigned_ip: Some(assigned_ip),
            network: Some(network),
            server_ip: Some(server_ip),
            assigned_ip6: None,
            network6: None,
            server_ip6: None,
            reject_reason: None,
        }
    }

    /// Create an accepted response with dual-stack (IPv4 + IPv6).
    pub fn accepted_dual_stack(
        wg_public_key: WgPublicKey,
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
        assigned_ip6: Ipv6Addr,
        network6: Ipv6Net,
        server_ip6: Ipv6Addr,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            wg_public_key: Some(wg_public_key),
            assigned_ip: Some(assigned_ip),
            network: Some(network),
            server_ip: Some(server_ip),
            assigned_ip6: Some(assigned_ip6),
            network6: Some(network6),
            server_ip6: Some(server_ip6),
            reject_reason: None,
        }
    }

    /// Create a rejected response.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: false,
            wg_public_key: None,
            assigned_ip: None,
            network: None,
            server_ip: None,
            assigned_ip6: None,
            network6: None,
            server_ip6: None,
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

/// Message types for the VPN data channel.
///
/// The data channel uses a simple framing protocol:
/// - First byte: message type
/// - For WireGuard packets: 4-byte big-endian length + packet data
/// - For heartbeat: no additional payload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMessageType {
    /// WireGuard encrypted packet (followed by length-prefixed data).
    WireGuard = 0x00,
    /// Heartbeat ping (client -> server).
    HeartbeatPing = 0x01,
    /// Heartbeat pong (server -> client).
    HeartbeatPong = 0x02,
}

impl DataMessageType {
    /// Convert from byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::WireGuard),
            0x01 => Some(Self::HeartbeatPing),
            0x02 => Some(Self::HeartbeatPong),
            _ => None,
        }
    }

    /// Convert to byte value.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Error returned when converting an invalid byte to `DataMessageType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessageType(pub u8);

impl std::fmt::Display for InvalidMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid message type: 0x{:02x}", self.0)
    }
}

impl std::error::Error for InvalidMessageType {}

impl TryFrom<u8> for DataMessageType {
    type Error = InvalidMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_byte(value).ok_or(InvalidMessageType(value))
    }
}

impl From<DataMessageType> for u8 {
    fn from(value: DataMessageType) -> Self {
        value.as_byte()
    }
}

/// Frame a WireGuard packet for transmission on the data channel.
///
/// Builds a buffer with the format: `[type: 0x00] [length: 4 bytes BE] [data: N bytes]`
///
/// This is the standard framing for WireGuard packets on the multiplexed data stream.
/// The buffer is cleared and filled with the framed packet, then can be passed to `write_all()`.
///
/// # Arguments
/// * `buf` - Reusable buffer to write into (cleared and resized as needed)
/// * `data` - The WireGuard packet payload to frame
///
/// Returns an error if the packet exceeds `u32::MAX` bytes (matching `write_message` behavior).
#[inline]
pub fn frame_wireguard_packet(buf: &mut Vec<u8>, data: &[u8]) -> VpnResult<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| VpnError::Signaling(format!("Packet too large: {} bytes", data.len())))?;
    buf.clear();
    buf.reserve(1 + 4 + data.len());
    buf.push(DataMessageType::WireGuard.as_byte());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let key = WgPublicKey([1u8; 32]);
        let handshake = VpnHandshake::new(key.clone()).with_auth_token("test-token");

        let encoded = handshake.encode().unwrap();
        let decoded = VpnHandshake::decode(&encoded).unwrap();

        assert_eq!(decoded.version, VPN_PROTOCOL_VERSION);
        assert_eq!(decoded.wg_public_key, key);
        assert_eq!(decoded.auth_token, Some("test-token".to_string()));
    }

    #[test]
    fn test_response_accepted_roundtrip() {
        let key = WgPublicKey([2u8; 32]);
        let response = VpnHandshakeResponse::accepted(
            key.clone(),
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
    fn test_response_accepted_dual_stack_roundtrip() {
        let key = WgPublicKey([3u8; 32]);
        let assigned_ip: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let server_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let assigned_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let network6: Ipv6Net = "fd00::/64".parse().unwrap();
        let server_ip6: Ipv6Addr = "fd00::1".parse().unwrap();

        let response = VpnHandshakeResponse::accepted_dual_stack(
            key.clone(),
            assigned_ip,
            network,
            server_ip,
            assigned_ip6,
            network6,
            server_ip6,
        );

        let encoded = response.encode().unwrap();
        let decoded = VpnHandshakeResponse::decode(&encoded).unwrap();

        assert!(decoded.accepted);
        assert_eq!(decoded.wg_public_key, Some(key));
        assert_eq!(decoded.assigned_ip, Some(assigned_ip));
        assert_eq!(decoded.network, Some(network));
        assert_eq!(decoded.server_ip, Some(server_ip));
        assert_eq!(decoded.assigned_ip6, Some(assigned_ip6));
        assert_eq!(decoded.network6, Some(network6));
        assert_eq!(decoded.server_ip6, Some(server_ip6));
        assert_eq!(decoded.reject_reason, None);
    }

    #[test]
    fn test_response_rejected_roundtrip() {
        let response = VpnHandshakeResponse::rejected("Server full");

        let encoded = response.encode().unwrap();
        let decoded = VpnHandshakeResponse::decode(&encoded).unwrap();

        assert!(!decoded.accepted);
        assert_eq!(decoded.reject_reason, Some("Server full".to_string()));
    }

    #[test]
    fn test_data_message_type_roundtrip() {
        // Test all valid message types: byte -> DataMessageType -> byte
        for (byte, expected_type) in [
            (0x00, DataMessageType::WireGuard),
            (0x01, DataMessageType::HeartbeatPing),
            (0x02, DataMessageType::HeartbeatPong),
        ] {
            // from_byte roundtrip
            let msg_type = DataMessageType::from_byte(byte).unwrap();
            assert_eq!(msg_type, expected_type);
            assert_eq!(msg_type.as_byte(), byte);

            // TryFrom/From trait roundtrip
            let msg_type: DataMessageType = byte.try_into().unwrap();
            assert_eq!(msg_type, expected_type);
            let back: u8 = msg_type.into();
            assert_eq!(back, byte);
        }
    }

    #[test]
    fn test_data_message_type_invalid_bytes() {
        // Test that invalid bytes return None from from_byte
        for invalid in [0x03, 0x04, 0x10, 0x80, 0xFF] {
            assert!(
                DataMessageType::from_byte(invalid).is_none(),
                "from_byte(0x{:02x}) should return None",
                invalid
            );
        }
    }

    #[test]
    fn test_data_message_type_try_from_invalid() {
        // Test that TryFrom returns InvalidMessageType error for invalid bytes
        for invalid in [0x03, 0x04, 0x10, 0x80, 0xFF] {
            let result: Result<DataMessageType, _> = invalid.try_into();
            assert!(result.is_err(), "TryFrom(0x{:02x}) should fail", invalid);

            let err = result.unwrap_err();
            assert_eq!(err, InvalidMessageType(invalid));
            assert!(err.to_string().contains(&format!("0x{:02x}", invalid)));
        }
    }

    #[test]
    fn test_frame_wireguard_packet() {
        let payload = b"hello wireguard";
        let mut buf = Vec::new();
        frame_wireguard_packet(&mut buf, payload).unwrap();

        // Total length: 1 (type) + 4 (length) + payload
        assert_eq!(buf.len(), 1 + 4 + payload.len());

        // First byte is message type
        assert_eq!(buf[0], DataMessageType::WireGuard.as_byte());

        // Next 4 bytes are big-endian length
        let len_bytes = (payload.len() as u32).to_be_bytes();
        assert_eq!(&buf[1..5], &len_bytes);

        // Trailing bytes are the payload
        assert_eq!(&buf[5..], payload);
    }
}
