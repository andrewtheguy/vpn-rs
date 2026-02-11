//! VPN signaling protocol for tunnel establishment over iroh.
//!
//! This module defines the handshake messages exchanged between VPN
//! client and server to establish IP-over-QUIC tunnels. Clients identify
//! via a random `device_id` (allowing multiple sessions per iroh endpoint),
//! and the server responds with assigned IP addresses, route metadata, and
//! connection capabilities.

use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::offload::{VirtioNetHdr, VIRTIO_NET_HDR_LEN};
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// VPN protocol version.
pub const VPN_PROTOCOL_VERSION: u16 = 2;

/// ALPN identifier for VPN mode.
pub const VPN_ALPN: &[u8] = b"vpn-rs/2";

/// Bit flag indicating support for GSO metadata on data-stream packets.
const CAPABILITIES_GSO_BIT: u8 = 1 << 0;

/// VPN handshake request from client to server.
///
/// Sent over the iroh QUIC connection to initiate VPN setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshake {
    /// Protocol version.
    pub version: u16,
    /// Client's unique device ID (randomly generated per session).
    pub device_id: u64,
    /// Authentication token (optional, for token-based auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

impl VpnHandshake {
    /// Create a new handshake request.
    pub fn new(device_id: u64) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            device_id,
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
        let handshake: Self = serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode handshake: {}", e)))?;

        if handshake.version != VPN_PROTOCOL_VERSION {
            return Err(VpnError::Signaling(format!(
                "Unsupported handshake protocol version: {} (expected {})",
                handshake.version, VPN_PROTOCOL_VERSION
            )));
        }

        Ok(handshake)
    }
}

/// VPN handshake response from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshakeResponse {
    /// Protocol version.
    pub version: u16,
    /// Whether the handshake was accepted.
    pub accepted: bool,
    /// Server-local TUN GSO/offload status.
    pub server_gso_enabled: bool,
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
    /// Validate handshake response invariants.
    ///
    /// Accepted responses must include at least one assigned address family.
    pub fn is_valid(&self) -> bool {
        !(self.accepted && self.assigned_ip.is_none() && self.assigned_ip6.is_none())
    }

    /// Create an accepted response (IPv4 only).
    pub fn accepted(
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
        server_gso_enabled: bool,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled,
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
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
        assigned_ip6: Ipv6Addr,
        network6: Ipv6Net,
        server_ip6: Ipv6Addr,
        server_gso_enabled: bool,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled,
            assigned_ip: Some(assigned_ip),
            network: Some(network),
            server_ip: Some(server_ip),
            assigned_ip6: Some(assigned_ip6),
            network6: Some(network6),
            server_ip6: Some(server_ip6),
            reject_reason: None,
        }
    }

    /// Create an accepted response with IPv6 only (no IPv4).
    ///
    /// Use this for IPv6-only VPN networks where no IPv4 address is allocated.
    pub fn accepted_ipv6_only(
        assigned_ip6: Ipv6Addr,
        network6: Ipv6Net,
        server_ip6: Ipv6Addr,
        server_gso_enabled: bool,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled,
            assigned_ip: None,
            network: None,
            server_ip: None,
            assigned_ip6: Some(assigned_ip6),
            network6: Some(network6),
            server_ip6: Some(server_ip6),
            reject_reason: None,
        }
    }

    /// Create a rejected response.
    pub fn rejected(reason: impl Into<String>, server_gso_enabled: bool) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: false,
            server_gso_enabled,
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
        if !self.is_valid() {
            return Err(VpnError::Signaling(
                "Invalid handshake response: accepted response must include assigned_ip or assigned_ip6".into(),
            ));
        }
        serde_json::to_vec(self)
            .map_err(|e| VpnError::Signaling(format!("Failed to encode response: {}", e)))
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> VpnResult<Self> {
        let response: Self = serde_json::from_slice(data)
            .map_err(|e| VpnError::Signaling(format!("Failed to decode response: {}", e)))?;

        if response.version != VPN_PROTOCOL_VERSION {
            return Err(VpnError::Signaling(format!(
                "Unsupported handshake response protocol version: {} (expected {})",
                response.version, VPN_PROTOCOL_VERSION
            )));
        }

        if !response.is_valid() {
            return Err(VpnError::Signaling(
                "Invalid handshake response: accepted response must include assigned_ip or assigned_ip6".into(),
            ));
        }
        Ok(response)
    }
}

/// Data-channel capabilities exchanged after handshake and before IP packet flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitiesMessage {
    /// Whether this endpoint can send/receive GSO metadata on data packets.
    pub gso_enabled: bool,
}

impl CapabilitiesMessage {
    /// Convert capability flags to the compact byte payload.
    pub fn encode_payload(self) -> u8 {
        let mut payload = 0u8;
        if self.gso_enabled {
            payload |= CAPABILITIES_GSO_BIT;
        }
        payload
    }

    /// Parse capability flags from the compact byte payload.
    pub fn decode_payload(payload: u8) -> Self {
        Self {
            gso_enabled: (payload & CAPABILITIES_GSO_BIT) != 0,
        }
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
/// - For IP packets: 4-byte big-endian frame length + frame payload
/// - For capabilities: one-byte payload (flags)
/// - For heartbeat: no additional payload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMessageType {
    /// IP packet v2 frame.
    IpPacket = 0x00,
    /// Heartbeat ping (client -> server).
    HeartbeatPing = 0x01,
    /// Heartbeat pong (server -> client).
    HeartbeatPong = 0x02,
    /// Capability negotiation message.
    Capabilities = 0x03,
}

impl DataMessageType {
    /// Convert from byte value.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::IpPacket),
            0x01 => Some(Self::HeartbeatPing),
            0x02 => Some(Self::HeartbeatPong),
            0x03 => Some(Self::Capabilities),
            _ => None,
        }
    }

    /// Convert to byte value.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Static byte slices for heartbeat messages (avoids per-send allocation).
pub const HEARTBEAT_PING_BYTE: &[u8] = &[DataMessageType::HeartbeatPing.as_byte()];
pub const HEARTBEAT_PONG_BYTE: &[u8] = &[DataMessageType::HeartbeatPong.as_byte()];

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

/// Frame a capabilities message for transmission on the data channel.
#[inline]
pub fn frame_capabilities_message(buf: &mut BytesMut, caps: CapabilitiesMessage) {
    buf.clear();
    buf.reserve(2);
    buf.put_u8(DataMessageType::Capabilities.as_byte());
    buf.put_u8(caps.encode_payload());
}

/// Frame an IP packet for transmission on the data channel.
///
/// v2 layout:
/// `[type: 0x00] [frame_len: 4 bytes BE] [offload_len: 1 byte] [offload: N bytes] [ip_packet]`
///
/// `offload_len` is either:
/// - `0` (no offload metadata)
/// - `10` (`virtio_net_hdr` metadata)
#[inline]
pub fn frame_ip_packet_v2(
    buf: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    ip_packet: &[u8],
) -> VpnResult<()> {
    if ip_packet.is_empty() {
        return Err(VpnError::Signaling(
            "Cannot frame empty IP packet".to_string(),
        ));
    }

    const _: () = assert!(
        VIRTIO_NET_HDR_LEN <= u8::MAX as usize,
        "VIRTIO_NET_HDR_LEN must fit in u8"
    );
    let offload_len: u8 = if offload.is_some() {
        VIRTIO_NET_HDR_LEN as u8
    } else {
        0
    };
    let frame_len = 1 + usize::from(offload_len) + ip_packet.len();
    let frame_len_u32 = u32::try_from(frame_len)
        .map_err(|_| VpnError::Signaling(format!("Packet frame too large: {}", frame_len)))?;

    buf.clear();
    buf.reserve(1 + 4 + frame_len);
    buf.put_u8(DataMessageType::IpPacket.as_byte());
    buf.put_slice(&frame_len_u32.to_be_bytes());
    buf.put_u8(offload_len);
    if let Some(hdr) = offload {
        buf.put_slice(&hdr.to_bytes());
    }
    buf.put_slice(ip_packet);
    Ok(())
}

/// Parse a full v2 IP packet message including type and frame length fields.
#[inline]
#[cfg(test)]
pub fn parse_ip_packet_message_v2(message: &[u8]) -> VpnResult<(Option<VirtioNetHdr>, &[u8])> {
    if message.len() < 5 {
        return Err(VpnError::Signaling(format!(
            "IP message too short: {} bytes",
            message.len()
        )));
    }
    if message[0] != DataMessageType::IpPacket.as_byte() {
        return Err(VpnError::Signaling(format!(
            "Unexpected message type 0x{:02x} for IP packet",
            message[0]
        )));
    }

    let frame_len = u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize;
    if message.len() != 5 + frame_len {
        return Err(VpnError::Signaling(format!(
            "Malformed IP frame length: header={}, actual={}",
            frame_len,
            message.len().saturating_sub(5)
        )));
    }

    parse_ip_packet_v2(&message[5..])
}

/// Parse a v2 IP packet frame payload (without leading type and frame_len fields).
#[inline]
pub fn parse_ip_packet_v2(frame_payload: &[u8]) -> VpnResult<(Option<VirtioNetHdr>, &[u8])> {
    if frame_payload.is_empty() {
        return Err(VpnError::Signaling("Empty IP frame payload".to_string()));
    }

    let offload_len = usize::from(frame_payload[0]);
    if offload_len != 0 && offload_len != VIRTIO_NET_HDR_LEN {
        return Err(VpnError::Signaling(format!(
            "Invalid offload metadata length {} (expected 0 or {})",
            offload_len, VIRTIO_NET_HDR_LEN
        )));
    }

    let offload_end = 1 + offload_len;
    if frame_payload.len() <= offload_end {
        return Err(VpnError::Signaling(format!(
            "IP frame payload too short: {} bytes",
            frame_payload.len()
        )));
    }

    let ip_version = frame_payload[offload_end] >> 4;
    let ip_payload_len = frame_payload.len() - offload_end;
    match ip_version {
        4 => {
            if ip_payload_len < 20 {
                return Err(VpnError::Signaling(format!(
                    "IPv4 packet too short: {} bytes (minimum 20)",
                    ip_payload_len
                )));
            }
        }
        6 => {
            if ip_payload_len < 40 {
                return Err(VpnError::Signaling(format!(
                    "IPv6 packet too short: {} bytes (minimum 40)",
                    ip_payload_len
                )));
            }
        }
        _ => {
            return Err(VpnError::Signaling(format!(
                "Unsupported IP version: {}",
                ip_version
            )));
        }
    }

    let offload = if offload_len == 0 {
        None
    } else {
        Some(
            VirtioNetHdr::from_bytes(&frame_payload[1..offload_end])
                .map_err(|e| VpnError::Signaling(format!("Invalid offload metadata: {}", e)))?,
        )
    };

    Ok((offload, &frame_payload[offload_end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let handshake = VpnHandshake::new(12345).with_auth_token("test-token");
        let encoded = handshake.encode().expect("encode handshake");
        let decoded = VpnHandshake::decode(&encoded).expect("decode handshake");
        assert_eq!(decoded.version, VPN_PROTOCOL_VERSION);
        assert_eq!(decoded.device_id, 12345);
        assert_eq!(decoded.auth_token, Some("test-token".to_string()));
    }

    #[test]
    fn test_handshake_rejects_unsupported_version() {
        let raw = serde_json::to_vec(&VpnHandshake {
            version: 1,
            device_id: 7,
            auth_token: None,
        })
        .expect("serialize handshake");

        let err = VpnHandshake::decode(&raw).expect_err("v1 handshake should be rejected");
        assert!(err
            .to_string()
            .contains("Unsupported handshake protocol version"));
    }

    #[test]
    fn test_response_accepted_roundtrip() {
        let response = VpnHandshakeResponse::accepted(
            "10.0.0.2".parse().expect("parse IPv4"),
            "10.0.0.0/24".parse().expect("parse network"),
            "10.0.0.1".parse().expect("parse server ip"),
            true,
        );
        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");
        assert!(decoded.accepted);
        assert!(decoded.server_gso_enabled);
        assert_eq!(
            decoded.assigned_ip,
            Some("10.0.0.2".parse().expect("parse IPv4"))
        );
    }

    #[test]
    fn test_response_accepted_dual_stack_roundtrip() {
        let assigned_ip: Ipv4Addr = "10.0.0.2".parse().expect("parse IPv4");
        let network: Ipv4Net = "10.0.0.0/24".parse().expect("parse network");
        let server_ip: Ipv4Addr = "10.0.0.1".parse().expect("parse server ip");
        let assigned_ip6: Ipv6Addr = "fd00::2".parse().expect("parse IPv6");
        let network6: Ipv6Net = "fd00::/64".parse().expect("parse network6");
        let server_ip6: Ipv6Addr = "fd00::1".parse().expect("parse server ip6");

        let response = VpnHandshakeResponse::accepted_dual_stack(
            assigned_ip,
            network,
            server_ip,
            assigned_ip6,
            network6,
            server_ip6,
            false,
        );

        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");

        assert!(decoded.accepted);
        assert!(!decoded.server_gso_enabled);
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
        let response = VpnHandshakeResponse::rejected("Server full", false);
        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");
        assert!(!decoded.accepted);
        assert!(!decoded.server_gso_enabled);
        assert_eq!(decoded.reject_reason, Some("Server full".to_string()));
    }

    #[test]
    fn test_response_accepted_ipv6_only_roundtrip() {
        let assigned_ip6: Ipv6Addr = "fd00::2".parse().expect("parse IPv6");
        let network6: Ipv6Net = "fd00::/64".parse().expect("parse network6");
        let server_ip6: Ipv6Addr = "fd00::1".parse().expect("parse server ip6");

        let response =
            VpnHandshakeResponse::accepted_ipv6_only(assigned_ip6, network6, server_ip6, true);

        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");

        assert!(decoded.accepted);
        assert!(decoded.server_gso_enabled);
        assert_eq!(decoded.assigned_ip, None);
        assert_eq!(decoded.network, None);
        assert_eq!(decoded.server_ip, None);
        assert_eq!(decoded.assigned_ip6, Some(assigned_ip6));
        assert_eq!(decoded.network6, Some(network6));
        assert_eq!(decoded.server_ip6, Some(server_ip6));
        assert_eq!(decoded.reject_reason, None);
    }

    #[test]
    fn test_response_invalid_when_accepted_without_assigned_ip() {
        let response = VpnHandshakeResponse {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled: false,
            assigned_ip: None,
            network: None,
            server_ip: None,
            assigned_ip6: None,
            network6: None,
            server_ip6: None,
            reject_reason: None,
        };

        assert!(!response.is_valid());
        assert!(response.encode().is_err());

        let raw = serde_json::to_vec(&response).expect("serialize response");
        let decoded = VpnHandshakeResponse::decode(&raw);
        assert!(decoded.is_err());
    }

    #[test]
    fn test_data_message_type_roundtrip() {
        for (byte, expected_type) in [
            (0x00, DataMessageType::IpPacket),
            (0x01, DataMessageType::HeartbeatPing),
            (0x02, DataMessageType::HeartbeatPong),
            (0x03, DataMessageType::Capabilities),
        ] {
            let msg_type = DataMessageType::from_byte(byte).expect("valid message type");
            assert_eq!(msg_type, expected_type);
            assert_eq!(msg_type.as_byte(), byte);

            let msg_type: DataMessageType = byte.try_into().expect("try_from should work");
            assert_eq!(msg_type, expected_type);
            let back: u8 = msg_type.into();
            assert_eq!(back, byte);
        }
    }

    #[test]
    fn test_data_message_type_invalid_bytes() {
        for invalid in [0x04, 0x10, 0x80, 0xff] {
            assert!(
                DataMessageType::from_byte(invalid).is_none(),
                "from_byte(0x{:02x}) should return None",
                invalid
            );
        }
    }

    #[test]
    fn test_data_message_type_try_from_invalid() {
        for invalid in [0x04, 0x10, 0x80, 0xff] {
            let result: Result<DataMessageType, _> = invalid.try_into();
            assert!(result.is_err(), "TryFrom(0x{:02x}) should fail", invalid);

            let err = result.expect_err("invalid type");
            assert_eq!(err, InvalidMessageType(invalid));
            assert!(err.to_string().contains(&format!("0x{:02x}", invalid)));
        }
    }

    #[test]
    fn test_frame_capabilities_message() {
        let mut buf = BytesMut::new();
        frame_capabilities_message(&mut buf, CapabilitiesMessage { gso_enabled: true });

        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], DataMessageType::Capabilities.as_byte());
        assert_eq!(buf[1], CAPABILITIES_GSO_BIT);

        let caps = CapabilitiesMessage::decode_payload(buf[1]);
        assert!(caps.gso_enabled);
    }

    #[test]
    fn test_frame_ip_packet_v2_without_offload() {
        let payload = b"hello ip packet";
        let mut buf = BytesMut::new();
        frame_ip_packet_v2(&mut buf, None, payload).expect("frame packet");

        assert_eq!(buf[0], DataMessageType::IpPacket.as_byte());

        let frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        assert_eq!(frame_len, 1 + payload.len());
        assert_eq!(buf[5], 0);
        assert_eq!(&buf[6..], payload);
    }

    #[test]
    fn test_parse_ip_packet_message_v2_roundtrip_without_offload() {
        // Minimal valid IPv4 header (20 bytes, version=4, IHL=5)
        let mut payload = [0u8; 20];
        payload[0] = 0x45; // version 4, IHL 5
        let mut buf = BytesMut::new();
        frame_ip_packet_v2(&mut buf, None, &payload).expect("frame packet");

        let (offload, parsed_payload) =
            parse_ip_packet_message_v2(&buf).expect("parse full message");
        assert!(offload.is_none());
        assert_eq!(parsed_payload, &payload[..]);
    }

    #[test]
    fn test_frame_and_parse_ip_packet_v2_with_offload() {
        // Minimal valid IPv4 header (20 bytes, version=4, IHL=5) + 4 bytes payload
        let mut payload = [0u8; 24];
        payload[0] = 0x45; // version 4, IHL 5
        let offload = VirtioNetHdr {
            flags: 1,
            gso_type: 1,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let mut buf = BytesMut::new();
        frame_ip_packet_v2(&mut buf, Some(&offload), &payload).expect("frame packet");

        let frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let frame_payload = &buf[5..5 + frame_len];

        let (parsed_offload, parsed_payload) =
            parse_ip_packet_v2(frame_payload).expect("parse v2 frame payload");
        assert_eq!(parsed_offload, Some(offload));
        assert_eq!(parsed_payload, &payload[..]);
    }

    #[test]
    fn test_parse_ip_packet_message_v2_rejects_malformed_frame_len() {
        let payload = b"malformed length payload";
        let mut buf = BytesMut::new();
        frame_ip_packet_v2(&mut buf, None, payload).expect("frame packet");

        // Corrupt the declared frame length to be larger than actual payload.
        let bad_len = (payload.len() as u32) + 9;
        buf[1..5].copy_from_slice(&bad_len.to_be_bytes());

        let err =
            parse_ip_packet_message_v2(&buf).expect_err("mismatched frame length should fail");
        assert!(err.to_string().contains("Malformed IP frame length"));
    }

    #[test]
    fn test_parse_ip_packet_v2_rejects_invalid_offload_len() {
        let payload = [7u8, 1, 2, 3, 4, 5];
        let err = parse_ip_packet_v2(&payload).expect_err("invalid offload length must fail");
        assert!(err.to_string().contains("Invalid offload metadata length"));
    }

    #[test]
    fn test_parse_ip_packet_v2_rejects_empty_ip_payload() {
        let mut payload = vec![VIRTIO_NET_HDR_LEN as u8];
        payload.extend_from_slice(&[0u8; VIRTIO_NET_HDR_LEN]);
        let err = parse_ip_packet_v2(&payload).expect_err("empty payload must fail");
        assert!(err.to_string().contains("IP frame payload too short"));
    }
}
