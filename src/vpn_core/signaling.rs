//! VPN signaling protocol for tunnel establishment over plain UDP.
//!
//! This module defines the handshake messages exchanged between VPN client and
//! server to establish IP-over-UDP tunnels, plus the data-channel message
//! framing. Clients identify via a random `device_id` (so a client keeps its
//! assigned VPN IP across reconnects / source-port changes), and the server
//! responds with assigned IP addresses, route metadata, and capabilities.
//!
//! Each UDP datagram carries exactly one message; there is no transport-level
//! authentication or encryption here (the external tunnel owns that).

use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::offload::{VirtioNetHdr, VIRTIO_NET_HDR_LEN};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// VPN protocol version.
pub const VPN_PROTOCOL_VERSION: u16 = 4;

/// Bit flag indicating support for GSO metadata on data-channel packets.
const CAPABILITIES_GSO_BIT: u8 = 1 << 0;

/// VPN handshake request from client to server.
///
/// Sent as a single UDP datagram to initiate VPN setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHandshake {
    /// Protocol version.
    pub version: u16,
    /// Client's unique device ID (randomly generated per session).
    ///
    /// The server keys IP-pool allocation by this id, so a reconnecting client
    /// (which may arrive from a new UDP source port) keeps its assigned IP.
    pub device_id: u64,
}

impl VpnHandshake {
    /// Create a new handshake request.
    pub fn new(device_id: u64) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            device_id,
        }
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
    /// MTU the client must use for its TUN device.
    pub mtu: u16,
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
        mtu: u16,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled,
            mtu,
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
    #[allow(clippy::too_many_arguments)]
    pub fn accepted_dual_stack(
        assigned_ip: Ipv4Addr,
        network: Ipv4Net,
        server_ip: Ipv4Addr,
        assigned_ip6: Ipv6Addr,
        network6: Ipv6Net,
        server_ip6: Ipv6Addr,
        server_gso_enabled: bool,
        mtu: u16,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled,
            mtu,
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
        mtu: u16,
    ) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: true,
            server_gso_enabled,
            mtu,
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
    ///
    /// MTU is a placeholder; clients ignore it when `accepted == false`.
    pub fn rejected(reason: impl Into<String>, server_gso_enabled: bool) -> Self {
        Self {
            version: VPN_PROTOCOL_VERSION,
            accepted: false,
            server_gso_enabled,
            mtu: crate::vpn_core::file_config::DEFAULT_VPN_MTU,
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

    /// Parse capability flags from a variable-length payload.
    ///
    /// Unknown trailing bytes are silently ignored for forward compatibility.
    /// An empty payload yields the default (all capabilities off).
    pub fn decode_payload(payload: &[u8]) -> Self {
        let flags = payload.first().copied().unwrap_or(0);
        Self {
            gso_enabled: (flags & CAPABILITIES_GSO_BIT) != 0,
        }
    }
}

/// Message types for the VPN data channel (one message per UDP datagram).
///
/// Datagram layout by type:
/// - IP packets: `[0x00] [offload_len: 1] [offload: 0|10] [ip_packet]`
/// - heartbeat ping/pong: `[0x01]` / `[0x02]` (no payload)
/// - capabilities: `[0x03] [payload_len: 1] [payload]`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMessageType {
    /// IP packet datagram.
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

/// Static byte slices for heartbeat datagrams (avoids per-send allocation).
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

/// Build a capabilities datagram.
///
/// Wire format: `[type: 0x03] [payload_len: 1 byte] [payload: payload_len bytes]`
#[inline]
pub fn encode_capabilities_datagram(caps: CapabilitiesMessage) -> [u8; 3] {
    [
        DataMessageType::Capabilities.as_byte(),
        1, // payload length
        caps.encode_payload(),
    ]
}

/// Parse a v2 IP packet datagram body (everything after the leading type byte).
///
/// Body layout: `[offload_len: 1] [offload: 0|10] [ip_packet]`. Returns the
/// optional offload metadata and a slice referencing the IP packet within
/// `body`.
#[inline]
pub fn parse_ip_packet_v2(body: &[u8]) -> VpnResult<(Option<VirtioNetHdr>, &[u8])> {
    if body.is_empty() {
        return Err(VpnError::Signaling("Empty IP datagram body".to_string()));
    }

    let offload_len = usize::from(body[0]);
    if offload_len != 0 && offload_len != VIRTIO_NET_HDR_LEN {
        return Err(VpnError::Signaling(format!(
            "Invalid offload metadata length {} (expected 0 or {})",
            offload_len, VIRTIO_NET_HDR_LEN
        )));
    }

    let offload_end = 1 + offload_len;
    if body.len() <= offload_end {
        return Err(VpnError::Signaling(format!(
            "IP datagram body too short: {} bytes",
            body.len()
        )));
    }

    let ip_version = body[offload_end] >> 4;
    let ip_payload_len = body.len() - offload_end;
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
            VirtioNetHdr::from_bytes(&body[1..offload_end])
                .map_err(|e| VpnError::Signaling(format!("Invalid offload metadata: {}", e)))?,
        )
    };

    Ok((offload, &body[offload_end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let handshake = VpnHandshake::new(12345);
        let encoded = handshake.encode().expect("encode handshake");
        let decoded = VpnHandshake::decode(&encoded).expect("decode handshake");
        assert_eq!(decoded.version, VPN_PROTOCOL_VERSION);
        assert_eq!(decoded.device_id, 12345);
    }

    #[test]
    fn test_handshake_rejects_unsupported_version() {
        let raw = serde_json::to_vec(&VpnHandshake {
            version: 1,
            device_id: 7,
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
            1420,
        );
        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");
        assert!(decoded.accepted);
        assert!(decoded.server_gso_enabled);
        assert_eq!(decoded.mtu, 1420);
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
            1440,
        );

        let encoded = response.encode().expect("encode response");
        let decoded = VpnHandshakeResponse::decode(&encoded).expect("decode response");

        assert!(decoded.accepted);
        assert!(!decoded.server_gso_enabled);
        assert_eq!(decoded.mtu, 1440);
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

        let response = VpnHandshakeResponse::accepted_ipv6_only(
            assigned_ip6,
            network6,
            server_ip6,
            true,
            1440,
        );

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
            mtu: 1440,
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
    fn test_response_rejects_old_protocol_version() {
        let mut response = VpnHandshakeResponse::rejected("nope", false);
        response.version = 2;
        let raw = serde_json::to_vec(&response).expect("serialize response");
        let err = VpnHandshakeResponse::decode(&raw).expect_err("v2 response should be rejected");
        assert!(err
            .to_string()
            .contains("Unsupported handshake response protocol version"));
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
    fn test_encode_capabilities_datagram() {
        let dgram = encode_capabilities_datagram(CapabilitiesMessage { gso_enabled: true });
        assert_eq!(dgram[0], DataMessageType::Capabilities.as_byte());
        assert_eq!(dgram[1], 1); // payload length
        assert_eq!(dgram[2], CAPABILITIES_GSO_BIT);

        let caps = CapabilitiesMessage::decode_payload(&dgram[2..]);
        assert!(caps.gso_enabled);
    }

    #[test]
    fn test_decode_capabilities_empty_payload() {
        let caps = CapabilitiesMessage::decode_payload(&[]);
        assert!(!caps.gso_enabled);
    }

    #[test]
    fn test_decode_capabilities_extra_bytes_ignored() {
        let caps = CapabilitiesMessage::decode_payload(&[CAPABILITIES_GSO_BIT, 0xff, 0xab]);
        assert!(caps.gso_enabled);
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
        assert!(err.to_string().contains("IP datagram body too short"));
    }
}
