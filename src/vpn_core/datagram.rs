//! Datagram framing for the plain-UDP VPN transport.
//!
//! Each UDP datagram carries exactly one VPN message, so there is no
//! length-prefix: the datagram boundary *is* the message length. The leading
//! byte is the [`DataMessageType`]; the remainder is type-specific.

use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::offload::{
    materialize_offload_into, CoalescedOutput, VirtioNetHdr, VIRTIO_NET_HDR_LEN,
};
use crate::vpn_core::signaling::DataMessageType;
use bytes::{BufMut, Bytes, BytesMut};

/// Maximum UDP datagram payload we will ever emit (IPv4 UDP payload ceiling).
///
/// A single datagram cannot exceed this, so offload super-frames whose framed
/// size would be larger must be segmented before sending. Also used as the
/// default datagram-size cap; a restrictive tunnel can lower it via config.
pub const MAX_DATAGRAM_PAYLOAD: usize = 65507;

/// Reserve granularity for the framing arena. Frames are appended to a
/// long-lived `BytesMut` and split off as refcounted `Bytes`, so the allocator
/// is only hit once per chunk instead of once per packet.
pub const FRAME_ARENA_CHUNK: usize = 64 * 1024;

/// A classified inbound datagram (a borrowed view into the receive buffer).
#[derive(Debug)]
pub enum Datagram<'a> {
    /// IP packet message body (everything after the type byte): pass to
    /// [`crate::vpn_core::signaling::parse_ip_packet_v2`].
    Ip(&'a [u8]),
    /// Heartbeat ping.
    Ping,
    /// Heartbeat pong.
    Pong,
    /// Capabilities payload (the flag bytes, with the type+len stripped).
    Capabilities(&'a [u8]),
}

/// Append an IP-packet datagram to `buf` (arena-style) and return the number of
/// bytes written.
///
/// Layout: `[type: 0x00] [offload_len: 1] [offload: 0|10 bytes] [ip_packet]`.
/// Unlike the old stream framing there is no 4-byte length prefix — the UDP
/// datagram boundary delimits the message.
#[inline]
pub fn encode_ip_datagram(
    buf: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    ip_packet: &[u8],
) -> VpnResult<usize> {
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
    let total = 1 + 1 + usize::from(offload_len) + ip_packet.len();

    buf.reserve(total);
    buf.put_u8(DataMessageType::IpPacket.as_byte());
    buf.put_u8(offload_len);
    if let Some(hdr) = offload {
        buf.put_slice(&hdr.to_bytes());
    }
    buf.put_slice(ip_packet);
    Ok(total)
}

/// Framed datagram size for an IP packet with the given offload state.
#[inline]
pub fn ip_datagram_len(has_offload: bool, ip_len: usize) -> usize {
    1 + 1 + if has_offload { VIRTIO_NET_HDR_LEN } else { 0 } + ip_len
}

/// Append a datagram to the arena and split it off as a refcounted `Bytes`.
#[inline]
pub fn frame_datagram(
    arena: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
) -> VpnResult<Bytes> {
    let size = ip_datagram_len(offload.is_some(), packet.len());
    if arena.capacity() - arena.len() < size {
        arena.reserve(FRAME_ARENA_CHUNK.max(size));
    }
    let written = encode_ip_datagram(arena, offload, packet)?;
    Ok(arena.split_to(written).freeze())
}

/// Frame an IP packet (and optional offload metadata) into one or more
/// datagrams pushed onto `pending`, segmenting offload super-frames whose framed
/// size would exceed `max_datagram_size` (a single UDP datagram cannot exceed
/// [`MAX_DATAGRAM_PAYLOAD`]).
///
/// `emit_offload` is whether offload metadata may be forwarded as-is (the peer
/// negotiated GSO, or can materialize it); when false, offload frames are always
/// segmented into plain packets.
pub fn build_datagrams(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    emit_offload: bool,
    max_datagram_size: usize,
) -> VpnResult<()> {
    match offload {
        Some(meta)
            if emit_offload && ip_datagram_len(true, packet.len()) <= max_datagram_size =>
        {
            pending.push(frame_datagram(arena, Some(meta), packet)?);
        }
        Some(meta) => {
            // Segment the super-frame so each emitted datagram fits.
            materialize_offload_into(meta, packet, seg_scratch, |seg| {
                let frame = frame_datagram(arena, None, seg).map_err(|e| e.to_string())?;
                pending.push(frame);
                Ok(())
            })
            .map_err(VpnError::Signaling)?;
        }
        None => {
            pending.push(frame_datagram(arena, None, packet)?);
        }
    }
    Ok(())
}

/// Frame software-GRO outputs into datagrams pushed onto `pending`.
pub fn build_gro_datagrams(
    arena: &mut BytesMut,
    seg_scratch: &mut Vec<u8>,
    pending: &mut Vec<Bytes>,
    outputs: &[CoalescedOutput],
    max_datagram_size: usize,
) -> VpnResult<()> {
    for output in outputs {
        match output {
            CoalescedOutput::Coalesced(hdr, packet) => {
                build_datagrams(
                    arena,
                    seg_scratch,
                    pending,
                    Some(hdr),
                    packet,
                    true,
                    max_datagram_size,
                )?;
            }
            CoalescedOutput::Single(packet) => {
                build_datagrams(
                    arena,
                    seg_scratch,
                    pending,
                    None,
                    packet,
                    true,
                    max_datagram_size,
                )?;
            }
        }
    }
    Ok(())
}

/// Classify a received datagram by its leading message-type byte.
#[inline]
pub fn classify(dgram: &[u8]) -> VpnResult<Datagram<'_>> {
    let Some((&type_byte, rest)) = dgram.split_first() else {
        return Err(VpnError::Signaling("Empty datagram".to_string()));
    };
    match DataMessageType::from_byte(type_byte) {
        Some(DataMessageType::IpPacket) => Ok(Datagram::Ip(rest)),
        Some(DataMessageType::HeartbeatPing) => Ok(Datagram::Ping),
        Some(DataMessageType::HeartbeatPong) => Ok(Datagram::Pong),
        Some(DataMessageType::Capabilities) => {
            // Layout after type byte: [payload_len: 1] [payload].
            let payload = match rest.split_first() {
                Some((&len, tail)) => {
                    let end = usize::from(len).min(tail.len());
                    &tail[..end]
                }
                None => &[],
            };
            Ok(Datagram::Capabilities(payload))
        }
        None => Err(VpnError::Signaling(format!(
            "Unknown datagram message type: 0x{:02x}",
            type_byte
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::signaling::{
        encode_capabilities_datagram, parse_ip_packet_v2, CapabilitiesMessage,
    };

    fn minimal_ipv4() -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p
    }

    #[test]
    fn test_ip_datagram_roundtrip_no_offload() {
        let packet = minimal_ipv4();
        let mut buf = BytesMut::new();
        let written = encode_ip_datagram(&mut buf, None, &packet).expect("encode");
        assert_eq!(written, buf.len());
        // No 4-byte length field: byte[1] is the offload_len (0), not a length.
        assert_eq!(buf[0], DataMessageType::IpPacket.as_byte());
        assert_eq!(buf[1], 0);
        assert_eq!(&buf[2..], &packet[..]);

        match classify(&buf).expect("classify") {
            Datagram::Ip(body) => {
                let (offload, ip) = parse_ip_packet_v2(body).expect("parse body");
                assert!(offload.is_none());
                assert_eq!(ip, &packet[..]);
            }
            other => panic!("expected Ip, got {other:?}"),
        }
    }

    #[test]
    fn test_ip_datagram_roundtrip_with_offload() {
        let mut packet = [0u8; 24];
        packet[0] = 0x45;
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
        encode_ip_datagram(&mut buf, Some(&offload), &packet).expect("encode");
        assert_eq!(buf[1], VIRTIO_NET_HDR_LEN as u8);

        match classify(&buf).expect("classify") {
            Datagram::Ip(body) => {
                let (parsed, ip) = parse_ip_packet_v2(body).expect("parse body");
                assert_eq!(parsed, Some(offload));
                assert_eq!(ip, &packet[..]);
            }
            other => panic!("expected Ip, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_heartbeats() {
        assert!(matches!(
            classify(&[DataMessageType::HeartbeatPing.as_byte()]).unwrap(),
            Datagram::Ping
        ));
        assert!(matches!(
            classify(&[DataMessageType::HeartbeatPong.as_byte()]).unwrap(),
            Datagram::Pong
        ));
    }

    #[test]
    fn test_classify_capabilities() {
        let dgram = encode_capabilities_datagram(CapabilitiesMessage { gso_enabled: true });
        match classify(&dgram).expect("classify") {
            Datagram::Capabilities(payload) => {
                assert!(CapabilitiesMessage::decode_payload(payload).gso_enabled);
            }
            other => panic!("expected Capabilities, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_empty_and_unknown() {
        assert!(classify(&[]).is_err());
        assert!(classify(&[0x7f]).is_err());
    }

    #[test]
    fn test_ip_datagram_len_matches_encoding() {
        let packet = minimal_ipv4();
        let mut buf = BytesMut::new();
        let written = encode_ip_datagram(&mut buf, None, &packet).unwrap();
        assert_eq!(written, ip_datagram_len(false, packet.len()));
    }

    /// Build a valid IPv4/TCP packet with `payload_len` bytes of payload.
    fn build_ipv4_tcp_packet(payload_len: usize) -> Vec<u8> {
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 251) as u8).collect();
        let mut tcp = TcpHeader::new(12345, 443, 10_000, 65_535);
        tcp.ack = true;
        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        )
        .expect("valid IPv4 header");
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, &payload).expect("tcp checksum");
        ip.header_checksum = ip.calc_header_checksum();
        let mut packet = Vec::new();
        ip.write(&mut packet).expect("write ip");
        tcp.write(&mut packet).expect("write tcp");
        packet.extend_from_slice(&payload);
        packet
    }

    fn tcp_gso_header() -> VirtioNetHdr {
        VirtioNetHdr {
            flags: 0,
            gso_type: 1, // VIRTIO_NET_HDR_GSO_TCPV4
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        }
    }

    #[test]
    fn test_gso_superframe_forwarded_whole_under_large_cap() {
        let packet = build_ipv4_tcp_packet(3500); // ~3540-byte super-frame
        let offload = tcp_gso_header();
        let (mut arena, mut scratch, mut pending) =
            (BytesMut::new(), Vec::new(), Vec::new());

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            true,
            MAX_DATAGRAM_PAYLOAD,
        )
        .expect("frame");

        assert_eq!(pending.len(), 1, "should forward as one offload datagram");
        assert_eq!(pending[0][0], DataMessageType::IpPacket.as_byte());
        assert_eq!(pending[0][1], VIRTIO_NET_HDR_LEN as u8, "offload metadata present");
    }

    #[test]
    fn test_gso_superframe_segmented_under_small_cap() {
        let packet = build_ipv4_tcp_packet(3500);
        let offload = tcp_gso_header();
        let (mut arena, mut scratch, mut pending) =
            (BytesMut::new(), Vec::new(), Vec::new());
        let cap = 1500;

        build_datagrams(
            &mut arena,
            &mut scratch,
            &mut pending,
            Some(&offload),
            &packet,
            true,
            cap,
        )
        .expect("frame");

        // gso_size 1200 over 3500 bytes -> 3 segments, each within the cap and
        // emitted as a plain (non-offload) datagram.
        assert_eq!(pending.len(), 3);
        for d in &pending {
            assert!(d.len() <= cap, "datagram {} exceeds cap {}", d.len(), cap);
            assert_eq!(d[1], 0, "segmented datagrams carry no offload metadata");
        }
    }
}
