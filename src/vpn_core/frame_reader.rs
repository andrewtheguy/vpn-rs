//! Buffered frame reader for the VPN data channel.
//!
//! Replaces per-frame `read_exact` sequences (type byte, length, payload) with
//! a single accumulator fed by large `RecvStream::read_chunk` pulls. Complete
//! frames are parsed synchronously from the buffer, so the QUIC stream is only
//! awaited when more data is genuinely needed — typically once per many frames
//! instead of three times per frame.

use bytes::{Buf, Bytes, BytesMut};
use iroh::endpoint::RecvStream;

use crate::vpn_core::signaling::DataMessageType;

/// Max bytes pulled per `read_chunk` call. Bounds a single buffered read so
/// the accumulator stays small; the QUIC receive window still governs total
/// in-flight data.
const READ_CHUNK_MAX: usize = 256 * 1024;

/// One parsed data-channel message.
#[derive(Debug)]
pub enum FrameEvent {
    /// IP packet v2 frame payload (the bytes after type + frame length:
    /// offload_len byte + optional virtio header + IP packet). Zero-copy view
    /// into the accumulator; run `parse_ip_packet_v2` on it.
    IpFrame(Bytes),
    HeartbeatPing,
    HeartbeatPong,
    /// Capabilities message. Capabilities are exchanged at stream setup
    /// (before the frame reader takes over), so in steady state this only
    /// signals that the payload was drained to keep the stream aligned.
    Capabilities,
}

/// Frame-level read errors. Callers map these to their existing disconnect
/// semantics.
#[derive(Debug)]
pub enum FrameError {
    /// Unknown message type byte — stream framing is unrecoverable.
    UnknownType(u8),
    /// Declared IP frame length exceeds the caller's maximum.
    FrameTooLarge(usize),
    /// Underlying QUIC read error or truncated frame at end of stream.
    Read(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType(b) => write!(f, "unknown message type: 0x{:02x}", b),
            Self::FrameTooLarge(len) => write!(f, "IP frame too large: {}", len),
            Self::Read(e) => write!(f, "QUIC read error: {}", e),
        }
    }
}

/// Buffered reader that owns the data-channel `RecvStream`.
pub struct FrameReader {
    stream: RecvStream,
    buf: BytesMut,
    max_ip_frame: usize,
}

impl FrameReader {
    pub fn new(stream: RecvStream, max_ip_frame: usize) -> Self {
        Self {
            stream,
            buf: BytesMut::new(),
            max_ip_frame,
        }
    }

    /// Pull the next complete frame, awaiting the stream only when the
    /// accumulator lacks one. Returns `Ok(None)` on clean end of stream.
    pub async fn next_frame(&mut self) -> Result<Option<FrameEvent>, FrameError> {
        loop {
            if let Some(event) = parse_one(&mut self.buf, self.max_ip_frame)? {
                return Ok(Some(event));
            }
            match self.stream.read_chunk(READ_CHUNK_MAX).await {
                Ok(Some(chunk)) => self.buf.extend_from_slice(&chunk),
                Ok(None) => {
                    return if self.buf.is_empty() {
                        Ok(None)
                    } else {
                        Err(FrameError::Read(format!(
                            "stream ended mid-frame ({} buffered bytes)",
                            self.buf.len()
                        )))
                    };
                }
                Err(e) => return Err(FrameError::Read(e.to_string())),
            }
        }
    }
}

/// Parse one complete frame from the front of `buf`, consuming its bytes.
/// Returns `Ok(None)` when the buffer does not yet hold a complete frame.
fn parse_one(buf: &mut BytesMut, max_ip_frame: usize) -> Result<Option<FrameEvent>, FrameError> {
    let Some(&type_byte) = buf.first() else {
        return Ok(None);
    };
    match DataMessageType::from_byte(type_byte) {
        None => Err(FrameError::UnknownType(type_byte)),
        Some(DataMessageType::HeartbeatPing) => {
            buf.advance(1);
            Ok(Some(FrameEvent::HeartbeatPing))
        }
        Some(DataMessageType::HeartbeatPong) => {
            buf.advance(1);
            Ok(Some(FrameEvent::HeartbeatPong))
        }
        Some(DataMessageType::Capabilities) => {
            // [type] [payload_len: 1 byte] [payload] — payload is drained to
            // keep the stream aligned; it is only meaningful at stream setup.
            if buf.len() < 2 {
                return Ok(None);
            }
            let payload_len = usize::from(buf[1]);
            if buf.len() < 2 + payload_len {
                return Ok(None);
            }
            buf.advance(2 + payload_len);
            Ok(Some(FrameEvent::Capabilities))
        }
        Some(DataMessageType::IpPacket) => {
            // [type] [frame_len: 4 bytes BE] [frame payload]
            if buf.len() < 5 {
                return Ok(None);
            }
            let frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if frame_len > max_ip_frame {
                return Err(FrameError::FrameTooLarge(frame_len));
            }
            if buf.len() < 5 + frame_len {
                return Ok(None);
            }
            buf.advance(5);
            let frame = buf.split_to(frame_len).freeze();
            Ok(Some(FrameEvent::IpFrame(frame)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::offload::VirtioNetHdr;
    use crate::vpn_core::signaling::{
        append_ip_packet_v2, frame_capabilities_message, parse_ip_packet_v2, CapabilitiesMessage,
        HEARTBEAT_PING_BYTE, HEARTBEAT_PONG_BYTE,
    };

    const TEST_MAX_FRAME: usize = 65536 + 64;

    /// Minimal IPv4-looking packet that passes `parse_ip_packet_v2` length
    /// validation (>= 20 bytes, version nibble 4).
    fn ipv4_packet(len: usize, fill: u8) -> Vec<u8> {
        assert!(len >= 20);
        let mut packet = vec![fill; len];
        packet[0] = 0x45;
        packet
    }

    fn framed_ip_packet(offload: Option<&VirtioNetHdr>, packet: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        append_ip_packet_v2(&mut buf, offload, packet).expect("frame packet");
        buf
    }

    fn expect_ip_frame(event: Option<FrameEvent>) -> Bytes {
        match event {
            Some(FrameEvent::IpFrame(frame)) => frame,
            other => panic!("expected IpFrame, got {:?}", other),
        }
    }

    #[test]
    fn parses_single_ip_frame() {
        let expected = ipv4_packet(24, 1);
        let mut buf = framed_ip_packet(None, &expected);
        let frame = expect_ip_frame(parse_one(&mut buf, TEST_MAX_FRAME).unwrap());
        let (offload, packet) = parse_ip_packet_v2(&frame).expect("parse v2");
        assert!(offload.is_none());
        assert_eq!(packet, &expected[..]);
        assert!(buf.is_empty());
        // Empty buffer: need more data.
        assert!(parse_one(&mut buf, TEST_MAX_FRAME).unwrap().is_none());
    }

    #[test]
    fn parses_frame_with_offload_metadata() {
        let hdr = VirtioNetHdr {
            flags: 1,
            gso_type: 1,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };
        let expected = ipv4_packet(40, 9);
        let mut buf = framed_ip_packet(Some(&hdr), &expected);
        let frame = expect_ip_frame(parse_one(&mut buf, TEST_MAX_FRAME).unwrap());
        let (offload, packet) = parse_ip_packet_v2(&frame).expect("parse v2");
        assert_eq!(offload, Some(hdr));
        assert_eq!(packet, &expected[..]);
    }

    #[test]
    fn parses_partial_then_complete_frame() {
        let expected = ipv4_packet(100, 0x45);
        let full = framed_ip_packet(None, &expected);

        let mut buf = BytesMut::new();
        // Feed in three pieces: mid-header, mid-payload, rest.
        for (start, end) in [(0usize, 3usize), (3, 40), (40, full.len())] {
            buf.extend_from_slice(&full[start..end]);
            if end < full.len() {
                assert!(
                    parse_one(&mut buf, TEST_MAX_FRAME).unwrap().is_none(),
                    "incomplete frame must not parse (fed {} bytes)",
                    end
                );
            }
        }
        let frame = expect_ip_frame(parse_one(&mut buf, TEST_MAX_FRAME).unwrap());
        let (_, packet) = parse_ip_packet_v2(&frame).expect("parse v2");
        assert_eq!(packet, &expected[..]);
    }

    #[test]
    fn parses_multiple_frames_and_interleaved_messages() {
        let first = ipv4_packet(20, 1);
        let second = ipv4_packet(20, 2);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&framed_ip_packet(None, &first));
        buf.extend_from_slice(HEARTBEAT_PONG_BYTE);
        let mut caps = BytesMut::new();
        frame_capabilities_message(&mut caps, CapabilitiesMessage { gso_enabled: true });
        buf.extend_from_slice(&caps);
        buf.extend_from_slice(HEARTBEAT_PING_BYTE);
        buf.extend_from_slice(&framed_ip_packet(None, &second));

        let frame = expect_ip_frame(parse_one(&mut buf, TEST_MAX_FRAME).unwrap());
        assert_eq!(parse_ip_packet_v2(&frame).unwrap().1, &first[..]);

        assert!(matches!(
            parse_one(&mut buf, TEST_MAX_FRAME).unwrap(),
            Some(FrameEvent::HeartbeatPong)
        ));

        assert!(matches!(
            parse_one(&mut buf, TEST_MAX_FRAME).unwrap(),
            Some(FrameEvent::Capabilities)
        ));

        assert!(matches!(
            parse_one(&mut buf, TEST_MAX_FRAME).unwrap(),
            Some(FrameEvent::HeartbeatPing)
        ));

        let frame = expect_ip_frame(parse_one(&mut buf, TEST_MAX_FRAME).unwrap());
        assert_eq!(parse_ip_packet_v2(&frame).unwrap().1, &second[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_unknown_type() {
        let mut buf = BytesMut::from(&[0xff, 1, 2, 3][..]);
        match parse_one(&mut buf, TEST_MAX_FRAME) {
            Err(FrameError::UnknownType(0xff)) => {}
            other => panic!("expected UnknownType, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[DataMessageType::IpPacket.as_byte()]);
        buf.extend_from_slice(&u32::try_from(TEST_MAX_FRAME + 1).unwrap().to_be_bytes());
        match parse_one(&mut buf, TEST_MAX_FRAME) {
            Err(FrameError::FrameTooLarge(len)) => assert_eq!(len, TEST_MAX_FRAME + 1),
            other => panic!("expected FrameTooLarge, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn capabilities_needs_full_payload() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[DataMessageType::Capabilities.as_byte(), 3, 0xaa]);
        assert!(parse_one(&mut buf, TEST_MAX_FRAME).unwrap().is_none());
        buf.extend_from_slice(&[0xbb, 0xcc]);
        assert!(matches!(
            parse_one(&mut buf, TEST_MAX_FRAME).unwrap(),
            Some(FrameEvent::Capabilities)
        ));
        assert!(buf.is_empty(), "payload must be fully consumed");
    }
}
