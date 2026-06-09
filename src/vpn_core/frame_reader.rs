//! Buffered frame reader for the VPN data channel.
//!
//! Reads protocol headers exactly and fills payload buffers directly from the
//! QUIC stream. Payloads are read into `BytesMut` spare capacity via
//! `ReadBuf::uninit`, avoiding zero-fill before the stream overwrites those
//! bytes.

#[cfg(test)]
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use iroh::endpoint::RecvStream;
use std::future::poll_fn;
use std::mem::MaybeUninit;
use std::pin::Pin;
use tokio::io::{AsyncRead, ReadBuf};

use crate::vpn_core::signaling::{DataMessageType, MAX_CAPABILITIES_PAYLOAD};

/// Reserve granularity for exact-read payload storage. Completed frame payloads
/// are split out as `Bytes`, while unused tail capacity remains available for
/// later reads.
const FRAME_READ_ARENA_CHUNK: usize = 64 * 1024;

/// One parsed data-channel message.
#[derive(Debug)]
pub enum FrameEvent {
    /// IP packet v2 frame payload (the bytes after type + frame length:
    /// offload_len byte + optional virtio header + IP packet). Run
    /// `parse_ip_packet_v2` on it.
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

#[derive(Debug)]
enum ExactReadError {
    FinishedEarly(usize),
    Read(std::io::Error),
}

/// Read until `read_buf` is full without requiring an initialized `&mut [u8]`.
///
/// This mirrors iroh's `RecvStream::read_exact`, but works with
/// `ReadBuf::uninit` so payload storage can be filled without a zeroing pass.
async fn read_exact_uninit<R>(
    reader: &mut R,
    read_buf: &mut ReadBuf<'_>,
) -> Result<(), ExactReadError>
where
    R: AsyncRead + Unpin,
{
    let initial_filled = read_buf.filled().len();
    while read_buf.remaining() > 0 {
        let before = read_buf.filled().len();
        poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, read_buf))
            .await
            .map_err(ExactReadError::Read)?;
        let after = read_buf.filled().len();
        if after == before {
            return Err(ExactReadError::FinishedEarly(
                after.saturating_sub(initial_filled),
            ));
        }
    }
    Ok(())
}

fn map_exact_read_error(error: ExactReadError, context: &str, expected: usize) -> FrameError {
    match error {
        ExactReadError::FinishedEarly(read) => FrameError::Read(format!(
            "stream ended mid-{} ({} of {} bytes)",
            context, read, expected
        )),
        ExactReadError::Read(e) => FrameError::Read(format!("failed to read {}: {}", context, e)),
    }
}

/// Exact frame reader that owns the data-channel `RecvStream`.
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

    /// Pull the next complete frame. Returns `Ok(None)` on clean end of stream.
    pub async fn next_frame(&mut self) -> Result<Option<FrameEvent>, FrameError> {
        let Some(type_byte) = self.read_message_type().await? else {
            return Ok(None);
        };

        match DataMessageType::from_byte(type_byte) {
            None => Err(FrameError::UnknownType(type_byte)),
            Some(DataMessageType::HeartbeatPing) => Ok(Some(FrameEvent::HeartbeatPing)),
            Some(DataMessageType::HeartbeatPong) => Ok(Some(FrameEvent::HeartbeatPong)),
            Some(DataMessageType::Capabilities) => {
                let mut len_buf = [0u8; 1];
                self.read_exact_stack(&mut len_buf, "capabilities length")
                    .await?;

                let payload_len = usize::from(len_buf[0]);
                if payload_len > 0 {
                    let mut discard = [MaybeUninit::<u8>::uninit(); MAX_CAPABILITIES_PAYLOAD];
                    let mut read_buf = ReadBuf::uninit(&mut discard[..payload_len]);
                    read_exact_uninit(&mut self.stream, &mut read_buf).await.map_err(|e| {
                        map_exact_read_error(e, "capabilities payload", payload_len)
                    })?;
                }

                Ok(Some(FrameEvent::Capabilities))
            }
            Some(DataMessageType::IpPacket) => {
                let mut len_buf = [0u8; 4];
                self.read_exact_stack(&mut len_buf, "IP frame length")
                    .await?;

                let frame_len = u32::from_be_bytes(len_buf) as usize;
                if frame_len > self.max_ip_frame {
                    return Err(FrameError::FrameTooLarge(frame_len));
                }

                let frame = self.read_frame_payload(frame_len).await?;
                Ok(Some(FrameEvent::IpFrame(frame)))
            }
        }
    }

    async fn read_message_type(&mut self) -> Result<Option<u8>, FrameError> {
        let mut type_buf = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut type_buf);
        match read_exact_uninit(&mut self.stream, &mut read_buf).await {
            Ok(()) => Ok(Some(type_buf[0])),
            Err(ExactReadError::FinishedEarly(0)) => Ok(None),
            Err(e) => Err(map_exact_read_error(e, "message type", 1)),
        }
    }

    async fn read_exact_stack(
        &mut self,
        buf: &mut [u8],
        context: &str,
    ) -> Result<(), FrameError> {
        let expected = buf.len();
        let mut read_buf = ReadBuf::new(buf);
        read_exact_uninit(&mut self.stream, &mut read_buf)
            .await
            .map_err(|e| map_exact_read_error(e, context, expected))
    }

    async fn read_frame_payload(&mut self, frame_len: usize) -> Result<Bytes, FrameError> {
        assert!(self.buf.is_empty());
        if self.buf.capacity() < frame_len {
            self.buf.reserve(FRAME_READ_ARENA_CHUNK.max(frame_len));
        }

        {
            let spare = self.buf.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(&mut spare[..frame_len]);
            read_exact_uninit(&mut self.stream, &mut read_buf)
                .await
                .map_err(|e| map_exact_read_error(e, "IP frame payload", frame_len))?;
        }

        // This is the only `unsafe` in the codebase that is not an FFI/OS call
        // (libc, ioctl, raw fds). It is a deliberate performance choice, not a
        // requirement: reading straight into `spare_capacity_mut` lets us build
        // an owned, zero-copy `Bytes` from the reused arena without the memset
        // that a safe `resize(frame_len, 0)` + `read_exact` would incur on every
        // frame (the no-zero-fill goal stated in this module's doc comment).
        //
        // SAFETY: `read_exact_uninit` returns `Ok(())` only when its `ReadBuf`
        // is fully filled, so the exact read above initialized exactly
        // `frame_len` bytes in `spare_capacity_mut`, starting at the current
        // empty buffer tail (asserted above). Any short read returns early and
        // never reaches this `set_len`.
        unsafe {
            self.buf.set_len(frame_len);
        }
        Ok(self.buf.split_to(frame_len).freeze())
    }
}

/// Parse one complete frame from the front of `buf`, consuming its bytes.
/// Returns `Ok(None)` when the buffer does not yet hold a complete frame.
#[cfg(test)]
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
    use tokio::io::AsyncWriteExt;

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

    #[tokio::test]
    async fn read_exact_uninit_fills_uninitialized_storage() {
        let (mut writer, mut reader) = tokio::io::duplex(2);
        let writer_task = tokio::spawn(async move {
            writer.write_all(b"hello").await.expect("write payload");
        });

        let mut storage = [MaybeUninit::<u8>::uninit(); 5];
        let mut read_buf = ReadBuf::uninit(&mut storage);
        read_exact_uninit(&mut reader, &mut read_buf)
            .await
            .expect("exact read");

        assert_eq!(read_buf.filled(), b"hello");
        writer_task.await.expect("writer task");
    }

    #[tokio::test]
    async fn read_exact_uninit_reports_early_eof() {
        let (mut writer, mut reader) = tokio::io::duplex(4);
        writer.write_all(b"abc").await.expect("write partial");
        drop(writer);

        let mut storage = [MaybeUninit::<u8>::uninit(); 5];
        let mut read_buf = ReadBuf::uninit(&mut storage);
        match read_exact_uninit(&mut reader, &mut read_buf).await {
            Err(ExactReadError::FinishedEarly(3)) => {}
            other => panic!("expected FinishedEarly(3), got {:?}", other),
        }
        assert_eq!(read_buf.filled(), b"abc");
    }
}
