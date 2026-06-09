//! Helpers for the unreliable-QUIC-datagram data plane.
//!
//! The iroh transport carries each IP packet in a single unreliable, unordered
//! QUIC datagram (`Connection::send_datagram_wait` / `read_datagram`). Datagrams
//! are size-capped at roughly the path MTU, so — unlike the reliable-stream path
//! — a GSO super-frame can never cross the wire as one unit. Outbound packets are
//! therefore split into per-packet datagrams here; the receiver's TUN writer
//! re-coalesces same-flow runs into TSO super-frames (`TunWriter::write_batch`).

use crate::vpn_core::offload::{materialize_offload_into, VirtioNetHdr};
use crate::vpn_core::signaling::{append_ip_datagram, DATAGRAM_IP_OVERHEAD};
use bytes::{Bytes, BytesMut};

/// Frame an outbound IP packet into one or more datagrams, emitting each as a
/// refcounted `Bytes` view over `arena`.
///
/// When `offload` is present the packet is a GSO super-frame: it is split into
/// individual IP packets via [`materialize_offload_into`], each framed as its own
/// datagram with no offload metadata. A plain packet is framed directly. Any
/// datagram whose framed length would exceed `max_frame_size` is dropped with a
/// warning — this defends against a peer whose `max_datagram_size` is smaller
/// than the negotiated tunnel MTU on an asymmetric path; the MTU clamp normally
/// guarantees a fit.
pub fn frame_outbound_datagrams<F>(
    arena: &mut BytesMut,
    offload: Option<&VirtioNetHdr>,
    packet: &[u8],
    seg_scratch: &mut Vec<u8>,
    max_frame_size: usize,
    mut emit: F,
) -> Result<(), String>
where
    F: FnMut(Bytes),
{
    match offload {
        Some(meta) => materialize_offload_into(meta, packet, seg_scratch, |seg| {
            emit_datagram(arena, seg, max_frame_size, &mut emit);
            Ok(())
        }),
        None => {
            emit_datagram(arena, packet, max_frame_size, &mut emit);
            Ok(())
        }
    }
}

/// Frame a single IP packet as one datagram and hand it to `emit`, dropping it
/// (with a warning) if it would not fit `max_frame_size`.
fn emit_datagram<F>(arena: &mut BytesMut, pkt: &[u8], max_frame_size: usize, emit: &mut F)
where
    F: FnMut(Bytes),
{
    let framed_len = DATAGRAM_IP_OVERHEAD + pkt.len();
    if framed_len > max_frame_size {
        log::warn!(
            "Dropping {}-byte IP packet: framed datagram ({} bytes) exceeds peer max_datagram_size ({})",
            pkt.len(),
            framed_len,
            max_frame_size
        );
        return;
    }
    match append_ip_datagram(arena, None, pkt) {
        Ok(written) => emit(arena.split_to(written).freeze()),
        Err(e) => log::warn!("Failed to frame datagram: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::signaling::parse_ip_datagram;

    fn ipv4_packet(len: usize) -> Vec<u8> {
        assert!(len >= 20);
        let mut packet = vec![0xcd; len];
        packet[0] = 0x45;
        packet
    }

    #[test]
    fn plain_packet_yields_one_datagram() {
        let packet = ipv4_packet(100);
        let mut arena = BytesMut::new();
        let mut scratch = Vec::new();
        let mut out: Vec<Bytes> = Vec::new();
        frame_outbound_datagrams(&mut arena, None, &packet, &mut scratch, 1500, |dg| {
            out.push(dg)
        })
        .expect("frame");
        assert_eq!(out.len(), 1);
        let (offload, parsed) = parse_ip_datagram(&out[0]).expect("parse");
        assert!(offload.is_none());
        assert_eq!(parsed, &packet[..]);
    }

    #[test]
    fn oversize_packet_is_dropped() {
        // Packet larger than the datagram budget must be dropped, not framed.
        let packet = ipv4_packet(1500);
        let mut arena = BytesMut::new();
        let mut scratch = Vec::new();
        let mut out: Vec<Bytes> = Vec::new();
        frame_outbound_datagrams(&mut arena, None, &packet, &mut scratch, 1300, |dg| {
            out.push(dg)
        })
        .expect("frame");
        assert!(out.is_empty(), "oversize packet must be dropped");
    }

    #[test]
    fn packet_exactly_at_budget_fits() {
        let packet = ipv4_packet(100);
        let budget = DATAGRAM_IP_OVERHEAD + packet.len();
        let mut arena = BytesMut::new();
        let mut scratch = Vec::new();
        let mut out: Vec<Bytes> = Vec::new();
        frame_outbound_datagrams(&mut arena, None, &packet, &mut scratch, budget, |dg| {
            out.push(dg)
        })
        .expect("frame");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), budget);
    }
}
