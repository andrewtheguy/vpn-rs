//! Packet routing helpers for sharding VPN packets over multiple transport streams.

use crate::vpn_core::signaling::{parse_ip_packet_v2, DataMessageType};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_MIN_HEADER: usize = 40;

pub(crate) fn frame_route_index(frame: &[u8], stream_count: usize) -> usize {
    if stream_count <= 1 {
        return 0;
    }
    let Some(payload) = ip_frame_payload(frame) else {
        return 0;
    };
    let Ok((_, packet)) = parse_ip_packet_v2(payload) else {
        return 0;
    };
    packet_route_index(packet, stream_count)
}

pub(crate) fn packet_route_index(packet: &[u8], stream_count: usize) -> usize {
    if stream_count <= 1 {
        return 0;
    }
    (packet_route_hash(packet) as usize) % stream_count
}

fn ip_frame_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 5 || frame[0] != DataMessageType::IpPacket.as_byte() {
        return None;
    }
    let payload_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() < 5 + payload_len {
        return None;
    }
    Some(&frame[5..5 + payload_len])
}

fn packet_route_hash(packet: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn add(mut hash: u64, bytes: &[u8]) -> u64 {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    let mut hash = FNV_OFFSET;
    if packet.len() < IPV4_MIN_HEADER {
        return add(hash, packet);
    }

    match packet[0] >> 4 {
        4 => {
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER || packet.len() < ihl {
                return add(hash, packet);
            }
            hash = add(hash, &[4, packet[9]]);
            hash = add(hash, &packet[12..20]);
            match packet[9] {
                6 if packet.len() >= ihl + 8 => {
                    hash = add(hash, &packet[ihl..ihl + 8]);
                }
                17 if packet.len() >= ihl + 8 => {
                    hash = add(hash, &packet[ihl..ihl + 8]);
                }
                _ => {}
            }
            hash
        }
        6 => {
            if packet.len() < IPV6_MIN_HEADER {
                return add(hash, packet);
            }
            hash = add(hash, &[6, packet[6]]);
            hash = add(hash, &packet[8..40]);
            match packet[6] {
                6 if packet.len() >= IPV6_MIN_HEADER + 8 => {
                    hash = add(hash, &packet[IPV6_MIN_HEADER..IPV6_MIN_HEADER + 8]);
                }
                17 if packet.len() >= IPV6_MIN_HEADER + 8 => {
                    hash = add(hash, &packet[IPV6_MIN_HEADER..IPV6_MIN_HEADER + 8]);
                }
                _ => {}
            }
            hash
        }
        _ => add(hash, packet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::signaling::append_ip_packet_v2;
    use bytes::BytesMut;

    fn ipv4_tcp_packet(src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 41];
        let total_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        packet[40] = (seq & 0xff) as u8;
        packet
    }

    #[test]
    fn same_tcp_flow_can_stripe_across_streams() {
        let routes: std::collections::HashSet<_> = (0..32)
            .map(|i| packet_route_index(&ipv4_tcp_packet(50000, 5201, i * 1448), 4))
            .collect();

        assert!(routes.len() > 1);
    }

    #[test]
    fn framed_packet_routes_like_payload_packet() {
        let packet = ipv4_tcp_packet(50000, 5201, 1);
        let mut frame = BytesMut::new();
        append_ip_packet_v2(&mut frame, None, &packet).expect("valid IP frame");

        assert_eq!(
            frame_route_index(&frame, 4),
            packet_route_index(&packet, 4)
        );
    }

    #[test]
    fn control_frames_route_to_stream_zero() {
        assert_eq!(frame_route_index(&[0xff], 4), 0);
        assert_eq!(packet_route_index(&ipv4_tcp_packet(50000, 5201, 1), 1), 0);
    }
}
