//! Linux TUN offload metadata helpers and software fallback segmentation.
//!
//! This module handles:
//! - Parsing and serializing `virtio_net_hdr` metadata (10-byte variant).
//! - Splitting/assembling TUN frames when `IFF_VNET_HDR` is enabled.
//! - Fallback software segmentation for TCP GSO frames when peer/local offload
//!   support is unavailable.

use bytes::{BufMut, BytesMut};

/// Size of the Linux virtio header used by TUN when `IFF_VNET_HDR` is enabled.
pub const VIRTIO_NET_HDR_LEN: usize = 10;

/// GSO type: no segmentation offload.
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
/// GSO type: TCP over IPv4.
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// GSO type: TCP over IPv6.
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// GSO type flag: ECN is present.
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Offload metadata carried by Linux TUN when `IFF_VNET_HDR` is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Parse a 10-byte virtio header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != VIRTIO_NET_HDR_LEN {
            return Err(format!(
                "virtio_net_hdr must be {} bytes, got {}",
                VIRTIO_NET_HDR_LEN,
                bytes.len()
            ));
        }

        Ok(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
            num_buffers: 0,
        })
    }

    /// Serialize a virtio header to its 10-byte wire form.
    pub fn to_bytes(self) -> [u8; VIRTIO_NET_HDR_LEN] {
        let mut out = [0u8; VIRTIO_NET_HDR_LEN];
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        out[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        out[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        out
    }

    /// Return true if this header carries a TCP GSO packet (v4 or v6).
    pub fn is_tcp_gso(self) -> bool {
        matches!(
            self.gso_type & !VIRTIO_NET_HDR_GSO_ECN,
            VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6
        ) && self.gso_size != 0
    }

    /// Return the normalized GSO type value without ECN bit.
    pub fn normalized_gso_type(self) -> u8 {
        self.gso_type & !VIRTIO_NET_HDR_GSO_ECN
    }
}

impl From<[u8; VIRTIO_NET_HDR_LEN]> for VirtioNetHdr {
    fn from(value: [u8; VIRTIO_NET_HDR_LEN]) -> Self {
        Self {
            flags: value[0],
            gso_type: value[1],
            hdr_len: u16::from_le_bytes([value[2], value[3]]),
            gso_size: u16::from_le_bytes([value[4], value[5]]),
            csum_start: u16::from_le_bytes([value[6], value[7]]),
            csum_offset: u16::from_le_bytes([value[8], value[9]]),
            num_buffers: 0,
        }
    }
}

/// Split a TUN frame into optional offload metadata and raw IP payload.
///
/// When `vnet_hdr_enabled` is false, the frame is treated as plain IP.
/// When true, the leading 10-byte `virtio_net_hdr` is parsed and stripped.
pub fn split_tun_frame(
    frame: &[u8],
    vnet_hdr_enabled: bool,
) -> Result<(Option<VirtioNetHdr>, &[u8]), String> {
    if !vnet_hdr_enabled {
        if frame.is_empty() {
            return Err("zero-length TUN frame".to_string());
        }
        return Ok((None, frame));
    }

    if frame.len() < VIRTIO_NET_HDR_LEN {
        return Err(format!(
            "TUN frame shorter than virtio header: {} < {}",
            frame.len(),
            VIRTIO_NET_HDR_LEN
        ));
    }

    let offload = VirtioNetHdr::from_bytes(&frame[..VIRTIO_NET_HDR_LEN])?;
    let ip_packet = &frame[VIRTIO_NET_HDR_LEN..];
    if ip_packet.is_empty() {
        return Err("empty IP payload after virtio header".to_string());
    }

    if offload.gso_type == VIRTIO_NET_HDR_GSO_NONE {
        return Ok((None, ip_packet));
    }

    if offload.is_tcp_gso() {
        return Ok((Some(offload), ip_packet));
    }

    Err(format!(
        "unsupported GSO type from TUN: 0x{:02x}",
        offload.gso_type
    ))
}

/// Compose a TUN frame for writing.
///
/// If `vnet_hdr_enabled` is true, a 10-byte virtio header is prepended. If no
/// offload header is provided, a zeroed header is used for plain packets.
pub fn compose_tun_frame(
    out: &mut BytesMut,
    vnet_hdr_enabled: bool,
    offload: Option<&VirtioNetHdr>,
    ip_packet: &[u8],
) -> Result<(), String> {
    if ip_packet.is_empty() {
        return Err("cannot compose TUN frame with empty IP payload".to_string());
    }

    if !vnet_hdr_enabled && offload.is_some() {
        return Err(
            "received offload metadata but local TUN does not use vnet headers".to_string(),
        );
    }

    out.clear();
    out.reserve(
        ip_packet.len()
            + if vnet_hdr_enabled {
                VIRTIO_NET_HDR_LEN
            } else {
                0
            },
    );

    if vnet_hdr_enabled {
        let header = offload.copied().unwrap_or_default().to_bytes();
        out.put_slice(&header);
    }
    out.put_slice(ip_packet);
    Ok(())
}

/// Software fallback: segment a TCP GSO packet into plain TCP packets.
///
/// This is used when offload metadata is present but the local write path or
/// remote peer cannot handle GSO metadata directly.
pub fn segment_tcp_gso_packet(
    offload: &VirtioNetHdr,
    ip_packet: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if !offload.is_tcp_gso() {
        return Err("offload header is not TCP GSO".to_string());
    }

    if ip_packet.is_empty() {
        return Err("empty IP packet".to_string());
    }

    let version = ip_packet[0] >> 4;
    let normalized_type = offload.normalized_gso_type();
    match (version, normalized_type) {
        (4, VIRTIO_NET_HDR_GSO_TCPV4) | (6, VIRTIO_NET_HDR_GSO_TCPV6) => {}
        (4, other) | (6, other) => {
            return Err(format!(
                "IP version/GSO mismatch (ip v{}, gso type 0x{:02x})",
                version, other
            ))
        }
        _ => return Err(format!("unsupported IP version {}", version)),
    }

    let header_len = usize::from(offload.hdr_len);
    if header_len == 0 || header_len > ip_packet.len() {
        return Err(format!(
            "invalid offload hdr_len {} for packet length {}",
            header_len,
            ip_packet.len()
        ));
    }

    let tcp_offset = usize::from(offload.csum_start);
    if tcp_offset + 20 > header_len {
        return Err(format!(
            "invalid csum_start {} for header_len {}",
            tcp_offset, header_len
        ));
    }

    let tcp_header_len = usize::from(ip_packet[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 || tcp_offset + tcp_header_len > header_len {
        return Err(format!(
            "invalid TCP header length {} (offset {}, header_len {})",
            tcp_header_len, tcp_offset, header_len
        ));
    }

    let checksum_index = tcp_offset + usize::from(offload.csum_offset);
    if checksum_index + 2 > header_len {
        return Err(format!(
            "invalid csum_offset {} (checksum index {} beyond header_len {})",
            offload.csum_offset, checksum_index, header_len
        ));
    }

    let payload = &ip_packet[header_len..];
    if payload.is_empty() {
        return Ok(vec![ip_packet.to_vec()]);
    }

    let gso_size = usize::from(offload.gso_size);
    if payload.len() <= gso_size {
        return Ok(vec![ip_packet.to_vec()]);
    }

    let base_seq = u32::from_be_bytes([
        ip_packet[tcp_offset + 4],
        ip_packet[tcp_offset + 5],
        ip_packet[tcp_offset + 6],
        ip_packet[tcp_offset + 7],
    ]);
    let original_tcp_flags = ip_packet[tcp_offset + 13];

    let mut out = Vec::with_capacity(payload.len().div_ceil(gso_size));
    for chunk_offset in (0..payload.len()).step_by(gso_size) {
        let chunk_end = (chunk_offset + gso_size).min(payload.len());
        let chunk = &payload[chunk_offset..chunk_end];

        let mut segment = Vec::with_capacity(header_len + chunk.len());
        segment.extend_from_slice(&ip_packet[..header_len]);
        segment.extend_from_slice(chunk);

        // Sequence number increments by payload bytes emitted in previous segments.
        let seq = base_seq.wrapping_add(chunk_offset as u32);
        segment[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());

        // FIN/PSH belong only on the last segment.
        if chunk_end < payload.len() {
            segment[tcp_offset + 13] = original_tcp_flags & !(0x01 | 0x08);
        }

        // Update IP length fields and checksum first.
        match version {
            4 => update_ipv4_lengths_and_checksum(&mut segment, header_len + chunk.len())?,
            6 => update_ipv6_payload_length(&mut segment, header_len + chunk.len())?,
            _ => unreachable!(),
        }

        // Recalculate TCP checksum for this segment.
        segment[checksum_index] = 0;
        segment[checksum_index + 1] = 0;
        let checksum = match version {
            4 => tcp_checksum_ipv4(&segment, tcp_offset)?,
            6 => tcp_checksum_ipv6(&segment, tcp_offset)?,
            _ => unreachable!(),
        };
        segment[checksum_index..checksum_index + 2].copy_from_slice(&checksum.to_be_bytes());

        out.push(segment);
    }

    Ok(out)
}

fn update_ipv4_lengths_and_checksum(packet: &mut [u8], packet_len: usize) -> Result<(), String> {
    if packet.len() < 20 {
        return Err("IPv4 packet too short".to_string());
    }

    if packet[9] != 6 {
        return Err(format!("IPv4 protocol {} is not TCP", packet[9]));
    }

    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || ihl > packet.len() {
        return Err(format!("invalid IPv4 IHL {}", ihl));
    }

    let total_len = u16::try_from(packet_len)
        .map_err(|_| format!("IPv4 packet too large for total_len: {}", packet_len))?;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());

    packet[10] = 0;
    packet[11] = 0;
    let checksum = finalize_checksum(add_bytes(0, &packet[..ihl]));
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}

fn update_ipv6_payload_length(packet: &mut [u8], packet_len: usize) -> Result<(), String> {
    if packet.len() < 40 {
        return Err("IPv6 packet too short".to_string());
    }

    let payload_len = packet_len
        .checked_sub(40)
        .ok_or_else(|| "IPv6 packet length underflow".to_string())?;
    let payload_len_u16 = u16::try_from(payload_len)
        .map_err(|_| format!("IPv6 payload too large: {}", payload_len))?;
    packet[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());

    Ok(())
}

fn tcp_checksum_ipv4(packet: &[u8], tcp_offset: usize) -> Result<u16, String> {
    if packet.len() < 20 || tcp_offset >= packet.len() {
        return Err("invalid TCP offset for IPv4 checksum".to_string());
    }
    let tcp_len = packet
        .len()
        .checked_sub(tcp_offset)
        .ok_or_else(|| "TCP length underflow".to_string())?;
    let tcp_len_u16 = u16::try_from(tcp_len)
        .map_err(|_| format!("TCP segment too large for IPv4 checksum: {}", tcp_len))?;

    let mut sum = 0u32;
    sum = add_bytes(sum, &packet[12..20]);
    sum = sum.wrapping_add(u32::from(6u16));
    sum = sum.wrapping_add(u32::from(tcp_len_u16));
    sum = add_bytes(sum, &packet[tcp_offset..]);
    Ok(finalize_checksum(sum))
}

fn tcp_checksum_ipv6(packet: &[u8], tcp_offset: usize) -> Result<u16, String> {
    if packet.len() < 40 || tcp_offset >= packet.len() {
        return Err("invalid TCP offset for IPv6 checksum".to_string());
    }
    let tcp_len = packet
        .len()
        .checked_sub(tcp_offset)
        .ok_or_else(|| "TCP length underflow".to_string())?;
    let tcp_len_u32 = u32::try_from(tcp_len)
        .map_err(|_| format!("TCP segment too large for IPv6 checksum: {}", tcp_len))?;

    let mut sum = 0u32;
    sum = add_bytes(sum, &packet[8..24]);
    sum = add_bytes(sum, &packet[24..40]);
    sum = sum.wrapping_add((tcp_len_u32 >> 16) & 0xffff);
    sum = sum.wrapping_add(tcp_len_u32 & 0xffff);
    sum = sum.wrapping_add(u32::from(6u16));
    sum = add_bytes(sum, &packet[tcp_offset..]);
    Ok(finalize_checksum(sum))
}

fn add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{IpNumber, Ipv4Header, Ipv6Header, PacketHeaders, TransportHeader};

    fn build_ipv4_tcp_packet(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 251) as u8).collect();

        let mut tcp = etherparse::TcpHeader::new(12345, 443, 10_000, 65_535);
        tcp.ack = true;
        tcp.psh = true;
        tcp.fin = true;

        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        )
        .expect("valid IPv4 header");
        tcp.checksum = tcp
            .calc_checksum_ipv4(&ip, &payload)
            .expect("valid IPv4 TCP checksum");
        ip.header_checksum = ip.calc_header_checksum();

        let mut packet = Vec::with_capacity(ip.header_len() + tcp.header_len() + payload.len());
        ip.write(&mut packet).expect("serialize IPv4 header");
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(&payload);
        packet
    }

    fn build_ipv6_tcp_packet(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|v| (v % 253) as u8).collect();

        let mut tcp = etherparse::TcpHeader::new(12345, 443, 20_000, 65_535);
        tcp.ack = true;
        tcp.psh = true;
        tcp.fin = true;

        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: etherparse::Ipv6FlowLabel::ZERO,
            payload_length: u16::try_from(tcp.header_len() + payload.len())
                .expect("IPv6 payload length fits in u16"),
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            destination: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        tcp.checksum = tcp
            .calc_checksum_ipv6(&ip, &payload)
            .expect("valid IPv6 TCP checksum");

        let mut packet = Vec::with_capacity(40 + tcp.header_len() + payload.len());
        ip.write(&mut packet).expect("serialize IPv6 header");
        tcp.write(&mut packet).expect("serialize TCP header");
        packet.extend_from_slice(&payload);
        packet
    }

    fn assert_tcp_checksum_valid(packet: &[u8]) {
        let headers = PacketHeaders::from_ip_slice(packet).expect("packet parses");
        match (headers.net, headers.transport, headers.payload) {
            (
                Some(etherparse::NetHeaders::Ipv4(ip, _)),
                Some(TransportHeader::Tcp(tcp)),
                etherparse::PayloadSlice::Tcp(payload),
            ) => {
                let expected = tcp
                    .calc_checksum_ipv4(&ip, payload)
                    .expect("IPv4 checksum calculation succeeds");
                assert_eq!(tcp.checksum, expected, "invalid IPv4 TCP checksum");
            }
            (
                Some(etherparse::NetHeaders::Ipv6(ip, _)),
                Some(TransportHeader::Tcp(tcp)),
                etherparse::PayloadSlice::Tcp(payload),
            ) => {
                let expected = tcp
                    .calc_checksum_ipv6(&ip, payload)
                    .expect("IPv6 checksum calculation succeeds");
                assert_eq!(tcp.checksum, expected, "invalid IPv6 TCP checksum");
            }
            _ => panic!("packet is not TCP over IP"),
        }
    }

    #[test]
    fn test_virtio_header_roundtrip() {
        let hdr = VirtioNetHdr {
            flags: 1,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let encoded = hdr.to_bytes();
        let decoded = VirtioNetHdr::from_bytes(&encoded).expect("decode header");
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn test_split_tun_frame_with_plain_vnet_header() {
        let mut frame = vec![0u8; VIRTIO_NET_HDR_LEN];
        frame.extend_from_slice(&[0x45, 0, 0, 20]);

        let (offload, payload) = split_tun_frame(&frame, true).expect("split frame");
        assert!(offload.is_none());
        assert_eq!(payload, &[0x45, 0, 0, 20]);
    }

    #[test]
    fn test_compose_tun_frame_with_vnet_header() {
        let mut out = BytesMut::new();
        compose_tun_frame(&mut out, true, None, &[0x45, 1, 2, 3]).expect("compose frame");

        assert_eq!(out.len(), VIRTIO_NET_HDR_LEN + 4);
        assert!(out[..VIRTIO_NET_HDR_LEN].iter().all(|b| *b == 0));
        assert_eq!(&out[VIRTIO_NET_HDR_LEN..], &[0x45, 1, 2, 3]);
    }

    #[test]
    fn test_segment_tcp_gso_ipv4() {
        let packet = build_ipv4_tcp_packet(3500);
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        };

        let segments = segment_tcp_gso_packet(&offload, &packet).expect("segment IPv4 packet");
        assert_eq!(segments.len(), 3);

        for (idx, segment) in segments.iter().enumerate() {
            assert_tcp_checksum_valid(segment);

            let headers = PacketHeaders::from_ip_slice(segment).expect("segment parses");
            let tcp = match headers.transport {
                Some(TransportHeader::Tcp(t)) => t,
                _ => panic!("not tcp"),
            };

            if idx < 2 {
                assert!(!tcp.fin, "FIN must be cleared in non-last segments");
                assert!(!tcp.psh, "PSH must be cleared in non-last segments");
            } else {
                assert!(tcp.fin, "FIN should remain set in last segment");
                assert!(tcp.psh, "PSH should remain set in last segment");
            }
        }
    }

    #[test]
    fn test_segment_tcp_gso_ipv6() {
        let packet = build_ipv6_tcp_packet(2600);
        let offload = VirtioNetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: 60,
            gso_size: 1000,
            csum_start: 40,
            csum_offset: 16,
            num_buffers: 0,
        };

        let segments = segment_tcp_gso_packet(&offload, &packet).expect("segment IPv6 packet");
        assert_eq!(segments.len(), 3);

        for segment in segments {
            assert_tcp_checksum_valid(&segment);
            assert_eq!(segment[0] >> 4, 6);
        }
    }
}
