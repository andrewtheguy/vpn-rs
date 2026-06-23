//! Minimal IP packet field extraction (source / destination address).
//!
//! Shared by the UDP server ([`crate::vpn_core::server`]) and the TCP server
//! ([`crate::vpn_core::tcp_server`]) for destination-based routing and
//! anti-spoofing. Only the fixed header fields needed for routing are parsed.

use std::net::{Ipv4Addr, Ipv6Addr};

/// IP address extracted from a packet (source or destination).
pub(crate) enum PacketIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Minimum IPv4 header size (20 bytes, no options).
const IPV4_MIN_HEADER: usize = 20;
/// Minimum IPv6 header size (40 bytes fixed).
const IPV6_MIN_HEADER: usize = 40;
/// IPv4 version nibble.
const IP_VERSION_4: u8 = 4;
/// IPv6 version nibble.
const IP_VERSION_6: u8 = 6;

/// Extract source IP address from an IP packet (IPv4 or IPv6).
#[inline]
pub(crate) fn extract_source_ip(packet: &[u8]) -> Option<PacketIp> {
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }
    let version = packet[0] >> 4;
    if version == IP_VERSION_4 {
        return Some(PacketIp::V4(read_ipv4_addr(packet, 12)));
    }
    if version == IP_VERSION_6 {
        if len < IPV6_MIN_HEADER {
            return None;
        }
        return Some(PacketIp::V6(read_ipv6_addr(packet, 8)));
    }
    None
}

/// Extract destination IP address from an IP packet (IPv4 or IPv6).
#[inline]
pub(crate) fn extract_dest_ip(packet: &[u8]) -> Option<PacketIp> {
    let len = packet.len();
    if len < IPV4_MIN_HEADER {
        return None;
    }
    let version = packet[0] >> 4;
    if version == IP_VERSION_4 {
        return Some(PacketIp::V4(read_ipv4_addr(packet, 16)));
    }
    if version == IP_VERSION_6 {
        if len < IPV6_MIN_HEADER {
            return None;
        }
        return Some(PacketIp::V6(read_ipv6_addr(packet, 24)));
    }
    None
}

/// Read an IPv4 address from a packet at the given offset.
#[inline(always)]
fn read_ipv4_addr(packet: &[u8], offset: usize) -> Ipv4Addr {
    let bytes: [u8; 4] = packet[offset..offset + 4]
        .try_into()
        .expect("IPv4 address read: bounds already verified");
    Ipv4Addr::from(bytes)
}

/// Read an IPv6 address from a packet at the given offset.
#[inline(always)]
fn read_ipv6_addr(packet: &[u8], offset: usize) -> Ipv6Addr {
    let bytes: [u8; 16] = packet[offset..offset + 16]
        .try_into()
        .expect("IPv6 address read: bounds already verified");
    Ipv6Addr::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dest_ip_v4_and_v6() {
        let mut p4 = [0u8; 20];
        p4[0] = 0x45;
        p4[16..20].copy_from_slice(&[10, 0, 0, 5]);
        assert!(matches!(extract_dest_ip(&p4), Some(PacketIp::V4(ip)) if ip == Ipv4Addr::new(10, 0, 0, 5)));

        let mut p6 = [0u8; 40];
        p6[0] = 0x60;
        p6[24..40].copy_from_slice(&"fd00::5".parse::<Ipv6Addr>().unwrap().octets());
        assert!(matches!(extract_dest_ip(&p6), Some(PacketIp::V6(ip)) if ip == "fd00::5".parse::<Ipv6Addr>().unwrap()));

        assert!(extract_dest_ip(&[0x45u8; 10]).is_none());
        assert!(extract_dest_ip(&[]).is_none());
    }

    #[test]
    fn test_extract_source_ip_v4_and_v6() {
        let mut p4 = [0u8; 20];
        p4[0] = 0x45;
        p4[12..16].copy_from_slice(&[192, 168, 1, 100]);
        assert!(matches!(extract_source_ip(&p4), Some(PacketIp::V4(ip)) if ip == Ipv4Addr::new(192, 168, 1, 100)));

        let mut p6 = [0u8; 40];
        p6[0] = 0x60;
        p6[8..24].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        assert!(matches!(extract_source_ip(&p6), Some(PacketIp::V6(ip)) if ip == "fd00::2".parse::<Ipv6Addr>().unwrap()));
    }
}
