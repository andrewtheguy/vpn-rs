//! Checksum computation helpers for NAT64 translation.
//!
//! When translating between IPv6 and IPv4, checksums must be recalculated because:
//! - IPv4 header has its own checksum (IPv6 does not)
//! - TCP/UDP checksums include a pseudo-header that differs between IPv4 and IPv6

use std::net::{Ipv4Addr, Ipv6Addr};

/// Compute the ones' complement sum of 16-bit words in a byte slice.
///
/// This is the core operation for IP/TCP/UDP checksum calculation.
#[inline]
pub fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;

    // Sum 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte if present
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    sum
}

/// Fold a 32-bit sum into a 16-bit ones' complement value.
#[inline]
pub fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Compute the final ones' complement checksum.
#[inline]
pub fn compute_checksum(data: &[u8]) -> u16 {
    let sum = ones_complement_sum(data);
    !fold_checksum(sum)
}

/// Compute IPv4 header checksum.
///
/// The checksum field in the header should be set to 0 before calling this.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    compute_checksum(header)
}

/// Compute IPv4 pseudo-header contribution to TCP/UDP checksum.
pub fn ipv4_pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, length: u16) -> u32 {
    let src = src.octets();
    let dst = dst.octets();

    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += protocol as u32;
    sum += length as u32;
    sum
}

/// Compute IPv6 pseudo-header contribution to TCP/UDP checksum.
pub fn ipv6_pseudo_header_sum(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, length: u32) -> u32 {
    let src = src.octets();
    let dst = dst.octets();

    let mut sum: u32 = 0;

    // Source address (8 x 16-bit words)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
    }

    // Destination address (8 x 16-bit words)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }

    // Upper-layer packet length (32-bit, but we sum as two 16-bit values)
    sum += length >> 16;
    sum += length & 0xFFFF;

    // Next header (padded to 32 bits, upper 3 bytes are zero)
    sum += next_header as u32;

    sum
}

/// Update a checksum incrementally when a 16-bit value changes.
///
/// This uses the algorithm from RFC 1624 for efficient checksum updates.
/// `old_checksum` is the current checksum (already complemented),
/// `old_value` is the old 16-bit value, `new_value` is the new 16-bit value.
#[inline]
#[allow(dead_code)]
pub fn update_checksum_16(old_checksum: u16, old_value: u16, new_value: u16) -> u16 {
    // HC' = ~(~HC + ~m + m') from RFC 1624
    let hc = !old_checksum as u32;
    let m = !old_value as u32;
    let m_prime = new_value as u32;

    let sum = hc + m + m_prime;
    !fold_checksum(sum)
}

/// Update a checksum incrementally when a 32-bit value changes.
///
/// Useful for updating IP addresses in TCP/UDP checksums.
#[inline]
#[allow(dead_code)]
pub fn update_checksum_32(old_checksum: u16, old_value: u32, new_value: u32) -> u16 {
    // Split into two 16-bit updates
    let old_hi = (old_value >> 16) as u16;
    let old_lo = old_value as u16;
    let new_hi = (new_value >> 16) as u16;
    let new_lo = new_value as u16;

    let checksum = update_checksum_16(old_checksum, old_hi, new_hi);
    update_checksum_16(checksum, old_lo, new_lo)
}

/// Adjust TCP/UDP checksum for IPv6-to-IPv4 translation.
///
/// This adjusts the checksum to account for the pseudo-header change
/// from IPv6 to IPv4 format.
pub fn adjust_checksum_6to4(
    old_checksum: u16,
    src6: Ipv6Addr,
    dst6: Ipv6Addr,
    src4: Ipv4Addr,
    dst4: Ipv4Addr,
    protocol: u8,
    payload_len: u16,
) -> u16 {
    // Calculate old (IPv6) pseudo-header sum
    let old_pseudo = ipv6_pseudo_header_sum(src6, dst6, protocol, payload_len as u32);

    // Calculate new (IPv4) pseudo-header sum
    let new_pseudo = ipv4_pseudo_header_sum(src4, dst4, protocol, payload_len);

    // Adjust checksum: subtract old pseudo-header, add new pseudo-header
    // Using ones' complement arithmetic
    let hc = !old_checksum as u32;
    let old_folded = fold_checksum(old_pseudo); // Keep as u16 for proper inversion
    let new_folded = fold_checksum(new_pseudo) as u32;

    // HC' = ~(~HC + ~old + new)
    // Note: invert old_folded as u16 before casting to u32 to avoid 32-bit complement
    let sum = hc + (!old_folded) as u32 + new_folded;
    !fold_checksum(sum)
}

/// Adjust TCP/UDP checksum for IPv4-to-IPv6 translation.
///
/// This adjusts the checksum to account for the pseudo-header change
/// from IPv4 to IPv6 format.
pub fn adjust_checksum_4to6(
    old_checksum: u16,
    src4: Ipv4Addr,
    dst4: Ipv4Addr,
    src6: Ipv6Addr,
    dst6: Ipv6Addr,
    protocol: u8,
    payload_len: u16,
) -> u16 {
    // Calculate old (IPv4) pseudo-header sum
    let old_pseudo = ipv4_pseudo_header_sum(src4, dst4, protocol, payload_len);

    // Calculate new (IPv6) pseudo-header sum
    // Note: IPv6 uses the same protocol number in next header field for TCP/UDP
    let new_pseudo = ipv6_pseudo_header_sum(src6, dst6, protocol, payload_len as u32);

    // Adjust checksum: subtract old pseudo-header, add new pseudo-header
    let hc = !old_checksum as u32;
    let old_folded = fold_checksum(old_pseudo); // Keep as u16 for proper inversion
    let new_folded = fold_checksum(new_pseudo) as u32;

    // HC' = ~(~HC + ~old + new)
    // Note: invert old_folded as u16 before casting to u32 to avoid 32-bit complement
    let sum = hc + (!old_folded) as u32 + new_folded;
    !fold_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ones_complement_sum() {
        // Test with known data
        let data = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11];
        let sum = ones_complement_sum(&data);
        assert!(sum > 0);
    }

    #[test]
    fn test_fold_checksum() {
        // Test folding
        // 0x1_FFFF = 0xFFFF + 0x0001 (carry) = 0x10000 -> 0x0000 + 0x0001 = 0x0001
        let sum: u32 = 0x1_FFFF;
        let folded = fold_checksum(sum);
        assert_eq!(folded, 1);

        // 0x1_FFFE = 0xFFFE + 0x0001 (carry) = 0xFFFF (no further carry)
        let sum2: u32 = 0x1_FFFE;
        let folded2 = fold_checksum(sum2);
        assert_eq!(folded2, 0xFFFF);
    }

    #[test]
    fn test_ipv4_header_checksum() {
        // Example IPv4 header (checksum field at bytes 10-11 set to 0)
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // checksum = 0
            0xc0, 0xa8, 0x00, 0x01, // src: 192.168.0.1
            0xc0, 0xa8, 0x00, 0xc7, // dst: 192.168.0.199
        ];

        let checksum = ipv4_header_checksum(&header);
        // Verify the checksum is non-zero (actual value depends on header content)
        assert_ne!(checksum, 0);

        // Verify checksum: sum of header with correct checksum should be 0xFFFF
        let mut header_with_checksum = header;
        header_with_checksum[10] = (checksum >> 8) as u8;
        header_with_checksum[11] = checksum as u8;

        let verify_sum = ones_complement_sum(&header_with_checksum);
        assert_eq!(fold_checksum(verify_sum), 0xFFFF);
    }

    #[test]
    fn test_incremental_checksum_update() {
        // Test that incremental update produces correct result
        let data = [0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        let original_checksum = compute_checksum(&data);

        // Change first 16-bit word from 0x0001 to 0x0005
        let old_value = 0x0001u16;
        let new_value = 0x0005u16;

        let incremental_checksum = update_checksum_16(original_checksum, old_value, new_value);

        // Verify against recomputed checksum
        let modified_data = [0x00, 0x05, 0x00, 0x02, 0x00, 0x03];
        let recomputed_checksum = compute_checksum(&modified_data);

        assert_eq!(incremental_checksum, recomputed_checksum);
    }

    #[test]
    fn test_ipv4_pseudo_header_sum() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let protocol = 6; // TCP
        let length = 20;

        let sum = ipv4_pseudo_header_sum(src, dst, protocol, length);
        assert!(sum > 0);
    }

    #[test]
    fn test_ipv6_pseudo_header_sum() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let next_header = 6; // TCP
        let length = 20;

        let sum = ipv6_pseudo_header_sum(src, dst, next_header, length);
        assert!(sum > 0);
    }
}
