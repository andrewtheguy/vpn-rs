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
///
/// # Panics
///
/// Panics in debug builds if `header.len() < 20` (minimum IPv4 header size)
/// or if `header.len()` is not a multiple of 4 (IPv4 header length must be
/// a multiple of 4 bytes as specified by the IHL field).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    assert!(
        header.len() >= 20,
        "IPv4 header must be at least 20 bytes, got {}",
        header.len()
    );
    assert!(
        header.len().is_multiple_of(4),
        "IPv4 header length must be a multiple of 4 bytes, got {}",
        header.len()
    );
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
///
/// # UDP Zero-Checksum Handling
///
/// In IPv6, UDP checksum is **mandatory** and should never be 0x0000. However,
/// if `old_checksum == 0x0000` and `protocol == 17` (UDP), this function returns
/// 0x0000 to preserve the "no checksum" semantics for IPv4 UDP, where a zero
/// checksum indicates that no checksum was computed (optional per RFC 768).
///
/// This handles edge cases where an invalid IPv6 UDP packet with zero checksum
/// is being translated - the semantically closest IPv4 representation is also
/// "no checksum".
pub fn adjust_checksum_6to4(
    old_checksum: u16,
    src6: Ipv6Addr,
    dst6: Ipv6Addr,
    src4: Ipv4Addr,
    dst4: Ipv4Addr,
    protocol: u8,
    payload_len: u16,
) -> u16 {
    // UDP zero-checksum special case: In IPv4 UDP, 0x0000 means "no checksum".
    // In IPv6 UDP, checksum is mandatory and 0x0000 is invalid. If we receive
    // an invalid IPv6 UDP packet with zero checksum, preserve it as "no checksum"
    // in the translated IPv4 packet.
    const UDP_PROTOCOL: u8 = 17;
    if protocol == UDP_PROTOCOL && old_checksum == 0 {
        return 0;
    }

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
    let adjusted = !fold_checksum(sum);
    if protocol == UDP_PROTOCOL && old_checksum != 0 && adjusted == 0 {
        0xFFFF
    } else {
        adjusted
    }
}

/// Adjust TCP/UDP checksum for IPv4-to-IPv6 translation.
///
/// This adjusts the checksum to account for the pseudo-header change
/// from IPv4 to IPv6 format.
///
/// Returns `None` for the IPv4 UDP zero-checksum case (protocol 17 with
/// `old_checksum == 0`), because IPv6 requires a checksum and the caller
/// must recompute the full UDP checksum.
pub fn adjust_checksum_4to6(
    old_checksum: u16,
    src4: Ipv4Addr,
    dst4: Ipv4Addr,
    src6: Ipv6Addr,
    dst6: Ipv6Addr,
    protocol: u8,
    payload_len: u16,
) -> Option<u16> {
    // IPv4 UDP can omit the checksum (0x0000), but IPv6 requires it.
    // Signal to the caller that a full recompute is required.
    const UDP_PROTOCOL: u8 = 17;
    if protocol == UDP_PROTOCOL && old_checksum == 0 {
        return None;
    }

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
    let adjusted = !fold_checksum(sum);
    if protocol == UDP_PROTOCOL && adjusted == 0 {
        Some(0xFFFF)
    } else {
        Some(adjusted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ones_complement_sum() {
        // Test with known data: partial IPv4 header bytes
        // 16-bit words: 0x4500 + 0x0073 + 0x0000 + 0x4000 + 0x4011 = 0xC584
        let data = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11];
        let sum = ones_complement_sum(&data);
        assert_eq!(sum, 0xC584, "ones_complement_sum should return 0xC584 for test data");

        // Test with odd-length data (last byte padded with 0x00)
        // 16-bit words: 0x0102 + 0x0300 = 0x0402
        let odd_data = [0x01, 0x02, 0x03];
        let odd_sum = ones_complement_sum(&odd_data);
        assert_eq!(odd_sum, 0x0402, "ones_complement_sum should handle odd-length data");

        // Test empty data
        let empty_sum = ones_complement_sum(&[]);
        assert_eq!(empty_sum, 0, "ones_complement_sum of empty data should be 0");
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

    /// Helper to check ones' complement equivalence.
    /// In ones' complement, 0x0000 and 0xFFFF are both representations of zero.
    fn ones_complement_eq(a: u16, b: u16) -> bool {
        // Normalize: treat 0xFFFF as 0x0000 (both are zero in ones' complement)
        let norm_a = if a == 0xFFFF { 0x0000 } else { a };
        let norm_b = if b == 0xFFFF { 0x0000 } else { b };
        norm_a == norm_b
    }

    #[test]
    fn test_adjust_checksum_6to4_then_4to6_roundtrip() {
        // Test that applying 6to4 then 4to6 returns the original checksum
        let src6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst6: Ipv6Addr = "64:ff9b::8.8.8.8".parse().unwrap();
        let src4 = Ipv4Addr::new(10, 0, 0, 1); // NAT64 server IP
        let dst4 = Ipv4Addr::new(8, 8, 8, 8); // Extracted from NAT64 address
        let protocol = 6; // TCP
        let payload_len: u16 = 40;

        // Test various original checksum values including edge cases
        // Note: 0x0000 and 0xFFFF are equivalent in ones' complement (both are zero)
        let test_checksums: [u16; 8] = [
            0x0000, // Zero (edge case)
            0xFFFF, // All ones / negative zero (edge case)
            0x0001, // Minimal non-zero
            0xFFFE, // Near max
            0x1234, // Arbitrary value
            0xABCD, // Another arbitrary value
            0x8000, // High bit set
            0x5A5A, // Alternating pattern
        ];

        for original in test_checksums {
            // Apply 6to4 translation (IPv6 -> IPv4)
            let after_6to4 = adjust_checksum_6to4(
                original, src6, dst6, src4, dst4, protocol, payload_len,
            );

            // Apply 4to6 translation (IPv4 -> IPv6) - reverse direction
            // Note: In the reverse direction, src4 becomes the source, dst4 is where we came from
            // and we're going back to src6/dst6
            let after_4to6 = adjust_checksum_4to6(
                after_6to4, src4, dst4, src6, dst6, protocol, payload_len,
            )
            .expect("TCP checksum adjustment should always succeed");

            assert!(
                ones_complement_eq(after_4to6, original),
                "Round-trip 6to4->4to6 failed for original checksum 0x{:04X}: \
                 6to4 gave 0x{:04X}, 4to6 gave 0x{:04X}",
                original, after_6to4, after_4to6
            );
        }
    }

    #[test]
    fn test_adjust_checksum_4to6_then_6to4_roundtrip() {
        // Test the reverse direction: 4to6 then 6to4 returns original
        let src4 = Ipv4Addr::new(8, 8, 8, 8); // External IPv4 source
        let dst4 = Ipv4Addr::new(10, 0, 0, 1); // NAT64 server IP (was destination)
        let src6: Ipv6Addr = "64:ff9b::8.8.8.8".parse().unwrap(); // NAT64-embedded source
        let dst6: Ipv6Addr = "fd00::2".parse().unwrap(); // Client IPv6
        let protocol = 17; // UDP
        let payload_len: u16 = 100;

        let test_checksums: [u16; 8] = [
            0x0000, 0xFFFF, 0x0001, 0xFFFE, 0x1234, 0xABCD, 0x8000, 0x5A5A,
        ];

        for original in test_checksums {
            // Apply 4to6 translation (IPv4 -> IPv6)
            let after_4to6 = adjust_checksum_4to6(
                original, src4, dst4, src6, dst6, protocol, payload_len,
            );

            if original == 0 {
                assert!(
                    after_4to6.is_none(),
                    "UDP zero checksum should require full recompute"
                );
                continue;
            }

            let after_4to6 = after_4to6.expect("UDP non-zero checksum should adjust");

            // Apply 6to4 translation (IPv6 -> IPv4) - reverse direction
            let after_6to4 = adjust_checksum_6to4(
                after_4to6, src6, dst6, src4, dst4, protocol, payload_len,
            );

            assert!(
                ones_complement_eq(after_6to4, original),
                "Round-trip 4to6->6to4 failed for original checksum 0x{:04X}: \
                 4to6 gave 0x{:04X}, 6to4 gave 0x{:04X}",
                original, after_4to6, after_6to4
            );
        }
    }

    #[test]
    fn test_adjust_checksum_with_different_protocols_and_lengths() {
        // Test round-trip with different protocol numbers and payload lengths
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "64:ff9b::192.0.2.1".parse().unwrap();
        let src4 = Ipv4Addr::new(203, 0, 113, 1);
        let dst4 = Ipv4Addr::new(192, 0, 2, 1);

        let test_cases: [(u8, u16); 6] = [
            (6, 20),    // TCP, minimum header
            (6, 1460),  // TCP, full segment
            (17, 8),    // UDP, minimum
            (17, 512),  // UDP, DNS-sized
            (17, 1472), // UDP, max without fragmentation
            (6, 60),    // TCP with options
        ];

        let original: u16 = 0x9ABC;

        for (protocol, payload_len) in test_cases {
            let after_6to4 = adjust_checksum_6to4(
                original, src6, dst6, src4, dst4, protocol, payload_len,
            );
            let after_4to6 = adjust_checksum_4to6(
                after_6to4, src4, dst4, src6, dst6, protocol, payload_len,
            )
            .expect("checksum adjustment should succeed for non-zero UDP/TCP checksums");

            assert_eq!(
                after_4to6, original,
                "Round-trip failed for protocol {} with payload_len {}: \
                 original=0x{:04X}, after_6to4=0x{:04X}, after_4to6=0x{:04X}",
                protocol, payload_len, original, after_6to4, after_4to6
            );
        }
    }

    #[test]
    fn test_adjust_checksum_deterministic() {
        // Verify that the same inputs always produce the same output
        let src6: Ipv6Addr = "fd00::100".parse().unwrap();
        let dst6: Ipv6Addr = "64:ff9b::1.2.3.4".parse().unwrap();
        let src4 = Ipv4Addr::new(10, 1, 1, 1);
        let dst4 = Ipv4Addr::new(1, 2, 3, 4);
        let protocol = 6;
        let payload_len: u16 = 200;
        let original: u16 = 0xBEEF;

        let result1 = adjust_checksum_6to4(original, src6, dst6, src4, dst4, protocol, payload_len);
        let result2 = adjust_checksum_6to4(original, src6, dst6, src4, dst4, protocol, payload_len);
        let result3 = adjust_checksum_6to4(original, src6, dst6, src4, dst4, protocol, payload_len);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);

        let result4 = adjust_checksum_4to6(original, src4, dst4, src6, dst6, protocol, payload_len);
        let result5 = adjust_checksum_4to6(original, src4, dst4, src6, dst6, protocol, payload_len);

        assert_eq!(result4, result5);
    }

    #[test]
    fn test_adjust_checksum_4to6_udp_zero_checksum_requires_recompute() {
        let src4 = Ipv4Addr::new(8, 8, 8, 8);
        let dst4 = Ipv4Addr::new(10, 0, 0, 1);
        let src6: Ipv6Addr = "64:ff9b::8.8.8.8".parse().unwrap();
        let dst6: Ipv6Addr = "fd00::2".parse().unwrap();
        let protocol = 17;
        let payload_len: u16 = 100;

        let result = adjust_checksum_4to6(0x0000, src4, dst4, src6, dst6, protocol, payload_len);
        assert!(result.is_none(), "UDP zero checksum must be recomputed for IPv6");
    }

    #[test]
    fn test_adjust_checksum_4to6_udp_never_returns_zero() {
        let src4 = Ipv4Addr::new(192, 168, 1, 1);
        let dst4 = Ipv4Addr::new(10, 0, 0, 1);
        let src6: Ipv6Addr = "64:ff9b::192.168.1.1".parse().unwrap();
        let dst6: Ipv6Addr = "fd00::1".parse().unwrap();
        let protocol = 17;
        let payload_len: u16 = 128;

        for original in (0u16..=u16::MAX).step_by(257) {
            let adjusted = adjust_checksum_4to6(
                original, src4, dst4, src6, dst6, protocol, payload_len,
            );

            if let Some(checksum) = adjusted {
                assert_ne!(
                    checksum, 0,
                    "adjust_checksum_4to6 must not return 0x0000 for UDP (original=0x{:04X})",
                    original
                );
            }
        }
    }

    #[test]
    fn test_adjust_checksum_6to4_udp_zero_checksum() {
        // Test that UDP zero-checksum is preserved (means "no checksum" in IPv4)
        let src6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst6: Ipv6Addr = "64:ff9b::8.8.8.8".parse().unwrap();
        let src4 = Ipv4Addr::new(10, 0, 0, 1);
        let dst4 = Ipv4Addr::new(8, 8, 8, 8);
        let udp_protocol = 17;
        let tcp_protocol = 6;
        let payload_len: u16 = 100;

        // UDP with zero checksum should return zero (preserves "no checksum" semantics)
        let result = adjust_checksum_6to4(0x0000, src6, dst6, src4, dst4, udp_protocol, payload_len);
        assert_eq!(result, 0x0000, "UDP zero checksum should be preserved");

        // TCP with zero checksum should NOT return zero (TCP checksum is always required)
        let result = adjust_checksum_6to4(0x0000, src6, dst6, src4, dst4, tcp_protocol, payload_len);
        assert_ne!(result, 0x0000, "TCP zero checksum should be adjusted, not preserved");

        // UDP with non-zero checksum should be adjusted normally
        let result = adjust_checksum_6to4(0x1234, src6, dst6, src4, dst4, udp_protocol, payload_len);
        assert_ne!(result, 0x1234, "UDP non-zero checksum should be adjusted");
    }
}
