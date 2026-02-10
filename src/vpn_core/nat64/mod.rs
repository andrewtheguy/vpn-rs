//! NAT64 translation module for IPv6-only clients to access IPv4 resources.
//!
//! This module implements RFC 6146 (Stateful NAT64) translation, allowing IPv6-only
//! VPN clients to access IPv4 destinations through the well-known NAT64 prefix
//! `64:ff9b::/96`.
//!
//! # Architecture
//!
//! ```text
//! IPv6 Client                     NAT64 Translator                IPv4 Destination
//!     │                                 │                               │
//!     │  IPv6 packet to                 │                               │
//!     │  64:ff9b::192.168.1.1           │                               │
//!     ├────────────────────────────────>│                               │
//!     │                                 │  IPv4 packet to               │
//!     │                                 │  192.168.1.1                  │
//!     │                                 │  (NAPT: src port translated)  │
//!     │                                 ├──────────────────────────────>│
//!     │                                 │                               │
//!     │                                 │  IPv4 response                │
//!     │                                 │<──────────────────────────────┤
//!     │  IPv6 response from             │                               │
//!     │  64:ff9b::192.168.1.1           │                               │
//!     │<────────────────────────────────┤                               │
//! ```
//!
//! # Protocol Support
//!
//! - TCP: Full connection tracking with configurable timeout
//! - UDP: Session tracking with configurable timeout
//! - ICMP/ICMPv6: Echo request/reply translation with identifier mapping

mod checksum;
mod clock;
mod state;
mod translator;

pub use state::Nat64StateTable;
pub use translator::{Nat64TranslateResult, Nat64Translator};

/// The well-known NAT64 prefix (RFC 6052).
/// IPv6 addresses in this range embed IPv4 addresses in the last 32 bits.
pub const NAT64_PREFIX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// The well-known NAT64 prefix as a CIDR string for display/logging purposes.
pub const NAT64_PREFIX_CIDR: &str = "64:ff9b::/96";

/// Check if an IPv6 address is in the NAT64 prefix `64:ff9b::/96`.
#[inline]
pub fn is_nat64_address(addr: &std::net::Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[..12] == NAT64_PREFIX
}

/// Extract the embedded IPv4 address from a NAT64 IPv6 address.
/// Returns None if the address is not in the NAT64 prefix.
#[inline]
pub fn extract_ipv4_from_nat64(addr: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if !is_nat64_address(addr) {
        return None;
    }
    let octets = addr.octets();
    Some(std::net::Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

/// Embed an IPv4 address into a NAT64 IPv6 address.
#[inline]
pub fn embed_ipv4_in_nat64(addr: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
    let v4_octets = addr.octets();
    std::net::Ipv6Addr::new(
        0x0064,
        0xff9b,
        0,
        0,
        0,
        0,
        u16::from_be_bytes([v4_octets[0], v4_octets[1]]),
        u16::from_be_bytes([v4_octets[2], v4_octets[3]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_nat64_address() {
        // Valid NAT64 addresses
        assert!(is_nat64_address(
            &"64:ff9b::192.168.1.1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(is_nat64_address(
            &"64:ff9b::8.8.8.8".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(is_nat64_address(
            &"64:ff9b::0.0.0.0".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(is_nat64_address(
            &"64:ff9b::255.255.255.255".parse::<Ipv6Addr>().unwrap()
        ));

        // Non-NAT64 addresses
        assert!(!is_nat64_address(&"::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!is_nat64_address(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!is_nat64_address(
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_nat64_address(
            &"64:ff9a::1".parse::<Ipv6Addr>().unwrap()
        )); // Wrong prefix byte
    }

    #[test]
    fn test_extract_ipv4_from_nat64() {
        // Valid extractions
        assert_eq!(
            extract_ipv4_from_nat64(&"64:ff9b::192.168.1.1".parse::<Ipv6Addr>().unwrap()),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            extract_ipv4_from_nat64(&"64:ff9b::8.8.8.8".parse::<Ipv6Addr>().unwrap()),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(
            extract_ipv4_from_nat64(&"64:ff9b::10.0.0.1".parse::<Ipv6Addr>().unwrap()),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );

        // Non-NAT64 addresses return None
        assert_eq!(
            extract_ipv4_from_nat64(&"fd00::1".parse::<Ipv6Addr>().unwrap()),
            None
        );
    }

    #[test]
    fn test_embed_ipv4_in_nat64() {
        assert_eq!(
            embed_ipv4_in_nat64(Ipv4Addr::new(192, 168, 1, 1)),
            "64:ff9b::192.168.1.1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            embed_ipv4_in_nat64(Ipv4Addr::new(8, 8, 8, 8)),
            "64:ff9b::8.8.8.8".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            embed_ipv4_in_nat64(Ipv4Addr::new(10, 0, 0, 1)),
            "64:ff9b::10.0.0.1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn test_roundtrip() {
        let v4_addrs = [
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        ];

        for v4 in v4_addrs {
            let v6 = embed_ipv4_in_nat64(v4);
            assert!(is_nat64_address(&v6));
            assert_eq!(extract_ipv4_from_nat64(&v6), Some(v4));
        }
    }
}
