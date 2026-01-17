//! NAT64 packet translator.
//!
//! This module provides the core translation logic for converting between
//! IPv6 packets (using the NAT64 prefix) and IPv4 packets.

use super::checksum::{
    adjust_checksum_4to6, adjust_checksum_6to4, compute_checksum, ipv4_header_checksum,
};
use super::state::{Nat64Protocol, Nat64StateTable};
use super::{embed_ipv4_in_nat64, extract_ipv4_from_nat64, is_nat64_address};
use crate::config::Nat64Config;
use crate::error::{VpnError, VpnResult};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Result of an IPv4-to-IPv6 NAT64 translation attempt.
#[derive(Debug)]
pub enum Nat64TranslateResult {
    /// Packet was successfully translated to IPv6.
    Translated {
        /// The IPv6 address of the client to route this packet to.
        client_ip6: Ipv6Addr,
        /// The translated IPv6 packet.
        packet: Vec<u8>,
    },
    /// Packet is not a NAT64 response (no mapping found or not destined for NAT64).
    /// This is normal for IPv4 packets that aren't responses to NAT64-translated traffic.
    NotNat64Packet,
}
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// IPv4 header size (without options).
const IPV4_HEADER_SIZE: usize = 20;

/// IPv6 header size (fixed).
const IPV6_HEADER_SIZE: usize = 40;

/// Minimum TCP header size.
const TCP_HEADER_MIN_SIZE: usize = 20;

/// Minimum UDP header size.
const UDP_HEADER_SIZE: usize = 8;

/// ICMP header minimum size.
const ICMP_HEADER_MIN_SIZE: usize = 8;

/// ICMPv6 echo request type.
const ICMPV6_ECHO_REQUEST: u8 = 128;

/// ICMPv6 echo reply type.
const ICMPV6_ECHO_REPLY: u8 = 129;

/// ICMPv4 echo request type.
const ICMPV4_ECHO_REQUEST: u8 = 8;

/// ICMPv4 echo reply type.
const ICMPV4_ECHO_REPLY: u8 = 0;

/// Default cleanup interval for expired NAT64 state entries (60 seconds).
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// NAT64 translator for converting between IPv6 and IPv4 packets.
pub struct Nat64Translator {
    /// NAT64 state table for connection tracking.
    state: Nat64StateTable,
    /// Server's IPv4 address (used as source for outbound IPv4 packets).
    server_ip4: Ipv4Addr,
    /// Last cleanup time.
    last_cleanup: RwLock<Instant>,
    /// Cleanup interval.
    cleanup_interval: Duration,
}

impl Nat64Translator {
    /// Create a new NAT64 translator.
    ///
    /// `server_ip4` is the IPv4 address that will be used as the source
    /// for translated IPv4 packets (NAPT).
    pub fn new(config: &Nat64Config, server_ip4: Ipv4Addr) -> Self {
        Self {
            state: Nat64StateTable::new(config),
            server_ip4,
            last_cleanup: RwLock::new(Instant::now()),
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        }
    }

    /// Check if a destination IPv6 address should be NAT64 translated.
    #[inline]
    pub fn is_nat64_dest(dest: &Ipv6Addr) -> bool {
        is_nat64_address(dest)
    }

    /// Translate an IPv6 packet to IPv4.
    ///
    /// Returns the translated IPv4 packet if successful.
    /// The source address is translated to `server_ip4` with NAPT.
    ///
    /// Note: IPv6 extension headers are not parsed. `next_header` is treated
    /// as the transport protocol, so packets with extension headers may be
    /// rejected as unsupported.
    pub fn translate_6to4(&self, ipv6_packet: &[u8]) -> VpnResult<Vec<u8>> {
        // Validate minimum IPv6 header size
        if ipv6_packet.len() < IPV6_HEADER_SIZE {
            return Err(VpnError::Nat64("IPv6 packet too short".into()));
        }

        // Parse IPv6 header
        let version = ipv6_packet[0] >> 4;
        if version != 6 {
            return Err(VpnError::Nat64(format!(
                "Not an IPv6 packet: version {}",
                version
            )));
        }

        let payload_length = u16::from_be_bytes([ipv6_packet[4], ipv6_packet[5]]) as usize;
        let next_header = ipv6_packet[6];
        let hop_limit = ipv6_packet[7];

        // Extract source and destination IPv6 addresses
        let src_ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_packet[8..24]).unwrap());
        let dst_ip6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_packet[24..40]).unwrap());

        // Extract embedded IPv4 destination from NAT64 address
        let dst_ip4 = extract_ipv4_from_nat64(&dst_ip6).ok_or_else(|| {
            VpnError::Nat64(format!(
                "Destination {} is not a NAT64 address",
                dst_ip6
            ))
        })?;

        // Get protocol (extension headers are not parsed here).
        let protocol = match Nat64Protocol::from_ipv6_next_header(next_header) {
            Some(protocol) => protocol,
            None => {
                let ext_header_name = match next_header {
                    0 => Some("Hop-by-Hop Options"),
                    43 => Some("Routing"),
                    44 => Some("Fragment"),
                    50 => Some("ESP"),
                    51 => Some("AH"),
                    60 => Some("Destination Options"),
                    135 => Some("Mobility"),
                    139 => Some("HIP"),
                    140 => Some("Shim6"),
                    _ => None,
                };

                if let Some(name) = ext_header_name {
                    return Err(VpnError::Nat64(format!(
                        "IPv6 extension header {} ({}) not supported (transport header not parsed)",
                        next_header, name
                    )));
                }

                return Err(VpnError::Nat64UnsupportedProtocol(next_header));
            }
        };

        // Get payload
        let payload_start = IPV6_HEADER_SIZE;
        let payload_end = payload_start + payload_length;
        if ipv6_packet.len() < payload_end {
            return Err(VpnError::Nat64("IPv6 packet truncated".into()));
        }
        let payload = &ipv6_packet[payload_start..payload_end];

        // Perform periodic cleanup
        self.maybe_cleanup().ok();

        // Translate based on protocol
        // TTL is decremented per RFC 6146 Section 4
        let ttl = hop_limit.saturating_sub(1);

        // Drop packet if TTL would be 0 (RFC 6146: must not forward with TTL=0)
        // In a full implementation, we would send ICMPv6 Time Exceeded back to source.
        if ttl == 0 {
            return Err(VpnError::Nat64("Hop limit expired (would be 0 after decrement)".into()));
        }

        match protocol {
            Nat64Protocol::Tcp => {
                self.translate_tcp_6to4(src_ip6, dst_ip4, payload, payload_length as u16, ttl)
            }
            Nat64Protocol::Udp => {
                self.translate_udp_6to4(src_ip6, dst_ip4, payload, payload_length as u16, ttl)
            }
            Nat64Protocol::Icmp => self.translate_icmp_6to4(src_ip6, dst_ip4, payload, ttl),
        }
    }

    /// Translate an IPv4 packet to IPv6.
    ///
    /// Returns `Nat64TranslateResult::Translated` with the destination client IPv6 and
    /// translated packet if successful, or `Nat64TranslateResult::NotNat64Packet` if
    /// this packet is not a NAT64 response (no mapping found or not destined for NAT64).
    pub fn translate_4to6(&self, ipv4_packet: &[u8]) -> VpnResult<Nat64TranslateResult> {
        // Validate minimum IPv4 header size
        if ipv4_packet.len() < IPV4_HEADER_SIZE {
            return Err(VpnError::Nat64("IPv4 packet too short".into()));
        }

        // Parse IPv4 header
        let version_ihl = ipv4_packet[0];
        let version = version_ihl >> 4;
        if version != 4 {
            return Err(VpnError::Nat64(format!(
                "Not an IPv4 packet: version {}",
                version
            )));
        }

        let ihl = (version_ihl & 0x0F) as usize * 4;
        if ihl < IPV4_HEADER_SIZE || ipv4_packet.len() < ihl {
            return Err(VpnError::Nat64("Invalid IPv4 header length".into()));
        }

        let total_length = u16::from_be_bytes([ipv4_packet[2], ipv4_packet[3]]) as usize;
        let protocol = ipv4_packet[9];
        let ttl = ipv4_packet[8];

        // Extract source and destination IPv4 addresses
        let src_ip4 = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[12..16]).unwrap());
        let dst_ip4 = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[16..20]).unwrap());

        // If packet is not destined for our NAT64 address, it's not a NAT64 response
        if dst_ip4 != self.server_ip4 {
            return Ok(Nat64TranslateResult::NotNat64Packet);
        }

        // Get protocol
        let nat64_protocol = Nat64Protocol::from_ipv4_protocol(protocol)
            .ok_or(VpnError::Nat64UnsupportedProtocol(protocol))?;

        // Validate total_length and extract payload
        // Check for truncated packet (total_length claims more data than we have)
        if total_length > ipv4_packet.len() {
            return Err(VpnError::Nat64(format!(
                "IPv4 packet truncated: total_length {} but buffer is {} bytes",
                total_length,
                ipv4_packet.len()
            )));
        }
        // Check that total_length is at least as large as the header
        if total_length < ihl {
            return Err(VpnError::Nat64(format!(
                "IPv4 total_length {} is less than header length {}",
                total_length, ihl
            )));
        }

        let payload = &ipv4_packet[ihl..total_length];
        let payload_length = payload.len() as u16;

        // Translate based on protocol
        // Hop limit is decremented per RFC 6146 Section 4
        let hop_limit = ttl.saturating_sub(1);

        // Drop packet if hop limit would be 0 (RFC 6146: must not forward with hop_limit=0)
        // In a full implementation, we would send ICMP Time Exceeded back to source.
        if hop_limit == 0 {
            return Err(VpnError::Nat64("TTL expired (would be 0 after decrement)".into()));
        }

        match nat64_protocol {
            Nat64Protocol::Tcp => self.translate_tcp_4to6(src_ip4, payload, payload_length, hop_limit),
            Nat64Protocol::Udp => self.translate_udp_4to6(src_ip4, payload, payload_length, hop_limit),
            Nat64Protocol::Icmp => self.translate_icmp_4to6(src_ip4, payload, hop_limit),
        }
    }

    /// Translate TCP from IPv6 to IPv4.
    fn translate_tcp_6to4(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip4: Ipv4Addr,
        tcp_payload: &[u8],
        payload_len: u16,
        ttl: u8,
    ) -> VpnResult<Vec<u8>> {
        if tcp_payload.len() < TCP_HEADER_MIN_SIZE {
            return Err(VpnError::Nat64("TCP segment too short".into()));
        }

        let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
        let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
        let old_checksum = u16::from_be_bytes([tcp_payload[16], tcp_payload[17]]);

        // Get or create NAT mapping
        let translated_port =
            self.state
                .get_or_create_mapping(src_ip6, src_port, dst_ip4, dst_port, Nat64Protocol::Tcp)?;

        // Build IPv4 packet
        self.build_ipv4_packet(
            dst_ip4,
            6, // TCP
            tcp_payload,
            src_port,
            translated_port,
            old_checksum,
            payload_len,
            src_ip6,
            embed_ipv4_in_nat64(dst_ip4),
            ttl,
        )
    }

    /// Translate UDP from IPv6 to IPv4.
    fn translate_udp_6to4(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip4: Ipv4Addr,
        udp_payload: &[u8],
        payload_len: u16,
        ttl: u8,
    ) -> VpnResult<Vec<u8>> {
        if udp_payload.len() < UDP_HEADER_SIZE {
            return Err(VpnError::Nat64("UDP datagram too short".into()));
        }

        let src_port = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
        let dst_port = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
        let old_checksum = u16::from_be_bytes([udp_payload[6], udp_payload[7]]);

        // Get or create NAT mapping
        let translated_port =
            self.state
                .get_or_create_mapping(src_ip6, src_port, dst_ip4, dst_port, Nat64Protocol::Udp)?;

        // Build IPv4 packet
        self.build_ipv4_packet(
            dst_ip4,
            17, // UDP
            udp_payload,
            src_port,
            translated_port,
            old_checksum,
            payload_len,
            src_ip6,
            embed_ipv4_in_nat64(dst_ip4),
            ttl,
        )
    }

    /// Translate ICMPv6 to ICMPv4.
    fn translate_icmp_6to4(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip4: Ipv4Addr,
        icmp_payload: &[u8],
        ttl: u8,
    ) -> VpnResult<Vec<u8>> {
        if icmp_payload.len() < ICMP_HEADER_MIN_SIZE {
            return Err(VpnError::Nat64("ICMPv6 message too short".into()));
        }

        let icmp_type = icmp_payload[0];
        let _icmp_code = icmp_payload[1];

        // Only translate echo request/reply for now
        let icmpv4_type = match icmp_type {
            ICMPV6_ECHO_REQUEST => ICMPV4_ECHO_REQUEST,
            ICMPV6_ECHO_REPLY => ICMPV4_ECHO_REPLY,
            _ => {
                return Err(VpnError::Nat64(format!(
                    "Unsupported ICMPv6 type: {}",
                    icmp_type
                )))
            }
        };

        // ICMP identifier is at bytes 4-5
        let identifier = u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]);

        // Get or create NAT mapping (using identifier as "port")
        let translated_id = self.state.get_or_create_mapping(
            src_ip6,
            identifier,
            dst_ip4,
            0, // No destination port for ICMP
            Nat64Protocol::Icmp,
        )?;

        // Build ICMPv4 packet
        let mut icmpv4 = Vec::with_capacity(icmp_payload.len());
        icmpv4.push(icmpv4_type);
        icmpv4.push(0); // Code (same as ICMPv6 for echo)
        icmpv4.extend_from_slice(&[0, 0]); // Checksum placeholder
        icmpv4.extend_from_slice(&translated_id.to_be_bytes()); // Identifier
        icmpv4.extend_from_slice(&icmp_payload[6..]); // Sequence + data

        // Compute ICMPv4 checksum (covers entire ICMP message, no pseudo-header)
        let checksum = compute_checksum(&icmpv4);
        icmpv4[2] = (checksum >> 8) as u8;
        icmpv4[3] = checksum as u8;

        // Build IPv4 packet
        self.build_ipv4_header_with_payload(dst_ip4, 1, &icmpv4, ttl) // ICMP = 1
    }

    /// Build an IPv4 packet with translated TCP/UDP payload.
    #[allow(clippy::too_many_arguments)]
    fn build_ipv4_packet(
        &self,
        dst_ip4: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
        old_src_port: u16,
        new_src_port: u16,
        old_checksum: u16,
        payload_len: u16,
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        ttl: u8,
    ) -> VpnResult<Vec<u8>> {
        use super::checksum::update_checksum_16;

        // Create modified payload with new source port
        let mut new_payload = payload.to_vec();
        new_payload[0] = (new_src_port >> 8) as u8;
        new_payload[1] = new_src_port as u8;

        // If is_udp_zero_checksum is true (protocol == 17 && old_checksum == 0),
        // preserve a received IPv6 UDP checksum of 0 by emitting a zero checksum
        // in the IPv4 packet to keep "no checksum" semantics.
        let is_udp_zero_checksum = protocol == 17 && old_checksum == 0;

        let checksum_offset = if protocol == 6 { 16 } else { 6 }; // TCP vs UDP

        if is_udp_zero_checksum {
            // Preserve UDP zero-checksum: skip all checksum adjustments
            new_payload[checksum_offset] = 0;
            new_payload[checksum_offset + 1] = 0;
        } else {
            // Adjust checksum for pseudo-header change (IPv6 -> IPv4)
            let checksum_after_pseudo = adjust_checksum_6to4(
                old_checksum,
                src_ip6,
                dst_ip6,
                self.server_ip4,
                dst_ip4,
                protocol,
                payload_len,
            );

            // Also adjust checksum for source port change (old_src_port -> new_src_port)
            let new_checksum = update_checksum_16(checksum_after_pseudo, old_src_port, new_src_port);

            // Update checksum in payload
            new_payload[checksum_offset] = (new_checksum >> 8) as u8;
            new_payload[checksum_offset + 1] = new_checksum as u8;
        }

        self.build_ipv4_header_with_payload(dst_ip4, protocol, &new_payload, ttl)
    }

    /// Build an IPv4 header and combine with payload.
    fn build_ipv4_header_with_payload(
        &self,
        dst_ip4: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
        ttl: u8,
    ) -> VpnResult<Vec<u8>> {
        let total_length = (IPV4_HEADER_SIZE + payload.len()) as u16;

        let mut packet = Vec::with_capacity(total_length as usize);

        // IPv4 header
        packet.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&total_length.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // Identification
        packet.extend_from_slice(&[0x40, 0x00]); // Flags (DF) + Fragment offset
        packet.push(ttl); // TTL (decremented from IPv6 hop limit)
        packet.push(protocol); // Protocol
        packet.extend_from_slice(&[0x00, 0x00]); // Header checksum placeholder
        packet.extend_from_slice(&self.server_ip4.octets()); // Source IP
        packet.extend_from_slice(&dst_ip4.octets()); // Destination IP

        // Compute header checksum
        let header_checksum = ipv4_header_checksum(&packet[..IPV4_HEADER_SIZE]);
        packet[10] = (header_checksum >> 8) as u8;
        packet[11] = header_checksum as u8;

        // Append payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    /// Translate TCP from IPv4 to IPv6.
    fn translate_tcp_4to6(
        &self,
        src_ip4: Ipv4Addr,
        tcp_payload: &[u8],
        payload_len: u16,
        hop_limit: u8,
    ) -> VpnResult<Nat64TranslateResult> {
        use super::checksum::update_checksum_16;

        if tcp_payload.len() < TCP_HEADER_MIN_SIZE {
            return Err(VpnError::Nat64("TCP segment too short".into()));
        }

        let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
        let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
        let old_checksum = u16::from_be_bytes([tcp_payload[16], tcp_payload[17]]);

        // Look up the original client - if no mapping, this isn't a NAT64 response
        let (client_ip6, client_port) = match self
            .state
            .lookup_reverse(dst_port, src_ip4, src_port, Nat64Protocol::Tcp)
        {
            Some(result) => result,
            None => return Ok(Nat64TranslateResult::NotNat64Packet),
        };

        // Build IPv6 packet
        let src_ip6 = embed_ipv4_in_nat64(src_ip4);
        let dst_ip6 = client_ip6;

        // Create modified payload with original destination port
        let mut new_payload = tcp_payload.to_vec();
        new_payload[2] = (client_port >> 8) as u8;
        new_payload[3] = client_port as u8;

        // Adjust checksum for pseudo-header change (IPv4 -> IPv6)
        let checksum_after_pseudo = adjust_checksum_4to6(
            old_checksum,
            src_ip4,
            self.server_ip4,
            src_ip6,
            dst_ip6,
            6, // TCP
            payload_len,
        )
        .ok_or_else(|| {
            VpnError::Nat64("TCP checksum adjustment failed (zero checksum)".into())
        })?;

        // Also adjust checksum for destination port change (dst_port -> client_port)
        let new_checksum = update_checksum_16(checksum_after_pseudo, dst_port, client_port);

        new_payload[16] = (new_checksum >> 8) as u8;
        new_payload[17] = new_checksum as u8;

        let packet = self.build_ipv6_packet(src_ip6, dst_ip6, 6, &new_payload, hop_limit);
        Ok(Nat64TranslateResult::Translated {
            client_ip6,
            packet,
        })
    }

    /// Translate UDP from IPv4 to IPv6.
    fn translate_udp_4to6(
        &self,
        src_ip4: Ipv4Addr,
        udp_payload: &[u8],
        payload_len: u16,
        hop_limit: u8,
    ) -> VpnResult<Nat64TranslateResult> {
        use super::checksum::update_checksum_16;

        if udp_payload.len() < UDP_HEADER_SIZE {
            return Err(VpnError::Nat64("UDP datagram too short".into()));
        }

        let src_port = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
        let dst_port = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
        let old_checksum = u16::from_be_bytes([udp_payload[6], udp_payload[7]]);

        // Look up the original client - if no mapping, this isn't a NAT64 response
        let (client_ip6, client_port) = match self
            .state
            .lookup_reverse(dst_port, src_ip4, src_port, Nat64Protocol::Udp)
        {
            Some(result) => result,
            None => return Ok(Nat64TranslateResult::NotNat64Packet),
        };

        // Build IPv6 packet
        let src_ip6 = embed_ipv4_in_nat64(src_ip4);
        let dst_ip6 = client_ip6;

        // Create modified payload with original destination port
        let mut new_payload = udp_payload.to_vec();
        new_payload[2] = (client_port >> 8) as u8;
        new_payload[3] = client_port as u8;

        // Adjust checksum (handle zero checksum in UDP)
        // First adjust for pseudo-header change (IPv4 -> IPv6).
        // UDP zero-checksum returns None, which signals that we must recompute.
        let checksum_after_pseudo = adjust_checksum_4to6(
            old_checksum,
            src_ip4,
            self.server_ip4,
            src_ip6,
            dst_ip6,
            17, // UDP
            payload_len,
        );

        let new_checksum = match checksum_after_pseudo {
            Some(checksum_after_pseudo) => {
                // Also adjust checksum for destination port change (dst_port -> client_port)
                update_checksum_16(checksum_after_pseudo, dst_port, client_port)
            }
            None => {
                // UDP checksum was 0 (optional in IPv4), but mandatory in IPv6.
                // Compute it from scratch (new_payload already has client_port).
                self.compute_udp_checksum_ipv6(src_ip6, dst_ip6, &new_payload)
            }
        };

        new_payload[6] = (new_checksum >> 8) as u8;
        new_payload[7] = new_checksum as u8;

        let packet = self.build_ipv6_packet(src_ip6, dst_ip6, 17, &new_payload, hop_limit);
        Ok(Nat64TranslateResult::Translated {
            client_ip6,
            packet,
        })
    }

    /// Translate ICMPv4 to ICMPv6.
    fn translate_icmp_4to6(
        &self,
        src_ip4: Ipv4Addr,
        icmp_payload: &[u8],
        hop_limit: u8,
    ) -> VpnResult<Nat64TranslateResult> {
        if icmp_payload.len() < ICMP_HEADER_MIN_SIZE {
            return Err(VpnError::Nat64("ICMPv4 message too short".into()));
        }

        let icmp_type = icmp_payload[0];
        let _icmp_code = icmp_payload[1];

        // Only translate echo request/reply
        let icmpv6_type = match icmp_type {
            ICMPV4_ECHO_REQUEST => ICMPV6_ECHO_REQUEST,
            ICMPV4_ECHO_REPLY => ICMPV6_ECHO_REPLY,
            _ => {
                return Err(VpnError::Nat64(format!(
                    "Unsupported ICMPv4 type: {}",
                    icmp_type
                )))
            }
        };

        // ICMP identifier is at bytes 4-5
        let translated_id = u16::from_be_bytes([icmp_payload[4], icmp_payload[5]]);

        // Look up the original client - if no mapping, this isn't a NAT64 response
        let (client_ip6, original_id) = match self
            .state
            .lookup_reverse(translated_id, src_ip4, 0, Nat64Protocol::Icmp)
        {
            Some(result) => result,
            None => return Ok(Nat64TranslateResult::NotNat64Packet),
        };

        let src_ip6 = embed_ipv4_in_nat64(src_ip4);
        let dst_ip6 = client_ip6;

        // Build ICMPv6 packet
        let mut icmpv6 = Vec::with_capacity(icmp_payload.len());
        icmpv6.push(icmpv6_type);
        icmpv6.push(0); // Code
        icmpv6.extend_from_slice(&[0, 0]); // Checksum placeholder
        icmpv6.extend_from_slice(&original_id.to_be_bytes()); // Original identifier
        icmpv6.extend_from_slice(&icmp_payload[6..]); // Sequence + data

        // Compute ICMPv6 checksum (includes pseudo-header)
        let checksum = self.compute_icmpv6_checksum(src_ip6, dst_ip6, &icmpv6);
        icmpv6[2] = (checksum >> 8) as u8;
        icmpv6[3] = checksum as u8;

        let packet = self.build_ipv6_packet(src_ip6, dst_ip6, 58, &icmpv6, hop_limit); // ICMPv6 = 58
        Ok(Nat64TranslateResult::Translated {
            client_ip6,
            packet,
        })
    }

    /// Build an IPv6 packet.
    fn build_ipv6_packet(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
        hop_limit: u8,
    ) -> Vec<u8> {
        let payload_length = payload.len() as u16;

        let mut packet = Vec::with_capacity(IPV6_HEADER_SIZE + payload.len());

        // IPv6 header
        packet.push(0x60); // Version 6, traffic class 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Traffic class + flow label
        packet.extend_from_slice(&payload_length.to_be_bytes()); // Payload length
        packet.push(next_header); // Next header
        packet.push(hop_limit); // Hop limit (decremented from IPv4 TTL)
        packet.extend_from_slice(&src_ip6.octets()); // Source
        packet.extend_from_slice(&dst_ip6.octets()); // Destination

        // Append payload
        packet.extend_from_slice(payload);

        packet
    }

    /// Compute UDP checksum for IPv6 (mandatory, unlike IPv4).
    fn compute_udp_checksum_ipv6(&self, src: Ipv6Addr, dst: Ipv6Addr, udp_data: &[u8]) -> u16 {
        use super::checksum::{fold_checksum, ipv6_pseudo_header_sum, ones_complement_sum};

        let pseudo_sum = ipv6_pseudo_header_sum(src, dst, 17, udp_data.len() as u32);
        let data_sum = ones_complement_sum(udp_data);
        let total = pseudo_sum + data_sum;
        let checksum = !fold_checksum(total);

        // UDP checksum of 0 is transmitted as 0xFFFF in IPv6
        if checksum == 0 {
            0xFFFF
        } else {
            checksum
        }
    }

    /// Compute ICMPv6 checksum (includes pseudo-header).
    fn compute_icmpv6_checksum(&self, src: Ipv6Addr, dst: Ipv6Addr, icmp_data: &[u8]) -> u16 {
        use super::checksum::{fold_checksum, ipv6_pseudo_header_sum, ones_complement_sum};

        let pseudo_sum = ipv6_pseudo_header_sum(src, dst, 58, icmp_data.len() as u32);
        let data_sum = ones_complement_sum(icmp_data);
        let total = pseudo_sum + data_sum;
        !fold_checksum(total)
    }

    /// Perform cleanup if enough time has passed.
    fn maybe_cleanup(&self) -> VpnResult<()> {
        // Try to acquire read lock to check time
        if let Ok(last) = self.last_cleanup.try_read() {
            if last.elapsed() < self.cleanup_interval {
                return Ok(());
            }
        }

        // Time to cleanup - try to acquire write lock
        if let Ok(mut last) = self.last_cleanup.try_write() {
            // Double-check after acquiring write lock
            if last.elapsed() >= self.cleanup_interval {
                let removed = self.state.cleanup_expired();
                if removed > 0 {
                    log::debug!("NAT64: cleaned up {} expired mappings", removed);
                }
                *last = Instant::now();
            }
        }

        Ok(())
    }

    /// Get the number of active NAT64 mappings.
    pub fn active_mappings(&self) -> usize {
        self.state.active_mappings()
    }

    /// Force cleanup of expired entries.
    pub fn cleanup(&self) -> usize {
        self.state.cleanup_expired()
    }
}

/// Create a NAT64 translator from config.
#[allow(dead_code)]
pub fn create_nat64_translator(
    config: &Nat64Config,
    server_ip4: Ipv4Addr,
) -> Option<Arc<Nat64Translator>> {
    if config.enabled {
        Some(Arc::new(Nat64Translator::new(config, server_ip4)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Nat64Config {
        Nat64Config {
            enabled: true,
            port_range: (10000, 10100),
            tcp_timeout_secs: 300,
            udp_timeout_secs: 30,
            icmp_timeout_secs: 30,
            source_ip: None,
        }
    }

    #[test]
    fn test_is_nat64_dest() {
        assert!(Nat64Translator::is_nat64_dest(
            &"64:ff9b::8.8.8.8".parse().unwrap()
        ));
        assert!(!Nat64Translator::is_nat64_dest(
            &"fd00::1".parse().unwrap()
        ));
    }

    #[test]
    fn test_build_ipv6_packet() {
        let translator = Nat64Translator::new(&test_config(), Ipv4Addr::new(10, 0, 0, 1));

        let src: Ipv6Addr = "64:ff9b::8.8.8.8".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let payload = vec![0x12, 0x34, 0x56, 0x78];
        let hop_limit = 63u8;

        let packet = translator.build_ipv6_packet(src, dst, 17, &payload, hop_limit);

        // Verify header
        assert_eq!(packet[0] >> 4, 6); // Version
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]),
            payload.len() as u16
        ); // Payload length
        assert_eq!(packet[6], 17); // Next header (UDP)
        assert_eq!(packet[7], hop_limit); // Hop limit

        // Verify addresses
        let src_from_packet = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
        let dst_from_packet = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        assert_eq!(src_from_packet, src);
        assert_eq!(dst_from_packet, dst);

        // Verify payload
        assert_eq!(&packet[40..], &payload[..]);
    }

    #[test]
    fn test_translate_6to4_too_short() {
        let translator = Nat64Translator::new(&test_config(), Ipv4Addr::new(10, 0, 0, 1));

        // Too short for IPv6 header
        let short_packet = vec![0x60; 20];
        assert!(translator.translate_6to4(&short_packet).is_err());
    }

    #[test]
    fn test_translate_6to4_not_ipv6() {
        let translator = Nat64Translator::new(&test_config(), Ipv4Addr::new(10, 0, 0, 1));

        // IPv4 packet (version 4)
        let mut packet = vec![0; 40];
        packet[0] = 0x45; // IPv4 version
        assert!(translator.translate_6to4(&packet).is_err());
    }

    #[test]
    fn test_translate_6to4_not_nat64() {
        let translator = Nat64Translator::new(&test_config(), Ipv4Addr::new(10, 0, 0, 1));

        // Valid IPv6 packet but destination is not NAT64
        let mut packet = vec![0; 60];
        packet[0] = 0x60; // IPv6 version
        packet[4] = 0x00;
        packet[5] = 0x14; // Payload length = 20
        packet[6] = 6; // TCP

        // Source: fd00::2
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        packet[8..24].copy_from_slice(&src.octets());

        // Destination: fd00::1 (not NAT64)
        let dst: Ipv6Addr = "fd00::1".parse().unwrap();
        packet[24..40].copy_from_slice(&dst.octets());

        assert!(translator.translate_6to4(&packet).is_err());
    }

    /// Helper to build a valid IPv6 UDP packet for testing.
    fn build_test_ipv6_udp_packet(
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use super::super::checksum::{fold_checksum, ipv6_pseudo_header_sum, ones_complement_sum};

        let udp_len = 8 + payload.len();
        let mut udp = Vec::with_capacity(udp_len);

        // UDP header
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // Checksum placeholder
        udp.extend_from_slice(payload);

        // Compute UDP checksum with IPv6 pseudo-header
        let pseudo_sum = ipv6_pseudo_header_sum(src_ip6, dst_ip6, 17, udp_len as u32);
        let data_sum = ones_complement_sum(&udp);
        let checksum = !fold_checksum(pseudo_sum + data_sum);
        let checksum = if checksum == 0 { 0xFFFF } else { checksum };
        udp[6] = (checksum >> 8) as u8;
        udp[7] = checksum as u8;

        // Build IPv6 packet
        let mut packet = Vec::with_capacity(40 + udp_len);
        packet.push(0x60); // Version 6
        packet.extend_from_slice(&[0, 0, 0]); // Traffic class + flow label
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.push(17); // UDP
        packet.push(64); // Hop limit
        packet.extend_from_slice(&src_ip6.octets());
        packet.extend_from_slice(&dst_ip6.octets());
        packet.extend_from_slice(&udp);

        packet
    }

    /// Helper to build a valid IPv6 TCP packet for testing.
    fn build_test_ipv6_tcp_packet(
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use super::super::checksum::{fold_checksum, ipv6_pseudo_header_sum, ones_complement_sum};

        let tcp_header_len = 20; // Minimum TCP header
        let tcp_len = tcp_header_len + payload.len();
        let mut tcp = Vec::with_capacity(tcp_len);

        // TCP header (minimum 20 bytes)
        tcp.extend_from_slice(&src_port.to_be_bytes()); // Source port
        tcp.extend_from_slice(&dst_port.to_be_bytes()); // Dest port
        tcp.extend_from_slice(&0u32.to_be_bytes()); // Sequence number
        tcp.extend_from_slice(&0u32.to_be_bytes()); // Ack number
        tcp.push(0x50); // Data offset (5 * 4 = 20 bytes) + reserved
        tcp.push(0x02); // Flags (SYN)
        tcp.extend_from_slice(&1024u16.to_be_bytes()); // Window
        tcp.extend_from_slice(&[0, 0]); // Checksum placeholder
        tcp.extend_from_slice(&[0, 0]); // Urgent pointer
        tcp.extend_from_slice(payload);

        // Compute TCP checksum with IPv6 pseudo-header
        let pseudo_sum = ipv6_pseudo_header_sum(src_ip6, dst_ip6, 6, tcp_len as u32);
        let data_sum = ones_complement_sum(&tcp);
        let checksum = !fold_checksum(pseudo_sum + data_sum);
        tcp[16] = (checksum >> 8) as u8;
        tcp[17] = checksum as u8;

        // Build IPv6 packet
        let mut packet = Vec::with_capacity(40 + tcp_len);
        packet.push(0x60); // Version 6
        packet.extend_from_slice(&[0, 0, 0]); // Traffic class + flow label
        packet.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        packet.push(6); // TCP
        packet.push(64); // Hop limit
        packet.extend_from_slice(&src_ip6.octets());
        packet.extend_from_slice(&dst_ip6.octets());
        packet.extend_from_slice(&tcp);

        packet
    }

    /// Helper to build a valid IPv6 ICMPv6 echo request packet for testing.
    fn build_test_ipv6_icmp_echo_packet(
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use super::super::checksum::{fold_checksum, ipv6_pseudo_header_sum, ones_complement_sum};

        let icmp_len = 8 + payload.len();
        let mut icmp = Vec::with_capacity(icmp_len);

        // ICMPv6 echo request
        icmp.push(ICMPV6_ECHO_REQUEST); // Type
        icmp.push(0); // Code
        icmp.extend_from_slice(&[0, 0]); // Checksum placeholder
        icmp.extend_from_slice(&identifier.to_be_bytes());
        icmp.extend_from_slice(&sequence.to_be_bytes());
        icmp.extend_from_slice(payload);

        // Compute ICMPv6 checksum with pseudo-header
        let pseudo_sum = ipv6_pseudo_header_sum(src_ip6, dst_ip6, 58, icmp_len as u32);
        let data_sum = ones_complement_sum(&icmp);
        let checksum = !fold_checksum(pseudo_sum + data_sum);
        icmp[2] = (checksum >> 8) as u8;
        icmp[3] = checksum as u8;

        // Build IPv6 packet
        let mut packet = Vec::with_capacity(40 + icmp_len);
        packet.push(0x60); // Version 6
        packet.extend_from_slice(&[0, 0, 0]); // Traffic class + flow label
        packet.extend_from_slice(&(icmp_len as u16).to_be_bytes());
        packet.push(58); // ICMPv6
        packet.push(64); // Hop limit
        packet.extend_from_slice(&src_ip6.octets());
        packet.extend_from_slice(&dst_ip6.octets());
        packet.extend_from_slice(&icmp);

        packet
    }

    #[test]
    fn test_translate_udp_6to4_success() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4); // 64:ff9b::8.8.8.8

        let src_port = 54321u16;
        let dst_port = 53u16;
        let payload = b"test dns query";

        let ipv6_packet =
            build_test_ipv6_udp_packet(client_ip6, dest_ip6, src_port, dst_port, payload);

        // Translate IPv6 -> IPv4
        let ipv4_packet = translator.translate_6to4(&ipv6_packet).unwrap();

        // Verify IPv4 header
        assert_eq!(ipv4_packet[0] >> 4, 4); // Version 4
        assert_eq!(ipv4_packet[9], 17); // Protocol = UDP

        // Verify source IP is server's IP (NAPT)
        let src_ip4_result = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[12..16]).unwrap());
        assert_eq!(src_ip4_result, server_ip4);

        // Verify destination IP
        let dst_ip4_result = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[16..20]).unwrap());
        assert_eq!(dst_ip4_result, dest_ip4);

        // Verify UDP payload destination port unchanged
        let udp_start = 20; // IPv4 header size
        let udp_dst_port =
            u16::from_be_bytes([ipv4_packet[udp_start + 2], ipv4_packet[udp_start + 3]]);
        assert_eq!(udp_dst_port, dst_port);

        // Verify payload
        let payload_start = udp_start + 8;
        assert_eq!(&ipv4_packet[payload_start..], payload);

        // Verify a NAT mapping was created
        assert_eq!(translator.active_mappings(), 1);
    }

    #[test]
    fn test_translate_tcp_6to4_success() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(93, 184, 216, 34); // example.com
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let src_port = 45678u16;
        let dst_port = 80u16;
        let payload = b"";

        let ipv6_packet =
            build_test_ipv6_tcp_packet(client_ip6, dest_ip6, src_port, dst_port, payload);

        // Translate IPv6 -> IPv4
        let ipv4_packet = translator.translate_6to4(&ipv6_packet).unwrap();

        // Verify IPv4 header
        assert_eq!(ipv4_packet[0] >> 4, 4); // Version 4
        assert_eq!(ipv4_packet[9], 6); // Protocol = TCP

        // Verify source IP is server's IP (NAPT)
        let src_ip4_result = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[12..16]).unwrap());
        assert_eq!(src_ip4_result, server_ip4);

        // Verify destination IP
        let dst_ip4_result = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[16..20]).unwrap());
        assert_eq!(dst_ip4_result, dest_ip4);

        // Verify TCP destination port unchanged
        let tcp_start = 20;
        let tcp_dst_port =
            u16::from_be_bytes([ipv4_packet[tcp_start + 2], ipv4_packet[tcp_start + 3]]);
        assert_eq!(tcp_dst_port, dst_port);

        // Verify a NAT mapping was created
        assert_eq!(translator.active_mappings(), 1);
    }

    #[test]
    fn test_translate_icmp_6to4_success() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let identifier = 1234u16;
        let sequence = 1u16;
        let payload = b"ping data";

        let ipv6_packet =
            build_test_ipv6_icmp_echo_packet(client_ip6, dest_ip6, identifier, sequence, payload);

        // Translate IPv6 -> IPv4
        let ipv4_packet = translator.translate_6to4(&ipv6_packet).unwrap();

        // Verify IPv4 header
        assert_eq!(ipv4_packet[0] >> 4, 4); // Version 4
        assert_eq!(ipv4_packet[9], 1); // Protocol = ICMP

        // Verify ICMP type is echo request (8 for ICMPv4)
        let icmp_start = 20;
        assert_eq!(ipv4_packet[icmp_start], ICMPV4_ECHO_REQUEST);

        // Verify sequence number is preserved
        let icmp_seq =
            u16::from_be_bytes([ipv4_packet[icmp_start + 6], ipv4_packet[icmp_start + 7]]);
        assert_eq!(icmp_seq, sequence);

        // Verify payload
        let payload_start = icmp_start + 8;
        assert_eq!(&ipv4_packet[payload_start..], payload);

        // Verify a NAT mapping was created
        assert_eq!(translator.active_mappings(), 1);
    }

    #[test]
    fn test_translate_udp_roundtrip() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let src_port = 54321u16;
        let dst_port = 53u16;
        let payload = b"dns query payload";

        // Step 1: Client sends IPv6 packet to NAT64 destination
        let ipv6_packet =
            build_test_ipv6_udp_packet(client_ip6, dest_ip6, src_port, dst_port, payload);
        let original_hop_limit = ipv6_packet[7]; // Hop limit is at offset 7 in IPv6 header
        let ipv4_outbound = translator.translate_6to4(&ipv6_packet).unwrap();

        // Verify TTL is decremented (RFC 6146 Section 4)
        let ipv4_ttl = ipv4_outbound[8]; // TTL is at offset 8 in IPv4 header
        assert_eq!(
            ipv4_ttl,
            original_hop_limit - 1,
            "IPv4 TTL should be IPv6 hop limit - 1"
        );

        // Extract the translated source port (NAPT port)
        let udp_start = 20;
        let translated_port =
            u16::from_be_bytes([ipv4_outbound[udp_start], ipv4_outbound[udp_start + 1]]);
        assert!((10000..=10100).contains(&translated_port));

        // Step 2: Simulate response from IPv4 destination
        // Build an IPv4 UDP response packet
        let response_payload = b"dns response";
        let ipv4_response = build_test_ipv4_udp_packet(
            dest_ip4,     // Source is original dest
            server_ip4,   // Dest is server's NAPT address
            dst_port,     // Source port is original dest port
            translated_port, // Dest port is the translated NAPT port
            response_payload,
        );
        let original_ipv4_ttl = ipv4_response[8]; // TTL is at offset 8 in IPv4 header

        // Step 3: Translate response back to IPv6
        let result = translator.translate_4to6(&ipv4_response).unwrap();
        let (returned_client, ipv6_response) = match result {
            Nat64TranslateResult::Translated { client_ip6, packet } => (client_ip6, packet),
            Nat64TranslateResult::NotNat64Packet => panic!("Expected translated packet"),
        };

        // Verify the response goes to the correct client
        assert_eq!(returned_client, client_ip6);

        // Verify IPv6 header
        assert_eq!(ipv6_response[0] >> 4, 6); // Version 6
        assert_eq!(ipv6_response[6], 17); // Next header = UDP

        // Verify hop limit is decremented (RFC 6146 Section 4)
        let ipv6_hop_limit = ipv6_response[7]; // Hop limit is at offset 7 in IPv6 header
        assert_eq!(
            ipv6_hop_limit,
            original_ipv4_ttl - 1,
            "IPv6 hop limit should be IPv4 TTL - 1"
        );

        // Verify source is NAT64 address of original destination
        let src_from_response =
            Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_response[8..24]).unwrap());
        assert_eq!(src_from_response, dest_ip6);

        // Verify destination is original client
        let dst_from_response =
            Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_response[24..40]).unwrap());
        assert_eq!(dst_from_response, client_ip6);

        // Verify UDP ports are restored
        let udp6_start = 40;
        let udp_src = u16::from_be_bytes([ipv6_response[udp6_start], ipv6_response[udp6_start + 1]]);
        let udp_dst =
            u16::from_be_bytes([ipv6_response[udp6_start + 2], ipv6_response[udp6_start + 3]]);
        assert_eq!(udp_src, dst_port); // Source was original dest port
        assert_eq!(udp_dst, src_port); // Dest is original client port

        // Verify payload
        let payload6_start = udp6_start + 8;
        assert_eq!(&ipv6_response[payload6_start..], response_payload);
    }

    #[test]
    fn test_translate_tcp_roundtrip() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::3".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(93, 184, 216, 34);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let src_port = 45678u16;
        let dst_port = 443u16;

        // Step 1: Client sends TCP SYN
        let ipv6_packet = build_test_ipv6_tcp_packet(client_ip6, dest_ip6, src_port, dst_port, b"");
        let ipv4_outbound = translator.translate_6to4(&ipv6_packet).unwrap();

        // Extract translated port
        let tcp_start = 20;
        let translated_port =
            u16::from_be_bytes([ipv4_outbound[tcp_start], ipv4_outbound[tcp_start + 1]]);

        // Step 2: Simulate SYN-ACK response
        let ipv4_response = build_test_ipv4_tcp_packet(
            dest_ip4,
            server_ip4,
            dst_port,
            translated_port,
            b"",
        );

        // Step 3: Translate response back
        let result = translator.translate_4to6(&ipv4_response).unwrap();
        let (returned_client, ipv6_response) = match result {
            Nat64TranslateResult::Translated { client_ip6, packet } => (client_ip6, packet),
            Nat64TranslateResult::NotNat64Packet => panic!("Expected translated packet"),
        };

        assert_eq!(returned_client, client_ip6);

        // Verify TCP ports restored
        let tcp6_start = 40;
        let tcp_dst =
            u16::from_be_bytes([ipv6_response[tcp6_start + 2], ipv6_response[tcp6_start + 3]]);
        assert_eq!(tcp_dst, src_port);
    }

    #[test]
    fn test_translate_icmp_roundtrip() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::4".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(1, 1, 1, 1);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let identifier = 5678u16;
        let sequence = 42u16;
        let payload = b"icmp echo data";

        // Step 1: Client sends ICMPv6 echo request
        let ipv6_packet =
            build_test_ipv6_icmp_echo_packet(client_ip6, dest_ip6, identifier, sequence, payload);
        let ipv4_outbound = translator.translate_6to4(&ipv6_packet).unwrap();

        // Extract translated identifier
        let icmp_start = 20;
        let translated_id =
            u16::from_be_bytes([ipv4_outbound[icmp_start + 4], ipv4_outbound[icmp_start + 5]]);

        // Step 2: Simulate ICMPv4 echo reply
        let ipv4_response = build_test_ipv4_icmp_echo_reply(
            dest_ip4,
            server_ip4,
            translated_id,
            sequence,
            payload,
        );

        // Step 3: Translate response back
        let result = translator.translate_4to6(&ipv4_response).unwrap();
        let (returned_client, ipv6_response) = match result {
            Nat64TranslateResult::Translated { client_ip6, packet } => (client_ip6, packet),
            Nat64TranslateResult::NotNat64Packet => panic!("Expected translated packet"),
        };

        assert_eq!(returned_client, client_ip6);

        // Verify ICMPv6 echo reply type
        let icmp6_start = 40;
        assert_eq!(ipv6_response[icmp6_start], ICMPV6_ECHO_REPLY);

        // Verify identifier restored
        let response_id =
            u16::from_be_bytes([ipv6_response[icmp6_start + 4], ipv6_response[icmp6_start + 5]]);
        assert_eq!(response_id, identifier);

        // Verify sequence preserved
        let response_seq =
            u16::from_be_bytes([ipv6_response[icmp6_start + 6], ipv6_response[icmp6_start + 7]]);
        assert_eq!(response_seq, sequence);

        // Verify payload
        let payload6_start = icmp6_start + 8;
        assert_eq!(&ipv6_response[payload6_start..], payload);
    }

    /// Helper to build IPv4 UDP packet for response simulation.
    fn build_test_ipv4_udp_packet(
        src_ip4: Ipv4Addr,
        dst_ip4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use super::super::checksum::{
            fold_checksum, ipv4_header_checksum, ipv4_pseudo_header_sum, ones_complement_sum,
        };

        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;

        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x40, 0x00]); // Flags + fragment
        packet.push(64); // TTL
        packet.push(17); // UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        packet.extend_from_slice(&src_ip4.octets());
        packet.extend_from_slice(&dst_ip4.octets());

        // IPv4 header checksum
        let hdr_checksum = ipv4_header_checksum(&packet[..20]);
        packet[10] = (hdr_checksum >> 8) as u8;
        packet[11] = hdr_checksum as u8;

        // UDP header
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // Checksum placeholder
        packet.extend_from_slice(payload);

        // UDP checksum
        let pseudo_sum = ipv4_pseudo_header_sum(src_ip4, dst_ip4, 17, udp_len as u16);
        let data_sum = ones_complement_sum(&packet[20..]);
        let udp_checksum = !fold_checksum(pseudo_sum + data_sum);
        packet[26] = (udp_checksum >> 8) as u8;
        packet[27] = udp_checksum as u8;

        packet
    }

    /// Helper to build IPv4 TCP packet for response simulation.
    fn build_test_ipv4_tcp_packet(
        src_ip4: Ipv4Addr,
        dst_ip4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use super::super::checksum::{
            fold_checksum, ipv4_header_checksum, ipv4_pseudo_header_sum, ones_complement_sum,
        };

        let tcp_len = 20 + payload.len();
        let total_len = 20 + tcp_len;

        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x40, 0x00]);
        packet.push(64);
        packet.push(6); // TCP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&src_ip4.octets());
        packet.extend_from_slice(&dst_ip4.octets());

        let hdr_checksum = ipv4_header_checksum(&packet[..20]);
        packet[10] = (hdr_checksum >> 8) as u8;
        packet[11] = hdr_checksum as u8;

        // TCP header
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes()); // Seq
        packet.extend_from_slice(&0u32.to_be_bytes()); // Ack
        packet.push(0x50); // Data offset
        packet.push(0x12); // SYN-ACK
        packet.extend_from_slice(&1024u16.to_be_bytes()); // Window
        packet.extend_from_slice(&[0, 0]); // Checksum placeholder
        packet.extend_from_slice(&[0, 0]); // Urgent
        packet.extend_from_slice(payload);

        // TCP checksum
        let pseudo_sum = ipv4_pseudo_header_sum(src_ip4, dst_ip4, 6, tcp_len as u16);
        let data_sum = ones_complement_sum(&packet[20..]);
        let tcp_checksum = !fold_checksum(pseudo_sum + data_sum);
        packet[36] = (tcp_checksum >> 8) as u8;
        packet[37] = tcp_checksum as u8;

        packet
    }

    /// Helper to build IPv4 ICMP echo reply packet.
    fn build_test_ipv4_icmp_echo_reply(
        src_ip4: Ipv4Addr,
        dst_ip4: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use super::super::checksum::{compute_checksum, ipv4_header_checksum};

        let icmp_len = 8 + payload.len();
        let total_len = 20 + icmp_len;

        let mut packet = Vec::with_capacity(total_len);

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x40, 0x00]);
        packet.push(64);
        packet.push(1); // ICMP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&src_ip4.octets());
        packet.extend_from_slice(&dst_ip4.octets());

        let hdr_checksum = ipv4_header_checksum(&packet[..20]);
        packet[10] = (hdr_checksum >> 8) as u8;
        packet[11] = hdr_checksum as u8;

        // ICMP echo reply
        packet.push(ICMPV4_ECHO_REPLY); // Type 0
        packet.push(0); // Code
        packet.extend_from_slice(&[0, 0]); // Checksum placeholder
        packet.extend_from_slice(&identifier.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(payload);

        // ICMP checksum (no pseudo-header)
        let icmp_checksum = compute_checksum(&packet[20..]);
        packet[22] = (icmp_checksum >> 8) as u8;
        packet[23] = icmp_checksum as u8;

        packet
    }

    #[test]
    fn test_mapping_creation_and_reuse() {
        let translator = Nat64Translator::new(&test_config(), Ipv4Addr::new(10, 0, 0, 1));

        let client_ip6: Ipv6Addr = "fd00::5".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let src_port = 11111u16;
        let dst_port = 53u16;

        // First packet creates a mapping
        let packet1 =
            build_test_ipv6_udp_packet(client_ip6, dest_ip6, src_port, dst_port, b"query1");
        let ipv4_1 = translator.translate_6to4(&packet1).unwrap();
        let port1 = u16::from_be_bytes([ipv4_1[20], ipv4_1[21]]);

        assert_eq!(translator.active_mappings(), 1);

        // Second packet to same destination reuses the mapping
        let packet2 =
            build_test_ipv6_udp_packet(client_ip6, dest_ip6, src_port, dst_port, b"query2");
        let ipv4_2 = translator.translate_6to4(&packet2).unwrap();
        let port2 = u16::from_be_bytes([ipv4_2[20], ipv4_2[21]]);

        // Same mapping, same port
        assert_eq!(port1, port2);
        assert_eq!(translator.active_mappings(), 1);

        // Different source port creates new mapping
        let packet3 =
            build_test_ipv6_udp_packet(client_ip6, dest_ip6, src_port + 1, dst_port, b"query3");
        let ipv4_3 = translator.translate_6to4(&packet3).unwrap();
        let port3 = u16::from_be_bytes([ipv4_3[20], ipv4_3[21]]);

        // Different mapping, different port
        assert_ne!(port1, port3);
        assert_eq!(translator.active_mappings(), 2);
    }

    #[test]
    fn test_mapping_expiry_via_cleanup() {
        // Use very short timeouts for testing
        let config = Nat64Config {
            enabled: true,
            port_range: (10000, 10100),
            tcp_timeout_secs: 1,
            udp_timeout_secs: 1,
            icmp_timeout_secs: 1,
            source_ip: None,
        };
        let translator = Nat64Translator::new(&config, Ipv4Addr::new(10, 0, 0, 1));

        let client_ip6: Ipv6Addr = "fd00::6".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        // Create a mapping
        let packet = build_test_ipv6_udp_packet(client_ip6, dest_ip6, 22222, 53, b"test");
        translator.translate_6to4(&packet).unwrap();
        assert_eq!(translator.active_mappings(), 1);

        // Force the mapping to appear expired by manipulating last_activity
        // Access internal state (we need to make last_activity old)
        // Since we can't easily manipulate internal state, we rely on cleanup()
        // after manually aging entries via the state table's forward map

        // For this test, we'll just verify cleanup() can be called
        // A more thorough test would require exposing internal state or using
        // a test-specific time source
        let removed = translator.cleanup();
        // Initially nothing should be expired (just created)
        assert_eq!(removed, 0);
        assert_eq!(translator.active_mappings(), 1);
    }

    #[test]
    fn test_multiple_clients_separate_mappings() {
        let translator = Nat64Translator::new(&test_config(), Ipv4Addr::new(10, 0, 0, 1));

        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);
        let dst_port = 80u16;

        // Multiple clients connecting to same destination
        let clients: Vec<Ipv6Addr> = (1..=5)
            .map(|i| format!("fd00::{}", i).parse().unwrap())
            .collect();

        let mut ports = Vec::new();
        for (i, client) in clients.iter().enumerate() {
            let packet =
                build_test_ipv6_tcp_packet(*client, dest_ip6, 30000 + i as u16, dst_port, b"");
            let ipv4 = translator.translate_6to4(&packet).unwrap();
            let port = u16::from_be_bytes([ipv4[20], ipv4[21]]);
            ports.push(port);
        }

        // All clients should have separate mappings with unique ports
        assert_eq!(translator.active_mappings(), 5);

        let unique_ports: std::collections::HashSet<_> = ports.iter().collect();
        assert_eq!(unique_ports.len(), 5);
    }

    #[test]
    fn test_translate_4to6_wrong_destination() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        // Create a mapping first
        let client_ip6: Ipv6Addr = "fd00::7".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);
        let packet = build_test_ipv6_udp_packet(client_ip6, dest_ip6, 33333, 53, b"query");
        translator.translate_6to4(&packet).unwrap();

        // Try to translate an IPv4 packet not destined for server
        let wrong_dest = Ipv4Addr::new(192, 168, 1, 1);
        let ipv4_packet = build_test_ipv4_udp_packet(
            dest_ip4,
            wrong_dest, // Wrong destination
            53,
            33333,
            b"response",
        );

        let result = translator.translate_4to6(&ipv4_packet).unwrap();
        assert!(matches!(result, Nat64TranslateResult::NotNat64Packet));
    }

    #[test]
    fn test_translate_4to6_no_mapping() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        // No mapping exists - returns NotNat64Packet (not an error)
        let ipv4_packet = build_test_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            server_ip4,
            53,
            12345, // Unknown translated port
            b"response",
        );

        let result = translator.translate_4to6(&ipv4_packet).unwrap();
        assert!(matches!(result, Nat64TranslateResult::NotNat64Packet));
    }

    /// Helper to build an IPv6 UDP packet with zero checksum for testing.
    /// In IPv4, UDP checksum 0 means "no checksum computed" (optional per RFC 768).
    fn build_test_ipv6_udp_packet_zero_checksum(
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut udp = Vec::with_capacity(udp_len);

        // UDP header
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // Zero checksum
        udp.extend_from_slice(payload);

        // Build IPv6 packet
        let mut packet = Vec::with_capacity(40 + udp_len);
        packet.push(0x60); // Version 6
        packet.extend_from_slice(&[0, 0, 0]); // Traffic class + flow label
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.push(17); // UDP
        packet.push(64); // Hop limit
        packet.extend_from_slice(&src_ip6.octets());
        packet.extend_from_slice(&dst_ip6.octets());
        packet.extend_from_slice(&udp);

        packet
    }

    #[test]
    fn test_udp_zero_checksum_preserved_6to4() {
        let server_ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let translator = Nat64Translator::new(&test_config(), server_ip4);

        let client_ip6: Ipv6Addr = "fd00::8".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);
        let dest_ip6 = embed_ipv4_in_nat64(dest_ip4);

        let src_port = 44444u16;
        let dst_port = 53u16;
        let payload = b"zero checksum test";

        // Build IPv6 UDP packet with zero checksum
        let ipv6_packet = build_test_ipv6_udp_packet_zero_checksum(
            client_ip6,
            dest_ip6,
            src_port,
            dst_port,
            payload,
        );

        // Verify the IPv6 packet has zero checksum
        let ipv6_udp_checksum = u16::from_be_bytes([ipv6_packet[46], ipv6_packet[47]]);
        assert_eq!(ipv6_udp_checksum, 0, "Input packet should have zero checksum");

        // Translate to IPv4
        let ipv4_packet = translator.translate_6to4(&ipv6_packet).unwrap();

        // Verify IPv4 header
        assert_eq!(ipv4_packet[0] >> 4, 4); // Version 4
        assert_eq!(ipv4_packet[9], 17); // Protocol = UDP

        // Verify UDP checksum is preserved as zero
        let udp_start = 20; // IPv4 header size
        let ipv4_udp_checksum =
            u16::from_be_bytes([ipv4_packet[udp_start + 6], ipv4_packet[udp_start + 7]]);
        assert_eq!(
            ipv4_udp_checksum, 0,
            "UDP zero checksum should be preserved after NAT64 translation"
        );

        // Verify payload is correct
        let payload_start = udp_start + 8;
        assert_eq!(&ipv4_packet[payload_start..], payload);
    }
}
