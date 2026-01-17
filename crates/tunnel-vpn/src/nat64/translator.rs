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
            cleanup_interval: Duration::from_secs(60), // Cleanup every minute
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
        let _hop_limit = ipv6_packet[7];

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

        // Get protocol
        let protocol = Nat64Protocol::from_ipv6_next_header(next_header)
            .ok_or(VpnError::Nat64UnsupportedProtocol(next_header))?;

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
        match protocol {
            Nat64Protocol::Tcp => {
                self.translate_tcp_6to4(src_ip6, dst_ip4, payload, payload_length as u16)
            }
            Nat64Protocol::Udp => {
                self.translate_udp_6to4(src_ip6, dst_ip4, payload, payload_length as u16)
            }
            Nat64Protocol::Icmp => self.translate_icmp_6to4(src_ip6, dst_ip4, payload),
        }
    }

    /// Translate an IPv4 packet to IPv6.
    ///
    /// Returns `(destination_client_ip6, translated_ipv6_packet)` if successful.
    /// The destination is looked up in the NAT64 state table.
    pub fn translate_4to6(&self, ipv4_packet: &[u8]) -> VpnResult<(Ipv6Addr, Vec<u8>)> {
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
        let _ttl = ipv4_packet[8];

        // Extract source and destination IPv4 addresses
        let src_ip4 = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[12..16]).unwrap());
        let dst_ip4 = Ipv4Addr::from(<[u8; 4]>::try_from(&ipv4_packet[16..20]).unwrap());

        // Verify this packet is destined for our NAT64 address
        if dst_ip4 != self.server_ip4 {
            return Err(VpnError::Nat64(format!(
                "IPv4 packet not destined for NAT64: {} != {}",
                dst_ip4, self.server_ip4
            )));
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
        match nat64_protocol {
            Nat64Protocol::Tcp => self.translate_tcp_4to6(src_ip4, payload, payload_length),
            Nat64Protocol::Udp => self.translate_udp_4to6(src_ip4, payload, payload_length),
            Nat64Protocol::Icmp => self.translate_icmp_4to6(src_ip4, payload),
        }
    }

    /// Translate TCP from IPv6 to IPv4.
    fn translate_tcp_6to4(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip4: Ipv4Addr,
        tcp_payload: &[u8],
        payload_len: u16,
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
        )
    }

    /// Translate UDP from IPv6 to IPv4.
    fn translate_udp_6to4(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip4: Ipv4Addr,
        udp_payload: &[u8],
        payload_len: u16,
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
        )
    }

    /// Translate ICMPv6 to ICMPv4.
    fn translate_icmp_6to4(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip4: Ipv4Addr,
        icmp_payload: &[u8],
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
        self.build_ipv4_header_with_payload(dst_ip4, 1, &icmpv4) // ICMP = 1
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
    ) -> VpnResult<Vec<u8>> {
        use super::checksum::update_checksum_16;

        // Create modified payload with new source port
        let mut new_payload = payload.to_vec();
        new_payload[0] = (new_src_port >> 8) as u8;
        new_payload[1] = new_src_port as u8;

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
        let checksum_offset = if protocol == 6 { 16 } else { 6 }; // TCP vs UDP
        new_payload[checksum_offset] = (new_checksum >> 8) as u8;
        new_payload[checksum_offset + 1] = new_checksum as u8;

        self.build_ipv4_header_with_payload(dst_ip4, protocol, &new_payload)
    }

    /// Build an IPv4 header and combine with payload.
    fn build_ipv4_header_with_payload(
        &self,
        dst_ip4: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> VpnResult<Vec<u8>> {
        let total_length = (IPV4_HEADER_SIZE + payload.len()) as u16;

        let mut packet = Vec::with_capacity(total_length as usize);

        // IPv4 header
        packet.push(0x45); // Version 4, IHL 5 (20 bytes)
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&total_length.to_be_bytes()); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // Identification
        packet.extend_from_slice(&[0x40, 0x00]); // Flags (DF) + Fragment offset
        packet.push(64); // TTL
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
    ) -> VpnResult<(Ipv6Addr, Vec<u8>)> {
        use super::checksum::update_checksum_16;

        if tcp_payload.len() < TCP_HEADER_MIN_SIZE {
            return Err(VpnError::Nat64("TCP segment too short".into()));
        }

        let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
        let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
        let old_checksum = u16::from_be_bytes([tcp_payload[16], tcp_payload[17]]);

        // Look up the original client
        let (client_ip6, client_port) = self
            .state
            .lookup_reverse(dst_port, src_ip4, src_port, Nat64Protocol::Tcp)
            .ok_or_else(|| VpnError::Nat64("No NAT64 mapping for TCP response".into()))?;

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
        );

        // Also adjust checksum for destination port change (dst_port -> client_port)
        let new_checksum = update_checksum_16(checksum_after_pseudo, dst_port, client_port);

        new_payload[16] = (new_checksum >> 8) as u8;
        new_payload[17] = new_checksum as u8;

        let packet = self.build_ipv6_packet(src_ip6, dst_ip6, 6, &new_payload);
        Ok((client_ip6, packet))
    }

    /// Translate UDP from IPv4 to IPv6.
    fn translate_udp_4to6(
        &self,
        src_ip4: Ipv4Addr,
        udp_payload: &[u8],
        payload_len: u16,
    ) -> VpnResult<(Ipv6Addr, Vec<u8>)> {
        use super::checksum::update_checksum_16;

        if udp_payload.len() < UDP_HEADER_SIZE {
            return Err(VpnError::Nat64("UDP datagram too short".into()));
        }

        let src_port = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
        let dst_port = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);
        let old_checksum = u16::from_be_bytes([udp_payload[6], udp_payload[7]]);

        // Look up the original client
        let (client_ip6, client_port) = self
            .state
            .lookup_reverse(dst_port, src_ip4, src_port, Nat64Protocol::Udp)
            .ok_or_else(|| VpnError::Nat64("No NAT64 mapping for UDP response".into()))?;

        // Build IPv6 packet
        let src_ip6 = embed_ipv4_in_nat64(src_ip4);
        let dst_ip6 = client_ip6;

        // Create modified payload with original destination port
        let mut new_payload = udp_payload.to_vec();
        new_payload[2] = (client_port >> 8) as u8;
        new_payload[3] = client_port as u8;

        // Adjust checksum (handle zero checksum in UDP)
        let new_checksum = if old_checksum == 0 {
            // UDP checksum was 0 (optional in IPv4), but mandatory in IPv6
            // We need to compute it from scratch (new_payload already has client_port)
            self.compute_udp_checksum_ipv6(src_ip6, dst_ip6, &new_payload)
        } else {
            // First adjust for pseudo-header change (IPv4 -> IPv6)
            let checksum_after_pseudo = adjust_checksum_4to6(
                old_checksum,
                src_ip4,
                self.server_ip4,
                src_ip6,
                dst_ip6,
                17, // UDP
                payload_len,
            );

            // Also adjust checksum for destination port change (dst_port -> client_port)
            update_checksum_16(checksum_after_pseudo, dst_port, client_port)
        };

        new_payload[6] = (new_checksum >> 8) as u8;
        new_payload[7] = new_checksum as u8;

        let packet = self.build_ipv6_packet(src_ip6, dst_ip6, 17, &new_payload);
        Ok((client_ip6, packet))
    }

    /// Translate ICMPv4 to ICMPv6.
    fn translate_icmp_4to6(
        &self,
        src_ip4: Ipv4Addr,
        icmp_payload: &[u8],
    ) -> VpnResult<(Ipv6Addr, Vec<u8>)> {
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

        // Look up the original client
        let (client_ip6, original_id) = self
            .state
            .lookup_reverse(translated_id, src_ip4, 0, Nat64Protocol::Icmp)
            .ok_or_else(|| VpnError::Nat64("No NAT64 mapping for ICMP response".into()))?;

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

        let packet = self.build_ipv6_packet(src_ip6, dst_ip6, 58, &icmpv6); // ICMPv6 = 58
        Ok((client_ip6, packet))
    }

    /// Build an IPv6 packet.
    fn build_ipv6_packet(
        &self,
        src_ip6: Ipv6Addr,
        dst_ip6: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let payload_length = payload.len() as u16;

        let mut packet = Vec::with_capacity(IPV6_HEADER_SIZE + payload.len());

        // IPv6 header
        packet.push(0x60); // Version 6, traffic class 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // Traffic class + flow label
        packet.extend_from_slice(&payload_length.to_be_bytes()); // Payload length
        packet.push(next_header); // Next header
        packet.push(64); // Hop limit
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

        let packet = translator.build_ipv6_packet(src, dst, 17, &payload);

        // Verify header
        assert_eq!(packet[0] >> 4, 6); // Version
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]),
            payload.len() as u16
        ); // Payload length
        assert_eq!(packet[6], 17); // Next header (UDP)
        assert_eq!(packet[7], 64); // Hop limit

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
}
