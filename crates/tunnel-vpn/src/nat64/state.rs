//! NAT64 connection state tracking.
//!
//! This module provides a state table for tracking NAT64 connections, including
//! port allocation for NAPT (Network Address Port Translation).

use crate::config::Nat64Config;
use crate::error::{VpnError, VpnResult};
use dashmap::DashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Protocol type for NAT64 connection tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nat64Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Nat64Protocol {
    /// Get the IP protocol number.
    pub fn protocol_number(&self) -> u8 {
        match self {
            Nat64Protocol::Tcp => 6,
            Nat64Protocol::Udp => 17,
            Nat64Protocol::Icmp => 1, // ICMPv4 (translates to/from ICMPv6 = 58)
        }
    }

    /// Create from IPv4 protocol number.
    pub fn from_ipv4_protocol(proto: u8) -> Option<Self> {
        match proto {
            6 => Some(Nat64Protocol::Tcp),
            17 => Some(Nat64Protocol::Udp),
            1 => Some(Nat64Protocol::Icmp),
            _ => None,
        }
    }

    /// Create from IPv6 next header (protocol).
    pub fn from_ipv6_next_header(next_header: u8) -> Option<Self> {
        match next_header {
            6 => Some(Nat64Protocol::Tcp),
            17 => Some(Nat64Protocol::Udp),
            58 => Some(Nat64Protocol::Icmp), // ICMPv6
            _ => None,
        }
    }
}

/// Key for forward lookup (IPv6 client -> IPv4 destination).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForwardKey {
    /// Client's IPv6 source address.
    pub client_ip6: Ipv6Addr,
    /// Client's source port (or ICMP identifier).
    pub client_port: u16,
    /// Destination IPv4 address (extracted from NAT64 address).
    pub dest_ip4: Ipv4Addr,
    /// Destination port (or ICMP identifier for echo requests).
    pub dest_port: u16,
    /// Protocol.
    pub protocol: Nat64Protocol,
}

/// Key for reverse lookup (IPv4 response -> IPv6 client).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReverseKey {
    /// Translated NAPT port on server.
    pub translated_port: u16,
    /// Source IPv4 address of response (was dest_ip4 in forward direction).
    pub src_ip4: Ipv4Addr,
    /// Source port of response (was dest_port in forward direction).
    pub src_port: u16,
    /// Protocol.
    pub protocol: Nat64Protocol,
}

/// NAT64 state entry for a connection/session.
#[derive(Debug, Clone)]
pub struct Nat64Entry {
    /// Client's IPv6 source address.
    pub client_ip6: Ipv6Addr,
    /// Client's original source port.
    pub client_port: u16,
    /// Translated NAPT port (used as source in IPv4 packet).
    pub translated_port: u16,
    /// Destination IPv4 address.
    pub dest_ip4: Ipv4Addr,
    /// Destination port.
    pub dest_port: u16,
    /// Protocol.
    pub protocol: Nat64Protocol,
    /// Last activity timestamp.
    pub last_activity: Instant,
}

/// Port allocator for NAPT.
struct PortAllocator {
    /// Start of port range.
    start: u16,
    /// End of port range (inclusive).
    end: u16,
    /// Next port to try (wraps around).
    next: AtomicU16,
}

impl PortAllocator {
    fn new(start: u16, end: u16) -> Self {
        Self {
            start,
            end,
            next: AtomicU16::new(start),
        }
    }

    /// Try to allocate a port, checking if it's in use.
    /// Returns None if all ports are exhausted (after full cycle).
    fn allocate<F>(&self, is_in_use: F) -> Option<u16>
    where
        F: Fn(u16) -> bool,
    {
        let range_size = (self.end - self.start + 1) as usize;

        for _ in 0..range_size {
            let port = self.next.fetch_add(1, Ordering::Relaxed);

            // Wrap around if needed
            if port > self.end {
                // Try to reset, but another thread might beat us
                let _ = self.next.compare_exchange(
                    port + 1,
                    self.start,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                continue;
            }

            if !is_in_use(port) {
                return Some(port);
            }
        }

        None // All ports in use
    }
}

/// NAT64 state table for connection tracking and NAPT.
pub struct Nat64StateTable {
    /// Forward lookup: (client_ip6, client_port, dest_ip4, dest_port, proto) -> entry.
    forward: DashMap<ForwardKey, Nat64Entry>,
    /// Reverse lookup: (translated_port, src_ip4, src_port, proto) -> forward key.
    reverse: DashMap<ReverseKey, ForwardKey>,
    /// Port allocator for NAPT.
    port_allocator: PortAllocator,
    /// TCP timeout duration.
    tcp_timeout: Duration,
    /// UDP timeout duration.
    udp_timeout: Duration,
    /// ICMP timeout duration.
    icmp_timeout: Duration,
}

impl Nat64StateTable {
    /// Create a new NAT64 state table from configuration.
    pub fn new(config: &Nat64Config) -> Self {
        Self {
            forward: DashMap::new(),
            reverse: DashMap::new(),
            port_allocator: PortAllocator::new(config.port_range.0, config.port_range.1),
            tcp_timeout: Duration::from_secs(config.tcp_timeout_secs),
            udp_timeout: Duration::from_secs(config.udp_timeout_secs),
            icmp_timeout: Duration::from_secs(config.icmp_timeout_secs),
        }
    }

    /// Get timeout duration for a protocol.
    fn timeout_for_protocol(&self, protocol: Nat64Protocol) -> Duration {
        match protocol {
            Nat64Protocol::Tcp => self.tcp_timeout,
            Nat64Protocol::Udp => self.udp_timeout,
            Nat64Protocol::Icmp => self.icmp_timeout,
        }
    }

    /// Get or create a NAT64 mapping for an outbound (IPv6 -> IPv4) connection.
    ///
    /// Returns the translated port to use as the source port in the IPv4 packet.
    pub fn get_or_create_mapping(
        &self,
        client_ip6: Ipv6Addr,
        client_port: u16,
        dest_ip4: Ipv4Addr,
        dest_port: u16,
        protocol: Nat64Protocol,
    ) -> VpnResult<u16> {
        let forward_key = ForwardKey {
            client_ip6,
            client_port,
            dest_ip4,
            dest_port,
            protocol,
        };

        // Check if mapping already exists
        if let Some(mut entry) = self.forward.get_mut(&forward_key) {
            entry.last_activity = Instant::now();
            return Ok(entry.translated_port);
        }

        // Allocate a new port
        let translated_port = self
            .port_allocator
            .allocate(|port| {
                let reverse_key = ReverseKey {
                    translated_port: port,
                    src_ip4: dest_ip4,
                    src_port: dest_port,
                    protocol,
                };
                self.reverse.contains_key(&reverse_key)
            })
            .ok_or(VpnError::Nat64PortExhausted)?;

        let now = Instant::now();
        let entry = Nat64Entry {
            client_ip6,
            client_port,
            translated_port,
            dest_ip4,
            dest_port,
            protocol,
            last_activity: now,
        };

        let reverse_key = ReverseKey {
            translated_port,
            src_ip4: dest_ip4,
            src_port: dest_port,
            protocol,
        };

        // Insert into both maps
        self.forward.insert(forward_key.clone(), entry);
        self.reverse.insert(reverse_key, forward_key);

        Ok(translated_port)
    }

    /// Look up the client information for an inbound (IPv4 -> IPv6) response.
    ///
    /// Returns (client_ip6, client_port) if found, updating the last activity time.
    pub fn lookup_reverse(
        &self,
        translated_port: u16,
        src_ip4: Ipv4Addr,
        src_port: u16,
        protocol: Nat64Protocol,
    ) -> Option<(Ipv6Addr, u16)> {
        let reverse_key = ReverseKey {
            translated_port,
            src_ip4,
            src_port,
            protocol,
        };

        // Look up the forward key from reverse mapping
        let forward_key = self.reverse.get(&reverse_key)?.clone();

        // Update last activity and return client info
        if let Some(mut entry) = self.forward.get_mut(&forward_key) {
            entry.last_activity = Instant::now();
            return Some((entry.client_ip6, entry.client_port));
        }

        None
    }

    /// Clean up expired entries.
    ///
    /// Returns the number of entries removed.
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut removed = 0;

        // Collect expired forward keys
        let expired_keys: Vec<ForwardKey> = self
            .forward
            .iter()
            .filter(|entry| {
                let timeout = self.timeout_for_protocol(entry.protocol);
                now.duration_since(entry.last_activity) > timeout
            })
            .map(|entry| ForwardKey {
                client_ip6: entry.client_ip6,
                client_port: entry.client_port,
                dest_ip4: entry.dest_ip4,
                dest_port: entry.dest_port,
                protocol: entry.protocol,
            })
            .collect();

        // Remove expired entries from both maps
        for forward_key in expired_keys {
            if let Some((_, entry)) = self.forward.remove(&forward_key) {
                let reverse_key = ReverseKey {
                    translated_port: entry.translated_port,
                    src_ip4: entry.dest_ip4,
                    src_port: entry.dest_port,
                    protocol: entry.protocol,
                };
                self.reverse.remove(&reverse_key);
                removed += 1;
            }
        }

        removed
    }

    /// Get the current number of active mappings.
    pub fn active_mappings(&self) -> usize {
        self.forward.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Nat64Config {
        Nat64Config {
            enabled: true,
            port_range: (10000, 10100),
            tcp_timeout_secs: 1,
            udp_timeout_secs: 1,
            icmp_timeout_secs: 1,
        }
    }

    #[test]
    fn test_create_mapping() {
        let table = Nat64StateTable::new(&test_config());

        let client_ip6 = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        // Create a mapping
        let port1 = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        assert!(port1 >= 10000 && port1 <= 10100);
        assert_eq!(table.active_mappings(), 1);

        // Same connection should return same port
        let port2 = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        assert_eq!(port1, port2);
        assert_eq!(table.active_mappings(), 1);
    }

    #[test]
    fn test_reverse_lookup() {
        let table = Nat64StateTable::new(&test_config());

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        // Create a mapping
        let translated_port = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        // Reverse lookup should find the client
        let result = table.lookup_reverse(translated_port, dest_ip4, 80, Nat64Protocol::Tcp);

        assert_eq!(result, Some((client_ip6, 12345)));
    }

    #[test]
    fn test_different_connections_get_different_ports() {
        let table = Nat64StateTable::new(&test_config());

        let client_ip6 = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        // Different source ports = different connections
        let port1 = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        let port2 = table
            .get_or_create_mapping(client_ip6, 12346, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        assert_ne!(port1, port2);
        assert_eq!(table.active_mappings(), 2);
    }

    #[test]
    fn test_protocol_numbers() {
        assert_eq!(Nat64Protocol::Tcp.protocol_number(), 6);
        assert_eq!(Nat64Protocol::Udp.protocol_number(), 17);
        assert_eq!(Nat64Protocol::Icmp.protocol_number(), 1);

        assert_eq!(Nat64Protocol::from_ipv4_protocol(6), Some(Nat64Protocol::Tcp));
        assert_eq!(Nat64Protocol::from_ipv4_protocol(17), Some(Nat64Protocol::Udp));
        assert_eq!(Nat64Protocol::from_ipv4_protocol(1), Some(Nat64Protocol::Icmp));
        assert_eq!(Nat64Protocol::from_ipv4_protocol(99), None);

        assert_eq!(
            Nat64Protocol::from_ipv6_next_header(6),
            Some(Nat64Protocol::Tcp)
        );
        assert_eq!(
            Nat64Protocol::from_ipv6_next_header(17),
            Some(Nat64Protocol::Udp)
        );
        assert_eq!(
            Nat64Protocol::from_ipv6_next_header(58),
            Some(Nat64Protocol::Icmp)
        );
    }

    #[test]
    fn test_cleanup_expired() {
        let table = Nat64StateTable::new(&test_config());

        let client_ip6 = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        // Create a mapping
        let _ = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        assert_eq!(table.active_mappings(), 1);

        // Wait for timeout (1 second in test config)
        std::thread::sleep(Duration::from_millis(1100));

        // Cleanup should remove the expired entry
        let removed = table.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(table.active_mappings(), 0);
    }
}
