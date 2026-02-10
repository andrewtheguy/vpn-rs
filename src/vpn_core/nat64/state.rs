//! NAT64 connection state tracking.
//!
//! This module provides a state table for tracking NAT64 connections, including
//! port allocation for NAPT (Network Address Port Translation).

use crate::vpn_core::config::Nat64Config;
use crate::vpn_core::error::{VpnError, VpnResult};
use dashmap::DashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use super::clock::Instant;

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
    ///
    /// This assumes `next_header` is the transport protocol and does not
    /// account for IPv6 extension headers.
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
    /// Create a new port allocator with the given range.
    ///
    /// # Panics
    ///
    /// Panics if `end < start`, as this would cause underflow in `range_size`
    /// computation.
    fn new(start: u16, end: u16) -> Self {
        assert!(
            end >= start,
            "PortAllocator: end ({}) must be >= start ({})",
            end,
            start
        );
        Self {
            start,
            end,
            next: AtomicU16::new(start),
        }
    }

    /// Get the next candidate port, advancing the counter.
    /// Returns None if we've cycled through all ports.
    /// The caller is responsible for checking if the port is actually usable
    /// and retrying if not.
    fn next_candidate(&self, attempts: &mut usize) -> Option<u16> {
        let range_size = (self.end - self.start + 1) as usize;
        let max_spins = 64usize;
        let mut spins = 0usize;

        if *attempts >= range_size {
            return None; // Exhausted all ports
        }

        loop {
            let current = self.next.load(Ordering::Relaxed);

            // Calculate next value with proper wrap-around (no overflow)
            let next_val = if current >= self.end {
                self.start
            } else {
                current.wrapping_add(1)
            };

            // Try to atomically advance the counter
            match self.next.compare_exchange_weak(
                current,
                next_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Successfully claimed this port candidate
                    // Only count as attempt if port is in valid range
                    if current >= self.start && current <= self.end {
                        *attempts += 1;
                        return Some(current);
                    }
                    // Port was out of range (shouldn't happen normally).
                    // Panic immediately for clarity rather than silently continuing.
                    panic!(
                        "PortAllocator::next_candidate: current {} outside {}..={} (attempts={})",
                        current, self.start, self.end, *attempts
                    );
                }
                Err(_) => {
                    // Another thread beat us, retry
                    spins += 1;
                    if spins > max_spins {
                        std::thread::yield_now();
                        spins = 0;
                    }
                    continue;
                }
            }
        }
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
        use dashmap::mapref::entry::Entry;

        let forward_key = ForwardKey {
            client_ip6,
            client_port,
            dest_ip4,
            dest_port,
            protocol,
        };

        // Use entry API for atomic check-and-insert on the forward map
        match self.forward.entry(forward_key.clone()) {
            Entry::Occupied(mut occupied) => {
                // Mapping already exists, update last_activity and return
                occupied.get_mut().last_activity = Instant::now();
                Ok(occupied.get().translated_port)
            }
            Entry::Vacant(vacant) => {
                // Need to allocate a new port and insert atomically
                let now = Instant::now();
                let mut attempts: usize = 0;

                // Retry loop: allocate port and try to insert into reverse map
                loop {
                    let translated_port = self
                        .port_allocator
                        .next_candidate(&mut attempts)
                        .ok_or(VpnError::Nat64PortExhausted)?;

                    let reverse_key = ReverseKey {
                        translated_port,
                        src_ip4: dest_ip4,
                        src_port: dest_port,
                        protocol,
                    };

                    // Try to atomically insert into reverse map
                    // Use entry API to avoid TOCTOU race
                    match self.reverse.entry(reverse_key) {
                        Entry::Occupied(_) => {
                            // Port already in use for this (dest_ip4, dest_port, protocol),
                            // try next port
                            continue;
                        }
                        Entry::Vacant(reverse_vacant) => {
                            // Successfully claimed this port in reverse map
                            let entry = Nat64Entry {
                                client_ip6,
                                client_port,
                                translated_port,
                                dest_ip4,
                                dest_port,
                                protocol,
                                last_activity: now,
                            };

                            // Insert the entry into forward map first.
                            // This ensures we don't have orphan reverse entries if a
                            // panic occurs between insertions.
                            vacant.insert(entry);

                            // Now insert the forward key reference into reverse map.
                            // If this panics, the forward entry exists but has no reverse
                            // mapping, which is safer than the reverse case.
                            reverse_vacant.insert(forward_key.clone());

                            return Ok(translated_port);
                        }
                    }
                }
            }
        }
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

        // Collect candidate expired forward keys (snapshot)
        // Note: entries may be refreshed between collection and removal
        let candidate_keys: Vec<ForwardKey> = self
            .forward
            .iter()
            .filter(|entry| {
                let timeout = self.timeout_for_protocol(entry.protocol);
                now.duration_since(entry.last_activity) > timeout
            })
            .map(|entry| entry.key().clone())
            .collect();

        // Remove entries only if they are still expired (re-check before removal)
        // This handles the race where get_or_create_mapping or lookup_reverse
        // refreshed the entry between collection and removal
        for forward_key in candidate_keys {
            let reverse_key = match self.forward.get(&forward_key) {
                Some(entry) => {
                    let timeout = self.timeout_for_protocol(entry.protocol);
                    if now.duration_since(entry.last_activity) > timeout {
                        Some(ReverseKey {
                            translated_port: entry.translated_port,
                            src_ip4: entry.dest_ip4,
                            src_port: entry.dest_port,
                            protocol: entry.protocol,
                        })
                    } else {
                        None
                    }
                }
                None => None,
            };

            if let Some(reverse_key) = reverse_key {
                // Use remove_if for atomic conditional removal:
                // only remove if the entry is still expired
                let maybe_removed = self.forward.remove_if(&forward_key, |_key, entry| {
                    let timeout = self.timeout_for_protocol(entry.protocol);
                    now.duration_since(entry.last_activity) > timeout
                });

                if maybe_removed.is_some() {
                    // Remove reverse mapping only after forward removal succeeds.
                    // If remove_if returns None, the entry was refreshed and reverse
                    // mapping must remain intact.
                    self.reverse.remove(&reverse_key);
                    removed += 1;
                }
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
    use crate::vpn_core::nat64::clock::MockClock;

    fn test_config() -> Nat64Config {
        Nat64Config {
            enabled: true,
            port_range: (10000, 10100),
            tcp_timeout_secs: 1,
            udp_timeout_secs: 1,
            icmp_timeout_secs: 1,
            source_ip: None,
        }
    }

    fn cleanup_single_expired_with_hook<F>(
        table: &Nat64StateTable,
        forward_key: ForwardKey,
        mut hook: F,
    ) -> usize
    where
        F: FnMut(&ForwardKey),
    {
        let now = Instant::now();
        let mut removed = 0;

        let reverse_key = match table.forward.get(&forward_key) {
            Some(entry) => {
                let timeout = table.timeout_for_protocol(entry.protocol);
                if now.duration_since(entry.last_activity) > timeout {
                    Some(ReverseKey {
                        translated_port: entry.translated_port,
                        src_ip4: entry.dest_ip4,
                        src_port: entry.dest_port,
                        protocol: entry.protocol,
                    })
                } else {
                    None
                }
            }
            None => None,
        };

        if let Some(reverse_key) = reverse_key {
            hook(&forward_key);

            let maybe_removed = table.forward.remove_if(&forward_key, |_key, entry| {
                let timeout = table.timeout_for_protocol(entry.protocol);
                now.duration_since(entry.last_activity) > timeout
            });

            if maybe_removed.is_some() {
                table.reverse.remove(&reverse_key);
                removed += 1;
            }
        }

        removed
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

        assert!((10000..=10100).contains(&port1));
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

        assert_eq!(
            Nat64Protocol::from_ipv4_protocol(6),
            Some(Nat64Protocol::Tcp)
        );
        assert_eq!(
            Nat64Protocol::from_ipv4_protocol(17),
            Some(Nat64Protocol::Udp)
        );
        assert_eq!(
            Nat64Protocol::from_ipv4_protocol(1),
            Some(Nat64Protocol::Icmp)
        );
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
        // Reset mock clock to a known state
        MockClock::set_time(Duration::ZERO);

        let table = Nat64StateTable::new(&test_config());

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        // Create a mapping
        let _ = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        assert_eq!(table.active_mappings(), 1);

        // Cleanup should not remove anything yet (not expired)
        let removed = table.cleanup_expired();
        assert_eq!(removed, 0);
        assert_eq!(table.active_mappings(), 1);

        // Advance time past the TCP timeout (1 second in test_config)
        MockClock::advance(Duration::from_secs(2));

        // Cleanup should now remove the expired entry
        let removed = table.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(table.active_mappings(), 0);
    }

    #[test]
    fn test_cleanup_expired_keeps_reverse_on_refresh() {
        // Reset mock clock to a known state
        MockClock::set_time(Duration::ZERO);

        let table = Nat64StateTable::new(&test_config());

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        let translated_port = table
            .get_or_create_mapping(client_ip6, 12345, dest_ip4, 80, Nat64Protocol::Tcp)
            .unwrap();

        let forward_key = ForwardKey {
            client_ip6,
            client_port: 12345,
            dest_ip4,
            dest_port: 80,
            protocol: Nat64Protocol::Tcp,
        };

        // Advance time past the timeout to make the entry appear expired
        MockClock::advance(Duration::from_secs(2));

        // Use the hook to simulate a concurrent refresh during cleanup.
        // The entry is "expired" when cleanup starts, but gets refreshed
        // (via the hook) before the conditional remove_if executes.
        let removed = cleanup_single_expired_with_hook(&table, forward_key.clone(), |key| {
            if let Some(mut entry) = table.forward.get_mut(key) {
                // Refresh the entry by updating last_activity to "now"
                entry.last_activity = Instant::now();
            }
        });

        // Entry should NOT be removed because it was refreshed
        assert_eq!(removed, 0);
        assert_eq!(table.active_mappings(), 1);

        // Reverse mapping should still be present
        let reverse_key = ReverseKey {
            translated_port,
            src_ip4: dest_ip4,
            src_port: 80,
            protocol: Nat64Protocol::Tcp,
        };
        assert!(table.reverse.contains_key(&reverse_key));
    }

    #[test]
    fn test_port_exhaustion() {
        // Use a small port range for testing exhaustion
        let config = Nat64Config {
            enabled: true,
            port_range: (10000, 10100), // 101 ports
            tcp_timeout_secs: 300,
            udp_timeout_secs: 30,
            icmp_timeout_secs: 30,
            source_ip: None,
        };
        let table = Nat64StateTable::new(&config);

        let client_ip6: Ipv6Addr = "fd00::2".parse().unwrap();
        let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

        // Allocate all 101 ports (10000..=10100)
        let port_range_size = 101;
        for i in 0..port_range_size {
            let result = table.get_or_create_mapping(
                client_ip6,
                (1000 + i) as u16, // Different client port for each connection
                dest_ip4,
                80,
                Nat64Protocol::Tcp,
            );
            assert!(
                result.is_ok(),
                "mapping {} should succeed, got {:?}",
                i,
                result
            );
        }

        assert_eq!(table.active_mappings(), port_range_size);

        // Next allocation should fail with port exhaustion
        let result = table.get_or_create_mapping(
            client_ip6,
            2000, // New client port
            dest_ip4,
            80,
            Nat64Protocol::Tcp,
        );
        assert!(
            matches!(result, Err(VpnError::Nat64PortExhausted)),
            "expected Nat64PortExhausted, got {:?}",
            result
        );

        // Active mappings should still be at max
        assert_eq!(table.active_mappings(), port_range_size);
    }

    #[test]
    fn test_concurrent_mappings() {
        use std::collections::HashSet;
        use std::sync::Arc;
        use std::thread;

        let config = Nat64Config {
            enabled: true,
            port_range: (20000, 20999), // 1000 ports for concurrency test
            tcp_timeout_secs: 300,
            udp_timeout_secs: 30,
            icmp_timeout_secs: 30,
            source_ip: None,
        };
        let table = Arc::new(Nat64StateTable::new(&config));

        let num_threads = 10;
        let mappings_per_thread = 50;
        let total_mappings = num_threads * mappings_per_thread;

        // Spawn threads that create mappings concurrently
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let table = Arc::clone(&table);
                thread::spawn(move || {
                    let mut ports = Vec::new();
                    // Each thread uses a different client IPv6 to avoid key collisions
                    let client_ip6: Ipv6Addr =
                        format!("fd00::{:x}", thread_id + 1).parse().unwrap();
                    let dest_ip4 = Ipv4Addr::new(8, 8, 8, 8);

                    for i in 0..mappings_per_thread {
                        let client_port = (3000 + i) as u16;
                        let result = table.get_or_create_mapping(
                            client_ip6,
                            client_port,
                            dest_ip4,
                            80,
                            Nat64Protocol::Tcp,
                        );
                        match result {
                            Ok(port) => ports.push(port),
                            Err(e) => panic!("thread {} mapping {} failed: {:?}", thread_id, i, e),
                        }
                    }
                    ports
                })
            })
            .collect();

        // Collect all allocated ports from all threads
        let mut all_ports = Vec::new();
        for handle in handles {
            let ports = handle.join().expect("thread should not panic");
            all_ports.extend(ports);
        }

        // Verify total number of mappings
        assert_eq!(table.active_mappings(), total_mappings);

        // Verify all allocated ports are unique
        let unique_ports: HashSet<u16> = all_ports.iter().copied().collect();
        assert_eq!(
            unique_ports.len(),
            total_mappings,
            "all translated ports should be unique"
        );

        // Verify all ports are within the configured range
        for port in &all_ports {
            assert!(
                *port >= 20000 && *port <= 20999,
                "port {} should be in range 20000-20999",
                port
            );
        }
    }
}
