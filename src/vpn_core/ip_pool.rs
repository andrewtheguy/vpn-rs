//! VPN client IP address pools (IPv4 and IPv6).
//!
//! Both pools assign addresses keyed by client `device_id` so allocation is
//! idempotent across reconnects, and released addresses are reused. Shared by
//! the UDP server ([`crate::vpn_core::server`]) and the TCP server
//! ([`crate::vpn_core::tcp_server`]).

use crate::vpn_core::error::{VpnError, VpnResult};
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4 address pool for assigning addresses to clients (keyed by device id).
pub(crate) struct IpPool {
    network: Ipv4Net,
    server_ip: Ipv4Addr,
    next_ip: u32,
    max_ip: u32,
    in_use: HashMap<u64, Ipv4Addr>,
    released: Vec<Ipv4Addr>,
    reserved: HashSet<Ipv4Addr>,
}

impl IpPool {
    pub(crate) fn new(network: Ipv4Net, server_ip: Option<Ipv4Addr>) -> Self {
        let net_addr: u32 = network.network().into();
        let broadcast: u32 = network.broadcast().into();
        let server_ip = server_ip.unwrap_or_else(|| Ipv4Addr::from(net_addr + 1));
        let server_ip_u32: u32 = server_ip.into();
        let next_ip = server_ip_u32 + 1;
        let max_ip = broadcast - 1; // Exclude broadcast address
        Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            in_use: HashMap::new(),
            released: Vec::new(),
            reserved: HashSet::new(),
        }
    }

    pub(crate) fn server_ip(&self) -> Ipv4Addr {
        self.server_ip
    }

    pub(crate) fn network(&self) -> Ipv4Net {
        self.network
    }

    #[cfg(test)]
    fn reserve_next_available(&mut self) -> Option<Ipv4Addr> {
        let ip = self.next_unreserved_ip()?;
        self.reserved.insert(ip);
        Some(ip)
    }

    fn next_unreserved_ip(&mut self) -> Option<Ipv4Addr> {
        while self.next_ip <= self.max_ip {
            let ip = Ipv4Addr::from(self.next_ip);
            self.next_ip += 1;
            if self.reserved.contains(&ip) {
                continue;
            }
            return Some(ip);
        }
        None
    }

    /// Allocate an IP for a client, idempotent per `device_id`.
    pub(crate) fn allocate(&mut self, device_id: u64) -> Option<Ipv4Addr> {
        if let Some(&ip) = self.in_use.get(&device_id) {
            return Some(ip);
        }
        while let Some(ip) = self.released.pop() {
            if self.reserved.contains(&ip) {
                continue;
            }
            self.in_use.insert(device_id, ip);
            return Some(ip);
        }
        if let Some(ip) = self.next_unreserved_ip() {
            self.in_use.insert(device_id, ip);
            Some(ip)
        } else {
            None
        }
    }

    /// Release an IP when a client is reaped.
    pub(crate) fn release(&mut self, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&device_id) {
            self.released.push(ip);
        }
    }
}

/// IPv6 address pool for assigning /128 addresses to clients (sequential, keyed by device id).
#[derive(Debug)]
pub(crate) struct Ip6Pool {
    network: Ipv6Net,
    server_ip: Ipv6Addr,
    next_ip: u128,
    max_ip: u128,
    released: Vec<Ipv6Addr>,
    in_use: HashMap<u64, Ipv6Addr>,
}

impl Ip6Pool {
    /// Create a new IPv6 pool. Server gets `::1` (or `server_ip`); clients get
    /// subsequent addresses. Requires a /126 or wider network.
    pub(crate) fn new(network: Ipv6Net, server_ip: Option<Ipv6Addr>) -> VpnResult<Self> {
        let prefix_len = network.prefix_len();
        if prefix_len >= 127 {
            return Err(VpnError::config(format!(
                "IPv6 prefix /{} is too small for VPN pool (need at least /126 for 1 client)",
                prefix_len
            )));
        }

        let net_addr: u128 = network.network().into();
        let server_ip = server_ip.unwrap_or_else(|| Ipv6Addr::from(net_addr + 1));
        let server_ip_u128: u128 = server_ip.into();
        let next_ip = server_ip_u128 + 1;
        let host_bits: u32 = 128 - u32::from(prefix_len);
        // host_bits >= 2 here because prefix_len < 127, so the shift is safe.
        let max_ip = net_addr + ((1u128 << host_bits) - 1) - 1; // Exclude last address

        Ok(Self {
            network,
            server_ip,
            next_ip,
            max_ip,
            released: Vec::new(),
            in_use: HashMap::new(),
        })
    }

    pub(crate) fn server_ip(&self) -> Ipv6Addr {
        self.server_ip
    }

    pub(crate) fn network(&self) -> Ipv6Net {
        self.network
    }

    /// Allocate an IPv6 for a client, idempotent per `device_id`.
    pub(crate) fn allocate(&mut self, device_id: u64) -> Option<Ipv6Addr> {
        if let Some(&ip) = self.in_use.get(&device_id) {
            return Some(ip);
        }
        if let Some(ip) = self.released.pop() {
            self.in_use.insert(device_id, ip);
            return Some(ip);
        }
        if self.next_ip <= self.max_ip {
            let ip = Ipv6Addr::from(self.next_ip);
            self.next_ip += 1;
            self.in_use.insert(device_id, ip);
            Some(ip)
        } else {
            None
        }
    }

    /// Release an IPv6 when a client is reaped.
    pub(crate) fn release(&mut self, device_id: u64) {
        if let Some(ip) = self.in_use.remove(&device_id) {
            self.released.push(ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_pool_allocation() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);

        assert_eq!(pool.server_ip(), Ipv4Addr::new(10, 0, 0, 1));

        let ip1 = pool.allocate(1).unwrap();
        let ip2 = pool.allocate(2).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 3));

        // Re-allocate same device returns same IP (idempotent).
        assert_eq!(pool.allocate(1).unwrap(), ip1);

        // Release and reallocate reuses the released IP.
        pool.release(1);
        let ip3 = pool.allocate(3).unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ip_pool_reserve_next_available() {
        let network: Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let mut pool = IpPool::new(network, None);
        let reserved = pool.reserve_next_available().unwrap();
        assert_eq!(reserved, Ipv4Addr::new(10, 0, 0, 2));
        let ip1 = pool.allocate(1).unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let network: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        let mut pool = IpPool::new(network, None);
        assert!(pool.allocate(1).is_some());
        assert!(pool.allocate(2).is_none()); // only .2 available for clients
    }

    #[test]
    fn test_ip6_pool_allocation() {
        let network: Ipv6Net = "fd00::/120".parse().unwrap();
        let mut pool = Ip6Pool::new(network, None).unwrap();

        assert_eq!(pool.server_ip(), "fd00::1".parse::<Ipv6Addr>().unwrap());

        let ip1 = pool.allocate(1).unwrap();
        let ip2 = pool.allocate(2).unwrap();
        assert_eq!(ip1, "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ip2, "fd00::3".parse::<Ipv6Addr>().unwrap());

        assert_eq!(pool.allocate(1).unwrap(), ip1);

        pool.release(1);
        let ip3 = pool.allocate(3).unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ip6_pool_exhaustion() {
        let network: Ipv6Net = "fd00::/126".parse().unwrap();
        let mut pool = Ip6Pool::new(network, None).unwrap();
        assert!(pool.allocate(1).is_some());
        assert!(pool.allocate(2).is_none());
    }

    #[test]
    fn test_ip6_pool_rejects_slash127_and_128() {
        for prefix in ["fd00::/127", "fd00::/128"] {
            let network: Ipv6Net = prefix.parse().unwrap();
            let result = Ip6Pool::new(network, None);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), VpnError::Config(_)));
        }
    }
}
