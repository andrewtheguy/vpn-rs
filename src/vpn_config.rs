//! Shared VPN configuration types and validation rules.
//!
//! Single source of truth for the semantic rules enforced at both the TOML
//! config layer (`vpn_common`) and the runtime config layer (`vpn_core`).
//! Rules operate on parsed types and return plain `String` errors; callers
//! wrap them in their own error types (anyhow with section prefix, VpnError).

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv6 address-assignment strategy for VPN clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Ip6Strategy {
    /// Sequential allocation: server gets ::1, clients get ::2, ::3, ...
    #[default]
    Sequential,
    /// Stateless deterministic addresses: host suffix derived from the iroh
    /// node id (clients from their own id, server from its id).
    /// Requires an IPv6 subnet of /64 or wider.
    NodeId,
}

/// Validate node-id strategy requirements: `network6` of /64 or wider and no
/// `server_ip6` override (the server address is derived from the node id).
///
/// A no-op for the sequential strategy.
pub fn validate_ip6_strategy(
    strategy: Ip6Strategy,
    network6: Option<Ipv6Net>,
    server_ip6: Option<Ipv6Addr>,
) -> Result<(), String> {
    if strategy != Ip6Strategy::NodeId {
        return Ok(());
    }

    let Some(network6) = network6 else {
        return Err("ip6_strategy 'node-id' requires 'network6' to be set".to_string());
    };
    if network6.prefix_len() > 64 {
        return Err(format!(
            "ip6_strategy 'node-id' requires an IPv6 subnet of /64 or wider (got /{})",
            network6.prefix_len()
        ));
    }
    if server_ip6.is_some() {
        return Err(
            "'server_ip6' cannot be combined with ip6_strategy 'node-id' (the server address is derived from the server node id)"
                .to_string(),
        );
    }

    Ok(())
}

/// Validate the combination of VPN networks, server addresses, and IPv6
/// strategy.
pub fn validate_vpn_networks(
    network: Option<Ipv4Net>,
    server_ip: Option<Ipv4Addr>,
    network6: Option<Ipv6Net>,
    server_ip6: Option<Ipv6Addr>,
    ip6_strategy: Ip6Strategy,
) -> Result<(), String> {
    // At least one network must be configured
    if network.is_none() && network6.is_none() {
        return Err(
            "At least one of 'network' (IPv4) or 'network6' (IPv6) must be configured".to_string(),
        );
    }

    // server_ip requires network
    if server_ip.is_some() && network.is_none() {
        return Err("'server_ip' requires 'network' to be set".to_string());
    }

    // server_ip must be within network
    if let (Some(server_ip), Some(network)) = (server_ip, network) {
        if !network.contains(&server_ip) {
            return Err(format!(
                "'server_ip' {} is not within 'network' {}",
                server_ip, network
            ));
        }
    }

    // server_ip6 requires network6
    if server_ip6.is_some() && network6.is_none() {
        return Err("'server_ip6' requires 'network6' to be set".to_string());
    }

    // server_ip6 must be within network6
    if let (Some(server_ip6), Some(network6)) = (server_ip6, network6) {
        if !network6.contains(&server_ip6) {
            return Err(format!(
                "'server_ip6' {} is not within 'network6' {}",
                server_ip6, network6
            ));
        }
    }

    validate_ip6_strategy(ip6_strategy, network6, server_ip6)
}
