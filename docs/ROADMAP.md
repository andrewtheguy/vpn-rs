# vpn-rs Roadmap

This document outlines planned features and improvements for `vpn-rs`.

## Current Status

`vpn-rs` provides iroh-based VPN tunneling with:

- Full-network IP-over-QUIC transport
- Token authentication
- Dynamic per-session client IP assignment
- Optional dual-stack IPv4/IPv6 operation
- Experimental NAT64 for IPv6-only deployments
- Auto-reconnect and heartbeat-based connection health

---

## Planned Features

### NAT64 Enhancements

**Status:** Experimental / Partial

NAT64 translation is implemented for TCP, UDP, and ICMP echo (ping). The following features are still planned:

| Feature | Status | Notes |
|---------|--------|-------|
| TCP/UDP translation | Implemented | Full NAPT with connection tracking |
| ICMP Echo (ping) | Implemented | Echo request/reply |
| ICMP error translation | Planned | Needed for PMTU and richer error propagation |
| IPv6 extension headers | Planned | Parse/skip extension headers to find transport |
| IPv4 fragmentation support | Planned | Improve compatibility for oversized packets |
| PMTU discovery handling | Planned | Better behavior on constrained links |

### IPv6-Only Hardening

**Status:** In progress

Improve operational guidance and defaults for IPv6-only VPN deployments, including NAT64 source IP ergonomics and validation clarity.

### Authentication Rate Limiting

**Status:** Idea

Add configurable rate limiting for invalid auth-token attempts to reduce brute-force and resource abuse risk.

See [`RATE_LIMITING_PROPOSAL.md`](RATE_LIMITING_PROPOSAL.md) for a concrete design draft.

### Dynamic Client Whitelisting for Self-Hosted Relay

**Status:** Idea

For self-hosted `iroh-relay`, explore dynamic allow/deny integration keyed by authenticated client identity so relay-level access can track active authorized sessions.

### Connection Migration (IP Change Resilience)

**Status:** Idea

Improve tunnel continuity when clients switch networks (for example, Wi-Fi to cellular) by better leveraging QUIC path migration behavior.

### Performance Metrics

**Status:** Idea

Add built-in metrics for latency, throughput, loss, reconnect counts, and tunnel uptime.

### Multi-Path Support

**Status:** Idea

Use multiple network paths simultaneously for higher throughput or failover.

### Web UI

**Status:** Idea

Browser-based interface for configuration, connection state, and diagnostics.
