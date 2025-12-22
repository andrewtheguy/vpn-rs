# tunnel-rs Roadmap

This document outlines planned features and improvements for tunnel-rs.

## Current Status

tunnel-rs currently supports four operational modes:
- **iroh-default**: Production-ready with automatic discovery and relay fallback
- **iroh-manual**: Serverless with manual signaling
- **custom**: Full ICE with manual signaling
- **nostr**: Full ICE with automated Nostr relay signaling

All modes support TCP and UDP tunneling with end-to-end encryption via QUIC/TLS 1.3.

---

## Planned Features

### High Priority

#### Multi-Session Support for Manual Signaling Modes

**Status:** Planned

Currently, `iroh-manual`, `custom`, and `nostr` modes support only one tunnel session at a time. This enhancement would allow a single sender to accept multiple simultaneous receivers.

**Scope:**
- Accept multiple signaling exchanges in parallel
- Maintain independent ICE/QUIC connections per session
- Track sessions by unique session_id
- Handle connection lifecycle independently

**Design Considerations:**
- Spawn async task for each incoming request/offer
- Shared state management for active sessions
- Graceful handling of session termination
- Resource limits (max concurrent sessions)

**Workaround (Current):**
- Use `iroh-default` mode (already supports multiple receivers)
- Run separate sender instances per tunnel
- Use different keypairs for independent tunnels

---

#### Relay Fallback for Custom/Nostr Modes

**Status:** Planned

Custom and nostr modes use full ICE but have no relay fallback for symmetric NAT scenarios where direct connectivity fails.

**Options:**
- Integrate TURN server support into ICE
- Add optional iroh relay fallback
- Implement custom relay protocol

---

### Medium Priority

#### Connection Migration

**Status:** Research

QUIC supports connection migration when IP addresses change. This would improve resilience for mobile users or network transitions.

**Use Cases:**
- Mobile device switching between WiFi and cellular
- VPN connect/disconnect scenarios
- Network interface changes

---

#### Performance Metrics

**Status:** Planned

Built-in monitoring for:
- Connection latency (RTT)
- Throughput (bytes/second)
- Packet loss statistics
- Connection uptime

**Output Options:**
- Console display
- JSON export
- Prometheus metrics endpoint

---

#### Multi-path Support

**Status:** Research

Utilize multiple network paths simultaneously for increased throughput or redundancy.

**Approaches:**
- QUIC multipath extension (when standardized)
- Application-level path bonding

---

### Low Priority

#### Web UI

**Status:** Idea

Browser-based interface for:
- Configuration management
- Connection monitoring
- Key/identity management
- Log viewing

---

#### Mobile Support

**Status:** Idea

Native support for mobile platforms:
- iOS app
- Android app
- Background service mode

---

## Contributing

Feature requests and contributions are welcome. Please open an issue on GitHub to discuss proposed changes before submitting a pull request.

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed technical architecture
- [README.md](../README.md) - Usage documentation
