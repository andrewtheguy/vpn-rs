# tunnel-rs Roadmap

This document outlines planned features and improvements for tunnel-rs.

## Current Status

tunnel-rs currently supports four operational modes:
- **iroh-default**: Persistent identity support with automatic discovery and relay fallback
- **iroh-manual**: Serverless with manual signaling
- **custom**: Full ICE with manual signaling
- **nostr**: Full ICE with automated Nostr relay signaling

All modes support TCP and UDP tunneling with end-to-end encryption via QUIC/TLS 1.3.

---

## Planned Features

### High Priority

#### Multi-Session Support for Manual Signaling Modes

**Status:** Partial (Nostr mode complete, others planned)

| Mode | Multi-Session |
|------|---------------|
| `nostr` | **Implemented** - use `--max-sessions` (default: 10) |
| `iroh-manual` | Planned |
| `custom` | Planned |

**Nostr Mode Usage:**
```bash
# Accept up to 5 concurrent sessions
tunnel-rs sender nostr -s tcp://127.0.0.1:22 --nsec <KEY> --peer-npub <NPUB> --max-sessions 5

# Unlimited sessions
tunnel-rs sender nostr -s tcp://127.0.0.1:22 --nsec <KEY> --peer-npub <NPUB> --max-sessions 0
```

**Implementation Details (Nostr):**
- Each session gets independent ICE/QUIC stack
- Session IDs prevent cross-session interference
- Automatic cleanup when receivers disconnect
- Shared NostrSignaling client for efficient relay usage

**Remaining Work (iroh-manual, custom):**
- Manual copy-paste signaling is the bottleneck
- Would require rethinking the signaling UX

---

#### Relay Fallback for Custom/Nostr Modes

**Status:** Planned

Custom and nostr modes use full ICE but have no relay fallback for symmetric NAT scenarios where direct connectivity fails.

**Options:**
- Integrate TURN server support into ICE
- Add optional iroh relay fallback
- Implement custom relay protocol

---

#### Automatic Reconnection

**Status:** Partial

Resilience features for handling connection failures:

| Feature | Status |
|---------|--------|
| QUIC keepalive (15s interval) | **Implemented** |
| Stream retry with backoff | **Implemented** |
| Connection-level auto-reconnect | Planned |

**Current Implementation:**
- QUIC sends periodic PING frames to detect dead connections
- Failed `open_bi()` calls retry 3 times with exponential backoff (100ms → 200ms → 400ms)

**Planned (Connection-level reconnect):**
- Detect when QUIC connection is dead (not just stream failures)
- For nostr mode: Re-signal via Nostr relays and re-establish ICE/QUIC
- For iroh-default: Leverage iroh's built-in reconnection
- Seamlessly resume accepting local connections after reconnect

---

### Medium Priority

#### Connection Migration (Resilience to IP Changes)

**Status:** Research

While tunnel-rs handles dynamic IPs for *establishing* connections (via identity-based discovery), **active sessions may currently drop** if a peer's IP address changes due to a network transition (e.g., switching from WiFi to 4G). 

QUIC natively supports **connection migration**, which allows a session to continue even as the underlying network path changes. We plan to implement this to improve resilience.

**Current Behavior:**
- IP changes during an active session will likely cause the QUIC connection to time out.
- For most modes, you would need to re-initiate the connection.
- For `nostr` mode, automated re-signaling is also planned (see [Automatic Reconnection](#automatic-reconnection)).

**Use Cases:**
- Mobile device switching between WiFi and cellular
- ISP dynamic IP re-assignment during long-running tunnels
- Network interface changes (e.g., connecting/disconnecting a VPN)

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
