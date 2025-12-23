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

#### Receiver-Requested Source for Nostr Mode

**Status:** Planned

Enable receivers to request specific source endpoints, similar to SSH's `-R` flag for reverse tunnels. Currently, the sender specifies the source at startup. This feature allows receivers to dynamically request which local service to tunnel.

**Use Cases:**
- SSH-style reverse tunneling: receiver requests `tcp://127.0.0.1:22`
- Dynamic service access without sender reconfiguration
- Multi-service tunneling from a single sender

---

### Medium Priority

#### Multi-Session Support

**Status:** Partial

| Mode | Multi-Session |
|------|---------------|
| `iroh-default` | **Implemented** - unlimited concurrent receivers |
| `nostr` | **Implemented** - use `--max-sessions` (default: 10) |

**Implementation Details:**
- Each session gets independent ICE/QUIC stack
- Session IDs prevent cross-session interference
- Automatic cleanup when receivers disconnect

---

#### Relay Fallback for Custom/Nostr Modes

**Status:** Idea

Custom and nostr modes use full ICE but have no relay fallback for symmetric NAT scenarios where direct connectivity fails.

---

#### Automatic Reconnection

**Status:** Partial

| Feature | Status |
|---------|--------|
| QUIC keepalive (15s interval) | **Implemented** |
| Stream retry with backoff | **Implemented** |
| Connection-level auto-reconnect | Idea |

**iroh-default mode (Moderate complexity):**
- Add receiver-side connection retry loop with exponential backoff
- Iroh's discovery automatically re-resolves sender's new IP/relay address

**nostr mode (Higher complexity):**
- Re-signal via Nostr relays and re-establish ICE/QUIC

---

#### Connection Migration (Resilience to IP Changes)

**Status:** Idea

QUIC natively supports connection migration, allowing sessions to continue when network path changes. Currently, active sessions may drop if a peer's IP changes.

---

#### Performance Metrics

**Status:** Idea

Built-in monitoring for connection latency, throughput, packet loss, and uptime.

---

#### Multi-path Support

**Status:** Idea

Utilize multiple network paths simultaneously for increased throughput or redundancy.

---

#### Web UI

**Status:** Idea

Browser-based interface for configuration, monitoring, and key management.

---

## Contributing

Feature requests and contributions are welcome. Please open an issue on GitHub to discuss proposed changes before submitting a pull request.

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed technical architecture
- [README.md](../README.md) - Usage documentation
