# tunnel-rs Roadmap

This document outlines planned features and improvements for tunnel-rs.

## Current Status

tunnel-rs currently supports four operational modes:
- **iroh**: Persistent identity with automatic discovery, relay fallback, and receiver-requested sources
- **nostr**: Full ICE with automated Nostr relay signaling and receiver-requested sources
- **iroh-manual**: Serverless with manual signaling (single-target)
- **custom-manual**: Full ICE with manual signaling (single-target)

All modes support TCP and UDP tunneling with end-to-end encryption via QUIC/TLS 1.3.

---

## Planned Features

### High Priority

#### Receiver-Requested Source (iroh and nostr modes)

**Status:** Implemented

Both `iroh` and `nostr` modes support receiver-requested sources, similar to SSH's `-R` flag for reverse tunnels. Senders restrict allowed networks via `--allowed-tcp` / `--allowed-udp` flags or config file.

**Usage (iroh mode):**
```bash
# Sender: allow networks via CIDR
tunnel-rs sender iroh \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-tcp 192.168.0.0/16 \
  --allowed-udp 10.0.0.0/8

# Receiver: request a specific source
tunnel-rs receiver iroh \
  --node-id <sender-node-id> \
  --source tcp://127.0.0.1:22 \
  --listen 127.0.0.1:2222
```

**Usage (nostr mode):**
```bash
# Sender: allow networks via CIDR
tunnel-rs sender nostr --nsec-file ./sender.nsec \
  --peer-npub npub1receiver... \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-udp 10.0.0.0/8

# Receiver: request a specific source
tunnel-rs receiver nostr --nsec-file ./receiver.nsec \
  --peer-npub npub1sender... \
  --source tcp://127.0.0.1:22 \
  --listen 127.0.0.1:2222
```

**Network Patterns (CIDR):**
- IPv4: `127.0.0.0/8`, `192.168.0.0/16`, `10.0.0.0/8`
- IPv6: `::1/128`, `fe80::/10`

**Use Cases:**
- SSH-style reverse tunneling: receiver requests `tcp://127.0.0.1:22`
- Dynamic service access without sender reconfiguration
- Multi-service tunneling from a single sender

---

### Medium Priority

#### Multi-Session and Dynamic Source Support

**Status:** Implemented

| Mode | Multi-Session | Dynamic Source |
|------|---------------|----------------|
| `iroh` | **Yes** - use `--max-sessions` (default: 100) | **Yes** - receiver specifies `--source` |
| `nostr` | **Yes** - use `--max-sessions` (default: 10) | **Yes** - receiver specifies `--source` |
| `iroh-manual` | No | No |
| `custom-manual` | No | No |

**Multi-Session** = Multiple concurrent connections to the same sender
**Dynamic Source** = Receiver specifies which service to tunnel (iroh and nostr modes)

**Implementation Details:**
- Each session gets independent ICE/QUIC stack
- Session IDs prevent cross-session interference
- Automatic cleanup when receivers disconnect

---

#### Relay Fallback for Custom-Manual/Nostr Modes

**Status:** Idea

Custom-manual and nostr modes use full ICE but have no relay fallback for symmetric NAT scenarios where direct connectivity fails.

---

#### Automatic Reconnection

**Status:** Partial

| Feature | Status |
|---------|--------|
| QUIC keepalive (15s interval) | **Implemented** |
| Stream retry with backoff | **Implemented** |
| Connection-level auto-reconnect | Idea |

**iroh mode (Moderate complexity):**
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
