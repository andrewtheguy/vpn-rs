# tunnel-rs Roadmap

This document outlines planned features and improvements for tunnel-rs.

## Current Status

tunnel-rs currently supports three stable operational modes:
- **iroh**: Persistent identity with automatic discovery, relay fallback, and receiver-requested sources
- **nostr**: Full ICE with automated Nostr relay signaling and receiver-requested sources
- **manual**: Full ICE with manual signaling (single-target)

All modes support TCP and UDP tunneling with end-to-end encryption via QUIC/TLS 1.3.

---

## Planned Features

### High Priority

#### Receiver-Requested Source (iroh and nostr modes)

**Status:** Implemented

Both `iroh` and `nostr` modes support receiver-requested sources, similar to SSH's `-R` flag for reverse tunnels. Senders restrict allowed networks via `--allowed-tcp` / `--allowed-udp` flags or config file.

**Usage (iroh mode):**
```bash
# Server: allow networks via CIDR
tunnel-rs server \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-tcp 192.168.0.0/16 \
  --allowed-udp 10.0.0.0/8

# Client: request a specific source
tunnel-rs client \
  --server-node-id <sender-node-id> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

**Usage (nostr mode):**
```bash
# Server: allow networks via CIDR
tunnel-rs-ice server nostr --nsec-file ./server.nsec \
  --peer-npub npub1receiver... \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-udp 10.0.0.0/8

# Client: request a specific source
tunnel-rs-ice client nostr --nsec-file ./receiver.nsec \
  --peer-npub npub1sender... \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
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
| `manual` | No | No |

**Multi-Session** = Multiple concurrent connections to the same sender
**Dynamic Source** = Receiver specifies which service to tunnel (iroh and nostr modes)

**Implementation Details:**
- Each session gets independent ICE/QUIC stack
- Session IDs prevent cross-session interference
- Automatic cleanup when receivers disconnect

---

#### Multi-Source/Target per Client

**Status:** Idea

Currently, each client connection tunnels a single source to a single target. This feature would allow a single client to tunnel multiple source/target pairs simultaneously, with live updates.

**Proposed Features:**
- **Multiple tunnels per client**: Configure multiple `--source`/`--target` pairs in one client instance
- **Live update**: Add/remove tunnels without restarting the client (via config file reload, API, or CLI command)
- **Config file support**: Define multiple tunnels in TOML config

**Example (proposed config):**
```toml
role = "client"
mode = "iroh"

[iroh]
server_node_id = "..."
auth_token = "..."

[[iroh.tunnels]]
source = "tcp://127.0.0.1:22"
target = "127.0.0.1:2222"

[[iroh.tunnels]]
source = "tcp://127.0.0.1:5432"
target = "127.0.0.1:5432"

[[iroh.tunnels]]
source = "udp://127.0.0.1:53"
target = "udp://127.0.0.1:5353"
```

**Complexity:** High
- Requires refactoring client to manage multiple listener loops
- Live update needs signal handling (SIGHUP) or control socket/API
- State management for adding/removing tunnels without disrupting existing connections
- Error handling per-tunnel (one tunnel failure shouldn't affect others)

**Use Cases:**
- Single client exposing multiple services (SSH + database + DNS)
- Dynamic service discovery and tunnel provisioning
- Reduced overhead vs. running multiple client processes

---

#### Auth Rate Limiting

**Status:** Idea

Rate limiting for token authentication to prevent brute-force attacks. Hybrid approach with per-client limits (for typo handling) and global limits (for distributed attack detection).

See [RATE_LIMITING_PROPOSAL.md](RATE_LIMITING_PROPOSAL.md) for detailed design.

---

#### macOS Localhost Multi-Binding (tunnel-ice only)

**Status:** Idea

**Note:** This issue affects **tunnel-ice only** (nostr and manual modes). The iroh mode is already fixed.

On macOS, third-party apps connecting to `localhost` try IPv6 (`::1`) before IPv4 (`127.0.0.1`). If the tunnel-ice client only binds to one address, connections may fail or experience 250ms delays. The fix is to bind to both addresses when listening on localhost.

See [MACOS_LOCALHOST_PROPOSAL.md](MACOS_LOCALHOST_PROPOSAL.md) for detailed design.

---

#### Relay Fallback for manual/nostr Modes

**Status:** Idea

manual and nostr modes use full ICE but have no relay fallback for symmetric NAT scenarios where direct connectivity fails.

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

#### Smart Routing (Server Mesh)

**Status:** Idea

A mesh of tunnel-rs servers where clients can connect to any server and be redirected to the optimal server based on routing rules.

**Concept:**
- Multiple tunnel-rs servers form a mesh, each responsible for certain CIDR ranges or services
- Client connects to any server in the mesh
- Server evaluates the requested source against routing rules and either:
  - Handles the connection directly if it owns the route
  - Returns the address of the best server for that destination
  - Proxies the connection through the mesh

**Proposed Routing Criteria:**
- **CIDR-based**: Route `10.0.0.0/8` to Server A, `192.168.0.0/16` to Server B
- **Service-based**: Route database connections to Server A, SSH to Server B
- **Geographic**: Route based on client location for latency optimization
- **Load-based**: Distribute connections across servers based on current load

**Example (proposed config):**
```toml
role = "server"
mode = "iroh"

[mesh]
enabled = true
peers = ["node_id_a", "node_id_b", "node_id_c"]

[[mesh.routes]]
cidr = "10.0.0.0/8"
owner = "self"  # This server handles this range

[[mesh.routes]]
cidr = "192.168.0.0/16"
owner = "node_id_b"  # Redirect to Server B
```

**Complexity:** High
- Requires mesh discovery and health checking between servers
- Routing table synchronization across the mesh
- Decision: redirect client vs. proxy through mesh
- Fallback handling when preferred server is unavailable

**Use Cases:**
- Distributed infrastructure with region-specific access
- High availability with automatic failover
- Load distribution across multiple servers
- Simplified client configuration (connect to any entry point)

---

#### Native VPN Mode

**Status:** Idea

Full VPN functionality using IP-over-QUIC, eliminating the need for external VPN solutions like WireGuard.

**Motivation:**
Traditional VPNs like WireGuard require static keypair configuration per device. If two devices share the same config, they conflict. tunnel-rs can avoid this by using iroh node IDs as identity - each client is inherently unique.

**Concept:**
- Client creates TUN device, routes traffic through QUIC tunnel to server
- Server assigns unique internal IP based on client's iroh node_id
- Server routes traffic to destination (with NAT/masquerade for internet)
- No keypairs to manage - just auth token

**Architecture:**
```
Client (node_id: abc123)                Server
    │                                      │
  [tun0: 10.0.0.2] ──QUIC──> [assigns IP based on node_id]
                                           │
                              [tun0: 10.0.0.1] ──> Internet/LAN
```

**Proposed CLI:**
```bash
# Server: assign IPs from network, self gets .1
tunnel-rs vpn server --network 10.0.0.0/24

# Client: auto-assigned IP, routes traffic through tunnel
tunnel-rs vpn client --server-node-id <id> --auth-token <token>
```

**Implementation Requirements:**
- TUN device via `tun-rs` crate (cross-platform: Linux, macOS, Windows, iOS, Android)
- IP assignment protocol (server tracks node_id → IP mapping)
- Length-prefixed IP packet framing over QUIC (reuse existing helpers)
- Platform-specific routing setup
- Privilege handling (CAP_NET_ADMIN on Linux, root on macOS)

**Phases:**
1. **MVP**: TUN device, IP assignment, basic packet forwarding (Linux)
2. **Production**: Privilege dropping, reconnection, multi-client, DNS
3. **Advanced**: Split tunneling, peer-to-peer mesh, mobile support

**Advantages over WireGuard:**
| Feature | WireGuard | tunnel-rs VPN |
|---------|-----------|---------------|
| Identity | Static keypair | iroh node_id (dynamic) |
| Config conflict | Same key = conflict | Each client unique |
| NAT traversal | Manual setup | Built-in via iroh |
| IP assignment | Static in config | Dynamic from server |

**Complexity:** High
- Platform-specific TUN handling
- Routing table manipulation
- ~2 weeks MVP for Linux, additional time for other platforms

---

## Contributing

Feature requests and contributions are welcome. Please open an issue on GitHub to discuss proposed changes before submitting a pull request.

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed technical architecture
- [README.md](../README.md) - Usage documentation
