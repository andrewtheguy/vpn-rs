# tunnel-rs Roadmap

This document outlines planned features and improvements for tunnel-rs.

## Current Status

tunnel-rs currently supports four operational modes:
- **iroh**: Persistent identity with automatic discovery, relay fallback, and receiver-requested sources
- **vpn**: Native TUN-based VPN with automatic IP assignment (Linux/macOS/Windows)
- **nostr**: Full ICE with automated Nostr relay signaling and receiver-requested sources
- **manual**: Full ICE with manual signaling (single-target)
- **vpn-ice (experimental)**: VPN over ICE with Nostr relay signaling

Port forwarding modes (iroh, nostr, manual) support TCP and UDP tunneling with end-to-end encryption via QUIC/TLS 1.3. VPN mode provides full network access via direct IP-over-QUIC using iroh's TLS 1.3 transport.

---

## Planned Features

### Medium Priority

#### NAT64 Enhancements

**Status:** Experimental / Partial

NAT64 basic translation is implemented for TCP, UDP, and ICMP echo (ping). It is **experimental** and intended primarily for IPv6-only VPN deployments (also **experimental**) that need IPv4 reachability. The table below shows the implementation status for each NAT64 feature:

| Feature | Status | Notes |
|---------|--------|-------|
| TCP/UDP translation | **Implemented** | Full NAPT with connection tracking |
| ICMP Echo (ping) | **Implemented** | Echo request/reply only |
| ICMP Error Messages | Not implemented | Destination Unreachable, Time Exceeded, etc. |
| IPv6 Extension Headers | Not implemented | Assumes simple IPv6 header |
| IPv4 Fragmentation | Not implemented | DF bit is set; large packets may be dropped |
| Path MTU Discovery | Not implemented | No ICMPv6 Packet Too Big generation |
| ALG (FTP, SIP, etc.) | Not implemented | Protocols embedding IP addresses in payload won't work |

**Priority improvements:**
1. **ICMP Error Translation** - Translating error messages enables proper TCP path MTU discovery and error reporting
2. **IPv6 Extension Header Handling** - Skip extension headers to find the transport layer

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

#### VPN Performance Optimizations

**Status:** Partial (quick wins implemented)

Performance improvements inspired by [quincy-rs/quincy](https://github.com/quincy-rs/quincy), a QUIC-based VPN implementation.

**Implemented:**
- LTO release profile with strip, fat LTO, single codegen unit
- jemalloc allocator (optional feature on tunnel-rs-vpn)
- Uninitialized TUN read buffers (unsafe optimization to skip buffer zeroing)
- **QUIC transport tuning** - Configurable congestion controller (Cubic/BBR/NewReno) and window sizes

**Future Improvements:**

| Improvement | Impact | Complexity | Notes |
|------------|--------|------------|-------|
| Batch TUN I/O (GSO/GRO) | High | High | Requires switching to `tun_rs` crate for Linux batch operations |

**QUIC Transport Tuning (Implemented):**

Configure congestion control algorithm and QUIC flow control windows via `[iroh.transport]`:

```toml
[iroh.transport]
congestion_controller = "cubic"  # cubic (default), bbr, newreno
receive_window = 2097152         # 2MB default (valid: 1KB-16MB)
send_window = 2097152            # 2MB default (valid: 1KB-16MB)
```

- **Cubic** (default): Loss-based, widely deployed, best for general internet
- **BBR**: Model-based, may perform better on high-bandwidth/high-latency links
- **NewReno**: Classic TCP-like, most conservative

**Batch TUN I/O Details:**
The `tun_rs` crate supports `recv_multiple`/`send_multiple` with Linux GSO/GRO offload, reducing syscall overhead by batching up to 64 packets per syscall. Current `tun` crate (v0.8) only supports single-packet operations.

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

## Contributing

Feature requests and contributions are welcome. Please open an issue on GitHub to discuss proposed changes before submitting a pull request.

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed technical architecture
- [README.md](../README.md) - Usage documentation
