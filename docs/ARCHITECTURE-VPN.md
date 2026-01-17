# tunnel-rs Architecture: VPN

This document covers VPN mode architecture, including NAT64.
See `docs/ARCHITECTURE.md` for common architecture components.

## VPN Mode

VPN mode provides full network tunneling using direct IP-over-QUIC. Unlike port forwarding modes, VPN mode creates a TUN device and routes IP traffic directly through the encrypted Iroh QUIC connection. This eliminates double encryption overhead while maintaining strong security via TLS 1.3.

> **Note:** VPN mode requires root/admin privileges. On Windows, you also need `wintun.dll` from https://www.wintun.net/ (official WireGuard project) — download the zip, extract, and copy `wintun/bin/amd64/wintun.dll` to the same directory as the executable (or any directory in the system PATH).

### Architecture Overview

```mermaid
graph TB
    subgraph "Client Side"
        A[Applications]
        B[TUN Device<br/>tun0: 10.0.0.2<br/>fd00::2]
        D[iroh Endpoint]
    end

    subgraph "Transport"
        E[iroh Connection<br/>NAT Traversal + Relay]
    end

    subgraph "Server Side"
        F[iroh Endpoint]
        H[TUN Device<br/>tun0: 10.0.0.1<br/>fd00::1]
        I[Target Network<br/>LAN / Internet]
    end

    A -->|IP packets| B
    B -->|read & frame| D
    D <-->|iroh QUIC| E
    E <-->|iroh QUIC| F
    F -->|write & unframe| H
    H -->|forward| I

    style B fill:#FFE0B2
    style H fill:#FFE0B2
    style E fill:#BBDEFB
```

**IPv6 Dual-Stack Support:**

VPN mode supports optional IPv6 alongside IPv4. When `network6` is configured on the server, clients receive both an IPv4 address and an IPv6 address. This enables:
- Native IPv6 connectivity through the VPN tunnel
- Dual-stack applications (IPv4 and IPv6 simultaneously)
- Backwards compatibility (IPv4-only configs continue to work)

IPv4 is optional: the server can run IPv6-only with `network6` and no `network`. **IPv6-only mode is experimental.** In that mode, IPv4 reachability is only available via **experimental** NAT64.

### Key Components

```mermaid
graph LR
    subgraph "tunnel-vpn Crate"
        A[VpnServer / VpnClient]
        C[TUN Device<br/>tun crate]
        D[IP Pool<br/>address management]
        E[Signaling<br/>handshake & framing]
        F[VpnLock<br/>single instance]
    end

    A --> C
    A --> D
    A --> E
    A --> F

    style C fill:#FFE0B2
    style E fill:#BBDEFB
```

### Connection Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant CI as Client iroh
    participant SI as Server iroh
    participant S as Server

    Note over C: User runs vpn client
    C->>C: Acquire VPN lock
    C->>C: Generate session device_id
    C->>CI: Create iroh endpoint

    CI->>SI: Connect via iroh (NAT traversal)
    SI-->>CI: Connection established

    Note over C,S: VPN Handshake Phase
    C->>S: VpnHandshake {device_id, auth_token}
    S->>S: Validate auth token
    S->>S: Store client (EndpointId, device_id)
    S->>S: Allocate IP(s) from pool(s)
    S-->>C: VpnHandshakeResponse {assigned_ip, network, server_ip, ...}

    Note over C,S: TUN Device Setup
    C->>C: Create TUN device (tun0)
    C->>C: Assign IP(s) (10.0.0.2, fd00::2)
    C->>C: Configure routes
    S->>S: Create TUN device (tun0)
    S->>S: Assign IP(s) (10.0.0.1, fd00::1)

    Note over C,S: Direct IP Tunnel Active
    loop Packet Flow
        C->>C: Application sends packet
        C->>C: TUN captures packet
        C->>S: Send over QUIC (encrypted)
        S->>S: Unframe IP packet
        S->>S: TUN injects packet
        S->>S: Forward to destination
    end
```

**`VpnHandshakeResponse` Fields:**

The response includes different fields depending on the server's address configuration:

| Mode | Fields in Response |
|------|-------------------|
| IPv4-only | `assigned_ip`, `network`, `server_ip` |
| IPv6-only | `assigned_ip6`, `network6`, `server_ip6` |
| Dual-stack | All six fields: `assigned_ip`, `network`, `server_ip`, `assigned_ip6`, `network6`, `server_ip6` |

When `network6` is configured on the server, clients receive IPv6 addresses alongside IPv4 (dual-stack) or IPv6-only if `network` is omitted.

### Direct IP over QUIC Integration

The VPN mode sends raw IP packets directly over Iroh's QUIC streams (using TLS 1.3). This removes the double encryption overhead of running WireGuard inside QUIC.

**Key Design Decisions:**
- **Framing**: IP packets are length-prefixed and sent over the QUIC stream.
- **Security**: Relies on Iroh/QUIC's built-in encryption (TLS 1.3) with Noise-derived keys.
- **Efficiency**: Zero-copy forwarding where possible between TUN and QUIC buffers.
- **Identification**: Clients identify via a random `u64` `device_id` generated at startup, allowing multiple sessions per Iroh endpoint.
- **Reconnects**: The server automatically manages session limits and cleanup, allowing seamless reconnects from the same device ID.

**Device ID Generation:**

The `device_id` is generated using `rand::thread_rng()`, which in rand 0.8 provides a thread-local CSPRNG (ChaCha12) seeded from OS entropy via `OsRng`. This produces cryptographically random 64-bit values suitable for unique session identification.

**Security Considerations:**

The `device_id` is used **purely for session tracking** within an already-authenticated iroh connection—it is NOT used for access control. Security relies on:
1. Iroh's cryptographic `EndpointId` authentication (Noise protocol)
2. Auth token validation (if configured)

Clients are keyed by `(EndpointId, device_id)`, so an attacker cannot hijack a session by guessing a `device_id` without also possessing the victim's iroh private key.

**Collision Handling:**

The 64-bit ID space provides a ~2^32 birthday bound for collisions, which is sufficient for session tracking across reasonable client counts (thousands of concurrent sessions). Unpredictability is not a security requirement since `device_id` only differentiates sessions from the same authenticated endpoint. We use `rand::thread_rng()` (a CSPRNG) for defense-in-depth: it avoids predictable collision patterns, reduces correlation/timing attack surface, and makes accidental collisions less likely in practice.

### IP Pool Management

```mermaid
graph TB
    subgraph "IPv4 Pool (Server)"
        A[Network: 10.0.0.0/24]
        B[Server IP: 10.0.0.1]
        C[Available: 10.0.0.2 - 10.0.0.254]
        D[Allocated Set<br/>tracks in-use IPs]
    end

    subgraph "IPv6 Pool (Optional)"
        A6[Network: fd00::/64]
        B6[Server IP: fd00::1]
        C6[Available: fd00::2 onwards]
        D6[Allocated Set<br/>one IPv6 per client]
    end

    subgraph "Allocation"
        E[Client connects]
        F[Find first available IPv4]
        F6[Find first available IPv6]
        G[Mark as allocated]
        H[Return to client]
    end

    subgraph "Release"
        I[Client disconnects]
        J[Return IPs to pools]
    end

    E --> F
    E -.->|if IPv6 enabled| F6
    F --> C
    F6 --> C6
    F --> G
    F6 --> G
    G --> D
    G -.-> D6
    G --> H

    I --> J
    J --> D
    J -.-> D6

    style B fill:#FFE0B2
    style B6 fill:#FFE0B2
    style D fill:#BBDEFB
    style D6 fill:#BBDEFB
```

When `network6` is configured, each client receives both an IPv4 and IPv6 address. The IPv6 pool works identically to the IPv4 pool, with each client getting a single /128 address. Unlike IPv4, a /64 network provides an effectively unlimited address space (~18.4 quintillion (2^64) addresses), so pool exhaustion is not a practical concern for IPv6. If `network` is omitted, the IPv4 pool is not created and the server runs IPv6-only (experimental); NAT64 (also experimental) can be enabled to reach IPv4 destinations.

### NAT64 (Experimental)

NAT64 allows IPv6-only VPN clients to reach IPv4 destinations by translating IPv6 packets
destined for the well-known NAT64 prefix `64:ff9b::/96` into IPv4 and performing NAPT.
This is intended for IPv6-only server deployments where `network6` is set and `network`
is omitted. NAT64 requires an IPv4 source address for translated packets, provided by
either the VPN IPv4 network (when configured) or an explicit `nat64.source_ip`.

```mermaid
sequenceDiagram
    participant C as Client (IPv6)
    participant S as Server
    participant V4 as IPv4 Dest

    C->>S: IPv6 packet to 64:ff9b::/96
    S->>S: Translate IPv6->IPv4 + NAPT
    S->>V4: IPv4 packet (src = nat64.source_ip)
    V4-->>S: IPv4 response
    S-->>C: IPv6 response (translated)
```

**Limitations (current):**
- ICMP error translation is not implemented.
- IPv6 extension headers are not parsed.
- Fragmentation handling and PMTU discovery are not implemented.

### Platform-Specific Details

| Platform | TUN Device | Route Configuration | Privileges |
|----------|------------|---------------------|------------|
| Linux | `/dev/net/tun` | `ip route add` | CAP_NET_ADMIN or root |
| macOS | `utunX` | `route add` | root |
| Windows | `wintun.dll` | `route add` | Administrator |
### Security Model

```mermaid
graph TB
    subgraph "Authentication"
        A[Auth Token<br/>tunnel-auth format]
        B[Validate before IP assignment]
    end

    subgraph "Encryption"
        C[Iroh QUIC<br/>TLS 1.3]
        E[Forward Secrecy]
    end

    subgraph "Isolation"
        F[Single Instance Lock<br/>prevents conflicts]
        G[Session Keys<br/>per-connection]
    end

    A --> B
    C --> E

    style E fill:#C8E6C9
    style F fill:#FFF9C4
```

### Auto-Reconnect and Connection Health

VPN mode includes automatic reconnection when the tunnel connection fails. This handles scenarios like server restarts or network partitions.

**Configuration:**
- `auto_reconnect = true` (default): Automatically reconnect on connection loss
- `auto_reconnect = false`: Exit on first disconnection
- `max_reconnect_attempts`: Limit total attempts (unlimited if not set)

**Health Monitoring Layers:**

The VPN client uses two complementary health monitoring mechanisms:

1. **Application-Level Heartbeat** (fast detection, ~30s)
   - Client sends ping every 10 seconds
   - Server responds with pong immediately
   - Client triggers reconnection if no pong received within 30 seconds
   - Detects: server restart, IP changes, network partitions, NAT timeout, relay issues

2. **Connection Monitoring** (instant)
   - Iroh/QUIC connection errors (timeouts, closures)
   - TUN read/write errors

**Interaction Between Layers:**
- Heartbeat traffic uses the same underlying iroh QUIC connection as the VPN data.
- If heartbeats fail, it indicates an issue with the QUIC connection itself.
```mermaid
graph TB
    subgraph "Application Heartbeat (Fast)"
        H1[Heartbeat Ping<br/>10s interval]
        H2[Heartbeat Pong<br/>server response]
        H3[Timeout Check<br/>30s threshold]
    end

    subgraph "Failure Detection"
        D[Heartbeat Timeout<br/>30s no pong]
        E[QUIC Error<br/>Connection Lost]
        F[Connection Down<br/>trigger reconnect]
    end

    subgraph "Recovery"
        G[Exponential Backoff<br/>1s → 60s max]
        HH[Reconnect Attempt]
        I[Re-establish Tunnel]
    end

    H1 --> H2
    H2 --> H3
    H3 -->|no pong| D
    D --> F
    E --> F
    F --> G
    G --> HH
    HH --> I

    style D fill:#FFE0B2
    style E fill:#FFCCBC
    style F fill:#FFF9C4
    style I fill:#C8E6C9
```

**Application-Level Heartbeat Protocol:**

Heartbeats and IP packets are multiplexed on the same bidirectional QUIC stream (the "data stream" opened after handshake). All messages are prefixed with a 1-byte type discriminator defined in `DataMessageType` in `crates/tunnel-vpn/src/signaling.rs`:

```
Data channel message framing:

  IP packet (type 0x00):
    [0x00] [4 bytes: length BE u32] [N bytes: raw IP packet]

  Heartbeat ping (type 0x01):
    [0x01]

  Heartbeat pong (type 0x02):
    [0x02]
```

**Implementation locations** (search by symbol name; line numbers may shift):
- Type enum: `DataMessageType` in `signaling.rs`
- Packet framing: `frame_ip_packet()` in `signaling.rs`
- Client send (outbound): TUN reader task in `client.rs` - calls `frame_ip_packet()`
- Client receive (inbound): inbound reader task in `client.rs` - reads type byte, dispatches via `DataMessageType::from_byte()`
- Client heartbeat sender: heartbeat task in `client.rs` - sends `HeartbeatPing` byte
- Server receive: inbound reader task in `server.rs` - reads type byte, responds to pings with `HeartbeatPong`
- Server send: TUN reader and timer tasks in `server.rs` - call `frame_ip_packet()`

**Compatibility note:** This framing was added with the heartbeat feature. Older clients/servers that expect raw length-prefixed IP packets (without the type byte) are incompatible.

This allows fast failure detection (~30 seconds) for common issues like server restarts or network changes.

**Connection Check:**

The application uses the heartbeat to detect broken connections faster than standard TCP/QUIC timeouts.

```mermaid
sequenceDiagram
    participant T as Timer Task
    participant VPN as VPN Loop
    participant RC as Reconnect Logic

    loop Every 10s
        T->>VPN: Send Heartbeat Ping
    end

    Note over VPN: No Pong received (30s)
    T->>VPN: Timeout Error
    VPN-->>RC: VpnError::ConnectionLost

    alt auto_reconnect = true
        RC->>RC: Calculate backoff delay
        RC->>RC: Wait (1s, 2s, 4s... up to 60s)
        RC->>VPN: Reconnect
    else auto_reconnect = false
        RC->>RC: Exit with error
    end
```

**Reconnection Backoff:**
- Base delay: 1 second
- Exponential growth: 1s → 2s → 4s → 8s → 16s → 32s → 60s
- Maximum delay: 60 seconds
- Jitter: 0-500ms added to prevent thundering herd
- Counter reset: Resets to 0 after successful tunnel operation

---
