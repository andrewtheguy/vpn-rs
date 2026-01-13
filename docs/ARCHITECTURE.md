# tunnel-rs Architecture

This document provides a comprehensive overview of the tunnel-rs architecture, including detailed diagrams of all four operational modes, component interactions, data flows, and security considerations.

## Table of Contents

- [System Overview](#system-overview)
- [Mode Comparison](#mode-comparison)
- [iroh Mode](#iroh-mode)
- [VPN Mode](#vpn-mode)
- [manual Mode](#manual-mode)
- [nostr Mode](#nostr-mode)
- [Configuration System](#configuration-system)
- [Security Model](#security-model)
- [Protocol Support](#protocol-support)
- [Mode Capabilities](#mode-capabilities)
- [Current Limitations](#current-limitations)

---

## System Overview

tunnel-rs is a P2P TCP/UDP port forwarding tool that supports multiple distinct operational modes, each optimized for different use cases and network environments.

Binary layout:
- `tunnel-rs`: iroh mode (port forwarding)
- `tunnel-rs-vpn`: VPN mode (Linux/macOS)
- `tunnel-rs-ice`: manual and nostr modes

> **Design Goal:** The project's primary goal is to provide a convenient way to connect to different networks for development or homelab purposes without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale.

```mermaid
graph TB
    subgraph "tunnel-rs Modes"
        A[iroh]
        A2[vpn]
        C[manual]
        D2[nostr]
    end

    subgraph "Use Cases"
        D[Persistent<br/>Best NAT Traversal]
        D3[Full Network VPN<br/>WireGuard Encryption]
        F[Manual Signaling<br/>Full ICE]
        F2[Automated Signaling<br/>Static Keys]
    end

    subgraph "Infrastructure"
        G[Pkarr/DNS<br/>Relay Servers]
        I[STUN Only]
        I2[STUN + Nostr Relays]
    end

    A --> D
    A2 --> D3
    C --> F
    D2 --> F2

    A --> G
    A2 --> G
    C --> I
    D2 --> I2

    style A fill:#4CAF50
    style A2 fill:#2196F3
    style C fill:#FF9800
    style D2 fill:#9C27B0
```

### Binaries & Crates

The project is split into separate binaries to isolate dependencies:

| Binary | Modes | Key Modules |
|--------|-------|-------------|
| `tunnel-rs` | `iroh` | `iroh_mode`, `auth`, `socks5_bridge` |
| `tunnel-rs-vpn` | `vpn` | `tunnel_vpn`, `auth` |
| `tunnel-rs-ice` | `manual`, `nostr` | `custom`, `nostr`, `transport` |

The `test-utils` feature is still available on the iroh crates/binary to enable `--relay-only` for testing.

### Core Components

```mermaid
graph LR
    subgraph "Core Modules"
        A[main.rs<br/>CLI & Orchestration]
        B[config.rs<br/>Configuration]
        C[tunnel.rs<br/>TCP/UDP Forwarding]
        D[endpoint.rs<br/>iroh Endpoint]
        E[secret.rs<br/>Identity Management]
        E2[auth.rs<br/>Token Authentication]
    end

    subgraph "Manual/Custom Mode"
        F[transport/ice.rs<br/>ICE with str0m]
        G[transport/quic.rs<br/>QUIC with quinn]
        H[signaling/manual.rs<br/>Offer/Answer]
        I[transport/mux.rs<br/>Stream Multiplexing]
    end

    subgraph "Nostr Mode"
        J[signaling/nostr.rs<br/>Nostr Relay Signaling]
    end

    A --> B
    A --> C
    A --> D
    A --> E
    A --> E2
    A --> F
    A --> G
    A --> H
    A --> J

    F --> G
    H --> F
    J --> H
    G --> I

    style A fill:#E3F2FD
    style C fill:#E8F5E9
    style E2 fill:#FFCCBC
    style F fill:#FFF3E0
    style G fill:#FFF3E0
    style J fill:#E1BEE7
```

---

## Mode Comparison

> **Tip for Containerized Environments:** Use `iroh` mode for Docker, Kubernetes, and cloud VM deployments. It includes relay fallback which ensures connectivity even when both peers are behind restrictive NATs (common in cloud environments). The `nostr` and `manual` modes use STUN-only NAT traversal which may fail in these environments.

### Feature Matrix

```mermaid
graph TD
    subgraph "iroh"
        A1[Discovery: Automatic]
        A2[NAT: Relay Fallback]
        A3[Setup: Minimal - EndpointId required]
        A4[Infrastructure: Required]
    end

    subgraph "manual"
        C1[Discovery: Copy-Paste]
        C2[NAT: Full ICE]
        C3[Setup: Manual Exchange]
        C4[Infrastructure: STUN Only]
    end

    style A1 fill:#C8E6C9
    style A2 fill:#C8E6C9
    style A3 fill:#C8E6C9
    style A4 fill:#FFCCBC

    style C1 fill:#FFE0B2
    style C2 fill:#C8E6C9
    style C3 fill:#FFE0B2
    style C4 fill:#C8E6C9
```

### NAT Traversal Capabilities

```mermaid
graph LR
    subgraph "NAT Types"
        A[Full Cone]
        B[Restricted Cone]
        C[Port Restricted]
        D[Symmetric]
    end

    subgraph "iroh"
        E1[✓ Direct/Relay]
        E2[✓ Direct/Relay]
        E3[✓ Direct/Relay]
        E4[✓ Relay]
    end

    subgraph "manual"
        G1[✓ Direct]
        G2[✓ Direct]
        G3[✓ Direct]
        G4[~ Best-effort<br/>may fail without relay]
    end

    A --> E1
    B --> E2
    C --> E3
    D --> E4

    A --> G1
    B --> G2
    C --> G3
    D --> G4

    style E1 fill:#C8E6C9
    style E2 fill:#C8E6C9
    style E3 fill:#C8E6C9
    style E4 fill:#C8E6C9

    style G1 fill:#C8E6C9
    style G2 fill:#C8E6C9
    style G3 fill:#C8E6C9
    style G4 fill:#FFF9C4
```

---

## iroh Mode

### Architecture Overview

```mermaid
graph TB
    subgraph "Server Side"
        A[tunnel-rs server]
        B[iroh Endpoint]
        C[Target Service<br/>e.g., SSH:22]
        D[Discovery<br/>Pkarr/DNS]
        E[Relay Server]
    end

    subgraph "Client Side"
        F[tunnel-rs client]
        G[iroh Endpoint]
        H[Local Client<br/>e.g., SSH client]
        I[Discovery<br/>Pkarr/DNS]
        J[Relay Server]
    end
    
    A --> B
    B --> C
    B --> D
    B --> E
    
    F --> G
    G --> H
    G --> I
    G --> J
    
    B <-.QUIC/TLS.-> G
    D <-.Publish/Resolve.-> I
    E <-.Fallback.-> J
    
    style A fill:#E8F5E9
    style F fill:#E8F5E9
    style B fill:#BBDEFB
    style G fill:#BBDEFB
```

### Connection Establishment Flow

```mermaid
sequenceDiagram
    participant S as Server
    participant SD as Discovery Service
    participant C as Client
    participant RS as Relay Server

    Note over S: Generate/Load Secret Key
    S->>S: Create iroh Endpoint
    S->>SD: Publish EndpointId + Addresses
    Note over S: Display EndpointId
    S->>RS: Connect to relay

    Note over C: User provides EndpointId
    C->>C: Create iroh Endpoint
    C->>SD: Resolve EndpointId
    SD-->>C: Return addresses
    C->>RS: Connect to relay

    alt Direct Connection Possible
        C->>S: Direct QUIC connection
        S-->>C: Accept connection
    else NAT Traversal Failed
        C->>RS: Connect via relay
        RS->>S: Forward connection
        S-->>RS: Accept via relay
        RS-->>C: Relay established
    end

    Note over S,C: Encrypted QUIC tunnel established

    Note over C,S: Authentication Phase
    C->>S: Open auth stream
    C->>S: AuthRequest {token}
    alt Token Valid
        S-->>C: AuthResponse {accepted}
    else Token Invalid
        S-->>C: AuthResponse {rejected}
        S->>C: Close connection
    end

    Note over C,S: Source Request Phase
    C->>S: Open source stream
    C->>S: SourceRequest {source}
    S-->>C: SourceResponse {accepted}

    loop Data Transfer
        C->>S: Forward client traffic
        S->>S: Forward to target
        S->>C: Return target response
        C->>C: Forward to client
    end
```

### TCP Tunnel Data Flow

```mermaid
graph LR
    subgraph "Client"
        A[TCP Client] -->|connect| B[Listen Socket]
        B -->|accept| C[TCP Stream]
        C -->|read| D[Buffer]
        D -->|write| E[iroh SendStream]
    end

    subgraph "QUIC Transport"
        E <-->|encrypted| F[iroh RecvStream]
    end

    subgraph "Server"
        F -->|read| G[Buffer]
        G -->|write| H[TCP Stream]
        H -->|connect| I[Target Service]
        I -->|response| H
        H -->|read| J[Buffer]
        J -->|write| K[iroh SendStream]
    end
    
    subgraph "Return Path"
        K <-->|encrypted| L[iroh RecvStream]
        L -->|read| M[Buffer]
        M -->|write| C
        C -->|send| A
    end
    
    style E fill:#BBDEFB
    style F fill:#BBDEFB
    style K fill:#BBDEFB
    style L fill:#BBDEFB
```

### UDP Tunnel Data Flow

```mermaid
graph TB
    subgraph "Client"
        A[UDP Client] -->|sendto| B[UDP Socket]
        B -->|recvfrom| C[Packet Buffer]
        C -->|encode length + data| D[iroh SendStream]
    end

    subgraph "QUIC Transport"
        D <-->|encrypted| E[iroh RecvStream]
    end

    subgraph "Server"
        E -->|decode| F[Packet Buffer]
        F -->|sendto| G[UDP Socket]
        G -->|forward| H[Target Service]
        H -->|response| G
        G -->|recvfrom| I[Response Buffer]
        I -->|encode| J[iroh SendStream]
    end
    
    subgraph "Return Path"
        J <-->|encrypted| K[iroh RecvStream]
        K -->|decode| L[Packet Buffer]
        L -->|sendto| B
        B -->|deliver| A
    end
    
    style D fill:#BBDEFB
    style E fill:#BBDEFB
    style J fill:#BBDEFB
    style K fill:#BBDEFB
```

### Endpoint Management

```mermaid
graph TB
    subgraph "Endpoint Creation"
        A[Load/Generate Secret] --> B[Create Endpoint Builder]
        B --> C{Relay URLs?}
        C -->|Yes| D[Add Custom Relays]
        C -->|No| E[Use Default Relays]
        D --> F{Relay Only?}
        E --> F
        F -->|Yes| G[Set RelayOnly Mode]
        F -->|No| H[Set RelayAndDirect Mode]
        G --> I{DNS Server?}
        H --> I
        I -->|Yes| J[Add Custom DNS]
        I -->|No| K[Use Default DNS]
        J --> L[Build Endpoint]
        K --> L
    end
    
    subgraph "Discovery"
        L --> M[Publish to Pkarr/DNS]
        M --> N[Enable mDNS]
        N --> O[Endpoint Ready]
    end
    
    style A fill:#FFE0B2
    style L fill:#C8E6C9
    style O fill:#C8E6C9
```

---

## VPN Mode

VPN mode provides full network tunneling using WireGuard encryption via the boringtun library. Unlike port forwarding modes, VPN mode creates a TUN device and routes IP traffic.

> **Note:** VPN mode is only available on Linux and macOS. It requires root/sudo privileges.

### Architecture Overview

```mermaid
graph TB
    subgraph "Client Side"
        A[Applications]
        B[TUN Device<br/>tun0: 10.0.0.2]
        C[WireGuard Tunnel<br/>boringtun]
        D[iroh Endpoint]
    end

    subgraph "Transport"
        E[iroh Connection<br/>NAT Traversal + Relay]
    end

    subgraph "Server Side"
        F[iroh Endpoint]
        G[WireGuard Tunnel<br/>boringtun]
        H[TUN Device<br/>tun0: 10.0.0.1]
        I[Target Network<br/>LAN / Internet]
    end

    A -->|IP packets| B
    B -->|capture| C
    C -->|encrypt| D
    D <-->|iroh QUIC| E
    E <-->|iroh QUIC| F
    F -->|decrypt| G
    G -->|inject| H
    H -->|forward| I

    style C fill:#4CAF50
    style G fill:#4CAF50
    style E fill:#BBDEFB
```

### Key Components

```mermaid
graph LR
    subgraph "tunnel-vpn Crate"
        A[VpnServer / VpnClient]
        B[WgTunnel<br/>boringtun wrapper]
        C[TUN Device<br/>tun crate]
        D[IP Pool<br/>address management]
        E[Signaling<br/>key exchange]
        F[VpnLock<br/>single instance]
    end

    A --> B
    A --> C
    A --> D
    A --> E
    A --> F

    style B fill:#C8E6C9
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
    C->>C: Generate ephemeral WireGuard keypair
    C->>CI: Create iroh endpoint

    CI->>SI: Connect via iroh (NAT traversal)
    SI-->>CI: Connection established

    Note over C,S: VPN Handshake Phase
    C->>S: VpnHandshake {wg_pubkey, auth_token}
    S->>S: Validate auth token
    S->>S: Allocate IP from pool
    S->>S: Generate ephemeral WireGuard keypair
    S-->>C: VpnHandshakeResponse {wg_pubkey, assigned_ip, network}

    Note over C,S: TUN Device Setup
    C->>C: Create TUN device (tun0)
    C->>C: Assign IP (10.0.0.2)
    C->>C: Configure routes
    S->>S: Create TUN device (tun0)
    S->>S: Assign IP (10.0.0.1)

    Note over C,S: WireGuard Tunnel Active
    loop Packet Flow
        C->>C: Application sends packet
        C->>C: TUN captures packet
        C->>C: WireGuard encrypts
        C->>S: Send via iroh
        S->>S: WireGuard decrypts
        S->>S: TUN injects packet
        S->>S: Forward to destination
    end
```

### WireGuard Integration

The VPN mode uses **boringtun** (Cloudflare's userspace WireGuard) for encryption:

```mermaid
graph TB
    subgraph "WgTunnel Wrapper"
        A[encapsulate<br/>plaintext → ciphertext]
        B[decapsulate<br/>ciphertext → plaintext]
        C[update_timers<br/>keepalive + handshake]
        D[Reusable Buffer<br/>avoid per-packet alloc]
    end

    subgraph "boringtun Tunn"
        E[Noise Protocol<br/>key derivation]
        F[ChaCha20-Poly1305<br/>AEAD encryption]
        G[Handshake State<br/>automatic rekey]
    end

    A --> E
    B --> E
    E --> F
    C --> G

    style F fill:#C8E6C9
    style D fill:#FFF9C4
```

**Key Design Decisions:**
- **Ephemeral keys**: WireGuard keypairs are generated per-session (no static config)
- **Reusable buffers**: Avoid heap allocation per packet for performance
- **Atomic connection counting**: Server tracks active clients with `AtomicUsize`
- **Single instance lock**: File-based lock prevents multiple VPN clients

### IP Pool Management

```mermaid
graph TB
    subgraph "IP Pool (Server)"
        A[Network: 10.0.0.0/24]
        B[Server IP: 10.0.0.1]
        C[Available: 10.0.0.2 - 10.0.0.254]
        D[Allocated Set<br/>tracks in-use IPs]
    end

    subgraph "Allocation"
        E[Client connects]
        F[Find first available IP]
        G[Mark as allocated]
        H[Return to client]
    end

    subgraph "Release"
        I[Client disconnects]
        J[Return IP to pool]
    end

    E --> F
    F --> C
    F --> G
    G --> D
    G --> H

    I --> J
    J --> D

    style B fill:#FFE0B2
    style D fill:#BBDEFB
```

### Platform-Specific Details

| Platform | TUN Device | Route Configuration | Privileges |
|----------|------------|---------------------|------------|
| Linux | `/dev/net/tun` | `ip route add` | CAP_NET_ADMIN or root |
| macOS | `utunX` | `route add` | root |

### Security Model

```mermaid
graph TB
    subgraph "Authentication"
        A[Auth Token<br/>tunnel-auth format]
        B[Validate before IP assignment]
    end

    subgraph "Encryption"
        C[WireGuard<br/>Noise Protocol]
        D[ChaCha20-Poly1305]
        E[Perfect Forward Secrecy]
    end

    subgraph "Isolation"
        F[Single Instance Lock<br/>prevents conflicts]
        G[Ephemeral Keys<br/>no key reuse]
    end

    A --> B
    C --> D
    C --> E

    style D fill:#C8E6C9
    style E fill:#C8E6C9
    style F fill:#FFF9C4
```

### Auto-Reconnect and Connection Health

VPN mode includes automatic reconnection when the WireGuard tunnel fails. This handles scenarios like server restarts, network changes, or WireGuard session expiration.

**Configuration:**
- `auto_reconnect = true` (default): Automatically reconnect on connection loss
- `auto_reconnect = false`: Exit on first disconnection
- `max_reconnect_attempts`: Limit total attempts (unlimited if not set)

```mermaid
graph TB
    subgraph "Connection Health Monitoring"
        A[WireGuard Timers<br/>100ms interval]
        B[Keepalive Packets<br/>default 25s]
        C[Rekey Handshake<br/>every 120s]
    end

    subgraph "Failure Detection"
        D[Rekey Timeout<br/>5s per attempt]
        E[Session Expiration<br/>90s of failures]
        F[Connection Lost<br/>trigger reconnect]
    end

    subgraph "Recovery"
        G[Exponential Backoff<br/>1s → 60s max]
        H[Reconnect Attempt]
        I[Re-establish Tunnel]
    end

    A --> B
    A --> C
    C --> D
    D -->|repeated failures| E
    E --> F
    F --> G
    G --> H
    H --> I

    style E fill:#FFCCBC
    style F fill:#FFF9C4
    style I fill:#C8E6C9
```

**WireGuard Session Expiration:**

The boringtun library manages WireGuard handshake state. When rekey fails:
1. `REKEY_TIMEOUT` warning logged every 5 seconds
2. After 90 seconds of failures, `ConnectionExpired` error returned
3. Timer task detects error and exits VPN loop
4. `run_with_reconnect` handles reconnection with backoff

```mermaid
sequenceDiagram
    participant T as Timer Task
    participant WG as WireGuard (boringtun)
    participant VPN as VPN Loop
    participant RC as Reconnect Logic

    loop Every 100ms
        T->>WG: update_timers()
        WG-->>T: PacketResult::WriteToNetwork (handshake init)
    end

    Note over WG: Handshake responses not received
    WG->>WG: Log REKEY_TIMEOUT (5s)
    WG->>WG: Retry handshake

    Note over WG: After 90s of failures
    WG-->>T: PacketResult::Error (ConnectionExpired)
    T->>T: Log error, exit loop

    T-->>VPN: Task ended
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

## manual Mode

> **Note:** manual mode implements full ICE with STUN-only connectivity checks. TURN/relay servers are not implemented. This means symmetric NAT peers may still fail to establish a connection without a relay fallback mechanism.

### Architecture Overview

```mermaid
graph TB
    subgraph "Server Side"
        A[tunnel-rs server]
        B[ICE Agent<br/>str0m]
        C[QUIC Endpoint<br/>quinn]
        D[Stream Mux]
        E[Target Service]
    end

    subgraph "Client Side"
        F[tunnel-rs client]
        G[ICE Agent<br/>str0m]
        H[QUIC Endpoint<br/>quinn]
        I[Stream Mux]
        J[Local Client]
    end
    
    subgraph "Manual Exchange"
        K[Offer<br/>ICE Creds + Candidates]
        L[Answer<br/>ICE Creds + Candidates]
    end
    
    A --> B
    B --> C
    C --> D
    D --> E
    
    F --> G
    G --> H
    H --> I
    I --> J
    
    B --> K
    K -.Copy/Paste.-> G
    G --> L
    L -.Copy/Paste.-> B
    
    B <-.ICE Checks.-> G
    C <-.QUIC/TLS.-> H
    
    style A fill:#E8F5E9
    style F fill:#E8F5E9
    style B fill:#FFE0B2
    style G fill:#FFE0B2
    style C fill:#BBDEFB
    style H fill:#BBDEFB
```

### Full ICE + QUIC Stack

```mermaid
graph LR
    subgraph "Application Layer"
        A[TCP/UDP Tunnel Logic]
    end
    
    subgraph "Transport Layer"
        B[QUIC Streams<br/>quinn]
        C[QUIC Connection]
    end
    
    subgraph "ICE Layer"
        D[ICE Agent<br/>str0m]
        E[Connectivity Checks]
        F[Candidate Gathering]
    end
    
    subgraph "Network Layer"
        G[UDP Socket]
        H[STUN Client]
    end
    
    A --> B
    B --> C
    C --> D
    D --> E
    D --> F
    E --> G
    F --> H
    H --> G
    
    style B fill:#BBDEFB
    style C fill:#BBDEFB
    style D fill:#FFE0B2
    style E fill:#FFE0B2
```

### ICE Candidate Gathering

```mermaid
sequenceDiagram
    participant App as Application
    participant ICE as ICE Agent (str0m)
    participant Net as Network Interfaces
    participant STUN as STUN Server
    
    App->>ICE: Create IceAgent
    ICE->>ICE: Generate ufrag + pwd
    
    Note over ICE: Gather Host Candidates
    ICE->>Net: List network interfaces
    Net-->>ICE: IP addresses
    
    loop For each interface
        ICE->>ICE: Bind UDP socket
        ICE->>ICE: Add host candidate
    end
    
    Note over ICE: Gather Server Reflexive
    loop For each STUN server
        ICE->>STUN: STUN Binding Request
        STUN-->>ICE: Public IP:Port
        ICE->>ICE: Add srflx candidate
    end
    
    ICE->>App: Return candidates
    App->>App: Encode to offer/answer
```

### ICE Connectivity Checks

```mermaid
graph TB
    subgraph "Candidate Pairing"
        A[Local Candidates] --> C[Generate Pairs]
        B[Remote Candidates] --> C
        C --> D[Sort by Priority]
    end
    
    subgraph "Connectivity Checks"
        D --> E[Send STUN Checks]
        E --> F{Response?}
        F -->|Yes| G[Mark Valid]
        F -->|No| H[Mark Failed]
        G --> I{Nominated?}
        I -->|Yes| J[Selected Pair]
        I -->|No| E
    end
    
    subgraph "Connection Established"
        J --> K[ICE Connected]
        K --> L[Use Socket for QUIC]
    end
    
    style G fill:#C8E6C9
    style J fill:#C8E6C9
    style K fill:#C8E6C9
```

### Signaling Flow (Custom Mode)

```mermaid
sequenceDiagram
    participant C as Client
    participant STUN as STUN Server
    participant User as User (Copy/Paste)
    participant S as Server

    Note over C: Start client
    C->>C: Create ICE Agent (Controlling)
    C->>C: Bind UDP sockets
    C->>STUN: Gather candidates
    STUN-->>C: Server reflexive addresses

    Note over C: Create Offer (v1)
    C->>C: Encode ufrag, pwd, candidates, source
    C->>User: Display Offer Block

    Note over User: Copy offer
    Note over S: Start server
    S->>S: Create ICE Agent (Controlled)
    S->>S: Bind UDP sockets
    S->>STUN: Gather candidates
    STUN-->>S: Server reflexive addresses

    User->>S: Paste offer
    S->>S: Decode remote credentials + source
    S->>S: Validate source against --allowed-tcp/udp
    S->>S: Create Answer
    S->>User: Display Answer Block

    Note over User: Copy answer
    User->>C: Paste answer
    C->>C: Decode remote credentials
    C->>C: Set remote candidates

    par ICE Connectivity Checks
        S->>C: STUN Binding Requests
        C->>S: STUN Binding Requests
    and
        C-->>S: STUN Binding Responses
        S-->>C: STUN Binding Responses
    end

    Note over S,C: Best candidate pair selected

    S->>C: QUIC Handshake over ICE socket
    C-->>S: QUIC Accept

    Note over S,C: QUIC connection established
```

### QUIC Over ICE Socket

```mermaid
graph TB
    subgraph "ICE Connection"
        A[ICE Agent] --> B[Selected Socket]
        B --> C[Local: IP:Port]
        B --> D[Remote: IP:Port]
    end
    
    subgraph "QUIC Setup"
        E[Create quinn Endpoint] --> F[Bind to ICE socket]
        F --> G[TLS Configuration]
        G --> H{Role?}
        H -->|Server| I[Connect to remote]
        H -->|Client| J[Accept connection]
    end
    
    subgraph "Data Transfer"
        I --> K[QUIC Connection]
        J --> K
        K --> L[Open Streams]
        L --> M[Multiplex TCP/UDP]
    end
    
    B --> F
    C --> F
    D --> I
    D --> J
    
    style B fill:#FFE0B2
    style K fill:#BBDEFB
    style L fill:#BBDEFB
```

### Stream Multiplexing

```mermaid
graph TB
    subgraph "TCP Tunneling"
        A[TCP Client Connection] --> B[Open QUIC Stream]
        B --> C[Send Marker Byte]
        C --> D[Bidirectional Bridge]
        D --> E[Target TCP Connection]
    end
    
    subgraph "UDP Tunneling"
        F[UDP Packet] --> G[Single Bidirectional Stream]
        G --> H[Encode: Length + Data]
        H --> I[Send over Stream]
        I --> J[Decode Packet]
        J --> K[Forward to Target]
    end
    
    subgraph "QUIC Connection"
        L[Multiple Concurrent Streams]
        B --> L
        G --> L
    end
    
    style L fill:#BBDEFB
    style D fill:#C8E6C9
    style I fill:#C8E6C9
```

### Connection Type Detection

```mermaid
graph TB
    A[ICE Connection Established] --> B{Candidate Type?}
    
    B -->|Host| C[Direct - Host]
    B -->|Server Reflexive| D[NAT Traversal - srflx]
    
    C --> E[Display Connection Info]
    D --> E
    
    E --> F[Show Local Address]
    E --> G[Show Remote Address]
    E --> H[Show Connection Type]
    
    style C fill:#C8E6C9
    style D fill:#FFF9C4
    style E fill:#E3F2FD
```

---

## nostr Mode

Nostr mode combines the full ICE implementation from manual mode with automated signaling via Nostr relays. Instead of manual copy-paste, ICE credentials are exchanged through Nostr events using static keypairs.

> **Note for Containerized Environments:** Like manual mode, nostr mode uses STUN-only NAT traversal without relay fallback. If both peers are behind restrictive NATs (common in Docker, Kubernetes, or cloud VMs), ICE connectivity may fail. For containerized deployments, consider using `iroh` mode which includes automatic relay fallback.

### Client-Initiated Dynamic Source

All modes use a **client-initiated** model for consistent UX:

- **Server**: Whitelists allowed networks with `--allowed-tcp`/`--allowed-udp` (CIDR notation)
- **Client**: Specifies which service to tunnel with `--source` (hostname:port)

This is similar to SSH's `-L` flag for local port forwarding, where the client chooses the destination.

```
Server: --allowed-tcp 10.0.0.0/8           # Whitelist networks (no ports)
Client: --source tcp://postgres:5432       # Request specific service
        --target 127.0.0.1:5432            # Local listen address
```

### Architecture Overview

```mermaid
graph TB
    subgraph "Server Side"
        A[tunnel-rs server]
        B[ICE Agent<br/>str0m]
        C[QUIC Endpoint<br/>quinn]
        D[Nostr Client]
        E[Target Service<br/>client-specified]
    end

    subgraph "Nostr Relays"
        F[relay.nostr.net]
        G[nos.lol]
        H[relay.primal.net / relay.snort.social]
    end

    subgraph "Client Side"
        I[tunnel-rs client]
        J[ICE Agent<br/>str0m]
        K[QUIC Endpoint<br/>quinn]
        L[Nostr Client]
        M[Local Client]
    end

    A --> B
    B --> C
    A --> D
    C -.->|--source| E

    I --> J
    J --> K
    I --> L
    K --> M

    D <-.Publish/Subscribe.-> F
    D <-.Publish/Subscribe.-> G
    L <-.Publish/Subscribe.-> F
    L <-.Publish/Subscribe.-> G

    B <-.ICE Checks.-> J
    C <-.QUIC/TLS.-> K

    style A fill:#E8F5E9
    style I fill:#E8F5E9
    style B fill:#FFE0B2
    style J fill:#FFE0B2
    style D fill:#E1BEE7
    style L fill:#E1BEE7
    style E fill:#FFF9C4
```

### Client-First Signaling Flow

Nostr mode uses a client-first protocol where the client initiates the signaling exchange. This allows the server to wait for clients to come online.

```mermaid
sequenceDiagram
    participant C as Client
    participant NR as Nostr Relays
    participant S as Server
    participant STUN as STUN Server

    Note over S: Start server (waits for request)
    S->>NR: Subscribe to events
    S->>S: Wait for fresh request

    Note over C: Start client
    C->>NR: Subscribe to events
    C->>C: Generate session_id + timestamp
    C->>STUN: Gather ICE candidates
    STUN-->>C: Server reflexive addresses

    Note over C: Create Request
    C->>C: Encode ufrag, pwd, candidates, session_id, timestamp, source
    C->>NR: Publish Request (kind 24242)

    NR-->>S: Deliver Request
    S->>S: Validate timestamp (reject stale)
    S->>S: Extract session_id + source
    S->>S: Validate source against --allowed-tcp/udp

    Note over S: Gather ICE candidates
    S->>STUN: STUN queries
    STUN-->>S: Server reflexive addresses

    Note over S: Create Offer
    S->>S: Encode ufrag, pwd, candidates, session_id
    S->>NR: Publish Offer (kind 24242)

    NR-->>C: Deliver Offer
    C->>C: Validate session_id matches

    Note over C: Create Answer
    C->>C: Encode session_id
    C->>NR: Publish Answer (kind 24242)

    NR-->>S: Deliver Answer
    S->>S: Validate session_id matches

    par ICE Connectivity Checks
        S->>C: STUN Binding Requests
        C->>S: STUN Binding Requests
    end

    Note over S,C: Best candidate pair selected

    S->>C: QUIC Handshake over ICE socket
    C-->>S: QUIC Accept

    Note over S,C: Encrypted tunnel established
```

### Session ID and Stale Event Filtering

Nostr events persist on relays, so tunnel-rs uses session IDs and timestamps to filter stale events from previous sessions:

```mermaid
graph TB
    subgraph "Request Message"
        A[session_id: random 16 hex chars]
        B[timestamp: Unix seconds]
        C[ICE credentials + candidates]
        C2[source: requested service]
    end

    subgraph "Server Validation"
        D[Check timestamp age]
        E{Age <= 30s?}
        F[Accept request]
        G[Ignore stale request]
    end

    subgraph "Offer/Answer"
        H[Echo session_id in Offer]
        I[Echo session_id in Answer]
    end

    subgraph "Client Validation"
        J[Check offer session_id]
        K{Matches request?}
        L[Accept offer]
        M[Ignore stale offer]
    end

    A --> D
    B --> D
    D --> E
    E -->|Yes| F
    E -->|No| G

    F --> H
    H --> J
    J --> K
    K -->|Yes| L
    K -->|No| M

    style F fill:#C8E6C9
    style L fill:#C8E6C9
    style G fill:#FFCCBC
    style M fill:#FFCCBC
```

### Nostr Event Structure

```mermaid
graph TB
    subgraph "Event Kind 24242"
        A[kind: 24242]
        B[content: base64 encoded JSON]
        C[tags]
    end

    subgraph "Tags"
        D["t" tag: transfer_id]
        E["p" tag: peer_pubkey]
        F["type" tag: message type]
    end

    subgraph "Message Types"
        G[tunnel-request]
        H[tunnel-offer]
        I[tunnel-answer]
    end

    subgraph "Transfer ID"
        J[SHA256 of sorted pubkeys]
        K[First 32 hex chars]
        L[Deterministic - both peers compute same ID]
    end

    A --> B
    A --> C
    C --> D
    C --> E
    C --> F

    F --> G
    F --> H
    F --> I

    J --> K
    K --> L
    L --> D

    style A fill:#E1BEE7
    style D fill:#FFF9C4
    style L fill:#C8E6C9
```

---

## Configuration System

### Configuration File Structure

```mermaid
graph TB
    subgraph "Config File"
        A[role: server/client]
        B[mode: iroh/manual/nostr]
        C[source/target: tcp://host:port or udp://host:port]
    end

    subgraph "Mode Sections"
        E[iroh]
        G[manual]
        H[nostr]
    end

    subgraph "iroh Options"
        I[secret_file]
        I2[auth_tokens - server only]
        I3[auth_token - client only]
        J[relay_urls]
        K[relay_only]
        L[dns_server]
        M[server_node_id - client only]
    end

    subgraph "manual Options"
        N[stun_servers]
    end

    subgraph "nostr Options"
        O[nsec/nsec_file]
        P[peer_npub]
        Q[relays]
        R[stun_servers]
    end

    A --> S[Validation]
    B --> S
    S --> E
    S --> G
    S --> H

    E --> I
    E --> I2
    E --> I3
    E --> J
    E --> K
    E --> L
    E --> M

    G --> N
    H --> O
    H --> P
    H --> Q
    H --> R

    style S fill:#FFF9C4
```

### Configuration Loading Flow

```mermaid
sequenceDiagram
    participant CLI as CLI Parser
    participant Main as Main
    participant Config as Config Module
    participant File as Config File
    
    CLI->>Main: Parse arguments
    Main->>Main: Check config flags
    
    alt --default-config
        Main->>Config: Load from default path
        Config->>File: Read ~/.config/tunnel-rs/{role}.toml (tunnel-rs) or ~/.config/tunnel-rs/{role}_ice.toml (tunnel-rs-ice)
    else -c <path>
        Main->>Config: Load from path
        Config->>File: Read specified file
    else No config flag
        Main->>Main: Use CLI arguments only
    end
    
    alt Config loaded
        File-->>Config: TOML content
        Config->>Config: Parse TOML
        Config->>Config: Validate role + mode
        Config-->>Main: Validated config
        Main->>Main: Merge with CLI args
    end
    
    Main->>Main: Proceed with merged config
```

Note: For `tunnel-rs-ice`, the mode is inferred from the config file, so `server -c <file>` / `client -c <file>` can be used without a subcommand.

### Config Validation

```mermaid
graph TB
    A[Load Config] --> B{Role matches?}
    B -->|No| C[Error: Role mismatch]
    B -->|Yes| D{Mode matches?}
    D -->|No| E[Error: Mode mismatch]
    D -->|Yes| F{Check sections}
    
    F --> G{Extra sections?}
    G -->|Yes| H[Ignored by parser]
    G -->|No| I{Required fields?}
    
    I -->|Missing| J[Error: Missing field]
    I -->|Present| K[Validation Success]
    
    style C fill:#FFCCBC
    style E fill:#FFCCBC
    style H fill:#FFF9C4
    style J fill:#FFCCBC
    style K fill:#C8E6C9
```

---

## Security Model

### Encryption Stack

```mermaid
graph TB
    subgraph "Application Data"
        A[TCP/UDP Payload]
    end
    
    subgraph "QUIC Layer"
        B[QUIC Stream Encryption]
        C[TLS 1.3]
        D[Per-Stream Keys]
    end
    
    subgraph "Transport"
        E[QUIC Packets]
        F[Authenticated Encryption]
    end
    
    subgraph "Network"
        G[UDP Datagrams]
    end
    
    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G
    
    style C fill:#C8E6C9
    style D fill:#C8E6C9
    style F fill:#C8E6C9
```

### Identity and Authentication

```mermaid
graph TB
    subgraph "iroh Mode"
        A[Server Secret Key] --> B[Ed25519 Private Key]
        B --> C[EndpointId - Public Key]
        C --> D[Client Connects]
        D --> E[Token Validation]
        E --> F{Valid Token?}
        F -->|Yes| G[Authenticated]
        F -->|No| H[Rejected]
    end

    subgraph "manual Mode"
        I[ICE Credentials] --> J[ufrag + pwd]
        J --> K[STUN Auth]
        K --> L[QUIC TLS]
    end

    style B fill:#FFE0B2
    style C fill:#C8E6C9
    style G fill:#C8E6C9
    style H fill:#FFCCBC
    style L fill:#C8E6C9
```

### Token Authentication (iroh Mode)

Iroh mode requires authentication using pre-shared tokens. Clients use ephemeral identities but must provide a valid token. **Authentication is mandatory and must complete successfully before any source requests are permitted.** The client must authenticate via a dedicated auth stream with a valid token within a 10-second timeout immediately after QUIC connection establishment.

1. **Server Configuration**: Server specifies `--auth-tokens` with one or more pre-shared tokens
2. **Client Configuration**: Client specifies `--auth-token` with the token received from the server admin
3. **Protocol Flow**: Client opens a dedicated auth stream immediately after connection and sends an `AuthRequest`. **No source requests are accepted until authentication succeeds.**
4. **Validation**: Server validates the token using `is_token_valid()` within a 10-second timeout
5. **Rejection**: Invalid tokens receive an `AuthResponse::rejected()` and the connection is closed immediately

This early validation prevents unauthorized clients from holding open connections or attempting source requests.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant A as Auth Module

    C->>S: Connect (QUIC TLS handshake)
    S->>C: Accept connection

    Note over C,S: Auth Phase (10s timeout)
    C->>S: Open auth stream
    C->>S: AuthRequest {version, auth_token}
    S->>A: is_token_valid(auth_token, auth_tokens)
    alt Token is valid
        A-->>S: true
        S->>C: AuthResponse {accepted: true}
        Note over S,C: Connection authenticated
    else Token is invalid
        A-->>S: false
        S->>C: AuthResponse {accepted: false, reason}
        S->>S: Close connection (error code 1)
        Note over S,C: Connection rejected
    else Timeout (no auth within 10s)
        S->>S: Close connection (error code 2)
        Note over S,C: Connection rejected
    end

    Note over C,S: Source Request Phase (after successful auth)
    C->>S: Open source stream
    C->>S: SourceRequest {source}
    S->>S: Validate source against allowed networks
    S->>C: SourceResponse::accepted()
    Note over S,C: Proceed with tunnel data transfer
```

### Threat Model

```mermaid
graph TB
    subgraph "Protected Against"
        A[Eavesdropping<br/>TLS 1.3 encryption]
        B[MITM<br/>Peer authentication]
        C[Replay Attacks<br/>QUIC nonces]
        D[Tampering<br/>Authenticated encryption]
        E2[Unauthorized Access<br/>Token Authentication - iroh mode]
    end

    subgraph "User Responsibility"
        E[Signaling Channel Security<br/>Manual modes]
        F[Secret Key Protection<br/>iroh server]
        G[EndpointId Verification<br/>Trust on first use]
        H[Auth Token Security<br/>Treat tokens like passwords]
    end

    style A fill:#C8E6C9
    style B fill:#C8E6C9
    style C fill:#C8E6C9
    style D fill:#C8E6C9
    style E2 fill:#C8E6C9

    style E fill:#FFF9C4
    style F fill:#FFF9C4
    style G fill:#FFF9C4
    style H fill:#FFF9C4
```

### Secret Key Management (Server Only)

In iroh mode, only the **server** needs a persistent secret key to maintain a stable EndpointId. Clients use ephemeral identities and authenticate via tokens.

```mermaid
sequenceDiagram
    participant User as User
    participant CLI as CLI
    participant Secret as Secret Module
    participant FS as File System

    alt Generate Server Key
        User->>CLI: generate-server-key --output server.key
        CLI->>Secret: Generate Ed25519 key
        Secret->>Secret: Derive EndpointId
        Secret->>FS: Write with 0600 permissions
        FS-->>Secret: Success
        Secret->>CLI: Display EndpointId
        CLI->>User: Show EndpointId (share with clients)
    end

    alt Load Server Secret
        User->>CLI: server --secret-file server.key
        CLI->>FS: Read key file
        FS-->>Secret: Key bytes
        Secret->>Secret: Parse Ed25519 key
        Secret->>Secret: Derive EndpointId
        Secret-->>CLI: Secret + EndpointId
    end

    alt Show EndpointId
        User->>CLI: show-server-id --secret-file server.key
        CLI->>FS: Read key file
        FS-->>Secret: Key bytes
        Secret->>Secret: Derive EndpointId
        Secret->>User: Display EndpointId
    end
```

---

## Protocol Support

### TCP Tunneling Architecture

```mermaid
graph TB
    subgraph "Client Side"
        A[Listen Socket] --> B[Accept Connection]
        B --> C[TCP Stream]
        C --> D[Async Read/Write]
    end

    subgraph "QUIC Tunnel"
        E[Open Bi-Stream]
        F[Send Stream]
        G[Recv Stream]
    end

    subgraph "Server Side"
        H[Connect to Target]
        I[TCP Stream]
        J[Async Read/Write]
    end
    
    D --> E
    E --> F
    E --> G
    
    F --> J
    G --> D
    J --> H
    
    style E fill:#BBDEFB
    style F fill:#BBDEFB
    style G fill:#BBDEFB
```

### UDP Tunneling Architecture

```mermaid
graph TB
    subgraph "Client Side"
        A[UDP Socket] --> B[Receive Packet]
        B --> C[Track Client Address]
        C --> D[Encode: u16 len + data]
    end

    subgraph "QUIC Tunnel"
        E[Single Bidirectional Stream]
        F[Send Stream]
        G[Recv Stream]
    end

    subgraph "Server Side"
        H[Decode Packet]
        I[Send to Target]
        J[Receive Response]
        K[Encode Response]
    end
    
    subgraph "Return Path"
        L[Send via QUIC]
        M[Decode at Client]
        N[Send to Client]
    end
    
    D --> E
    E --> F
    F --> H
    H --> I
    I --> J
    J --> K
    K --> L
    L --> G
    G --> M
    M --> N
    N --> C
    
    style E fill:#BBDEFB
    style F fill:#BBDEFB
    style G fill:#BBDEFB
    style L fill:#BBDEFB
```

### UDP Packet Framing

```mermaid
graph LR
    subgraph "UDP Packet"
        A[Payload<br/>variable length]
    end
    
    subgraph "QUIC Stream Frame"
        B[Length<br/>u16 BE]
        C[Payload<br/>bytes]
    end
    
    subgraph "Decoding"
        D[Read 2 bytes]
        E[Parse length]
        F[Read N bytes]
        G[Reconstruct packet]
    end
    
    A --> B
    A --> C
    
    B --> D
    D --> E
    E --> F
    C --> F
    F --> G
    
    style B fill:#FFF9C4
    style C fill:#C8E6C9
```

---

## Component Details

### IceAgent (str0m)

The `IceAgent` from str0m handles ICE connectivity establishment:

- **Candidate Gathering**: Discovers local and server-reflexive addresses
- **Connectivity Checks**: Performs STUN binding checks to all candidate pairs
- **Nomination**: Selects the best working candidate pair
- **Socket Management**: Provides the UDP socket for QUIC transport

### QUIC Endpoint (quinn)

The `quinn` QUIC implementation provides:

- **TLS 1.3**: Encrypted transport with certificate-based auth
- **Stream Multiplexing**: Multiple concurrent streams over one connection
- **Congestion Control**: Built-in congestion control and flow control
- **0-RTT**: Not currently enabled (future optimization)

### Endpoint (iroh)

The `iroh::Endpoint` provides:

- **Discovery**: Automatic peer discovery via Pkarr/DNS/mDNS
- **Relay**: Fallback relay servers for NAT traversal
- **QUIC**: Built-in QUIC transport with hole punching
- **Identity**: Ed25519-based peer identity and authentication

### SOCKS5 Bridge (Tor Support)

For `.onion` relay URLs, tunnel-rs creates local TCP bridges through a Tor SOCKS5 proxy:

- **Tor-Only**: SOCKS5 proxy requires all relay URLs to be `.onion` addresses
- **Proxy Validation**: At startup, validates the proxy is a real Tor proxy via `check.torproject.org`
- **Relay Bridge**: Routes relay connections through SOCKS5 proxy to `.onion` addresses
- **Transparent**: URLs are rewritten to localhost, iroh connects normally
- **No DNS Server**: When using SOCKS5 proxy, DNS server is not used (relay handles discovery)
- **Direct P2P Bypass**: Direct P2P connections bypass Tor entirely (no performance impact)

---

## Performance Considerations

### Connection Establishment Times

```mermaid
graph LR
    subgraph "iroh"
        A[Discovery: 1-3s]
        B[Connection: 0.5-2s]
        C[Total: 1.5-5s]
    end

    subgraph "manual"
        H[ICE Gather: 1-2s]
        I[Manual: User dependent]
        J[ICE Checks: 1-3s]
        K[QUIC: 0.5s]
        L[Total: 2.5-5.5s + manual]
    end

    style C fill:#FFF9C4
    style L fill:#FFF9C4
```

### Throughput Characteristics

- **TCP Tunneling**: Limited by QUIC stream flow control and congestion control
- **UDP Tunneling**: Additional framing overhead (2 bytes per packet)
- **Relay Mode**: Higher latency, potentially lower throughput
- **Direct Mode**: Near-native performance with encryption overhead

---

## Error Handling

### Connection Failures

```mermaid
graph TB
    A[Connection Attempt] --> B{Success?}
    B -->|Yes| C[Established]
    B -->|No| D{Mode?}
    
    D -->|iroh| E{Relay available?}
    E -->|Yes| F[Fallback to relay]
    E -->|No| G[Connection failed]

    D -->|manual| I[ICE checks failed]
    
    F --> C
    H --> G
    I --> G
    
    style C fill:#C8E6C9
    style F fill:#FFF9C4
    style G fill:#FFCCBC
```

### Stream Errors

- **TCP**: Connection reset, timeout → close QUIC stream
- **UDP**: Packet loss → no retry (UDP semantics preserved)
- **QUIC**: Stream reset → close local TCP connection or stop UDP forwarding

---

## Mode Capabilities

| Mode | Multi-Session | Dynamic Source | Encryption | Platform |
|------|---------------|----------------|------------|----------|
| `iroh` | **Yes** | **Yes** | QUIC/TLS 1.3 | Linux, macOS, Windows |
| `vpn` | **Yes** | N/A (full tunnel) | WireGuard + QUIC | Linux, macOS |
| `nostr` | **Yes** | **Yes** | QUIC/TLS 1.3 | Linux, macOS, Windows |
| `manual` | No | **Yes** | QUIC/TLS 1.3 | Linux, macOS, Windows |

**Multi-Session** = Multiple concurrent connections to the same server
**Dynamic Source** = Client specifies which service to tunnel (via `--source`)
**VPN Mode** = Full network tunneling with automatic IP assignment (no per-port config)

---

## Current Limitations

### Single Session (Manual Signaling Mode)

The `manual` mode currently supports only one tunnel session at a time per server instance. Each signaling exchange establishes exactly one tunnel.

```mermaid
graph TB
    subgraph "manual Behavior"
        A[Server starts] --> B[Wait for client offer]
        B --> C[Validate source request]
        C --> D[Establish single tunnel]
        D --> E[Handle streams over this tunnel]
        E --> F[Additional clients timeout]
    end

    subgraph "Workarounds"
        G[Run multiple server instances]
        I[Use iroh mode]
    end

    style F fill:#FFCCBC
    style I fill:#C8E6C9
```

**Why this limitation exists:**
- Manual signaling mode performs a single offer/answer exchange
- The server enters a connection handling loop after establishing the tunnel
- No mechanism to accept additional signaling while serving existing tunnel

**Workarounds:**
- Use `iroh` mode for multi-client support
- Run separate server instances for each tunnel

See [Roadmap](ROADMAP.md) for planned multi-session support.

---

## References

- [iroh Documentation](https://iroh.computer/)
- [str0m ICE Implementation](https://github.com/algesten/str0m)
- [quinn QUIC Implementation](https://github.com/quinn-rs/quinn)
- [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
- [RFC 9000 - QUIC](https://datatracker.ietf.org/doc/html/rfc9000)
