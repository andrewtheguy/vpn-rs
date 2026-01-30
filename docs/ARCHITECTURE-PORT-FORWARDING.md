# tunnel-rs Architecture: Port Forwarding

This document covers the port-forwarding modes (iroh, manual, nostr).
See `docs/ARCHITECTURE.md` for common architecture components.

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
        D --> F{Relay Only? (CLI-only)}
        E --> F
        F -->|Yes| G[Disable IP transports]
        F -->|No| H[Keep IP + relay transports]
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
