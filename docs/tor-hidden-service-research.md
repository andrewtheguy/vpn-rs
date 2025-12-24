# Tor Hidden Service Signaling Research

Research on leveraging Tor hidden services via the arti crate for a signaling-only mode in tunnel-rs, enabling coordinated hole punching without relaying tunnel traffic.

## Motivation

Current tunnel-rs modes have trade-offs:
- **iroh mode**: Reliable but relays data through DERP servers (bandwidth concern)
- **nostr mode**: Signaling-only but no timing coordination (lower hole punch success)

A Tor-based signaling mode could provide:
- Signaling server with no public IP (hidden service)
- Globally accessible without port forwarding
- Timing coordination for higher hole punch success (~70% like DCUtR)
- No data relay (Tor only carries small signaling messages)

## Proposed Architecture

```
┌─────────┐     Tor (.onion)      ┌──────────────────┐     Tor (.onion)      ┌─────────┐
│ Client A│◄────signaling────────►│ Signaling Server │◄────signaling────────►│ Client B│
└────┬────┘   (small messages)    │ (hidden service) │   (small messages)    └────┬────┘
     │                            └──────────────────┘                             │
     │                                                                              │
     └──────────────────────── Direct P2P (hole punched) ──────────────────────────┘
```

**Key points:**
- Tor latency (~100-500ms) only affects signaling, not data transfer
- Signaling messages are small (< 1KB), latency acceptable
- Data flows directly between peers after successful hole punch
- If hole punch fails, no fallback (or optional Tor fallback for reliability)

## arti Crate Usage

### Dependencies

```toml
[dependencies]
arti-client = { version = "0.26", default-features = false, features = [
    "tokio",
    "rustls",
    "onion-service-client",    # For connecting to .onion
    "onion-service-service"    # For hosting hidden service
] }
tor-hsservice = "0.26"
tor-cell = "0.26"
safelog = "0.4"
```

### Ephemeral Tor Client Bootstrap

No persistent state needed - creates fresh Tor identity each run:

```rust
use arti_client::{TorClient, TorClientConfigBuilder};
use arti_client::config::StorageConfig;

let config = TorClientConfigBuilder::default()
    .storage(StorageConfig::Ephemeral)  // No persistent state/cache
    .build()?;

let tor_client = TorClient::with_runtime(runtime)
    .config(config)
    .bootstrap()
    .await?;
```

### Creating a Hidden Service (Server)

```rust
use tor_hsservice::{HsNickname, OnionServiceConfigBuilder};

// Random nickname for ephemeral service
let nickname = HsNickname::new(format!("tunnel_{}", hex::encode(&random_bytes)))?;

let onion_service = tor_client.launch_onion_service(
    OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .build()?,
)?;

// Get the .onion address to share with clients
let onion_address = onion_service.onion_name().unwrap();
println!("Signaling server: {}.onion", onion_address);
```

### Accepting Connections (Server)

```rust
use tor_hsservice::handle_rend_requests;

let mut rend_requests = handle_rend_requests(&onion_service);

while let Some(request) = rend_requests.next().await {
    let stream = request.accept().await?;
    // stream implements AsyncRead + AsyncWrite
    tokio::spawn(handle_client(stream));
}
```

### Connecting to Hidden Service (Client)

```rust
let tor_client = /* bootstrap as above */;

// Connect to .onion address
let stream = tor_client
    .connect(("abc123xyz.onion", 80))
    .await?;

// stream implements AsyncRead + AsyncWrite
```

## Signaling Protocol Design

### Message Types

```rust
#[derive(Serialize, Deserialize)]
enum SignalingMessage {
    // Registration
    Register { client_id: String },
    Registered { client_id: String },

    // RTT measurement for timing coordination
    Ping { seq: u32, timestamp: u64 },
    Pong { seq: u32, client_timestamp: u64, server_timestamp: u64 },

    // Peer discovery
    ConnectRequest {
        target_id: String,
        my_addrs: Vec<SocketAddr>,  // From STUN or configured
    },
    ConnectNotify {
        peer_id: String,
        peer_addrs: Vec<SocketAddr>,
    },

    // Coordinated hole punch
    SyncConnect {
        peer_addrs: Vec<SocketAddr>,
        start_at_ms: u64,  // Unix timestamp in milliseconds
    },

    // Result reporting
    ConnectResult { success: bool, method: Option<String> },
}
```

### Timing Coordination Flow

```
1. Both clients connect to signaling server via Tor
2. Each client measures RTT to server (3-5 ping/pong rounds)
   - Client A: RTT_A = 250ms
   - Client B: RTT_B = 180ms

3. Client A sends ConnectRequest for Client B
   - Includes public addresses (from STUN discovery)

4. Server calculates synchronized start time:
   - Current server time: T
   - Send to A at: T (arrives at T + RTT_A/2 = T + 125ms)
   - Send to B at: T (arrives at T + RTT_B/2 = T + 90ms)
   - Start time: T + max(RTT_A, RTT_B)/2 + buffer
   - Both receive ~200ms before start time

5. Server sends SyncConnect to both clients with:
   - Partner's public addresses
   - Coordinated start time

6. Both clients initiate simultaneous TCP/UDP connect at start_at_ms
   - Creates symmetric NAT hole punch opportunity
   - Success rate ~70% (similar to DCUtR)
```

### Tor Latency Considerations

Tor adds ~100-500ms latency with variability. For timing coordination:

- **RTT measurement**: Average multiple samples to reduce variance
- **Buffer time**: Add extra margin (e.g., 100ms) to account for jitter
- **Tolerance window**: Simultaneous open has ~500ms tolerance window
- **Expected accuracy**: Within 50-200ms of perfect sync (acceptable)

## Implementation Options

### Option 1: Standalone Signaling Server

Separate binary that runs as hidden service:

```
tunnel-rs-signaling --onion
```

Clients specify .onion address:
```
tunnel-rs sender tor --signaling-server abc123.onion <target>
```

**Pros:** Simple, can run on any machine
**Cons:** Requires distributing .onion address

### Option 2: Peer-to-Peer Hidden Service

Sender creates ephemeral hidden service, receiver connects directly:

```
Sender: tunnel-rs sender tor-direct <local-port>
        → Outputs: tor:abc123.onion:<key>

Receiver: tunnel-rs receiver tor:abc123.onion:<key>
```

**Pros:** No central server needed
**Cons:** Can't do timing coordination (no third party to measure RTT)

### Option 3: Hybrid with Nostr Discovery

Use Nostr to discover/publish signaling server .onion addresses:

1. Signaling server publishes .onion address to Nostr (NIP-XX)
2. Clients discover servers from Nostr relays
3. Connect to nearest/fastest signaling server via Tor
4. Proceed with coordinated hole punch

**Pros:** Decentralized server discovery
**Cons:** More complex, depends on Nostr

## Comparison with Existing Modes

| Aspect | Nostr Mode | iroh Mode | Tor Signaling (Proposed) |
|--------|------------|-----------|--------------------------|
| Signaling | Nostr relays | DNS/mDNS + relay | Tor hidden service |
| Timing sync | None | iroh handles | RTT-based coordination |
| Data relay | None | DERP fallback | None (or optional Tor) |
| Hole punch success | ~30-50% | ~95% (with relay) | ~70% (estimated) |
| Bandwidth concern | None | Relay uses bandwidth | None |
| Server requirement | Public Nostr relays | Public DERP relays | Self-hosted .onion |

## Next Steps

1. **Prototype signaling server** - Rust binary with arti, handles registration + timing
2. **Add `tor` feature to tunnel-rs** - Client-side Tor connection
3. **Implement timing coordination** - RTT measurement + synchronized connect
4. **Test hole punch success rate** - Compare with nostr mode
5. **Document deployment** - How to run signaling server as hidden service

## References

- [arti crate documentation](https://docs.rs/arti-client)
- [tor-hsservice documentation](https://docs.rs/tor-hsservice)
- [DCUtR specification](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md) - Timing coordination reference
- [wormhole-rs](https://github.com/andrewtheguy/wormhole-rs) - Example arti usage for hidden services
