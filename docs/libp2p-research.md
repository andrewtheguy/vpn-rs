# libp2p-quic Research Findings

Research into using libp2p-quic as an alternative QUIC transport for tunnel-rs.

## Summary

**libp2p is not a good fit for serverless manual modes** because DCUtR (the hole punching protocol) requires a relay server for coordination. However, libp2p could be valuable for scenarios where automatic relay discovery is acceptable.

---

## How libp2p NAT Traversal Works

### DCUtR (Direct Connection Upgrade through Relay)

DCUtR coordinates hole punching **over an existing relayed connection**:

1. Both peers first connect to a public relay server
2. Relay forwards coordination messages between peers
3. Peers exchange addresses via libp2p Identify protocol
4. DCUtR measures RTT and coordinates simultaneous connection attempts
5. Direct connection established (or falls back to relay)

**Success rate:** ~70% in production ([FOSDEM 2023 presentation](https://archive.fosdem.org/2023/schedule/event/network_hole_punching_in_the_wild/))

### Key Limitation

DCUtR **cannot work with manual copy-paste signaling** - it requires an active relay connection for coordination. This fundamentally differs from our custom mode (ICE) which is serverless.

---

## Automatic Relay Discovery

libp2p can automatically discover relay servers through:

1. **Bootstrap nodes** - Entry points to the Kademlia DHT
2. **DHT lookup** - Search for nodes advertising `/libp2p/relay` protocol
3. **AutoNAT** - Detect if node is behind NAT
4. **AutoRelay** - Automatically bind to discovered relays

### Public Bootstrap Nodes

IPFS/libp2p maintains public bootstrap nodes for DHT entry:

```
/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN
/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa
/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb
/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt
/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ
```

These resolve via DNS TXT records at `_dnsaddr.bootstrap.libp2p.io` to regional nodes:
- Amsterdam (`ams-2.bootstrap.libp2p.io`)
- San Jose (`sjc-1.bootstrap.libp2p.io`)
- Tokyo (`nrt-1.bootstrap.libp2p.io`)
- Newark (`ewr-1.bootstrap.libp2p.io`)

### Important: Bootstrap vs Relay

The `bootstrap.libp2p.io` nodes are **not public relays** - they only provide DHT entry. Public relays must be discovered via DHT lookup for nodes advertising the circuit-relay protocol.

---

## rust-libp2p AutoRelay Status

| Implementation | AutoRelay Support |
|----------------|-------------------|
| **go-libp2p** | Built-in via `libp2p.EnableAutoRelay()` |
| **rust-libp2p** | No built-in behavior |

For rust-libp2p, AutoRelay must be implemented manually:
- Combine `libp2p::relay` + `libp2p::autonat` behaviors
- External crate [`libp2p-auto-relay`](https://docs.rs/libp2p-auto-relay) (v0.1.2) exists but is separate
- Community PoC implementations exist

---

## Comparison with Current Modes

| Mode | NAT Traversal | Signaling | Relay Required | QUIC Stack |
|------|---------------|-----------|----------------|------------|
| iroh default | Auto + relay fallback | Pkarr/DNS/mDNS | Optional | iroh (quinn) |
| iroh manual | STUN heuristic | Copy-paste | No | iroh (quinn) |
| custom | Full ICE | Copy-paste | No | quinn |
| **libp2p** | DCUtR | Relay-based | **Yes** | quinn |

---

## Why libp2p-quic Transport Alone Doesn't Help

- libp2p-quic is just quinn with libp2p protocol framing
- Our custom mode already uses quinn directly
- The NAT traversal comes from DCUtR protocol, not the QUIC transport
- Using libp2p-quic without DCUtR = just quinn (what we already have)

---

## Implementation Options

### Option A: Add libp2p Mode with Auto-Relay

Add libp2p as a fourth mode that uses DHT-discovered relays and DCUtR.

**Pros:**
- ~70% hole punching success rate
- Graceful fallback to relay if direct fails
- Production-tested by IPFS network
- Interoperable with other libp2p nodes

**Cons:**
- Requires internet connectivity for DHT bootstrap
- Depends on public relay availability
- Heavier dependency (~50+ transitive crates)
- AutoRelay not built into rust-libp2p

**Implementation:**
- New `src/libp2p/` module
- CLI: `sender libp2p`, `receiver libp2p`
- Auto-discover relays via DHT after bootstrap

### Option B: Keep Current Architecture

Custom mode with ICE already provides best serverless NAT traversal.

**Rationale:**
- ICE with STUN is the industry standard for serverless hole punching
- We already use quinn (same QUIC as libp2p)
- No external dependencies for NAT traversal

---

## References

- [libp2p Hole Punching Tutorial](https://docs.rs/libp2p/latest/libp2p/tutorials/hole_punching/)
- [DCUtR Spec](https://github.com/libp2p/specs/blob/master/connections/hole-punching.md)
- [FOSDEM 2023: Hole Punching in the Wild](https://archive.fosdem.org/2023/schedule/event/network_hole_punching_in_the_wild/)
- [rust-libp2p AutoRelay Discussion](https://github.com/libp2p/rust-libp2p/discussions/2944)
- [IPFS Bootstrap List](https://docs.ipfs.tech/how-to/modify-bootstrap-list/)
- [libp2p Connectivity](https://connectivity.libp2p.io/)
- [QUIC Hole Punching PR #3964](https://github.com/libp2p/rust-libp2p/pull/3964)
