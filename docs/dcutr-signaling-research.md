# DCUtR-Style Signaling Server Research

Research on implementing a lightweight DCUtR-style signaling server for coordinated NAT hole punching in tunnel-rs.

## Motivation

Current tunnel-rs modes have trade-offs:
- **iroh mode**: Reliable but relays data through DERP servers (bandwidth concern)
- **nostr mode**: Signaling-only but no timing coordination (lower hole punch success)

A dedicated signaling server could provide:
- Timing coordination for higher hole punch success (~70% like DCUtR)
- No data relay (signaling messages only)
- Extensible for future controller features

## Phased Implementation

### Phase 1: Plain TCP Server
Validate the timing coordination concept with a simple TCP server.

```
┌─────────┐       TCP          ┌──────────────────┐       TCP          ┌─────────┐
│ Client A│◄───signaling──────►│ Signaling Server │◄───signaling──────►│ Client B│
└────┬────┘                    │   (public IP)    │                    └────┬────┘
     │                         └──────────────────┘                         │
     │                                                                       │
     └────────────────────── Direct P2P (hole punched) ─────────────────────┘
```

**Deployment**: Server runs on any host with public IP or port-forwarded.

### Phase 2: Tor Hidden Service
After Phase 1 validation, wrap the server as a Tor hidden service.

```
┌─────────┐     Tor (.onion)   ┌──────────────────┐     Tor (.onion)   ┌─────────┐
│ Client A│◄───signaling──────►│ Signaling Server │◄───signaling──────►│ Client B│
└────┬────┘                    │ (hidden service) │                    └────┬────┘
     │                         └──────────────────┘                         │
     │                                                                       │
     └────────────────────── Direct P2P (hole punched) ─────────────────────┘
```

**Deployment**: Server runs as Tor hidden service via arti. No public IP needed.

## Protocol Specification

### Transport Layer

Both phases use raw `AsyncRead + AsyncWrite` streams:
- **Phase 1**: `TcpStream`
- **Phase 2**: Tor stream via arti

### Message Framing

```
┌─────────────────┬──────────────────────────┐
│ Length (4 bytes)│ JSON-RPC Message (N bytes)│
│  big-endian u32 │                          │
└─────────────────┴──────────────────────────┘
```

### Message Format (JSON-RPC 2.0)

**Request** (expects response):
```json
{
  "jsonrpc": "2.0",
  "method": "register",
  "params": {"client_id": "abc123"},
  "id": 1
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "result": {"success": true},
  "id": 1
}
```

**Notification** (no response):
```json
{
  "jsonrpc": "2.0",
  "method": "sync_connect",
  "params": {"peer_addrs": ["1.2.3.4:5678"], "start_at_ms": 1703500000000}
}
```

**Error**:
```json
{
  "jsonrpc": "2.0",
  "error": {"code": -32600, "message": "Invalid request"},
  "id": 1
}
```

### Methods

#### Signaling Methods

| Method | Type | Params | Description |
|--------|------|--------|-------------|
| `register` | Request | `{client_id: String}` | Register client with server |
| `ping` | Request | `{seq: u32, timestamp: u64}` | RTT measurement |
| `connect_request` | Request | `{target_id: String, my_addrs: Vec<SocketAddr>}` | Request connection to peer |
| `sync_connect` | Notification | `{peer_addrs: Vec<SocketAddr>, start_at_ms: u64}` | Coordinated hole punch timing |
| `connect_result` | Notification | `{success: bool, method: Option<String>}` | Report hole punch result |

#### Future Controller Methods

| Method | Type | Description |
|--------|------|-------------|
| `list_clients` | Request | List connected clients |
| `get_stats` | Request | Connection statistics |
| `kick_client` | Request | Disconnect a client |

## Timing Coordination Flow

```
1. Both clients connect to signaling server
2. Each client registers and measures RTT (3-5 ping/pong rounds)

   Client A → Server: {"method": "ping", "params": {"seq": 1, "timestamp": 1703500000000}, "id": 1}
   Server → Client A: {"result": {"seq": 1, "client_ts": 1703500000000, "server_ts": 1703500000050}, "id": 1}

   Measured: RTT_A = 100ms, RTT_B = 80ms

3. Client A requests connection to Client B

   Client A → Server: {"method": "connect_request", "params": {"target_id": "clientB", "my_addrs": ["1.2.3.4:5678"]}, "id": 2}

4. Server calculates synchronized start time:
   - Current server time: T
   - Message to A arrives at: T + RTT_A/2
   - Message to B arrives at: T + RTT_B/2
   - Start time: T + max(RTT_A, RTT_B)/2 + buffer (e.g., 200ms)

5. Server sends SyncConnect to both clients simultaneously

   Server → Client A: {"method": "sync_connect", "params": {"peer_addrs": ["5.6.7.8:1234"], "start_at_ms": 1703500000400}}
   Server → Client B: {"method": "sync_connect", "params": {"peer_addrs": ["1.2.3.4:5678"], "start_at_ms": 1703500000400}}

6. Both clients initiate simultaneous TCP/UDP connect at start_at_ms
   - Creates symmetric NAT hole punch opportunity
   - Expected success rate: ~70% (similar to DCUtR)

7. Clients report result

   Client A → Server: {"method": "connect_result", "params": {"success": true, "method": "direct"}}
```

## Implementation

### Phase 1: TCP Server

```rust
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn run_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Signaling server listening on {}", addr);

    while let Ok((stream, peer_addr)) = listener.accept().await {
        println!("Client connected: {}", peer_addr);
        tokio::spawn(handle_client(stream));
    }
    Ok(())
}

async fn handle_client<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> Result<()> {
    loop {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Read JSON-RPC message
        let mut msg_buf = vec![0u8; len];
        stream.read_exact(&mut msg_buf).await?;
        let request: JsonRpcRequest = serde_json::from_slice(&msg_buf)?;

        // Handle method
        let response = match request.method.as_str() {
            "register" => handle_register(&request.params),
            "ping" => handle_ping(&request.params),
            "connect_request" => handle_connect_request(&request.params),
            _ => Err(JsonRpcError::method_not_found()),
        };

        // Send response if request had id
        if let Some(id) = request.id {
            let resp_json = serde_json::to_vec(&JsonRpcResponse { id, result: response })?;
            stream.write_u32(resp_json.len() as u32).await?;
            stream.write_all(&resp_json).await?;
        }
    }
}
```

**CLI Usage (Phase 1)**:
```bash
# Start server
tunnel-rs-signaling --bind 0.0.0.0:9999

# Client usage
tunnel-rs sender dcutr --signaling-server 1.2.3.4:9999 <target-id>
tunnel-rs receiver dcutr --signaling-server 1.2.3.4:9999 --id <my-id>
```

### Phase 2: Tor Hidden Service

Same `handle_client` function, different transport setup:

```rust
use arti_client::{TorClient, TorClientConfigBuilder};
use arti_client::config::StorageConfig;
use tor_hsservice::{HsNickname, OnionServiceConfigBuilder, handle_rend_requests};

async fn run_onion_server() -> Result<()> {
    // Bootstrap Tor client (ephemeral - no persistent state)
    let config = TorClientConfigBuilder::default()
        .storage(StorageConfig::Ephemeral)
        .build()?;

    let tor_client = TorClient::with_runtime(tokio::runtime::Handle::current())
        .config(config)
        .bootstrap()
        .await?;

    // Create hidden service
    let nickname = HsNickname::new("tunnel_signaling")?;
    let onion_service = tor_client.launch_onion_service(
        OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()?,
    )?;

    let onion_addr = onion_service.onion_name().unwrap();
    println!("Signaling server: {}.onion", onion_addr);

    // Accept connections (same handler as Phase 1)
    let mut rend_requests = handle_rend_requests(&onion_service);
    while let Some(request) = rend_requests.next().await {
        let stream = request.accept().await?;
        tokio::spawn(handle_client(stream));  // Same function!
    }
    Ok(())
}
```

**CLI Usage (Phase 2)**:
```bash
# Start server as hidden service
tunnel-rs-signaling --onion

# Client usage (connects via Tor)
tunnel-rs sender dcutr --signaling-server abc123xyz.onion <target-id>
```

### Client Connection (Phase 2)

```rust
async fn connect_to_signaling_server(onion_addr: &str) -> Result<impl AsyncRead + AsyncWrite> {
    let config = TorClientConfigBuilder::default()
        .storage(StorageConfig::Ephemeral)
        .build()?;

    let tor_client = TorClient::with_runtime(tokio::runtime::Handle::current())
        .config(config)
        .bootstrap()
        .await?;

    let stream = tor_client.connect((onion_addr, 80)).await?;
    Ok(stream)
}
```

## Comparison with Existing Modes

| Aspect | Nostr Mode | iroh Mode | DCUtR Signaling |
|--------|------------|-----------|-----------------|
| Signaling | Nostr relays | DNS/mDNS + relay | Custom server |
| Timing sync | None | iroh handles | RTT-based coordination |
| Data relay | None | DERP fallback | None |
| Hole punch success | ~30-50% | ~95% (with relay) | ~70% (estimated) |
| Bandwidth concern | None | Relay uses bandwidth | None |
| Server requirement | Public Nostr relays | Public DERP relays | Self-hosted |
| Phase 2 benefit | N/A | N/A | No public IP needed |

## Dependencies

### Phase 1
```toml
[dependencies]
tokio = { version = "1", features = ["net", "io-util", "rt-multi-thread"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

### Phase 2 (additional)
```toml
[dependencies]
arti-client = { version = "0.26", default-features = false, features = [
    "tokio", "rustls", "onion-service-client", "onion-service-service"
] }
tor-hsservice = "0.26"
```

## References

- [DCUtR Specification](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md) - libp2p timing coordination
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [arti documentation](https://docs.rs/arti-client) - Tor client in Rust
- [wormhole-rs](https://github.com/andrewtheguy/wormhole-rs) - Example arti usage
