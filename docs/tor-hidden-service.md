# Serving iroh-relay via Tor Hidden Service

> **⚠️ Experimental Feature:** Tor hidden service support is experimental and might not work reliably.

Run iroh-relay as a Tor hidden service (.onion) to avoid needing a public IP address. This is useful when:
- You can't get a public IP or open ports
- Cloudflare tunnel doesn't work (HTTP/2 breaks WebSocket upgrades)
- You want to self-host relay infrastructure without exposing servers

---

## When to Use This

> **TL;DR:** Use `--socks5-proxy` when you're self-hosting your own iroh-relay as a Tor hidden service (.onion). This is the **only** supported use case for SOCKS5 proxy.

### ✅ Use SOCKS5 Proxy When:
- You're running your own iroh-relay behind Tor
- All your relay URLs are `.onion` addresses
- You want to avoid exposing public IP addresses for your relay infrastructure

### ❌ Do NOT Use SOCKS5 Proxy When:
- You're using public iroh relays (default behavior)
- You want to proxy regular HTTPS traffic through Tor
- You're trying to anonymize your tunnel traffic (direct P2P bypasses Tor anyway)

### Design Rationale

The `--socks5-proxy` option is intentionally limited to Tor hidden services because:

1. **Self-hosted relay scenario**: When self-hosting a relay, Tor hidden services provide a way to make it accessible without a public IP
2. **No DNS needed**: With a self-hosted relay, the relay itself handles peer discovery — no external DNS server is required
3. **Tor validation**: At startup, tunnel-rs validates the proxy is a real Tor proxy (via `check.torproject.org`) to prevent misconfiguration
4. **Clear use case**: Limiting to `.onion` URLs eliminates ambiguity about what the proxy is for

If you need a general-purpose SOCKS5 proxy for other purposes, that's outside the scope of tunnel-rs.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Client ──[Tor]──► .onion relay ◄──[Tor]── Server          │
│     │                                          │            │
│     │         (relay for discovery/fallback)   │            │
│     │                                          │            │
│     └────────── Direct P2P (QUIC/UDP) ─────────┘            │
│                  (bypasses Tor entirely)                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key points:**
- Tor is only used to reach the relay server
- Direct P2P (QUIC/UDP) bypasses Tor entirely - no performance impact
- If direct P2P fails, traffic falls back through relay (via Tor)

## Setup

Use external `tor` daemon with native `--socks5-proxy` support.

### Prerequisites

```bash
# Install Tor
# Debian/Ubuntu:
sudo apt install tor

# macOS:
brew install tor

# Install iroh-relay
cargo install iroh-relay
```

### Server Setup (Relay Host)

#### Step 1: Configure Tor Hidden Service

```bash
# Create hidden service directory
sudo mkdir -p /var/lib/tor/iroh-relay
sudo chown debian-tor:debian-tor /var/lib/tor/iroh-relay  # Adjust user for your OS
sudo chmod 700 /var/lib/tor/iroh-relay

# Add to /etc/tor/torrc (or /usr/local/etc/tor/torrc on macOS)
cat << 'EOF' | sudo tee -a /etc/tor/torrc
# iroh-relay hidden service
HiddenServiceDir /var/lib/tor/iroh-relay/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:3340
EOF

# Restart Tor
sudo systemctl restart tor  # Linux
# or: brew services restart tor  # macOS

# Get your .onion address
sudo cat /var/lib/tor/iroh-relay/hostname
# Example: abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567.onion
```

Save this `.onion` address - you'll need it for clients.

#### Step 2: Start iroh-relay

```bash
# Development mode (HTTP on localhost:3340)
iroh-relay --dev

# Or for production (HTTP only, no TLS - Tor provides encryption)
iroh-relay --http-bind-addr 127.0.0.1:3340
```

#### Step 3: Start tunnel-rs Server

```bash
# Replace with your .onion address
tunnel-rs server iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-tcp 10.0.0.0/8
```

> **Note:** Use `socks5h://` scheme to ensure .onion hostname resolution happens through the proxy.

### Client Setup

#### Step 1: Start Local Tor Daemon

```bash
# Start Tor (provides SOCKS5 proxy on 127.0.0.1:9050)
tor
```

#### Step 2: Connect with Native SOCKS5 Proxy

```bash
# Use --socks5-proxy to route relay connections through Tor
# Note: Only relay connections go through Tor, direct P2P bypasses it
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --node-id <SERVER_ENDPOINT_ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

#### Step 3: Test the Tunnel

```bash
# SSH through the tunnel
ssh -p 2222 user@127.0.0.1
```

### Verification Steps

```bash
# 1. Verify Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# 2. Verify .onion is reachable
curl --socks5-hostname 127.0.0.1:9050 http://YOUR_ADDRESS.onion/

# 3. Test WebSocket upgrade (optional, requires websocat with SOCKS5 support)
websocat --socks5 127.0.0.1:9050 ws://YOUR_ADDRESS.onion/relay
```

### Troubleshooting

**"Connection refused" when accessing .onion:**
- Ensure Tor daemon is running: `systemctl status tor`
- Check hidden service directory permissions: `ls -la /var/lib/tor/iroh-relay/`
- Verify iroh-relay is listening: `ss -tlnp | grep 3340`

**"SOCKS5 proxy required for .onion relay URLs":**
- Add `--socks5-proxy socks5h://127.0.0.1:9050` to your command
- Or add `socks5_proxy = "socks5h://127.0.0.1:9050"` to your config file
- All relay URLs must be .onion addresses when using SOCKS5 proxy

**Direct P2P not working:**
- This is expected if both peers are behind symmetric NAT
- Traffic will fall back to relay (via Tor) automatically
- Check with `--relay-only` flag to force relay mode for testing

---

## Technical Details: SOCKS5 Bridge

The native SOCKS5 proxy support works by creating local TCP bridges:

```
iroh → localhost:random_port → SOCKS5 proxy → .onion:port → iroh-relay
```

When you specify `--socks5-proxy` with `.onion` relay URLs:
1. tunnel-rs validates that the proxy is a real Tor proxy (via check.torproject.org)
2. tunnel-rs starts a local TCP listener on a random port for each .onion URL
3. The URLs are rewritten to `http://127.0.0.1:<random_port>`
4. When iroh connects to the local listener, traffic is forwarded through SOCKS5 to the .onion address
5. This bridges TCP traffic transparently - iroh doesn't need native SOCKS5 support

### Config File Support

You can also specify the SOCKS5 proxy in config files:

```toml
# server.toml or client.toml
[iroh]
relay_urls = ["http://abc123...xyz.onion"]
socks5_proxy = "socks5h://127.0.0.1:9050"
```

> **Note:** When using `socks5_proxy`, all relay URLs must be `.onion` addresses and `dns_server` cannot be used (the relay handles peer discovery).

---

## Security Considerations

### What Tor Provides
- **No public IP needed:** Hidden service is only accessible via Tor network
- **End-to-end encryption:** Tor encrypts traffic between client and hidden service
- **Location hiding:** Server's IP address is not exposed to clients

### What Tor Does NOT Provide (in this setup)
- **Anonymity for users:** Direct P2P connections bypass Tor, revealing IP addresses
- **Traffic analysis protection:** Tunnel patterns may be observable
- **Full anonymity:** This setup prioritizes avoiding public IP, not anonymity

### Recommendations
- Keep hidden service private keys secure (`/var/lib/tor/iroh-relay/hs_ed25519_secret_key`)
- Use unique .onion addresses for different services
- Consider rate limiting if exposing relay publicly

---

## Performance Notes

| Path | Latency | Throughput |
|------|---------|------------|
| Direct P2P | ~10-50ms | Full speed |
| Relay via Tor | ~500ms-2s | ~1-5 Mbps |

Direct P2P bypasses Tor entirely, so performance is unaffected when direct connections succeed. Tor latency only applies when falling back to relay.

---

## Future Direction: Embedded Arti

> **Note:** This section documents research for a planned future feature.

### Current Limitation: SOCKS5 Bridge

The current `--socks5-proxy` approach requires:
- External Tor daemon running
- Manual hidden service configuration
- SOCKS5 bridge to route iroh relay traffic

### Alternative: Embedded Arti (Rust Tor)

[Arti](https://gitlab.torproject.org/tpo/core/arti) is the official Rust implementation of Tor. It can be embedded directly into Rust applications without requiring an external Tor daemon or SOCKS5 bridging.

**Key capabilities:**
- **Direct API**: `TorClient::connect()` returns async streams without SOCKS
- **Onion services**: Can create ephemeral hidden services programmatically
- **No external daemon**: Fully embedded, no subprocess management

**Reference implementation**: See [wormhole-rs](https://github.com/nickelc/wormhole-rs) which uses Arti for direct Tor integration.

### Potential ice-nostr Integration

A future `--tor-fallback` flag for ice-nostr mode could:
1. Attempt ICE connection first (direct P2P)
2. If ICE fails (symmetric NAT, timeout) **and tunnel is TCP**:
   - Server creates ephemeral Tor hidden service via Arti
   - Server publishes .onion address via Nostr signaling
   - Client connects via embedded Arti
3. If ICE fails **and tunnel is UDP**: connection fails (Tor is TCP-only)
4. No external Tor daemon or SOCKS5 proxy needed

### Comparison: SOCKS5 Bridge vs Embedded Arti

| Feature | SOCKS5 Bridge (current) | Embedded Arti (future) |
|---------|------------------------|------------------------|
| External Tor daemon | Required | Not needed |
| Mode support | iroh only | ice-nostr |
| Setup complexity | High | Low (just a flag) |
| Hidden service | Manual config | Automatic ephemeral |
| Dependencies | External tor process | arti-client crate |
| Feature flag | None | `onion` |

### Arti Dependencies

```toml
# Behind optional 'onion' feature flag
arti-client = { version = "0.37", features = ["onion-service-service", "onion-service-client", "tokio"] }
tor-hsservice = { version = "0.37" }
tor-cell = { version = "0.37" }
```

### Important Limitation: TCP Only

**Tor only supports TCP streams.** This has significant implications for the Arti fallback:

| Tunnel Type | ICE Succeeds | ICE Fails + Tor Fallback |
|-------------|--------------|--------------------------|
| TCP (SSH, HTTP, databases) | ✅ Works | ✅ Falls back to Tor |
| UDP (DNS, WireGuard, gaming) | ✅ Works | ❌ Connection fails |

**Behavior with `--tor-fallback`:**
- TCP tunnels: ICE first, Tor fallback if ICE fails
- UDP tunnels: ICE only, no fallback available

This is an acceptable trade-off because:
1. Most tunnel use cases are TCP (SSH, databases, web services)
2. UDP applications (gaming, real-time) have latency requirements incompatible with Tor (~500ms-2s)
3. UDP-over-TCP encapsulation would add overhead and break UDP semantics

**Workaround for UDP:** Ensure direct connectivity (port forwarding, UPnP, or avoid symmetric NAT on both sides).

### Trade-offs

| Aspect | Impact |
|--------|--------|
| Startup latency | Tor bootstrap takes 10-30 seconds |
| Connection latency | Tor adds ~500ms-2s vs direct |
| Binary size | Arti adds ~5-10MB |
| No external infra | Uses public Tor network (no self-hosted relay needed) |
| **TCP only** | UDP tunnels cannot fall back to Tor |
