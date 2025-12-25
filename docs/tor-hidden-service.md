# Serving iroh-relay via Tor Hidden Service

Run iroh-relay as a Tor hidden service (.onion) to avoid needing a public IP address. This is useful when:
- You can't get a public IP or open ports
- Cloudflare tunnel doesn't work (HTTP/2 breaks WebSocket upgrades)
- You want to self-host relay infrastructure without exposing servers

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
# Use --socks5-proxy to route .onion relay/DNS connections through Tor
# Note: Only relay/DNS connections go through Tor, direct P2P bypasses it
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

**"SOCKS5 proxy required for .onion relay/DNS URLs":**
- Add `--socks5-proxy socks5h://127.0.0.1:9050` to your command
- Or add `socks5_proxy = "socks5h://127.0.0.1:9050"` to your config file
- Use `socks5h://` (not `socks5://`) for .onion addresses

**Direct P2P not working:**
- This is expected if both peers are behind symmetric NAT
- Traffic will fall back to relay (via Tor) automatically
- Check with `--relay-only` flag to force relay mode for testing

---

## Technical Details: SOCKS5 Bridge

The native SOCKS5 proxy support works by creating local TCP bridges:

```
iroh → localhost:random_port → SOCKS5 proxy → .onion:port → iroh-relay
iroh → localhost:random_port → SOCKS5 proxy → .onion:port → iroh-dns-server
```

When you specify `--socks5-proxy` with `.onion` relay or DNS server URLs:
1. tunnel-rs starts a local TCP listener on a random port for each .onion URL
2. The URLs are rewritten to `http://127.0.0.1:<random_port>` (preserving paths like `/pkarr`)
3. When iroh connects to the local listener, traffic is forwarded through SOCKS5 to the .onion address
4. This bridges TCP traffic transparently - iroh doesn't need native SOCKS5 support

Both relay and DNS connections are bridged independently, allowing fully self-hosted infrastructure over Tor.

### Config File Support

You can also specify the SOCKS5 proxy in config files:

```toml
# server.toml or client.toml
[iroh]
relay_urls = ["http://abc123...xyz.onion"]
dns_server = "http://def456...uvw.onion/pkarr"
socks5_proxy = "socks5h://127.0.0.1:9050"
```

> **Note:** Use `socks5h://` (not `socks5://`) for .onion addresses to ensure DNS resolution happens through the proxy.

---

## Future: Embedded Arti

Single-binary deployment with Tor built-in using [Arti](https://gitlab.torproject.org/tpo/core/arti) (Rust Tor implementation).

### Concept

```bash
# Hypothetical - start relay with embedded Tor hidden service
tunnel-rs server iroh \
  --tor-hidden-service \
  --tor-key-file ./onion.key \
  --allowed-tcp 127.0.0.0/8

# Output: Hidden service available at abc123...xyz.onion
```

### Trade-offs
- **Pros:** Single binary, no external dependencies, programmatic control
- **Cons:** Large dependency (~10MB+), experimental APIs, longer compile times

### Status
Not yet implemented. Requires `arti-client` and `tor-hsservice` crates.

---

## iroh-dns-server via Tor

For fully self-hosted infrastructure over Tor, you can also run iroh-dns-server as a hidden service:

### Setup

```bash
# Add to /etc/tor/torrc
HiddenServiceDir /var/lib/tor/iroh-dns/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080

# Restart Tor
sudo systemctl restart tor

# Get your .onion address
sudo cat /var/lib/tor/iroh-dns/hostname

# Start iroh-dns-server
iroh-dns-server --config dns.toml
```

### Usage with tunnel-rs

```bash
# Server
tunnel-rs server iroh \
  --relay-url http://YOUR_RELAY.onion \
  --dns-server http://YOUR_DNS.onion/pkarr \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8

# Client
tunnel-rs client iroh \
  --relay-url http://YOUR_RELAY.onion \
  --dns-server http://YOUR_DNS.onion/pkarr \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

This provides a completely self-hosted P2P infrastructure accessible only via Tor.

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
