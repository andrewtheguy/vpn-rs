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
  --socks5-proxy socks5://127.0.0.1:9050 \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-tcp 10.0.0.0/8
```

### Client Setup

#### Step 1: Start Local Tor Daemon

```bash
# Start Tor (provides SOCKS5 proxy on 127.0.0.1:9050)
tor
```

#### Step 2: Connect with Native SOCKS5 Proxy

```bash
# Use --socks5-proxy to route .onion relay connections through Tor
# Note: Only relay connection goes through Tor, direct P2P bypasses it
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5://127.0.0.1:9050 \
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
- Add `--socks5-proxy socks5://127.0.0.1:9050` to your command
- Or add `socks5_proxy = "socks5://127.0.0.1:9050"` to your config file

**Direct P2P not working:**
- This is expected if both peers are behind symmetric NAT
- Traffic will fall back to relay (via Tor) automatically
- Check with `--relay-only` flag to force relay mode for testing

---

## Technical Details: SOCKS5 Bridge

The native SOCKS5 proxy support works by creating a local TCP bridge:

```
iroh → localhost:random_port → SOCKS5 proxy → .onion:port → iroh-relay
```

When you specify `--socks5-proxy` with a `.onion` relay URL:
1. tunnel-rs starts a local TCP listener on a random port
2. The relay URL is rewritten to `http://127.0.0.1:<random_port>`
3. When iroh connects to the local listener, traffic is forwarded through SOCKS5 to the .onion address
4. This bridges TCP traffic transparently - iroh doesn't need native SOCKS5 support

### Config File Support

You can also specify the SOCKS5 proxy in config files:

```toml
# server.toml or client.toml
[iroh]
relay_urls = ["http://abc123...xyz.onion"]
socks5_proxy = "socks5://127.0.0.1:9050"
```

---

## Embedded Arti (Client Mode)

For clients, you can use the embedded Arti (Rust Tor implementation) to connect to `.onion` relay URLs without running a separate Tor daemon.

**Note:** Due to dependency conflicts between str0m (ICE) and Arti, embedded Tor and ICE modes cannot be built together. The embedded-tor build only includes iroh mode.

### Build with Embedded Tor Support

```bash
# Use the build script (recommended)
./scripts/build-tor.sh

# This produces: target/release/tunnel-rs (with embedded Tor)
```

The build script temporarily swaps `Cargo.toml` with `Cargo.tor.toml` to enable the embedded-tor feature without ICE dependencies.

### Usage (Client Only)

With embedded Tor, clients can connect to `.onion` relay URLs directly:

```bash
# No need to run separate Tor daemon!
# No need for --socks5-proxy flag!
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --node-id <SERVER_ENDPOINT_ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

### How It Works

```
iroh → localhost:port → Arti bridge → tor_client.connect() → .onion relay
                        (embedded Tor, no SOCKS5 protocol)
```

- Uses Arti's `TorClient::connect()` directly (no SOCKS5 protocol overhead)
- Persistent state stored at:
  - Linux: `~/.local/share/tunnel-rs/arti/`
  - macOS: `~/Library/Application Support/tunnel-rs/arti/`
  - Windows: `%APPDATA%/tunnel-rs/arti/`
- First run bootstraps Tor network (~10-30 seconds)
- Subsequent runs are faster due to cached state

### Trade-offs

| Pros | Cons |
|------|------|
| No external Tor daemon needed | Binary size increases ~10-20MB |
| Self-contained client | Longer compile times |
| Works on any platform | First bootstrap takes 10-30s |
| Proven pattern (Arti v0.37) | |

### Server Mode

Server mode still requires an external Tor daemon with `--socks5-proxy`. This is intentional since servers typically run dedicated infrastructure and benefit from the external Tor daemon's maturity and configurability.

---

## iroh-dns-server via Tor (Optional)

Same approach works for DNS server:

```bash
# Add to /etc/tor/torrc
HiddenServiceDir /var/lib/tor/iroh-dns/
HiddenServiceVersion 3
HiddenServicePort 443 127.0.0.1:8443

# Start iroh-dns-server
iroh-dns-server --config dns.toml
```

Lower priority since DNS is low-bandwidth and less problematic with Cloudflare.

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
