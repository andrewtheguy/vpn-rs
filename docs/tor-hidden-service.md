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

## Phase 1: External Tor Daemon (Current)

No code changes required. Use external `tor` daemon and `torsocks` wrapper.

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

#### Step 2: Connect via torsocks

```bash
# torsocks wraps the command to route through Tor SOCKS5 proxy
# Note: Only relay connection goes through Tor, direct P2P bypasses it
torsocks tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
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
torsocks curl -v http://YOUR_ADDRESS.onion/

# 3. Test WebSocket upgrade
torsocks websocat ws://YOUR_ADDRESS.onion/relay
```

### Troubleshooting

**"Connection refused" when accessing .onion:**
- Ensure Tor daemon is running: `systemctl status tor`
- Check hidden service directory permissions: `ls -la /var/lib/tor/iroh-relay/`
- Verify iroh-relay is listening: `ss -tlnp | grep 3340`

**torsocks not working with async Rust:**
- Try using environment variables instead:
  ```bash
  ALL_PROXY=socks5h://127.0.0.1:9050 tunnel-rs client iroh ...
  ```
- Or use `torify` as an alternative to `torsocks`

**Direct P2P not working:**
- This is expected if both peers are behind symmetric NAT
- Traffic will fall back to relay (via Tor) automatically
- Check with `--relay-only` flag to force relay mode for testing

---

## Phase 2: Native SOCKS5 Proxy Support (Planned)

Add `--socks5-proxy` CLI option for native .onion URL handling without external wrappers.

### Planned Implementation

```bash
# No torsocks needed - native proxy support
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --node-id <SERVER_ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

### Files to Modify
- `src/main.rs` - Add `--socks5-proxy` CLI option
- `src/config.rs` - Add `socks5_proxy` config field
- `src/iroh/endpoint.rs` - Pass proxy config to iroh endpoint

### Status
Not yet implemented. Use Phase 1 (torsocks) for now.

---

## Phase 3: Embedded Arti (Future)

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
