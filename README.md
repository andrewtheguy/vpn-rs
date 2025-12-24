# tunnel-rs

**Cross-platform Secure Peer-to-Peer TCP/UDP port forwarding with NAT traversal.**

Tunnel-rs enables you to forward TCP and UDP traffic between machines without requiring public IP addresses, port forwarding, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

> [!IMPORTANT]
> **Project Goal:** This tool provides a convenient way to connect to different networks for **development or homelab purposes** without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale.

**Key Features:**
- **Full TCP and UDP support** — Seamlessly tunnel any TCP or UDP traffic
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching and stable peer identities eliminate the need for complex firewall rules or dynamic DNS
- **Cross-platform support** — Works on Linux, macOS, and Windows
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with multiple strategies (relay fallback, STUN, full ICE)
- **Minimal configuration** — Automatic peer discovery using simple, shareable identities
- **Flexible signaling** — Supports multiple connection methods, from automated discovery to manual exchange
- **High performance** — Optimized for low latency using QUIC stream multiplexing

**Common Use Cases:**
- **SSH access** to machines behind NAT/firewalls
- **UDP Tunneling** — A key advantage over AWS SSM and `kubectl port-forward` which typically lack UDP support. Ideal for:
  - WireGuard VPNs over P2P
  - Game servers (Valheim, Minecraft Bedrock, etc.)
  - VoIP applications and WebRTC
  - Accessing UDP services in Kubernetes (bypassing the [7+ year old limitation in `kubectl`](https://github.com/kubernetes/kubernetes/issues/47862) without complex sidecar workarounds)
- **Simpler Alternative to SSM For Staging Environment Access Purposes** — Great for ad-hoc access without configuring AWS agents or IAM users. **Note:** Not intended for production; it is not battle-tested for enterprise use and lacks integration with cloud security policies (IAM, auditing).
- **Remote Desktop** access (RDP/VNC over TCP) without port forwarding
- **Secure Service Exposure** (HTTP servers, databases, etc.) without public infrastructure
- **Development and Testing** of TCP/UDP services across network boundaries
- **Homelab Networking** — Connecting distributed homelab nodes or accessing local services remotely without complex VPN setups or public IP requirements
- **Cross-platform Tunneling** for both TCP and UDP workflows (including Windows endpoints)

## Overview

tunnel-rs provides multiple modes for establishing tunnels:

| Mode | Discovery | NAT Traversal | Protocols | Use Case |
|------|-----------|---------------|-----------|----------|
| **iroh** | Automatic (Pkarr/DNS/mDNS) | Relay fallback | TCP, UDP | Persistent, multi-source tunnels |
| **iroh-manual** | Manual copy-paste | STUN heuristic | TCP, UDP | Serverless, simple NATs |
| **custom-manual** | Manual copy-paste | Full ICE | TCP, UDP | Best NAT compatibility |
| **nostr** | Nostr relays | Full ICE | TCP, UDP | Automated signaling, static keys |
| **dcutr** *(experimental)* | Signaling server | Full ICE + timing | TCP, UDP | Coordinated hole punching |

> [!TIP]
> **For containerized environments (Docker, Kubernetes, cloud VMs):** Use `iroh` mode. It includes relay fallback which ensures connectivity even when both peers are behind restrictive NATs (common in cloud environments). The `nostr`, `custom-manual`, and `iroh-manual` modes use STUN-only NAT traversal which may fail when both peers are behind symmetric NAT.

### Choosing a Serverless Mode

The `iroh-manual`, `custom-manual`, and `nostr` modes don't require iroh discovery/relay infrastructure:

| Feature | iroh-manual | custom-manual | nostr |
|---------|-------------|---------------|-------|
| Signaling | Manual copy-paste | Manual copy-paste | Nostr relays (automated) |
| NAT traversal | STUN heuristic | Full ICE | Full ICE |
| Symmetric NAT | May fail | Best-effort | Best-effort |
| Keys | Ephemeral | Ephemeral | Static (WireGuard-like) |
| QUIC stack | iroh | str0m + quinn | str0m + quinn |

**Recommendation:** Use `nostr` mode for automated signaling with persistent identity, or `custom-manual` mode for best NAT traversal without external dependencies.

## Installation

The release installers fetch a native, standalone executable. You only need the binary in your PATH; no runtime dependencies or package managers are required.

### Quick Install (Linux & macOS)

```bash
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash
```

Install with custom release tag:
```bash
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash -s <RELEASE_TAG>
```

By default the installer pulls the latest **stable** release. Use `--prerelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples:

```bash
# Latest prerelease
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash -s -- --prerelease

# Pin to a specific tag
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash -s 20251210172710
```

### Quick Install (Windows)

```powershell
irm https://andrewtheguy.github.io/tunnel-rs/install.ps1 | iex
```

Install with custom release tag:
```powershell
irm https://andrewtheguy.github.io/tunnel-rs/install.ps1 | iex -Args <RELEASE_TAG>
```

By default the PowerShell installer pulls the latest **stable** release. Use `-PreRelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples:

```powershell
# Latest prerelease
irm https://andrewtheguy.github.io/tunnel-rs/install.ps1 | iex -Args -PreRelease

# Pin to a specific tag
irm https://andrewtheguy.github.io/tunnel-rs/install.ps1 | iex -Args 20251210172710
```

### From Source

```bash
cargo install --path .
```

### Supported Platforms

tunnel-rs is fully supported on:
- **Linux** (x86_64, ARM64)
- **macOS** (Intel, Apple Silicon)
- **Windows** (x86_64)

All four modes (iroh, iroh-manual, custom-manual, nostr) work across all platforms, enabling cross-platform P2P tunneling.

### Docker & Kubernetes

Container images are available at `ghcr.io/andrewtheguy/tunnel-rs:latest`.

Access services running in Docker or Kubernetes remotely — without opening ports, configuring ingress, or requiring `kubectl`. See [examples/](examples/) for Docker Compose and Kubernetes configurations.

---

# iroh Mode

Uses iroh's P2P network for automatic peer discovery and NAT traversal with relay fallback. This is a **multi-source mode** where the client requests which service to tunnel (similar to SSH `-L` tunneling).

**Note:** While discovery and relay are fully automatic, peers still need to exchange the server's **EndpointId** to initiate the connection. The server whitelists allowed networks, and the client specifies which service to tunnel.

## Architecture

### TCP Tunneling

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | client          |  iroh  | server          |  TCP   | SSH Server      |
|                 |<------>| (local:2222)    |<======>|                 |<------>| (client req)    |
|                 |        |                 |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
     Client Side                                            Server Side
```

### UDP Tunneling

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| WireGuard       |  UDP   | client          |  iroh  | server          |  UDP   | WireGuard       |
| Client          |<------>| (local:51820)   |<======>|                 |<------>| Server          |
|                 |        |                 |  QUIC  |                 |        | (client req)    |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
     Client Side                                            Server Side
```

## Quick Start

### TCP Tunnel (e.g., SSH)

**Server** (on server — waits for client connections):
```bash
tunnel-rs server iroh --allowed-tcp 127.0.0.0/8
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Waiting for clients to connect...
```

**Client** (on client — requests source from server):
```bash
tunnel-rs client iroh --node-id <ENDPOINT_ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
```

Then connect: `ssh -p 2222 user@127.0.0.1`

### UDP Tunnel (e.g., WireGuard)

**Server**:
```bash
tunnel-rs server iroh --allowed-udp 127.0.0.0/8
```

**Client**:
```bash
tunnel-rs client iroh --node-id <ENDPOINT_ID> --source udp://127.0.0.1:51820 --target 0.0.0.0:51820
```

## CLI Options

### server

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/server.toml` |

### server iroh

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tcp` | - | Allowed TCP networks in CIDR notation (repeatable) |
| `--allowed-udp` | - | Allowed UDP networks in CIDR notation (repeatable) |
| `--max-sessions` | 100 | Maximum concurrent sessions |
| `--secret` | - | Base64-encoded secret key for persistent identity |
| `--secret-file` | - | Path to secret key file for persistent identity |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (requires `test-utils` feature) |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--socks5-proxy` | - | SOCKS5 proxy for relay connections (e.g., `socks5://127.0.0.1:9050` for Tor) |

### client

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/client.toml` |

### client iroh

| Option | Default | Description |
|--------|---------|-------------|
| `--node-id`, `-n` | required | EndpointId of the server |
| `--source`, `-s` | required | Source address to request from server (tcp://host:port or udp://host:port) |
| `--target`, `-t` | required | Local address to listen on |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (requires `test-utils` feature) |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--socks5-proxy` | - | SOCKS5 proxy for relay connections (e.g., `socks5://127.0.0.1:9050` for Tor) |

## Configuration Files

Use `--default-config` to load from the default location, or `-c <path>` for a custom path. Each mode has its own section (`[iroh]`, `[iroh-manual]`, `[custom-manual]`, `[nostr]`).

**Default locations:**
- Server: `~/.config/tunnel-rs/server.toml`
- Client: `~/.config/tunnel-rs/client.toml`

### Server Config Example

```toml
# Example server configuration (iroh mode)

# Required: validates config matches CLI command
role = "server"
mode = "iroh"  # or "iroh-manual", "custom-manual", or "nostr"

[iroh]
secret_file = "./server.key"
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
max_sessions = 100
# Optional: SOCKS5 proxy for .onion relay URLs (Tor)
# socks5_proxy = "socks5://127.0.0.1:9050"

[iroh.allowed_sources]
tcp = ["127.0.0.0/8", "192.168.0.0/16"]
udp = ["10.0.0.0/8"]
```

> [!NOTE]
> See [`server.toml.example`](server.toml.example) for configuration options for other modes and all available options for each mode.

```bash
# Load from default location (mode inferred from config)
tunnel-rs server --default-config

# Load from custom path
tunnel-rs server -c ./my-server.toml
```

### Client Config Example

```toml
# Example client configuration (iroh mode)

# Required: validates config matches CLI command
role = "client"
mode = "iroh"  # or "iroh-manual", "custom-manual", or "nostr"

[iroh]
node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
request_source = "tcp://127.0.0.1:22"
target = "127.0.0.1:2222"
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
# Optional: SOCKS5 proxy for .onion relay URLs (Tor)
# socks5_proxy = "socks5://127.0.0.1:9050"
```

> [!NOTE]
> See [`client.toml.example`](client.toml.example) for configuration options for other modes and all available options for each mode.

```bash
# Load from default location (mode inferred from config)
tunnel-rs client --default-config

# Load from custom path
tunnel-rs client -c ./my-client.toml
```

## Persistent Identity

By default, a new EndpointId is generated each run. For long-running setups, use persistent identity:

```bash
# Generate key and output EndpointId
tunnel-rs generate-iroh-key --output ./server.key

# Show EndpointId for existing key
tunnel-rs show-iroh-node-id --secret-file ./server.key
```

Then use the key for the server:

```bash
tunnel-rs server iroh --allowed-tcp 127.0.0.0/8 --secret-file ./server.key
```

## Custom Relay Server

```bash
# Both sides must use the same relay
tunnel-rs server iroh --relay-url https://relay.example.com --allowed-tcp 127.0.0.0/8
tunnel-rs client iroh --relay-url https://relay.example.com --node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222

# Force relay-only (no direct P2P) - requires test-utils feature
# Build with: cargo build --features test-utils
tunnel-rs server iroh --relay-url https://relay.example.com --relay-only --allowed-tcp 127.0.0.0/8
```

### Running iroh-relay

```bash
cargo install iroh-relay
iroh-relay --dev  # Local testing on http://localhost:3340
```

## Self-Hosted DNS Discovery

For fully independent operation without public infrastructure:

```bash
# Both sides use custom DNS server
tunnel-rs server iroh --dns-server https://dns.example.com/pkarr --secret-file ./server.key --allowed-tcp 127.0.0.0/8
tunnel-rs client iroh --dns-server https://dns.example.com/pkarr --node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
```

## Self-Hosted Infrastructure

For fully independent operation, you can self-host iroh's relay and DNS servers.

### Running iroh-relay

```bash
cargo install iroh-relay
iroh-relay --config relay.toml
```

Example `relay.toml`:
```toml
[relay]
http_bind_addr = "0.0.0.0:80"
tls_bind_addr = "0.0.0.0:443"
hostname = "relay.example.com"
```

### Running iroh-dns-server

```bash
cargo install iroh-dns-server
iroh-dns-server --config dns.toml
```

### Using Your Infrastructure

```bash
# Server
tunnel-rs server iroh \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8

# Client
tunnel-rs client iroh \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

### Relay Behavior

iroh mode uses the relay for both **signaling/coordination** and as a **data transport fallback**:

1. Initial connection goes through relay for signaling
2. iroh attempts hole punching (similar to libp2p's DCUtR)
3. If successful (~70%), traffic flows directly between peers
4. If hole punching fails, **traffic continues through relay**

> [!NOTE]
> **Bandwidth Concern:** If you want signaling-only coordination **without** relay fallback (to avoid forwarding any tunnel traffic), iroh mode currently doesn't support this. The relay always acts as fallback when direct connection fails.
>
> **Alternative for signaling-only:** Use `nostr` mode with self-hosted Nostr relays. Nostr relays only handle signaling (small encrypted messages), never tunnel traffic. If hole punching fails, the connection fails — no traffic is ever forwarded through the relay.

### Tor Hidden Service (No Public IP)

If you can't get a public IP or Cloudflare tunnel doesn't work (HTTP/2 breaks WebSocket upgrades), you can run iroh-relay as a Tor hidden service:

```bash
# Server side: configure tor hidden service pointing to localhost:3340
# Then start iroh-relay and tunnel-rs with the .onion URL
tunnel-rs server iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5://127.0.0.1:9050 \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8

# Client side: use --socks5-proxy to reach .onion relay (direct P2P bypasses Tor)
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5://127.0.0.1:9050 \
  --node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

See [docs/tor-hidden-service.md](docs/tor-hidden-service.md) for complete setup guide.

---

# iroh-manual Mode

Uses iroh's QUIC transport with manual copy-paste signaling. No discovery servers or relay infrastructure needed, but STUN is used by default.

**NAT Traversal:** Uses STUN to discover public addresses and bidirectional connection racing. Works with most NATs but may fail on symmetric NATs. For difficult NAT scenarios, use [Custom Mode](#custom-mode) which has full ICE support.

## Quick Start

1. **Client** starts first and outputs an offer:
   ```bash
   tunnel-rs client iroh-manual --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
   ```

   Copy the `-----BEGIN TUNNEL-RS IROH OFFER-----` block.

2. **Server** validates the source request and outputs an answer:
   ```bash
   tunnel-rs server iroh-manual --allowed-tcp 127.0.0.0/8
   ```

   Paste the offer, then copy the `-----BEGIN TUNNEL-RS IROH ANSWER-----` block.

3. **Client** receives the answer:

   Paste the answer into the client terminal.

4. **Connect**:
   ```bash
   ssh -p 2222 user@127.0.0.1
   ```

## CLI Options

### server iroh-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tcp` | none | Allowed TCP networks in CIDR notation (repeatable) |
| `--allowed-udp` | none | Allowed UDP networks in CIDR notation (repeatable) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

### client iroh-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source to request from server (e.g., tcp://127.0.0.1:22) |
| `--target`, `-t` | required | Local address to listen on (e.g., 127.0.0.1:2222) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

Note: Config file options (`-c`, `--default-config`) are at the `server`/`client` command level. See [Configuration Files](#configuration-files) above.

## Serverless Manual Mode (No STUN)

If you want **zero external infrastructure**, you can run manual modes without any STUN servers. This only works reliably when both peers are on public IPs or permissive NATs. Disabling STUN reduces NAT hole‑punching success.

If your goal is simply to avoid self‑hosting or depending on smaller/less‑reliable infra (e.g., iroh relay/discovery), you do **not** need `--no-stun`, public STUN servers (like Google's) are widely available and help NAT traversal without requiring you to run anything yourself.

Use `--no-stun` on the CLI, or set `stun_servers = []` in your config. If you omit STUN entirely (no config and no CLI), tunnel-rs uses its default public STUN list.

Example (CLI only):
```bash
tunnel-rs client iroh-manual --no-stun --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
tunnel-rs server iroh-manual --no-stun --allowed-tcp 127.0.0.0/8
```

## UDP Example

All modes support TCP and UDP tunneling; example below uses UDP:

```bash
# Client (starts first)
tunnel-rs client iroh-manual --source udp://127.0.0.1:51820 --target 0.0.0.0:51820

# Server (validates and responds)
tunnel-rs server iroh-manual --allowed-udp 127.0.0.0/8
```

---

# Custom-Manual Mode

Uses full ICE (Interactive Connectivity Establishment) with str0m + quinn QUIC.

**NAT Traversal:** Full ICE implementation with STUN candidate gathering and connectivity checks. This provides the best NAT traversal success rate, including support for symmetric NATs that fail with simpler STUN-only approaches.

## Architecture

```
+-----------------+        +-----------------+                    +-----------------+        +-----------------+
| SSH Client      |  TCP   | client          |  ICE/QUIC          | server          |  TCP   | SSH Server      |
|                 |<------>| (local:2222)    |<===================|                 |<------>| (local:22)      |
|                 |        |                 |  (copy-paste)      |                 |        |                 |
+-----------------+        +-----------------+                    +-----------------+        +-----------------+
     Client Side                                                        Server Side
```

## Quick Start

1. **Client** starts first and outputs an offer:
   ```bash
   tunnel-rs client custom-manual --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
   ```

   Copy the `-----BEGIN TUNNEL-RS MANUAL OFFER-----` block.

2. **Server** validates the source request and outputs an answer:
   ```bash
   tunnel-rs server custom-manual --allowed-tcp 127.0.0.0/8
   ```

   Paste the offer, then copy the `-----BEGIN TUNNEL-RS MANUAL ANSWER-----` block.

3. **Client** receives the answer:

   Paste the answer into the client terminal.

4. **Connect**:
   ```bash
   ssh -p 2222 user@127.0.0.1
   ```

## UDP Tunnel (e.g., WireGuard)

```bash
# Client (starts first)
tunnel-rs client custom-manual --source udp://127.0.0.1:51820 --target 0.0.0.0:51820

# Server (validates and responds)
tunnel-rs server custom-manual --allowed-udp 127.0.0.0/8
```

## CLI Options

### server custom-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tcp` | none | Allowed TCP networks in CIDR notation (repeatable) |
| `--allowed-udp` | none | Allowed UDP networks in CIDR notation (repeatable) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

### client custom-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source to request from server (e.g., tcp://127.0.0.1:22) |
| `--target`, `-t` | required | Local address to listen on (e.g., 127.0.0.1:2222) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

Note: Config file options (`-c`, `--default-config`) are at the `server`/`client` command level. See [Configuration Files](#configuration-files) above.

## Connection Types

After ICE negotiation, the connection type is displayed:

```
ICE connection established!
   Connection: Direct (Host)
   Local: 10.0.0.5:54321 -> Remote: 10.0.0.10:12345
```

| Type | Description |
|------|-------------|
| Direct (Host) | Both peers on same network |
| NAT Traversal (Server Reflexive) | Peers behind NAT, using STUN |

## Notes

- Full ICE provides best NAT traversal - works with most symmetric NATs
- Signaling payloads include a version number; mismatches are rejected

---

# Nostr Mode

Uses full ICE with Nostr-based signaling. Instead of manual copy-paste, ICE offers/answers are exchanged automatically via Nostr relays using static keypairs (like WireGuard).

**Key Features:**
- **Static keys** — Persistent identity using nsec/npub keypairs (like WireGuard)
- **Automated signaling** — No copy-paste required; offers/answers exchanged via Nostr relays
- **Full ICE** — Same NAT traversal as custom mode (str0m + quinn)
- **Deterministic pairing** — Transfer ID derived from both pubkeys; no coordination needed

## Architecture

```
+-----------------+        +-----------------+        +---------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | receiver        |  ICE   |   Nostr       |  ICE   | sender          |  TCP   | SSH Server      |
|                 |<------>| (local:2222)    |<======>|   Relays      |<======>|                 |<------>| (local:22)      |
|                 |        |                 |  QUIC  | (signaling)   |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +---------------+        +-----------------+        +-----------------+
     Client Side                                                                     Server Side
```

## Quick Start

### 1. Generate Keypairs (One-Time Setup)

Each peer needs their own keypair:

```bash
# On server machine
tunnel-rs generate-nostr-key --output ./server.nsec
# Output (stdout): npub1server...

# On client machine
tunnel-rs generate-nostr-key --output ./client.nsec
# Output (stdout): npub1client...
```

Exchange public keys (npub) between peers.

### 2. Start Tunnel

**Server** (on server with SSH — waits for client connections):
```bash
tunnel-rs server nostr \
  --allowed-tcp 127.0.0.0/8 \
  --nsec-file ./server.nsec \
  --peer-npub npub1client...
```

**Client** (on client — initiates connection):
```bash
tunnel-rs client nostr \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222 \
  --nsec-file ./client.nsec \
  --peer-npub npub1server...
```

### 3. Connect

```bash
ssh -p 2222 user@127.0.0.1
```

## UDP Tunnel (e.g., WireGuard)

```bash
# Server (allows UDP traffic to localhost)
tunnel-rs server nostr \
  --allowed-udp 127.0.0.0/8 \
  --nsec-file ./server.nsec \
  --peer-npub npub1client...

# Client (requests WireGuard tunnel)
tunnel-rs client nostr \
  --source udp://127.0.0.1:51820 \
  --target udp://0.0.0.0:51820 \
  --nsec-file ./client.nsec \
  --peer-npub npub1server...
```

## CLI Options

### server nostr

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tcp` | - | Allowed TCP networks in CIDR (repeatable, e.g., `127.0.0.0/8`) |
| `--allowed-udp` | - | Allowed UDP networks in CIDR (repeatable, e.g., `10.0.0.0/8`) |
| `--nsec` | - | Your Nostr private key (nsec or hex format) |
| `--nsec-file` | - | Path to file containing your Nostr private key |
| `--peer-npub` | required | Peer's Nostr public key (npub or hex format) |
| `--relay` | public relays | Nostr relay URL(s), repeatable |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN |
| `--max-sessions` | 10 | Maximum concurrent sessions (0 = unlimited) |

### client nostr

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source address to request from server |
| `--target`, `-t` | required | Local address to listen on |
| `--nsec` | - | Your Nostr private key (nsec or hex format) |
| `--nsec-file` | - | Path to file containing your Nostr private key |
| `--peer-npub` | required | Peer's Nostr public key (npub or hex format) |
| `--relay` | public relays | Nostr relay URL(s), repeatable |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN |

## Configuration File

```toml
# Server config
role = "server"
mode = "nostr"

[nostr]
nsec_file = "./server.nsec"
peer_npub = "npub1..."
allowed_tcp = ["127.0.0.0/8", "10.0.0.0/8"]
relays = ["wss://relay.damus.io", "wss://nos.lol"]
stun_servers = ["stun.l.google.com:19302"]
max_sessions = 10
```

## Default Nostr Relays

When no relays are specified, these public relays are used:
- `wss://relay.damus.io`
- `wss://nos.lol`
- `wss://relay.nostr.band`
- `wss://relay.primal.net`
- `wss://nostr.mom`
- `wss://relay.snort.social`

## Notes

- Keys are static like WireGuard — generate once, use repeatedly
- Transfer ID is derived from SHA256 of sorted pubkeys — both peers compute the same ID
- Signaling uses Nostr event kind 24242 with tags for transfer ID and peer pubkey
- Full ICE provides best NAT traversal (same as custom mode)
- **Client-first protocol:** The client initiates the connection by publishing a request first; server waits for a request before publishing its offer

> [!WARNING]
> **Containerized Environments:** Nostr mode uses STUN-only NAT traversal without relay fallback. If both peers are behind restrictive NATs (common in Docker, Kubernetes, or cloud VMs), ICE connectivity may fail. For containerized deployments, consider using `iroh` mode which includes automatic relay fallback.

## Mode Capabilities

| Mode | Multi-Session | Dynamic Source | Description |
|------|---------------|----------------|-------------|
| `iroh` | **Yes** | **Yes** | Multiple receivers, receiver chooses source |
| `nostr` | **Yes** | **Yes** | Multiple receivers, receiver chooses source |
| `iroh-manual` | No | No | Single session, fixed source |
| `custom-manual` | No | No | Single session, fixed source |

**Multi-Session** = Multiple concurrent connections to the same sender
**Dynamic Source** = Receiver specifies which service to tunnel (like SSH `-L`)

### iroh (Multi-Session + Dynamic Source)

Server whitelists networks; clients choose which service to tunnel:

```bash
# Server: whitelist networks, clients choose destination
tunnel-rs server iroh --allowed-tcp 127.0.0.0/8 --max-sessions 100

# Client 1: tunnel to SSH
tunnel-rs client iroh --node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222

# Client 2: tunnel to web server (same server!)
tunnel-rs client iroh --node-id <ID> --source tcp://127.0.0.1:80 --target 127.0.0.1:8080
```

### nostr (Multi-Session + Dynamic Source)

Server whitelists networks; clients choose which service to tunnel:

```bash
# Server: whitelist networks, clients choose destination
tunnel-rs server nostr --allowed-tcp 127.0.0.0/8 --nsec-file ./server.nsec --peer-npub <NPUB> --max-sessions 5

# Client 1: tunnel to SSH
tunnel-rs client nostr --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 ...

# Client 2: tunnel to web server (same server!)
tunnel-rs client nostr --source tcp://127.0.0.1:80 --target 127.0.0.1:8080 ...
```

### Single-Session Modes (iroh-manual, custom-manual)

For `iroh-manual` and `custom-manual`, use separate instances for each tunnel:
- Different keypairs/instances per tunnel
- Or use `iroh` or `nostr` mode for multi-session support

---

# DCUtR Mode (Experimental)

Uses timing-coordinated hole punching with a dedicated signaling server. The server coordinates the exact moment both peers attempt connection, improving NAT traversal success rates.

> [!WARNING]
> **Experimental:** This mode is under active development. For production use, prefer `iroh` mode which has relay fallback.

## Architecture

```
+-----------------+        +-----------------+        +------------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | client          |  ICE   | Signaling Server |  ICE   | server          |  TCP   | SSH Server      |
|                 |<------>| (local:2222)    |<======>| (coordinates     |<======>|                 |<------>| (local:22)      |
|                 |        |                 |  QUIC  |  timing)         |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +------------------+        +-----------------+        +-----------------+
     Client Side                                        Self-hosted                     Server Side
```

## Quick Start

### 1. Start Signaling Server

```bash
# Build and run the signaling server binary
cargo build --release --bin signaling
./target/release/signaling --bind 0.0.0.0:9999
```

### 2. Start Tunnel Server

```bash
# Server specifies the exact source to forward to
tunnel-rs server dcutr \
  --signaling-server <signaling-ip>:9999 \
  --source tcp://127.0.0.1:22 \
  --server-id my-server
```

### 3. Start Tunnel Client

```bash
# Client specifies local listen address and peer to connect to
tunnel-rs client dcutr \
  --signaling-server <signaling-ip>:9999 \
  --peer-id my-server \
  --target 127.0.0.1:2222
```

### 4. Connect

```bash
ssh -p 2222 user@127.0.0.1
```

## How It Works

1. Both peers register with the signaling server
2. Server measures RTT to each peer (5 ping rounds)
3. Client requests connection to server by peer ID
4. Signaling server calculates synchronized start time
5. Both peers receive sync_connect with peer's ICE candidates and start time
6. Both peers begin ICE simultaneously at the coordinated time
7. Direct QUIC connection established over ICE

**Key optimizations:**
- True RTT measurement (client-measured, not clock-dependent)
- Fast ICE timing parameters for coordinated attempts
- 500ms timing buffer for clock skew and jitter

---

# Utility Commands

## generate-nostr-key

Generate a Nostr keypair for use with nostr mode:

```bash
# Save nsec to file and output npub
tunnel-rs generate-nostr-key --output ./nostr.nsec

# Overwrite existing file
tunnel-rs generate-nostr-key --output ./nostr.nsec --force

# Output nsec to stdout and npub to stderr (wireguard-style)
tunnel-rs generate-nostr-key --output -
```

Output (when using `--output -`):

stdout (nsec):
```
nsec1...
```

stderr (npub):
```
npub1...
```

## generate-iroh-key

*For iroh and iroh-manual modes.*

```bash
tunnel-rs generate-iroh-key --output ./server.key
```

## show-iroh-node-id

```bash
tunnel-rs show-iroh-node-id --secret-file ./server.key
```

## show-npub

Display the npub for an existing nsec key file:

```bash
tunnel-rs show-npub --nsec-file ./nostr.nsec
```

---

## Platform Compatibility

tunnel-rs is designed to work across different operating systems:
- **Windows** can receive connections from Linux/macOS and vice versa
- **macOS** endpoints can tunnel to Linux systems
- **Linux** endpoints work with all platforms

All protocol modes and features are available on all platforms.

## Security

- All traffic is encrypted using QUIC/TLS 1.3
- The EndpointId is a public key that identifies the sender
- Secret key files are created with `0600` permissions (Unix) and appropriate permissions on Windows
- Treat secret key files like SSH private keys

## How It Works

### iroh Mode
1. Sender creates an iroh endpoint with discovery services
2. Sender publishes its address via Pkarr/DNS
3. Receiver resolves the sender via discovery
4. Connection established via iroh's NAT traversal
5. Receiver sends `SourceRequest` with desired source address
6. Sender validates against allowed networks and responds
7. If accepted, traffic forwarding begins

### iroh-manual Mode
1. Sender creates iroh endpoint (no relay, no discovery)
2. STUN queries discover public addresses (heuristic port mapping)
3. Manual exchange of offer/answer (copy-paste with NodeId + addresses)
4. Both sides race connect/accept for hole punching
5. Direct connection established via iroh's QUIC

*Limitation: Uses heuristic port mapping which may fail on symmetric NATs.*

### Custom-Manual Mode
1. Both sides gather ICE candidates via STUN (same socket used for data)
2. Manual exchange of offer/answer (copy-paste)
3. ICE connectivity checks probe all candidate pairs simultaneously
4. Best working path selected via ICE nomination
5. QUIC connection established over ICE socket

*Advantage: Full ICE provides reliable NAT traversal even for symmetric NATs.*

### Nostr Mode (Receiver-Initiated)
1. Both peers derive deterministic transfer ID from their sorted public keys
2. Sender waits for connection requests from receivers
3. Receiver publishes connection request with desired source to Nostr relays
4. Sender receives request, gathers ICE candidates, publishes offer
5. Receiver receives offer, gathers candidates, publishes answer
6. ICE connectivity checks begin, best path selected
7. QUIC connection established over ICE socket

*Advantage: Receiver-initiated flow (like WireGuard) + automated signaling + full ICE NAT traversal.*

### DCUtR Mode (Experimental)
1. Both peers connect to signaling server and register
2. Each peer measures RTT to signaling server (5 ping rounds)
3. Client requests connection to server by peer ID
4. Signaling server calculates synchronized start time based on RTT
5. Both peers receive sync_connect notification with peer's ICE candidates
6. Both peers begin ICE simultaneously at coordinated time (fast timing mode)
7. QUIC connection established over ICE socket

*Advantage: Timing coordination improves hole punch success. Self-hosted signaling (no third-party relays).*
