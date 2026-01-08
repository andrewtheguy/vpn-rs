# tunnel-rs

**Cross-platform Secure Peer-to-Peer TCP/UDP port forwarding with NAT traversal.**

Tunnel-rs enables you to forward TCP and UDP traffic between machines without requiring public IP addresses, port forwarding, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

> [!IMPORTANT]
> **Project Goal:** This tool provides a convenient way to connect to different networks for **development or homelab purposes** without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale.

**Key Features:**
- **Full TCP and UDP support** — Seamlessly tunnel any TCP or UDP traffic
- **Native VPN mode** — Full WireGuard-based VPN with automatic IP assignment (Linux/macOS)
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching and stable peer identities eliminate the need for complex firewall rules or dynamic DNS
- **Cross-platform support** — Works on Linux, macOS, and Windows
- **End-to-end encryption** via QUIC/TLS 1.3 (port forwarding) or WireGuard + QUIC (VPN mode)
- **NAT traversal** with multiple strategies (relay fallback, STUN, full ICE)
- **Minimal configuration** — Automatic peer discovery using simple, shareable identities
- **Flexible signaling** — Supports multiple connection methods, from automated discovery to manual exchange
- **Offline/LAN support** — manual mode works without internet for local network tunneling
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

tunnel-rs provides multiple modes for establishing tunnels. **Use `iroh` mode** for most use cases — it provides the best NAT traversal with relay fallback, automatic discovery, and client authentication.

Binary layout:
- `tunnel-rs`: iroh mode + VPN mode
- `tunnel-rs-ice`: manual and nostr

| Mode | NAT Traversal | Discovery | External Dependency | Use Case |
|------|---------------|-----------|---------------------|----------|
| **iroh** (recommended) | Best (relay fallback) | Automatic | iroh relay infrastructure | TCP/UDP port forwarding |
| **vpn** | Best (relay fallback) | Automatic | iroh relay infrastructure | Full network tunneling (Linux/macOS) |
| nostr | STUN only | Automatic (Nostr) | Nostr relays (decentralized) | Decentralized port forwarding |
| manual | STUN only | Manual copy-paste | None | Offline/LAN port forwarding |

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### When to Use Alternative Modes

Choose an alternative mode only if you have specific requirements:

- **nostr**: You want decentralized signaling without depending on iroh infrastructure. Uses Nostr relays instead.
- **manual**: You want complete independence from third-party services (disable STUN for fully self-contained operation), or no internet is available (offline/LAN-only). Signaling is done via manual copy-paste.

> [!NOTE]
> The `nostr` and `manual` modes use STUN-only NAT traversal, which may fail when both peers are behind symmetric NATs. For containerized environments (Docker, Kubernetes, cloud VMs), use `iroh` mode which includes relay fallback.

> [!TIP]
> If you only need iroh mode, use the `tunnel-rs` binary. ICE modes are in `tunnel-rs-ice`.

## Installation

GitHub releases include both `tunnel-rs` (iroh-only) and `tunnel-rs-ice` binaries. You only need the binary in your PATH; no runtime dependencies or package managers are required.

### Quick Install (Linux & macOS, iroh only)

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

### Quick Install (Windows, iroh only)

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

Note: The quick install scripts install the `tunnel-rs` iroh-only binary.
For ICE modes (`tunnel-rs-ice`), download the `tunnel-rs-ice` binary manually
from GitHub releases or build from source.

### From Source

```bash
cargo install --path . -p tunnel-rs
```

To install the ICE binary:
```bash
cargo install --path . -p tunnel-rs-ice
```

### Feature Flags

`test-utils` is available on the iroh crates/binary for enabling `--relay-only` during testing.

### Supported Platforms

tunnel-rs is fully supported on:
- **Linux** (x86_64, ARM64)
- **macOS** (Intel, Apple Silicon)
- **Windows** (x86_64)

All modes (iroh, manual, nostr) work across all platforms, enabling cross-platform P2P tunneling.

### Docker & Kubernetes

Container images are available at `ghcr.io/andrewtheguy/tunnel-rs:latest` (iroh-only).

Access services running in Docker or Kubernetes remotely — without opening ports, configuring ingress, or requiring `kubectl`. See [container-deploy/](container-deploy/) for Docker Compose and Kubernetes configurations.

---

# iroh Mode (Recommended)

Uses iroh's P2P network for automatic peer discovery and NAT traversal with relay fallback. Best for containerized environments and persistent tunnels.

> **Summary:** Automatic discovery via Pkarr/DNS, relay fallback for restrictive NATs, multi-session support. See [Architecture: iroh Mode](docs/ARCHITECTURE.md#iroh-mode) for detailed diagrams.

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

### 1. Setup (One-Time)

Generate a server key and create an authentication token:

```bash
# On server machine - generate persistent identity
tunnel-rs generate-server-key --output ./server.key
# Output: EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga

# Create a shared authentication token
# Share this token with authorized clients
AUTH_TOKEN=$(tunnel-rs generate-token)
echo $AUTH_TOKEN
```

### 2. TCP Tunnel (e.g., SSH)

**Server** (on server — waits for client connections):
```bash
tunnel-rs server \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --auth-tokens "$AUTH_TOKEN"
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Auth tokens: 1 token(s) configured
Waiting for clients to connect...
```

**Client** (on client — requests source from server):
```bash
tunnel-rs client \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222 \
  --auth-token "$AUTH_TOKEN"
```

Then connect: `ssh -p 2222 user@127.0.0.1`

### 3. UDP Tunnel (e.g., WireGuard)

**Server**:
```bash
tunnel-rs server \
  --secret-file ./server.key \
  --allowed-udp 127.0.0.0/8 \
  --auth-tokens "$AUTH_TOKEN"
```

**Client**:
```bash
tunnel-rs client \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --source udp://127.0.0.1:51820 \
  --target 0.0.0.0:51820 \
  --auth-token "$AUTH_TOKEN"
```

## CLI Options

### server

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/server.toml` (`tunnel-rs`) or `~/.config/tunnel-rs/server_ice.toml` (`tunnel-rs-ice`) |

### server iroh

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tcp` | - | Allowed TCP networks in CIDR notation (repeatable) |
| `--allowed-udp` | - | Allowed UDP networks in CIDR notation (repeatable) |
| `--auth-tokens` | required | Authentication tokens (repeatable). Clients must provide one of these tokens to connect. |
| `--auth-tokens-file` | - | Path to file containing authentication tokens (one per line, # comments allowed) |
| `--max-sessions` | 100 | Maximum concurrent sessions |
| `--secret` | - | Base64-encoded secret key for persistent server identity |
| `--secret-file` | - | Path to secret key file for persistent server identity |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (requires `test-utils` feature) |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--socks5-proxy` | - | **(Experimental)** Tor SOCKS5 proxy for self-hosted .onion relay. **Tor-only:** requires all relay URLs to be `.onion` addresses, validates proxy is Tor at startup, cannot be used with `--dns-server`. See [Tor Hidden Service](#tor-hidden-service-no-public-ip). |

### client

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/client.toml` (`tunnel-rs`) or `~/.config/tunnel-rs/client_ice.toml` (`tunnel-rs-ice`) |

### client iroh

| Option | Default | Description |
|--------|---------|-------------|
| `--server-node-id`, `-n` | required | EndpointId of the server |
| `--source`, `-s` | required | Source address to request from server (tcp://host:port or udp://host:port) |
| `--target`, `-t` | required | Local address to listen on |
| `--auth-token` | required | Authentication token to send to server |
| `--auth-token-file` | - | Path to file containing authentication token |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (requires `test-utils` feature) |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--socks5-proxy` | - | **(Experimental)** Tor SOCKS5 proxy for self-hosted .onion relay. **Tor-only:** requires all relay URLs to be `.onion` addresses, validates proxy is Tor at startup, cannot be used with `--dns-server`. See [Tor Hidden Service](#tor-hidden-service-no-public-ip). |

## Configuration Files

Use `--default-config` to load from the default location, or `-c <path>` for a custom path. Each mode has its own configuration section:
- **iroh** mode: `[iroh]` section
- **manual** mode: `[manual]` section
- **nostr** mode: `[nostr]` section

When using `tunnel-rs-ice` with a config file, the mode is inferred from the file, so you can omit the subcommand:
```bash
tunnel-rs-ice server -c server_ice.toml
tunnel-rs-ice client -c client_ice.toml
```

**Default locations:**
- Server: `~/.config/tunnel-rs/server.toml` (`tunnel-rs`) or `~/.config/tunnel-rs/server_ice.toml` (`tunnel-rs-ice`)
- Client: `~/.config/tunnel-rs/client.toml` (`tunnel-rs`) or `~/.config/tunnel-rs/client_ice.toml` (`tunnel-rs-ice`)

### Overriding Config Values

CLI arguments take precedence over config file values. Use `--default-config` with CLI arguments to override specific fields:

```bash
# Use config but override source and target
tunnel-rs client --default-config \
  --source tcp://localhost:3000 \
  --target 127.0.0.1:8080

# Use config but override allowed networks
tunnel-rs server --default-config \
  --allowed-tcp 10.0.0.0/8
```

This lets you keep common settings (keys, relay URLs) in the config file while varying per-session options on the command line. You can also omit fields like `source` and `target` from the config entirely and provide them only via CLI.

### Server Config Example

```toml
# Example server configuration (iroh mode)

# Required: validates config matches CLI command
role = "server"
mode = "iroh"  # or "manual", or "nostr"

[iroh]
secret_file = "./server.key"
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
max_sessions = 100

# Authentication: clients must provide one of these tokens (18 chars)
# Generate with: tunnel-rs generate-token
auth_tokens = [
    "ikAdvudu_ZxNXhNLCD",
    "iw3nLKic3oV7zmFJ8v",
]
# Or use: auth_tokens_file = "/etc/tunnel-rs/auth_tokens.txt"

[iroh.allowed_sources]
tcp = ["127.0.0.0/8", "192.168.0.0/16"]
udp = ["10.0.0.0/8"]
```

> [!NOTE]
> See [`server.toml.example`](server.toml.example) for the full iroh example, and [`server_ice.toml.example`](server_ice.toml.example) for ICE modes.

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
mode = "iroh"

[iroh]
server_node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
request_source = "tcp://127.0.0.1:22"
target = "127.0.0.1:2222"
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"

# Authentication token (get from server admin, 18 chars)
auth_token = "ikAdvudu_ZxNXhNLCD"
# Or use: auth_token_file = "~/.config/tunnel-rs/token.txt"
```

> [!NOTE]
> See [`client.toml.example`](client.toml.example) for the full iroh example, and [`client_ice.toml.example`](client_ice.toml.example) for ICE modes.

```bash
# Load from default location (mode inferred from config)
tunnel-rs client --default-config

# Load from custom path
tunnel-rs client -c ./my-client.toml
```

## Persistent Server Identity

By default, a new EndpointId is generated each run. For long-running setups, use persistent identity for the **server**:

```bash
# Generate key and output EndpointId
tunnel-rs generate-server-key --output ./server.key

# Show EndpointId for existing key
tunnel-rs show-server-id --secret-file ./server.key
```

Then use the key for the server:

```bash
tunnel-rs server --allowed-tcp 127.0.0.0/8 --secret-file ./server.key --auth-tokens "$AUTH_TOKEN"
```

> **Note:** Clients use ephemeral identities by default. Only the server needs a persistent key to maintain a stable EndpointId that clients can connect to.

## Authentication

Iroh mode requires authentication using pre-shared tokens. Clients must provide a valid token to connect.

**Token Format:**
- Exactly 18 characters
- Starts with `i` (for iroh)
- Ends with a checksum character
- Middle 16 characters: `A-Za-z0-9` and `-` `_` `.` (period is valid but rare in generated tokens)

Generate tokens with: `tunnel-rs generate-token`

### Setup Workflow

1. **Generate a server key:**
   ```bash
   tunnel-rs generate-server-key --output ./server.key
   ```

2. **Create authentication tokens:**
   ```bash
   # Generate a valid token
   AUTH_TOKEN=$(tunnel-rs generate-token)
   echo $AUTH_TOKEN  # Share this with authorized clients

   # Generate multiple tokens
   tunnel-rs generate-token -c 5
   ```

3. **Start server with auth tokens:**
   ```bash
   tunnel-rs server \
     --secret-file ./server.key \
     --allowed-tcp 127.0.0.0/8 \
     --auth-tokens "$AUTH_TOKEN"
   ```

4. **Start client with auth token:**
   ```bash
   tunnel-rs client \
     --server-node-id <SERVER_ENDPOINT_ID> \
     --source tcp://127.0.0.1:22 \
     --target 127.0.0.1:2222 \
     --auth-token "$AUTH_TOKEN"
   ```

### Multiple Tokens

```bash
# Multiple --auth-tokens flags
tunnel-rs server \
  --allowed-tcp 127.0.0.0/8 \
  --auth-tokens "token-for-alice" \
  --auth-tokens "token-for-bob"

# Or use a file (one token per line, # comments allowed)
tunnel-rs server \
  --allowed-tcp 127.0.0.0/8 \
  --auth-tokens-file /etc/tunnel-rs/auth_tokens.txt
```

**Example `auth_tokens.txt`:**
```text
# Alice's token (generate with: tunnel-rs generate-token)
ikAdvudu_ZxNXhNLCD

# Bob's token
iw3nLKic3oV7zmFJ8v
```

### Configuration File

In `server.toml`:

```toml
[iroh]
# Inline list (tokens must be exactly 18 characters)
# Generate with: tunnel-rs generate-token
auth_tokens = [
    "ikAdvudu_ZxNXhNLCD",  # Alice
    "iw3nLKic3oV7zmFJ8v",  # Bob
]

# Or use a file
# auth_tokens_file = "/etc/tunnel-rs/auth_tokens.txt"
```

## Custom Relay Server

Use a custom relay server instead of the public iroh relay infrastructure.

> **Note:** When using `--relay-url`, you only need a custom relay server. The `--dns-server` option is **not required** — DNS discovery is only needed if you also want to avoid the public iroh DNS infrastructure (see [Self-Hosted DNS Discovery](#self-hosted-dns-discovery)).

```bash
# Both sides must use the same relay
tunnel-rs server --relay-url https://relay.example.com --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"
tunnel-rs client --relay-url https://relay.example.com --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 --auth-token "$AUTH_TOKEN"

# Force relay-only (no direct P2P) - requires test-utils feature
# Build with: cargo build --features test-utils
tunnel-rs server --relay-url https://relay.example.com --relay-only --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"
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
tunnel-rs server --dns-server https://dns.example.com/pkarr --secret-file ./server.key --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"
tunnel-rs client --dns-server https://dns.example.com/pkarr --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 --auth-token "$AUTH_TOKEN"
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
tunnel-rs server \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --auth-tokens "$AUTH_TOKEN"

# Client
tunnel-rs client \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --server-node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222 \
  --auth-token "$AUTH_TOKEN"
```

### Relay Behavior

iroh mode uses the relay for both **signaling/coordination** and as a **data transport fallback**:

1. Initial connection goes through relay for signaling
2. iroh attempts coordinated hole punching (similar to libp2p's DCUtR protocol)
3. If successful (~70%), traffic flows directly between peers
4. If hole punching fails, **traffic continues through relay**

> [!NOTE]
> **Bandwidth Concern:** If you want signaling-only coordination **without** relay fallback (to avoid forwarding any tunnel traffic), iroh mode currently doesn't support this. The relay always acts as fallback when direct connection fails.
>
> **Alternative for signaling-only:** Use `nostr` mode with self-hosted Nostr relays. Nostr relays only handle signaling (small encrypted messages), never tunnel traffic. If hole punching fails, the connection fails — no traffic is ever forwarded through the relay.

### Tor Hidden Service (No Public IP)

> [!WARNING]
> **Experimental Feature:** Tor hidden service support is experimental and might not work reliably.

> **Use Case:** Self-hosting your own iroh-relay without a public IP. The `--socks5-proxy` option is **exclusively for Tor hidden services** — it requires `.onion` relay URLs and validates that the proxy is a real Tor proxy at startup.

If you can't get a public IP or Cloudflare tunnel doesn't work (HTTP/2 breaks WebSocket upgrades), you can run iroh-relay as a Tor hidden service:

```bash
# Server side: configure tor hidden service pointing to localhost:3340
# Then start iroh-relay and tunnel-rs with the .onion URL
tunnel-rs server \
  --relay-url http://YOUR_RELAY.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --auth-tokens "$AUTH_TOKEN"

# Client side: use --socks5-proxy to reach .onion relay (direct P2P bypasses Tor)
tunnel-rs client \
  --relay-url http://YOUR_RELAY.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --server-node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222 \
  --auth-token "$AUTH_TOKEN"
```

> **Note:** When using `--socks5-proxy`, all relay URLs must be `.onion` addresses. The proxy is validated as a real Tor proxy at startup. DNS discovery is not used with Tor — the relay handles peer discovery.

See [docs/tor-hidden-service.md](docs/tor-hidden-service.md) for complete setup guide.

---

# VPN Mode (Linux/macOS)

Native WireGuard-based VPN mode for full network tunneling. Unlike port forwarding modes, VPN mode creates a TUN device and routes IP traffic through an encrypted WireGuard tunnel.

> **Note:** VPN mode is only available on Linux and macOS. It requires root/sudo privileges to create TUN devices and configure routes.

## Architecture

```
Client                                     Server
┌─────────────────────┐                   ┌─────────────────────┐
│  Applications       │                   │  Target Network     │
│        ↓            │                   │        ↑            │
│  [tun0: 10.0.0.2]   │                   │  [tun0: 10.0.0.1]   │
│        ↓            │                   │        ↑            │
│  WireGuard (boringtun)                  │  WireGuard (boringtun)
│        ↓            │                   │        ↑            │
│  iroh (signaling)   │ ════════════════► │  iroh (signaling)   │
└─────────────────────┘   NAT traversal   └─────────────────────┘
```

**Key Differences from Port Forwarding:**
- Creates a virtual network interface (TUN device)
- Assigns VPN IP addresses automatically (no keypair management)
- Routes entire IP subnets, not just individual ports
- Uses WireGuard encryption (via boringtun) on top of iroh's QUIC transport

## Quick Start

### 1. Setup (One-Time)

Generate a server key for persistent identity:

```bash
# On server machine
tunnel-rs generate-server-key --output ./server.key

# Create authentication token
AUTH_TOKEN=$(tunnel-rs generate-token)
echo $AUTH_TOKEN
```

### 2. Start VPN Server

```bash
sudo tunnel-rs vpn server \
  --network 10.0.0.0/24 \
  --secret-file ./server.key \
  --auth-tokens "$AUTH_TOKEN"
```

Output:
```
VPN Server Node ID: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Clients connect with: tunnel-rs vpn client --server-node-id <ID> --auth-token <TOKEN>
```

### 3. Connect VPN Client

```bash
sudo tunnel-rs vpn client \
  --server-node-id <SERVER_NODE_ID> \
  --auth-token "$AUTH_TOKEN"
```

The client will:
1. Connect to the server via iroh (NAT traversal)
2. Exchange ephemeral WireGuard keys
3. Receive an assigned IP (e.g., 10.0.0.2)
4. Create a TUN device and configure routes

### 4. Verify Connection

```bash
# Check assigned IP
ip addr show tun0  # Linux
ifconfig utun9     # macOS

# Ping the server
ping 10.0.0.1
```

## CLI Options

> **Note:** VPN mode currently does not support configuration files. All options must be passed via CLI.

### vpn server

| Option | Default | Description |
|--------|---------|-------------|
| `--network`, `-n` | 10.0.0.0/24 | VPN network CIDR. Server gets .1, clients get subsequent IPs |
| `--server-ip` | First IP in network | Override server's VPN IP address |
| `--mtu` | 1420 | MTU for VPN packets |
| `--secret-file` | - | Path to secret key for persistent iroh identity |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--auth-tokens` | required | Authentication tokens (repeatable) |
| `--auth-tokens-file` | - | Path to file with tokens (one per line) |

### vpn client

| Option | Default | Description |
|--------|---------|-------------|
| `--server-node-id`, `-n` | required | EndpointId of the VPN server |
| `--mtu` | 1420 | MTU for VPN packets |
| `--keepalive-secs` | 25 | WireGuard keepalive interval |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--auth-token` | required | Authentication token |
| `--auth-token-file` | - | Path to file containing token |
| `--route` | - | Additional CIDRs to route through VPN (repeatable) |

## Split Tunneling

By default, only traffic to the VPN network (e.g., 10.0.0.0/24) is routed through the tunnel. Use `--route` to add additional networks:

```bash
sudo tunnel-rs vpn client \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

## How It Works

1. **Signaling via iroh**: Client connects to server using iroh for peer discovery and NAT traversal
2. **WireGuard Key Exchange**: Ephemeral WireGuard keys are generated and exchanged (no manual keypair management)
3. **IP Assignment**: Server assigns client an IP from the VPN network pool
4. **TUN Device**: Both sides create TUN devices for packet capture
5. **Packet Flow**: IP packets are encrypted with WireGuard and tunneled through the iroh connection

**Advantages over traditional WireGuard:**
| Feature | WireGuard | tunnel-rs VPN |
|---------|-----------|---------------|
| Identity | Static keypair per device | Ephemeral keys (auto-generated) |
| Config conflict | Same keypair = conflict | Each session unique |
| NAT traversal | Manual endpoint config | Automatic via iroh |
| IP assignment | Static in config | Dynamic from server |

## Single Instance Lock

Only one VPN client can run at a time per machine. This prevents routing conflicts and TUN device issues. The lock is automatically released when the client exits.

---

# Alternative: manual Mode

> Use this mode for: (1) complete independence from third-party services (disable STUN), or (2) offline/LAN-only operation when no internet is available. For most use cases, [iroh mode](#iroh-mode-recommended) is recommended.

Uses full ICE (Interactive Connectivity Establishment) with str0m + quinn QUIC. Signaling is done via manual copy-paste.

> **Summary:** Manual copy-paste signaling, full ICE NAT traversal via STUN, no relay fallback. See [Architecture: manual Mode](docs/ARCHITECTURE.md#manual-mode) for detailed diagrams.

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
   tunnel-rs-ice client manual --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
   ```

   Copy the `-----BEGIN TUNNEL-RS MANUAL OFFER-----` block.

2. **Server** validates the source request and outputs an answer:
   ```bash
   tunnel-rs-ice server manual --allowed-tcp 127.0.0.0/8
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
tunnel-rs-ice client manual --source udp://127.0.0.1:51820 --target 0.0.0.0:51820

# Server (validates and responds)
tunnel-rs-ice server manual --allowed-udp 127.0.0.0/8
```

## CLI Options

### server manual

| Option | Default | Description |
|--------|---------|-------------|
| `--allowed-tcp` | none | Allowed TCP networks in CIDR notation (repeatable) |
| `--allowed-udp` | none | Allowed UDP networks in CIDR notation (repeatable) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

### client manual

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

- Full ICE improves NAT traversal, but without TURN/relay servers symmetric NATs can still fail
- Signaling payloads include a version number; mismatches are rejected

---

# Alternative: nostr Mode

> Use this mode if you want decentralized signaling without depending on iroh infrastructure. For most use cases, [iroh mode](#iroh-mode-recommended) is recommended.

Uses full ICE with Nostr-based signaling. Instead of manual copy-paste, ICE offers/answers are exchanged automatically via Nostr relays using static keypairs (like WireGuard).

> **Summary:** Automated signaling via Nostr relays, static WireGuard-like keys, full ICE NAT traversal, no relay fallback. See [Architecture: nostr Mode](docs/ARCHITECTURE.md#nostr-mode) for detailed diagrams.

**Key Features:**
- **Static keys** — Persistent identity using nsec/npub keypairs (like WireGuard)
- **Automated signaling** — No copy-paste required; offers/answers exchanged via Nostr relays
- **Full ICE** — Same NAT traversal as manual mode (str0m + quinn)
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
tunnel-rs-ice generate-nostr-key --output ./server.nsec
# Output (stdout): npub1server...

# On client machine
tunnel-rs-ice generate-nostr-key --output ./client.nsec
# Output (stdout): npub1client...
```

Exchange public keys (npub) between peers.

### 2. Start Tunnel

**Server** (on server with SSH — waits for client connections):
```bash
tunnel-rs-ice server nostr \
  --allowed-tcp 127.0.0.0/8 \
  --nsec-file ./server.nsec \
  --peer-npub npub1client...
```

**Client** (on client — initiates connection):
```bash
tunnel-rs-ice client nostr \
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
tunnel-rs-ice server nostr \
  --allowed-udp 127.0.0.0/8 \
  --nsec-file ./server.nsec \
  --peer-npub npub1client...

# Client (requests WireGuard tunnel)
tunnel-rs-ice client nostr \
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
relays = ["wss://relay.damus.io", "wss://nos.lol"]
stun_servers = ["stun.l.google.com:19302"]
max_sessions = 10

[nostr.allowed_sources]
tcp = ["127.0.0.0/8", "10.0.0.0/8"]
```

## Default Nostr Relays

When no relays are specified, these public relays are used:
- `wss://nos.lol`
- `wss://relay.nostr.net`
- `wss://relay.primal.net`
- `wss://relay.snort.social`

## Notes

- Keys are static like WireGuard — generate once, use repeatedly
- Transfer ID is derived from SHA256 of sorted pubkeys — both peers compute the same ID
- Signaling uses Nostr event kind 24242 with tags for transfer ID and peer pubkey
- Full ICE provides reliable NAT traversal (same as custom mode)
- **Client-first protocol:** The client initiates the connection by publishing a request first; server waits for a request before publishing its offer

> [!WARNING]
> **Containerized Environments:** nostr mode uses full ICE but without relay fallback. If both peers are behind restrictive NATs (common in Docker, Kubernetes, or cloud VMs), ICE connectivity may fail. For containerized deployments, consider using `iroh` mode which includes automatic relay fallback.

## Mode Capabilities

| Mode | Multi-Session | Dynamic Source | Description |
|------|---------------|----------------|-------------|
| `iroh` | **Yes** | **Yes** | Multiple clients, client chooses source |
| `nostr` | **Yes** | **Yes** | Multiple clients, client chooses source |
| `manual` | No | **Yes** | Single session, client chooses source |

**Multi-Session** = Multiple concurrent connections to the same sender
**Dynamic Source** = Client specifies which service to tunnel (like SSH `-L`)

### iroh (Multi-Session + Dynamic Source)

Server whitelists networks; clients choose which service to tunnel:

```bash
# Server: whitelist networks, clients choose destination
tunnel-rs server --allowed-tcp 127.0.0.0/8 --max-sessions 100 --auth-tokens "$AUTH_TOKEN"

# Client 1: tunnel to SSH
tunnel-rs client --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 --auth-token "$AUTH_TOKEN"

# Client 2: tunnel to web server (same server!)
tunnel-rs client --server-node-id <ID> --source tcp://127.0.0.1:80 --target 127.0.0.1:8080 --auth-token "$AUTH_TOKEN"
```

### nostr (Multi-Session + Dynamic Source)

Server whitelists networks; clients choose which service to tunnel:

```bash
# Server: whitelist networks, clients choose destination
tunnel-rs-ice server nostr --allowed-tcp 127.0.0.0/8 --nsec-file ./server.nsec --peer-npub <NPUB> --max-sessions 5

# Client 1: tunnel to SSH
tunnel-rs-ice client nostr --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 ...

# Client 2: tunnel to web server (same server!)
tunnel-rs-ice client nostr --source tcp://127.0.0.1:80 --target 127.0.0.1:8080 ...
```

### Single-Session Mode (manual)

For `manual`, use separate instances for each tunnel:
- Different instances per tunnel
- Or use `iroh` or `nostr` mode for multi-session support

---

---

# Utility Commands

## generate-nostr-key

Generate a Nostr keypair for use with nostr mode:

```bash
# Save nsec to file and output npub
tunnel-rs-ice generate-nostr-key --output ./nostr.nsec

# Overwrite existing file
tunnel-rs-ice generate-nostr-key --output ./nostr.nsec --force

# Output nsec to stdout and npub to stderr (wireguard-style)
tunnel-rs-ice generate-nostr-key --output -
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

## generate-token

Generate authentication tokens for iroh mode:

```bash
# Generate a single token
tunnel-rs generate-token
# Output: ikAdvudu_ZxNXhNLCD

# Generate multiple tokens
tunnel-rs generate-token -c 5
```

Token format: `i` + 16 random chars + checksum = 18 characters total.

## generate-server-key

*For iroh mode.*

```bash
tunnel-rs generate-server-key --output ./server.key
```

## show-server-id

```bash
tunnel-rs show-server-id --secret-file ./server.key
```

## show-npub

Display the npub for an existing nsec key file:

```bash
tunnel-rs-ice show-npub --nsec-file ./nostr.nsec
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
- The EndpointId is a public key that identifies the server
- **Token Authentication (iroh mode):** Clients authenticate immediately after QUIC connection via a dedicated auth stream. Invalid tokens are rejected within 10 seconds and the connection is closed. See [Architecture: Token Authentication](docs/ARCHITECTURE.md#token-authentication-iroh-mode).
- Secret key files are created with `0600` permissions (Unix) and appropriate permissions on Windows
- Treat secret key files and auth tokens like passwords

## How It Works

### iroh Mode
1. Server creates an iroh endpoint with discovery services
2. Server publishes its address via Pkarr/DNS
3. Client resolves the server via discovery
4. QUIC connection established via iroh's NAT traversal
5. **Authentication phase:** Client opens dedicated auth stream and sends `AuthRequest` with token
6. **Server validates token immediately** (10s timeout) — invalid tokens close connection
   - *If authentication fails, the connection is closed and steps 7–9 do not occur*
7. **Source request phase:** Client opens source stream with `SourceRequest`
8. Server validates source against allowed networks and responds
9. If accepted, traffic forwarding begins


### manual Mode
1. Both sides gather ICE candidates via STUN (same socket used for data)
2. Manual exchange of offer/answer (copy-paste)
3. ICE connectivity checks probe all candidate pairs simultaneously
4. Best working path selected via ICE nomination
5. QUIC connection established over ICE socket

*Advantage: Full ICE provides reliable NAT traversal even for symmetric NATs.*

### nostr Mode (Receiver-Initiated)
1. Both peers derive deterministic transfer ID from their sorted public keys
2. Sender waits for connection requests from receivers
3. Receiver publishes connection request (ICE credentials + candidates + source) to Nostr relays
4. Sender receives request, gathers its ICE candidates, publishes offer, starts ICE immediately
5. Receiver receives offer, publishes answer (echo session_id), starts ICE immediately
6. ICE connectivity checks begin, best path selected
7. QUIC connection established over ICE socket

*Advantage: Receiver-initiated flow (like WireGuard) + automated signaling + full ICE NAT traversal.*
