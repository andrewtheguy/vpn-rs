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
- **Offline/LAN support** — ice-manual mode works without internet for local network tunneling
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
- `tunnel-rs`: iroh-only
- `tunnel-rs-ice`: manual and nostr

| Mode | NAT Traversal | Discovery | External Dependency |
|------|---------------|-----------|---------------------|
| **iroh** (recommended) | Best (relay fallback) | Automatic | iroh relay infrastructure |
| ice-nostr | STUN only | Automatic (Nostr) | Nostr relays (decentralized) |
| ice-manual | STUN only | Manual copy-paste | None |

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### When to Use Alternative Modes

Choose an alternative mode only if you have specific requirements:

- **ice-nostr**: You want decentralized signaling without depending on iroh infrastructure. Uses Nostr relays instead.
- **ice-manual**: You want complete independence from third-party services (disable STUN for fully self-contained operation), or no internet is available (offline/LAN-only). Signaling is done via manual copy-paste.

> [!NOTE]
> The `ice-nostr` and `ice-manual` modes use STUN-only NAT traversal, which may fail when both peers are behind symmetric NATs. For containerized environments (Docker, Kubernetes, cloud VMs), use `iroh` mode which includes relay fallback.

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

All modes (iroh, ice-manual, ice-nostr) work across all platforms, enabling cross-platform P2P tunneling.

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

### 1. Generate Keys (One-Time Setup)

Each peer needs their own keypair for authentication:

```bash
# On server machine
tunnel-rs generate-iroh-key --output ./server.key
# Output: EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga

# On client machine
tunnel-rs generate-iroh-key --output ./client.key
tunnel-rs show-iroh-node-id --secret-file ./client.key
# Output: 3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e
```

Exchange NodeIds between peers (server needs client's NodeId).

### 2. TCP Tunnel (e.g., SSH)

**Server** (on server — waits for client connections):
```bash
tunnel-rs server \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-clients <CLIENT_NODE_ID>
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Allowed clients: 1 NodeId(s) configured
Waiting for clients to connect...
```

**Client** (on client — requests source from server):
```bash
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

Then connect: `ssh -p 2222 user@127.0.0.1`

### 3. UDP Tunnel (e.g., WireGuard)

**Server**:
```bash
tunnel-rs server \
  --secret-file ./server.key \
  --allowed-udp 127.0.0.0/8 \
  --allowed-clients <CLIENT_NODE_ID>
```

**Client**:
```bash
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --source udp://127.0.0.1:51820 \
  --target 0.0.0.0:51820
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
| `--allowed-clients` | required | Allowed client NodeIds (repeatable). Only clients with these NodeIds can connect. |
| `--allowed-clients-file` | - | Path to file containing allowed NodeIds (one per line, # comments allowed) |
| `--max-sessions` | 100 | Maximum concurrent sessions |
| `--secret` | - | Base64-encoded secret key for persistent identity |
| `--secret-file` | - | Path to secret key file for persistent identity |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (requires `test-utils` feature) |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--socks5-proxy` | - | **(Experimental)** Tor SOCKS5 proxy for self-hosted .onion relay. **Tor-only:** requires all relay URLs to be `.onion` addresses, validates proxy is Tor at startup, cannot be used with `--dns-server`. See [Tor Hidden Service](#tor-hidden-service-no-public-ip). |

### client

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/client.toml` |

### client iroh

| Option | Default | Description |
|--------|---------|-------------|
| `--server-node-id`, `-n` | required | EndpointId of the server |
| `--source`, `-s` | required | Source address to request from server (tcp://host:port or udp://host:port) |
| `--target`, `-t` | required | Local address to listen on |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (requires `test-utils` feature) |
| `--dns-server` | public | Custom DNS server URL for peer discovery |
| `--socks5-proxy` | - | **(Experimental)** Tor SOCKS5 proxy for self-hosted .onion relay. **Tor-only:** requires all relay URLs to be `.onion` addresses, validates proxy is Tor at startup, cannot be used with `--dns-server`. See [Tor Hidden Service](#tor-hidden-service-no-public-ip). |

## Configuration Files

Use `--default-config` to load from the default location, or `-c <path>` for a custom path. Each mode has its own configuration section:
- **iroh** mode: `[iroh]` section
- **ice-manual** mode: `[ice-manual]` section
- **ice-nostr** mode: `[ice-nostr]` section

**Default locations:**
- Server: `~/.config/tunnel-rs/server.toml`
- Client: `~/.config/tunnel-rs/client.toml`

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
mode = "iroh"  # or "ice-manual", or "ice-nostr"

[iroh]
secret_file = "./server.key"
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
max_sessions = 100

# Authentication: only these clients can connect
allowed_clients = [
    "3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e",
]
# Or use: allowed_clients_file = "/etc/tunnel-rs/allowed_clients.txt"

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
mode = "iroh"  # or "ice-manual", or "ice-nostr"

[iroh]
server_node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
request_source = "tcp://127.0.0.1:22"
target = "127.0.0.1:2222"
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
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
tunnel-rs server --allowed-tcp 127.0.0.0/8 --secret-file ./server.key --allowed-clients <CLIENT_NODE_ID>
```

## Authentication

Iroh mode requires authentication using NodeId whitelisting. Only clients whose NodeIds are in the server's allowed list can connect. This leverages iroh's built-in Ed25519 identity system—each peer has a cryptographic identity, and the server validates the client's NodeId during the TLS handshake.

### Setup Workflow

1. **Generate keys for both peers:**
   ```bash
   # Server
   tunnel-rs generate-iroh-key --output ./server.key

   # Client
   tunnel-rs generate-iroh-key --output ./client.key
   ```

2. **Get the client's NodeId:**
   ```bash
   tunnel-rs show-iroh-node-id --secret-file ./client.key
   # Output: 3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e
   ```

3. **Start server with allowed clients:**
   ```bash
   tunnel-rs server \
     --secret-file ./server.key \
     --allowed-tcp 127.0.0.0/8 \
     --allowed-clients 3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e
   ```

### Multiple Clients

```bash
# Multiple --allowed-clients flags
tunnel-rs server \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-clients <ALICE_NODE_ID> \
  --allowed-clients <BOB_NODE_ID>

# Or use a file (one NodeId per line, # comments allowed)
tunnel-rs server \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-clients-file /etc/tunnel-rs/allowed_clients.txt
```

**Example `allowed_clients.txt`:**
```text
# Alice's laptop
3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e

# Bob's workstation
2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
```

### Configuration File

In `server.toml`:

```toml
[iroh]
# Inline list
allowed_clients = [
    "3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e",  # Alice
    "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga",  # Bob
]

# Or use a file
# allowed_clients_file = "/etc/tunnel-rs/allowed_clients.txt"
```

## Custom Relay Server

Use a custom relay server instead of the public iroh relay infrastructure.

> **Note:** When using `--relay-url`, you only need a custom relay server. The `--dns-server` option is **not required** — DNS discovery is only needed if you also want to avoid the public iroh DNS infrastructure (see [Self-Hosted DNS Discovery](#self-hosted-dns-discovery)).

```bash
# Both sides must use the same relay
tunnel-rs server --relay-url https://relay.example.com --allowed-tcp 127.0.0.0/8 --allowed-clients <CLIENT_NODE_ID>
tunnel-rs client --relay-url https://relay.example.com --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222

# Force relay-only (no direct P2P) - requires test-utils feature
# Build with: cargo build --features test-utils
tunnel-rs server --relay-url https://relay.example.com --relay-only --allowed-tcp 127.0.0.0/8 --allowed-clients <CLIENT_NODE_ID>
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
tunnel-rs server --dns-server https://dns.example.com/pkarr --secret-file ./server.key --allowed-tcp 127.0.0.0/8 --allowed-clients <CLIENT_NODE_ID>
tunnel-rs client --dns-server https://dns.example.com/pkarr --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
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
  --allowed-clients <CLIENT_NODE_ID>

# Client
tunnel-rs client \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --secret-file ./client.key \
  --server-node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
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
> **Alternative for signaling-only:** Use `ice-nostr` mode with self-hosted Nostr relays. Nostr relays only handle signaling (small encrypted messages), never tunnel traffic. If hole punching fails, the connection fails — no traffic is ever forwarded through the relay.

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
  --allowed-clients <CLIENT_NODE_ID>

# Client side: use --socks5-proxy to reach .onion relay (direct P2P bypasses Tor)
tunnel-rs client \
  --relay-url http://YOUR_RELAY.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --secret-file ./client.key \
  --server-node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

> **Note:** When using `--socks5-proxy`, all relay URLs must be `.onion` addresses. The proxy is validated as a real Tor proxy at startup. DNS discovery is not used with Tor — the relay handles peer discovery.

See [docs/tor-hidden-service.md](docs/tor-hidden-service.md) for complete setup guide.

---

# Alternative: ice-manual Mode

> Use this mode for: (1) complete independence from third-party services (disable STUN), or (2) offline/LAN-only operation when no internet is available. For most use cases, [iroh mode](#iroh-mode-recommended) is recommended.

Uses full ICE (Interactive Connectivity Establishment) with str0m + quinn QUIC. Signaling is done via manual copy-paste.

> **Summary:** Manual copy-paste signaling, full ICE NAT traversal via STUN, no relay fallback. See [Architecture: ice-manual Mode](docs/ARCHITECTURE.md#ice-manual-mode) for detailed diagrams.

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

- Full ICE provides reliable NAT traversal - works with most symmetric NATs
- Signaling payloads include a version number; mismatches are rejected

---

# Alternative: ice-nostr Mode

> Use this mode if you want decentralized signaling without depending on iroh infrastructure. For most use cases, [iroh mode](#iroh-mode-recommended) is recommended.

Uses full ICE with Nostr-based signaling. Instead of manual copy-paste, ICE offers/answers are exchanged automatically via Nostr relays using static keypairs (like WireGuard).

> **Summary:** Automated signaling via Nostr relays, static WireGuard-like keys, full ICE NAT traversal, no relay fallback. See [Architecture: ice-nostr Mode](docs/ARCHITECTURE.md#ice-nostr-mode) for detailed diagrams.

**Key Features:**
- **Static keys** — Persistent identity using nsec/npub keypairs (like WireGuard)
- **Automated signaling** — No copy-paste required; offers/answers exchanged via Nostr relays
- **Full ICE** — Same NAT traversal as ice-manual mode (str0m + quinn)
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
mode = "ice-nostr"

[ice-nostr]
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
- Full ICE provides reliable NAT traversal (same as custom mode)
- **Client-first protocol:** The client initiates the connection by publishing a request first; server waits for a request before publishing its offer

> [!WARNING]
> **Containerized Environments:** ice-nostr mode uses full ICE but without relay fallback. If both peers are behind restrictive NATs (common in Docker, Kubernetes, or cloud VMs), ICE connectivity may fail. For containerized deployments, consider using `iroh` mode which includes automatic relay fallback.

## Mode Capabilities

| Mode | Multi-Session | Dynamic Source | Description |
|------|---------------|----------------|-------------|
| `iroh` | **Yes** | **Yes** | Multiple receivers, receiver chooses source |
| `ice-nostr` | **Yes** | **Yes** | Multiple receivers, receiver chooses source |
| `ice-manual` | No | **Yes** | Single session, receiver chooses source |

**Multi-Session** = Multiple concurrent connections to the same sender
**Dynamic Source** = Receiver specifies which service to tunnel (like SSH `-L`)

### iroh (Multi-Session + Dynamic Source)

Server whitelists networks; clients choose which service to tunnel:

```bash
# Server: whitelist networks, clients choose destination
tunnel-rs server --allowed-tcp 127.0.0.0/8 --max-sessions 100 --allowed-clients <CLIENT1_NODE_ID> --allowed-clients <CLIENT2_NODE_ID>

# Client 1: tunnel to SSH
tunnel-rs client --secret-file ./client1.key --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222

# Client 2: tunnel to web server (same server!)
tunnel-rs client --secret-file ./client2.key --server-node-id <ID> --source tcp://127.0.0.1:80 --target 127.0.0.1:8080
```

### ice-nostr (Multi-Session + Dynamic Source)

Server whitelists networks; clients choose which service to tunnel:

```bash
# Server: whitelist networks, clients choose destination
tunnel-rs-ice server nostr --allowed-tcp 127.0.0.0/8 --nsec-file ./server.nsec --peer-npub <NPUB> --max-sessions 5

# Client 1: tunnel to SSH
tunnel-rs-ice client nostr --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 ...

# Client 2: tunnel to web server (same server!)
tunnel-rs-ice client nostr --source tcp://127.0.0.1:80 --target 127.0.0.1:8080 ...
```

### Single-Session Mode (ice-manual)

For `ice-manual`, use separate instances for each tunnel:
- Different instances per tunnel
- Or use `iroh` or `ice-nostr` mode for multi-session support

---

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

Generate a Nostr keypair for use with ice-nostr mode:

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

## generate-iroh-key

*For iroh mode.*

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
- The EndpointId is a public key that identifies the sender
- **NodeId Whitelisting (iroh mode):** Server rejects clients not in the `--allowed-clients` list. Authentication uses iroh's built-in Ed25519 identity—the NodeId is verified during the TLS handshake.
- Secret key files are created with `0600` permissions (Unix) and appropriate permissions on Windows
- Treat secret key files like SSH private keys

## How It Works

### iroh Mode
1. Sender creates an iroh endpoint with discovery services
2. Sender publishes its address via Pkarr/DNS
3. Receiver resolves the sender via discovery
4. Connection established via iroh's NAT traversal (TLS handshake verifies NodeId)
5. **Sender validates client NodeId against allowed clients list**
6. Receiver sends `SourceRequest` with desired source address
7. Sender validates against allowed networks and responds
8. If accepted, traffic forwarding begins


### ice-manual Mode
1. Both sides gather ICE candidates via STUN (same socket used for data)
2. Manual exchange of offer/answer (copy-paste)
3. ICE connectivity checks probe all candidate pairs simultaneously
4. Best working path selected via ICE nomination
5. QUIC connection established over ICE socket

*Advantage: Full ICE provides reliable NAT traversal even for symmetric NATs.*

### ice-nostr Mode (Receiver-Initiated)
1. Both peers derive deterministic transfer ID from their sorted public keys
2. Sender waits for connection requests from receivers
3. Receiver publishes connection request with desired source to Nostr relays
4. Sender receives request, gathers ICE candidates, publishes offer
5. Receiver receives offer, gathers candidates, publishes answer
6. ICE connectivity checks begin, best path selected
7. QUIC connection established over ICE socket

*Advantage: Receiver-initiated flow (like WireGuard) + automated signaling + full ICE NAT traversal.*
