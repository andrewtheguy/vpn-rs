# tunnel-rs

**Cross-platform Secure Peer-to-Peer TCP/UDP port forwarding and VPN with NAT traversal.**

Tunnel-rs enables you to forward TCP and UDP traffic—or tunnel entire networks via VPN mode—between machines without requiring public IP addresses, open ports, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

> [!IMPORTANT]
> **Project Goal:** This tool provides a convenient way to connect to different networks for **development or homelab purposes** without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale.

> [!TIP]
> **Looking for a GUI?** Check out [tunnel-rs-manager](https://github.com/andrewtheguy/tunnel-rs-manager), a companion desktop application for managing tunnel-rs connections.

**Port Forwarding Features:**
- **Full TCP and UDP support** — Seamlessly tunnel any TCP or UDP traffic
- **Cross-platform** — Works on Linux, macOS, and Windows
- **No root required** — Runs as unprivileged user
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with multiple strategies (relay fallback, STUN, full ICE)
- **Flexible signaling** — Automated discovery (iroh), decentralized (Nostr), or manual exchange
- **Offline/LAN support** — manual mode works without internet

**VPN Mode Features**
- **Direct IP-over-QUIC** — High performance direct tunneling with TLS 1.3 encryption
- **Automatic IP assignment** — No manual keypair or IP management

**Common Features:**
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching
 

**Common Use Cases:**
- **SSH access** to machines behind NAT/firewalls
- **UDP Tunneling** — A key advantage over AWS SSM and `kubectl port-forward` which typically lack UDP support. Ideal for:
  - WireGuard/OpenVPN over P2P
  - Game servers (Valheim, Minecraft Bedrock, etc.)
  - VoIP applications and WebRTC
  - Accessing UDP services in Kubernetes (bypassing the [7+ year old limitation in `kubectl`](https://github.com/kubernetes/kubernetes/issues/47862) without complex sidecar workarounds)
- **Simpler Alternative to SSM For Staging Environment Access Purposes** — Great for ad-hoc access without configuring AWS agents or IAM users. **Note:** Not intended for production; it is not battle-tested for enterprise use and lacks integration with cloud security policies (IAM, auditing).
- **Remote Desktop** access (RDP/VNC over TCP) without port forwarding
- **Secure Service Exposure** (HTTP servers, databases, etc.) without public infrastructure
- **Development and Testing** of TCP/UDP services across network boundaries
- **Homelab Networking** — Connecting distributed homelab nodes or accessing local services remotely without complex VPN setups or public IP requirements
- **Cross-platform Tunneling** for both TCP and UDP workflows (including Windows endpoints)

## Which Should I Use?

| Need | Recommended | Binary |
|------|-------------|--------|
| Forward a specific port (SSH, HTTP, database) | Port Forwarding (iroh mode) | `tunnel-rs` |
| Access UDP services (WireGuard, DNS, game servers) | Port Forwarding (iroh mode) | `tunnel-rs` |
| Alternative to `kubectl port-forward` with UDP support | Port Forwarding (iroh mode) | `tunnel-rs` |
| No root/admin privileges available | Port Forwarding (iroh mode) | `tunnel-rs` |
| Route all traffic through tunnel | VPN Mode (requires root/admin) | `tunnel-rs-vpn` |
| Access an entire remote subnet | VPN Mode (requires root/admin) | `tunnel-rs-vpn` |

### Alternative Modes (Niche Use Cases)

| Need | Recommended | Binary |
|------|-------------|--------|
| Decentralized signaling (no iroh dependency) | Port Forwarding (nostr mode) | `tunnel-rs-ice` |
| Offline/LAN-only operation | Port Forwarding (manual mode) | `tunnel-rs-ice` |

> See [docs/ALTERNATIVE-MODES.md](docs/ALTERNATIVE-MODES.md) for detailed documentation on manual and nostr modes.

## Overview

tunnel-rs provides multiple modes for establishing tunnels. **Use `iroh` mode** for most use cases — it provides the best NAT traversal with relay fallback, automatic discovery, and client authentication.

**Identity reuse note:** Automatic peer discovery uses simple, shareable identities. For **VPN (iroh)**, the same client identity can be reused across multiple devices without conflicts because sessions are keyed by `(EndpointId, device_id)`, which is convenient for staging/homelab setups. For **port forwarding (iroh/nostr/manual)**, multiple sessions on the same device with one identity are supported, but reusing a single identity concurrently across multiple devices can cause conflicts.

**Binary layout:**
- `tunnel-rs`: Port forwarding with iroh mode
- `tunnel-rs-ice`: Port forwarding with manual and nostr modes
- `tunnel-rs-vpn`: VPN mode (iroh)
- `tunnel-rs-vpn-ice`: VPN mode (Nostr/ICE, **experimental**)

### Port Forwarding Modes

| Mode | NAT Traversal | Discovery | External Dependency |
|------|---------------|-----------|---------------------|
| **iroh** (recommended) | Best (relay fallback) | Automatic | iroh relay infrastructure |
| nostr (alternative mode) | STUN only | Automatic (Nostr) | Nostr relays (decentralized) |
| manual (alternative mode) | STUN only | Manual copy-paste | None |

### VPN Mode

| Mode | NAT Traversal | Discovery | Platform | External Dependency |
|------|---------------|-----------|----------|---------------------|
| **tunnel-rs-vpn** (iroh) | Best (relay fallback) | Automatic | Linux/macOS/Windows | iroh relay infrastructure |
| tunnel-rs-vpn-ice (alternative mode, experimental) | STUN only | Nostr | Linux/macOS/Windows | Nostr relays (decentralized) |

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

You only need the binary in your PATH; no runtime dependencies or package managers are required.

### Port Forwarding (`tunnel-rs`)

**Linux & macOS:**
```bash
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash
```

**Windows:**
```powershell
irm https://andrewtheguy.github.io/tunnel-rs/install.ps1 | iex
```

This installs `tunnel-rs` (iroh mode). For nostr/manual ICE modes, download `tunnel-rs-ice` separately from [GitHub releases](https://github.com/andrewtheguy/tunnel-rs/releases) or build from source.

<details>
<summary>Advanced installation options</summary>

Install with custom release tag:
```bash
# Linux/macOS
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash -s <RELEASE_TAG>
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install.ps1))) <RELEASE_TAG>
```

By default the installer pulls the latest **stable** release. Use `--prerelease` for the newest prerelease, or pass an explicit tag to pin to a specific build:

```bash
# Linux/macOS - latest prerelease
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash -s -- --prerelease

# Linux/macOS - pin to specific tag
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install.sh | bash -s 20251210172710
```

```powershell
# Windows - latest prerelease
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install.ps1))) -PreRelease

# Windows - pin to specific tag
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install.ps1))) 20251210172710
```

</details>

### VPN Mode (`tunnel-rs-vpn`)

> VPN mode requires root/admin privileges to create TUN devices and configure routes.

**Linux & macOS:**
```bash
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install-vpn.sh | sudo bash
```

**Windows:**
```powershell
irm https://andrewtheguy.github.io/tunnel-rs/install-vpn.ps1 | iex
```
> [!NOTE]
> **Windows Requirements:** Running `tunnel-rs-vpn.exe` requires the **WinTun driver** and **Administrator privileges** for TUN device creation.
>
> 1. Download WinTun driver from https://www.wintun.net/ (official WireGuard project)
> 2. Extract the zip and copy `wintun/bin/amd64/wintun.dll` to:
>    - The same directory as `tunnel-rs-vpn.exe` (default: `%LOCALAPPDATA%\Programs\tunnel-rs\`), OR
>    - Any directory in the system PATH
> 3. **Run `tunnel-rs-vpn.exe` as Administrator:** Right-click PowerShell or Command Prompt → "Run as administrator", then execute the VPN command
>
> **Troubleshooting:** If you see `Failed to create TUN device: LoadLibraryExW failed`, the `wintun.dll` is missing or not in a valid DLL search path.

<details>
<summary>Advanced installation options</summary>

Install with custom release tag:
```bash
# Linux/macOS
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install-vpn.sh | sudo bash -s <RELEASE_TAG>
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install-vpn.ps1))) <RELEASE_TAG>
```

Latest prerelease:
```bash
# Linux/macOS
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install-vpn.sh | sudo bash -s -- --prerelease
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install-vpn.ps1))) -PreRelease
```

</details>

### From Source

```bash
# Port forwarding (iroh mode)
cargo install --path . -p tunnel-rs

# Port forwarding (nostr/manual modes)
cargo install --path . -p tunnel-rs-ice

# VPN mode (requires root/admin to run)
cargo install --path . -p tunnel-rs-vpn
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

# Common Configuration

These settings apply to both Port Forwarding (`tunnel-rs`) and VPN (`tunnel-rs-vpn`) modes using iroh.

## Persistent Server Identity

By default, a new EndpointId is generated each run. For long-running setups, use persistent identity for the **server**:

```bash
# Generate key and output EndpointId
tunnel-rs generate-server-key --output ./server.key

# Show EndpointId for existing key
tunnel-rs show-server-id --secret-file ./server.key
```

Then reference the key in your server config or CLI:

**CLI** (both modes):
```bash
# Port forwarding
tunnel-rs server --secret-file ./server.key --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"

# VPN
sudo tunnel-rs-vpn server --secret-file ./server.key -c vpn_server.toml
```

**Config file** (both modes - in `server.toml` or `vpn_server.toml`):
```toml
[iroh]
secret_file = "./server.key"
```

> **Note:** Clients use ephemeral identities by default. Only the server needs a persistent key to maintain a stable EndpointId that clients can connect to.

## Authentication

Iroh mode requires authentication using pre-shared tokens. Clients must provide a valid token to connect.

**Token Format:**
- Exactly 18 characters
- Starts with `i` (for iroh)
- Ends with a [Luhn mod N](https://en.wikipedia.org/wiki/Luhn_mod_N_algorithm) checksum character
- Middle 16 characters: `A-Za-z0-9` and `-` `_` `.` (period is valid but rare in generated tokens)

The checksum detects all single-character typos and adjacent transpositions (same algorithm family as credit cards).

Generate tokens with: `tunnel-rs generate-token`

### Token Management

```bash
# Generate a valid token
AUTH_TOKEN=$(tunnel-rs generate-token)
echo $AUTH_TOKEN  # Share this with authorized clients

# Generate multiple tokens
tunnel-rs generate-token -c 5
```

### Multiple Tokens (Server)

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
iXXXXXXXXXXXXXXXXX

# Bob's token
iYYYYYYYYYYYYYYYYY
```

### Configuration File

**Server** (`server.toml` or `vpn_server.toml`):
```toml
[iroh]
auth_tokens = [
    "iXXXXXXXXXXXXXXXXX",  # Alice
    "iYYYYYYYYYYYYYYYYY",  # Bob
]
# Or use: auth_tokens_file = "/etc/tunnel-rs/auth_tokens.txt"
```

**Client** (`client.toml` or CLI):
```toml
[iroh]
auth_token = "iXXXXXXXXXXXXXXXXX"
# Or use: auth_token_file = "~/.config/tunnel-rs/token.txt"
```

## Self-Hosting

For custom relay servers, DNS discovery, or fully independent operation without public infrastructure, see [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

---

# Port Forwarding

Forward specific TCP/UDP ports between machines. Cross-platform (Linux, macOS, Windows), no root required.

## iroh Mode (Recommended)

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

### Full Network Tunneling (VPN Mode)

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| System Network  |  IP    | client          |  iroh  | server          |  IP    | Target Network  |
| Stack (tun0)    |<------>| (frame/unframe) |<======>| (frame/unframe) |<------>| (LAN/Internet)  |
|                 |        |                 |  QUIC  |                 |        |                 |
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

### 3. UDP Tunnel (e.g., WireGuard/Game/DNS)

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
| `--dns-server` | public | Custom DNS server URL, or "none" to disable DNS discovery |

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
| `--dns-server` | public | Custom DNS server URL, or "none" to disable DNS discovery |

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
    "iXXXXXXXXXXXXXXXXX",
    "iYYYYYYYYYYYYYYYYY",
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
auth_token = "iXXXXXXXXXXXXXXXXX"
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

---

# VPN Mode

Full network tunneling with Direct QUIC encryption. Requires root/admin privileges.

Native direct TUN-based VPN mode for full network tunneling. Unlike port forwarding modes, VPN mode creates a TUN device and routes IP traffic directly through the encrypted Iroh QUIC connection, eliminating double encryption overhead.

> **Note:** VPN mode requires root/admin privileges to create TUN devices and configure routes.

<details>
<summary><b>Windows Setup: WinTun Driver Required</b></summary>

Windows VPN mode requires the WinTun driver DLL from https://www.wintun.net/ (official WireGuard project):

1. Download and extract the zip file
2. Copy `wintun/bin/amd64/wintun.dll` to the same directory as `tunnel-rs-vpn.exe` (or any directory in the system PATH)
3. Run as Administrator

If you see `Failed to create TUN device: LoadLibraryExW failed`, the DLL is missing or not in a valid DLL search path.

</details>

> **Similar Project:** This VPN mode is conceptually similar to [quincy](https://github.com/quincy-rs/quincy), a VPN implementation using the QUIC protocol. The key difference is that tunnel-rs uses iroh's NAT traversal infrastructure, so **no open port is required on the server** — connections work through NAT/firewalls without manual port forwarding.

## Architecture

```
Client                                     Server
┌─────────────────────┐                   ┌─────────────────────┐
│  Applications       │                   │  Target Network     │
│        ↓            │                   │        ↑            │
│  [tun0: 10.0.0.2]   │                   │  [tun0: 10.0.0.1]   │
│        ↓            │                   │        ↑            │
│  Tunnel (VPN)       │                   │  Tunnel (VPN)       │
│        ↓            │                   │        ↑            │
│  iroh (transport)   │ ════════════════► │  iroh (transport)   │
└─────────────────────┘   NAT traversal   └─────────────────────┘
```

- Creates a virtual network interface (TUN device)
- Assigns VPN IP addresses automatically (no keypair management)
- Routes entire IP subnets, not just individual ports
- **Direct IP-over-QUIC** tunneling (TLS 1.3 encryption)
- No double encryption (removes WireGuard overhead)

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

### 2. Create Server Config

Create `vpn_server.toml` (or copy from `vpn_server.toml.example`):

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]  # Replace with token from step 1
```

Notes:
- The IPv4 VPN network is optional; you can run IPv6-only by setting `network6 = "fd00::/64"` instead (needs `dns_server = "none"` or your custom iroh DNS server that supports IPv6 because the default dns.iroh.link server does not support IPv6). **IPv6-only mode is experimental.**
- Preliminary NAT64 support is available but **experimental** (not fully tested, may have stability or compatibility limitations).

### 3. Start VPN Server

```bash
sudo tunnel-rs-vpn server -c vpn_server.toml
```

Output:
```
VPN Server Node ID: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Clients connect with: tunnel-rs-vpn client --server-node-id <ID> --auth-token <TOKEN>
```

### 4. Connect VPN Client

```bash
sudo tunnel-rs-vpn client \
  --server-node-id <SERVER_NODE_ID> \
  --auth-token "$AUTH_TOKEN"
```

The client will:
1. Connect to the server via iroh (NAT traversal)
2. Receive an assigned IP (e.g., 10.0.0.2)
3. Create a TUN device and configure routes

### 5. Verify Connection

```bash
# Check assigned IP
ip addr show tun0  # Linux
ifconfig utun9     # macOS

# Ping the server
ping 10.0.0.1
```

## CLI Options

### server (tunnel-rs-vpn)

VPN server requires a config file. Use `-c <FILE>` or `--default-config` for `~/.config/tunnel-rs/vpn_server.toml`.

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to config file (required unless --default-config) |
| `--default-config` | Use `~/.config/tunnel-rs/vpn_server.toml` |

See [`vpn_server.toml.example`](vpn_server.toml.example) for all available configuration options.

### client (tunnel-rs-vpn)

| Option | Default | Description |
|--------|---------|-------------|
| `--server-node-id`, `-n` | required | EndpointId of the VPN server |
| `--mtu` | 1420 | MTU for VPN packets |
| `--keepalive-secs` | 25 | Keepalive interval |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--dns-server` | public | Custom DNS server URL, or "none" to disable DNS discovery |
| `--auth-token` | required | Authentication token |
| `--auth-token-file` | - | Path to file containing token |
| `--route` | - | Additional CIDRs to route through VPN (repeatable) |
| `--auto-reconnect` | true | Enable auto-reconnect on connection loss |
| `--no-auto-reconnect` | - | Disable auto-reconnect (exit on first disconnection) |
| `--max-reconnect-attempts` | unlimited | Maximum reconnect attempts (unlimited if not specified) |

## Split Tunneling

By default, only traffic to the VPN network (e.g., 10.0.0.0/24) is routed through the tunnel. Use `--route` to add additional networks:

```bash
sudo tunnel-rs-vpn client \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

## How It Works

1. **Signaling via iroh**: Client connects to server using iroh for peer discovery and NAT traversal
2. **Handshake**: Client and server exchange device IDs and session parameters (TLS 1.3 secured)
3. **IP Assignment**: Server assigns client an IP from the VPN network pool
4. **TUN Device**: Both sides create TUN devices for packet capture
5. **Packet Flow**: IP packets are framed and sent directly over the encrypted Iroh QUIC stream

**Advantages over traditional WireGuard:**
| Feature | WireGuard | tunnel-rs VPN |
|---------|-----------|---------------|
| Identity | Static keypair per device | Ephemeral `device_id` (per session) |
| Config conflict | Same keypair = conflict | Each session unique via `device_id` |
| NAT traversal | Manual endpoint config | Automatic via iroh |
| IP assignment | Static in config | Dynamic from server |

### About `device_id`

The `device_id` is a random 64-bit integer generated fresh each time the VPN client starts (ephemeral per session). It is used purely for **session tracking** on the server, not for security or access control.

- **Format**: Random `u64` (displayed as 16 hex characters in logs, e.g., `a1b2c3d4e5f67890`)
- **Lifecycle**: Generated at client startup using CSPRNG; not persisted across restarts
- **Purpose**: Allows multiple VPN sessions from the same iroh endpoint (the server keys clients by `(EndpointId, device_id)`)
- **Security**: Authentication relies on iroh's cryptographic EndpointId + auth tokens, not on device_id unpredictability

This differs from WireGuard where a static public key identifies each device and conflicts arise if the same key is used from multiple locations.

## Single Instance Lock

Only one VPN client can run at a time per machine. This prevents routing conflicts and TUN device issues. The lock is automatically released when the client exits.

---

# VPN Mode (Nostr / ICE, Experimental)

For completely decentralized VPN without iroh infrastructure dependencies, use `tunnel-rs-vpn-ice`. This **experimental** mode uses Nostr relays for signaling and ICE (STUN) for NAT traversal.

> [!WARNING]
> **NAT Traversal Limitation:** This mode uses STUN-only NAT traversal. If both peers are behind symmetric NATs (common in enterprise/cellular networks), the connection will fail. Use `tunnel-rs-vpn` (iroh mode) for reliable connectivity with relay fallback.

## Quick Start

### 1. Installation

Download `tunnel-rs-vpn-ice` from releases or build from source:
```bash
cargo install --path . -p tunnel-rs-vpn-ice
```

> [!NOTE]
> **Windows requirements:** `tunnel-rs-vpn-ice` requires the WinTun driver on Windows. Install/enable the WinTun driver as Administrator, ensure the driver is loaded before starting `tunnel-rs-vpn-ice` (server or client), and run with admin privileges to create the TUN device. The `vpn_server_ice.toml` and `vpn_client_ice.toml` examples assume the driver is present.

### 2. Generate Nostr Keys

Both server and client need a Nostr identity (nsec/npub).

```bash
# Generate server key
tunnel-rs-vpn-ice generate-nostr-key > server_nsec.txt
tunnel-rs-vpn-ice show-pubkey server_nsec.txt
# Output: npub1server... (Share this with client)

# Generate client key
tunnel-rs-vpn-ice generate-nostr-key > client_nsec.txt
tunnel-rs-vpn-ice show-pubkey client_nsec.txt
# Output: npub1client... (Add this to server config whitelist)
```

### 3. Server Configuration

Create `vpn_server_ice.toml`:
```toml
network = "10.0.0.0/24"
server_ip = "10.0.0.1"
nsec_file = "server_nsec.txt"

# Authorized client npub
peer_npub = "npub1client..."
```

Start server:
```bash
sudo tunnel-rs-vpn-ice server -c vpn_server_ice.toml
```

### 4. Client Configuration

Create `vpn_client_ice.toml`:
```toml
nsec_file = "client_nsec.txt"
peer_npub = "npub1server..." # Server's npub
```

Start client:
```bash
sudo tunnel-rs-vpn-ice client -c vpn_client_ice.toml
```

**See [`vpn_server_ice.toml.example`](vpn_server_ice.toml.example) and [`vpn_client_ice.toml.example`](vpn_client_ice.toml.example) for full configuration options.**

## CLI Options

### server (tunnel-rs-vpn-ice)

VPN ICE server requires a config file. Use `-c <FILE>` or `--default-config` for `~/.config/tunnel-rs/vpn_server_ice.toml`.

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to config file (required unless --default-config) |
| `--default-config` | Use `~/.config/tunnel-rs/vpn_server_ice.toml` |

**Not supported via CLI (configure in `vpn_server_ice.toml`):** `network`, `network6`, `server_ip`, `server_ip6`, `mtu`, `max_clients`, `nsec`/`nsec_file`, `peer_npub`, `relays`, `stun_servers`.

### client (tunnel-rs-vpn-ice)

| Option | Default | Description |
|--------|---------|-------------|
| `-c, --config <FILE>` | required unless `--default-config` | Path to config file |
| `--default-config` | `~/.config/tunnel-rs/vpn_client_ice.toml` | Use default config path |
| `--nsec` | required unless `--nsec-file` | Nostr private key (nsec format) |
| `--nsec-file` | - | Path to file containing nsec |
| `--peer-npub` | required | Server's Nostr public key (npub format) |
| `--relay` | - | Nostr relay URL(s), repeatable (defaults to config if set) |
| `--stun-server` | `stun.l.google.com:19302`, `stun1.l.google.com:19302` | STUN server(s), repeatable (defaults to config if set) |
| `--mtu` | 1420 | MTU for VPN packets |
| `--route` | required (at least one route/route6) | IPv4 routes to tunnel (repeatable) |
| `--route6` | required (at least one route/route6) | IPv6 routes to tunnel (repeatable) |

**Not supported in vpn-ice (iroh-only features):** `--keepalive-secs`, `--auth-token`, `--auth-token-file`, `--auto-reconnect`, `--no-auto-reconnect`, `--max-reconnect-attempts`, `--dns-server`.

---

# Utility Commands

## generate-token

Generate authentication tokens for iroh mode:

```bash
# Generate a single token
tunnel-rs generate-token
# Output: i<random-16-chars><checksum>

# Generate multiple tokens
tunnel-rs generate-token -c 5
```

Token format: `i` + 16 random chars + Luhn mod N checksum = 18 characters total.

## generate-server-key

*For iroh mode.*

```bash
tunnel-rs generate-server-key --output ./server.key
```

## show-server-id

```bash
tunnel-rs show-server-id --secret-file ./server.key
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

> For manual and nostr mode details, see [docs/ALTERNATIVE-MODES.md](docs/ALTERNATIVE-MODES.md).
