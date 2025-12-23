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
| **iroh-default** | Automatic (Pkarr/DNS/mDNS) | Relay fallback | TCP, UDP | Persistent, always-on tunnels |
| **iroh-manual** | Manual copy-paste | STUN heuristic | TCP, UDP | Serverless, simple NATs |
| **custom** | Manual copy-paste | Full ICE | TCP, UDP | Best NAT compatibility |
| **nostr** | Nostr relays | Full ICE | TCP, UDP | Automated signaling, static keys |

### Choosing a Serverless Mode

The `iroh-manual`, `custom`, and `nostr` modes don't require iroh discovery/relay infrastructure:

| Feature | iroh-manual | custom | nostr |
|---------|-------------|--------|-------|
| Signaling | Manual copy-paste | Manual copy-paste | Nostr relays (automated) |
| NAT traversal | STUN heuristic | Full ICE | Full ICE |
| Symmetric NAT | May fail | Best-effort | Best-effort |
| Keys | Ephemeral | Ephemeral | Static (WireGuard-like) |
| QUIC stack | iroh | str0m + quinn | str0m + quinn |

**Recommendation:** Use `nostr` mode for automated signaling with persistent identity, or `custom` mode for best NAT traversal without external dependencies.

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

All four modes (iroh-default, iroh-manual, custom, nostr) work across all platforms, enabling cross-platform P2P tunneling.

### Docker & Kubernetes

Container images are available at `ghcr.io/andrewtheguy/tunnel-rs:latest`.

Access services running in Docker or Kubernetes remotely — without opening ports, configuring ingress, or requiring `kubectl`. See [examples/](examples/) for Docker Compose and Kubernetes configurations.

---

# iroh-default Mode

Uses iroh's P2P network for automatic peer discovery and NAT traversal with relay fallback.

**Note:** While discovery and relay are fully automatic, peers still need to exchange the sender's **EndpointId** to initiate the connection. Optional settings like relay URLs and DNS servers can also be customized per connection.

## Architecture

### TCP Tunneling

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | receiver        |  iroh  | sender          |  TCP   | SSH Server      |
|                 |<------>| (local:2222)    |<======>|                 |<------>| (local:22)      |
|                 |        |                 |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
     Client Side                                            Server Side
```

### UDP Tunneling

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| WireGuard       |  UDP   | receiver        |  iroh  | sender          |  UDP   | WireGuard       |
| Client          |<------>| (local:51820)   |<======>|                 |<------>| Server          |
|                 |        |                 |  QUIC  |                 |        | (local:51820)   |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
     Client Side                                            Server Side
```

## Quick Start

### TCP Tunnel (e.g., SSH)

**Sender** (on server with SSH):
```bash
tunnel-rs sender iroh-default --source tcp://127.0.0.1:22
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Waiting for receiver to connect...
```

**Receiver** (on client):
```bash
tunnel-rs receiver iroh-default --node-id <ENDPOINT_ID> --target tcp://127.0.0.1:2222
```

Then connect: `ssh -p 2222 user@127.0.0.1`

### UDP Tunnel (e.g., WireGuard)

**Sender**:
```bash
tunnel-rs sender iroh-default --source udp://127.0.0.1:51820
```

**Receiver**:
```bash
tunnel-rs receiver iroh-default --node-id <ENDPOINT_ID> --target udp://0.0.0.0:51820
```

## CLI Options

### sender

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/sender.toml` |

### sender iroh-default

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source address to forward traffic to (hostname allowed) |
| `--secret-file` | - | Path to secret key file for persistent identity |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay |
| `--dns-server` | public | Custom DNS server URL for peer discovery |

### receiver

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/tunnel-rs/receiver.toml` |

### receiver iroh-default

| Option | Default | Description |
|--------|---------|-------------|
| `--node-id`, `-n` | required | EndpointId of the sender |
| `--target`, `-t` | required | Local address to listen on |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay |
| `--dns-server` | public | Custom DNS server URL for peer discovery |

## Configuration Files

Use `--default-config` to load from the default location, or `-c <path>` for a custom path. Each mode has its own section (`[iroh-default]`, `[iroh-manual]`, `[custom]`, `[nostr]`).

**Default locations:**
- Sender: `~/.config/tunnel-rs/sender.toml`
- Receiver: `~/.config/tunnel-rs/receiver.toml`

### Sender Config Example

```toml
# Example sender configuration (iroh-default mode)

# Required: validates config matches CLI command
role = "sender"
mode = "iroh-default"  # or "iroh-manual", "custom", or "nostr"

# Shared options
source = "tcp://127.0.0.1:22"

[iroh-default]
secret_file = "./sender.key"
relay_urls = ["https://relay.example.com"]
relay_only = false
dns_server = "https://dns.example.com/pkarr"
```

> [!NOTE]
> See [`sender.toml.example`](sender.toml.example) for configuration options for other modes and all available options for each mode.

```bash
# Load from default location (mode inferred from config)
tunnel-rs sender --default-config

# Load from custom path
tunnel-rs sender -c ./my-sender.toml
```

### Receiver Config Example

```toml
# Example receiver configuration (iroh-default mode)

# Required: validates config matches CLI command
role = "receiver"
mode = "iroh-default"  # or "iroh-manual", "custom", or "nostr"

# Shared options
target = "tcp://127.0.0.1:2222"

[iroh-default]
node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
relay_urls = ["https://relay.example.com"]
relay_only = false
dns_server = "https://dns.example.com/pkarr"
```

> [!NOTE]
> See [`receiver.toml.example`](receiver.toml.example) for configuration options for other modes and all available options for each mode.

```bash
# Load from default location (mode inferred from config)
tunnel-rs receiver --default-config

# Load from custom path
tunnel-rs receiver -c ./my-receiver.toml
```

> [!NOTE]
> See [`receiver.toml.example`](receiver.toml.example) for comprehensive configuration examples showing all available options for each mode.

## Persistent Identity

By default, a new EndpointId is generated each run. For long-running setups, use persistent identity:

```bash
# Generate key and output EndpointId
tunnel-rs generate-iroh-key --output ./sender.key

# Show EndpointId for existing key
tunnel-rs show-iroh-node-id --secret-file ./sender.key
```

Then use the key for the sender:

```bash
tunnel-rs sender iroh-default --source tcp://127.0.0.1:22 --secret-file ./sender.key
```

## Custom Relay Server

```bash
# Both sides must use the same relay
tunnel-rs sender iroh-default --relay-url https://relay.example.com --source tcp://127.0.0.1:22
tunnel-rs receiver iroh-default --relay-url https://relay.example.com --node-id <ID> --target tcp://127.0.0.1:2222

# Force relay-only (no direct P2P)
tunnel-rs sender iroh-default --relay-url https://relay.example.com --relay-only --source tcp://127.0.0.1:22
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
tunnel-rs sender iroh-default --dns-server https://dns.example.com/pkarr --secret-file ./sender.key
tunnel-rs receiver iroh-default --dns-server https://dns.example.com/pkarr --node-id <ID> --target tcp://127.0.0.1:2222
```

---

# iroh-manual Mode

Uses iroh's QUIC transport with manual copy-paste signaling. No discovery servers or relay infrastructure needed, but STUN is used by default.

**NAT Traversal:** Uses STUN to discover public addresses and bidirectional connection racing. Works with most NATs but may fail on symmetric NATs. For difficult NAT scenarios, use [Custom Mode](#custom-mode) which has full ICE support.

## Quick Start

1. **Sender** starts and outputs an offer:
   ```bash
   tunnel-rs sender iroh-manual --source tcp://127.0.0.1:22
   ```

   Copy the `-----BEGIN TUNNEL-RS IROH OFFER-----` block.

2. **Receiver** starts and pastes the offer:
   ```bash
   tunnel-rs receiver iroh-manual --target tcp://127.0.0.1:2222
   ```

   Paste the offer, then copy the `-----BEGIN TUNNEL-RS IROH ANSWER-----` block.

3. **Sender** receives the answer:

   Paste the answer into the sender terminal.

4. **Connect**:
   ```bash
   ssh -p 2222 user@127.0.0.1
   ```

## CLI Options

### sender iroh-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source address to forward traffic to (hostname allowed) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

### receiver iroh-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--target`, `-t` | required | Local address to listen on |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

Note: Config file options (`-c`, `--default-config`) are at the `sender`/`receiver` command level. See [Configuration Files](#configuration-files) above.

## Serverless Manual Mode (No STUN)

If you want **zero external infrastructure**, you can run manual modes without any STUN servers. This only works reliably when both peers are on public IPs or permissive NATs. Disabling STUN reduces NAT hole‑punching success.

If your goal is simply to avoid self‑hosting or depending on smaller/less‑reliable infra (e.g., iroh relay/discovery), you do **not** need `--no-stun`, public STUN servers (like Google's) are widely available and help NAT traversal without requiring you to run anything yourself.

Use `--no-stun` on the CLI, or set `stun_servers = []` in your config. If you omit STUN entirely (no config and no CLI), tunnel-rs uses its default public STUN list.

Example (CLI only):
```bash
tunnel-rs sender iroh-manual --no-stun --source tcp://127.0.0.1:22
```

## UDP Example

All modes support TCP and UDP tunneling; example below uses UDP:

```bash
# Sender
tunnel-rs sender iroh-manual --source udp://127.0.0.1:51820

# Receiver
tunnel-rs receiver iroh-manual --target udp://0.0.0.0:51820
```

---

# Custom Mode

Uses full ICE (Interactive Connectivity Establishment) with str0m + quinn QUIC.

**NAT Traversal:** Full ICE implementation with STUN candidate gathering and connectivity checks. This provides the best NAT traversal success rate, including support for symmetric NATs that fail with simpler STUN-only approaches.

## Architecture

```
+-----------------+        +-----------------+                    +-----------------+        +-----------------+
| SSH Client      |  TCP   | receiver        |  ICE/QUIC          | sender          |  TCP   | SSH Server      |
|                 |<------>| (local:2222)    |<===================|                 |<------>| (local:22)      |
|                 |        |                 |  (copy-paste)      |                 |        |                 |
+-----------------+        +-----------------+                    +-----------------+        +-----------------+
     Client Side                                                        Server Side
```

## Quick Start

1. **Sender** starts and outputs an offer:
   ```bash
   tunnel-rs sender custom --source tcp://127.0.0.1:22
   ```

   Copy the `-----BEGIN TUNNEL-RS MANUAL OFFER-----` block.

2. **Receiver** starts and pastes the offer:
   ```bash
   tunnel-rs receiver custom --target tcp://127.0.0.1:2222
   ```

   Paste the offer, then copy the `-----BEGIN TUNNEL-RS MANUAL ANSWER-----` block.

3. **Sender** receives the answer:

   Paste the answer into the sender terminal.

4. **Connect**:
   ```bash
   ssh -p 2222 user@127.0.0.1
   ```

## UDP Tunnel (e.g., WireGuard)

```bash
# Sender
tunnel-rs sender custom --source udp://127.0.0.1:51820

# Receiver
tunnel-rs receiver custom --target udp://0.0.0.0:51820
```

## CLI Options

### sender custom

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source address to forward traffic to (hostname allowed) |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

### receiver custom

| Option | Default | Description |
|--------|---------|-------------|
| `--target`, `-t` | required | Local address to listen on |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN (no external infrastructure, CLI only) |

Note: Config file options (`-c`, `--default-config`) are at the `sender`/`receiver` command level. See [Configuration Files](#configuration-files) above.

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
# On sender machine
tunnel-rs generate-nostr-key --output ./sender.nsec
# Output (stdout): npub1sender...

# On receiver machine
tunnel-rs generate-nostr-key --output ./receiver.nsec
# Output (stdout): npub1receiver...
```

Exchange public keys (npub) between peers.

### 2. Start Tunnel

**Sender** (on server with SSH — waits for receiver connections):
```bash
tunnel-rs sender nostr \
  --allowed-tcp 127.0.0.0/8 \
  --nsec-file ./sender.nsec \
  --peer-npub npub1receiver...
```

**Receiver** (on client — initiates connection):
```bash
tunnel-rs receiver nostr \
  --source tcp://127.0.0.1:22 \
  --target tcp://127.0.0.1:2222 \
  --nsec-file ./receiver.nsec \
  --peer-npub npub1sender...
```

### 3. Connect

```bash
ssh -p 2222 user@127.0.0.1
```

## UDP Tunnel (e.g., WireGuard)

```bash
# Sender (allows UDP traffic to localhost)
tunnel-rs sender nostr \
  --allowed-udp 127.0.0.0/8 \
  --nsec-file ./sender.nsec \
  --peer-npub npub1receiver...

# Receiver (requests WireGuard tunnel)
tunnel-rs receiver nostr \
  --source udp://127.0.0.1:51820 \
  --target udp://0.0.0.0:51820 \
  --nsec-file ./receiver.nsec \
  --peer-npub npub1sender...
```

## CLI Options

### sender nostr

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

### receiver nostr

| Option | Default | Description |
|--------|---------|-------------|
| `--source`, `-s` | required | Source address to request from sender |
| `--target`, `-t` | required | Local address to listen on |
| `--nsec` | - | Your Nostr private key (nsec or hex format) |
| `--nsec-file` | - | Path to file containing your Nostr private key |
| `--peer-npub` | required | Peer's Nostr public key (npub or hex format) |
| `--relay` | public relays | Nostr relay URL(s), repeatable |
| `--stun-server` | public | STUN server(s), repeatable |
| `--no-stun` | false | Disable STUN |

## Configuration File

```toml
# Sender config
role = "sender"
mode = "nostr"

[nostr]
nsec_file = "./sender.nsec"
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
- **Receiver-first protocol:** The receiver initiates the connection by publishing a request first; sender waits for a request before publishing its offer

## Mode Capabilities

| Mode | Multi-Session | Dynamic Source | Description |
|------|---------------|----------------|-------------|
| `iroh-default` | **Yes** | No | Multiple receivers, fixed source |
| `nostr` | **Yes** | **Yes** | Multiple receivers, receiver chooses source |
| `iroh-manual` | No | No | Single session, fixed source |
| `custom` | No | No | Single session, fixed source |

**Multi-Session** = Multiple concurrent connections to the same sender
**Dynamic Source** = Receiver specifies which service to tunnel (like SSH `-L`)

### iroh-default (Multi-Session, Fixed Source)

Sender specifies a fixed `--source`; multiple receivers can connect:

```bash
# Sender: fixed source, multiple receivers allowed
tunnel-rs sender iroh-default --source tcp://127.0.0.1:22
```

### nostr (Multi-Session + Dynamic Source)

Sender whitelists networks; receivers choose which service to tunnel:

```bash
# Sender: whitelist networks, receivers choose destination
tunnel-rs sender nostr --allowed-tcp 127.0.0.0/8 --nsec-file ./sender.nsec --peer-npub <NPUB> --max-sessions 5

# Receiver 1: tunnel to SSH
tunnel-rs receiver nostr --source tcp://127.0.0.1:22 --target tcp://127.0.0.1:2222 ...

# Receiver 2: tunnel to web server (same sender!)
tunnel-rs receiver nostr --source tcp://127.0.0.1:80 --target tcp://127.0.0.1:8080 ...
```

### Single-Session Modes (iroh-manual, custom)

For `iroh-manual` and `custom`, use separate instances for each tunnel:
- Different keypairs/instances per tunnel
- Or use `iroh-default` or `nostr` mode for multi-session support

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

*For iroh-default mode only.*

```bash
tunnel-rs generate-iroh-key --output ./sender.key
```

## show-iroh-node-id

```bash
tunnel-rs show-iroh-node-id --secret-file ./sender.key
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

### iroh-default Mode
1. Sender creates an iroh endpoint with discovery services
2. Sender publishes its address via Pkarr/DNS
3. Receiver resolves the sender via discovery
4. Connection established via iroh's NAT traversal

### iroh-manual Mode
1. Sender creates iroh endpoint (no relay, no discovery)
2. STUN queries discover public addresses (heuristic port mapping)
3. Manual exchange of offer/answer (copy-paste with NodeId + addresses)
4. Both sides race connect/accept for hole punching
5. Direct connection established via iroh's QUIC

*Limitation: Uses heuristic port mapping which may fail on symmetric NATs.*

### Custom Mode
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
