# tunnel-rs

**Cross-platform Secure peer-to-peer TCP/UDP port forwarding with NAT traversal.**

tunnel-rs enables you to forward TCP and UDP traffic between machines without requiring public IP addresses, port forwarding, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

**Key Features:**
- **Cross-platform support** — Works on Linux, macOS, and Windows
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with multiple strategies (relay fallback, STUN, full ICE)
- **Minimal configuration** for automatic peer discovery (iroh-default mode; EndpointId required)
- **Serverless options** with manual signaling (iroh-manual, custom modes)
- **Protocol support** for both TCP and UDP tunneling
- **High performance** with QUIC multiplexing

**Common Use Cases:**
- SSH access to machines behind NAT/firewalls
- WireGuard VPN tunneling over P2P connections
- Remote desktop access without port forwarding
- Secure service exposure without public infrastructure
- Development and testing across network boundaries

## Overview

tunnel-rs provides multiple modes for establishing tunnels:

| Mode | Discovery | NAT Traversal | Protocols | Use Case |
|------|-----------|---------------|-----------|----------|
| **iroh-default** | Automatic (Pkarr/DNS/mDNS) | Relay fallback | TCP, UDP | Production, always-on tunnels |
| **iroh-manual** | Manual copy-paste | STUN heuristic | TCP, UDP | Serverless, simple NATs |
| **custom** | Manual copy-paste | Full ICE | TCP, UDP | Best NAT compatibility |

### Choosing a Manual Mode

Both `iroh-manual` and `custom` modes use copy-paste signaling without servers:

| Feature | iroh-manual | custom |
|---------|-------------|--------|
| NAT traversal | STUN-based (heuristic) | Full ICE (connectivity checks) |
| Symmetric NAT | May fail | Best-effort (STUN-only, may fail without relay) |
| Protocols | TCP + UDP | TCP + UDP |
| QUIC stack | iroh | str0m + quinn |

**Recommendation:** Use `custom` mode for best NAT traversal, especially for symmetric NATs.

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

All three modes (iroh-default, iroh-manual, custom) work across all platforms, enabling cross-platform P2P tunneling.

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

Use `--default-config` to load from the default location, or `-c <path>` for a custom path. Each mode has its own section (`[iroh-default]`, `[iroh-manual]`, `[custom]`).

**Default locations:**
- Sender: `~/.config/tunnel-rs/sender.toml`
- Receiver: `~/.config/tunnel-rs/receiver.toml`

### Sender Config Example

```toml
# Example sender configuration (iroh-default mode)

# Required: validates config matches CLI command
role = "sender"
mode = "iroh-default"  # or "iroh-manual" or "custom"

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
mode = "iroh-default"  # or "iroh-manual" or "custom"

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

By default, a new EndpointId is generated each run. For production, use persistent identity:

```bash
# First run: generates and saves key
tunnel-rs sender iroh-default --source tcp://127.0.0.1:22 --secret-file ./sender.key

# Subsequent runs: loads existing key
tunnel-rs sender iroh-default --source tcp://127.0.0.1:22 --secret-file ./sender.key
```

### Pre-generating Keys

```bash
# Generate key and output EndpointId
tunnel-rs generate-secret --output ./sender.key

# Show EndpointId for existing key
tunnel-rs show-id --secret-file ./sender.key
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

If you want **zero external infrastructure**, you can run manual modes without any STUN servers. This works best when both peers are on public IPs or permissive NATs. Use `--no-stun` on the CLI, or set `stun_servers = []` in your config. If you omit STUN entirely (no config and no CLI), tunnel-rs uses its default public STUN list.

## UDP Support

iroh-manual mode supports both TCP and UDP tunneling:

```bash
# Sender
tunnel-rs sender iroh-manual --source udp://127.0.0.1:51820

# Receiver
tunnel-rs receiver iroh-manual --target udp://0.0.0.0:51820
```

---

# Custom Mode

Uses full ICE (Interactive Connectivity Establishment) with str0m + quinn QUIC. Supports TCP and UDP tunneling.

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

# Utility Commands

These commands manage persistent identity (secret files, EndpointId) and apply only to **iroh-default mode**. Other modes do not use persistent identity.

## generate-secret

Generate a new secret key for persistent identity:

```bash
# Save to file and output EndpointId
tunnel-rs generate-secret --output ./sender.key

# Overwrite existing file
tunnel-rs generate-secret --output ./sender.key --force
```

## show-id

Display the EndpointId for an existing secret key:

```bash
tunnel-rs show-id --secret-file ./sender.key
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
