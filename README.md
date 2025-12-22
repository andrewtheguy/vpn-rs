# tunnel-rs

**Secure peer-to-peer TCP/UDP port forwarding with NAT traversal.**

tunnel-rs enables you to forward TCP and UDP traffic between machines without requiring public IP addresses, port forwarding, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

**Key Features:**
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with multiple strategies (relay fallback, STUN, full ICE)
- **Zero configuration** for automatic peer discovery (iroh-default mode)
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
| Symmetric NAT | May fail | Works |
| Protocols | TCP + UDP | TCP + UDP |
| QUIC stack | iroh | str0m + quinn |

**Recommendation:** Use `custom` mode for best NAT traversal, especially for symmetric NATs.

## Installation

```bash
cargo install --path .
```

---

# iroh-default Mode

Uses iroh's P2P network for automatic peer discovery and NAT traversal with relay fallback.

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
tunnel-rs sender iroh-default --target 127.0.0.1:22
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Waiting for receiver to connect...
```

**Receiver** (on client):
```bash
tunnel-rs receiver iroh-default --node-id <ENDPOINT_ID> --listen 127.0.0.1:2222
```

Then connect: `ssh -p 2222 user@127.0.0.1`

### UDP Tunnel (e.g., WireGuard)

**Sender**:
```bash
tunnel-rs sender iroh-default --protocol udp --target 127.0.0.1:51820
```

**Receiver**:
```bash
tunnel-rs receiver iroh-default --protocol udp --node-id <ENDPOINT_ID> --listen 0.0.0.0:51820
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
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
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
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--node-id`, `-n` | required | EndpointId of the sender |
| `--listen`, `-l` | required | Local address to listen on |
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
# ~/.config/tunnel-rs/sender.toml

# Required: validates config matches CLI command
role = "sender"
mode = "iroh-default"

# Shared options
protocol = "tcp"
target = "127.0.0.1:22"

[iroh-default]
secret_file = "./sender.key"
relay_urls = ["https://relay.example.com"]
relay_only = false
dns_server = "https://dns.example.com/pkarr"
```

```bash
# Load from default location (mode inferred from config)
tunnel-rs sender --default-config

# Load from custom path
tunnel-rs sender -c ./my-sender.toml
```

> [!NOTE]
> See [`sender.toml.example`](sender.toml.example) for comprehensive configuration examples showing all available options for each mode.

### Receiver Config Example

```toml
# ~/.config/tunnel-rs/receiver.toml

# Required: validates config matches CLI command
role = "receiver"
mode = "iroh-default"

# Shared options
protocol = "tcp"
listen = "127.0.0.1:2222"

[iroh-default]
node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
relay_urls = ["https://relay.example.com"]
relay_only = false
dns_server = "https://dns.example.com/pkarr"
```

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
tunnel-rs sender iroh-default --target 127.0.0.1:22 --secret-file ./sender.key

# Subsequent runs: loads existing key
tunnel-rs sender iroh-default --target 127.0.0.1:22 --secret-file ./sender.key
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
tunnel-rs sender iroh-default --relay-url https://relay.example.com --target 127.0.0.1:22
tunnel-rs receiver iroh-default --relay-url https://relay.example.com --node-id <ID> --listen 127.0.0.1:2222

# Force relay-only (no direct P2P)
tunnel-rs sender iroh-default --relay-url https://relay.example.com --relay-only --target 127.0.0.1:22
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
tunnel-rs receiver iroh-default --dns-server https://dns.example.com/pkarr --node-id <ID> --listen 127.0.0.1:2222
```

---

# iroh-manual Mode

Uses iroh's QUIC transport with manual copy-paste signaling. No discovery servers or relay infrastructure needed - fully serverless.

**NAT Traversal:** Uses STUN to discover public addresses and bidirectional connection racing. Works with most NATs but may fail on symmetric NATs. For difficult NAT scenarios, use [Custom Mode](#custom-mode) which has full ICE support.

## Quick Start

1. **Sender** starts and outputs an offer:
   ```bash
   tunnel-rs sender iroh-manual --target 127.0.0.1:22
   ```

   Copy the `-----BEGIN TUNNEL-RS IROH OFFER-----` block.

2. **Receiver** starts and pastes the offer:
   ```bash
   tunnel-rs receiver iroh-manual --listen 127.0.0.1:2222
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
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
| `--stun-server` | public | STUN server(s), repeatable |

### receiver iroh-manual

| Option | Default | Description |
|--------|---------|-------------|
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--listen`, `-l` | required | Local address to listen on |
| `--stun-server` | public | STUN server(s), repeatable |

Note: Config file options (`-c`, `--default-config`) are at the `sender`/`receiver` command level. See [Configuration Files](#configuration-files) above.

## UDP Support

iroh-manual mode supports both TCP and UDP tunneling:

```bash
# Sender
tunnel-rs sender iroh-manual --protocol udp --target 127.0.0.1:51820

# Receiver
tunnel-rs receiver iroh-manual --protocol udp --listen 0.0.0.0:51820
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
   tunnel-rs sender custom --target 127.0.0.1:22
   ```

   Copy the `-----BEGIN TUNNEL-RS MANUAL OFFER-----` block.

2. **Receiver** starts and pastes the offer:
   ```bash
   tunnel-rs receiver custom --listen 127.0.0.1:2222
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
tunnel-rs sender custom --protocol udp --target 127.0.0.1:51820

# Receiver
tunnel-rs receiver custom --protocol udp --listen 0.0.0.0:51820
```

## CLI Options

### sender custom

| Option | Default | Description |
|--------|---------|-------------|
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
| `--stun-server` | public | STUN server(s), repeatable |

### receiver custom

| Option | Default | Description |
|--------|---------|-------------|
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--listen`, `-l` | required | Local address to listen on |
| `--stun-server` | public | STUN server(s), repeatable |

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

# Security

- All traffic is encrypted using QUIC/TLS 1.3
- The EndpointId is a public key that identifies the sender
- Secret key files are created with `0600` permissions (Unix)
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
