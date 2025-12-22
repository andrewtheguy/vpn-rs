# tunnel-rs

TCP/UDP port forwarding through P2P connections.

## Overview

tunnel-rs provides multiple modes for establishing tunnels:

| Mode | Discovery | Protocols | Use Case |
|------|-----------|-----------|----------|
| **iroh default** | Automatic (Pkarr/DNS/mDNS) | TCP, UDP | Production, always-on tunnels |
| **iroh manual** | Manual copy-paste | TCP, UDP | Serverless, no infrastructure needed |
| **custom** | Manual copy-paste (ICE) | TCP only | Alternative QUIC stack (str0m+quinn) |

## Installation

```bash
cargo install --path .
```

---

# Iroh Default Mode

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
tunnel-rs sender iroh default --target 127.0.0.1:22
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Waiting for receiver to connect...
```

**Receiver** (on client):
```bash
tunnel-rs receiver iroh default --node-id <ENDPOINT_ID> --listen 127.0.0.1:2222
```

Then connect: `ssh -p 2222 user@127.0.0.1`

### UDP Tunnel (e.g., WireGuard)

**Sender**:
```bash
tunnel-rs sender iroh default --protocol udp --target 127.0.0.1:51820
```

**Receiver**:
```bash
tunnel-rs receiver iroh default --protocol udp --node-id <ENDPOINT_ID> --listen 0.0.0.0:51820
```

## CLI Options

### sender iroh default

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
| `--secret-file` | - | Path to secret key file for persistent identity |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay |
| `--dns-server` | public | Custom DNS server URL for peer discovery |

### receiver iroh default

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--node-id`, `-n` | required | EndpointId of the sender |
| `--listen`, `-l` | required | Local address to listen on |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay |
| `--dns-server` | public | Custom DNS server URL for peer discovery |

## Configuration Files

### Sender Config

```toml
# iroh-sender.toml
protocol = "tcp"
target = "127.0.0.1:22"
secret_file = "./sender.key"
relay_urls = ["https://relay.example.com"]
relay_only = false
dns_server = "https://dns.example.com/pkarr"
```

```bash
tunnel-rs sender iroh default --config iroh-sender.toml
```

### Receiver Config

```toml
# iroh-receiver.toml
protocol = "tcp"
node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
listen = "127.0.0.1:2222"
relay_urls = ["https://relay.example.com"]
relay_only = false
dns_server = "https://dns.example.com/pkarr"
```

```bash
tunnel-rs receiver iroh default --config iroh-receiver.toml
```

## Persistent Identity

By default, a new EndpointId is generated each run. For production, use persistent identity:

```bash
# First run: generates and saves key
tunnel-rs sender iroh default --target 127.0.0.1:22 --secret-file ./sender.key

# Subsequent runs: loads existing key
tunnel-rs sender iroh default --target 127.0.0.1:22 --secret-file ./sender.key
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
tunnel-rs sender iroh default --relay-url https://relay.example.com --target 127.0.0.1:22
tunnel-rs receiver iroh default --relay-url https://relay.example.com --node-id <ID> --listen 127.0.0.1:2222

# Force relay-only (no direct P2P)
tunnel-rs sender iroh default --relay-url https://relay.example.com --relay-only --target 127.0.0.1:22
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
tunnel-rs sender iroh default --dns-server https://dns.example.com/pkarr --secret-file ./sender.key
tunnel-rs receiver iroh default --dns-server https://dns.example.com/pkarr --node-id <ID> --listen 127.0.0.1:2222
```

---

# Iroh Manual Mode

Uses iroh's QUIC transport with manual copy-paste signaling. No discovery servers or relay infrastructure needed - fully serverless.

## Quick Start

1. **Sender** starts and outputs an offer:
   ```bash
   tunnel-rs sender iroh manual --target 127.0.0.1:22
   ```

   Copy the `-----BEGIN TUNNEL-RS IROH OFFER-----` block.

2. **Receiver** starts and pastes the offer:
   ```bash
   tunnel-rs receiver iroh manual --listen 127.0.0.1:2222
   ```

   Paste the offer, then copy the `-----BEGIN TUNNEL-RS IROH ANSWER-----` block.

3. **Sender** receives the answer:

   Paste the answer into the sender terminal.

4. **Connect**:
   ```bash
   ssh -p 2222 user@127.0.0.1
   ```

## CLI Options

### sender iroh manual

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |

### receiver iroh manual

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--listen`, `-l` | required | Local address to listen on |

## UDP Support

Iroh manual mode supports both TCP and UDP tunneling:

```bash
# Sender
tunnel-rs sender iroh manual --protocol udp --target 127.0.0.1:51820

# Receiver
tunnel-rs receiver iroh manual --protocol udp --listen 0.0.0.0:51820
```

---

# Custom Mode

Uses manual ICE signaling with str0m + quinn QUIC. TCP tunneling only.

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

## CLI Options

### sender custom

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
| `--stun-server` | public | STUN server(s), repeatable |

### receiver custom

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--listen`, `-l` | required | Local address to listen on |
| `--stun-server` | public | STUN server(s), repeatable |

## Configuration Files

### Sender Config

```toml
# custom-sender.toml
target = "127.0.0.1:22"
stun_servers = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
]
```

### Receiver Config

```toml
# custom-receiver.toml
listen = "127.0.0.1:2222"
stun_servers = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
]
```

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

- Custom mode is **TCP only**
- Symmetric NATs may not connect without a relay (not supported in custom mode)
- Signaling payloads include a version number; mismatches are rejected

---

# Utility Commands

These commands are for managing persistent identity in iroh mode.

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

### Iroh Default Mode
1. Sender creates an iroh endpoint with discovery services
2. Sender publishes its address via Pkarr/DNS
3. Receiver resolves the sender via discovery
4. Connection established via iroh's NAT traversal

### Iroh Manual Mode
1. Sender creates iroh endpoint (no relay, no discovery)
2. Manual exchange of offer/answer (copy-paste with NodeId + addresses)
3. Direct connection established via iroh's QUIC

### Custom Mode
1. Both sides gather ICE candidates via STUN
2. Manual exchange of offer/answer (copy-paste)
3. ICE connectivity checks find best path
4. QUIC connection established over ICE socket
