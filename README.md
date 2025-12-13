# tunnel-rs

TCP/UDP port forwarding through iroh P2P connections.

## Architecture

### TCP Tunneling (Default)

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | receiver        |  iroh  | sender          |  TCP   | SSH Server      |
|                 |<------>| (local:22)      |<======>|                 |<------>| (local:22)      |
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

- **sender**: Runs on the machine with the service (e.g., SSH or WireGuard server). Accepts iroh connections and forwards traffic to the target service.
- **receiver**: Runs on the machine that wants to access the service. Exposes a local port and forwards traffic through the iroh tunnel.

The connection is established via iroh's P2P network, which handles NAT traversal using relay servers and direct connections where possible.

## Installation

```bash
cargo install --path .
```

Or run directly:

```bash
cargo run -- sender
cargo run -- receiver
```

## Usage

### TCP Tunneling (Default)

#### On the server (with SSH running on port 22):

```bash
tunnel-rs sender --target 127.0.0.1:22
```

This will print an EndpointId like:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Waiting for receiver to connect...
```

#### On the client:

```bash
tunnel-rs receiver --node-id <ENDPOINT_ID> --listen-port 2222
```

Then connect via SSH to `127.0.0.1:2222`.

### UDP Tunneling

#### On the server (with WireGuard running on port 51820):

```bash
tunnel-rs sender --protocol udp --target 127.0.0.1:51820
```

#### On the client:

```bash
tunnel-rs receiver --protocol udp --node-id <ENDPOINT_ID> --listen-port 51820
```

Then configure your WireGuard client to connect to `127.0.0.1:51820`.

## Command Line Options

### sender

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | (optional) | Path to TOML config file |
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
| `--secret-file` | (optional) | Path to secret key file for persistent identity |
| `--relay-url` | (optional) | Custom relay server URL(s). Can be specified multiple times for failover |
| `--relay-only` | false | Force all traffic through relay (requires `--relay-url`) |
| `--dns-server` | (optional) | Custom DNS server URL for peer discovery (for self-hosted iroh-dns-server) |

### receiver

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | (optional) | Path to TOML config file |
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--node-id`, `-n` | (required) | EndpointId of the sender to connect to |
| `--listen`, `-l` | (required) | Local address to listen on |
| `--relay-url` | (optional) | Custom relay server URL(s). Can be specified multiple times for failover |
| `--relay-only` | false | Force all traffic through relay (requires `--relay-url`) |
| `--dns-server` | (optional) | Custom DNS server URL for peer discovery (for self-hosted iroh-dns-server) |

## Configuration File

You can use a TOML config file instead of (or in addition to) command line arguments. CLI arguments take precedence over config file values.

### Sender Config Example

```toml
# sender.toml
protocol = "tcp"
target = "127.0.0.1:22"
secret_file = "./sender.key"
relay_urls = [
    "https://relay1.example.com",
    "https://relay2.example.com",
]
relay_only = false
```

```bash
tunnel-rs sender --config sender.toml
```

### Receiver Config Example

```toml
# receiver.toml
protocol = "tcp"
node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
listen = "127.0.0.1:2222"
relay_urls = [
    "https://relay1.example.com",
    "https://relay2.example.com",
]
relay_only = false
```

```bash
tunnel-rs receiver --config receiver.toml
```

### Config Options

| Option | Sender | Receiver | Description |
|--------|--------|----------|-------------|
| `protocol` | ✓ | ✓ | Protocol to tunnel ("tcp" or "udp") |
| `target` | ✓ | - | Target address to forward traffic to |
| `node_id` | - | ✓ | EndpointId of the sender (required) |
| `listen` | - | ✓ | Local address to listen on (required) |
| `secret_file` | ✓ | - | Path to secret key file |
| `relay_urls` | ✓ | ✓ | Array of relay server URLs |
| `relay_only` | ✓ | ✓ | Force relay-only mode |
| `dns_server` | ✓ | ✓ | Custom DNS server URL for peer discovery |

## Persistent Identity for VPN Use

By default, the sender generates a new random EndpointId each time it starts. For production setups, you'll want a persistent identity so the receiver can reconnect without needing to update the node ID.

### Using Persistent Identity

Start the sender with the `--secret-file` flag:

```bash
tunnel-rs sender --target 127.0.0.1:22 --secret-file ./sender.key
```

**First run**: Generates a new secret key and saves it to `sender.key`
```
Generated new persistent identity, saved to: ./sender.key
Fixed EndpointId: b5435df733f521751f7b916e801695ec02d1ec3c0b1333ccfd4821f46696470d
```

**Subsequent runs**: Loads the existing key
```
Loaded persistent identity from: ./sender.key
Fixed EndpointId: b5435df733f521751f7b916e801695ec02d1ec3c0b1333ccfd4821f46696470d
```

Now you can configure your receiver once with this fixed EndpointId, and it will work across sender restarts.

### Pre-generating Secret Keys for Automation

For automation workflows (e.g., deployment scripts, CI/CD), you can pre-generate secret keys:

```bash
# Generate a secret key and output the EndpointId to stdout
tunnel-rs generate-secret --output ./sender.key
# Output: b5435df733f521751f7b916e801695ec02d1ec3c0b1333ccfd4821f46696470d

# Output EndpointId only to stdout without saving to file
tunnel-rs generate-secret --output -
# Output: e48e9a70da7bf8a081322bb2ae6afc13afc6851fdbf723f4763d2dbbc637b99b

# Pipe to other commands (similar to WireGuard workflow)
ENDPOINT_ID=$(tunnel-rs generate-secret --output ./sender.key)
echo "Sender EndpointId: $ENDPOINT_ID"

# Use --force to overwrite existing files
tunnel-rs generate-secret --output ./sender.key --force
```

### Security Considerations

- The secret key file is automatically created with `0600` permissions (owner read/write only) on Unix systems
- **Back up your secret key file** - losing it means changing the EndpointId on all receivers
- The key file contains the sender's private key - treat it like an SSH private key
- For VPN use cases, the iroh encryption provides transport security; the secret key just maintains identity

## How It Works

1. **Sender** creates an iroh endpoint with discovery services (Pkarr, DNS, mDNS)
2. **Sender** prints its EndpointId and waits for connections
3. **Receiver** parses the EndpointId and connects via iroh's discovery system
4. For TCP: Each local TCP connection opens a new QUIC stream
5. For UDP: Packets are framed with a 2-byte length prefix to preserve datagram boundaries
6. All traffic is encrypted using iroh's built-in QUIC/TLS 1.3

## Security

- All traffic is encrypted using iroh's built-in QUIC/TLS 1.3
- The EndpointId is a public key that identifies the sender

## Private Relay Server

By default, tunnel-rs uses iroh's public relay servers. For production use, you can run your own private relay server with access control.

### Using a Custom Relay

```bash
# Sender with custom relay
tunnel-rs sender --target 127.0.0.1:22 --relay-url https://your-relay.example.com

# Receiver with custom relay
tunnel-rs receiver --node-id <ENDPOINT_ID> --listen 127.0.0.1:2222 --relay-url https://your-relay.example.com

# Multiple relays for failover (iroh selects best one based on latency)
tunnel-rs sender --target 127.0.0.1:22 \
  --relay-url https://relay1.example.com \
  --relay-url https://relay2.example.com

tunnel-rs receiver --node-id <ENDPOINT_ID> --listen 127.0.0.1:2222 \
  --relay-url https://relay1.example.com \
  --relay-url https://relay2.example.com
```

Both sender and receiver must use the same `--relay-url` option(s) to connect through your private relay(s).

### Relay-Only Mode

By default, iroh attempts direct P2P connections and uses relay servers as fallback. With `--relay-only`, all traffic is forced through the relay server, disabling direct connections entirely.

```bash
# Sender with relay-only mode
tunnel-rs sender --target 127.0.0.1:22 \
  --relay-url https://your-relay.example.com \
  --relay-only

# Receiver with relay-only mode
tunnel-rs receiver --node-id <ENDPOINT_ID> --listen 127.0.0.1:2222 \
  --relay-url https://your-relay.example.com \
  --relay-only
```

**Important**: `--relay-only` requires `--relay-url` to be specified. The default public relays are rate-limited and cannot be used for relay-only mode.

**When to use relay-only mode**:
- When you need guaranteed relay routing (e.g., for consistent latency or compliance)
- When direct P2P connections are blocked or unreliable
- When using a private relay with access control

### Running iroh-relay

Install and run your own relay server:

```bash
cargo install iroh-relay
iroh-relay --dev  # For local testing (http://localhost:3340)
```

### Access Control

iroh-relay supports built-in authorization via config:

```toml
# Only allow specific EndpointIds to use the relay
access.allowlist = [
  "your-sender-endpoint-id",
  "your-receiver-endpoint-id",
]

# Or use HTTP-based authorization
[access.http]
url = "https://your-auth-server.com/check-relay-access"
bearer_token = "secret"  # or set IROH_RELAY_HTTP_BEARER_TOKEN env var
```

### Required Ports

| Port | Protocol | Required | Description |
|------|----------|----------|-------------|
| 443 | TCP | Yes | HTTPS relay (core functionality) |
| 3478 | UDP | Recommended | STUN for NAT traversal |
| 7842 | UDP | Optional | QUIC address discovery |
| 9090 | TCP | Optional | Metrics endpoint |

Minimum setup: Only port 443/TCP is required. STUN (3478/UDP) improves direct P2P connection success rates.

See: https://github.com/n0-computer/iroh/discussions/3168

## Self-Hosted DNS Discovery

By default, tunnel-rs uses n0's (iroh's creator) public DNS infrastructure for peer discovery. This enables direct P2P connections through NAT traversal. For fully self-hosted operation with no external dependencies, you can run your own `iroh-dns-server`.

### What iroh-dns-server Provides

- **Pkarr relay**: HTTP endpoint for publishing/resolving signed peer addresses
- **DNS server**: Traditional DNS queries for peer resolution
- **DNS-over-HTTPS**: `/dns-query` endpoint
- **Mainline DHT**: Optional connection to BitTorrent DHT for decentralized discovery

### Running iroh-dns-server

```bash
# Download precompiled binary from GitHub releases
# https://github.com/n0-computer/iroh/releases
# Look for iroh-dns-server-<version>-<platform>.tar.gz

# Or build from source
git clone https://github.com/n0-computer/iroh
cd iroh/iroh-dns-server
cargo build --release

# Run with dev config (local testing)
./iroh-dns-server --config config.dev.toml
```

The server listens on:
- HTTP: port 8080 (pkarr and DNS-over-HTTPS)
- DNS: port 5300 (UDP/TCP)

### Using Custom DNS Server

**Important**: The `dns_server` URL must include the `/pkarr` path:

```bash
# Sender with custom DNS server
tunnel-rs sender --target 127.0.0.1:22 \
  --secret-file ./sender.key \
  --dns-server https://dns.example.com/pkarr \
  --relay-url https://relay.example.com

# Receiver with custom DNS server
tunnel-rs receiver --node-id <ENDPOINT_ID> --listen 127.0.0.1:2222 \
  --dns-server https://dns.example.com/pkarr \
  --relay-url https://relay.example.com
```

Or via config file:

```toml
# Fully self-hosted sender config
protocol = "tcp"
target = "127.0.0.1:22"
secret_file = "./sender.key"
dns_server = "https://dns.example.com/pkarr"
relay_urls = ["https://relay.example.com"]
```

### How It Works

1. **Sender** publishes its address info to your DNS server via pkarr (requires `--secret-file`)
2. **Receiver** resolves the sender's address via DNS queries to your server
3. Direct P2P hole-punching proceeds as normal
4. Relay is used as fallback if direct connection fails

### Benefits of Self-Hosted DNS

- **Zero dependency on n0's infrastructure**
- **Direct P2P connections** (not relay-only)
- **Full control over peer discovery**
- **Better privacy** - peer addresses not published to public DNS

### Notes

- The sender requires `--secret-file` to publish to the DNS server
- The receiver can resolve without a secret key (read-only)
- mDNS is always enabled for local network discovery regardless of DNS settings
- Both sender and receiver must use the same `--dns-server` URL
