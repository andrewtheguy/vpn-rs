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
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--target`, `-t` | 127.0.0.1:22 | Target address to forward traffic to |
| `--secret-file` | (optional) | Path to secret key file for persistent identity |

### receiver

| Option | Default | Description |
|--------|---------|-------------|
| `--protocol`, `-p` | tcp | Protocol to tunnel (tcp or udp) |
| `--node-id`, `-n` | (required) | EndpointId of the sender to connect to |
| `--listen-port`, `-l` | 22 | Local port to expose for clients |

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
