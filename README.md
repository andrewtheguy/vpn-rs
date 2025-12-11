# UDP Tunnel

UDP port forwarding through iroh P2P connections.

## Architecture

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| WireGuard       |  UDP   | receiver        |  iroh  | sender          |  UDP   | WireGuard       |
| Client          |<------>| (local:51820)   |<======>|                 |<------>| Server          |
|                 |        |                 |  QUIC  |                 |        | (local:51820)   |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
     Client Side                                            Server Side
```

- **sender**: Runs on the machine with the UDP service (e.g., WireGuard server). Accepts iroh connections and forwards traffic to the target service.
- **receiver**: Runs on the machine that wants to access the UDP service. Exposes a local UDP port and forwards traffic through the iroh tunnel.

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

### On the server (with WireGuard running on port 51820):

```bash
udp-tunnel sender --target 127.0.0.1:51820
```

Or with cargo:

```bash
cargo run -- sender --target 127.0.0.1:51820
```

This will print an EndpointId like:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Waiting for receiver to connect...
```

### On the client:

```bash
udp-tunnel receiver --node-id <ENDPOINT_ID> --listen-port 51820
```

Or with cargo:

```bash
cargo run -- receiver --node-id <ENDPOINT_ID> --listen-port 51820
```

Then configure your WireGuard client to connect to `127.0.0.1:51820`.

## Command Line Options

### sender

| Option | Default | Description |
|--------|---------|-------------|
| `--target`, `-t` | 127.0.0.1:51820 | Target UDP address to forward traffic to (e.g., WireGuard server) |

### receiver

| Option | Default | Description |
|--------|---------|-------------|
| `--node-id`, `-n` | (required) | EndpointId of the sender to connect to |
| `--listen-port`, `-l` | 51820 | Local UDP port to expose for clients |

## Testing with netcat

You can test the UDP forwarding without WireGuard using netcat:

### Terminal 1 (Server side - simulate UDP server):
```bash
# Start a UDP listener on port 51820
nc -u -l 51820
```

### Terminal 2 (Server side - start the forwarder):
```bash
cargo run -- sender --target 127.0.0.1:51820
# Note the EndpointId printed
```

### Terminal 3 (Client side - start the receiver):
```bash
cargo run -- receiver --node-id <ENDPOINT_ID> --listen-port 51820
```

### Terminal 4 (Client side - send test message):
```bash
echo "hello from client" | nc -u 127.0.0.1 51820
```

You should see "hello from client" appear in Terminal 1 (the UDP server).

### Bidirectional test:

After sending from the client, type a response in Terminal 1 and press Enter. The response will be forwarded back through the tunnel to the client.

## How It Works

1. **Sender** creates an iroh endpoint with discovery services (Pkarr, DNS, mDNS)
2. **Sender** prints its EndpointId and waits for connections
3. **Receiver** parses the EndpointId and connects via iroh's discovery system
4. Both sides establish a bidirectional QUIC stream
5. UDP packets are framed with a 2-byte length prefix and forwarded through the stream
6. The framing preserves UDP datagram boundaries over the byte-oriented QUIC stream

## Security

- All traffic is encrypted using iroh's built-in QUIC/TLS 1.3
- The EndpointId is a public key that identifies the sender
