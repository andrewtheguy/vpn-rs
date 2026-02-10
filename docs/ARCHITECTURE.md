# vpn-rs Architecture

`vpn-rs` provides full-network tunneling over iroh QUIC using TUN devices.

## Components

- `vpn-rs` binary: CLI, config loading, orchestration
- `vpn-common`: VPN config parsing, validation, and resolution
- `vpn-iroh`: endpoint/auth/secret helpers for iroh connectivity
- `vpn-core`: VPN client/server runtime, signaling, TUN I/O, NAT64

## Data Flow

1. Client connects to server endpoint over iroh QUIC.
2. Auth token is validated by the server.
3. Server assigns tunnel IPs and sends handshake response.
4. Both sides create/configure TUN interfaces.
5. Raw IP packets are framed and exchanged over QUIC streams.

## Security

- Transport encryption: QUIC + TLS 1.3 (iroh)
- Access control: token-based auth (`vpn-auth` format)
- Stable server identity: required `secret_file`

## NAT64

Optional NAT64 enables IPv6-only clients to reach IPv4 destinations using `64:ff9b::/96` translation.

## Reliability

Client supports auto-reconnect and heartbeat-based connection health monitoring.
