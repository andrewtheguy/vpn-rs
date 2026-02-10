# vpn-rs

CLI binary for the `vpn-rs` workspace.

`vpn-rs` establishes full-network IP-over-QUIC tunnels using iroh transport and local TUN devices.

## Quick Commands

```bash
# Generate server identity + auth token
vpn-rs generate-server-key --output ./vpn-server.key
vpn-rs generate-token

# Start server
sudo vpn-rs server -c vpn_server.toml

# Start client
sudo vpn-rs client --server-node-id <ID> --auth-token <TOKEN>
```

## Config Examples

- `../../vpn_server.toml.example`
- `../../vpn_client.toml.example`

## Full Documentation

- Root README: `../../README.md`
- Architecture: `../../docs/ARCHITECTURE.md`
- Self-hosted relay/discovery: `../../docs/SELF-HOSTING.md`
