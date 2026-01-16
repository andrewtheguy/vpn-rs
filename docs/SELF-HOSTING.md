# Self-Hosting Iroh Infrastructure

This document covers how to self-host iroh's relay and DNS servers for fully independent operation. This applies to both port forwarding (`tunnel-rs`) and VPN (`tunnel-rs-vpn`) modes.

## Custom Relay Server

Use a custom relay server instead of the public iroh relay infrastructure.

> **Note:** When using `--relay-url`, you only need a custom relay server. The `--dns-server` option is **not required** — DNS discovery is only needed if you also want to avoid the public iroh DNS infrastructure (see [Self-Hosted DNS Discovery](#self-hosted-dns-discovery)).

```bash
# Both sides must use the same relay
tunnel-rs server --relay-url https://relay.example.com --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"
tunnel-rs client --relay-url https://relay.example.com --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 --auth-token "$AUTH_TOKEN"

# Force relay-only (no direct P2P) - requires test-utils feature
# Build with: cargo build --features test-utils
tunnel-rs server --relay-url https://relay.example.com --relay-only --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"
```

### Running iroh-relay (Quick Start)

```bash
cargo install iroh-relay
iroh-relay --dev  # Local testing on http://localhost:3340
```

## Self-Hosted DNS Discovery

For fully independent operation without public infrastructure:

```bash
# Both sides use custom DNS server
tunnel-rs server --dns-server https://dns.example.com/pkarr --secret-file ./server.key --allowed-tcp 127.0.0.0/8 --auth-tokens "$AUTH_TOKEN"
tunnel-rs client --dns-server https://dns.example.com/pkarr --server-node-id <ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 --auth-token "$AUTH_TOKEN"
```

## Full Self-Hosted Infrastructure

For fully independent operation, you can self-host both iroh's relay and DNS servers.

### Running iroh-relay

```bash
cargo install iroh-relay
iroh-relay --config relay.toml
```

Example `relay.toml`:
```toml
[relay]
http_bind_addr = "0.0.0.0:80"
tls_bind_addr = "0.0.0.0:443"
hostname = "relay.example.com"
```

### Running iroh-dns-server

```bash
cargo install iroh-dns-server
iroh-dns-server --config dns.toml
```

### Using Your Infrastructure

```bash
# Server
tunnel-rs server \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --auth-tokens "$AUTH_TOKEN"

# Client
tunnel-rs client \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --server-node-id <ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222 \
  --auth-token "$AUTH_TOKEN"
```

## VPN Mode with Self-Hosted Infrastructure

The same `--relay-url` and `--dns-server` options work with VPN mode:

```bash
# VPN Server
sudo tunnel-rs-vpn server -c vpn_server.toml
# (configure relay_urls and dns_server in vpn_server.toml)

# VPN Client
sudo tunnel-rs-vpn client \
  --server-node-id <ID> \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --auth-token "$AUTH_TOKEN"
```

## Relay Behavior

iroh mode uses the relay for both **signaling/coordination** and as a **data transport fallback**:

1. Initial connection goes through relay for signaling
2. iroh attempts coordinated hole punching (similar to libp2p's DCUtR protocol)
3. If successful (~70%), traffic flows directly between peers
4. If hole punching fails, **traffic continues through relay**

> [!NOTE]
> **Bandwidth Concern:** If you want signaling-only coordination **without** relay fallback (to avoid forwarding any tunnel traffic), iroh mode currently doesn't support this. The relay always acts as fallback when direct connection fails.
>
> **Alternative for signaling-only:** Use [nostr mode](ALTERNATIVE-MODES.md#nostr-mode) with self-hosted Nostr relays. Nostr relays only handle signaling (small encrypted messages), never tunnel traffic. If hole punching fails, the connection fails — no traffic is ever forwarded through the relay.
