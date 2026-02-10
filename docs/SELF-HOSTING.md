# Self-Hosting Iroh Infrastructure

This document covers self-hosting iroh relay and discovery services for `vpn-rs`.

## Custom Relay Server

Use a custom relay instead of the public iroh relay network.

> [!NOTE]
> With `relay_urls`, you only need a relay server. `dns_server` is optional and only needed if you also want to avoid public iroh discovery.

> [!NOTE]
> The public iroh discovery endpoint is dual-stack (IPv4 + IPv6). IPv6-only environments usually do not need a custom discovery server.

Example `vpn_server.toml`:

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./vpn-server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]
relay_urls = ["https://relay.example.com"]
```

Client with custom relay:

```bash
sudo vpn-rs client \
  --server-node-id <ID> \
  --relay-url https://relay.example.com \
  --auth-token "$AUTH_TOKEN"
```

### Running `iroh-relay` (Quick Start)

```bash
cargo install iroh-relay
iroh-relay --dev
```

## Self-Hosted Discovery Server

Use a custom iroh discovery server (`/pkarr`) for fully independent endpoint discovery.

Example server config:

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./vpn-server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]
relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
```

Client with matching discovery server:

```bash
sudo vpn-rs client \
  --server-node-id <ID> \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --auth-token "$AUTH_TOKEN"
```

## Disabling DNS Discovery

Disable DNS-based discovery with `dns_server = "none"` in server config and `--dns-server none` on the client.

When discovery is disabled, peers must connect via:

1. Shared relay (`relay_urls` / `--relay-url`)
2. mDNS (same local network)

## Full Self-Hosted Deployment

### `iroh-relay`

```bash
cargo install iroh-relay
iroh-relay --config relay.toml --dev
```

Example `relay.toml`:

```toml
enable_quic_addr_discovery = true

[tls]
cert_mode = "Manual"
manual_cert_path = "/etc/letsencrypt/live/relay.example.com/fullchain.pem"
manual_key_path = "/etc/letsencrypt/live/relay.example.com/privkey.pem"
```

### `iroh-dns-server`

```bash
cargo install iroh-dns-server
iroh-dns-server --config dns.toml
```

Example `dns.toml`:

```toml
pkarr_put_rate_limit = "smart"

[http]
port = 8080
bind_addr = "0.0.0.0"

[https]
port = 443
domains = ["dns.example.com"]
cert_mode = "lets_encrypt"
letsencrypt_prod = true

[dns]
port = 53
default_ttl = 30
origins = ["dns.example.com", "."]
rr_a = "203.0.113.10"
rr_ns = "ns1.dns.example.com."
default_soa = "ns1.dns.example.com hostmaster.dns.example.com 0 10800 3600 604800 3600"
```

### End-to-End `vpn-rs` Example

`vpn_server.toml`:

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./vpn-server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]
relay_urls = [
  "https://relay.example.com",
  "https://relay-backup.example.com",
]
dns_server = "https://dns.example.com/pkarr"
```

Client:

```bash
sudo vpn-rs client \
  --server-node-id <ID> \
  --relay-url https://relay.example.com \
  --dns-server https://dns.example.com/pkarr \
  --auth-token "$AUTH_TOKEN"
```

## Relay Behavior

iroh uses relay infrastructure for signaling/coordination and as transport fallback:

1. Initial rendezvous happens via relay/discovery
2. iroh attempts direct P2P hole punching
3. If direct path fails, traffic continues via relay

If you need to avoid relay data transport entirely, ensure your network allows direct connectivity and validate path selection in logs.
