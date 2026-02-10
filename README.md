# vpn-rs

**Cross-platform IP-over-QUIC VPN with NAT traversal via iroh.**

`vpn-rs` provides full-network tunneling over encrypted QUIC. It creates a TUN interface and routes IP packets directly through an iroh connection, so peers can connect without open inbound ports or public IPs.

> [!IMPORTANT]
> **Project Goal:** `vpn-rs` is built for development and homelab use. It is not intended for production at scale.

> [!WARNING]
> **No Backward Compatibility (Pre-1.0):** Before 1.0, compatibility is not guaranteed across minor versions. Regenerate server keys and refresh configs when upgrading.

> [!NOTE]
> Running `vpn-rs` requires root/Administrator privileges to create TUN devices and routes.

## Features

- Full subnet routing (not just single-port forwarding)
- End-to-end encryption via QUIC/TLS 1.3 (iroh transport)
- NAT traversal with relay fallback
- Token-based authentication
- Optional dual-stack VPN (IPv4 + IPv6)
- Optional split tunneling (`--route` / `--route6`)
- Optional NAT64 for IPv6-only deployments (experimental)
- Auto-reconnect with heartbeat-based health checks

## When To Use It

Use `vpn-rs` when you need:

- Access to an entire remote subnet
- Stable full-network routing between peers behind NAT
- Cross-platform VPN connectivity (Linux/macOS/Windows)
- A WireGuard/OpenVPN alternative over iroh transport

## Installation

You only need the `vpn-rs` binary in your `PATH`.

### Linux and macOS

```bash
curl -sSL https://andrewtheguy.github.io/vpn-rs/install.sh | sudo bash
```

### Windows

```powershell
irm https://andrewtheguy.github.io/vpn-rs/install.ps1 | iex
```

### Windows: WinTun Required

Running `vpn-rs.exe` requires `wintun.dll` from <https://www.wintun.net/>:

1. Download and extract the WinTun zip
2. Copy `wintun/bin/amd64/wintun.dll` to either:
   - The same directory as `vpn-rs.exe` (default: `%LOCALAPPDATA%\\Programs\\vpn-rs\\`)
   - Any directory in your system `PATH`
3. Run `vpn-rs.exe` as Administrator

If you see `Failed to create TUN device: LoadLibraryExW failed`, the DLL is missing or not in a valid search path.

<details>
<summary>Advanced installation options</summary>

Install a specific release tag:

```bash
curl -sSL https://andrewtheguy.github.io/vpn-rs/install.sh | sudo bash -s <RELEASE_TAG>
```

```powershell
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/vpn-rs/install.ps1))) <RELEASE_TAG>
```

Install latest prerelease:

```bash
curl -sSL https://andrewtheguy.github.io/vpn-rs/install.sh | sudo bash -s -- --prerelease
```

```powershell
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/vpn-rs/install.ps1))) -PreRelease
```

</details>

### From Source

```bash
cargo install --path . -p vpn-rs
```

## Quick Start

### 1. Generate Server Identity and Auth Token

```bash
vpn-rs generate-server-key --output ./vpn-server.key
AUTH_TOKEN=$(vpn-rs generate-token)
echo "$AUTH_TOKEN"
```

### 2. Create Server Config

Create `vpn_server.toml` (or copy from `vpn_server.toml.example`):

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./vpn-server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]
```

Notes:
- At least one of `network` (IPv4) or `network6` (IPv6) is required.
- `secret_file` is required for a stable server `EndpointId`.
- IPv6-only mode is supported but still experimental.

### 3. Start Server

```bash
sudo vpn-rs server -c vpn_server.toml
```

### 4. Connect Client

```bash
sudo vpn-rs client \
  --server-node-id <SERVER_NODE_ID> \
  --auth-token "$AUTH_TOKEN"
```

### 5. Verify Connectivity

```bash
# Linux
ip addr show

# macOS
ifconfig

# Ping server VPN IP (example)
ping 10.0.0.1
```

## CLI Reference

### Server

`vpn-rs server` requires config:

- `-c, --config <FILE>`
- `--default-config` (uses `~/.config/vpn-rs/vpn_server.toml`)

### Client

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Client config path |
| `--default-config` | Use `~/.config/vpn-rs/vpn_client.toml` |
| `-n, --server-node-id <ID>` | VPN server EndpointId |
| `--auth-token <TOKEN>` | Authentication token |
| `--auth-token-file <PATH>` | Read token from file |
| `--mtu <MTU>` | Override MTU (576-1500) |
| `--route <CIDR>` | Additional IPv4 routes through VPN (repeatable) |
| `--route6 <CIDR>` | Additional IPv6 routes through VPN (repeatable) |
| `--relay-url <URL>` | Custom relay URL(s) |
| `--dns-server <URL|none>` | Custom iroh discovery server, or disable DNS discovery |
| `--auto-reconnect` | Force-enable reconnect |
| `--no-auto-reconnect` | Disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |

Use `vpn_server.toml.example` and `vpn_client.toml.example` for full tunables (routes, keepalive, transport tuning, NAT64).

## Split Tunneling

Route additional networks through VPN with repeatable `--route` and `--route6`:

```bash
sudo vpn-rs client \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

For full tunnel:

```bash
sudo vpn-rs client \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 0.0.0.0/0 \
  --route6 ::/0
```

## Self-Hosted Iroh Infrastructure

`vpn-rs` supports self-hosted relay and discovery services. See:

- [`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md)
- [`docs/iroh-relay-connection-trace.md`](docs/iroh-relay-connection-trace.md)

## Architecture

Detailed internals and flow diagrams:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Single Instance Lock

Only one `vpn-rs client` instance runs at a time per machine to avoid route and TUN conflicts.
