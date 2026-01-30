# tunnel-rs-vpn

Full network tunneling (TUN) over encrypted QUIC, with NAT traversal via iroh.

`tunnel-rs-vpn` is the VPN-mode binary in the `tunnel-rs` repo. Unlike port-forwarding modes, it creates a TUN interface and routes IP packets directly through an encrypted iroh QUIC connection (no WireGuard/OpenVPN layer required).

> [!NOTE]
> VPN mode requires root/admin privileges to create TUN devices and configure routes.
>
> Server identity is required. Configure `secret_file` in `vpn_server.toml`.

## When To Use This

- You want **full network/subnet routing** (not just a single TCP/UDP port).
- You need NAT traversal without opening ports (iroh relay fallback).
- You are OK with running as root/admin and creating a TUN device.

If you only need to forward ports (SSH/HTTP/databases, or UDP services like WireGuard/game servers), use `tunnel-rs` instead.

## Installation

You only need the `tunnel-rs-vpn` binary in your `PATH`.

**Linux & macOS:**
```bash
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install-vpn.sh | sudo bash
```

**Windows:**
```powershell
irm https://andrewtheguy.github.io/tunnel-rs/install-vpn.ps1 | iex
```

### Windows Setup: WinTun Driver Required

Running `tunnel-rs-vpn.exe` requires the WinTun driver DLL from https://www.wintun.net/ (official WireGuard project) and Administrator privileges:

1. Download and extract the WinTun zip
2. Copy `wintun/bin/amd64/wintun.dll` to:
   - The same directory as `tunnel-rs-vpn.exe` (default: `%LOCALAPPDATA%\\Programs\\tunnel-rs\\`), OR
   - Any directory in the system `PATH`
3. Run `tunnel-rs-vpn.exe` as Administrator

Troubleshooting: if you see `Failed to create TUN device: LoadLibraryExW failed`, `wintun.dll` is missing or not in a valid DLL search path.

<details>
<summary>Advanced installation options</summary>

Install with custom release tag:
```bash
# Linux/macOS
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install-vpn.sh | sudo bash -s <RELEASE_TAG>
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install-vpn.ps1))) <RELEASE_TAG>
```

Latest prerelease:
```bash
# Linux/macOS
curl -sSL https://andrewtheguy.github.io/tunnel-rs/install-vpn.sh | sudo bash -s -- --prerelease
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/tunnel-rs/install-vpn.ps1))) -PreRelease
```

</details>

### From Source

```bash
cargo install --path ../.. -p tunnel-rs-vpn
```

## Architecture (High Level)

```
Client                                     Server
+---------------------+                   +---------------------+
|  Applications       |                   |  Target Network     |
|        |            |                   |        ^            |
|  [tun0: 10.0.0.2]   |                   |  [tun0: 10.0.0.1]   |
|        |            |                   |        ^            |
|  Tunnel (VPN)       |                   |  Tunnel (VPN)       |
|        |            |                   |        ^            |
|  iroh (transport)   | ===== NAT ======> |  iroh (transport)   |
+---------------------+     traversal     +---------------------+
```

- Creates a virtual network interface (TUN device)
- Assigns VPN IP addresses automatically (no keypair management)
- Routes entire IP subnets, not just individual ports
- Direct IP-over-QUIC tunneling (TLS 1.3 encryption)

Related: this is conceptually similar to [quincy](https://github.com/quincy-rs/quincy) (QUIC VPN), but tunnel-rs uses iroh's NAT traversal infrastructure so no open port is required on the server.

## Quick Start

### 1. Setup (One-Time)

On the server machine, generate a persistent identity (required) and an auth token:

```bash
tunnel-rs-vpn generate-server-key --output ./server.key
AUTH_TOKEN=$(tunnel-rs-vpn generate-token)
echo "$AUTH_TOKEN"
```

### 2. Create Server Config

Create `vpn_server.toml` (or copy from `../../vpn_server.toml.example`):

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]
```

Notes:
- At least one of `network` (IPv4) or `network6` (IPv6) is required.
- IPv6-only mode is supported but still experimental; see `../../vpn_server.toml.example` for details.
- NAT64 support exists for IPv6-only setups but is still experimental; see `../../vpn_server.toml.example`.
- `secret_file` is required for a stable server `EndpointId`.

### 3. Start VPN Server

```bash
sudo tunnel-rs-vpn server -c vpn_server.toml
```

### 4. Connect VPN Client

```bash
sudo tunnel-rs-vpn client \
  --server-node-id <SERVER_NODE_ID> \
  --auth-token "$AUTH_TOKEN"
```

The client will:
1. Connect to the server via iroh (NAT traversal)
2. Receive an assigned IP (e.g., `10.0.0.2`)
3. Create a TUN device and configure routes

### 5. Verify Connection

```bash
# Check assigned IP
ip addr show tun0  # Linux
ifconfig utun9     # macOS (interface name varies)

# Ping the server
ping 10.0.0.1
```

## CLI Reference

### server

VPN server requires a config file. Use `-c <FILE>` or `--default-config` for `~/.config/tunnel-rs/vpn_server.toml`.

See `../../vpn_server.toml.example` for all available configuration options.

### client

The client can be configured via `-c/--config` (or `--default-config`) and optionally overridden via flags:

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to config file |
| `--default-config` | Use `~/.config/tunnel-rs/vpn_client.toml` |
| `-n, --server-node-id <ID>` | EndpointId of the VPN server |
| `--auth-token <TOKEN>` | Authentication token |
| `--auth-token-file <PATH>` | Read auth token from a file |
| `--mtu <MTU>` | Override MTU (576-1500) |
| `--route <CIDR>` | Additional IPv4 CIDRs to route through VPN (repeatable) |
| `--route6 <CIDR>` | Additional IPv6 CIDRs to route through VPN (repeatable) |
| `--relay-url <URL>` | Custom relay URL(s) (repeatable) |
| `--dns-server <URL|none>` | Custom iroh DNS discovery server, or `none` |
| `--auto-reconnect` | Enable auto-reconnect (override config) |
| `--no-auto-reconnect` | Disable auto-reconnect (exit on first disconnection) |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts (requires auto-reconnect) |

For the full set of tunables (keepalive, routes, transport tuning, etc.), use the config examples:
- `../../vpn_server.toml.example`
- `../../vpn_client.toml.example`

## Split Tunneling

By default, only the VPN subnet is routed. Use `--route` / `--route6` (or config `routes` / `routes6`) to add additional networks:

```bash
sudo tunnel-rs-vpn client \
  --server-node-id <ID> \
  --auth-token "$AUTH_TOKEN" \
  --route 192.168.1.0/24 \
  --route 172.16.0.0/12
```

## How It Works

1. Signaling via iroh: client connects to server using iroh for discovery and NAT traversal
2. Handshake: client and server exchange session parameters (TLS 1.3 secured)
3. IP assignment: server assigns a VPN IP from the configured pool(s)
4. TUN devices: both sides create TUN devices for packet capture/injection
5. Packet flow: IP packets are framed and sent over an encrypted QUIC stream

### About `device_id`

The VPN client generates a random 64-bit `device_id` at startup (ephemeral per session). It is used for session tracking on the server (keyed by `(EndpointId, device_id)`), not as an authentication mechanism.

## Single Instance Lock

Only one VPN client can run at a time per machine to prevent routing conflicts and TUN device issues.

## History

VPN-over-ICE/Nostr (`tunnel-rs-vpn-ice`) was removed. For historical reference, see the `before-ice-vpn-removal` tag in the GitHub releases.
