# vpn-rs

**Cross-platform IP-over-QUIC VPN with NAT traversal via iroh.**

`vpn-rs` provides full-network tunneling over encrypted QUIC. It creates a TUN interface and routes IP packets directly through an iroh connection, so peers can connect without open inbound ports or public IPs.

> [!IMPORTANT]
> **Project Goal:** `vpn-rs` is built for development and homelab use. It is not intended for production at scale.

> [!WARNING]
> **No Backward Compatibility in 0.0.x:** While `vpn-rs` remains in the `0.0.x` series, there is no backward compatibility between any versions. Regenerate server keys and refresh configs on every upgrade.
> The current wire protocol is v3 (`ALPN: vpn-rs/3`), and older peers are rejected.

> [!CAUTION]
> **Pre-release Proof of Concept:** `vpn-rs` is still prerelease software and currently in a proof-of-concept stage. Expect rough edges and breaking changes.

> [!NOTE]
> Running `vpn-rs` requires root/Administrator privileges to create TUN devices and routes.

## Features

- Full subnet routing (not just single-port forwarding)
- End-to-end encryption via QUIC/TLS 1.3 (iroh transport)
- NAT traversal with relay fallback
- Token-based authentication
- Optional dual-stack VPN (IPv4 + IPv6)
- Optional split tunneling (`--route` / `--route6`)
- Auto-reconnect with heartbeat-based health checks
- Automatic Linux TUN GSO offload with software segmentation fallback when a peer does not support GSO (e.g., mixed-OS peers)

## Protocol and Linux GSO

- Wire protocol v3 is required on both peers. Mixed-version pairs will not connect.
- On Linux, TUN offload is attempted automatically at startup (`vnet_hdr` + TCP GSO flags).
- No GSO config toggle is exposed in config files.
- If Linux offload setup fails, VPN traffic continues in non-GSO mode and logs a warning.
- Connection setup logs include local, remote, and negotiated GSO status.

## Throughput Tuning

For maximum throughput on direct P2P paths, configure the QUIC transport in the
`[iroh.transport]` section of the **server** config (see `vpn_server.toml.example`).
The server dictates these settings to clients during the handshake, so clients
need no transport configuration:

- `congestion_controller = "bbr"` — TCP carried through the tunnel reacts to its own
  congestion signals; when the underlying UDP path also drops packets, the default
  loss-based `cubic` compounds the backoff. BBR models the path instead of reacting to
  loss and typically sustains higher throughput on lossy or high-latency direct paths.
- `receive_window` / `send_window` — the 8 MB defaults cover most links. On
  high-bandwidth, high-latency paths (large bandwidth-delay product), raise them toward
  the 16 MB maximum so the window does not cap throughput at `window / RTT`.

`cubic` remains the default because it is the safer choice for relay paths and
general internet use.

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

Running `vpn-rs.exe` requires `wintun.dll` from <https://www.wintun.net/> (official WireGuard project site):

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
cargo install --path .
```

Or build a release binary directly:

```bash
cargo build --release
```

## Quick Start

### 1. Generate Server Identity and Auth Token

```bash
vpn-rs generate-server-key --output ./vpn-server.key
AUTH_TOKEN=$(vpn-rs generate-token)
echo "$AUTH_TOKEN"
```

Token format:
- Exactly 47 characters
- Prefix `v`
- Followed by 46 Base64URL (no padding) characters

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
| `--route <CIDR>` | Additional IPv4 routes through VPN (repeatable) |
| `--route6 <CIDR>` | Additional IPv6 routes through VPN (repeatable) |
| `--relay-url <URL>` | Custom relay URL(s) |
| `--dns-server <URL|none>` | Custom iroh discovery server, or disable DNS discovery |
| `--auto-reconnect` | Force-enable reconnect |
| `--no-auto-reconnect` | Disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |

Use `vpn_server.toml.example` and `vpn_client.toml.example` for full tunables. MTU and transport tuning are server-side settings dictated to clients during the handshake.

MTU accepts `576-9216` (default `1440`). A jumbo MTU (e.g. `9000`) significantly raises throughput on clients whose TUN does one packet per syscall (notably macOS `utun`, which has no GSO) — it roughly tripled macOS sender throughput in testing. **Only use jumbo when tunneled traffic stays VPN-to-VPN (split tunnel / site-to-site / LAN);** in full-tunnel mode a large inner packet egressing to the internet through a ~1500-MTU path causes fragmentation or PMTUD blackholes. **For IPv6-only or dual-stack deployments, keep the MTU at or above `1280`** — IPv6 mandates a 1280-byte minimum link MTU, so a lower value causes fragmentation/packet loss on the IPv6 path. See `vpn_server.toml.example` for the full rationale.

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

## External NAT64 (Linux + TAYGA)

`vpn-rs` no longer implements NAT64 translation internally.

For IPv6-only clients that need IPv4 reachability, run TAYGA as external host infrastructure and route `64:ff9b::/96` through the VPN from clients. Full setup instructions:

- [`docs/TAYGA_NAT64.md`](docs/TAYGA_NAT64.md)

## Self-Hosted Iroh Infrastructure

`vpn-rs` supports self-hosted relay and discovery services. See:

- [`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md)
- [`docs/iroh-relay-connection-trace.md`](docs/iroh-relay-connection-trace.md)

## Architecture

Detailed internals and flow diagrams:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Single Instance Lock

Only one `vpn-rs client` instance runs at a time per machine to avoid route and TUN conflicts.
