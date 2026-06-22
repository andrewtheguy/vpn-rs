# vpn-rs

**Single-purpose, cross-platform IP-over-UDP VPN. Loopback-only. Bring your own tunnel.**

`vpn-rs` does one job: VPN tunneling. It creates a TUN interface and moves IP
packets between it and a **plain UDP socket bound to loopback**. It does *not*
do encryption, authentication, NAT traversal, or transport across the network —
that is the job of a separate **tunnel** process (e.g.
[`tunnel-rs`](https://github.com/andrewtheguy), `duopipe`, or any UDP forwarder)
running on the same host.

```text
      host A (client)                                   host B (server)
 ┌───────────────────────┐                         ┌───────────────────────┐
 │  vpn-rs client        │                         │        vpn-rs server  │
 │   TUN ⇅ UDP 127.0.0.1 │                         │ 127.0.0.1 UDP ⇅ TUN   │
 │            │          │                         │          │            │
 │      local tunnel  ───┼──── encrypted link ─────┼──→  local tunnel      │
 └───────────────────────┘     (tunnel-rs/etc)     └───────────────────────┘
```

The VPN server binds **only** `127.0.0.1`/`::1` and is unreachable directly; the
tunnel on each host carries the loopback datagrams across the network.

> [!IMPORTANT]
> **Project Goal:** `vpn-rs` is built for development and homelab use. It is not intended for production at scale.

> [!WARNING]
> **No Backward Compatibility in 0.0.x:** while `vpn-rs` remains in `0.0.x`, there is no compatibility between versions — refresh configs on every upgrade. The current wire protocol is **v4** and older peers are rejected.

> [!NOTE]
> Running `vpn-rs` requires root/Administrator privileges to create TUN devices and routes.

> [!NOTE]
> For a design overview — wire protocol, server/client task graph, GSO capping, and
> the threat model — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Why a separate tunnel?

Encrypted/authenticated transport and NAT traversal are already solved well by
dedicated projects. Coupling them into the VPN duplicated that effort, so it was
removed. `vpn-rs` now speaks **plain UDP datagrams to localhost**:

- It rides any **UDP tunnel** (`tunnel-rs`, `duopipe`, …). Because the VPN is
  datagram-based, there is no TCP-over-TCP meltdown.
- SSH port-forwarding is **not** supported, because SSH cannot forward UDP.
- The tunnel owns encryption + authentication; the loopback bind keeps the VPN
  off the network entirely.

## Features

- Full subnet routing (not just single-port forwarding)
- Multi-client server, keyed by UDP source address
- Optional dual-stack VPN (IPv4 + IPv6)
- Optional split tunneling (`--route` / `--route6`)
- Auto-reconnect with heartbeat-based health checks; idle clients are reaped
- Automatic Linux TUN GSO offload with software segmentation fallback for peers
  without GSO (e.g. mixed-OS), and datagram-size capping so super-frames fit a
  single UDP datagram / your tunnel's limit

## Protocol and Linux GSO

- Wire protocol **v4** is required on both peers. Mixed-version pairs are rejected.
- Each UDP datagram carries exactly one VPN message (no length prefix).
- On Linux, TUN offload is attempted automatically at startup (`vnet_hdr` + TCP
  GSO flags). If it fails, traffic continues in non-GSO mode and logs a warning.
- Outbound offload super-frames are segmented when they would exceed
  `max_datagram_size` (default 65507, the UDP payload ceiling). Lower it if your
  tunnel cannot carry large datagrams.

## Installation

You only need the `vpn-rs` binary in your `PATH`, plus a UDP tunnel of your choice.

### Linux and macOS

```bash
curl -sSL https://andrewtheguy.github.io/vpn-rs/install.sh | sudo bash
```

### Windows

```powershell
irm https://andrewtheguy.github.io/vpn-rs/install.ps1 | iex
```

Running `vpn-rs.exe` on Windows requires `wintun.dll` from <https://www.wintun.net/>
next to the binary or in `PATH`.

### From source

```bash
cargo build --release   # or: cargo install --path .
```

## Quick Start

The example below tunnels with a UDP forwarder; substitute your real encrypted
tunnel (`tunnel-rs`, `duopipe`, …). The VPN config is identical regardless of
which tunnel you use.

### 1. Server host

Create `vpn_server.toml` (copy from `vpn_server.toml.example`):

```toml
role = "vpnserver"

[server]
listen  = "127.0.0.1:5555"
network = "10.0.0.0/24"
# network6 = "fd00::/64"   # optional dual-stack
```

Start the VPN server (binds loopback only) and a tunnel that delivers remote
traffic to `127.0.0.1:5555`:

```bash
sudo vpn-rs server -c vpn_server.toml
# + your tunnel terminating on this host, forwarding to udp/127.0.0.1:5555
```

### 2. Client host

Create `vpn_client.toml` (copy from `vpn_client.toml.example`):

```toml
role = "vpnclient"

[client]
server_addr = "127.0.0.1:5555"   # the LOCAL tunnel endpoint
routes      = ["0.0.0.0/0"]      # optional: full tunnel
```

Run a tunnel that listens on `127.0.0.1:5555` and forwards to the server host's
tunnel, then start the VPN client:

```bash
sudo vpn-rs client -c vpn_client.toml
```

### 3. Verify

```bash
ping 10.0.0.1     # the server's VPN gateway IP
```

To test the VPN by itself (no external tunnel), run the server and client on one
host in separate network namespaces — the client connects straight to the
server's loopback port.

## CLI Reference

### Server

`vpn-rs server` requires a config file:

- `-c, --config <FILE>`
- `--default-config` (uses `~/.config/vpn-rs/vpn_server.toml`)

All server tunables live in the config file — see `vpn_server.toml.example`.

### Client

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Client config path |
| `--default-config` | Use `~/.config/vpn-rs/vpn_client.toml` |
| `-s, --server-addr <ADDR>` | Loopback UDP address of the local tunnel (default `127.0.0.1:5555`) |
| `--route <CIDR>` | Additional IPv4 routes through the VPN (repeatable) |
| `--route6 <CIDR>` | Additional IPv6 routes through the VPN (repeatable) |
| `--auto-reconnect` / `--no-auto-reconnect` | Force-enable / disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |

MTU (server-side, dictated to clients) accepts `576-9216` (default `1440`). A
jumbo MTU raises throughput on clients whose TUN does one packet per syscall
(notably macOS `utun`, no GSO). **Only use jumbo when tunneled traffic stays
VPN-to-VPN (split tunnel / site-to-site / LAN).** **For IPv6-only or dual-stack,
keep MTU ≥ `1280`.**

## Loopback enforcement

The server's `listen` and the client's `server_addr` are **hard-locked to
loopback** (`127.0.0.1`/`::1`); any other address is rejected at startup. This
guarantees the VPN is only reachable through the local tunnel. Multiple clients
are distinguished by their UDP source address, so the tunnel must present each
client from a distinct local port (the usual behavior of per-flow UDP
forwarders).

## External NAT64 (Linux + TAYGA)

`vpn-rs` does not implement NAT64. For IPv6-only clients that need IPv4
reachability, run TAYGA as external infrastructure and route `64:ff9b::/96`
through the VPN. See [`docs/TAYGA_NAT64.md`](docs/TAYGA_NAT64.md).

## Single Instance Lock

Only one `vpn-rs client` instance runs at a time per machine to avoid route and
TUN conflicts.
