# vpn-rs

**A composable, cross-platform VPN layer you stack on any tunnel. Loopback-only, IP-over-TCP/UDP. Bring your own transport.**

`vpn-rs` is a **composable VPN layer**: it does one job — IP tunneling — and
leaves everything else to a transport you stack underneath it. It creates a TUN
interface and moves IP packets between it and a **plain socket bound to loopback**
(TCP by default, or UDP via `--transport`). It deliberately does *not* do
encryption, authentication, NAT traversal, or cross-network transport — you
supply those by running any **tunnel** process on the same host (e.g.
[`tunnel-rs`](https://github.com/andrewtheguy/tunnel-rs),
[`duopipe`](https://github.com/andrewtheguy/duopipe), an SSH tunnel, or any
loopback forwarder). Swap the tunnel and the VPN is unchanged.

```text
      host A (client)                                   host B (server)
 ┌───────────────────────┐                         ┌───────────────────────┐
 │  vpn-rs client        │                         │        vpn-rs server  │
 │   TUN ⇅ 127.0.0.1     │                         │   127.0.0.1 ⇅ TUN     │
 │            │          │                         │          │            │
 │      local tunnel  ───┼──── encrypted link ─────┼──→  local tunnel      │
 └───────────────────────┘     (tunnel-rs/etc)     └───────────────────────┘
```

The VPN server binds **only loopback addresses** and is unreachable directly; the
tunnel on each host carries the loopback traffic across the network.

> [!IMPORTANT]
> **Project Goal:** `vpn-rs` is a *modular* VPN — the IP-routing layer factored out
> from transport and crypto so you can mix and match. That composability costs an
> extra hop through a local socket and a second process, so it is generally **less
> performant than an integrated VPN** (WireGuard, OpenVPN, …) that fuses tunneling
> and encrypted transport into one datapath. It is built for development, homelab,
> and experimentation — not production at scale.

> [!WARNING]
> **No Backward Compatibility in 0.0.x:** while `vpn-rs` remains in `0.0.x`, there is no compatibility between versions — refresh configs on every upgrade. The current wire protocol is **v4** and older peers are rejected.

> [!NOTE]
> Running `vpn-rs` requires root/Administrator privileges to create TUN devices and routes.

> [!NOTE]
> For a design overview — wire protocol, server/client task graph, GSO capping, and
> the threat model — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## A composable VPN layer

Most VPNs are *integrated*: a single binary fuses IP tunneling, encryption /
authentication, and cross-network transport into one datapath. `vpn-rs` takes the
opposite stance — it factors out **just the IP-tunneling layer** and lets you
stack it on whatever transport you already trust:

- **Compose, don't reinvent.** Encrypted transport and NAT traversal are solved
  well by dedicated projects, so `vpn-rs` speaks **plain TCP or UDP to localhost**
  and rides any loopback tunnel ([`tunnel-rs`](https://github.com/andrewtheguy/tunnel-rs),
  [`duopipe`](https://github.com/andrewtheguy/duopipe), an SSH tunnel, …). Pick
  the transport that matches your tunnel with `--transport tcp` (default) or
  `--transport udp`.
- **The tunnel owns security.** Encryption + authentication live in the tunnel;
  the loopback bind keeps the VPN off the network entirely, so it is only ever
  reachable through that tunnel.
- **Mind the stacking.** With **UDP** the VPN is datagram-based, so there is no
  TCP-over-TCP meltdown when carried over a UDP tunnel. With **TCP** it can ride a
  stream tunnel (including SSH port-forwarding); avoid stacking it on a second
  lossy TCP path.
- **The tradeoff.** The extra local-socket hop and the separate tunnel process
  make this modular design **less performant than an integrated VPN**. You trade
  peak throughput for the freedom to swap transports — or drop in a new one —
  without touching the VPN.

## Features

- Selectable transport: **TCP** (default) or **UDP** (`--transport`)
- Full subnet routing (not just single-port forwarding)
- Multi-client server: keyed by connection (TCP) or by UDP source address (UDP)
- VPN address family can be IPv4-only, IPv6-only, or dual-stack
- Optional split tunneling (`--route` / `--route6`)
- Auto-reconnect with heartbeat-based health checks; idle clients are reaped
- Automatic Linux TUN GSO offload with software segmentation fallback for peers
  without GSO (e.g. mixed-OS); on UDP, super-frames are additionally capped to a
  single datagram / your tunnel's limit

## Protocol and Linux GSO

- Wire protocol **v4** is required on both peers. Mixed-version pairs are rejected.
- **UDP**: each datagram carries exactly one VPN message (no length prefix).
  **TCP**: messages are length-prefixed frames on the byte stream.
- On Linux, TUN offload is attempted automatically at startup (`vnet_hdr` + TCP
  GSO flags). If it fails, traffic continues in non-GSO mode and logs a warning.
- On UDP, outbound offload super-frames are segmented when they would exceed
  `max_datagram_size` (default 65507, the UDP payload ceiling). Lower it if your
  tunnel cannot carry large datagrams. TCP re-segments on the stream, so no cap
  applies.

## Installation

You only need the `vpn-rs` binary in your `PATH`, plus a loopback tunnel of your choice.

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

The example below uses the default **TCP** transport; substitute your real
encrypted tunnel ([`tunnel-rs`](https://github.com/andrewtheguy/tunnel-rs),
[`duopipe`](https://github.com/andrewtheguy/duopipe), …). The VPN config is
identical regardless of which tunnel you use; set `--transport udp` (and a
matching UDP tunnel) if you prefer UDP.

### 1. Server host

Create `vpn_server.toml` (copy from `vpn_server.toml.example`):

```toml
role = "vpnserver"

[server]
listen  = "127.0.0.1:5555"

# Choose the VPN address family:
#   IPv4-only:  set network only
#   IPv6-only:  set network6 only
#   Dual-stack: set both network and network6
network = "10.0.0.0/24"
# network6 = "fd00::/64"   # IPv6 pool; use /126 or wider
```

Start the VPN server (binds loopback only) and a tunnel that delivers remote
traffic to `127.0.0.1:5555`:

```bash
sudo vpn-rs server -c vpn_server.toml
# + your tunnel terminating on this host, forwarding to tcp/127.0.0.1:5555
#   (use --transport udp on both ends for a UDP tunnel)
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

To test the VPN by itself without an external tunnel, run the server and client
in the same network namespace so they share loopback. If you isolate them in
separate network namespaces, each namespace has its own loopback device, so you
still need a UDP forwarder/tunnel between namespaces — or use [test mode](#test-mode),
which lets the two ends talk directly over a non-loopback address.

## CLI Reference

### Server

`vpn-rs server` requires a config file:

- `-c, --config <FILE>`
- `--default-config` (uses `~/.config/vpn-rs/vpn_server.toml`)
- `--transport <tcp|udp>` (default `tcp`; overrides the config's `transport`)
- `--test-mode` (allow a non-loopback `listen`; see [Test mode](#test-mode))

All server tunables live in the config file — see `vpn_server.toml.example`.

### Client

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Client config path |
| `--default-config` | Use `~/.config/vpn-rs/vpn_client.toml` |
| `--transport <tcp\|udp>` | Transport carrying VPN traffic (default `tcp`; overrides config) |
| `-s, --server-addr <ADDR>` | Loopback address of the local tunnel (default `127.0.0.1:5555`) |
| `--route <CIDR>` | Additional IPv4 routes through the VPN (repeatable) |
| `--route6 <CIDR>` | Additional IPv6 routes through the VPN (repeatable) |
| `--auto-reconnect` / `--no-auto-reconnect` | Force-enable / disable reconnect |
| `--max-reconnect-attempts <N>` | Limit reconnect attempts |
| `--test-mode` | Allow a non-loopback `server_addr`; see [Test mode](#test-mode) |
| `--test-token <TOKEN>` | Token printed by the test server (required with `--test-mode`) |

MTU (server-side, dictated to clients) accepts `576-9216` (default `1440`). A
jumbo MTU raises throughput on clients whose TUN does one packet per syscall
(notably macOS `utun`, no GSO). **Only use jumbo when tunneled traffic stays
VPN-to-VPN (split tunnel / site-to-site / LAN).** **For IPv6-only or dual-stack,
keep MTU ≥ `1280`.**

Both the server and client enlarge their kernel socket buffers (`SO_RCVBUF` /
`SO_SNDBUF`) to **4 MiB each by default** so the kernel can absorb bursty
multi-Gbit traffic instead of silently dropping it (on UDP, drops show
up as inner-TCP retransmits in `iperf3`). Tune with `recv_buffer_size` /
`send_buffer_size` (bytes, `65536-1073741824`) in the `[server]` / `[client]`
TOML section. The **receive buffer is the one that matters** — it absorbs
inbound bursts, and a too-small `SO_RCVBUF` is what shows up as drops; the send
buffer rarely bottlenecks a tunnel. **Linux caps the request at
`net.core.rmem_max` / `net.core.wmem_max`**, so raise `net.core.rmem_max` first
(e.g. `sysctl -w net.core.rmem_max=16777216`) to actually use a larger buffer — a
startup log reports the requested-vs-applied size and warns when the kernel
capped it.

## Loopback enforcement

The server's `listen` and the client's `server_addr` are **hard-locked to
loopback** (`127.0.0.0/8`, `::1`, or IPv4-mapped loopback); any other address is
rejected at startup. This guarantees the VPN is only reachable through the local
tunnel, on either transport. On **TCP** each client is its own connection. On
**UDP** clients are distinguished by source address, so the tunnel must present
each client from a distinct local port (the usual behavior of per-flow UDP
forwarders).

The **only** exception is [test mode](#test-mode), an explicit opt-in for
testing the VPN directly between hosts without a tunnel.

## Test mode

> [!WARNING]
> Test mode runs the VPN **directly on the network with no encryption or
> authentication on the wire** (the tunnel normally provides those). Use it only
> for testing on trusted networks (such as benchmarking), never for production
> traffic.

Test mode lets the server bind — and the client connect to — a **non-loopback**
address, so you can run the VPN host-to-host without an external tunnel. It is
gated several ways so it can never be entered by accident:

- **`--test-mode` flag is required** on both server and client.
- **A dedicated config role is required** and must match the flag: the server
  needs `role = "testvpnserver"`, the client `role = "testvpnclient"`. Running
  `--test-mode` against a normal role (or a test role without `--test-mode`) is a
  startup error. See `vpn_server_test.toml.example` / `vpn_client_test.toml.example`.
- **A per-run token is required.** The server generates a **random token** at
  startup and logs it; each client must pass it with `--test-token <TOKEN>`. A
  handshake with the wrong, missing, or unexpected token is rejected. Because a
  non-test server has no token and a test server always has one, **test and
  non-test instances cannot connect to each other** in either direction.
- **Auto-stop.** A test-mode server or client stops itself automatically after
  **30 minutes**, so a forgotten test instance does not linger on the network.

```bash
# Server (binds a non-loopback address; prints a random --test-token to use)
sudo vpn-rs server --test-mode -c vpn_server_test.toml

# Client (supply the token the server logged)
sudo vpn-rs client --test-mode --test-token <TOKEN> -s <server-ip>:5555
```

## Benchmarking

Test mode doubles as the benchmark harness: it carries traffic directly on the
network with no external tunnel, so it measures **the VPN packet pipeline by
itself**. Use the default **TCP** transport for a clean baseline — a single
direct connection with end-to-end backpressure, so on a LAN there are no
datagram drops and effectively zero inner-TCP retransmits.

```bash
# Server (TCP is the default transport)
sudo vpn-rs server --test-mode -c vpn_server_test.toml   # prints a --test-token

# Client
sudo vpn-rs client --test-mode --test-token <TOKEN> -s <server-ip>:5555

# Then drive traffic across the tunnel:
iperf3 -s            # on the server host (its VPN gateway IP, e.g. 10.0.0.1)
iperf3 -c 10.0.0.1   # on the client host
```

Raise the server's `mtu` (e.g. `9000` in the config) to benchmark past the
single-packet-per-syscall ceiling; the TCP transport re-segments on the stream,
so no jumbo physical frames are needed. Compare against `--transport udp` to see
the datagram path. Like all test-mode runs, each end **stops itself after 30
minutes**.

## Single Instance Lock

Only one `vpn-rs client` instance runs at a time per machine to avoid route and
TUN conflicts.
