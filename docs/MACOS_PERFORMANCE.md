# macOS Performance

This document records why macOS VPN throughput is constrained, what vpn-rs
does about it, and which knobs are available. It also records why we
deliberately do **not** use Apple's Network Extension framework.

## TL;DR

| Lever | Status |
|---|---|
| Batched UDP syscalls (`sendmsg_x`/`recvmsg_x`) | Enabled via patched `netwatch` (see below) |
| Jumbo tunnel MTU | Available via server `mtu` config (e.g. 8000–16000) |
| Large UDP socket buffers | Already requested by netwatch (7 MB each direction) |
| TUN-side batching / offload | Impossible on macOS utun — OS limitation |
| Network Extension (`NEPacketTunnelProvider`) | Rejected for the CLI — see rationale below |

## Why macOS is slower than Linux

### utun is one packet per syscall, by design

The macOS TUN device (`utun`, a `PF_SYSTEM`/`SYSPROTO_CONTROL` socket) moves
exactly one IP packet per `read()`/`write()`. There is no batching API and no
offload (TSO/GSO/checksum) interface — nothing like Linux's `TUNSETOFFLOAD`,
which lets a single 64 KB superframe carry dozens of TCP segments across the
user/kernel boundary. For reference, wireguard-go hardcodes
`BatchSize() == 1` in its Darwin TUN driver, and all of Tailscale's published
throughput work (TSO/GRO + `sendmmsg`, 2.4 → 10+ Gbit/s) is Linux-only.

vpn-rs already minimizes the per-packet cost on macOS: the TUN fd is driven
directly through tokio's `AsyncFd` with `readv()`/`writev()` so the 4-byte
utun address-family header is handled without copying the payload
(`src/vpn_core/device.rs`). That removes a memcpy per packet, but the
syscall-per-packet floor remains — it is an OS constraint, not a vpn-rs one.

### What vpn-rs does instead

Per-packet syscalls get cheaper when each packet carries more bytes, and the
UDP side *does* have a batching API:

1. **Batched UDP datapath** — macOS has private `sendmsg_x`/`recvmsg_x`
   syscalls that send/receive up to 32 UDP datagrams per call (the Darwin
   analogue of Linux `sendmmsg`/`recvmmsg`; same mechanism Mozilla added to
   quinn-udp for Firefox). iroh's UDP layer (`noq-udp`) implements this
   behind the `fast-apple-datapath` feature and resolves the symbols via
   `dlsym` at runtime, automatically falling back to plain
   `sendmsg`/`recvmsg` when unavailable — so enabling it is safe on every
   macOS version. However, as of iroh 1.0.0-rc.1 nothing in the stack ever
   *activates* the fast path at runtime (`UdpSocketState::set_apple_fast_path`
   is never called). vpn-rs therefore pins a patched `netwatch` via
   `[patch.crates-io]` (`andrewchen5678/net-tools`, branch
   `apple-fast-datapath`) that activates it on every socket it binds.

   Verifying it is active: run with `RUST_LOG=netwatch=debug` and look for
   `enabled Apple fast UDP datapath (sendmsg_x/recvmsg_x)`.

   The patch can be dropped from `Cargo.toml` once upstream
   (n0-computer/net-tools) ships an equivalent.

2. **Jumbo tunnel MTU** — vpn-rs carries IP packets over a *reliable QUIC
   stream*, so the tunnel MTU is decoupled from the physical path MTU (QUIC
   handles its own path-MTU discovery on the outer connection, and stream
   data is segmented to fit). Raising the server's `mtu` setting (default
   1440) means TCP flows inside the tunnel negotiate a larger MSS, so the
   same throughput needs proportionally fewer utun syscalls on macOS — the
   software analogue of what GSO/GRO provides on Linux. utun accepts large
   MTUs in socket mode (the `SIOCSIFMTU` handler in xnu's `if_utun.c` applies
   no upper bound there).

   Suggested experiment for throughput-oriented deployments: set `mtu = 8000`
   (or sweep 4000/8000/16000) in the server config and measure with iperf3
   through the tunnel. Trade-offs: larger packets slightly increase
   head-of-line blocking latency for interactive traffic on lossy paths, and
   both sides buffer proportionally more per queued packet.

3. **Socket buffers** — netwatch already requests 7 MB `SO_RCVBUF`/`SO_SNDBUF`
   on the UDP sockets. macOS caps these at `kern.ipc.maxsockbuf` (8 MB by
   default); if you see `failed to set recv_buffer_size` in
   `RUST_LOG=netwatch=debug` output, raise it:

   ```sh
   sudo sysctl -w kern.ipc.maxsockbuf=16777216
   ```

## Why not the "native" macOS network stack (Network Extension)?

`NEPacketTunnelProvider` is the only macOS API with batched TUN packet I/O
(`NEPacketTunnelFlow.readPackets`/`writePackets` operate on arrays of
packets). It was considered and rejected for vpn-rs because it is
incompatible with single-binary CLI distribution:

- It must run as a **system extension embedded in a signed `.app` bundle**
  installed under `/Applications` — it cannot be a standalone binary.
- It requires the `com.apple.developer.networking.networkextension`
  entitlement, which means an Apple Developer Program membership ($99/yr),
  code signing with that team, a provisioning profile, and notarization.
- Installation triggers the System Extension user-approval flow in System
  Settings.

That abandons the `install.sh` / single-binary model entirely. Tailscale
ships *both* shapes for this reason: an open-source `tailscaled` on raw utun
(same architecture as vpn-rs) and a closed-source GUI app on Network
Extension. If a signed macOS `.app` distribution is ever wanted, NE is the
path — as a separate packaging track reusing the Rust core as a library, not
a refactor of the CLI.

## Benchmarking checklist

Compare configurations with iperf3 through the tunnel (macOS client against
a Linux server), watching client CPU:

1. Baseline.
2. With the batched UDP datapath (confirm the netwatch debug log line).
3. Same, plus jumbo tunnel MTU (sweep `mtu = 4000 / 8000 / 16000`).

Sanity-check interactive latency (`ping` through the tunnel under load)
doesn't regress at high MTU before standardizing on a value.
