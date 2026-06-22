# vpn-rs Architecture

`vpn-rs` is a **single-purpose IP-over-UDP VPN**. It creates a TUN device and
moves IP packets between it and a **plain UDP socket bound to loopback**. It does
*not* do encryption, authentication, NAT traversal, or cross-network transport —
those belong to a separate **tunnel** process (e.g. `tunnel-rs`, `duopipe`, or any
UDP forwarder) running on the same host.

```text
      host A (client)                                   host B (server)
 ┌───────────────────────┐                         ┌───────────────────────┐
 │  vpn-rs client        │                         │        vpn-rs server  │
 │   TUN ⇅ UDP 127.0.0.1 │                         │ 127.0.0.1 UDP ⇅ TUN   │
 │            │          │                         │          │            │
 │      local tunnel  ───┼──── encrypted link ─────┼──→  local tunnel      │
 └───────────────────────┘     (tunnel-rs/etc)     └───────────────────────┘
```

The VPN server binds **only loopback addresses** and is unreachable directly; the
tunnel on each host carries the loopback datagrams across the network. This is
the security boundary — the VPN itself has no transport-level auth or crypto, so
it relies on (a) never being on the network, and (b) the tunnel isolating peers.

## Design principles

- **Do one thing.** VPN tunneling only. Transport/crypto/NAT-traversal are
  explicitly *out of scope* and delegated to the external tunnel.
- **Datagram-oriented.** One UDP datagram = one VPN message. No length prefix; the
  datagram boundary *is* the message length. Because the VPN is datagram-based,
  riding a UDP tunnel avoids TCP-over-TCP meltdown. SSH port-forwarding is
  unsupported (SSH cannot forward UDP).
- **Loopback-locked.** The server `listen` and client `server_addr` are hard-locked
  to loopback addresses (`127.0.0.0/8`, `::1`, or IPv4-mapped loopback) with no
  override (`ensure_loopback`, [`udp.rs`](../src/vpn_core/udp.rs)). The lone
  exception is [test mode](#test-mode), an explicit opt-in for tunnel-less testing.
- **No backward compatibility** while in `0.0.x`. The wire protocol is **v4**; peers
  on any other version are rejected.

## Module map

All VPN logic lives in `src/vpn_core/` (a module inside the binary crate). `main.rs`
is the CLI shell (`server` / `client` subcommands only).

| Module | Responsibility |
|--------|----------------|
| [`udp.rs`](../src/vpn_core/udp.rs) | Loopback enforcement (`ensure_loopback`), server bind, client connect |
| [`udp_offload.rs`](../src/vpn_core/udp_offload.rs) | Kernel UDP GSO (`UDP_SEGMENT`) / GRO (`UDP_GRO`) batched send/recv, with plain fallback |
| [`datagram.rs`](../src/vpn_core/datagram.rs) | One-message-per-datagram framing; MTU-derived datagram-size cap |
| [`signaling.rs`](../src/vpn_core/signaling.rs) | Handshake JSON, `DataMessageType`, capabilities, IP-body parse |
| [`server.rs`](../src/vpn_core/server.rs) | `recv_from` demux, IP pools, reaper, TUN reader, routing |
| [`client.rs`](../src/vpn_core/client.rs) | Connect, handshake-with-retransmit, the 4 tunnel tasks, reconnect |
| [`config.rs`](../src/vpn_core/config.rs) | Runtime config structs + `validate()` |
| [`file_config.rs`](../src/vpn_core/file_config.rs) | TOML `[server]` / `[client]` schema → resolved config |
| [`device.rs`](../src/vpn_core/device.rs) | Cross-platform TUN creation + route management |
| [`offload.rs`](../src/vpn_core/offload.rs) | Linux GSO/GRO: virtio_net_hdr, software segmentation + coalescing |
| [`buffer.rs`](../src/vpn_core/buffer.rs) | Reusable receive/scratch buffers |
| [`lock.rs`](../src/vpn_core/lock.rs) | Single-instance client lock |
| [`error.rs`](../src/vpn_core/error.rs) | `VpnError` / `VpnResult`; recoverable-vs-permanent classification |

## Wire protocol (v4)

Two datagram kinds share the single UDP socket. They are disambiguated by the
**first byte**:

- **Handshake** datagrams are raw JSON, so they start with `{` (`0x7b`).
- **Data** datagrams start with a [`DataMessageType`](../src/vpn_core/signaling.rs)
  byte in `0x00..=0x03`, which can never be `{`.

### Handshake (JSON over UDP)

```
client → server : VpnHandshake          { version: 4, device_id: u64, test_token? }
server → client : VpnHandshakeResponse   { version, accepted, server_gso_enabled,
                                           mtu, assigned_ip[/6], network[/6],
                                           server_ip[/6], reject_reason? }
```

`device_id` is a random `u64` per client session. The server keys IP-pool
allocation by `device_id` (not by socket address), so a client that reconnects
from a new ephemeral UDP port keeps its previously-assigned VPN IP.

`test_token` is omitted (`skip_serializing_if`) outside [test mode](#test-mode),
so normal handshakes are unchanged on the wire. In test mode the server checks
`config.test_token == handshake.test_token` **before any allocation** and rejects
on mismatch. Since a non-test server holds `None` and a test server holds
`Some(token)`, this equality also makes test and non-test peers mutually
incompatible in both directions.

### Data channel

One datagram per message; layout by leading type byte:

| Type | Byte | Layout |
|------|------|--------|
| IP packet | `0x00` | `[0x00] [offload_len:1] [offload:0\|10] [ip_packet]` |
| Heartbeat ping | `0x01` | `[0x01]` |
| Heartbeat pong | `0x02` | `[0x02]` |
| Capabilities | `0x03` | `[0x03] [payload_len:1] [payload]` |

The `offload` block (when present) is a 10-byte `virtio_net_hdr` carrying TCP-GSO
metadata. `encode_ip_datagram` / `parse_ip_packet_v2` are the encode/decode pair.
Capabilities currently carry a single GSO-support bit; unknown trailing bytes are
ignored for forward compatibility.

## Server runtime

`VpnServer::new(config)` builds the TUN device and IP pools; `run(socket)` spawns
the task graph and enters the receive loop.

### State

- `clients: DashMap<SocketAddr, ClientState>` — one entry per active UDP flow.
  `ClientState` holds `device_id`, assigned IPs, GSO flags, and an
  `last_seen: AtomicU64` (millis) for liveness.
- `device_to_addr: DashMap<u64, SocketAddr>` — current flow for each device, used
  for max-client counting and reconnect/"move" handling.
- `ip_to_addr` / `ip6_to_addr: DashMap<IpAddr, SocketAddr>` — reverse routing index
  for TUN → client, and the source-IP ownership check for anti-spoofing.
- `IpPool` / `Ip6Pool` — allocation keyed by `device_id`, with existing-IP
  idempotency so a retransmitted handshake reuses the same address.

### Tasks (spawned by `run`)

1. **Main `recv_from` loop** — demux by first byte: `{` → `handle_handshake`,
   else → `handle_client_datagram`. Bumps `last_seen` on every datagram.
2. **Outbound sender** — drains an `mpsc<(SocketAddr, Bytes)>` and `send_to`s each
   datagram to its client. Single shared writer (replaces per-client QUIC streams).
3. **TUN reader** (`run_tun_reader`) — reads IP packets from the TUN device, looks
   up the destination IP in `ip_to_addr` / `ip6_to_addr`, frames via
   `encode_ip_datagram`, and enqueues to the outbound channel. Software-GRO state is
   keyed per client `SocketAddr`.
4. **TUN writer** — drains inbound IP packets and writes them to the TUN device.
5. **Reaper** (`run_reaper`) — periodically reaps clients whose `last_seen` is older
   than `client_timeout`. UDP has no FIN, so this is the only way idle/dead clients
   are cleaned up. IPs are released **only** if the addr is still the device's
   current addr (so a "move" doesn't release a live client's IP).

### Handshake handling (idempotent)

`handle_handshake` is safe to call for retransmits:

- **New device** under `max_clients` → allocate IPs, insert maps, send accept.
- **Known device, same addr** → re-send the same response (lost-response retransmit).
- **Known device, new addr** ("move") → update `device_to_addr` and the reverse maps
  to the new addr, drop the old `clients` entry, **keep** the IP allocation.
- **At capacity** → send a rejection (`reject_reason`).

### Anti-spoofing

Unless `disable_spoofing_check` is set, `source_ip_allowed` rejects an IP packet
whose source address is owned by a *different* client (compared against
`ip_to_addr` / `ip6_to_addr`). With no transport auth, this is the only inter-client
protection at the VPN layer.

## Client runtime

`VpnClient::connect()`:

1. `connect_client_socket(server_addr, allow_non_loopback)` — bind an ephemeral
   local socket (loopback, or the unspecified address in test mode), `connect()`
   to the target so `send`/`recv` are pinned to the server.
2. `perform_handshake` — send `VpnHandshake`, await a response with a 2s timeout,
   retransmit up to `HANDSHAKE_RETRIES` (5) times. Handles datagram loss.
3. Build the TUN device + routes from the accepted response; send a capabilities
   datagram.
4. `run_udp_tunnel` — run the four data-path tasks until one fails.

### Tunnel tasks

| Task | Role |
|------|------|
| **outbound** | TUN read → frame (`build_datagrams`, GSO cap applied) → `socket.send` |
| **inbound** | `socket.recv` → `classify` → IP to TUN-writer, ping → pong |
| **tun_writer** | batched writes to the TUN device (tolerates a bounded failure count) |
| **heartbeat** | every 10s send a ping; if no pong arrives for 30s, declare the connection lost |

`run_with_reconnect(max_attempts)` wraps `connect()` with exponential backoff
(1s → 2s → … capped at 60s, plus jitter), retrying only on recoverable errors
(`ConnectionLost` / `Network` / `Signaling`), never on `Config` / `TunDevice` /
`AuthenticationFailed`.

## GSO/GRO offload and the datagram cap

On Linux the kernel can hand the server ~64 KB TCP-GSO "super-frames" over the TUN
device (and coalesce inbound packets via software GRO). A super-frame bundles
dozens of MSS-sized TCP segments into one IP packet.

### The no-fragment cap

Emitting a super-frame as a single UDP datagram is fine over loopback (MTU 65536),
but the moment it rides a real network (e.g. [test mode](#test-mode), MTU 1500) the
kernel IP-fragments it into ~45 fragments. IPv4 reassembly is all-or-nothing, so a
single lost fragment discards the **whole** super-frame — dozens of TCP segments
retransmitted from one tiny loss. That amplification turns a near-clean link into a
retransmit storm.

To prevent it, the outbound path caps every emitted datagram at
[`datagram_cap_for_mtu(mtu)`](../src/vpn_core/datagram.rs) — the framed size of a
single plain MTU-sized IP packet (`mtu + 2`). `build_datagrams` segments any larger
offload frame with `materialize_offload_into` into ≤cap plain datagrams, so a
super-frame becomes a run of ≤MTU datagrams that **never IP-fragment**; a lost wire
packet now costs exactly one TCP segment. A single sub-MTU packet still rides whole.

- The **client** derives the cap from the server-dictated `mtu` (it has no separate
  knob).
- The **server** uses `min(max_datagram_size, datagram_cap_for_mtu(mtu))`:
  `max_datagram_size` can only *lower* the no-fragment cap further (for a tunnel
  that cannot carry MTU-sized datagrams), never raise it. Raise the **MTU** (e.g. a
  jumbo-frame path) to allow larger datagrams. `max_datagram_size` is
  range-validated to `576..=65507` (`MIN_DATAGRAM_SIZE`).

The receive side (`parse_ip_packet_v2` + `materialize_offload_into`) is already
per-datagram and needs no cap logic.

### Kernel UDP GSO/GRO ([`udp_offload.rs`](../src/vpn_core/udp_offload.rs))

Capping to the MTU turns one super-frame into many small datagrams, which would
otherwise be one `send`/`recv` syscall each. The transport therefore uses kernel
**UDP GSO** on send — a run of equal-sized datagrams goes out in one `sendmsg`
carrying a `UDP_SEGMENT` control message, and the kernel/NIC emits each as an
independent path-MTU wire packet — and **UDP GRO** on receive (`UDP_GRO` sockopt),
where a single `recvmsg` returns several coalesced packets and the caller splits
the buffer back into datagrams by the segment size reported in a control message.
Each wire packet is still one independent ≤MTU UDP datagram, so the
no-fragmentation guarantee holds; GSO/GRO only cut syscall count. Everything
degrades safely to one plain `send`/`recv` per datagram on non-Linux or if the
kernel/NIC rejects GSO.

## Configuration

TOML with a top-level `role` guard and a single `[server]` **or** `[client]`
section ([`file_config.rs`](../src/vpn_core/file_config.rs)):

- **Server:** `listen` (default `127.0.0.1:5555`), `network` / `network6`,
  `server_ip` / `server_ip6`, `mtu` (576–9216, default 1440), `max_clients`,
  `client_timeout_secs` (≥15), `max_datagram_size`, channel sizes, `drop_on_full`,
  `disable_spoofing_check`.
- **Client:** `server_addr` (loopback), `routes` / `routes6`, `auto_reconnect`,
  `max_reconnect_attempts`.

Both `validate()` paths call `ensure_loopback` (unless test mode is active), so a
non-loopback address is rejected at startup before any socket is bound.

`validate()` takes a `test_mode` flag threaded from the `--test-mode` CLI flag.
The `role` guard accepts `vpnserver`/`vpnclient` in normal mode and
`testvpnserver`/`testvpnclient` in test mode, and a flag/role mismatch is a
startup error.

## Test mode

An explicit, multiply-gated escape hatch for testing the VPN directly between
hosts **without a tunnel** — and therefore with no wire encryption or
authentication. Entered only when all gates agree:

- `--test-mode` on the CLI **and** the matching test `role` in the config
  (`testvpnserver` / `testvpnclient`); a mismatch aborts at startup.
- `allow_non_loopback` is threaded into `bind_server_socket` /
  `connect_client_socket` and the config validators, skipping `ensure_loopback`.
  The client binds the unspecified local address (`0.0.0.0` / `::`) instead of
  loopback so it can reach a remote server.
- The server generates a random token (`main.rs`), logs it, and stores it in
  `VpnServerConfig.test_token`; clients pass it via `--test-token`. The handshake
  equality check (above) enforces the token and the test/non-test split.
- Both ends self-terminate after `TEST_MODE_MAX_RUNTIME` (30 min) via a
  `tokio::select!` timeout in `main.rs`.

## Demux assumption

The server distinguishes clients purely by UDP source `SocketAddr`, so the tunnel
must present each client from a **distinct local port** (the usual behavior of
per-flow UDP forwarders). If a tunnel ever fanned many clients onto one socket, a
connection-id header would be required — intentionally out of scope.

## Threat model (what the VPN does *not* do)

- No encryption or authentication on the wire — the tunnel owns both.
- No NAT traversal or relays — the tunnel owns transport.
- Reachability is constrained by the loopback bind, not by firewall rules.
- Inter-client isolation rests on the anti-spoofing check (and/or tunnel isolation).
- [Test mode](#test-mode) deliberately lifts the loopback bind, putting plaintext
  VPN traffic on the network; its random token is an accident-prevention gate, not
  a security boundary. Use it only for testing on trusted networks (such as
  benchmarking).

## See also

- [`README.md`](../README.md) — quick start and CLI reference.
