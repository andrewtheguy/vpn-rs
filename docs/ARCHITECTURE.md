# vpn-rs Architecture

`vpn-rs` is a **composable IP-over-TCP/UDP VPN layer**: it factors the IP-tunneling
layer out from transport and crypto so it can be stacked on any tunnel. It creates
a TUN device and moves IP packets between it and a **plain socket bound to
loopback** — TCP by default, or UDP (`--transport`). It does *not* do encryption,
authentication, NAT traversal, or cross-network transport — those belong to a
separate **tunnel** process (e.g.
[`tunnel-rs`](https://github.com/andrewtheguy/tunnel-rs),
[`duopipe`](https://github.com/andrewtheguy/duopipe), an SSH tunnel, or any
loopback forwarder) running on the same host. This modularity trades some
throughput (an extra local-socket hop and a second process) for the freedom to
swap transports without touching the VPN, so it is generally less performant than
an integrated VPN such as WireGuard or OpenVPN.

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
tunnel on each host carries the loopback traffic across the network. This is the
security boundary — the VPN itself has no transport-level auth or crypto, so it
relies on (a) never being on the network, and (b) the tunnel isolating peers.

## Design principles

- **Do one thing (composability).** VPN tunneling only. Transport/crypto/NAT-traversal
  are explicitly *out of scope* and delegated to the external tunnel, so the layer
  stacks on whatever transport you trust. The cost is performance: the extra hop
  makes it slower than an integrated VPN.
- **Two transports, one protocol.** The same handshake and data messages ride
  either **TCP** (default; a connection per client, length-prefixed frames) or
  **UDP** (one datagram per message). Pick with `--transport tcp|udp`; the local
  tunnel must forward the matching protocol. UDP is datagram-based (no
  TCP-over-TCP meltdown over a UDP tunnel); TCP can ride a stream tunnel
  (including SSH port-forwarding).
- **Loopback-locked.** In normal mode, the server `listen` and client `server_addr`
  are hard-locked to loopback addresses (`127.0.0.0/8`, `::1`, or IPv4-mapped
  loopback) by `ensure_loopback` ([`udp.rs`](../src/vpn_core/udp.rs)), on either
  transport. The lone exception is [test mode](#test-mode), an explicit opt-in for
  tunnel-less testing.
- **No backward compatibility** while in `0.0.x`. The wire protocol is **v4**; peers
  on any other version are rejected.

## Transport selection

`Transport { Tcp, Udp }` (default `Tcp`) is resolved from CLI `--transport`
(highest precedence), then the config's `transport` field, then the default. It
flows into `VpnServerConfig` / `VpnClientConfig`, and `main.rs` dispatches:

| | Server | Client |
|--|--------|--------|
| **TCP** | `bind_tcp_listener` → `TcpVpnServer::run` | `connect_tcp_stream` → `run_tunnel` |
| **UDP** | `bind_server_socket` → `VpnServer::run` | `connect_client_socket` → `run_udp_tunnel` |

The TUN device, IP pools, handshake, anti-spoofing, GSO/GRO offload, and the
loopback boundary are shared; only the framing and the per-client demux differ.

## Module map

All VPN logic lives in `src/vpn_core/` (a module inside the binary crate). `main.rs`
is the CLI shell (`server` / `client` subcommands only).

| Module | Responsibility |
|--------|----------------|
| [`udp.rs`](../src/vpn_core/udp.rs) | Loopback enforcement (`ensure_loopback`), UDP bind/connect, socket buffers |
| [`tcp.rs`](../src/vpn_core/tcp.rs) | TCP listener bind / stream connect, `TCP_NODELAY`, socket buffers (reuses `ensure_loopback`) |
| [`datagram.rs`](../src/vpn_core/datagram.rs) | UDP one-message-per-datagram framing; GSO datagram-size capping |
| [`frame_reader.rs`](../src/vpn_core/frame_reader.rs) | TCP length-prefixed frame reader over any `AsyncRead` |
| [`chunked_write.rs`](../src/vpn_core/chunked_write.rs) | `ChunkedWrite` trait + vectored TCP write-half impl |
| [`signaling.rs`](../src/vpn_core/signaling.rs) | Handshake JSON, `DataMessageType`, capabilities, frame encode/parse |
| [`ip_pool.rs`](../src/vpn_core/ip_pool.rs) | `IpPool` / `Ip6Pool` — `device_id`-keyed allocation (shared by both servers) |
| [`packet.rs`](../src/vpn_core/packet.rs) | Source/destination IP extraction for routing + anti-spoofing (shared) |
| [`server.rs`](../src/vpn_core/server.rs) | **UDP** server: `recv_from` demux by `SocketAddr`, reaper, TUN reader, routing |
| [`tcp_server.rs`](../src/vpn_core/tcp_server.rs) | **TCP** server: accept loop, per-connection tasks, shared TUN reader/writer, routing |
| [`tunnel.rs`](../src/vpn_core/tunnel.rs) | `run_tunnel` — the shared stream (TCP) data pipeline used by the client |
| [`client.rs`](../src/vpn_core/client.rs) | Connect + handshake for both transports, reconnect, the UDP tunnel tasks |
| [`config.rs`](../src/vpn_core/config.rs) | Runtime config structs + `validate()` |
| [`file_config.rs`](../src/vpn_core/file_config.rs) | TOML `[server]` / `[client]` schema → resolved config; `Transport` enum |
| [`device.rs`](../src/vpn_core/device.rs) | Cross-platform TUN creation + route management |
| [`offload.rs`](../src/vpn_core/offload.rs) | Linux GSO/GRO: virtio_net_hdr, software segmentation + coalescing |
| [`buffer.rs`](../src/vpn_core/buffer.rs) | Reusable receive/scratch buffers |
| [`lock.rs`](../src/vpn_core/lock.rs) | Single-instance client lock |
| [`error.rs`](../src/vpn_core/error.rs) | `VpnError` / `VpnResult`; recoverable-vs-permanent classification |

## Wire protocol (v4)

The same handshake and data messages are used on both transports; only the
framing differs.

- **UDP framing.** One datagram per message; the datagram boundary *is* the
  length. Handshake and data datagrams share the one socket and are disambiguated
  by the **first byte**: a handshake is raw JSON (`{` = `0x7b`); a data datagram
  starts with a [`DataMessageType`](../src/vpn_core/signaling.rs) byte in
  `0x00..=0x03` (never `{`).
- **TCP framing.** Messages are length-prefixed frames on the byte stream. The
  handshake is a `[len:4 BE][JSON]` message (`write_message` / `read_message`).
  Data frames are split out by [`FrameReader`](../src/vpn_core/frame_reader.rs);
  the first data-stream frame is the client's capabilities, then IP/heartbeat
  frames follow.

### Handshake (JSON)

```
client → server : VpnHandshake          { version: 4, device_id: u64, test_token? }
server → client : VpnHandshakeResponse   { version, accepted, server_gso_enabled,
                                           mtu, assigned_ip[/6], network[/6],
                                           server_ip[/6], reject_reason? }
```

`device_id` is a random `u64` per client session. The server keys IP-pool
allocation by `device_id` (not by socket address / connection), so a client that
reconnects keeps its previously-assigned VPN IP.

`test_token` is omitted (`skip_serializing_if`) outside [test mode](#test-mode),
so normal handshakes are unchanged on the wire. In test mode the server checks
`config.test_token == handshake.test_token` **before any allocation** and rejects
on mismatch. Since a non-test server holds `None` and a test server holds
`Some(token)`, this equality also makes test and non-test peers mutually
incompatible in both directions. The UDP client retransmits the handshake (lossy
transport); the TCP client sends it once (the stream is reliable).

### Data channel

Message layout by leading type byte. On UDP the message is one datagram; on TCP
an IP packet additionally carries a 4-byte big-endian frame length after the type
byte (`[0x00][frame_len:4][offload_len:1][offload][ip_packet]`):

| Type | Byte | UDP datagram layout |
|------|------|---------------------|
| IP packet | `0x00` | `[0x00] [offload_len:1] [offload:0\|10] [ip_packet]` |
| Heartbeat ping | `0x01` | `[0x01]` |
| Heartbeat pong | `0x02` | `[0x02]` |
| Capabilities | `0x03` | `[0x03] [payload_len:1] [payload]` |

The `offload` block (when present) is a 10-byte `virtio_net_hdr` carrying TCP-GSO
metadata. `encode_ip_datagram` (UDP) and `append_ip_packet_v2` (TCP) are the
encoders; `parse_ip_packet_v2` is the shared decoder. Capabilities currently carry
a single GSO-support bit; unknown trailing bytes are ignored for forward
compatibility.

## Server runtime

Both servers validate config, build the `device_id`-keyed IP pools, create the
TUN device, and route TUN→client by destination IP using `ip_pool.rs` /
`packet.rs`. They differ in how clients are demultiplexed and framed.

### Shared state

- `IpPool` / `Ip6Pool` — allocation keyed by `device_id`, with existing-IP
  idempotency so a retransmitted/reconnecting handshake reuses the same address.
- Reverse routing index (assigned IP → client) for TUN → client, which is also
  the source-IP ownership check for anti-spoofing.
- A `device_id → current client` index for max-client counting and
  reconnect/"move" handling.

Unless `disable_spoofing_check` is set, `source_ip_allowed` rejects an IP packet
whose source address is owned by a *different* client. With no transport auth,
this is the only inter-client protection at the VPN layer.

### UDP server ([`server.rs`](../src/vpn_core/server.rs))

Demultiplexes every client onto **one** socket by source `SocketAddr`. Tasks:

1. **Main `recv_from` loop** — demux by first byte: `{` → `handle_handshake`,
   else `try_send` the owned datagram to the inbound worker (counting
   `packets_inbound_dropped_full` when the queue is full, so the socket keeps
   draining).
2. **Inbound worker** — bumps `last_seen`, handles capabilities/heartbeats,
   anti-spoofs, materializes offload, enqueues IP packets to the TUN writer.
3. **TUN writer** — batched writes to the TUN device.
4. **Outbound sender** — one shared task that `send_to`s each framed datagram.
5. **TUN reader** — destination-IP lookup → `encode_ip_datagram` → outbound
   channel; per-`SocketAddr` software-GRO state.
6. **Reaper** — reaps clients whose `last_seen` exceeds `client_timeout` (UDP has
   no FIN), releasing the IP only if the addr is still the device's current addr.

### TCP server ([`tcp_server.rs`](../src/vpn_core/tcp_server.rs))

Connection-oriented: one TCP connection per client, keyed by a connection id.
`run` creates the TUN device and spawns shared tasks, then enters an accept loop.

- **Shared TUN writer** — drains one `mpsc<TunWriteRequest>` and writes to the
  device (coalescing plain runs into GSO super-frames where supported).
- **Shared TUN reader** — reads the TUN, looks up the owning connection by
  destination IP, frames with `append_ip_packet_v2` (honoring that connection's
  negotiated GSO; per-connection software-GRO), and enqueues to the connection's
  outbound channel with the `drop_on_full` / backpressure policy.
- **Accept loop → per-connection task.** Each connection: read the length-prefixed
  handshake, apply the test-mode token gate, enforce `max_clients`, allocate IPs
  (idempotent per `device_id`), send the response, read the first capabilities
  frame, then run two tasks until the stream closes or the connection is torn
  down:
  - **reader** — a `FrameReader` over the read half; IP frames are anti-spoofed,
    offload-materialized if the server TUN lacks offload, and enqueued to the
    shared TUN writer; pings are answered with pongs on the outbound channel.
  - **writer** — drains the outbound channel and writes with vectored
    `write_all_chunks` ([`ChunkedWrite`](../src/vpn_core/chunked_write.rs)).
- **Reconnect.** A new handshake for a known `device_id` re-points routing to the
  new connection and signals the old one (via an `Arc<Notify>`) to tear down. The
  IP stays allocated to the device; cleanup is guarded by current-connection
  checks so the departing connection never releases a live IP.
- **Reaper** — signals connections whose `last_seen` exceeds `client_timeout` (in
  addition to TCP's own EOF/error detection). Cleanup releases the IP only if the
  connection is still the device's current one.

## Client runtime

`VpnClient::connect()` dispatches on `config.transport`. Both paths share
handshake-response → `ServerInfo` conversion, TUN device + route setup, the
capabilities advertisement, and the reconnect wrapper.

- **TCP** (`connect_tcp`): `connect_tcp_stream` (loopback unless test mode;
  `TCP_NODELAY`; socket buffers), a single length-prefixed handshake
  request/response (no retransmit — the stream is reliable), then
  [`run_tunnel`](../src/vpn_core/tunnel.rs) over the split halves.
- **UDP** (`connect_udp`): `connect_client_socket` (ephemeral local socket,
  loopback or unspecified in test mode), `perform_handshake` (2s timeout, up to
  `HANDSHAKE_RETRIES` = 5 retransmits to tolerate datagram loss), then
  `run_udp_tunnel`.

`run_with_reconnect(max_attempts)` wraps `connect()` with exponential backoff
(1s → 2s → … capped at 60s, plus jitter), retrying only on recoverable errors
(`ConnectionLost` / `Network` / `Signaling`), never on `Config` / `TunDevice` /
`AuthenticationFailed`.

### Tunnel tasks

The **UDP** path (`run_udp_tunnel`) runs four tasks: **outbound** (TUN read →
`build_datagrams` with GSO cap → `socket.send`), **inbound** (`recv` → `classify`
→ TUN writer; ping → pong), **tun_writer** (batched TUN writes), and **heartbeat**
(ping every 10s; declare the link lost if no pong for 30s).

The **TCP** path (`run_tunnel`, shared with the server's per-connection direction)
runs five tasks: a dedicated **writer** (batched vectored writes), an **outbound**
TUN reader (frame → channel), an **inbound** stream reader
([`FrameReader`](../src/vpn_core/frame_reader.rs) → TUN writer channel; ping →
pong), an **inbound TUN writer**, and a symmetric **heartbeat**.

## GSO/GRO offload and the datagram cap

On Linux the kernel can hand the server ~64 KB TCP-GSO "super-frames" over the TUN
device (and coalesce inbound packets via software GRO). Forwarding a super-frame
whole is cheap over loopback.

- **UDP:** the **external tunnel** may cap datagram size, so `build_datagrams`
  segments on the outbound path — if an offload frame's framed size would exceed
  `max_datagram_size`, it is split with `materialize_offload_into` into ≤cap plain
  datagrams. The default cap is `MAX_DATAGRAM_PAYLOAD = 65507` (the IPv4 UDP
  payload ceiling), range-validated to `576..=65507`; lower it if your tunnel
  cannot carry large datagrams.
- **TCP:** the stream re-segments naturally, so there is no datagram cap. Offload
  super-frames are forwarded whole when both peers negotiated GSO, and segmented
  in software (`materialize_offload_into`) for a peer without it.

The receive side (`parse_ip_packet_v2` + `materialize_offload_into`) is per-message
on both transports and needs no cap logic.

## Configuration

TOML with a top-level `role` guard and a single `[server]` **or** `[client]`
section ([`file_config.rs`](../src/vpn_core/file_config.rs)):

- **Server:** `transport` (`tcp` default / `udp`), `listen` (default
  `127.0.0.1:5555`), `network` / `network6` address-family selection (`network`
  only = IPv4-only, `network6` only = IPv6-only, both = dual-stack; `network6`
  must be `/126` or wider), `server_ip` / `server_ip6`, `mtu` (576–9216, default
  1440), `max_clients`, `client_timeout_secs` (≥15), `max_datagram_size` (UDP
  only), channel sizes, `recv_buffer_size` / `send_buffer_size`, `drop_on_full`,
  `disable_spoofing_check`.
- **Client:** `transport`, `server_addr` (loopback), `routes` / `routes6`,
  `auto_reconnect`, `max_reconnect_attempts`, `recv_buffer_size` /
  `send_buffer_size`.

The CLI `--transport` flag overrides the config's `transport` when set; otherwise
the config value (default `tcp`) is used.

`recv_buffer_size` / `send_buffer_size` set the kernel socket buffers (`SO_RCVBUF`
/ `SO_SNDBUF`) in bytes (64 KiB–1 GiB, default 4 MiB each), applied via `socket2`
so a large queue absorbs multi-Gbit bursts. The receive buffer is the impactful
one; on UDP a too-small `SO_RCVBUF` is what surfaces as dropped datagrams. Linux
caps the request at `net.core.rmem_max` / `net.core.wmem_max`; the applied size is
read back and logged, with a warning when capped — raise `net.core.rmem_max` first
when tuning.

Both `validate()` paths call `ensure_loopback` (unless test mode is active), so a
non-loopback address is rejected at startup before any socket is bound. The `role`
guard accepts `vpnserver`/`vpnclient` in normal mode and
`testvpnserver`/`testvpnclient` in test mode; a flag/role mismatch is a startup
error.

## Test mode

An explicit, multiply-gated escape hatch for testing the VPN directly between
hosts **without a tunnel** — and therefore with no wire encryption or
authentication — on either transport. Entered only when all gates agree:

- `--test-mode` on the CLI **and** the matching test `role` in the config
  (`testvpnserver` / `testvpnclient`); a mismatch aborts at startup.
- `allow_non_loopback` is threaded into the bind/connect helpers and the config
  validators, skipping `ensure_loopback`. The UDP client binds the unspecified
  local address (`0.0.0.0` / `::`) instead of loopback so it can reach a remote
  server.
- The server generates a random token (`main.rs`), logs it, and stores it in
  `VpnServerConfig.test_token`; clients pass it via `--test-token`. The handshake
  equality check (above) enforces the token and the test/non-test split.
- Both ends self-terminate after `TEST_MODE_MAX_RUNTIME` (30 min) via a
  `tokio::select!` timeout in `main.rs`.

Test mode also serves as the benchmark harness: it carries traffic directly, so it
measures the VPN packet pipeline by itself (the default TCP transport gives a
clean, drop-free baseline).

## Per-transport demux

- **TCP** distinguishes clients by connection — no header is needed, and a client
  reconnecting opens a fresh connection that takes over its `device_id`.
- **UDP** distinguishes clients purely by source `SocketAddr`, so the tunnel must
  present each client from a **distinct local port** (the usual behavior of
  per-flow UDP forwarders). If a UDP tunnel ever fanned many clients onto one
  socket, a connection-id header would be required — intentionally out of scope.

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
