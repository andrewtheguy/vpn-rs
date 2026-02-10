# External NAT64 With TAYGA (Linux)

`vpn-rs` does not provide built-in NAT64 translation.

For IPv6-only VPN clients that need IPv4 reachability, run TAYGA on the VPN server host and route the well-known NAT64 prefix (`64:ff9b::/96`) through the VPN.

## Architecture

- VPN clients send IPv6 traffic for `64:ff9b::/96` through `vpn-rs`.
- Linux policy routing sends only VPN-origin NAT64 traffic to the TAYGA `nat64` interface.
- TAYGA performs stateless v6<->v4 translation.
- Linux NAT44 (`MASQUERADE`) provides many-clients-to-one-IPv4 egress.

## 1. Prerequisites

- Linux host running `vpn-rs server`
- IPv6 VPN network configured (`network6` in `vpn_server.toml`)
- TAYGA installed (`tayga` binary available)
- `iproute2` and iptables or nftables installed
- IP forwarding enabled

## 2. TAYGA Config

Create `/etc/tayga/tayga.conf`:

```ini
tun-device nat64
ipv4-addr 192.168.240.1
prefix 64:ff9b::/96
dynamic-pool 192.168.240.0/20
data-dir /var/lib/tayga
wkpf-strict no
```

Notes:

- `prefix` is fixed to `64:ff9b::/96`.
- `dynamic-pool` is private IPv4 space assigned per IPv6 client flow.
- `wkpf-strict no` is required if clients must reach private IPv4 destinations (RFC1918) via the WKP.

## 3. Bring Up TAYGA Interface

```bash
sudo mkdir -p /var/lib/tayga
sudo tayga --mktun -c /etc/tayga/tayga.conf
sudo ip link set nat64 up
sudo ip addr add 192.168.240.1/20 dev nat64
```

Start the daemon:

```bash
sudo tayga -c /etc/tayga/tayga.conf
```

Or run it via systemd unit/service management.

## 4. Enable Forwarding and NAT44

Enable forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Add IPv4 masquerade from the TAYGA dynamic pool to WAN (replace `eth0` with your egress interface):

```bash
sudo iptables -t nat -A POSTROUTING -s 192.168.240.0/20 -o eth0 -j MASQUERADE
```

## 5. VPN-Scoped Routing Policy (No Global NAT64 Route)

Use a dedicated table so only VPN-origin packets to `64:ff9b::/96` are sent to TAYGA.

Example assumes VPN IPv6 network `fd00::/64` (replace with your `network6`):

```bash
# Add dedicated table entry (one-time)
echo "100 nat64vpn" | sudo tee -a /etc/iproute2/rt_tables

# Route NAT64 prefix only in dedicated table
sudo ip -6 route add 64:ff9b::/96 dev nat64 table nat64vpn

# Route selection rule: source is VPN v6 subnet + destination is NAT64 prefix
sudo ip -6 rule add from fd00::/64 to 64:ff9b::/96 lookup nat64vpn priority 100
```

Important:

- Do **not** add `64:ff9b::/96` to the main/global routing table.
- This keeps NAT64 path scoped to VPN client traffic by routing policy, without relying on public ingress firewall rules.

## 6. vpn-rs Client Routing

On clients, route NAT64 prefix through VPN:

```toml
# vpn_client.toml
[iroh]
routes6 = ["64:ff9b::/96"]
```

Use a DNS64 resolver so A records are synthesized into `64:ff9b::/96`.

## 7. Verification

- Policy routing:

```bash
ip -6 rule show
ip -6 route show table nat64vpn
```

- TAYGA interface state:

```bash
ip addr show dev nat64
```

- NAT44 rule present:

```bash
iptables -t nat -S POSTROUTING
```

- End-to-end from VPN client:

```bash
ping6 64:ff9b::8.8.8.8
```

## 8. Operational Notes

- Persist `ip rule`, `ip route`, sysctl, and iptables/nftables changes with your distro's native mechanism.
- If you use nftables instead of iptables, implement equivalent postrouting masquerade.
- If `network6` changes, update the `ip -6 rule from <network6>` selector accordingly.
