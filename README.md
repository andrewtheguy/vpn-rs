# vpn-rs

Full network tunneling (TUN) over encrypted QUIC with NAT traversal via iroh.

`vpn-rs` creates a TUN interface and routes IP packets directly through an encrypted iroh QUIC connection. It is intended for development and homelab use.

> [!NOTE]
> Running vpn-rs requires root/Administrator privileges to create TUN devices and routes.

## Installation

Linux/macOS:
```bash
curl -sSL https://andrewtheguy.github.io/vpn-rs/install.sh | sudo bash
```

Windows:
```powershell
irm https://andrewtheguy.github.io/vpn-rs/install.ps1 | iex
```

### Windows WinTun Requirement

`vpn-rs.exe` requires `wintun.dll` from <https://www.wintun.net/>.

1. Download and extract wintun zip
2. Copy `wintun/bin/amd64/wintun.dll` next to `vpn-rs.exe` (default `%LOCALAPPDATA%\Programs\vpn-rs\`) or into a directory in `PATH`
3. Run `vpn-rs.exe` as Administrator

## From Source

```bash
cargo install --path . -p vpn-rs
```

## Quick Start

Generate server identity and a token:

```bash
vpn-rs generate-server-key --output ./server.key
AUTH_TOKEN=$(vpn-rs generate-token)
echo "$AUTH_TOKEN"
```

Create `vpn_server.toml`:

```toml
role = "vpnserver"
mode = "iroh"

[iroh]
network = "10.0.0.0/24"
secret_file = "./server.key"
auth_tokens = ["<YOUR_AUTH_TOKEN>"]
```

Start server:

```bash
sudo vpn-rs server -c vpn_server.toml
```

Connect client:

```bash
sudo vpn-rs client \
  --server-node-id <SERVER_NODE_ID> \
  --auth-token "$AUTH_TOKEN"
```

## Config Paths

`--default-config` uses:

- server: `~/.config/vpn-rs/vpn_server.toml`
- client: `~/.config/vpn-rs/vpn_client.toml`

Example configs:

- `vpn_server.toml.example`
- `vpn_client.toml.example`
