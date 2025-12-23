# Multi-Session Testing Scripts

Scripts for testing multi-session nostr tunnel stability.

## Quick Start

```bash
# Build first
cargo build --release

# Terminal 1: Start echo server
python3 scripts/echo_server.py 9999

# Terminal 2: Start sender (auto-generates keys on first run)
./scripts/sender.sh

# Terminal 3: Start receiver(s)
./scripts/receiver.sh 3      # 3 sessions on ports 7001-7003

# Terminal 4: Run tests
python3 scripts/test_tunnel.py 3              # Ping 3 ports (7001-7003)
python3 scripts/test_tunnel.py 3 --loop       # Ping every 5s
python3 scripts/test_tunnel.py 3 --stream 10  # Stream for 10s
python3 scripts/test_tunnel.py 3 --stream 10 --loop  # Stream 10s repeatedly
```

## Scripts

| Script | Description |
|--------|-------------|
| `sender.sh [PORT] [MAX]` | Start sender with echo server (default: port 9999, max 5 sessions) |
| `receiver.sh [NUM] [PORT]` | Start N receivers (default: 1 receiver on port 7001) |
| `test_tunnel.py` | Test tunnel connectivity and data integrity |
| `echo_server.py [PORT]` | Multi-connection TCP echo server |
| `keys.sh` | Key management (auto-sourced by other scripts) |

## Key Management

Keys are auto-generated on first run and saved to `scripts/.tunnel_keys`.

```bash
# View current keys
source scripts/keys.sh && show_keys

# Regenerate keys
source scripts/keys.sh && generate_keys

# Use keys in custom commands
source scripts/keys.sh
echo $SENDER_NSEC $SENDER_NPUB $RECEIVER_NSEC $RECEIVER_NPUB
```

## Test Modes

### Ping Test
Send a single message and verify it echoes back:
```bash
python3 scripts/test_tunnel.py 3           # Once
python3 scripts/test_tunnel.py 3 --loop    # Every 5s
```

### Streaming Test
Concurrent streaming with data verification:
```bash
python3 scripts/test_tunnel.py 3 --stream 10           # 10 seconds
python3 scripts/test_tunnel.py 3 --stream 10 --loop    # 10s repeatedly
```

Output shows:
- Messages sent/received per session
- Bytes transferred
- Verified message counts
- Throughput stats

## Example Output

```
=== Streaming Test (10s) ===
Sessions: 3 (ports 7001-7003)
----------------------------------------------------------------------
[7001] Connected
[7002] Connected
[7003] Connected
[10.0s] Sent: 150.5KB, Recv: 180.2KB, Verified: 1500
----------------------------------------------------------------------
Results:
  [OK] Port 7001: sent=500 recv=495 verified=492 err=0
  [OK] Port 7002: sent=500 recv=492 verified=490 err=0
  [OK] Port 7003: sent=500 recv=493 verified=491 err=0
----------------------------------------------------------------------
Total: 150.5KB sent, 180.2KB recv, 1473 verified
Throughput: 15.0KB/s
*** ALL OK ***
```
