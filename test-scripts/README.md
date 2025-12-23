# Multi-Session Testing Scripts

Scripts for testing receiver-initiated multi-session nostr tunnel.

## Architecture

In receiver-initiated mode, the **receiver** initiates connections to the sender.
The sender waits for incoming connection requests and forwards traffic to the source service.

```
[Echo Server]     [Sender]              [Receiver]        [Test Client]
  :19999    <-->   nostr   <-- initiates --  nostr   <-->   :17001-17003
```

## Quick Start

```bash
# Build first
cargo build --release

# Terminal 1: Start echo server (the source service)
python3 test-scripts/echo_server.py 19999

# Terminal 2: Start sender (waits for receiver connections)
./test-scripts/sender.sh

# Terminal 3: Start receiver(s) - these initiate connections to sender
./test-scripts/receiver.sh 3      # 3 sessions on ports 17001-17003

# Terminal 4: Run tests
python3 test-scripts/test_tunnel.py -n 3                # Ping 3 ports (17001-17003)
python3 test-scripts/test_tunnel.py -n 3 --loop         # Ping every 5s
python3 test-scripts/test_tunnel.py -n 3 --stream 10    # Stream for 10s
python3 test-scripts/test_tunnel.py -n 3 --stream 10 --loop  # Stream 10s repeatedly
```

## Scripts

| Script | Description |
|--------|-------------|
| `sender.sh [PORT] [MAX]` | Start sender pointing to source (default: port 19999, max 5 sessions) |
| `receiver.sh [NUM] [PORT]` | Start N receivers (default: 1 receiver on port 17001) |
| `test_tunnel.py` | Test tunnel connectivity and data integrity |
| `echo_server.py [PORT]` | Multi-connection TCP echo server |
| `keys.sh` | Key management (auto-sourced by other scripts) |

## Key Management

Keys are auto-generated on first run:
- nsec files saved to `test-scripts/.keys/`
- npub values saved to `test-scripts/.tunnel_keys`

```bash
# View current keys
source test-scripts/keys.sh && show_keys

# Regenerate keys
source test-scripts/keys.sh && generate_keys

# Use keys in custom commands
source test-scripts/keys.sh
echo $SENDER_NSEC_FILE $SENDER_NPUB $RECEIVER_NSEC_FILE $RECEIVER_NPUB
```

## Test Modes

### Ping Test
Send a single message and verify it echoes back:
```bash
python3 test-scripts/test_tunnel.py -n 3           # Once
python3 test-scripts/test_tunnel.py -n 3 --loop    # Every 5s
```

### Streaming Test
Concurrent streaming with data verification:
```bash
python3 test-scripts/test_tunnel.py -n 3 --stream 10           # 10 seconds
python3 test-scripts/test_tunnel.py -n 3 --stream 10 --loop    # 10s repeatedly
```

Output shows:
- Messages sent/received per session
- Bytes transferred
- Verified message counts
- Throughput stats

## Example Output

```
=== Streaming Test (10s) ===
Sessions: 3 (ports 17001-17003)
----------------------------------------------------------------------
[17001] Connected
[17002] Connected
[17003] Connected
[10.0s] Sent: 150.5KB, Recv: 180.2KB, Verified: 1500
----------------------------------------------------------------------
Results:
  [OK] Port 17001: sent=500 recv=495 verified=492 err=0
  [OK] Port 17002: sent=500 recv=492 verified=490 err=0
  [OK] Port 17003: sent=500 recv=493 verified=491 err=0
----------------------------------------------------------------------
Total: 150.5KB sent, 180.2KB recv, 1473 verified
Throughput: 15.0KB/s
*** ALL OK ***
```
