#!/bin/bash
# Start tunnel server (client-initiated mode)
# Usage: ./test-scripts/server.sh [MAX_SESSIONS]
#
# The server whitelists allowed networks and waits for client connections.
# Clients specify which source to tunnel (e.g., --source tcp://127.0.0.1:19999).
#
# Note: Start echo server separately first:
#   python3 test-scripts/echo_server.py 19999

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/keys.sh"

MAX_SESSIONS="${1:-5}"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/tunnel-rs"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$SCRIPT_DIR/../Cargo.toml"

echo "=== Server ==="
echo "Allowed networks: 127.0.0.0/8 (TCP)"
echo "Max sessions: $MAX_SESSIONS"
echo ""

exec "$TUNNEL_BIN" server nostr \
    --allowed-tcp 127.0.0.0/8 \
    --nsec-file "$SERVER_NSEC_FILE" \
    --peer-npub "$CLIENT_NPUB" \
    --max-sessions "$MAX_SESSIONS"
