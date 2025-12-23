#!/bin/bash
# Start tunnel sender (receiver-initiated mode)
# Usage: ./test-scripts/sender.sh [SOURCE_PORT] [MAX_SESSIONS]
#
# The sender waits for receiver connections and forwards traffic
# to the source service (e.g., echo server).
#
# Note: Start echo server separately first:
#   python3 test-scripts/echo_server.py 19999

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/keys.sh"

SOURCE_PORT="${1:-19999}"
MAX_SESSIONS="${2:-5}"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/tunnel-rs"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$SCRIPT_DIR/../Cargo.toml"

echo "=== Sender ==="
echo "Source: tcp://127.0.0.1:$SOURCE_PORT"
echo "Max sessions: $MAX_SESSIONS"
echo ""

exec "$TUNNEL_BIN" sender nostr \
    --source "tcp://127.0.0.1:$SOURCE_PORT" \
    --nsec-file "$SENDER_NSEC_FILE" \
    --peer-npub "$RECEIVER_NPUB" \
    --max-sessions "$MAX_SESSIONS"
