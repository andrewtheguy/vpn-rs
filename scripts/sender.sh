#!/bin/bash
# Start tunnel sender
# Usage: ./scripts/sender.sh [SOURCE_PORT] [MAX_SESSIONS]
#
# Note: Start echo server separately first:
#   python3 scripts/echo_server.py 9999

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/keys.sh"

SOURCE_PORT="${1:-9999}"
MAX_SESSIONS="${2:-5}"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/tunnel-rs"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$SCRIPT_DIR/../Cargo.toml"

echo "=== Sender ==="
echo "Source: tcp://127.0.0.1:$SOURCE_PORT"
echo "Max sessions: $MAX_SESSIONS"
echo ""

exec "$TUNNEL_BIN" sender nostr \
    --source "tcp://127.0.0.1:$SOURCE_PORT" \
    --nsec "$SENDER_NSEC" \
    --peer-npub "$RECEIVER_NPUB" \
    --max-sessions "$MAX_SESSIONS"
