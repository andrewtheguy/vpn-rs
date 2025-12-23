#!/bin/bash
# Start tunnel receiver(s) - receiver-initiated mode
# Usage: ./test-scripts/receiver.sh [NUM_SESSIONS] [BASE_PORT]
#
# In receiver-initiated mode, the receiver initiates the connection
# to the sender and exposes the tunneled service on local target ports.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/keys.sh"

NUM_SESSIONS="${1:-1}"
BASE_PORT="${2:-17001}"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/tunnel-rs"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$SCRIPT_DIR/../Cargo.toml"

PIDS=()
cleanup() {
    echo "Stopping all receivers..."
    for pid in "${PIDS[@]}"; do kill $pid 2>/dev/null || true; done
}
trap cleanup EXIT

echo "=== Receiver ==="
echo "Sessions: $NUM_SESSIONS (ports $BASE_PORT-$((BASE_PORT + NUM_SESSIONS - 1)))"
echo ""

for i in $(seq 1 $NUM_SESSIONS); do
    PORT=$((BASE_PORT + i - 1))
    echo "[$i] Starting receiver on port $PORT..."
    "$TUNNEL_BIN" receiver nostr \
        --target "tcp://127.0.0.1:$PORT" \
        --nsec-file "$RECEIVER_NSEC_FILE" \
        --peer-npub "$SENDER_NPUB" &
    PIDS+=($!)
    [ $NUM_SESSIONS -gt 1 ] && sleep 2  # Stagger for rate limits
done

echo ""
echo "=== Ready ==="
echo "Test with: python3 test-scripts/test_tunnel.py -n $NUM_SESSIONS --port $BASE_PORT --loop"
echo "Press Ctrl+C to stop"
wait
