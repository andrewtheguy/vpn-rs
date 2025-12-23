#!/bin/bash
# Spawn multiple tunnel receivers for multi-session testing
#
# Usage:
#   ./multi_receiver.sh <RECEIVER_NSEC> <SENDER_NPUB> [NUM_SESSIONS]
#
# This spawns N receivers on ports 7001, 7002, 7003, etc.
# Then you can test each with: nc 127.0.0.1 7001

set -e

RECEIVER_NSEC="${1:-}"
SENDER_NPUB="${2:-}"
NUM_SESSIONS="${3:-3}"
BASE_PORT="${BASE_PORT:-7001}"

if [ -z "$RECEIVER_NSEC" ] || [ -z "$SENDER_NPUB" ]; then
    echo "Usage: $0 <RECEIVER_NSEC> <SENDER_NPUB> [NUM_SESSIONS]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TUNNEL_BIN="${PROJECT_DIR}/target/release/tunnel-rs"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$PROJECT_DIR/Cargo.toml"

PIDS=()
cleanup() {
    echo "Stopping all receivers..."
    for pid in "${PIDS[@]}"; do kill $pid 2>/dev/null || true; done
    exit 0
}
trap cleanup INT TERM

echo "=== Spawning $NUM_SESSIONS receivers ==="
for i in $(seq 1 $NUM_SESSIONS); do
    PORT=$((BASE_PORT + i - 1))
    echo "[$i] Starting receiver on port $PORT..."
    "$TUNNEL_BIN" receiver nostr \
        --target "tcp://127.0.0.1:$PORT" \
        --nsec "$RECEIVER_NSEC" \
        --peer-npub "$SENDER_NPUB" &
    PIDS+=($!)
    sleep 2  # Stagger to avoid Nostr relay rate limits
done

echo ""
echo "=== All receivers started ==="
echo "Test with:"
for i in $(seq 1 $NUM_SESSIONS); do
    echo "  echo 'test $i' | nc 127.0.0.1 $((BASE_PORT + i - 1))"
done
echo ""
echo "Press Ctrl+C to stop all"
wait
