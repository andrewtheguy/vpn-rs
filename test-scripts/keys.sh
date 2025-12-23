#!/bin/bash
# Key management for tunnel testing
# Usage: source test-scripts/keys.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/.keys"
KEYS_FILE="$SCRIPT_DIR/.tunnel_keys"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/tunnel-rs"

generate_keys() {
    echo "Generating new key pairs..."
    mkdir -p "$KEYS_DIR"

    # Generate sender keys (nsec saved to file, npub printed to stdout)
    SENDER_NPUB=$("$TUNNEL_BIN" generate-nostr-key --output "$KEYS_DIR/sender.nsec" --force 2>/dev/null | grep "^npub:" | awk '{print $2}')
    SENDER_NSEC_FILE="$KEYS_DIR/sender.nsec"

    # Generate receiver keys
    RECEIVER_NPUB=$("$TUNNEL_BIN" generate-nostr-key --output "$KEYS_DIR/receiver.nsec" --force 2>/dev/null | grep "^npub:" | awk '{print $2}')
    RECEIVER_NSEC_FILE="$KEYS_DIR/receiver.nsec"

    # Save paths and npubs to config file
    cat > "$KEYS_FILE" << EOF
# Tunnel test keys - generated $(date)
SENDER_NSEC_FILE=$SENDER_NSEC_FILE
SENDER_NPUB=$SENDER_NPUB
RECEIVER_NSEC_FILE=$RECEIVER_NSEC_FILE
RECEIVER_NPUB=$RECEIVER_NPUB
EOF

    echo "Keys saved to $KEYS_DIR/"
    echo "  Sender:   $SENDER_NPUB"
    echo "  Receiver: $RECEIVER_NPUB"
}

load_keys() {
    if [ ! -f "$KEYS_FILE" ]; then
        echo "No keys file found. Generating new keys..."
        generate_keys
    fi
    source "$KEYS_FILE"
    export SENDER_NSEC_FILE SENDER_NPUB RECEIVER_NSEC_FILE RECEIVER_NPUB
}

show_keys() {
    load_keys
    echo "=== Tunnel Test Keys ==="
    echo "Sender NSEC:   $SENDER_NSEC_FILE"
    echo "Sender NPUB:   $SENDER_NPUB"
    echo "Receiver NSEC: $RECEIVER_NSEC_FILE"
    echo "Receiver NPUB: $RECEIVER_NPUB"
}

# Auto-load keys when sourced
load_keys
