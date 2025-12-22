#!/bin/bash
# Key management for tunnel testing
# Usage: source scripts/keys.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_FILE="$SCRIPT_DIR/.tunnel_keys"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/tunnel-rs"

generate_keys() {
    echo "Generating new key pairs..."

    # Generate sender keys
    local sender_out
    sender_out=$("$TUNNEL_BIN" generate-nostr-key 2>&1)
    SENDER_NSEC=$(echo "$sender_out" | grep "Private key" | awk '{print $NF}')
    SENDER_NPUB=$(echo "$sender_out" | grep "Public key" | awk '{print $NF}')

    # Generate receiver keys
    local receiver_out
    receiver_out=$("$TUNNEL_BIN" generate-nostr-key 2>&1)
    RECEIVER_NSEC=$(echo "$receiver_out" | grep "Private key" | awk '{print $NF}')
    RECEIVER_NPUB=$(echo "$receiver_out" | grep "Public key" | awk '{print $NF}')

    # Save to file
    cat > "$KEYS_FILE" << EOF
# Tunnel test keys - generated $(date)
SENDER_NSEC=$SENDER_NSEC
SENDER_NPUB=$SENDER_NPUB
RECEIVER_NSEC=$RECEIVER_NSEC
RECEIVER_NPUB=$RECEIVER_NPUB
EOF

    echo "Keys saved to $KEYS_FILE"
}

load_keys() {
    if [ ! -f "$KEYS_FILE" ]; then
        echo "No keys file found. Generating new keys..."
        generate_keys
    fi
    source "$KEYS_FILE"
    export SENDER_NSEC SENDER_NPUB RECEIVER_NSEC RECEIVER_NPUB
}

show_keys() {
    load_keys
    echo "=== Tunnel Test Keys ==="
    echo "Sender NSEC:   ${SENDER_NSEC:0:25}..."
    echo "Sender NPUB:   ${SENDER_NPUB:0:25}..."
    echo "Receiver NSEC: ${RECEIVER_NSEC:0:25}..."
    echo "Receiver NPUB: ${RECEIVER_NPUB:0:25}..."
}

# Auto-load keys when sourced
load_keys
