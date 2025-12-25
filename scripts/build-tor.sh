#!/bin/bash
# Build tunnel-rs with embedded Tor support (iroh mode only)
#
# This swaps Cargo.toml with Cargo.tor.toml to avoid the dependency
# conflict between str0m (base64ct <1.8) and arti (base64ct >=1.8).

set -e

cd "$(dirname "$0")/.."

# Backup current Cargo.toml
mv Cargo.toml Cargo.ice.toml
mv Cargo.tor.toml Cargo.toml

# Build
cargo build --release "$@"

# Restore
mv Cargo.toml Cargo.tor.toml
mv Cargo.ice.toml Cargo.toml

echo ""
echo "Build complete: target/release/tunnel-rs (embedded Tor)"
