#!/bin/bash
set -euo pipefail

# Docker buildx script for cross-compiling Linux vpn-rs binaries.
# Outputs:
# - target/build/vpn-rs-linux-amd64
# - target/build/vpn-rs-linux-arm64
#
# Optional env overrides:
# - PLATFORMS (default: linux/amd64,linux/arm64)
# - BUILDER_NAME (default: vpn-rs-builder)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/target/build"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile.build"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BUILDER_NAME="${BUILDER_NAME:-vpn-rs-builder}"

echo "vpn-rs Docker Cross-Compilation Build Script"
echo "============================================"
echo ""
echo "Build directory: $BUILD_DIR"
echo "Dockerfile: $DOCKERFILE"
echo "Platforms: $PLATFORMS"
echo ""

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is not installed or not in PATH" >&2
    exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
    echo "Error: Docker buildx is not available" >&2
    echo "Please update Docker to a version that supports buildx" >&2
    exit 1
fi

if [ ! -f "$DOCKERFILE" ]; then
    echo "Error: $DOCKERFILE does not exist" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
    echo "Creating buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use --driver docker-container
else
    echo "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

echo ""
echo "Building for $PLATFORMS..."
echo "--------------------------"
docker buildx build \
    --platform "$PLATFORMS" \
    --file "$DOCKERFILE" \
    --target export \
    --output type=local,dest="$BUILD_DIR" \
    "$SCRIPT_DIR"

echo ""
echo "Organizing binaries..."
echo "----------------------"

found_any=false

if [ -f "$BUILD_DIR/linux_amd64/vpn-rs" ]; then
    mv "$BUILD_DIR/linux_amd64/vpn-rs" "$BUILD_DIR/vpn-rs-linux-amd64"
    echo "✓ vpn-rs AMD64 saved to: $BUILD_DIR/vpn-rs-linux-amd64"
    found_any=true
fi
if [ -d "$BUILD_DIR/linux_amd64" ]; then
    rm -rf "$BUILD_DIR/linux_amd64"
fi

if [ -f "$BUILD_DIR/linux_arm64/vpn-rs" ]; then
    mv "$BUILD_DIR/linux_arm64/vpn-rs" "$BUILD_DIR/vpn-rs-linux-arm64"
    echo "✓ vpn-rs ARM64 saved to: $BUILD_DIR/vpn-rs-linux-arm64"
    found_any=true
fi
if [ -d "$BUILD_DIR/linux_arm64" ]; then
    rm -rf "$BUILD_DIR/linux_arm64"
fi

if [ "$found_any" = false ]; then
    echo "Error: No binaries found in $BUILD_DIR (expected vpn-rs-linux-amd64 or vpn-rs-linux-arm64)" >&2
    exit 1
fi

echo ""
echo "Build complete!"
echo "==============="
echo ""
echo "Binaries:"
ls -lh "$BUILD_DIR"/vpn-rs-linux-* 2>/dev/null || echo "  (none found)"
echo ""

echo "Verifying binaries..."
echo "---------------------"
if command -v file >/dev/null 2>&1; then
    file "$BUILD_DIR"/vpn-rs-linux-* 2>/dev/null || true
else
    echo "Note: 'file' command not available, skipping binary verification"
fi

echo ""
echo "Binaries are ready in: $BUILD_DIR/"
