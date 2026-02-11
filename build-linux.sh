#!/usr/bin/env bash
set -euo pipefail

# Build Linux release binaries for vpn-rs.
# Outputs:
# - target/build/vpn-rs-linux-amd64
# - target/build/vpn-rs-linux-arm64
#
# Optional env override:
#   TARGETS="x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/target/build"
BIN_NAME="vpn-rs"
TARGETS="${TARGETS:-x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu}"

suffix_for_target() {
    case "$1" in
        x86_64-unknown-linux-gnu) echo "linux-amd64" ;;
        aarch64-unknown-linux-gnu) echo "linux-arm64" ;;
        *)
            echo "Unsupported target: $1" >&2
            return 1
            ;;
    esac
}

if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: cargo is not installed or not in PATH" >&2
    exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
    echo "Error: rustup is not installed or not in PATH" >&2
    exit 1
fi

mkdir -p "${BUILD_DIR}"

echo "vpn-rs Linux Build Script"
echo "========================="
echo "Targets: ${TARGETS}"
echo "Build output: ${BUILD_DIR}"
echo

IFS=',' read -r -a TARGET_LIST <<< "${TARGETS}"

for target in "${TARGET_LIST[@]}"; do
    suffix="$(suffix_for_target "${target}")"
    output="${BUILD_DIR}/${BIN_NAME}-${suffix}"

    echo "==> Building ${BIN_NAME} for ${target}"
    rustup target add "${target}" >/dev/null
    cargo build --release --target "${target}"

    src_bin="${SCRIPT_DIR}/target/${target}/release/${BIN_NAME}"
    if [[ ! -f "${src_bin}" ]]; then
        echo "Error: expected binary not found: ${src_bin}" >&2
        exit 1
    fi

    cp "${src_bin}" "${output}"
    chmod +x "${output}"
    echo "Saved: ${output}"
    echo
done

echo "Build complete."
echo "Artifacts:"
ls -lh "${BUILD_DIR}/${BIN_NAME}-linux-"* 2>/dev/null || echo "  (none)"

if command -v file >/dev/null 2>&1; then
    echo
    echo "Binary details:"
    file "${BUILD_DIR}/${BIN_NAME}-linux-"* 2>/dev/null || true
fi
