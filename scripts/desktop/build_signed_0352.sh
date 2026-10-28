#!/usr/bin/env bash
# Build the native Desktop using the public signing root of the owner's bundle.
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Usage: $0 <32-byte-ed25519-public-root-hex-file>" >&2; exit 2; fi
ROOT_FILE="$1"
[[ -f "$ROOT_FILE" && ! -L "$ROOT_FILE" ]] || { echo "Unsafe/missing root public key file" >&2; exit 2; }
ROOT=$(tr -d '\r\n ' < "$ROOT_FILE")
[[ "$ROOT" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Expected exactly 32-byte Ed25519 root (64 hex chars)" >&2; exit 2; }
ROOT=$(printf '%s' "$ROOT" | tr 'A-F' 'a-f')
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../../apps/desktop"
export NEVERLAUNCHER_BOOTSTRAP_ROOT_KEY="$ROOT"
# The root is embedded in Rust via option_env! at compile time, not passed to
# JavaScript or runtime environment. Requires the existing Tauri v2 toolchain.
npm ci --ignore-scripts
npm run tauri:build
