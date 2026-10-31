#!/usr/bin/env bash
# Requires an actual trusted Apple Developer ID Application identity.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${LAUNCHER_MACOS_SANDBOX_TEAM_ID:?required: ten-character Apple team ID}"
: "${LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY:?required: Developer ID Application certificate identity}"
[[ "$LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY" == Developer\ ID\ Application:* ]] || { echo "Developer ID Application required" >&2; exit 1; }
[[ "$LAUNCHER_MACOS_SANDBOX_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || { echo "invalid Team ID" >&2; exit 1; }
DEST="${1:?output path for signed helper required}"
[[ "$DEST" = /* ]] || { echo "output path must be absolute" >&2; exit 1; }
mkdir -p "$(dirname "$DEST")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
xcrun swiftc -O -whole-module-optimization \
    "$ROOT/macos/sandbox-helper/NeverExtensionSandbox.swift" -o "$TMP/NeverExtensionSandbox" -lsandbox
codesign --force --sign "$LAUNCHER_MACOS_SANDBOX_SIGN_IDENTITY" \
    --options runtime --timestamp \
    --entitlements "$ROOT/macos/sandbox-helper/NeverExtensionSandbox.entitlements" \
    "$TMP/NeverExtensionSandbox"
REQ="anchor apple generic and certificate leaf[subject.OU] = \"$LAUNCHER_MACOS_SANDBOX_TEAM_ID\""
codesign --verify --strict --verbose=2 --test-requirement "$REQ" "$TMP/NeverExtensionSandbox"
plutil -lint "$ROOT/macos/sandbox-helper/NeverExtensionSandbox.entitlements"
install -m 0500 "$TMP/NeverExtensionSandbox" "$DEST"
codesign --verify --strict --test-requirement "$REQ" "$DEST"
echo "Signed helper installed: $DEST"
