#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${1:-${ROOT_DIR}/dist/release-${VERSION}}"
PACKAGE_DIR="${OUT_DIR}/linux-desktop-package"
ARCH="$(uname -m)"
[[ "${ARCH}" == "x86_64" ]] || { echo "Linux production package currently requires x86_64, got ${ARCH}" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

cargo build --release --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
cargo build --release --manifest-path "${ROOT_DIR}/runtime/neverruntime/Cargo.toml" --bin neverguard
DESKTOP_SRC="${ROOT_DIR}/apps/desktop/src-tauri/target/release/neverlauncher-desktop"
GUARD_SRC="${ROOT_DIR}/runtime/neverruntime/target/release/neverguard"
[[ -x "${DESKTOP_SRC}" && -x "${GUARD_SRC}" ]] || { echo "Desktop/NeverGuard release binaries missing" >&2; exit 1; }

rm -rf "${PACKAGE_DIR}"
mkdir -p "${PACKAGE_DIR}" "${OUT_DIR}"
install -m 0755 "${DESKTOP_SRC}" "${PACKAGE_DIR}/neverlauncher-desktop"
install -m 0755 "${GUARD_SRC}" "${PACKAGE_DIR}/neverguard"

DESKTOP_HASH="$(sha256sum "${PACKAGE_DIR}/neverlauncher-desktop" | awk '{print $1}')"
GUARD_HASH="$(sha256sum "${PACKAGE_DIR}/neverguard" | awk '{print $1}')"
DESKTOP_SIZE="$(stat -c %s "${PACKAGE_DIR}/neverlauncher-desktop")"
GUARD_SIZE="$(stat -c %s "${PACKAGE_DIR}/neverguard")"
cat > "${PACKAGE_DIR}/LINUX_PACKAGE_MANIFEST.json" <<EOF
{
  "schemaVersion": "1.0",
  "productVersion": "${VERSION}",
  "platform": "linux-amd64",
  "neverGuardProtocolVersion": 4,
  "authenticatedIpc": "unix-domain-socket+0600+so-peercred+hmac-sha256-v4",
  "linuxProductionHardeningVersion": 1,
  "artifacts": [
    {"name":"neverlauncher-desktop","size":${DESKTOP_SIZE},"sha256":"${DESKTOP_HASH}"},
    {"name":"neverguard","size":${GUARD_SIZE},"sha256":"${GUARD_HASH}"}
  ]
}
EOF
chmod 0600 "${PACKAGE_DIR}/LINUX_PACKAGE_MANIFEST.json"
cat > "${OUT_DIR}/GUARD_RELEASE_ALLOWLIST_LINUX.json" <<EOF
{"schemaVersion":"2.0","releases":{"${VERSION}":{"protocolVersion":4,"platforms":{"linux":{"signingMode":"integrity-only","artifacts":[{"guardSha256":"${GUARD_HASH}","launcherSha256":"${DESKTOP_HASH}"}]}}}}}
EOF
chmod 0600 "${OUT_DIR}/GUARD_RELEASE_ALLOWLIST_LINUX.json"
cp "${PACKAGE_DIR}/LINUX_PACKAGE_MANIFEST.json" "${OUT_DIR}/LINUX_PACKAGE_MANIFEST.json"
chmod 0644 "${OUT_DIR}/LINUX_PACKAGE_MANIFEST.json"

cp "${PACKAGE_DIR}/neverlauncher-desktop" "${OUT_DIR}/neverlauncher-desktop-linux-amd64"
cp "${PACKAGE_DIR}/neverguard" "${OUT_DIR}/neverguard-linux-amd64"
chmod 0755 "${OUT_DIR}/neverlauncher-desktop-linux-amd64" "${OUT_DIR}/neverguard-linux-amd64"
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${PACKAGE_DIR}" "${OUT_DIR}/neverlauncher-desktop-${VERSION}-linux-amd64.zip" --prefix neverlauncher

echo "${PACKAGE_DIR}"
