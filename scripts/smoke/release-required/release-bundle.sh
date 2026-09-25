#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BUNDLE_DIR="${1:?Укажите каталог release bundle}"
PUBLIC_KEY="${NEVERLAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE:-${NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE:-${2:-}}}"
TRUST_STATE="${NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE:-${3:-}}"
TRUST_POLICY="${NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE:-${4:-}}"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"

test -d "${BUNDLE_DIR}"
for required in \
  "${BUNDLE_DIR}/PROVENANCE.json.sig" \
  "${BUNDLE_DIR}/RELEASE_TRUST_POLICY.json" \
  "${BUNDLE_DIR}/DELIVERY_MANIFEST.json" \
  "${BUNDLE_DIR}/PUBLIC_PRODUCTION_DELIVERY_MATRIX.json" \
  "${BUNDLE_DIR}/WINDOWS_SIGNING_EVIDENCE.json" \
  "${BUNDLE_DIR}/GUARD_RELEASE_ALLOWLIST_WINDOWS_DELIVERY.json" \
  "${BUNDLE_DIR}/neverruntime-windows-x64.exe" \
  "${BUNDLE_DIR}/neverruntime-windows-arm64.exe" \
  "${BUNDLE_DIR}/LINUX_PRODUCTION_EVIDENCE.json" \
  "${BUNDLE_DIR}/GUARD_RELEASE_ALLOWLIST_LINUX_DELIVERY.json" \
  "${BUNDLE_DIR}/LINUX_PACKAGE_MANIFEST_X64.json" \
  "${BUNDLE_DIR}/LINUX_PACKAGE_MANIFEST_ARM64.json" \
  "${BUNDLE_DIR}/neverlauncher-linux-x64-${VERSION}.tar.gz" \
  "${BUNDLE_DIR}/neverlauncher-linux-arm64-${VERSION}.tar.gz" \
  "${BUNDLE_DIR}/MACOS_NOTARIZATION_EVIDENCE.json" \
  "${BUNDLE_DIR}/GUARD_RELEASE_ALLOWLIST_MACOS_DELIVERY.json" \
  "${BUNDLE_DIR}/MACOS_PACKAGE_MANIFEST_X64.json" \
  "${BUNDLE_DIR}/MACOS_PACKAGE_MANIFEST_ARM64.json" \
  "${BUNDLE_DIR}/neverlauncher-desktop-${VERSION}-macos-x64.zip" \
  "${BUNDLE_DIR}/neverlauncher-desktop-${VERSION}-macos-arm64.zip" \
  "${BUNDLE_DIR}/MANAGED_JRE_MANIFEST.json" \
  "${BUNDLE_DIR}/MANAGED_JRE_EVIDENCE.json" \
  "${BUNDLE_DIR}/neverlauncher-jre-temurin21-windows-x64-${VERSION}.zip" \
  "${BUNDLE_DIR}/neverlauncher-jre-temurin21-windows-arm64-${VERSION}.zip" \
  "${BUNDLE_DIR}/neverlauncher-jre-temurin21-linux-x64-${VERSION}.tar.gz" \
  "${BUNDLE_DIR}/neverlauncher-jre-temurin21-linux-arm64-${VERSION}.tar.gz" \
  "${BUNDLE_DIR}/neverlauncher-jre-temurin21-macos-x64-${VERSION}.tar.gz" \
  "${BUNDLE_DIR}/neverlauncher-jre-temurin21-macos-arm64-${VERSION}.tar.gz" \
  "${BUNDLE_DIR}/SERVERBRIDGE2_CERTIFICATION.json" \
  "${BUNDLE_DIR}/BRIDGE_RELEASE_ALLOWLIST.json" \
  "${BUNDLE_DIR}/BRIDGE_PLUGIN_MANIFEST.json" \
  "${BUNDLE_DIR}/neverlauncher-desktop-package-${VERSION}.zip"; do
  if [[ ! -s "${required}" ]]; then
    echo "[NeverLauncher] release-bundle gate: отсутствует обязательный artifact ${required}" >&2
    exit 1
  fi
done
if [[ -z "${PUBLIC_KEY}" || ! -f "${PUBLIC_KEY}" ]]; then
  echo "[NeverLauncher] release-bundle gate требует внешний root Ed25519 public key" >&2
  exit 1
fi
if [[ -z "${TRUST_STATE}" ]]; then
  echo "[NeverLauncher] release-bundle gate требует persistent trust state через NEVERLAUNCHER_RELEASE_TRUST_STATE_FILE или третий аргумент" >&2
  exit 1
fi
if [[ -z "${TRUST_POLICY}" || ! -f "${TRUST_POLICY}" ]]; then
  echo "[NeverLauncher] release-bundle gate требует внешний current trust policy через NEVERLAUNCHER_RELEASE_TRUST_POLICY_FILE или четвёртый аргумент" >&2
  exit 1
fi
if [ -x "${ROOT_DIR}/dist/preflight/nl" ]; then
  "${ROOT_DIR}/dist/preflight/nl" release publish-check "${BUNDLE_DIR}" --public-key "${PUBLIC_KEY}" --trust-state "${TRUST_STATE}" --trust-policy "${TRUST_POLICY}"
else
  (cd "${ROOT_DIR}/cli" && go run -ldflags="-X main.version=${VERSION}" ./cmd/neverlauncher release publish-check "${BUNDLE_DIR}" --public-key "${PUBLIC_KEY}" --trust-state "${TRUST_STATE}" --trust-policy "${TRUST_POLICY}")
fi
