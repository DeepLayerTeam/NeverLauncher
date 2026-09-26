#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${ROOT_DIR}/dist/release-${VERSION}"
MODE="production"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-ad-hoc) MODE="adhoc"; shift ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    *)
      if [[ "$1" == --* ]]; then echo "unknown option: $1" >&2; exit 2; fi
      OUT_DIR="$1"; shift ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS x64+ARM64 production packages must be built on macOS" >&2; exit 2; }
for tool in go cargo rustup npm codesign lipo ditto shasum python3; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

SIGN_IDENTITY="${NEVERLAUNCHER_MACOS_SIGNING_IDENTITY:-}"
TEAM_ID="${NEVERLAUNCHER_MACOS_TEAM_ID:-}"
NOTARY_PROFILE="${NEVERLAUNCHER_MACOS_NOTARY_PROFILE:-}"
SIGNING_MODE="developer-id-notarized"
UPDATE_TRUST_MODE="developer-id-notarized"
TIMESTAMP_ARG="--timestamp"
if [[ "${MODE}" == "production" ]]; then
  command -v xcrun >/dev/null || { echo "xcrun is required for production notarization" >&2; exit 1; }
  [[ -x /usr/sbin/spctl ]] || { echo "spctl is required for production Gatekeeper validation" >&2; exit 1; }
  [[ -n "${SIGN_IDENTITY}" && -n "${TEAM_ID}" && -n "${NOTARY_PROFILE}" ]] || {
    echo "production macOS delivery requires NEVERLAUNCHER_MACOS_SIGNING_IDENTITY, NEVERLAUNCHER_MACOS_TEAM_ID and NEVERLAUNCHER_MACOS_NOTARY_PROFILE" >&2
    exit 2
  }
  [[ "${SIGN_IDENTITY}" == Developer\ ID\ Application:* ]] || { echo "signing identity must be Developer ID Application" >&2; exit 2; }
  [[ "${TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]] || { echo "NEVERLAUNCHER_MACOS_TEAM_ID must be a 10-character Apple Team ID" >&2; exit 2; }
else
  SIGN_IDENTITY="-"
  TEAM_ID="ADHOC-CI"
  SIGNING_MODE="adhoc-development"
  UPDATE_TRUST_MODE="adhoc-development"
  TIMESTAMP_ARG="--timestamp=none"
fi

mkdir -p "${OUT_DIR}"
WORK_ROOT="${OUT_DIR}/.macos-production-work"
rm -rf "${WORK_ROOT}"
mkdir -p "${WORK_ROOT}"
cleanup() { rm -rf "${WORK_ROOT}"; }
trap cleanup EXIT

# Tauri's Rust build embeds assets produced by the desktop web build.
(
  cd "${ROOT_DIR}/apps/desktop"
  npm ci
  npm run build
)

rustup target add x86_64-apple-darwin aarch64-apple-darwin
for target in x86_64-apple-darwin aarch64-apple-darwin; do
  cargo build --release --target "${target}" --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
  cargo build --release --target "${target}" --manifest-path "${ROOT_DIR}/runtime/neverruntime/Cargo.toml" --bin neverguard --bin neverruntime
done

NOTARY_X64=""
NOTARY_ARM64=""

for arch in x64 arm64; do
  case "${arch}" in
    x64) RUST_TARGET="x86_64-apple-darwin"; GOARCH="amd64"; LIPO_ARCH="x86_64" ;;
    arm64) RUST_TARGET="aarch64-apple-darwin"; GOARCH="arm64"; LIPO_ARCH="arm64" ;;
  esac

  GO_CLI="${WORK_ROOT}/neverlauncher-cli-${arch}"
  (
    cd "${ROOT_DIR}/cli"
    GOOS=darwin GOARCH="${GOARCH}" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${GO_CLI}" ./cmd/neverlauncher
  )

  APP_ROOT="${WORK_ROOT}/${arch}/NeverLauncher.app"
  MACOS_DIR="${APP_ROOT}/Contents/MacOS"
  RES_DIR="${APP_ROOT}/Contents/Resources"
  mkdir -p "${MACOS_DIR}" "${RES_DIR}"
  cp "${ROOT_DIR}/apps/desktop/src-tauri/target/${RUST_TARGET}/release/neverlauncher-desktop" "${MACOS_DIR}/neverlauncher-desktop"
  cp "${ROOT_DIR}/runtime/neverruntime/target/${RUST_TARGET}/release/neverguard" "${MACOS_DIR}/neverguard"
  cp "${ROOT_DIR}/runtime/neverruntime/target/${RUST_TARGET}/release/neverruntime" "${MACOS_DIR}/neverruntime"
  cp "${GO_CLI}" "${MACOS_DIR}/neverlauncher-cli"
  chmod 0755 "${MACOS_DIR}/"*

  cat > "${APP_ROOT}/Contents/Info.plist" <<EOF_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>NeverLauncher</string>
<key>CFBundleExecutable</key><string>neverlauncher-desktop</string>
<key>CFBundleIdentifier</key><string>ru.skif4er.neverlauncher</string>
<key>CFBundleName</key><string>NeverLauncher</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${VERSION}</string>
<key>CFBundleVersion</key><string>${VERSION}</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF_PLIST

  declare -A IDENTIFIERS=(
    [neverlauncher-desktop]="ru.skif4er.neverlauncher"
    [neverguard]="ru.skif4er.neverlauncher.guard"
    [neverruntime]="ru.skif4er.neverlauncher.runtime"
    [neverlauncher-cli]="ru.skif4er.neverlauncher.cli"
  )
  for binary in neverlauncher-desktop neverguard neverruntime neverlauncher-cli; do
    file="${MACOS_DIR}/${binary}"
    actual_arch="$(lipo -archs "${file}")"
    [[ "${actual_arch}" == "${LIPO_ARCH}" ]] || { echo "${file}: expected thin ${LIPO_ARCH}, got ${actual_arch}" >&2; exit 1; }
    codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier "${IDENTIFIERS[$binary]}" "${file}"
    codesign --verify --strict --verbose=2 "${file}"
    if [[ "${MODE}" == "production" ]]; then
      details="$(codesign -dv --verbose=4 "${file}" 2>&1)"
      grep -F "TeamIdentifier=${TEAM_ID}" <<<"${details}" >/dev/null || { echo "TeamIdentifier mismatch for ${file}" >&2; exit 1; }
      grep -E 'flags=.*runtime' <<<"${details}" >/dev/null || { echo "Hardened Runtime flag missing for ${file}" >&2; exit 1; }
    fi
  done

  python3 "${ROOT_DIR}/scripts/release/macos-package.py" manifest \
    --version "${VERSION}" --arch "${arch}" --team-id "${TEAM_ID}" \
    --trust-mode "${UPDATE_TRUST_MODE}" \
    --app "${APP_ROOT}" --out-dir "${OUT_DIR}"
  chmod 0644 "${APP_ROOT}/Contents/Info.plist" "${RES_DIR}/MACOS_PACKAGE_MANIFEST.json" "${RES_DIR}/COMPONENT_UPDATE_MANIFEST.json"

  codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier ru.skif4er.neverlauncher "${APP_ROOT}"
  codesign --verify --deep --strict --verbose=2 "${APP_ROOT}"
  if [[ "${MODE}" == "production" ]]; then
    app_details="$(codesign -dv --verbose=4 "${APP_ROOT}" 2>&1)"
    grep -F "TeamIdentifier=${TEAM_ID}" <<<"${app_details}" >/dev/null || { echo "TeamIdentifier mismatch for ${APP_ROOT}" >&2; exit 1; }
    grep -E 'flags=.*runtime' <<<"${app_details}" >/dev/null || { echo "Hardened Runtime flag missing for ${APP_ROOT}" >&2; exit 1; }
  fi

  NOTARY_ZIP="${WORK_ROOT}/neverlauncher-${arch}-notary.zip"
  rm -f "${NOTARY_ZIP}"
  ditto -c -k --sequesterRsrc --keepParent "${APP_ROOT}" "${NOTARY_ZIP}"

  if [[ "${MODE}" == "production" ]]; then
    NOTARY_JSON="${WORK_ROOT}/notary-${arch}.json"
    xcrun notarytool submit "${NOTARY_ZIP}" --keychain-profile "${NOTARY_PROFILE}" --wait --output-format json > "${NOTARY_JSON}"
    python3 - "${NOTARY_JSON}" <<'PY'
import json, sys
p=json.load(open(sys.argv[1], encoding='utf-8'))
if p.get('status') != 'Accepted' or not p.get('id'):
    raise SystemExit(f"notarytool did not accept package: {p}")
PY
    xcrun stapler staple "${APP_ROOT}"
    xcrun stapler validate "${APP_ROOT}"
    /usr/sbin/spctl --assess --type execute --verbose=2 "${APP_ROOT}"
    codesign --verify --deep --strict --verbose=2 "${APP_ROOT}"
    if [[ "${arch}" == "x64" ]]; then NOTARY_X64="${NOTARY_JSON}"; else NOTARY_ARM64="${NOTARY_JSON}"; fi
  fi

  python3 "${ROOT_DIR}/scripts/release/macos-package.py" finalize \
    --version "${VERSION}" --arch "${arch}" \
    --app "${APP_ROOT}" --out-dir "${OUT_DIR}"

  FINAL_ZIP="${OUT_DIR}/neverlauncher-desktop-${VERSION}-macos-${arch}.zip"
  rm -f "${FINAL_ZIP}"
  ditto -c -k --sequesterRsrc --keepParent "${APP_ROOT}" "${FINAL_ZIP}"
  python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${FINAL_ZIP}"
done

GENERATED_AT="$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
PY
)"
EVIDENCE_ARGS=(
  evidence --version "${VERSION}" --signing-mode "${SIGNING_MODE}" --team-id "${TEAM_ID}"
  --generated-at "${GENERATED_AT}" --out-dir "${OUT_DIR}"
)
if [[ "${MODE}" == "production" ]]; then
  EVIDENCE_ARGS+=(--notary-x64-json "${NOTARY_X64}" --notary-arm64-json "${NOTARY_ARM64}")
fi
python3 "${ROOT_DIR}/scripts/release/macos-package.py" "${EVIDENCE_ARGS[@]}"

for arch in x64 arm64; do
  shasum -a 256 \
    "${OUT_DIR}/neverlauncher-cli-macos-${arch}" \
    "${OUT_DIR}/neverlauncher-desktop-macos-${arch}" \
    "${OUT_DIR}/neverguard-macos-${arch}" \
    "${OUT_DIR}/neverruntime-macos-${arch}" \
    "${OUT_DIR}/neverlauncher-desktop-${VERSION}-macos-${arch}.zip"
done

echo "NeverLauncher ${VERSION} macOS x64+ARM64 packages prepared (signingMode=${SIGNING_MODE})"
