#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${1:-${ROOT_DIR}/dist/release-${VERSION}}"
MODE="production"
if [[ "${2:-}" == "--allow-ad-hoc" || "${1:-}" == "--allow-ad-hoc" ]]; then
  MODE="adhoc"
  [[ "${1:-}" == "--allow-ad-hoc" ]] && OUT_DIR="${ROOT_DIR}/dist/release-${VERSION}"
fi
[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS production package must be built on macOS" >&2; exit 2; }
for tool in cargo rustup lipo codesign ditto shasum python3; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }; done

SIGN_IDENTITY="${NEVERLAUNCHER_MACOS_SIGNING_IDENTITY:-}"
TEAM_ID="${NEVERLAUNCHER_MACOS_TEAM_ID:-}"
NOTARY_PROFILE="${NEVERLAUNCHER_MACOS_NOTARY_PROFILE:-}"
if [[ "${MODE}" == "production" ]]; then
  [[ -n "${SIGN_IDENTITY}" && -n "${TEAM_ID}" && -n "${NOTARY_PROFILE}" ]] || {
    echo "production macOS release requires Developer ID Application identity, Team ID and notarytool keychain profile via NEVERLAUNCHER_MACOS_SIGNING_IDENTITY, NEVERLAUNCHER_MACOS_TEAM_ID and NEVERLAUNCHER_MACOS_NOTARY_PROFILE" >&2; exit 2;
  }
  [[ "${SIGN_IDENTITY}" == Developer\ ID\ Application:* ]] || { echo "production signing identity must be a Developer ID Application certificate" >&2; exit 2; }
else
  SIGN_IDENTITY="-"
  TEAM_ID="ADHOC-CI"
fi

rustup target add aarch64-apple-darwin x86_64-apple-darwin
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --target "${target}" --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
  cargo build --release --target "${target}" --manifest-path "${ROOT_DIR}/runtime/neverruntime/Cargo.toml" --bin neverguard
done

PACKAGE_ROOT="${OUT_DIR}/macos-desktop-package"
APP="${PACKAGE_ROOT}/NeverLauncher.app"
MACOS_DIR="${APP}/Contents/MacOS"
RES_DIR="${APP}/Contents/Resources"
rm -rf "${PACKAGE_ROOT}"
mkdir -p "${MACOS_DIR}" "${RES_DIR}" "${OUT_DIR}"
lipo -create \
  "${ROOT_DIR}/apps/desktop/src-tauri/target/aarch64-apple-darwin/release/neverlauncher-desktop" \
  "${ROOT_DIR}/apps/desktop/src-tauri/target/x86_64-apple-darwin/release/neverlauncher-desktop" \
  -output "${MACOS_DIR}/neverlauncher-desktop"
lipo -create \
  "${ROOT_DIR}/runtime/neverruntime/target/aarch64-apple-darwin/release/neverguard" \
  "${ROOT_DIR}/runtime/neverruntime/target/x86_64-apple-darwin/release/neverguard" \
  -output "${MACOS_DIR}/neverguard"
chmod 0755 "${MACOS_DIR}/neverlauncher-desktop" "${MACOS_DIR}/neverguard"

cat > "${APP}/Contents/Info.plist" <<EOF_PLIST
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

if [[ "${MODE}" == "production" ]]; then DEV_REQUIRED=true; NOTARY_REQUIRED=true; else DEV_REQUIRED=false; NOTARY_REQUIRED=false; fi
if [[ "${MODE}" == "production" ]]; then TIMESTAMP_ARG="--timestamp"; else TIMESTAMP_ARG="--timestamp=none"; fi

# Sign the nested executables first. Their final signed bytes are then pinned in
# the package manifest, and the outer app signature seals that manifest.
codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier ru.skif4er.neverlauncher.guard "${MACOS_DIR}/neverguard"
codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" --identifier ru.skif4er.neverlauncher "${MACOS_DIR}/neverlauncher-desktop"
DESKTOP_HASH="$(shasum -a 256 "${MACOS_DIR}/neverlauncher-desktop" | awk '{print $1}')"
GUARD_HASH="$(shasum -a 256 "${MACOS_DIR}/neverguard" | awk '{print $1}')"
DESKTOP_SIZE="$(stat -f '%z' "${MACOS_DIR}/neverlauncher-desktop")"
GUARD_SIZE="$(stat -f '%z' "${MACOS_DIR}/neverguard")"

cat > "${RES_DIR}/MACOS_PACKAGE_MANIFEST.json" <<EOF_MANIFEST
{
  "schemaVersion":"1.0",
  "productVersion":"${VERSION}",
  "platform":"macos-universal",
  "neverGuardProtocolVersion":4,
  "authenticatedIpc":"unix-domain-socket+0600+peer-credentials+hmac-sha256-v4",
  "macosProductionHardeningVersion":1,
  "bundleIdentifier":"ru.skif4er.neverlauncher",
  "signingTeamId":"${TEAM_ID}",
  "desktopSha256":"${DESKTOP_HASH}",
  "desktopSize":${DESKTOP_SIZE},
  "guardSha256":"${GUARD_HASH}",
  "guardSize":${GUARD_SIZE},
  "developerIdRequired":${DEV_REQUIRED},
  "notarizationRequired":${NOTARY_REQUIRED}
}
EOF_MANIFEST
chmod 0644 "${APP}/Contents/Info.plist" "${RES_DIR}/MACOS_PACKAGE_MANIFEST.json"

codesign --force --sign "${SIGN_IDENTITY}" --options runtime "${TIMESTAMP_ARG}" "${APP}"
codesign --verify --deep --strict --verbose=2 "${APP}"
if [[ "${MODE}" == "production" ]]; then
  for signed in "${MACOS_DIR}/neverguard" "${MACOS_DIR}/neverlauncher-desktop"; do
    codesign -dv --verbose=4 "${signed}" 2>&1 | grep -F "TeamIdentifier=${TEAM_ID}" >/dev/null || { echo "signing team mismatch for ${signed}" >&2; exit 1; }
    codesign -dv --verbose=4 "${signed}" 2>&1 | grep -E 'flags=.*runtime' >/dev/null || { echo "Hardened Runtime flag missing for ${signed}" >&2; exit 1; }
  done
fi

TMP_ZIP="${OUT_DIR}/.neverlauncher-macos-notary-${VERSION}.zip"
ditto -c -k --sequesterRsrc --keepParent "${APP}" "${TMP_ZIP}"
if [[ "${MODE}" == "production" ]]; then
  command -v xcrun >/dev/null || { echo "xcrun is required for notarization" >&2; exit 1; }
  xcrun notarytool submit "${TMP_ZIP}" --keychain-profile "${NOTARY_PROFILE}" --wait
  xcrun stapler staple "${APP}"
  xcrun stapler validate "${APP}"
  /usr/sbin/spctl --assess --type execute --verbose=2 "${APP}"
  rm -f "${TMP_ZIP}"
  ditto -c -k --sequesterRsrc --keepParent "${APP}" "${TMP_ZIP}"
fi

SIGNING_MODE="adhoc-development"
[[ "${MODE}" == "production" ]] && SIGNING_MODE="developer-id-notarized"
cat > "${OUT_DIR}/GUARD_RELEASE_ALLOWLIST_MACOS.json" <<EOF_ALLOW
{"schemaVersion":"2.0","releases":{"${VERSION}":{"protocolVersion":4,"platforms":{"macos":{"signingMode":"${SIGNING_MODE}","artifacts":[{"guardSha256":"${GUARD_HASH}","launcherSha256":"${DESKTOP_HASH}"}]}}}}}
EOF_ALLOW
cp "${MACOS_DIR}/neverlauncher-desktop" "${OUT_DIR}/neverlauncher-desktop-macos-universal"
cp "${MACOS_DIR}/neverguard" "${OUT_DIR}/neverguard-macos-universal"
cp "${RES_DIR}/MACOS_PACKAGE_MANIFEST.json" "${OUT_DIR}/MACOS_PACKAGE_MANIFEST.json"
FINAL_ZIP="${OUT_DIR}/neverlauncher-desktop-${VERSION}-macos-universal.zip"
rm -f "${FINAL_ZIP}"
cp "${TMP_ZIP}" "${FINAL_ZIP}"
[[ "${MODE}" == production ]] && rm -f "${TMP_ZIP}"
shasum -a 256 "${FINAL_ZIP}" "${OUT_DIR}/neverlauncher-desktop-macos-universal" "${OUT_DIR}/neverguard-macos-universal"
echo "macOS ${MODE} package created: ${FINAL_ZIP}"
