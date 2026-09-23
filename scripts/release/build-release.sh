#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CANONICAL_VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
if [[ -n "${1:-}" && "$1" != "${CANONICAL_VERSION}" ]]; then
  echo "Ошибка: версия release задаётся только через VERSION=${CANONICAL_VERSION}; передано: $1" >&2
  exit 2
fi
VERSION="${CANONICAL_VERSION}"
OUT_DIR="${2:-${ROOT_DIR}/dist/release-${VERSION}}"
WORK_DIR="${ROOT_DIR}/dist/.release-${VERSION}"
PRIVATE_KEY="${NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE:-}"
PUBLIC_KEY="${NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE:-}"
COMPATIBILITY_MATRIX="${NEVERLAUNCHER_COMPATIBILITY_MATRIX_FILE:-}"
COMPATIBILITY_TARGETS="${NEVERLAUNCHER_COMPATIBILITY_TARGETS_FILE:-${ROOT_DIR}/compatibility/targets.json}"
DEVICE_TRUST_MATRIX="${NEVERLAUNCHER_DEVICE_TRUST_MATRIX_FILE:-}"
DEVICE_TRUST_TARGETS="${NEVERLAUNCHER_DEVICE_TRUST_TARGETS_FILE:-${ROOT_DIR}/device-trust/targets.json}"
SOURCE_COMMIT="${NEVERLAUNCHER_SOURCE_COMMIT:-}"

rm -rf "${OUT_DIR}" "${WORK_DIR}"
mkdir -p "${OUT_DIR}" "${WORK_DIR}"

log() { printf '[NeverLauncher %s] %s\n' "${VERSION}" "$*"; }
require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Ошибка: production release требует команду '$1'" >&2
    exit 1
  fi
}
require_file() {
  if [[ ! -f "$1" ]]; then
    echo "Ошибка: обязательный release artifact отсутствует: $1" >&2
    exit 1
  fi
}

for tool in go python3 npm cargo gradle; do require "${tool}"; done
if [[ -z "${PRIVATE_KEY}" || -z "${PUBLIC_KEY}" ]]; then
  echo "Ошибка: задайте NEVERLAUNCHER_RELEASE_SIGNING_PRIVATE_KEY_FILE и NEVERLAUNCHER_RELEASE_SIGNING_PUBLIC_KEY_FILE" >&2
  exit 1
fi
require_file "${PRIVATE_KEY}"
require_file "${PUBLIC_KEY}"
python3 "${ROOT_DIR}/scripts/version/manage.py" check
if [[ -n "${COMPATIBILITY_MATRIX}" ]]; then
  require_file "${COMPATIBILITY_MATRIX}"
  require_file "${COMPATIBILITY_TARGETS}"
fi
if [[ -n "${DEVICE_TRUST_MATRIX}" ]]; then
  require_file "${DEVICE_TRUST_MATRIX}"
  require_file "${DEVICE_TRUST_TARGETS}"
fi
if [[ -n "${COMPATIBILITY_MATRIX}" || -n "${DEVICE_TRUST_MATRIX}" ]]; then
  if [[ -z "${SOURCE_COMMIT}" ]] && command -v git >/dev/null 2>&1; then
    SOURCE_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || true)"
  fi
  if [[ -z "${SOURCE_COMMIT}" ]]; then
    echo "Ошибка: certified release требует NEVERLAUNCHER_SOURCE_COMMIT или git HEAD" >&2
    exit 1
  fi
fi

log "Сборка CLI linux/amd64"
(
  cd "${ROOT_DIR}/cli"
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/neverlauncher-cli-linux-amd64" ./cmd/neverlauncher
)
chmod +x "${OUT_DIR}/neverlauncher-cli-linux-amd64"

log "Сборка CLI windows/amd64"
(
  cd "${ROOT_DIR}/cli"
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/neverlauncher-cli-windows-amd64.exe" ./cmd/neverlauncher
)

log "Сборка Backend API linux/amd64 (production pgx, fail-closed)"
(
  cd "${ROOT_DIR}/services/api"
  GOOS=linux GOARCH=amd64 CGO_ENABLED="${NEVERLAUNCHER_API_CGO_ENABLED:-0}" go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/neverlauncher-api-linux-amd64" ./cmd/neverlauncher-api
)
chmod +x "${OUT_DIR}/neverlauncher-api-linux-amd64"
printf 'apiBuildMode=pgx-production\n' > "${OUT_DIR}/BUILD_NOTES.txt"

log "Сборка Admin Web"
(
  cd "${ROOT_DIR}/apps/admin"
  npm ci
  npm run build
)
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${ROOT_DIR}/apps/admin/dist" "${OUT_DIR}/neverlauncher-admin-web-${VERSION}.zip" --prefix admin

log "Сборка Desktop Web и native binary"
(
  cd "${ROOT_DIR}/apps/desktop"
  npm ci
  npm run build
)
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${ROOT_DIR}/apps/desktop/dist" "${OUT_DIR}/neverlauncher-desktop-web-${VERSION}.zip" --prefix desktop
cargo build --release --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
require_file "${ROOT_DIR}/apps/desktop/src-tauri/target/release/neverlauncher-desktop"
cp "${ROOT_DIR}/apps/desktop/src-tauri/target/release/neverlauncher-desktop" "${OUT_DIR}/neverlauncher-desktop-linux-amd64"
chmod +x "${OUT_DIR}/neverlauncher-desktop-linux-amd64"

log "Формирование и проверка реального Desktop package"
"${OUT_DIR}/neverlauncher-cli-linux-amd64" desktop package --version "${VERSION}" --artifact-dir "${OUT_DIR}" --out "${WORK_DIR}/desktop-package" --platform linux
"${OUT_DIR}/neverlauncher-cli-linux-amd64" desktop verify "${WORK_DIR}/desktop-package"
python3 "${ROOT_DIR}/scripts/release/zip-dir.py" "${WORK_DIR}/desktop-package" "${OUT_DIR}/neverlauncher-desktop-package-${VERSION}.zip" --prefix desktop-package

log "Сборка NeverRuntime"
cargo build --release --manifest-path "${ROOT_DIR}/runtime/neverruntime/Cargo.toml"
require_file "${ROOT_DIR}/runtime/neverruntime/target/release/neverruntime"
cp "${ROOT_DIR}/runtime/neverruntime/target/release/neverruntime" "${OUT_DIR}/neverruntime-linux-amd64"
chmod +x "${OUT_DIR}/neverruntime-linux-amd64"

log "Сборка ServerBridge JAR"
bash "${ROOT_DIR}/scripts/build/bridge-plugins.sh"
for bridge in velocity paper purpur; do
  src="${ROOT_DIR}/artifacts/plugins/neverlauncher-${bridge}-bridge-${VERSION}.jar"
  require_file "${src}"
  cp "${src}" "${OUT_DIR}/neverlauncher-${bridge}-bridge-${VERSION}.jar"
done
require_file "${ROOT_DIR}/artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json"
require_file "${ROOT_DIR}/artifacts/plugins/PLUGIN_MANIFEST.json"
cp "${ROOT_DIR}/artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json" "${OUT_DIR}/BRIDGE_RELEASE_ALLOWLIST.json"
cp "${ROOT_DIR}/artifacts/plugins/PLUGIN_MANIFEST.json" "${OUT_DIR}/BRIDGE_PLUGIN_MANIFEST.json"

log "Source archive только из git-tracked/allowlisted файлов"
python3 "${ROOT_DIR}/scripts/release/source-package.py" "${ROOT_DIR}" "${OUT_DIR}/neverlauncher-source-${VERSION}.zip" --list-file "${WORK_DIR}/source-files.txt"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/neverlauncher-source-${VERSION}.zip"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/neverlauncher-admin-web-${VERSION}.zip"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/neverlauncher-desktop-web-${VERSION}.zip"
python3 "${ROOT_DIR}/scripts/release/secret-scan.py" "${OUT_DIR}/neverlauncher-desktop-package-${VERSION}.zip"

log "Генерация RELEASE_MANIFEST/SHA256SUMS/SBOM/PROVENANCE"
release_build_args=(release build --version "${VERSION}" --out "${OUT_DIR}" --source-root "${ROOT_DIR}")
if [[ -n "${COMPATIBILITY_MATRIX}" ]]; then
  log "Встраивание machine-verifiable Minecraft Compatibility certification для commit ${SOURCE_COMMIT}"
  release_build_args+=(--compatibility-matrix "${COMPATIBILITY_MATRIX}" --compatibility-targets "${COMPATIBILITY_TARGETS}")
fi
if [[ -n "${DEVICE_TRUST_MATRIX}" ]]; then
  log "Встраивание machine-verifiable Device Trust certification для commit ${SOURCE_COMMIT}"
  release_build_args+=(--device-trust-matrix "${DEVICE_TRUST_MATRIX}" --device-trust-targets "${DEVICE_TRUST_TARGETS}")
fi
if [[ -n "${SOURCE_COMMIT}" ]]; then
  release_build_args+=(--source-commit "${SOURCE_COMMIT}")
fi
"${OUT_DIR}/neverlauncher-cli-linux-amd64" "${release_build_args[@]}"

log "Ed25519 release signing"
"${OUT_DIR}/neverlauncher-cli-linux-amd64" release sign "${OUT_DIR}" --private-key "${PRIVATE_KEY}"

log "Строгая проверка required artifacts/checksums/Ed25519 trust anchor"
"${OUT_DIR}/neverlauncher-cli-linux-amd64" release verify "${OUT_DIR}" --public-key "${PUBLIC_KEY}"
if [[ -n "${COMPATIBILITY_MATRIX}" && -n "${DEVICE_TRUST_MATRIX}" ]]; then
  log "Publish-check Minecraft Compatibility + Device Trust Release"
  "${OUT_DIR}/neverlauncher-cli-linux-amd64" release publish-check "${OUT_DIR}" --public-key "${PUBLIC_KEY}"
elif [[ -n "${COMPATIBILITY_MATRIX}" || -n "${DEVICE_TRUST_MATRIX}" ]]; then
  log "Передан неполный certification set: bundle проверен криптографически, но официальный publish-check 0.13.0 требует и Compatibility, и Device Trust evidence"
else
  log "Certification evidence не передан: bundle является CI release candidate и не проходит официальный publish-check"
fi

log "Каталог production-релиза готов: ${OUT_DIR}"
