#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT_DIR="${ROOT_DIR}/dist/release-${VERSION}"
if [[ $# -gt 0 && "$1" != --* ]]; then
  OUT_DIR="$1"
  shift
fi
EXPECTED_ARCH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-arch)
      EXPECTED_ARCH="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$(uname -m)" in
  x86_64|amd64) ARCH="x64"; GOARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64"; GOARCH="arm64" ;;
  *) echo "Unsupported native Linux architecture: $(uname -m)" >&2; exit 2 ;;
esac
if [[ -n "${EXPECTED_ARCH}" && "${EXPECTED_ARCH}" != "${ARCH}" ]]; then
  echo "Native runner architecture mismatch: expected ${EXPECTED_ARCH}, got ${ARCH}" >&2
  exit 2
fi

require() { command -v "$1" >/dev/null 2>&1 || { echo "$1 is required" >&2; exit 1; }; }
for tool in go cargo npm python3; do require "${tool}"; done
mkdir -p "${OUT_DIR}"

echo "[Launcher ${VERSION}] Linux ${ARCH}: build frontend"
(
  cd "${ROOT_DIR}/apps/desktop"
  npm ci
  npm run build
)

echo "[Launcher ${VERSION}] Linux ${ARCH}: build CLI/API"
(
  cd "${ROOT_DIR}/cli"
  GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.componentSetTrustedKey02310=${LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY:-} -X main.componentSetRootKey02312=${LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY:-}" -o "${OUT_DIR}/launcher-cli-linux-${ARCH}" ./cmd/launcher
)
(
  cd "${ROOT_DIR}/services/api"
  GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED="${LAUNCHER_API_CGO_ENABLED:-0}" go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${LAUNCHER_SOURCE_COMMIT:-${GITHUB_SHA:-unknown}}" -o "${OUT_DIR}/launcher-api-linux-${ARCH}" ./cmd/launcher-api
)

echo "[Launcher ${VERSION}] Linux ${ARCH}: build Desktop/Guard/Runtime natively"
cargo build --release --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
cargo build --release --manifest-path "${ROOT_DIR}/runtime/runtime/Cargo.toml" --bins

install -m 0755 "${ROOT_DIR}/apps/desktop/src-tauri/target/release/launcher-desktop" "${OUT_DIR}/launcher-desktop-linux-${ARCH}"
install -m 0755 "${ROOT_DIR}/runtime/runtime/target/release/guard" "${OUT_DIR}/guard-linux-${ARCH}"
install -m 0755 "${ROOT_DIR}/runtime/runtime/target/release/runtime" "${OUT_DIR}/runtime-linux-${ARCH}"
chmod 0755 \
  "${OUT_DIR}/launcher-cli-linux-${ARCH}" \
  "${OUT_DIR}/launcher-api-linux-${ARCH}"

python3 "${ROOT_DIR}/scripts/release/linux-package.py" \
  --out "${OUT_DIR}" --version "${VERSION}" --architecture "${ARCH}"

echo "[Launcher ${VERSION}] Linux ${ARCH} production package ready: ${OUT_DIR}"
