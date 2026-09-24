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

echo "[NeverLauncher ${VERSION}] Linux ${ARCH}: build frontend"
(
  cd "${ROOT_DIR}/apps/desktop"
  npm ci
  npm run build
)

echo "[NeverLauncher ${VERSION}] Linux ${ARCH}: build CLI/API"
(
  cd "${ROOT_DIR}/cli"
  GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/neverlauncher-cli-linux-${ARCH}" ./cmd/neverlauncher
)
(
  cd "${ROOT_DIR}/services/api"
  GOOS=linux GOARCH="${GOARCH}" CGO_ENABLED="${NEVERLAUNCHER_API_CGO_ENABLED:-0}" go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT_DIR}/neverlauncher-api-linux-${ARCH}" ./cmd/neverlauncher-api
)

echo "[NeverLauncher ${VERSION}] Linux ${ARCH}: build Desktop/NeverGuard/NeverRuntime natively"
cargo build --release --manifest-path "${ROOT_DIR}/apps/desktop/src-tauri/Cargo.toml"
cargo build --release --manifest-path "${ROOT_DIR}/runtime/neverruntime/Cargo.toml" --bins

install -m 0755 "${ROOT_DIR}/apps/desktop/src-tauri/target/release/neverlauncher-desktop" "${OUT_DIR}/neverlauncher-desktop-linux-${ARCH}"
install -m 0755 "${ROOT_DIR}/runtime/neverruntime/target/release/neverguard" "${OUT_DIR}/neverguard-linux-${ARCH}"
install -m 0755 "${ROOT_DIR}/runtime/neverruntime/target/release/neverruntime" "${OUT_DIR}/neverruntime-linux-${ARCH}"
chmod 0755 \
  "${OUT_DIR}/neverlauncher-cli-linux-${ARCH}" \
  "${OUT_DIR}/neverlauncher-api-linux-${ARCH}"

python3 "${ROOT_DIR}/scripts/release/linux-package.py" \
  --out "${OUT_DIR}" --version "${VERSION}" --architecture "${ARCH}"

echo "[NeverLauncher ${VERSION}] Linux ${ARCH} production package ready: ${OUT_DIR}"
