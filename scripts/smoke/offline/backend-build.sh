#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT="${ROOT_DIR}/dist/preflight/neverlauncher-api"
mkdir -p "$(dirname "${OUT}")"
cd "${ROOT_DIR}/services/api"
if [[ "${NEVERLAUNCHER_PREFLIGHT_PGX:-0}" == "1" || "${NEVERLAUNCHER_PREFLIGHT_PGX:-0}" == "true" ]]; then
  go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" ./cmd/neverlauncher-api
else
  echo "[NeverLauncher] backend build: offline neverlauncher_nopgx mode. Для pgx/full: NEVERLAUNCHER_PREFLIGHT_PGX=1" >&2
  go build -tags neverlauncher_nopgx -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" ./cmd/neverlauncher-api
fi
