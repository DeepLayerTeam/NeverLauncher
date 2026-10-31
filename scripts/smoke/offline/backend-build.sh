#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
OUT="${ROOT_DIR}/dist/preflight/launcher-api"
mkdir -p "$(dirname "${OUT}")"
cd "${ROOT_DIR}/services/api"
if [[ "${LAUNCHER_PREFLIGHT_PGX:-0}" == "1" || "${LAUNCHER_PREFLIGHT_PGX:-0}" == "true" ]]; then
  go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" ./cmd/launcher-api
else
  echo "[Launcher] backend build: offline launcher_nopgx mode. Для pgx/full: LAUNCHER_PREFLIGHT_PGX=1" >&2
  go build -tags launcher_nopgx -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" ./cmd/launcher-api
fi
