#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT_DIR}/services/api"
if [[ "${LAUNCHER_PREFLIGHT_PGX:-0}" == "1" || "${LAUNCHER_PREFLIGHT_PGX:-0}" == "true" ]]; then
  go test ./...
else
  echo "[Launcher] backend tests: offline launcher_nopgx mode. Для pgx/full: LAUNCHER_PREFLIGHT_PGX=1" >&2
  go test -tags launcher_nopgx ./...
fi
