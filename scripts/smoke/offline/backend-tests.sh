#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT_DIR}/services/api"
if [[ "${NEVERLAUNCHER_PREFLIGHT_PGX:-0}" == "1" || "${NEVERLAUNCHER_PREFLIGHT_PGX:-0}" == "true" ]]; then
  go test ./...
else
  echo "[NeverLauncher] backend tests: offline neverlauncher_nopgx mode. Для pgx/full: NEVERLAUNCHER_PREFLIGHT_PGX=1" >&2
  go test -tags neverlauncher_nopgx ./...
fi
