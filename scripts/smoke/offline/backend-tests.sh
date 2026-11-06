#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT_DIR}/services/api"
if [[ "${LAUNCHER_PREFLIGHT_PGX:-0}" == "1" || "${LAUNCHER_PREFLIGHT_PGX:-0}" == "true" ]]; then
  go test ./...
else
  echo "[Launcher] Тесты Backend: автономный режим launcher_nopgx. Для полной проверки с pgx: LAUNCHER_PREFLIGHT_PGX=1" >&2
  go test -tags launcher_nopgx ./...
fi
