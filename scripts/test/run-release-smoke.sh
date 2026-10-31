#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${LAUNCHER_EXPECTED_VERSION:-$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")}"
API_BIN="${TMPDIR:-/tmp}/launcher-api-smoke-${VERSION}"
API_ADDR="${LAUNCHER_SMOKE_ADDR:-127.0.0.1:18130}"
API_URL="http://${API_ADDR}"

printf '[Launcher] Release smoke %s: offline release gate\n' "${VERSION}"
LAUNCHER_PREFLIGHT_FRONTEND="${LAUNCHER_PREFLIGHT_FRONTEND:-auto}" \
LAUNCHER_PREFLIGHT_MODE=offline \
bash "${ROOT_DIR}/scripts/release/preflight.sh"

printf '[Launcher] Release smoke %s: production deployment config\n' "${VERSION}"
bash "${ROOT_DIR}/scripts/smoke/docker-required/production-compose-config.sh"

printf '[Launcher] Release smoke %s: backend API runtime smoke\n' "${VERSION}"
if [ -x "${ROOT_DIR}/dist/preflight/launcher-api" ]; then
  API_BIN="${ROOT_DIR}/dist/preflight/launcher-api"
else
  if ( cd "${ROOT_DIR}/services/api" && go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${API_BIN}" ./cmd/launcher-api ); then
    :
  else
    echo "[Launcher] pgx/full backend build недоступен; собираю launcher_nopgx fallback" >&2
    ( cd "${ROOT_DIR}/services/api" && go build -tags launcher_nopgx -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${API_BIN}" ./cmd/launcher-api )
  fi
fi
chmod +x "${API_BIN}" 2>/dev/null || true

LAUNCHER_HTTP_ADDR="${API_ADDR}" LAUNCHER_REPOSITORY_DRIVER=memory LAUNCHER_STORAGE_DRIVER=local "${API_BIN}" >/tmp/launcher-api-smoke-${VERSION}.log 2>&1 &
PID=$!
cleanup() { kill "${PID}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for _ in $(seq 1 50); do
  if curl -fsS "${API_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

SMOKE_TIMEOUT="${LAUNCHER_SMOKE_TIMEOUT:-45}"
run_api_smoke() {
  local name="$1"; shift
  echo "[Launcher][api-smoke:${name}] $*"
  timeout "${SMOKE_TIMEOUT}" "$@"
}

run_api_smoke api-required bash "${ROOT_DIR}/scripts/smoke/api-required/api-smoke.sh" "${API_URL}"
run_api_smoke auth-session bash "${ROOT_DIR}/scripts/test/auth-session-smoke.sh"
run_api_smoke admin-crud bash "${ROOT_DIR}/scripts/test/admin-crud-smoke.sh" "${API_URL}"
run_api_smoke package-product bash "${ROOT_DIR}/scripts/test/package-product-smoke.sh" "${API_URL}"

echo "[Launcher] Release smoke ${VERSION} завершён успешно"
