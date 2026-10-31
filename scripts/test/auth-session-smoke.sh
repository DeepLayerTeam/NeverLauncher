#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${LAUNCHER_EXPECTED_VERSION:-$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")}"
API_BIN="${LAUNCHER_API_BIN:-${ROOT_DIR}/services/api/launcher-api}"
API_ADDR="${LAUNCHER_AUTH_SMOKE_ADDR:-127.0.0.1:18131}"
API_URL="http://${API_ADDR}"
LOG_FILE="${TMPDIR:-/tmp}/launcher-auth-session-smoke.log"

if [[ ! -x "${API_BIN}" ]]; then
  echo "[Launcher] API binary не найден, собираю offline memory-only" >&2
  ( cd "${ROOT_DIR}/services/api" && go build -tags launcher_nopgx -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o launcher-api ./cmd/launcher-api )
  API_BIN="${ROOT_DIR}/services/api/launcher-api"
fi

LAUNCHER_HTTP_ADDR="${API_ADDR}" LAUNCHER_REPOSITORY_DRIVER=memory LAUNCHER_STORAGE_DRIVER=local "${API_BIN}" >"${LOG_FILE}" 2>&1 &
PID=$!
cleanup() { kill "${PID}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do
  if curl -fsS "${API_URL}/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

curl -fsS "${API_URL}/health" | grep -q "${VERSION}"

status=$(curl -sS -o /tmp/nl-auth-smoke-unauth.json -w '%{http_code}' "${API_URL}/api/v1/auth/accounts")
if [[ "${status}" != "401" ]]; then
  echo "Ожидался 401 для protected endpoint без токена, получено ${status}" >&2
  cat /tmp/nl-auth-smoke-unauth.json >&2 || true
  exit 1
fi

login_json=$(curl -fsS -X POST "${API_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@launcher.local","password":"admin","deviceId":"auth-smoke"}')

access=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["tokens"]["accessToken"])' <<<"${login_json}")
refresh=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["tokens"]["refreshToken"])' <<<"${login_json}")

curl -fsS "${API_URL}/api/v1/auth/accounts" -H "Authorization: Bearer ${access}" | grep -q 'accounts-enforced'

refresh_json=$(curl -fsS -X POST "${API_URL}/api/v1/auth/refresh" \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${refresh}\"}")
new_access=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["tokens"]["accessToken"])' <<<"${refresh_json}")
new_refresh=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["tokens"]["refreshToken"])' <<<"${refresh_json}")
if [[ "${new_refresh}" == "${refresh}" ]]; then
  echo "Refresh token не был ротирован" >&2
  exit 1
fi

curl -fsS -X POST "${API_URL}/api/v1/auth/logout" -H "Authorization: Bearer ${new_access}" | grep -q 'logged-out'
status=$(curl -sS -o /tmp/nl-auth-smoke-revoked.json -w '%{http_code}' "${API_URL}/api/v1/auth/accounts" -H "Authorization: Bearer ${new_access}")
if [[ "${status}" != "401" ]]; then
  echo "Ожидался 401 после logout/revoke, получено ${status}" >&2
  cat /tmp/nl-auth-smoke-revoked.json >&2 || true
  exit 1
fi

# Регрессия 0.11.1: повторное использование погашенного refresh-токена должно компрометировать всё семейство.
replay_login=$(curl -fsS -X POST "${API_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@launcher.local","password":"admin","deviceId":"auth-smoke-replay"}')
replay_old=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["tokens"]["refreshToken"])' <<<"${replay_login}")
replay_rotated=$(curl -fsS -X POST "${API_URL}/api/v1/auth/refresh" \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${replay_old}\"}")
replay_access=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["tokens"]["accessToken"])' <<<"${replay_rotated}")
status=$(curl -sS -o /tmp/nl-auth-smoke-replay.json -w '%{http_code}' -X POST "${API_URL}/api/v1/auth/refresh" \
  -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"${replay_old}\"}")
if [[ "${status}" != "401" ]]; then
  echo "Ожидался 401 при replay consumed refresh token, получено ${status}" >&2
  cat /tmp/nl-auth-smoke-replay.json >&2 || true
  exit 1
fi
status=$(curl -sS -o /tmp/nl-auth-smoke-family-revoked.json -w '%{http_code}' "${API_URL}/api/v1/auth/accounts" -H "Authorization: Bearer ${replay_access}")
if [[ "${status}" != "401" ]]; then
  echo "Ожидался 401 для access token из compromised refresh family, получено ${status}" >&2
  cat /tmp/nl-auth-smoke-family-revoked.json >&2 || true
  exit 1
fi

echo "[Launcher] Auth session smoke OK for ${VERSION}"
