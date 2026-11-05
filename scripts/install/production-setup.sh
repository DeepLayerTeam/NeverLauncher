#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
ENV_FILE="${ROOT_DIR}/deploy/production/env.production.example"
WORKSPACE="${ROOT_DIR}/.launcher/production-first-run"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENV_FILE="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "${WORKSPACE}"
REPORT="${WORKSPACE}/first-run-report-${VERSION}.json"
ADMIN_EMAIL=""
PUBLIC_URL="http://localhost"
POSTGRES_PASSWORD_SET="false"
TOKEN_SECRET_SET="false"
GUARD_ALLOWLIST_SET="false"
BRIDGE_ALLOWLIST_SET="false"

if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  set -a; source "${ENV_FILE}"; set +a
  ADMIN_EMAIL="${LAUNCHER_BOOTSTRAP_ADMIN_EMAIL:-${ADMIN_EMAIL}}"
  PUBLIC_URL="${LAUNCHER_PUBLIC_URL:-${PUBLIC_URL}}"
  [[ "${POSTGRES_PASSWORD:-}" != "" && "${POSTGRES_PASSWORD:-}" != change-me* ]] && POSTGRES_PASSWORD_SET="true"
  [[ "${LAUNCHER_AUTH_TOKEN_SECRET:-}" != "" && "${LAUNCHER_AUTH_TOKEN_SECRET:-}" != change-me* ]] && TOKEN_SECRET_SET="true"
  [[ "${LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON:-}" != "" ]] && GUARD_ALLOWLIST_SET="true"
  [[ "${LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON:-}" != "" ]] && BRIDGE_ALLOWLIST_SET="true"
fi

cat > "${REPORT}" <<JSON
{
  "schemaVersion": "${VERSION}",
  "toolVersion": "${VERSION}",
  "status": "prepared",
  "envFile": "${ENV_FILE}",
  "workspace": "${WORKSPACE}",
  "publicUrl": "${PUBLIC_URL}",
  "admin": {
    "email": "${ADMIN_EMAIL}",
    "nextStep": "задайте email явно при POST /api/v1/install/bootstrap-admin или nl install bootstrap-admin"
  },
  "project": {
    "projectId": "demo-project",
    "profileId": "vanilla",
    "channel": "stable",
    "nextStep": "POST /api/v1/install/first-project или nl install first-project"
  },
  "serverBridge": {
    "serverId": "velocity-production-10000",
    "kind": "velocity",
    "nextStep": "зарегистрируйте сервер Bridge и скопируйте токен в config.yml плагина"
  },
  "checks": [
    {"id": "env.file", "status": "$( [[ -f "${ENV_FILE}" ]] && echo ok || echo failed )", "message": "${ENV_FILE}"},
    {"id": "postgres.password", "status": "${POSTGRES_PASSWORD_SET}", "message": "Замените стандартный POSTGRES_PASSWORD перед промышленным запуском"},
    {"id": "token.secret", "status": "${TOKEN_SECRET_SET}", "message": "Замените стандартный LAUNCHER_AUTH_TOKEN_SECRET перед промышленным запуском"},
    {"id": "guard.release.allowlist", "status": "${GUARD_ALLOWLIST_SET}", "message": "Укажите LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON на основе объединённой производственной политики Guard schema 2.0"},
    {"id": "serverbridge.release.allowlist", "status": "${BRIDGE_ALLOWLIST_SET}", "message": "Укажите LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON на основе хешей итоговых релизных JAR ServerBridge"},
    {"id": "compose.file", "status": "$( [[ -f "${ROOT_DIR}/deploy/production/docker-compose.yml" ]] && echo ok || echo failed )", "message": "deploy/production/docker-compose.yml"},
    {"id": "nginx.file", "status": "$( [[ -f "${ROOT_DIR}/deploy/production/nginx.conf" ]] && echo ok || echo failed )", "message": "deploy/production/nginx.conf"}
  ],
  "commands": [
    "cp deploy/production/env.production.example deploy/production/.env",
    "cd deploy/production && docker compose --env-file .env up -d",
    "nl production first-run --output ${REPORT}",
    "nl e2e run --backend ${PUBLIC_URL} --server velocity-production-10000"
  ]
}
JSON

echo "[Launcher] отчёт первого промышленного запуска: ${REPORT}"
