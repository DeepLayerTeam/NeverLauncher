#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deploy/production/docker-compose.yml"
NGINX_FILE="${ROOT_DIR}/deploy/production/nginx.conf"
ENV_FILE="${ROOT_DIR}/deploy/production/env.production.example"

test -s "${COMPOSE_FILE}"
test -s "${NGINX_FILE}"
test -s "${ENV_FILE}"
grep -q "neverlauncher-api" "${COMPOSE_FILE}"
grep -q "postgres:16" "${COMPOSE_FILE}"
grep -q "redis:7" "${COMPOSE_FILE}"
grep -q "NEVERLAUNCHER_AUTH_TOKEN_SECRET" "${COMPOSE_FILE}"
grep -q "proxy_pass http://api:8080" "${NGINX_FILE}"

if command -v docker >/dev/null 2>&1; then
  (cd "${ROOT_DIR}/deploy/production" && docker compose -f docker-compose.yml --env-file env.production.example config >/tmp/neverlauncher-compose-10000.yml)
else
  echo "[NeverLauncher] docker не найден: выполнена статическая проверка production compose"
fi

echo "[NeverLauncher] production compose config smoke OK"
