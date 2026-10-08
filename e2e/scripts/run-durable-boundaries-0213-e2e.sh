#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="neverlauncher-durable-0213-${GITHUB_RUN_ID:-local}-$$"
PORT="${NEVERLAUNCHER_DURABLE_POSTGRES_PORT:-55434}"
DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:${PORT}/neverlauncher?sslmode=disable"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[durable-0213] required command missing: $1" >&2; exit 1; }; }
for cmd in docker go; do need "$cmd"; done

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[durable-0213] запуск изолированный PostgreSQL"
docker run -d --rm --name "$CONTAINER" \
  -e POSTGRES_DB=neverlauncher \
  -e POSTGRES_USER=neverlauncher \
  -e POSTGRES_PASSWORD=neverlauncher \
  -p "127.0.0.1:${PORT}:5432" postgres:16-alpine >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U neverlauncher -d neverlauncher >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$CONTAINER" pg_isready -U neverlauncher -d neverlauncher >/dev/null

echo "[durable-0213] работающий многорепликовый lease/restart/fencing тесты"
(
  cd "$ROOT/services/api"
  NEVERLAUNCHER_DURABLE_DSN="$DSN" go test ./internal/repository \
    -run 'TestDurable(JobLeaseRecoversAcrossReplicaRestart|ScopeLeaseHasSingleDistributedOwner)0213' \
    -count=1 -v
)

echo "[durable-0213] PASS"
