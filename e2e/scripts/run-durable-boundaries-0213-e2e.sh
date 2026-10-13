#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="neverlauncher-durable-0213-${GITHUB_RUN_ID:-local}-$$"
# Prefer a random free loopback port to avoid collisions with the other
# PostgreSQL stacks used in the same runner. An explicit override is retained
# for developers who require a predictable port.
PORT="${NEVERLAUNCHER_DURABLE_POSTGRES_PORT:-}"
PUBLISH_PORT="127.0.0.1::5432"
if [[ -n "$PORT" ]]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] && (( 10#$PORT >= 1 && 10#$PORT <= 65535 )) || { echo "[durable-0213] invalid port" >&2; exit 2; }
  PUBLISH_PORT="127.0.0.1:${PORT}:5432"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "[durable-0213] required command missing: $1" >&2; exit 1; }; }
for cmd in docker go; do need "$cmd"; done

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[durable-0213] starting isolated PostgreSQL"
docker run -d --rm --name "$CONTAINER" \
  -e POSTGRES_DB=neverlauncher \
  -e POSTGRES_USER=neverlauncher \
  -e POSTGRES_PASSWORD=neverlauncher \
  -p "$PUBLISH_PORT" postgres:16-alpine >/dev/null

if [[ -z "$PORT" ]]; then
  PORT="$(docker port "$CONTAINER" 5432/tcp | awk -F: '/127\.0\.0\.1/ {print $NF; exit}')"
  [[ "$PORT" =~ ^[0-9]+$ ]] || { echo "[durable-0213] unable to resolve published PostgreSQL port" >&2; exit 1; }
fi
DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:${PORT}/neverlauncher?sslmode=disable"

for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U neverlauncher -d neverlauncher >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$CONTAINER" pg_isready -U neverlauncher -d neverlauncher >/dev/null

echo "[durable-0213] running multi-replica lease/restart/fencing tests"
(
  cd "$ROOT/services/api"
  NEVERLAUNCHER_DURABLE_DSN="$DSN" go test ./internal/repository \
    -run 'TestDurable(JobLeaseRecoversAcrossReplicaRestart|ScopeLeaseHasSingleDistributedOwner)0213' \
    -count=1 -v
)

echo "[durable-0213] PASS"
