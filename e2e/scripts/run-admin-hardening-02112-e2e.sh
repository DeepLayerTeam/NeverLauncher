#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="neverlauncher-admin-hardening-02112-${GITHUB_RUN_ID:-local}-$$"
# Предпочитайте случайный свободный loopback-порт, чтобы не
# конфликтовать с другими PostgreSQL в том же агенте. Для
# разработчиков, которым нужен постоянный порт, остаётся явная настройка.
PORT="${NEVERLAUNCHER_ADMIN_HARDENING_PG_PORT:-}"
PUBLISH_PORT="127.0.0.1::5432"
if [[ -n "$PORT" ]]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] && (( 10#$PORT >= 1 && 10#$PORT <= 65535 )) || { echo "[admin-hardening-02112] invalid port" >&2; exit 2; }
  PUBLISH_PORT="127.0.0.1:${PORT}:5432"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "[admin-hardening-02112] required command missing: $1" >&2; exit 1; }; }
for cmd in docker go; do need "$cmd"; done

# Сохраняйте журналы ошибок в постоянном каталоге артефактов. Не
# выводите переменные окружения PostgreSQL или строку соединения в CI.
EVIDENCE_DIR="$ROOT/e2e/runtime-admin-hardening-02112"
mkdir -p "$EVIDENCE_DIR"
START_LOG="$EVIDENCE_DIR/docker-start.log"
READY_LOG="$EVIDENCE_DIR/postgres-readiness.log"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

postgres_diagnostics() {
  echo "[admin-hardening-02112] PostgreSQL container diagnostics:" >&2
  docker ps -a --filter "name=^/${CONTAINER}$" \
    --format 'name={{.Names}} status={{.Status}} ports={{.Ports}}' >&2 || true
  docker logs --tail 70 "$CONTAINER" >&2 || true
}

# На общих или загруженных CI-агентах Docker иногда временно отклоняет
# создание контейнера. Порт временный, каждая попытка должна поднимать
# новую БД. После неожиданного завершения оставьте контейнер до сбора
# журналов; очистка удалит его при выходе из скрипта.
STARTED=false
for attempt in 1 2 3; do
  cleanup
  echo "[admin-hardening-02112] starting isolated PostgreSQL (attempt $attempt/3)"
  if docker run -d --name "$CONTAINER" \
      -e POSTGRES_DB=neverlauncher \
      -e POSTGRES_USER=neverlauncher \
      -e POSTGRES_PASSWORD=neverlauncher \
      -p "$PUBLISH_PORT" postgres:16-alpine >"$START_LOG" 2>&1; then
    if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>>"$START_LOG" | grep -qx true; then
      STARTED=true
      break
    fi
    echo "[admin-hardening-02112] PostgreSQL exited immediately after container creation" >&2
  else
    echo "[admin-hardening-02112] docker run failed (attempt $attempt/3)" >&2
  fi
  cat "$START_LOG" >&2
  postgres_diagnostics
  if (( attempt < 3 )); then sleep "$attempt"; fi
done
if [[ "$STARTED" != true ]]; then
  echo "[admin-hardening-02112] unable to start PostgreSQL after 3 attempts" >&2
  exit 1
fi

if [[ -z "$PORT" ]]; then
  # docker inspect возвращает фактически назначенный порт хоста как для IPv4,
  # так и для dual-stack Docker. Нельзя предполагать фиксированный порт.
  PORT="$(docker inspect -f '{{ (index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort }}' "$CONTAINER" 2>>"$START_LOG")" || {
    cat "$START_LOG" >&2
    postgres_diagnostics
    echo "[admin-hardening-02112] could not inspect the published PostgreSQL port" >&2
    exit 1
  }
  if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( 10#$PORT < 1 || 10#$PORT > 65535 )); then
    postgres_diagnostics
    echo "[admin-hardening-02112] Docker returned an invalid PostgreSQL host port" >&2
    exit 1
  fi
fi
DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:${PORT}/neverlauncher?sslmode=disable"

READY=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U neverlauncher -d neverlauncher >"$READY_LOG" 2>&1; then
    READY=true
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != true ]]; then
    echo "[admin-hardening-02112] PostgreSQL container terminated before becoming ready" >&2
    break
  fi
  sleep 1
done
if [[ "$READY" != true ]]; then
  cat "$READY_LOG" >&2 || true
  postgres_diagnostics
  echo "[admin-hardening-02112] PostgreSQL did not become ready within 60 seconds" >&2
  exit 1
fi

echo "[admin-hardening-02112] running real PostgreSQL + ServerBridge v3 + CAS integration tests"
(
  cd "$ROOT/services/api"
  NEVERLAUNCHER_DURABLE_DSN="$DSN" NEVERLAUNCHER_SERVERBRIDGE_HA_DSN="$DSN" \
    go test -count=1 -timeout=180s ./internal/repository \
      -run 'Test(Hardening02112PostgresConcurrentRevisionCAS|ServerBridgeControl0195Postgres|ServerBridgeHAControlPlane01911MultiReplica|ServerBridgeEventStream0194Postgres|Durable(JobLeaseRecoversAcrossReplicaRestart|ScopeLeaseHasSingleDistributedOwner)0213)' -v
  go test -count=1 -timeout=120s ./internal/httpapi \
    -run 'Test(Hardening02112|RollbackOperationIdempotency0217|ServerBridgeOperations0219ProjectIsolation|OperationRoutesRequireAuthentication0217)' -v
)
echo "[admin-hardening-02112] PASS"
