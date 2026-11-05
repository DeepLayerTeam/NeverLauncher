#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="launcher-durable-0213-${GITHUB_RUN_ID:-local}-$$"
# Предпочитайте случайный свободный loopback-порт, чтобы не
# конфликтовать с другими PostgreSQL в том же агенте. Для
# разработчиков, которым нужен постоянный порт, остаётся явная настройка.
PORT="${LAUNCHER_DURABLE_POSTGRES_PORT:-}"
PUBLISH_PORT="127.0.0.1::5432"
if [[ -n "$PORT" ]]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] && (( 10#$PORT >= 1 && 10#$PORT <= 65535 )) || { echo "[durable-0213] invalid port" >&2; exit 2; }
  PUBLISH_PORT="127.0.0.1:${PORT}:5432"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "[durable-0213] отсутствует необходимая команда: $1" >&2; exit 1; }; }
for cmd in docker go; do need "$cmd"; done

# Сохраняйте журналы ошибок в постоянном каталоге артефактов. Не
# выводите переменные окружения PostgreSQL или строку соединения в CI.
EVIDENCE_DIR="$ROOT/e2e/runtime-durable-0213"
mkdir -p "$EVIDENCE_DIR"
START_LOG="$EVIDENCE_DIR/docker-start.log"
READY_LOG="$EVIDENCE_DIR/postgres-readiness.log"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

postgres_diagnostics() {
  echo "[durable-0213] диагностика контейнера PostgreSQL:" >&2
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
  echo "[durable-0213] запуск изолированного PostgreSQL (attempt $attempt/3)"
  if docker run -d --name "$CONTAINER" \
      -e POSTGRES_DB=launcher \
      -e POSTGRES_USER=launcher \
      -e POSTGRES_PASSWORD=launcher \
      -p "$PUBLISH_PORT" postgres:16-alpine >"$START_LOG" 2>&1; then
    if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>>"$START_LOG" | grep -qx true; then
      STARTED=true
      break
    fi
    echo "[durable-0213] PostgreSQL завершился сразу после создания контейнера" >&2
  else
    echo "[durable-0213] сбой docker run (попытка $attempt/3)" >&2
  fi
  cat "$START_LOG" >&2
  postgres_diagnostics
  if (( attempt < 3 )); then sleep "$attempt"; fi
done
if [[ "$STARTED" != true ]]; then
  echo "[durable-0213] не удалось запустить PostgreSQL после трёх попыток" >&2
  exit 1
fi

if [[ -z "$PORT" ]]; then
  # docker inspect возвращает фактически назначенный порт хоста как для IPv4,
  # так и для dual-stack Docker. Нельзя предполагать фиксированный порт.
  PORT="$(docker inspect -f '{{ (index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort }}' "$CONTAINER" 2>>"$START_LOG")" || {
    cat "$START_LOG" >&2
    postgres_diagnostics
    echo "[durable-0213] не удалось определить опубликованный порт PostgreSQL" >&2
    exit 1
  }
  if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( 10#$PORT < 1 || 10#$PORT > 65535 )); then
    postgres_diagnostics
    echo "[durable-0213] Docker вернул некорректный порт хоста PostgreSQL" >&2
    exit 1
  fi
fi
DSN="postgres://launcher:launcher@127.0.0.1:${PORT}/launcher?sslmode=disable"

READY=false
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U launcher -d launcher >"$READY_LOG" 2>&1; then
    READY=true
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != true ]]; then
    echo "[durable-0213] контейнер PostgreSQL завершился до перехода в состояние готовности" >&2
    break
  fi
  sleep 1
done
if [[ "$READY" != true ]]; then
  cat "$READY_LOG" >&2 || true
  postgres_diagnostics
  echo "[durable-0213] PostgreSQL не перешёл в состояние готовности за 60 секунд" >&2
  exit 1
fi

echo "[durable-0213] запуск проверок аренды, перезапуска и изоляции нескольких реплик"
(
  cd "$ROOT/services/api"
  LAUNCHER_DURABLE_DSN="$DSN" go test ./internal/repository \
    -run 'TestDurable(JobLeaseRecoversAcrossReplicaRestart|ScopeLeaseHasSingleDistributedOwner)0213' \
    -count=1 -v
)

echo "[durable-0213] PASS"
