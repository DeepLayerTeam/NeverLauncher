#!/usr/bin/env bash
# Настоящая приёмка на одноразовом Backend. К производственным БД и хранилищу не подключается.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# Допустима только стандартная тестовая идентичность CI/dev. Не направляйте этот runner на предоставленный
# Backend: он обязан запустить собственный временный экземпляр только в памяти.
export LAUNCHER_TEST_ADMIN_EMAIL=admin@launcher.local
export LAUNCHER_TEST_ADMIN_PASSWORD=admin
export LAUNCHER_REPOSITORY_DRIVER=memory
export LAUNCHER_STORAGE_DRIVER=local
export LAUNCHER_STORAGE_LOCAL_PATH="$TMP/storage"
PORT="$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1',0))
    print(s.getsockname()[1])
PY
)"
export LAUNCHER_HTTP_ADDR="127.0.0.1:$PORT"
VERSION="$(cat "$ROOT/VERSION")"
(
  cd "$ROOT/services/api"
  go build -tags launcher_nopgx -trimpath -ldflags="-X main.version=$VERSION" -o "$TMP/launcher-api" ./cmd/launcher-api
)
"$TMP/launcher-api" > "$TMP/backend.log" 2>&1 &
PID=$!
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 100); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo 'Disposable Backend failed to start (logs retained only during this run)' >&2
    exit 1
  fi
  if curl --noproxy '*' -fsS "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl --noproxy '*' -fsS "$BASE/health" >/dev/null
# Путь доказательств выбирает вызывающий; скрипт никогда не собирает учётные данные, тела
# HTTP-запросов и сырые журналы Backend в публикуемом артефакте.
python3 "$ROOT/scripts/acceptance/owner_player_api_0351.py" \
  --backend "$BASE" --isolated-test-instance --output "${1:?Usage: $0 /absolute/result.json}"
