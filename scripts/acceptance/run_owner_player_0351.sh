#!/usr/bin/env bash
# Real, disposable Backend acceptance. Never connects to production DB/storage.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# Only the CI/dev default test identity may be used. Do not point this runner at
# a supplied Backend; it must start its own ephemeral memory-only instance.
export NEVERLAUNCHER_TEST_ADMIN_EMAIL=admin@neverlauncher.local
export NEVERLAUNCHER_TEST_ADMIN_PASSWORD=admin
export NEVERLAUNCHER_REPOSITORY_DRIVER=memory
export NEVERLAUNCHER_STORAGE_DRIVER=local
export NEVERLAUNCHER_STORAGE_LOCAL_PATH="$TMP/storage"
PORT="$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1',0))
    print(s.getsockname()[1])
PY
)"
export NEVERLAUNCHER_HTTP_ADDR="127.0.0.1:$PORT"
VERSION="$(cat "$ROOT/VERSION")"
(
  cd "$ROOT/services/api"
  go build -tags neverlauncher_nopgx -trimpath -ldflags="-X main.version=$VERSION" -o "$TMP/neverlauncher-api" ./cmd/neverlauncher-api
)
"$TMP/neverlauncher-api" > "$TMP/backend.log" 2>&1 &
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
# Evidence path is caller-selected; this script never collects credentials,
# HTTP request bodies or raw Backend logs in the published artifact.
python3 "$ROOT/scripts/acceptance/owner_player_api_0351.py" \
  --backend "$BASE" --isolated-test-instance --output "${1:?Usage: $0 /absolute/result.json}"
