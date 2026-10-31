#!/usr/bin/env bash
# Live ServerBridge JVM/proxy/game compatibility. Does NOT accept fake server JARs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCOPE="${1:---all}"
case "$SCOPE" in --all) target=all ;; --core) target=core ;; *) echo 'usage: serverbridge-live-matrix-04113.sh [--core|--all]' >&2; exit 2 ;; esac
for executable in docker java gradle go cargo jq psql mvn; do
  command -v "$executable" >/dev/null || {
    echo "[0.41.13] real runtime prerequisite missing: $executable" >&2; exit 1;
  }
done
docker info >/dev/null 2>&1 || { echo '[0.41.13] Docker daemon unavailable: live certification impossible' >&2; exit 1; }
# Existing E2E creates real containers from upstream Minecraft/Proxy images,
# builds production bridge JARs, sends network join/revoke requests, and runs
# a real Mojang client JVM for Paper. The 0.41.13 extension records process,
# image and independently hashed network/log evidence as each service runs.
LAUNCHER_E2E_MODE=full bash "$ROOT/e2e/scripts/run-minecraft-e2e.sh"
python3 "$ROOT/serverbridge/live_matrix_04113.py" --root "$ROOT" \
  --runtime "$ROOT/e2e/runtime" --scope "$target" \
  --out "$ROOT/e2e/runtime/live-matrix-${target}-04113.json"
