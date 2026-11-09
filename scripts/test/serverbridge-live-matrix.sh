#!/usr/bin/env bash
# Живая совместимость JVM/прокси/игры ServerBridge. Поддельные серверные JAR не
# допускаются.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCOPE="${1:---all}"
case "$SCOPE" in --all) target=all ;; --core) target=core ;; *) echo 'Использование: serverbridge-live-matrix-04113.sh [--core|--all]' >&2; exit 2 ;; esac
for executable in docker java gradle go cargo jq psql mvn; do
  command -v "$executable" >/dev/null || {
    echo "[0.41.13] отсутствует обязательный исполняемый файл реального Runtime: $executable" >&2; exit 1;
  }
done
docker info >/dev/null 2>&1 || { echo '[0.41.13] демон Docker недоступен: реальная сертификация невозможна' >&2; exit 1; }
# Существующий E2E создаёт настоящие контейнеры из upstream-образов
# Minecraft/Proxy, собирает промышленные JAR Bridge, отправляет сетевые запросы
# join/revoke и запускает настоящую клиентскую JVM Mojang для Paper. Расширение
# 0.41.13 записывает процесс, образ и независимо хешированные сетевые/журнальные
# доказательства по мере работы каждой службы.
LAUNCHER_E2E_MODE=full bash "$ROOT/e2e/scripts/run-minecraft-e2e.sh"
python3 "$ROOT/serverbridge/live_matrix_04113.py" --root "$ROOT" \
  --runtime "$ROOT/e2e/runtime" --scope "$target" \
  --out "$ROOT/e2e/runtime/live-matrix-${target}-04113.json"
