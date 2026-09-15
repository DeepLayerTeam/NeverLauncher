#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"

if ! command -v gradle >/dev/null 2>&1 || ! command -v jar >/dev/null 2>&1; then
  if [[ "${NEVERLAUNCHER_PREFLIGHT_BRIDGE_STRICT:-0}" == "1" || "${NEVERLAUNCHER_PREFLIGHT_BRIDGE_STRICT:-0}" == "true" ]]; then
    echo "[NeverLauncher] strict preflight: Gradle/JDK обязательны для ServerBridge" >&2
    exit 1
  fi
  echo "[NeverLauncher] Gradle/JDK не найдены: production bridge build пропущен локально; такой прогон не является production-ready" >&2
  exit 0
fi

bash "${ROOT_DIR}/scripts/build/bridge-plugins.sh"
for artifact in \
  "${ROOT_DIR}/artifacts/plugins/neverlauncher-velocity-bridge-${VERSION}.jar" \
  "${ROOT_DIR}/artifacts/plugins/neverlauncher-paper-bridge-${VERSION}.jar" \
  "${ROOT_DIR}/artifacts/plugins/neverlauncher-purpur-bridge-${VERSION}.jar"; do
  test -s "$artifact"
done
grep -q "${VERSION}" "${ROOT_DIR}/artifacts/plugins/PLUGIN_MANIFEST.json"
