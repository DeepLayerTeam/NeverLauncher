#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"

if ! command -v gradle >/dev/null 2>&1 || ! command -v jar >/dev/null 2>&1; then
  if [[ "${LAUNCHER_PREFLIGHT_BRIDGE_STRICT:-0}" == "1" || "${LAUNCHER_PREFLIGHT_BRIDGE_STRICT:-0}" == "true" ]]; then
    echo "[Launcher] Строгая предварительная проверка: для ServerBridge необходимы Gradle и JDK" >&2
    exit 1
  fi
  echo "[Launcher] Gradle/JDK не найдены: Производственная сборка моста пропущена локально; такой запуск не подтверждает готовность к эксплуатации" >&2
  exit 0
fi

bash "${ROOT_DIR}/scripts/build/bridge-plugins.sh"
for platform in velocity bungeecord waterfall bukkit spigot paper purpur folia fabric quilt forge neoforge sponge vanilla; do
  artifact="${ROOT_DIR}/artifacts/plugins/launcher-${platform}-bridge-${VERSION}.jar"
  test -s "$artifact"
done
grep -q "${VERSION}" "${ROOT_DIR}/artifacts/plugins/PLUGIN_MANIFEST.json"
for field in velocitySha256 bungeeCordSha256 waterfallSha256 bukkitSha256 spigotSha256 paperSha256 purpurSha256 foliaSha256 fabricSha256 quiltSha256 forgeSha256 neoforgeSha256 spongeSha256 vanillaSha256; do
  grep -q "$field" "${ROOT_DIR}/artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json"
done
