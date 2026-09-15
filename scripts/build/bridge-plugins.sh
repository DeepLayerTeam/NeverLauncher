#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
OUT="$ROOT/artifacts/plugins"

if ! command -v gradle >/dev/null 2>&1; then
  echo "[NeverLauncher] production bridge build requires Gradle on PATH; API-stub fallback is forbidden" >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
(
  cd "$ROOT"
  gradle --no-daemon --console=plain \
    :plugins:velocity-bridge:clean :plugins:velocity-bridge:jar \
    :plugins:paper-bridge:clean :plugins:paper-bridge:jar \
    :plugins:purpur-bridge:clean :plugins:purpur-bridge:jar
)

copy_artifact() {
  local module="$1" expected="$2" src
  src="$(find "$ROOT/plugins/$module/build/libs" -maxdepth 1 -type f -name "*.jar" -print -quit)"
  [[ -n "$src" && -s "$src" ]] || { echo "[NeverLauncher] missing Gradle artifact for $module" >&2; exit 1; }
  cp "$src" "$OUT/$expected"
}
copy_artifact velocity-bridge "neverlauncher-velocity-bridge-${VERSION}.jar"
copy_artifact paper-bridge "neverlauncher-paper-bridge-${VERSION}.jar"
copy_artifact purpur-bridge "neverlauncher-purpur-bridge-${VERSION}.jar"

for artifact in "$OUT"/neverlauncher-*-bridge-"${VERSION}".jar; do
  jar tf "$artifact" | grep -q '^ru/neverlauncher/bridge/common/NeverLauncherApiClient.class$' || {
    echo "[NeverLauncher] bridge common runtime classes missing from $(basename "$artifact")" >&2
    exit 1
  }
done

(
  cd "$OUT"
  sha256sum neverlauncher-*-bridge-"${VERSION}".jar | sort > SHA256SUMS
)
cat > "$OUT/PLUGIN_MANIFEST.json" <<JSON
{
  "schemaVersion": "1.0",
  "toolVersion": "$VERSION",
  "status": "built",
  "compiler": "gradle-real-platform-api",
  "artifacts": [
    {"id":"velocity","file":"neverlauncher-velocity-bridge-${VERSION}.jar","platform":"velocity","descriptor":"velocity-plugin.json"},
    {"id":"paper","file":"neverlauncher-paper-bridge-${VERSION}.jar","platform":"paper","descriptor":"plugin.yml"},
    {"id":"purpur","file":"neverlauncher-purpur-bridge-${VERSION}.jar","platform":"purpur","descriptor":"plugin.yml"}
  ]
}
JSON
printf 'Production bridge plugin artifacts built against real platform APIs in %s\n' "$OUT"
