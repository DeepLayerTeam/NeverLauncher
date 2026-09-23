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
VELOCITY_SHA256="$(sha256sum "$OUT/neverlauncher-velocity-bridge-${VERSION}.jar" | awk '{print $1}')"
PAPER_SHA256="$(sha256sum "$OUT/neverlauncher-paper-bridge-${VERSION}.jar" | awk '{print $1}')"
PURPUR_SHA256="$(sha256sum "$OUT/neverlauncher-purpur-bridge-${VERSION}.jar" | awk '{print $1}')"
cat > "$OUT/BRIDGE_RELEASE_ALLOWLIST.json" <<JSON
{"${VERSION}":{"velocitySha256":["${VELOCITY_SHA256}"],"paperSha256":["${PAPER_SHA256}"],"purpurSha256":["${PURPUR_SHA256}"]}}
JSON
cat > "$OUT/PLUGIN_MANIFEST.json" <<JSON
{
  "schemaVersion": "1.1",
  "toolVersion": "$VERSION",
  "status": "built",
  "compiler": "gradle-real-platform-api",
  "integrityPolicy": "serverbridge-artifact-sha256-v1",
  "releaseAllowlist": "BRIDGE_RELEASE_ALLOWLIST.json",
  "artifacts": [
    {"id":"velocity","file":"neverlauncher-velocity-bridge-${VERSION}.jar","platform":"velocity","descriptor":"velocity-plugin.json","sha256":"${VELOCITY_SHA256}"},
    {"id":"paper","file":"neverlauncher-paper-bridge-${VERSION}.jar","platform":"paper","descriptor":"plugin.yml","sha256":"${PAPER_SHA256}"},
    {"id":"purpur","file":"neverlauncher-purpur-bridge-${VERSION}.jar","platform":"purpur","descriptor":"plugin.yml","sha256":"${PURPUR_SHA256}"}
  ]
}
JSON
printf 'Production bridge plugin artifacts and integrity allowlist built in %s\n' "$OUT"
