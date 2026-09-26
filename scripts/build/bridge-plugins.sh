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
    :plugins:bungeecord-bridge:clean :plugins:bungeecord-bridge:jar \
    :plugins:waterfall-bridge:clean :plugins:waterfall-bridge:jar \
    :plugins:bukkit-bridge:clean :plugins:bukkit-bridge:jar \
    :plugins:spigot-bridge:clean :plugins:spigot-bridge:jar \
    :plugins:paper-bridge:clean :plugins:paper-bridge:jar \
    :plugins:purpur-bridge:clean :plugins:purpur-bridge:jar \
    :plugins:folia-bridge:clean :plugins:folia-bridge:jar \
    :plugins:fabric-bridge:clean :plugins:fabric-bridge:remapJar \
    :plugins:forge-bridge:clean :plugins:forge-bridge:jar \
    :plugins:neoforge-bridge:clean :plugins:neoforge-bridge:jar
)

copy_artifact() {
  local module="$1" expected="$2" src
  src="$(find "$ROOT/plugins/$module/build/libs" -maxdepth 1 -type f -name "*.jar" -print -quit)"
  [[ -n "$src" && -s "$src" ]] || { echo "[NeverLauncher] missing Gradle artifact for $module" >&2; exit 1; }
  cp "$src" "$OUT/$expected"
}
copy_artifact velocity-bridge "neverlauncher-velocity-bridge-${VERSION}.jar"
copy_artifact bungeecord-bridge "neverlauncher-bungeecord-bridge-${VERSION}.jar"
copy_artifact waterfall-bridge "neverlauncher-waterfall-bridge-${VERSION}.jar"
copy_artifact bukkit-bridge "neverlauncher-bukkit-bridge-${VERSION}.jar"
copy_artifact spigot-bridge "neverlauncher-spigot-bridge-${VERSION}.jar"
copy_artifact paper-bridge "neverlauncher-paper-bridge-${VERSION}.jar"
copy_artifact purpur-bridge "neverlauncher-purpur-bridge-${VERSION}.jar"
copy_artifact folia-bridge "neverlauncher-folia-bridge-${VERSION}.jar"
FABRIC_SRC="$ROOT/plugins/fabric-bridge/build/libs/neverlauncher-fabric-bridge-${VERSION}.jar"
[[ -s "$FABRIC_SRC" ]] || { echo "[NeverLauncher] missing remapped Fabric artifact" >&2; exit 1; }
cp "$FABRIC_SRC" "$OUT/neverlauncher-fabric-bridge-${VERSION}.jar"
copy_artifact forge-bridge "neverlauncher-forge-bridge-${VERSION}.jar"
copy_artifact neoforge-bridge "neverlauncher-neoforge-bridge-${VERSION}.jar"

for artifact in "$OUT"/neverlauncher-{velocity,bungeecord,waterfall,bukkit,spigot,paper,purpur,folia,forge,neoforge}-bridge-"${VERSION}".jar; do
  jar tf "$artifact" | grep -q '^ru/neverlauncher/bridge/common/NeverLauncherApiClient.class$' || {
    echo "[NeverLauncher] bridge common runtime classes missing from $(basename "$artifact")" >&2
    exit 1
  }
done
for platform in velocity bungeecord waterfall; do
  artifact="$OUT/neverlauncher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class$' || {
    echo "[NeverLauncher] proxy-family runtime classes missing from $(basename "$artifact")" >&2
    exit 1
  }
done
for platform in bungeecord waterfall; do
  artifact="$OUT/neverlauncher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.class$' || {
    echo "[NeverLauncher] Bungee-family runtime classes missing from $(basename "$artifact")" >&2
    exit 1
  }
  jar tf "$artifact" | grep -q '^bungee.yml$' || {
    echo "[NeverLauncher] bungee.yml missing from $(basename "$artifact")" >&2
    exit 1
  }
done

for platform in bukkit spigot paper purpur folia; do
  artifact="$OUT/neverlauncher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class$' || {
    echo "[NeverLauncher] Bukkit-family runtime classes missing from $(basename "$artifact")" >&2
    exit 1
  }
done
jar tf "$OUT/neverlauncher-folia-bridge-${VERSION}.jar" | grep -q '^plugin.yml$' || {
  echo "[NeverLauncher] Folia descriptor is missing" >&2
  exit 1
}
unzip -p "$OUT/neverlauncher-folia-bridge-${VERSION}.jar" plugin.yml | grep -q '^folia-supported: true$' || {
  echo "[NeverLauncher] Folia artifact is not explicitly marked folia-supported" >&2
  exit 1
}

FABRIC_ARTIFACT="$OUT/neverlauncher-fabric-bridge-${VERSION}.jar"
for entry in \
  'fabric.mod.json' \
  'neverlauncher.fabric.mixins.json' \
  'ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.class' \
  'ru/neverlauncher/bridge/fabric/mixin/ServerLoginNetworkHandlerAccessor.class'; do
  jar tf "$FABRIC_ARTIFACT" | grep -q "^${entry}$" || {
    echo "[NeverLauncher] Fabric artifact missing ${entry}" >&2
    exit 1
  }
done
jar tf "$FABRIC_ARTIFACT" | grep -Eq '^META-INF/jars/bridge-common-[^/]+\.jar$' || {
  echo "[NeverLauncher] Fabric artifact does not embed bridge-common runtime" >&2
  exit 1
}
python3 - "$FABRIC_ARTIFACT" <<'PY_FABRIC_META'
import json
import sys
import zipfile

artifact = sys.argv[1]
try:
    with zipfile.ZipFile(artifact) as zf:
        metadata = json.loads(zf.read("fabric.mod.json"))
except (OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
    raise SystemExit(f"[NeverLauncher] Fabric metadata is unreadable: {exc}")

if metadata.get("environment") != "server":
    raise SystemExit("[NeverLauncher] Fabric artifact must be server-only")
custom = metadata.get("custom")
neverlauncher = custom.get("neverlauncher") if isinstance(custom, dict) else None
if not isinstance(neverlauncher, dict) or neverlauncher.get("clientModRequired") is not False:
    raise SystemExit("[NeverLauncher] Fabric artifact must not require a client mod")
PY_FABRIC_META

for platform in forge neoforge; do
  artifact="$OUT/neverlauncher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/neverlauncher/bridge/modloader/ModLoaderBridgeRuntime.class$' || {
    echo "[NeverLauncher] modloader-family runtime classes missing from $(basename "$artifact")" >&2
    exit 1
  }
done
jar tf "$OUT/neverlauncher-forge-bridge-${VERSION}.jar" | grep -q '^META-INF/mods.toml$' || {
  echo "[NeverLauncher] Forge mods.toml missing" >&2
  exit 1
}
jar tf "$OUT/neverlauncher-neoforge-bridge-${VERSION}.jar" | grep -q '^META-INF/neoforge.mods.toml$' || {
  echo "[NeverLauncher] NeoForge neoforge.mods.toml missing" >&2
  exit 1
}

(
  cd "$OUT"
  sha256sum neverlauncher-*-bridge-"${VERSION}".jar | sort > SHA256SUMS
)
VELOCITY_SHA256="$(sha256sum "$OUT/neverlauncher-velocity-bridge-${VERSION}.jar" | awk '{print $1}')"
BUNGEECORD_SHA256="$(sha256sum "$OUT/neverlauncher-bungeecord-bridge-${VERSION}.jar" | awk '{print $1}')"
WATERFALL_SHA256="$(sha256sum "$OUT/neverlauncher-waterfall-bridge-${VERSION}.jar" | awk '{print $1}')"
BUKKIT_SHA256="$(sha256sum "$OUT/neverlauncher-bukkit-bridge-${VERSION}.jar" | awk '{print $1}')"
SPIGOT_SHA256="$(sha256sum "$OUT/neverlauncher-spigot-bridge-${VERSION}.jar" | awk '{print $1}')"
PAPER_SHA256="$(sha256sum "$OUT/neverlauncher-paper-bridge-${VERSION}.jar" | awk '{print $1}')"
PURPUR_SHA256="$(sha256sum "$OUT/neverlauncher-purpur-bridge-${VERSION}.jar" | awk '{print $1}')"
FOLIA_SHA256="$(sha256sum "$OUT/neverlauncher-folia-bridge-${VERSION}.jar" | awk '{print $1}')"
FABRIC_SHA256="$(sha256sum "$OUT/neverlauncher-fabric-bridge-${VERSION}.jar" | awk '{print $1}')"
FORGE_SHA256="$(sha256sum "$OUT/neverlauncher-forge-bridge-${VERSION}.jar" | awk '{print $1}')"
NEOFORGE_SHA256="$(sha256sum "$OUT/neverlauncher-neoforge-bridge-${VERSION}.jar" | awk '{print $1}')"
cat > "$OUT/BRIDGE_RELEASE_ALLOWLIST.json" <<JSON
{"${VERSION}":{"velocitySha256":["${VELOCITY_SHA256}"],"bungeeCordSha256":["${BUNGEECORD_SHA256}"],"waterfallSha256":["${WATERFALL_SHA256}"],"bukkitSha256":["${BUKKIT_SHA256}"],"spigotSha256":["${SPIGOT_SHA256}"],"paperSha256":["${PAPER_SHA256}"],"purpurSha256":["${PURPUR_SHA256}"],"foliaSha256":["${FOLIA_SHA256}"],"fabricSha256":["${FABRIC_SHA256}"],"forgeSha256":["${FORGE_SHA256}"],"neoforgeSha256":["${NEOFORGE_SHA256}"]}}
JSON
cat > "$OUT/PLUGIN_MANIFEST.json" <<JSON
{
  "schemaVersion": "1.2",
  "toolVersion": "$VERSION",
  "status": "built",
  "compiler": "gradle-real-platform-api",
  "integrityPolicy": "serverbridge-artifact-sha256-v1",
  "releaseAllowlist": "BRIDGE_RELEASE_ALLOWLIST.json",
  "artifacts": [
    {"id":"velocity","file":"neverlauncher-velocity-bridge-${VERSION}.jar","platform":"velocity","descriptor":"velocity-plugin.json","sha256":"${VELOCITY_SHA256}"},
    {"id":"bungeecord","file":"neverlauncher-bungeecord-bridge-${VERSION}.jar","platform":"bungeecord","descriptor":"bungee.yml","sha256":"${BUNGEECORD_SHA256}"},
    {"id":"waterfall","file":"neverlauncher-waterfall-bridge-${VERSION}.jar","platform":"waterfall","descriptor":"bungee.yml","sha256":"${WATERFALL_SHA256}"},
    {"id":"bukkit","file":"neverlauncher-bukkit-bridge-${VERSION}.jar","platform":"bukkit","descriptor":"plugin.yml","sha256":"${BUKKIT_SHA256}"},
    {"id":"spigot","file":"neverlauncher-spigot-bridge-${VERSION}.jar","platform":"spigot","descriptor":"plugin.yml","sha256":"${SPIGOT_SHA256}"},
    {"id":"paper","file":"neverlauncher-paper-bridge-${VERSION}.jar","platform":"paper","descriptor":"plugin.yml","sha256":"${PAPER_SHA256}"},
    {"id":"purpur","file":"neverlauncher-purpur-bridge-${VERSION}.jar","platform":"purpur","descriptor":"plugin.yml","sha256":"${PURPUR_SHA256}"},
    {"id":"folia","file":"neverlauncher-folia-bridge-${VERSION}.jar","platform":"folia","descriptor":"plugin.yml","sha256":"${FOLIA_SHA256}","foliaSupported":true},
    {"id":"fabric","file":"neverlauncher-fabric-bridge-${VERSION}.jar","platform":"fabric","descriptor":"fabric.mod.json","sha256":"${FABRIC_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"forge","file":"neverlauncher-forge-bridge-${VERSION}.jar","platform":"forge","descriptor":"META-INF/mods.toml","sha256":"${FORGE_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"neoforge","file":"neverlauncher-neoforge-bridge-${VERSION}.jar","platform":"neoforge","descriptor":"META-INF/neoforge.mods.toml","sha256":"${NEOFORGE_SHA256}","serverOnly":true,"clientModRequired":false}
  ]
}
JSON
python3 "$ROOT/serverbridge/certify_release.py" --artifacts "$OUT"
printf 'Production ServerBridge 2 artifacts, integrity allowlist and certification built in %s\n' "$OUT"
