#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
OUT="$ROOT/artifacts/plugins"

if ! command -v gradle >/dev/null 2>&1; then
  echo "[Launcher] Для рабочей сборки моста требуется Gradle в PATH; подмена заглушкой API запрещена" >&2
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
    :plugins:quilt-bridge:clean :plugins:quilt-bridge:remapJar \
    :plugins:sponge-bridge:clean :plugins:sponge-bridge:jar \
    :plugins:vanilla-bridge:clean :plugins:vanilla-bridge:jar \
    :plugins:forge-bridge:clean :plugins:forge-bridge:jar \
    :plugins:neoforge-bridge:clean :plugins:neoforge-bridge:jar
)

copy_artifact() {
  local module="$1" expected="$2" src
  src="$(find "$ROOT/plugins/$module/build/libs" -maxdepth 1 -type f -name "*.jar" -print -quit)"
  [[ -n "$src" && -s "$src" ]] || { echo "[Launcher] Не найден артефакт Gradle для $module" >&2; exit 1; }
  cp "$src" "$OUT/$expected"
}
copy_artifact velocity-bridge "launcher-velocity-bridge-${VERSION}.jar"
copy_artifact bungeecord-bridge "launcher-bungeecord-bridge-${VERSION}.jar"
copy_artifact waterfall-bridge "launcher-waterfall-bridge-${VERSION}.jar"
copy_artifact bukkit-bridge "launcher-bukkit-bridge-${VERSION}.jar"
copy_artifact spigot-bridge "launcher-spigot-bridge-${VERSION}.jar"
copy_artifact paper-bridge "launcher-paper-bridge-${VERSION}.jar"
copy_artifact purpur-bridge "launcher-purpur-bridge-${VERSION}.jar"
copy_artifact folia-bridge "launcher-folia-bridge-${VERSION}.jar"
FABRIC_SRC="$ROOT/plugins/fabric-bridge/build/libs/launcher-fabric-bridge-${VERSION}.jar"
[[ -s "$FABRIC_SRC" ]] || { echo "[Launcher] Отсутствует преобразованный артефакт Fabric" >&2; exit 1; }
cp "$FABRIC_SRC" "$OUT/launcher-fabric-bridge-${VERSION}.jar"
QUILT_SRC="$ROOT/plugins/quilt-bridge/build/libs/launcher-quilt-bridge-${VERSION}.jar"
[[ -s "$QUILT_SRC" ]] || { echo "[Launcher] Отсутствует преобразованный артефакт Quilt" >&2; exit 1; }
cp "$QUILT_SRC" "$OUT/launcher-quilt-bridge-${VERSION}.jar"
copy_artifact sponge-bridge "launcher-sponge-bridge-${VERSION}.jar"
copy_artifact vanilla-bridge "launcher-vanilla-bridge-${VERSION}.jar"
copy_artifact forge-bridge "launcher-forge-bridge-${VERSION}.jar"
copy_artifact neoforge-bridge "launcher-neoforge-bridge-${VERSION}.jar"

for artifact in "$OUT"/launcher-{velocity,bungeecord,waterfall,bukkit,spigot,paper,purpur,folia,sponge,vanilla,forge,neoforge}-bridge-"${VERSION}".jar; do
  jar tf "$artifact" | grep -q '^ru/launcher/bridge/common/LauncherApiClient.class$' || {
    echo "[Launcher] В артефакте отсутствуют общие классы Runtime для Bridge: $(basename "$artifact")" >&2
    exit 1
  }
done
for platform in velocity bungeecord waterfall; do
  artifact="$OUT/launcher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/launcher/bridge/proxy/ProxyBridgeRuntime.class$' || {
    echo "[Launcher] В артефакте отсутствуют классы Runtime семейства прокси: $(basename "$artifact")" >&2
    exit 1
  }
done
for platform in bungeecord waterfall; do
  artifact="$OUT/launcher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/launcher/bridge/bungee/BungeeFamilyBridgePlugin.class$' || {
    echo "[Launcher] В артефакте отсутствуют классы Runtime семейства Bungee: $(basename "$artifact")" >&2
    exit 1
  }
  jar tf "$artifact" | grep -q '^bungee.yml$' || {
    echo "[Launcher] В артефакте отсутствует bungee.yml: $(basename "$artifact")" >&2
    exit 1
  }
done

for platform in bukkit spigot paper purpur folia; do
  artifact="$OUT/launcher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.class$' || {
    echo "[Launcher] в файле отсутствуют классы Runtime семейства Bukkit: $(basename "$artifact")" >&2
    exit 1
  }
done
jar tf "$OUT/launcher-folia-bridge-${VERSION}.jar" | grep -q '^plugin.yml$' || {
  echo "[Launcher] Отсутствует дескриптор Folia" >&2
  exit 1
}
unzip -p "$OUT/launcher-folia-bridge-${VERSION}.jar" plugin.yml | grep -q '^folia-supported: true$' || {
  echo "[Launcher] Артефакт Folia не помечен явно как folia-supported" >&2
  exit 1
}

FABRIC_ARTIFACT="$OUT/launcher-fabric-bridge-${VERSION}.jar"
for entry in \
  'fabric.mod.json' \
  'launcher.fabric.mixins.json' \
  'ru/launcher/bridge/fabric/LauncherFabricBridge.class' \
  'ru/launcher/bridge/fabric/mixin/ServerLoginNetworkHandlerAccessor.class'; do
  jar tf "$FABRIC_ARTIFACT" | grep -q "^${entry}$" || {
    echo "[Launcher] В артефакте Fabric отсутствует ${entry}" >&2
    exit 1
  }
done
jar tf "$FABRIC_ARTIFACT" | grep -Eq '^META-INF/jars/bridge-common-[^/]+\.jar$' || {
  echo "[Launcher] Артефакт Fabric не содержит встроенную среду bridge-common" >&2
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
    raise SystemExit(f"[Launcher] Не удалось прочитать метаданные Fabric: {exc}")

if metadata.get("environment") != "server":
    raise SystemExit("[Launcher] Артефакт Fabric должен быть предназначен только для сервера")
custom = metadata.get("custom")
launcher = custom.get("launcher") if isinstance(custom, dict) else None
if not isinstance(launcher, dict) or launcher.get("clientModRequired") is not False:
    raise SystemExit("[Launcher] Артефакт Fabric не должен требовать клиентский мод")
PY_FABRIC_META

QUILT_ARTIFACT="$OUT/launcher-quilt-bridge-${VERSION}.jar"
for entry in 'fabric.mod.json' 'quilt.mod.json' 'launcher.quilt.mixins.json' 'ru/launcher/bridge/quilt/LauncherQuiltBridge.class'; do
  jar tf "$QUILT_ARTIFACT" | grep -q "^${entry}$" || { echo "[Launcher] В артефакте Quilt отсутствует ${entry}" >&2; exit 1; }
done
jar tf "$QUILT_ARTIFACT" | grep -Eq '^META-INF/jars/bridge-common-[^/]+\.jar$' || { echo "[Launcher] Артефакт Quilt не содержит встроенную среду bridge-common" >&2; exit 1; }
python3 - "$QUILT_ARTIFACT" <<'PY_QUILT_META'
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    data=json.loads(zf.read('fabric.mod.json'))
    depends=data.get('depends') or {}
    custom=(data.get('custom') or {}).get('launcher') or {}
    if data.get('environment')!='server' or 'quilt_loader' not in depends or custom.get('clientModRequired') is not False:
        raise SystemExit('[Launcher] Артефакт Quilt должен предназначаться только для Quilt и сервера, а clientModRequired должен быть false')
PY_QUILT_META

for platform in forge neoforge; do
  artifact="$OUT/launcher-${platform}-bridge-${VERSION}.jar"
  jar tf "$artifact" | grep -q '^ru/launcher/bridge/modloader/ModLoaderBridgeRuntime.class$' || {
    echo "[Launcher] В артефакте отсутствуют классы Runtime семейства загрузчиков модов: $(basename "$artifact")" >&2
    exit 1
  }
done
jar tf "$OUT/launcher-forge-bridge-${VERSION}.jar" | grep -q '^META-INF/mods.toml$' || {
  echo "[Launcher] Отсутствует mods.toml для Forge" >&2
  exit 1
}
jar tf "$OUT/launcher-neoforge-bridge-${VERSION}.jar" | grep -q '^META-INF/neoforge.mods.toml$' || {
  echo "[Launcher] Отсутствует neoforge.mods.toml для NeoForge" >&2
  exit 1
}
jar tf "$OUT/launcher-sponge-bridge-${VERSION}.jar" | grep -q '^ru/launcher/bridge/sponge/LauncherSpongeBridge.class$' || { echo "[Launcher] Отсутствует класс Runtime Sponge" >&2; exit 1; }
jar tf "$OUT/launcher-vanilla-bridge-${VERSION}.jar" | grep -q '^ru/launcher/bridge/vanilla/LauncherVanillaBridge.class$' || { echo "[Launcher] Отсутствует вспомогательный класс Runtime Vanilla" >&2; exit 1; }
jar tf "$OUT/launcher-vanilla-bridge-${VERSION}.jar" | grep -q '^ru/launcher/bridge/vanilla/VanillaRconClient.class$' || { echo "[Launcher] Отсутствует клиент Vanilla RCON" >&2; exit 1; }

(
  cd "$OUT"
  sha256sum launcher-*-bridge-"${VERSION}".jar | sort > SHA256SUMS
)
VELOCITY_SHA256="$(sha256sum "$OUT/launcher-velocity-bridge-${VERSION}.jar" | awk '{print $1}')"
BUNGEECORD_SHA256="$(sha256sum "$OUT/launcher-bungeecord-bridge-${VERSION}.jar" | awk '{print $1}')"
WATERFALL_SHA256="$(sha256sum "$OUT/launcher-waterfall-bridge-${VERSION}.jar" | awk '{print $1}')"
BUKKIT_SHA256="$(sha256sum "$OUT/launcher-bukkit-bridge-${VERSION}.jar" | awk '{print $1}')"
SPIGOT_SHA256="$(sha256sum "$OUT/launcher-spigot-bridge-${VERSION}.jar" | awk '{print $1}')"
PAPER_SHA256="$(sha256sum "$OUT/launcher-paper-bridge-${VERSION}.jar" | awk '{print $1}')"
PURPUR_SHA256="$(sha256sum "$OUT/launcher-purpur-bridge-${VERSION}.jar" | awk '{print $1}')"
FOLIA_SHA256="$(sha256sum "$OUT/launcher-folia-bridge-${VERSION}.jar" | awk '{print $1}')"
FABRIC_SHA256="$(sha256sum "$OUT/launcher-fabric-bridge-${VERSION}.jar" | awk '{print $1}')"
QUILT_SHA256="$(sha256sum "$OUT/launcher-quilt-bridge-${VERSION}.jar" | awk '{print $1}')"
SPONGE_SHA256="$(sha256sum "$OUT/launcher-sponge-bridge-${VERSION}.jar" | awk '{print $1}')"
VANILLA_SHA256="$(sha256sum "$OUT/launcher-vanilla-bridge-${VERSION}.jar" | awk '{print $1}')"
FORGE_SHA256="$(sha256sum "$OUT/launcher-forge-bridge-${VERSION}.jar" | awk '{print $1}')"
NEOFORGE_SHA256="$(sha256sum "$OUT/launcher-neoforge-bridge-${VERSION}.jar" | awk '{print $1}')"
cat > "$OUT/BRIDGE_RELEASE_ALLOWLIST.json" <<JSON
{
  "schemaVersion":"3.0",
  "release":"ServerBridge 3",
  "protocolVersion":3,
  "minimumProtocolVersion":3,
  "ga":true,
  "protocolV3Frozen":true,
  "protocolV3FeatureDigest":"098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc",
  "protocolV2Mode":"compatibility-deprecated",
  "securityProfile":"serverbridge3-security-01912",
  "securityCapabilityDigest":"088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4",
  "requiredFeatures":["security.protocol-v3-signing-domain","security.capability-downgrade-protection","security.command-signatures-v3","security.event-signatures-v3","security.runtime-instance-binding-v3","security.online-key-rotation-v1"],
  "releases":{
    "${VERSION}":{"velocitySha256":["${VELOCITY_SHA256}"],"bungeeCordSha256":["${BUNGEECORD_SHA256}"],"waterfallSha256":["${WATERFALL_SHA256}"],"bukkitSha256":["${BUKKIT_SHA256}"],"spigotSha256":["${SPIGOT_SHA256}"],"paperSha256":["${PAPER_SHA256}"],"purpurSha256":["${PURPUR_SHA256}"],"foliaSha256":["${FOLIA_SHA256}"],"fabricSha256":["${FABRIC_SHA256}"],"quiltSha256":["${QUILT_SHA256}"],"forgeSha256":["${FORGE_SHA256}"],"neoforgeSha256":["${NEOFORGE_SHA256}"],"spongeSha256":["${SPONGE_SHA256}"],"vanillaSha256":["${VANILLA_SHA256}"]}
  }
}
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
    {"id":"velocity","file":"launcher-velocity-bridge-${VERSION}.jar","platform":"velocity","descriptor":"velocity-plugin.json","sha256":"${VELOCITY_SHA256}"},
    {"id":"bungeecord","file":"launcher-bungeecord-bridge-${VERSION}.jar","platform":"bungeecord","descriptor":"bungee.yml","sha256":"${BUNGEECORD_SHA256}"},
    {"id":"waterfall","file":"launcher-waterfall-bridge-${VERSION}.jar","platform":"waterfall","descriptor":"bungee.yml","sha256":"${WATERFALL_SHA256}"},
    {"id":"bukkit","file":"launcher-bukkit-bridge-${VERSION}.jar","platform":"bukkit","descriptor":"plugin.yml","sha256":"${BUKKIT_SHA256}"},
    {"id":"spigot","file":"launcher-spigot-bridge-${VERSION}.jar","platform":"spigot","descriptor":"plugin.yml","sha256":"${SPIGOT_SHA256}"},
    {"id":"paper","file":"launcher-paper-bridge-${VERSION}.jar","platform":"paper","descriptor":"plugin.yml","sha256":"${PAPER_SHA256}"},
    {"id":"purpur","file":"launcher-purpur-bridge-${VERSION}.jar","platform":"purpur","descriptor":"plugin.yml","sha256":"${PURPUR_SHA256}"},
    {"id":"folia","file":"launcher-folia-bridge-${VERSION}.jar","platform":"folia","descriptor":"plugin.yml","sha256":"${FOLIA_SHA256}","foliaSupported":true},
    {"id":"fabric","file":"launcher-fabric-bridge-${VERSION}.jar","platform":"fabric","descriptor":"fabric.mod.json","sha256":"${FABRIC_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"quilt","file":"launcher-quilt-bridge-${VERSION}.jar","platform":"quilt","descriptor":"fabric.mod.json+quilt.mod.json","sha256":"${QUILT_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"forge","file":"launcher-forge-bridge-${VERSION}.jar","platform":"forge","descriptor":"META-INF/mods.toml","sha256":"${FORGE_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"neoforge","file":"launcher-neoforge-bridge-${VERSION}.jar","platform":"neoforge","descriptor":"META-INF/neoforge.mods.toml","sha256":"${NEOFORGE_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"sponge","file":"launcher-sponge-bridge-${VERSION}.jar","platform":"sponge","descriptor":"@Plugin","sha256":"${SPONGE_SHA256}","serverOnly":true,"clientModRequired":false},
    {"id":"vanilla","file":"launcher-vanilla-bridge-${VERSION}.jar","platform":"vanilla","descriptor":"Main-Class","sha256":"${VANILLA_SHA256}","sidecar":true,"loginGate":false}
  ]
}
JSON
python3 "$ROOT/serverbridge/certify_release.py" --artifacts "$OUT"
printf 'Промышленные артефакты ServerBridge 3, список разрешённых контрольных сумм и сертификация собраны в %s\n' "$OUT"
