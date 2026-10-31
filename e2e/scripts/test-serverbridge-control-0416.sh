#!/usr/bin/env bash
# Compile actual production ServerBridge/Vanilla source, exercise postconditions and RCON TCP.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/classes" "$work/generated/ru/launcher/bridge/common"
version="$(tr -d '\r\n' < "$root/VERSION")"
cat > "$work/generated/ru/launcher/bridge/common/BridgeVersion.java" <<JAVA
package ru.launcher.bridge.common;
public final class BridgeVersion { public static final String VERSION = "$version"; private BridgeVersion() {} }
JAVA
mapfile -t common < <(find "$root/plugins/bridge-common/src/main/java" -name '*.java' -type f | sort)
mapfile -t vanilla < <(find "$root/plugins/vanilla-bridge/src/main/java" -name '*.java' -type f | sort)
mapfile -t tests < <(find "$root/plugins/bridge-common/src/test/java" "$root/plugins/vanilla-bridge/src/test/java" -name '*0416Test.java' -type f | sort)
javac --release 21 -encoding UTF-8 -d "$work/classes" "$work/generated/ru/launcher/bridge/common/BridgeVersion.java" "${common[@]}" "${vanilla[@]}" "${tests[@]}"
java -ea -cp "$work/classes" ru.launcher.bridge.common.PlatformControlReadback0416Test
java -ea -cp "$work/classes" ru.launcher.bridge.vanilla.VanillaRconReadback0416Test
java -ea -cp "$work/classes" ru.launcher.bridge.vanilla.VanillaRconWire0416Test
printf 'ServerBridge 0.41.6 Java/RCON source verification PASS\n'
