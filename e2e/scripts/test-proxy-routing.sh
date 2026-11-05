#!/usr/bin/env bash
# Компилируйте и выполняйте поставляемые тесты парсера ServerBridge, сеансов, авторизации и
# маршрутизации. Совместимость платформенных JAR требует отдельных внешних тестов Velocity/Bungee.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/generated/ru/launcher/bridge/common" "$work/classes"
version="$(tr -d '\r\n' < "$root/VERSION")"
cat > "$work/generated/ru/launcher/bridge/common/BridgeVersion.java" <<JAVA
package ru.launcher.bridge.common;
public final class BridgeVersion { public static final String VERSION = "$version"; private BridgeVersion() {} }
JAVA
mapfile -t sources < <(find "$root/plugins/bridge-common/src/main/java" "$root/plugins/proxy-family-common/src/main/java" -name '*.java' -type f | sort)
mapfile -t tests < <(find "$root/plugins/bridge-common/src/test/java" -name '*Test.java' -type f | sort)
javac --release 21 -encoding UTF-8 -d "$work/classes" "$work/generated/ru/launcher/bridge/common/BridgeVersion.java" "${sources[@]}" "${tests[@]}"
for test in BridgeAuthResponse0287Test BridgeControlJournal0412Test BridgeControlResult0411Test PlatformControlReadback0416Test ProxyRoutes0417Test; do
  java -ea -cp "$work/classes" "ru.launcher.bridge.common.$test"
done
printf 'регрессионная проверка промышленного исходного кода Java для маршрутизации прокси 0.41.7: PASS\n'
