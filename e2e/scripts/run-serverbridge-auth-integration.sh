#!/usr/bin/env bash
# Компилирует фактический нейтральный к платформе код моста авторизации и HTTP и проверяет
# сценарии разрешения/отказа. Заглушки API платформ Minecraft не используются.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/classes" "$WORK/generated/ru/launcher/bridge/common"
cat > "$WORK/generated/ru/launcher/bridge/common/BridgeVersion.java" <<JAVA
package ru.launcher.bridge.common;
public final class BridgeVersion { public static final String VERSION = "$VERSION"; }
JAVA
javac -encoding UTF-8 -d "$WORK/classes" \
  "$WORK/generated/ru/launcher/bridge/common/BridgeVersion.java" \
  "$ROOT"/plugins/bridge-common/src/main/java/ru/launcher/bridge/common/*.java \
  "$ROOT"/plugins/proxy-family-common/src/main/java/ru/launcher/bridge/proxy/*.java \
  "$ROOT"/plugins/bridge-common/src/test/java/ru/launcher/bridge/common/BridgeAuthResponse0287Test.java
java -ea -cp "$WORK/classes" ru.launcher.bridge.common.BridgeAuthResponse0287Test
(
  cd "$ROOT/services/api"
  GOPROXY=off go test ./internal/bridgeidentity -count=1
)
echo "ServerBridge 0.28.7 проверки исходного кода Authlib/Join прошли"
