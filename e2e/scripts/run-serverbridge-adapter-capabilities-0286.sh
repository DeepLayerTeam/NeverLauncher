#!/usr/bin/env bash
# Executes the real production bridge-common Java sources and fails on overclaims.
# Explicitly NOT a Minecraft process / login runtime certification.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/gen/ru/launcher/bridge/common" "$TMP/classes"
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
cat > "$TMP/gen/ru/launcher/bridge/common/BridgeVersion.java" <<JAVA
package ru.launcher.bridge.common;
public final class BridgeVersion { public static final String VERSION = "$VERSION"; private BridgeVersion() {} }
JAVA
mapfile -t SOURCES < <(find "$ROOT/plugins/bridge-common/src/main/java" -type f -name '*.java' | sort)
javac --release 17 -d "$TMP/classes" "$TMP/gen/ru/launcher/bridge/common/BridgeVersion.java" "${SOURCES[@]}" \
  "$ROOT/e2e/java/ru/launcher/bridge/common/ServerBridgeAdapterCapability0286Harness.java"
java -cp "$TMP/classes" ru.launcher.bridge.common.ServerBridgeAdapterCapability0286Harness
