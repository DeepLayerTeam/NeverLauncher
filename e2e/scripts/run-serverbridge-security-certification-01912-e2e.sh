#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MATRIX="$ROOT/serverbridge/security-e2e-matrix.json"
python3 - "$MATRIX" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p,encoding='utf-8'))
expected=['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','quilt','forge','neoforge','sponge','vanilla']
scenarios={'canonical-v3-domain','capability-downgrade','tampered-bridge-artifact','tampered-node-request','tampered-event','replayed-event','tampered-command','replayed-command','runtime-instance-rebind','online-key-rotation'}
if d.get('release')!='ServerBridge 3' or d.get('protocolVersion')!=3 or d.get('securityProfile')!='serverbridge3-security-01912': raise SystemExit('security matrix metadata mismatch')
if d.get('targets')!=expected: raise SystemExit('security matrix must cover all 14 ServerBridge 3 targets in release order')
if set(d.get('requiredScenarios') or [])!=scenarios or d.get('coverage')!='all-required-scenarios-on-every-target': raise SystemExit('security adversarial scenario matrix incomplete')
print(f'ServerBridge security E2E matrix: {len(expected)} targets x {len(scenarios)} scenarios')
PY
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/gen/ru/neverlauncher/bridge/common" "$TMP/classes"
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
cat > "$TMP/gen/ru/neverlauncher/bridge/common/BridgeVersion.java" <<JAVA
package ru.neverlauncher.bridge.common;
public final class BridgeVersion { public static final String VERSION = "$VERSION"; private BridgeVersion() {} }
JAVA
mapfile -t COMMON < <(find "$ROOT/plugins/bridge-common/src/main/java" -name '*.java' -type f | sort)
javac --release 17 -d "$TMP/classes" "$TMP/gen/ru/neverlauncher/bridge/common/BridgeVersion.java" "${COMMON[@]}" "$ROOT/e2e/java/ru/neverlauncher/bridge/common/ServerBridgeSecurityCertification01912Harness.java"
TARGETS=(velocity bungeecord waterfall bukkit spigot paper purpur folia fabric quilt forge neoforge sponge vanilla)
for target in "${TARGETS[@]}"; do
  java -cp "$TMP/classes" ru.neverlauncher.bridge.common.ServerBridgeSecurityCertification01912Harness "$target"
done
printf 'ServerBridge security E2E executed: %d targets x 10 scenarios\n' "${#TARGETS[@]}"
