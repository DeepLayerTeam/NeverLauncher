#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
work=examples/extensions/gravit-five
sh sdk/java/core/build.sh
sh sdk/java/trusted-agent/build.sh
mkdir -p "$work/build/classes" "$work/build/agent-classes" "$work/build/game-classes" "$work/build/package/backend" "$work/build/package/cli"
find "$work/src" -name '*.java' | LC_ALL=C sort > "$work/build/sources.txt"
javac -encoding UTF-8 --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes -d "$work/build/classes" @"$work/build/sources.txt"
cat > "$work/build/manifest.mf" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: ported.compat.PortedSuite
MANIFEST
jar --create --file "$work/build/package/backend/gravit-five.jar" --manifest "$work/build/manifest.mf" -C sdk/java/core/build/classes . -C "$work/build/classes" .
cp "$work/build/package/backend/gravit-five.jar" "$work/build/package/cli/gravit-five.jar"
cp "$work/launcher-extension.json" "$work/build/package/launcher-extension.json"
javac -encoding UTF-8 --release 17 -encoding UTF-8 -cp sdk/java/trusted-agent/build/classes -d "$work/build/agent-classes" "$work/agent/ported/compat/LegacyGameHook.java"
mkdir -p "$work/build/agent-classes/META-INF/services"
printf '%s\n' 'ported.compat.LegacyGameHook' > "$work/build/agent-classes/META-INF/services/ru.launcher.trusted.MinecraftHook"
jar --create --file "$work/build/game-hook.jar" -C "$work/build/agent-classes" .
javac -encoding UTF-8 --release 17 -encoding UTF-8 -d "$work/build/game-classes" "$work/fixtures/net/minecraft/client/main/Main.java"
jar --create --file "$work/build/game-fixture.jar" -C "$work/build/game-classes" .
if [ "${1:-}" = test ]; then python3 "$work/test-runner.py"; fi
