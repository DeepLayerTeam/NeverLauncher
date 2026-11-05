#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/core/build.sh
if [ -n "${JAVA_HOME:-}" ]; then javac="$JAVA_HOME/bin/javac"; jar="$JAVA_HOME/bin/jar"; else javac=javac; jar=jar; fi
work=examples/extensions/java-content-spi
mkdir -p "$work/build/classes" "$work/build/package/backend" "$work/build/package/cli"
"$javac" --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes -d "$work/build/classes" "$work/src/example/content/ContentExtension.java"
cat > "$work/build/manifest.txt" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: example.content.ContentExtension
MANIFEST
"$jar" --create --file "$work/build/package/backend/content-spi.jar" --manifest "$work/build/manifest.txt" -C sdk/java/core/build/classes . -C "$work/build/classes" .
cp "$work/build/package/backend/content-spi.jar" "$work/build/package/cli/content-spi.jar"
cp "$work/launcher-extension.json" "$work/build/package/launcher-extension.json"
printf '%s\n' 'Собран исполняемый JAR Java Content SPI для Backend/CLI (при выполнении требуется авторизованный Go Host)'
