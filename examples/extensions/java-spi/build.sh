#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/core/build.sh
if [ -n "${JAVA_HOME:-}" ]; then javac="$JAVA_HOME/bin/javac"; jar="$JAVA_HOME/bin/jar"; else javac=javac; jar=jar; fi
work=examples/extensions/java-spi
mkdir -p "$work/build/lib" "$work/build/extension" "$work/build/package/backend" "$work/build/package/cli"
"$javac" --release 17 -encoding UTF-8 -d "$work/build/lib" "$work/src/example/terms/Terms.java"
"$jar" --create --file "$work/build/terms.jar" -C "$work/build/lib" .
find "$work/src/example/spi" -name '*.java' | LC_ALL=C sort > "$work/build/sources.txt"
"$javac" --release 17 -encoding UTF-8 -cp "sdk/java/core/build/classes:$work/build/terms.jar" -d "$work/build/extension" @"$work/build/sources.txt"
cat > "$work/build/manifest.txt" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: example.spi.GreetingExtension
MANIFEST
"$jar" --create --file "$work/build/host.jar" --manifest "$work/build/manifest.txt" -C sdk/java/core/build/classes . -C "$work/build/extension" .
python3 scripts/java/package_dependencies.py --host "$work/build/host.jar" \
  --output "$work/build/package/backend/java-spi.jar" \
  --library "org.example:spi-terms@1.0.0@>=1.0.0 <2.0.0@$work/build/terms.jar"
cp "$work/build/package/backend/java-spi.jar" "$work/build/package/cli/java-spi.jar"
cp "$work/launcher-extension.json" "$work/build/package/launcher-extension.json"
printf '%s\n' "Собран исполняемый JAR SPI для Backend/CLI с изолированной вложенной зависимостью"
