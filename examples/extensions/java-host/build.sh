#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/core/build.sh
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then javac="$JAVA_HOME/bin/javac"; jar="$JAVA_HOME/bin/jar"; else javac=javac; jar=jar; fi
folder=examples/extensions/java-host
mkdir -p "$folder/build/classes" "$folder/build/package/backend"
"$javac" --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes -d "$folder/build/classes" "$folder/src/ru/example/launcher/HostExample.java"
cat > "$folder/build/jar-manifest.txt" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: ru.example.launcher.HostExample
MANIFEST
"$jar" --create --file "$folder/build/package/backend/java-host.jar" --manifest "$folder/build/jar-manifest.txt" -C sdk/java/core/build/classes . -C "$folder/build/classes" .
cp "$folder/launcher-extension.json" "$folder/build/package/launcher-extension.json"
echo "Built $folder/build/package/backend/java-host.jar"
