#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/gravit-compat/build.sh
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then javac="$JAVA_HOME/bin/javac"; jar="$JAVA_HOME/bin/jar"; else javac=javac; jar=jar; fi
folder=examples/extensions/gravit-compat
rm -rf "$folder/build/classes"
mkdir -p "$folder/build/classes" "$folder/build/package/backend"
find "$folder/src" -name '*.java' | LC_ALL=C sort > "$folder/build/sources.txt"
"$javac" --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes:sdk/java/gravit-compat/build/classes -d "$folder/build/classes" @"$folder/build/sources.txt"
cat > "$folder/build/jar-manifest.txt" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.neverlauncher.sdk.host.JavaExtensionHost
NeverLauncher-Extension-Class: ru.neverlauncher.sdk.gravit.GravitCompatExtension
NeverLauncher-Gravit-Module-Class: ru.example.gravit.PortedModule
MANIFEST
"$jar" --create --file "$folder/build/package/backend/gravit-port.jar" --manifest "$folder/build/jar-manifest.txt" -C sdk/java/core/build/classes . -C sdk/java/gravit-compat/build/classes . -C "$folder/build/classes" .
cp "$folder/neverlauncher-extension.json" "$folder/build/package/neverlauncher-extension.json"
printf 'Built %s\n' "$folder/build/package/backend/gravit-port.jar"
