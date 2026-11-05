#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/core/build.sh
folder=examples/extensions/java-ui
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then javac="$JAVA_HOME/bin/javac"; jar="$JAVA_HOME/bin/jar"; else javac=javac; jar=jar; fi
mkdir -p "$folder/build/classes" "$folder/build/package/backend" "$folder/build/package/cli" "$folder/build/package/admin" "$folder/build/package/desktop"
"$javac" --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes -d "$folder/build/classes" "$folder/src/example/ui/WorkspaceExtension.java"
cat > "$folder/build/manifest.txt" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: example.ui.WorkspaceExtension
MANIFEST
"$jar" --create --file "$folder/build/package/backend/workspace.jar" --manifest "$folder/build/manifest.txt" -C sdk/java/core/build/classes . -C "$folder/build/classes" .
cp "$folder/build/package/backend/workspace.jar" "$folder/build/package/cli/workspace.jar"
cp "$folder/admin/index.html" "$folder/build/package/admin/index.html"
cp "$folder/desktop/index.html" "$folder/build/package/desktop/index.html"
cp "$folder/launcher-extension.json" "$folder/build/package/launcher-extension.json"
echo "Реальное расширение Java для Admin/Desktop/CLI собрано в $folder/build/package"
