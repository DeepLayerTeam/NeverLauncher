#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/core/build.sh
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then javac="$JAVA_HOME/bin/javac"; jar="$JAVA_HOME/bin/jar"; else javac=javac; jar=jar; fi
work=examples/extensions/java-dependencies
mkdir -p "$work/build/lib" "$work/build/extension" "$work/build/package/backend"
"$javac" --release 17 -encoding UTF-8 -d "$work/build/lib" "$work/src/example/deps/Greeter.java"
"$jar" --create --file "$work/build/greeter.jar" -C "$work/build/lib" .
"$javac" --release 17 -encoding UTF-8 -cp "sdk/java/core/build/classes:$work/build/greeter.jar" -d "$work/build/extension" "$work/src/example/extension/DependencyExtension.java"
cat > "$work/build/manifest.txt" <<'MANIFEST'
Manifest-Version: 1.0
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: example.extension.DependencyExtension
MANIFEST
"$jar" --create --file "$work/build/host-unbundled.jar" --manifest "$work/build/manifest.txt" -C sdk/java/core/build/classes . -C "$work/build/extension" .
python3 scripts/java/package_dependencies_0482.py --host "$work/build/host-unbundled.jar" \
  --output "$work/build/package/backend/java-dependencies.jar" \
  --library "org.example:greeter@1.2.3@>=1.0 <2.0@$work/build/greeter.jar"
cp "$work/launcher-extension.json" "$work/build/package/launcher-extension.json"
echo "Собрано исполняемое расширение зависимостей: $work/build/package/backend/java-dependencies.jar"
