#!/bin/sh
set -eu
cd "$(dirname "$0")"
SDK=../../../sdk/java/core
sh "$SDK/build.sh" test
mkdir -p build/classes build/package/backend/bin build/package/backend/lib build/package/cli/bin
javac --release 17 -encoding UTF-8 -cp "$SDK/build/classes" -d build/classes src/ru/example/neverlauncher/RuntimeExample.java
jar --create --file build/package/backend/lib/java-runtime.jar -C build/classes .
cp "$SDK/build/neverlauncher-java-sdk-core-0.30.4.jar" build/package/backend/lib/neverlauncher-java-sdk-core.jar
cp neverlauncher-extension.json build/package/backend/manifest.json
cp neverlauncher-extension.json build/package/neverlauncher-extension.json
cp backend/bin/java-runtime build/package/backend/bin/java-runtime
cp cli/bin/java-runtime build/package/cli/bin/java-runtime
chmod 0755 build/package/backend/bin/java-runtime build/package/cli/bin/java-runtime
printf '%s\n' 'Prepared real Java backend + CLI targets in build/package (sign with nl extension pack).'
