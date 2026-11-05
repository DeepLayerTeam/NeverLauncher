#!/bin/sh
set -eu
cd "$(dirname "$0")"
SDK=../../../sdk/java/core
sh "$SDK/build.sh" test
mkdir -p build/classes build/package/backend/bin build/package/backend/lib
javac --release 17 -encoding UTF-8 -cp "$SDK/build/classes" -d build/classes src/ru/example/launcher/LifecycleExample.java
jar --create --file build/package/backend/lib/java-lifecycle.jar -C build/classes .
cp "$SDK/build/launcher-java-sdk-core.jar" build/package/backend/lib/launcher-java-sdk-core.jar
cp launcher-extension.json build/package/backend/manifest.json
cp launcher-extension.json build/package/launcher-extension.json
cp backend/bin/java-lifecycle build/package/backend/bin/java-lifecycle
chmod 0755 build/package/backend/bin/java-lifecycle
printf '%s\n' 'Расширение, готовое к подписанию, собрано в examples/extensions/java-lifecycle/build/package/'
printf '%s\n' 'Упакуйте расширение существующими средствами nl extension package/registry (подпись обязательна).'
