#!/bin/sh
set -eu
cd "$(dirname "$0")"
sh "../core/build.sh"
mkdir -p build/classes build/tests
find src/main/java -name '*.java' | sort > build/sources.txt
javac --release 17 -encoding UTF-8 -cp ../core/build/classes -d build/classes @build/sources.txt
jar --create --file "build/neverlauncher-api-sdk-$(cat ../../../VERSION).jar" -C build/classes .
if [ "${1:-}" = test ]; then
 find src/test/java -name '*.java' | sort > build/tests.txt
 javac --release 17 -encoding UTF-8 -cp build/classes:../core/build/classes -d build/tests @build/tests.txt
 java -cp build/classes:build/tests:../core/build/classes ru.neverlauncher.api.ClientTest
fi
