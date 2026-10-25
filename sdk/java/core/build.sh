#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then JAVAC="$JAVA_HOME/bin/javac"; JAVA="$JAVA_HOME/bin/java"; JAR="$JAVA_HOME/bin/jar"; else JAVAC=javac; JAVA=java; JAR=jar; fi
[ "${1:-}" != clean ] || { rm -rf build; exit 0; }
mkdir -p build/classes build/test-classes
find src/main/java -name '*.java' | LC_ALL=C sort > build/sources.txt
"$JAVAC" --release 17 -encoding UTF-8 -d build/classes @build/sources.txt
"$JAR" --create --file build/neverlauncher-java-sdk-core-0.30.2.jar -C build/classes .
if [ "${1:-}" = test ]; then
  find src/test/java -name '*.java' | LC_ALL=C sort > build/tests.txt
  "$JAVAC" --release 17 -encoding UTF-8 -cp build/classes -d build/test-classes @build/tests.txt
  "$JAVA" -cp build/classes:build/test-classes ru.neverlauncher.sdk.core.CoreTests
fi
