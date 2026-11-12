#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then JAVAC="$JAVA_HOME/bin/javac"; JAVA="$JAVA_HOME/bin/java"; JAR="$JAVA_HOME/bin/jar"; else JAVAC=javac; JAVA=java; JAR=jar; fi
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) cpsep=';' ;; *) cpsep=':' ;; esac
[ "${1:-}" != clean ] || { rm -rf build; exit 0; }
sh "../core/build.sh"
mkdir -p build/classes build/tests
find src/main/java -name '*.java' | LC_ALL=C sort > build/sources.txt
"$JAVAC" --release 17 -encoding UTF-8 -cp ../core/build/classes -d build/classes @build/sources.txt
"$JAR" --create --file "build/launcher-api-sdk-$(cat ../../../VERSION).jar" -C build/classes .
if [ "${1:-}" = test ]; then
  find src/test/java -name '*.java' | LC_ALL=C sort > build/tests.txt
  "$JAVAC" --release 17 -encoding UTF-8 -cp "build/classes${cpsep}../core/build/classes" -d build/tests @build/tests.txt
  "$JAVA" -cp "build/classes${cpsep}build/tests${cpsep}../core/build/classes" ru.launcher.api.ClientTest
fi
