#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then JAVAC="$JAVA_HOME/bin/javac"; JAR="$JAVA_HOME/bin/jar"; else JAVAC=javac; JAR=jar; fi
mkdir -p build/classes
find src/main/java -name '*.java' | sort > build/sources.txt
"$JAVAC" --release 8 -encoding UTF-8 -d build/classes @build/sources.txt
printf 'Manifest-Version: 1.0\nPremain-Class: ru.neverlauncher.trusted.Agent\nCan-Retransform-Classes: false\nCan-Redefine-Classes: false\n\n' > build/MANIFEST.MF
"$JAR" cfm build/agent.jar build/MANIFEST.MF -C build/classes .
