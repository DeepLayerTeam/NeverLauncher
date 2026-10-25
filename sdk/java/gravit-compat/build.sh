#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
sh sdk/java/core/build.sh
: "${JAVA_HOME:=}"
if [ -n "$JAVA_HOME" ]; then javac="$JAVA_HOME/bin/javac"; java="$JAVA_HOME/bin/java"; jar="$JAVA_HOME/bin/jar"; else javac=javac; java=java; jar=jar; fi
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) cpsep=';' ;; *) cpsep=':' ;; esac
folder=sdk/java/gravit-compat
mkdir -p "$folder/build/classes" "$folder/build/test-classes"
find "$folder/src/main/java" -name '*.java' | LC_ALL=C sort > "$folder/build/sources.txt"
"$javac" --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes -d "$folder/build/classes" @"$folder/build/sources.txt"
version=$(cat VERSION)
"$jar" --create --file "$folder/build/neverlauncher-gravit-compat-$version.jar" -C "$folder/build/classes" .
cp "$folder/build/neverlauncher-gravit-compat-$version.jar" "$folder/build/neverlauncher-gravit-compat.jar"
if [ "${1:-}" = test ]; then
  find "$folder/src/test/java" -name '*.java' | LC_ALL=C sort > "$folder/build/tests.txt"
  "$javac" --release 17 -encoding UTF-8 -cp sdk/java/core/build/classes${cpsep}"$folder/build/classes" -d "$folder/build/test-classes" @"$folder/build/tests.txt"
  "$java" -cp sdk/java/core/build/classes${cpsep}"$folder/build/classes"${cpsep}"$folder/build/test-classes" ru.neverlauncher.sdk.gravit.GravitCompatTests
fi
