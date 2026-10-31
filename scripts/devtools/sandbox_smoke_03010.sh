#!/usr/bin/env bash
set -euo pipefail
CLI="${1:?pass built CLI}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/Fixture.java" <<'JAVA'
public class Fixture {
 public static void main(String[] args) {
  if (System.getenv("LAUNCHER_TOKEN") != null) System.exit(91);
  try {
   new java.net.Socket("8.8.8.8", 53);
   System.exit(92);
  } catch (java.net.SocketException expected) {
   System.out.println("sandbox-network-blocked");
  } catch (Exception expected) {
   System.out.println("sandbox-network-blocked");
  }
 }
}
JAVA
javac -g -d "$TMP" "$TMP/Fixture.java"
python3 - "$TMP" <<'PY'
import sys,zipfile,pathlib
p=pathlib.Path(sys.argv[1]);z=zipfile.ZipFile(p/'fixture.jar','w',zipfile.ZIP_DEFLATED)
z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\r\nMain-Class: Fixture\r\n\r\n')
z.write(p/'Fixture.class','Fixture.class');z.close()
PY
LAUNCHER_TOKEN="production-test-secret" "$CLI" devtools component test --jar "$TMP/fixture.jar" --isolation sandbox --timeout 15s | tee "$TMP/report.json"
python3 - "$TMP/report.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['exitCode']==0 and r['isolation']=='sandbox' and 'sandbox-network-blocked' in r['stdout'];assert 'production-test-secret' not in r['stdout']
PY
