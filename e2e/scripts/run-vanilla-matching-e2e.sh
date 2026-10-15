#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
CLIENT_DIR="$RUNTIME_DIR/materialized-client"
SERVER_DIR="$RUNTIME_DIR/matching-server"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${NEVERLAUNCHER_COMPAT_TARGET_ID:-vanilla-matching-server}"
TARGET_OS="${NEVERLAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${NEVERLAUNCHER_COMPAT_ARCH:-x86_64}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
CLIENT_RUNTIME_SECONDS="${NEVERLAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-55}"
PLAYER_USERNAME="NL_Cert_Client"

[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[matching-e2e] invalid Minecraft version" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[matching-e2e] invalid Java major" >&2; exit 2; }
[[ "$TARGET_OS" == "linux" && "$TARGET_ARCH" == "x86_64" ]] || { echo "[matching-e2e] matching-server E2E is certified on linux/x86_64" >&2; exit 2; }
[[ -n "$JAVA_BIN" && -x "$JAVA_BIN" ]] || { echo "[matching-e2e] target Java executable is unavailable: $JAVA_BIN" >&2; exit 2; }
for cmd in go cargo python3 xvfb-run; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[matching-e2e] required command missing: $cmd" >&2; exit 1; }
done

rm -rf "$RUNTIME_DIR"
mkdir -p "$CLIENT_DIR" "$SERVER_DIR"
NL_BIN="$RUNTIME_DIR/nl"
NEVERRUNTIME_BIN="$ROOT/runtime/neverruntime/target/debug/neverruntime"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" >/dev/null 2>&1 || break
      sleep 0.25
    done
    kill -9 "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

printf '[matching-e2e] build CLI and NeverRuntime\n'
(
  cd "$ROOT/cli"
  go build -o "$NL_BIN" ./cmd/neverlauncher
)
cargo build --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime
[[ -x "$NEVERRUNTIME_BIN" ]] || { echo "[matching-e2e] NeverRuntime binary is missing" >&2; exit 1; }

printf '[matching-e2e] materialize actual Mojang client %s\n' "$MINECRAFT_VERSION"
"$NL_BIN" runtime vanilla-package \
  --minecraft "$MINECRAFT_VERSION" \
  --client-dir "$CLIENT_DIR" \
  --target "$TARGET_OS/$TARGET_ARCH" \
  --project compatibility-certification \
  --profile "vanilla-$MINECRAFT_VERSION-matching" \
  --channel stable \
  --version "$PRODUCT_VERSION-vanilla-$MINECRAFT_VERSION-matching" \
  --output "$RUNTIME_DIR/client-package.json"
"$NL_BIN" client verify \
  --package "$RUNTIME_DIR/client-package.json" \
  --client-dir "$CLIENT_DIR" \
  --output "$RUNTIME_DIR/materialized-client-verify.json"
cp "$CLIENT_DIR/.neverlauncher/vanilla-install.json" "$RUNTIME_DIR/vanilla-install.json"

printf '[matching-e2e] materialize verified Mojang server.jar for the exact same version %s\n' "$MINECRAFT_VERSION"
"$NL_BIN" runtime vanilla-server \
  --minecraft "$MINECRAFT_VERSION" \
  --server-dir "$SERVER_DIR" \
  --output "$RUNTIME_DIR/vanilla-server-install.json"

python3 - "$RUNTIME_DIR/vanilla-install.json" "$RUNTIME_DIR/vanilla-server-install.json" "$RUNTIME_DIR/materialized-client-verify.json" "$MINECRAFT_VERSION" "$JAVA_MAJOR" <<'PY'
import json, sys
client_p, server_p, verify_p, mc, java = sys.argv[1:]
java = int(java)
client = json.load(open(client_p, encoding='utf-8'))
server = json.load(open(server_p, encoding='utf-8'))
verify = json.load(open(verify_p, encoding='utf-8'))
if client.get('status') != 'installed-and-verified' or client.get('minecraftVersion') != mc or client.get('javaMajorVersion') != java:
    raise SystemExit('client install evidence does not match target')
if server.get('status') != 'installed-and-verified' or server.get('minecraftVersion') != mc or server.get('javaMajorVersion') != java:
    raise SystemExit('server install evidence does not match client version/Java')
if not isinstance(server.get('sha1'), str) or len(server['sha1']) != 40 or not isinstance(server.get('sha256'), str) or len(server['sha256']) != 64 or int(server.get('size') or 0) <= 0:
    raise SystemExit('server install integrity evidence is incomplete')
if verify.get('status') != 'valid' or (verify.get('verify') or {}).get('valid') is not True:
    raise SystemExit('client package verification failed')
PY

SERVER_PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
)"
cat > "$SERVER_DIR/eula.txt" <<'EULA'
eula=true
EULA
cat > "$SERVER_DIR/server.properties" <<EOFPROPS
server-ip=127.0.0.1
server-port=$SERVER_PORT
online-mode=false
enforce-secure-profile=false
white-list=false
spawn-protection=0
max-players=4
view-distance=2
simulation-distance=2
generate-structures=false
level-type=flat
enable-rcon=false
enable-query=false
motd=NeverLauncher Actual Client E2E II $MINECRAFT_VERSION
EOFPROPS
# Minecraft 1.17.1 has a documented dedicated-server generator-settings
# regression (MC-195468). Let the server create a real flat world first, then
# change its own level.dat in an offline, verified second stage.
# The first boot is never counted as matching-server/client certification.
if [[ "$MINECRAFT_VERSION" == "1.17.1" ]]; then
  # This codec (1.17.1) requires a complete flat generator-settings object.
  # The default {} produces "No key layers / No key structures" errors.
  # Preserve these settings for both the initial and restarted server;
  # mutate only the server-generated level.dat layers while it is stopped.
  cat >> "$SERVER_DIR/server.properties" <<'EOFVOID'
generator-settings={"biome":"minecraft:plains","layers":[{"block":"minecraft:bedrock","height":1},{"block":"minecraft:dirt","height":2},{"block":"minecraft:grass_block","height":1}],"structures":{"structures":{}},"features":false,"lakes":false}
gamemode=creative
allow-flight=true
EOFVOID
  mkfifo "$SERVER_DIR/server-console.fifo"
  # Keep a writer open so the server's FIFO stdin cannot close before stop.
  exec {SERVER_CONTROL_FD}<>"$SERVER_DIR/server-console.fifo"
  SERVER_STDIN="$SERVER_DIR/server-console.fifo"
else
  SERVER_STDIN=/dev/null
fi

printf '[matching-e2e] start Mojang server %s on 127.0.0.1:%s with Java %s\n' "$MINECRAFT_VERSION" "$SERVER_PORT" "$JAVA_MAJOR"
(
  cd "$SERVER_DIR"
  exec "$JAVA_BIN" -Xms256M -Xmx768M -jar server.jar nogui
) < "$SERVER_STDIN" > "$RUNTIME_DIR/matching-server.log" 2>&1 &
SERVER_PID=$!

python3 - "$SERVER_PID" "$SERVER_PORT" "$RUNTIME_DIR/matching-server.log" <<'PY'
import os, socket, sys, time
pid, port, log = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
deadline=time.time()+150
last=''
while time.time()<deadline:
    try:
        os.kill(pid,0)
    except OSError:
        try: last=open(log,encoding='utf-8',errors='replace').read()[-8000:]
        except OSError: pass
        raise SystemExit('matching server exited before accepting connections\n'+last)
    s=socket.socket(); s.settimeout(.5)
    try:
        if s.connect_ex(('127.0.0.1',port)) == 0:
            print('matching server TCP ready')
            raise SystemExit(0)
    finally:
        s.close()
    time.sleep(1)
try: last=open(log,encoding='utf-8',errors='replace').read()[-8000:]
except OSError: pass
raise SystemExit('matching server did not become ready\n'+last)
PY

# Rebuild the 1.17.1 world with an air-only generator using the *actual*
# server-produced level.dat NBT. Stop the first server gracefully, ensure the
# world metadata has been flushed, remove old bedrock chunks, then restart.
if [[ "$MINECRAFT_VERSION" == "1.17.1" ]]; then
  printf '[matching-e2e] stop initial 1.17.1 server for offline world preparation\n'
  printf 'stop\n' >&"$SERVER_CONTROL_FD"
  for _ in $(seq 1 120); do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then break; fi
    sleep 0.25
  done
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    echo '[matching-e2e] 1.17.1 server failed to stop cleanly' >&2
    exit 1
  fi
  wait "$SERVER_PID" || { echo '[matching-e2e] initial server exited with failure' >&2; exit 1; }
  # Keep first-boot diagnostics but never conflate them with the certification
  # server log. The second boot starts a clean log for the actual join proof.
  cp "$RUNTIME_DIR/matching-server.log" "$RUNTIME_DIR/matching-server.initial.log"
  python3 "$ROOT/e2e/scripts/prepare-vanilla-1171-void-world.py" "$SERVER_DIR/world/level.dat"
  # Existing chunks retain bedrock independently of the generator settings.
  rm -rf "$SERVER_DIR/world/region" "$SERVER_DIR/world/entities" "$SERVER_DIR/world/poi"
  printf '[matching-e2e] restart 1.17.1 server with verified void world\n'
  (
    cd "$SERVER_DIR"
    exec "$JAVA_BIN" -Xms256M -Xmx768M -jar server.jar nogui
  ) < "$SERVER_STDIN" > "$RUNTIME_DIR/matching-server.log" 2>&1 &
  SERVER_PID=$!
  python3 - "$SERVER_PID" "$SERVER_PORT" "$RUNTIME_DIR/matching-server.log" <<'PYREADY'
import os, socket, sys, time
pid, port, log = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
deadline = time.monotonic() + 150
while time.monotonic() < deadline:
    try: os.kill(pid, 0)
    except OSError: raise SystemExit('1.17.1 void-world server exited before ready')
    with socket.socket() as sock:
        sock.settimeout(1)
        if sock.connect_ex(('127.0.0.1', port)) == 0:
            print('[matching-e2e] 1.17.1 void-world TCP ready')
            break
    time.sleep(1)
else: raise SystemExit('1.17.1 void-world server did not become ready')
with open(log, encoding='utf-8', errors='replace') as inp:
    body = inp.read()
if 'Not a registry ops' in body or 'No key structures in MapLike' in body:
    raise SystemExit('1.17.1 world codec rejected generated settings')
PYREADY
fi

# Modern clients otherwise stop on first-run UI before automatic multiplayer connection.
cat > "$CLIENT_DIR/options.txt" <<'OPTIONS'
onboardAccessibility:false
skipMultiplayerWarning:true
joinedFirstServer:true
pauseOnLostFocus:false
OPTIONS
# The 1.17.1 matching-server target is rendered on llvmpipe in Xvfb.
# It can successfully authenticate/join and then crash on its first chunk
# tessellation. Exercise the real client in low-feature graphics mode; keep
# the server join proof, exact-version checks and fail-closed result intact.
if [[ "$MINECRAFT_VERSION" == "1.17.1" ]]; then
  cat >> "$CLIENT_DIR/options.txt" <<'OPTIONS'
graphicsMode:0
renderDistance:2
mipmapLevels:0
maxFps:30
entityShadows:false
biomeBlendRadius:0
OPTIONS
fi

printf '[matching-e2e] launch actual Mojang client %s and connect to exact matching server\n' "$MINECRAFT_VERSION"
# The hosted Linux runner has no ALSA playback device. OpenAL Soft repeatedly
# probes the missing hardware during the first resource reload, delaying block
# models while a 1.17.1 quick-connect client is already receiving chunks.
# Use OpenAL Soft's real null backend in this *headless CI only*: rendering,
# world loading, the actual server join and all fail-closed checks stay enabled.
export ALSOFT_DRIVERS=null
export LIBGL_ALWAYS_SOFTWARE=1
export NEVERLAUNCHER_RESOLUTION_WIDTH=854
export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
xvfb-run -a -s '-screen 0 1280x720x24 +extension GLX +render -noreset' \
  "$NEVERRUNTIME_BIN" certify-vanilla \
    --root "$CLIENT_DIR" \
    --version "$MINECRAFT_VERSION" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --server 127.0.0.1 \
    --server-port "$SERVER_PORT" \
    --max-runtime-seconds "$CLIENT_RUNTIME_SECONDS" \
    > "$RUNTIME_DIR/vanilla-certification.json"

python3 - "$RUNTIME_DIR/vanilla-certification.json" "$RUNTIME_DIR/matching-server.log" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$SERVER_PORT" "$PLAYER_USERNAME" "$SERVER_PID" "$RUNTIME_DIR/matching-server.json" <<'PY'
import json, os, re, sys
cert_p, log_p, mc, java, port, username, pid, out = sys.argv[1:]
java=int(java); port=int(port); pid=int(pid)
cert=json.load(open(cert_p,encoding='utf-8'))
log=open(log_p,encoding='utf-8',errors='replace').read()
joined = bool(re.search(r'(?im)\b'+re.escape(username)+r'\b.*(?:joined the game|logged in with entity id)', log))
try:
    os.kill(pid,0); alive=True
except OSError:
    alive=False
client_ok=(cert.get('status')=='passed' and cert.get('minecraftVersion')==mc and cert.get('requiredJavaMajor')==java and cert.get('detectedJavaMajor')==java and (cert.get('timedOut') is True or cert.get('success') is True) and cert.get('matchingServer')=='127.0.0.1' and cert.get('matchingServerPort')==port)
payload={
  'schemaVersion':'1.0','status':'passed' if client_ok and joined and alive else 'failed',
  'minecraftVersion':mc,'clientVersion':mc,'serverVersion':mc,'javaMajor':java,
  'serverHost':'127.0.0.1','serverPort':port,'serverProcessAlive':alive,
  'serverVersionMatched':True,'clientJoinedServer':joined,'actualClient':client_ok,
  'serverLog':'matching-server.log','serverArtifactEvidence':'vanilla-server-install.json'
}
open(out,'w',encoding='utf-8').write(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
if payload['status'] != 'passed':
    print(log[-12000:], file=sys.stderr)
    raise SystemExit('actual client did not complete matching-server E2E')
PY

python3 - "$RUNTIME_DIR/result.json" "$RUNTIME_DIR/matching-server.json" "$PRODUCT_VERSION" "$TARGET_ID" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$TARGET_OS" "$TARGET_ARCH" <<'PY'
import json, sys
out, match_p, version, target, mc, java, os_name, arch = sys.argv[1:]
match=json.load(open(match_p,encoding='utf-8')); java=int(java)
payload={
  'version':version,'status':'passed','targetId':target,
  'minecraft':{'version':mc,'loader':'vanilla','client':'actual-mojang-client','server':'actual-mojang-server','serverVersion':mc,'matchingServer':'passed'},
  'platform':{'os':os_name,'arch':arch},'java':{'requiredMajor':java,'detectedMajor':java},
  'checks':{'materialized':True,'packageVerified':True,'runtimeResolved':True,'javaMatched':True,'actualClient':True,'matchingServer':True,'serverVersionMatched':True,'serverHealthy':True,'clientJoinedServer':True},
  'evidence':['client-package.json','materialized-client-verify.json','vanilla-install.json','vanilla-server-install.json','vanilla-certification.json','matching-server.json','matching-server.log']
}
open(out,'w',encoding='utf-8').write(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
PY

printf '[matching-e2e] PASS client=%s server=%s Java=%s\n' "$MINECRAFT_VERSION" "$MINECRAFT_VERSION" "$JAVA_MAJOR"
