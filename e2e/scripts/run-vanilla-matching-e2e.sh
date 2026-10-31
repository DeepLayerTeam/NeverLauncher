#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
CLIENT_DIR="$RUNTIME_DIR/materialized-client"
SERVER_DIR="$RUNTIME_DIR/matching-server"
MINECRAFT_VERSION="${LAUNCHER_E2E_MINECRAFT_VERSION:-}"
JAVA_BIN="${LAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${LAUNCHER_E2E_JAVA_MAJOR:-}"
TARGET_ID="${LAUNCHER_COMPAT_TARGET_ID:-vanilla-matching-server}"
TARGET_OS="${LAUNCHER_COMPAT_OS:-linux}"
TARGET_ARCH="${LAUNCHER_COMPAT_ARCH:-x86_64}"
PRODUCT_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
CLIENT_RUNTIME_SECONDS="${LAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-55}"
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
RUNTIME_BIN="$ROOT/runtime/runtime/target/debug/runtime"
SERVER_PID=""
PROXY_PID=""
cleanup() {
  if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" >/dev/null 2>&1; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
  fi
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

printf '[matching-e2e] build CLI and Runtime\n'
(
  cd "$ROOT/cli"
  go build -o "$NL_BIN" ./cmd/launcher
)
cargo build --quiet --manifest-path "$ROOT/runtime/runtime/Cargo.toml" --bin runtime
[[ -x "$RUNTIME_BIN" ]] || { echo "[matching-e2e] Runtime binary is missing" >&2; exit 1; }

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
cp "$CLIENT_DIR/.launcher/vanilla-install.json" "$RUNTIME_DIR/vanilla-install.json"

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
motd=Launcher Actual Client E2E II $MINECRAFT_VERSION
EOFPROPS
# В выделенном сервере Minecraft 1.17.1 известна ошибка generator-settings
# (MC-195468). Сначала дайте серверу создать настоящий плоский мир, затем
# измените созданный level.dat на отдельном проверенном офлайн-этапе. Первый
# запуск не засчитывается в сертификацию соответствия сервера и клиента.
if [[ "$MINECRAFT_VERSION" == "1.17.1" ]]; then
  # Этот кодек 1.17.1 требует полный объект настройки плоского генератора.
  # Значение {} по умолчанию приводит к ошибкам "No key layers / No key
  # structures". Сохраняйте параметры при первоначальном и повторном
  # запуске; меняйте только слои в серверном level.dat после остановки.
  cat >> "$SERVER_DIR/server.properties" <<'EOFVOID'
generator-settings={"biome":"minecraft:plains","layers":[{"block":"minecraft:bedrock","height":1},{"block":"minecraft:dirt","height":2},{"block":"minecraft:grass_block","height":1}],"structures":{"structures":{}},"features":false,"lakes":false}
gamemode=creative
allow-flight=true
EOFVOID
  mkfifo "$SERVER_DIR/server-console.fifo"
  # Держите канал записи открытым, чтобы FIFO stdin сервера не закрылся до остановки.
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

# Пересоздайте мир 1.17.1 генератором только воздуха на основе настоящего NBT
# level.dat, созданного сервером. Корректно остановите первый сервер, убедитесь
# в сохранении метаданных мира, удалите старые чанки бедрока и перезапустите.
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
  # Сохраните диагностику первого запуска, но не смешивайте с журналом сертификационного
  # сервера. Второй запуск начинает чистый журнал для фактического доказательства соединения.
  cp "$RUNTIME_DIR/matching-server.log" "$RUNTIME_DIR/matching-server.initial.log"
  python3 "$ROOT/e2e/scripts/prepare-vanilla-1171-void-world.py" "$SERVER_DIR/world/level.dat"
  # Существующие чанки сохраняют бедрок независимо от настроек генератора.
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
# The 1.17.1 server prints "Not a registry ops" even while it continues
# loading the saved level.dat. This is not a fatal exit and the first-stage
# offline world NBT was already validated. Keep the diagnostic, then prove
# actual matching-server join and client runtime in the mandatory E2E below.
if 'Not a registry ops' in body or 'No key structures in MapLike' in body:
    print('[matching-e2e] 1.17.1 nonfatal world codec warning; verifying by real client join')
PYREADY
fi

# Иначе современные клиенты останавливаются на первоначальном интерфейсе до автоматического подключения к мультиплееру.
cat > "$CLIENT_DIR/options.txt" <<'OPTIONS'
onboardAccessibility:false
skipMultiplayerWarning:true
joinedFirstServer:true
pauseOnLostFocus:false
OPTIONS
# Цель matching-server 1.17.1 отображается через llvmpipe в Xvfb. Клиент способен
# успешно авторизоваться и войти, но упасть при тесселяции первого чанка.
# Запускайте настоящий клиент в упрощённом графическом режиме; сохраняйте
# доказательство входа, проверку точной версии и результат строгого отказа.
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

# Minecraft 1.17.1 can enter a chunk while its initial blocks texture atlas
# is still being created by Mesa/llvmpipe. Do not fake client readiness or
# delay a fixed number of seconds. Defer only the TCP handshake until the
# actual Mojang client emits its texture-atlas creation marker, then forward
# unmodified protocol bytes to the verified exact-version Mojang server.
CERT_PORT="$SERVER_PORT"
if [[ "$MINECRAFT_VERSION" == "1.17.1" ]]; then
  python3 "$ROOT/e2e/scripts/vanilla-1171-resource-ready-proxy.py" \
    --backend-port "$SERVER_PORT" \
    --logs "$CLIENT_DIR/logs" \
    --port-file "$RUNTIME_DIR/resource-ready-proxy.port" \
    --evidence "$RUNTIME_DIR/resource-ready-proxy.json" \
    --timeout 45 > "$RUNTIME_DIR/resource-ready-proxy.log" 2>&1 &
  PROXY_PID=$!
  for _ in $(seq 1 100); do
    [[ -s "$RUNTIME_DIR/resource-ready-proxy.port" ]] && break
    kill -0 "$PROXY_PID" >/dev/null 2>&1 || { echo '[matching-e2e] resource gate exited before binding localhost' >&2; exit 1; }
    sleep 0.1
  done
  [[ -s "$RUNTIME_DIR/resource-ready-proxy.port" ]] || { echo '[matching-e2e] resource gate did not bind' >&2; exit 1; }
  CERT_PORT="$(cat "$RUNTIME_DIR/resource-ready-proxy.port")"
  [[ "$CERT_PORT" =~ ^[0-9]{1,5}$ ]] || { echo '[matching-e2e] invalid gated client port' >&2; exit 1; }
fi

printf '[matching-e2e] launch actual Mojang client %s and connect to exact matching server\n' "$MINECRAFT_VERSION"
# На размещённом Linux-агенте нет устройства ALSA. OpenAL Soft постоянно ищет
# отсутствующее оборудование при первоначальной перезагрузке ресурсов, замедляя
# модели блоков, когда клиент 1.17.1 уже получает чанки. Используйте настоящий
# null-бэкенд OpenAL Soft только в CI без интерфейса; рендеринг, загрузка
# мира, реальный вход и строгие проверки остаются включёнными.
export ALSOFT_DRIVERS=null
export LIBGL_ALWAYS_SOFTWARE=1
export LAUNCHER_RESOLUTION_WIDTH=854
export LAUNCHER_RESOLUTION_HEIGHT=480
xvfb-run -a -s '-screen 0 1280x720x24 +extension GLX +render -noreset' \
  "$RUNTIME_BIN" certify-vanilla \
    --root "$CLIENT_DIR" \
    --version "$MINECRAFT_VERSION" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --server 127.0.0.1 \
    --server-port "$CERT_PORT" \
    --max-runtime-seconds "$CLIENT_RUNTIME_SECONDS" \
    > "$RUNTIME_DIR/vanilla-certification.json"

python3 - "$RUNTIME_DIR/vanilla-certification.json" "$RUNTIME_DIR/matching-server.log" "$MINECRAFT_VERSION" "$JAVA_MAJOR" "$SERVER_PORT" "$CERT_PORT" "$PLAYER_USERNAME" "$SERVER_PID" "$RUNTIME_DIR/matching-server.json" "$RUNTIME_DIR/resource-ready-proxy.json" <<'PY'
import json, os, re, sys
cert_p, log_p, mc, java, port, cert_port, username, pid, out, proxy_p = sys.argv[1:]
java=int(java); port=int(port); cert_port=int(cert_port); pid=int(pid)
cert=json.load(open(cert_p,encoding='utf-8'))
log=open(log_p,encoding='utf-8',errors='replace').read()
joined = bool(re.search(r'(?im)\b'+re.escape(username)+r'\b.*(?:joined the game|logged in with entity id)', log))
try:
    os.kill(pid,0); alive=True
except OSError:
    alive=False
proxy_ok = True
if mc == '1.17.1':
    try:
        proxy=json.load(open(proxy_p, encoding='utf-8'))
    except (OSError, ValueError):
        proxy={}
    proxy_ok = (proxy.get('status') == 'released'
                and proxy.get('atlasReady') is True
                and proxy.get('backendConnected') is True
                and proxy.get('backendHost') == '127.0.0.1'
                and proxy.get('backendPort') == port
                and proxy.get('listenHost') == '127.0.0.1'
                and proxy.get('listenPort') == cert_port)
client_ok=(cert.get('status')=='passed' and cert.get('minecraftVersion')==mc and cert.get('requiredJavaMajor')==java and cert.get('detectedJavaMajor')==java and (cert.get('timedOut') is True or cert.get('success') is True) and cert.get('matchingServer')=='127.0.0.1' and cert.get('matchingServerPort')==cert_port and proxy_ok)
payload={
  'schemaVersion':'1.0','status':'passed' if client_ok and joined and alive else 'failed',
  'minecraftVersion':mc,'clientVersion':mc,'serverVersion':mc,'javaMajor':java,
  'serverHost':'127.0.0.1','serverPort':port,'serverProcessAlive':alive,
  'serverVersionMatched':True,'clientJoinedServer':joined,'actualClient':client_ok,
  'resourceGateVerified':proxy_ok if mc == '1.17.1' else None,
  'clientConnectPort':cert_port,
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
  'evidence':['client-package.json','materialized-client-verify.json','vanilla-install.json','vanilla-server-install.json','vanilla-certification.json','matching-server.json','matching-server.log'] + (['resource-ready-proxy.json'] if mc == '1.17.1' else [])
}
open(out,'w',encoding='utf-8').write(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
PY

printf '[matching-e2e] PASS client=%s server=%s Java=%s\n' "$MINECRAFT_VERSION" "$MINECRAFT_VERSION" "$JAVA_MAJOR"
