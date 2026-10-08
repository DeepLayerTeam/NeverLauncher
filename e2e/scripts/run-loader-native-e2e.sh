#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT/e2e/runtime"
COMPOSE_FILE="$ROOT/e2e/docker-compose.minecraft-e2e.yml"
ENV_FILE="$RUNTIME_DIR/e2e.env"
SERVER_DIR="$RUNTIME_DIR/loader-native-server"
LOADER="$(printf '%s' "${NEVERLAUNCHER_E2E_LOADER:-}" | tr '[:upper:]' '[:lower:]')"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}"
LOADER_VERSION="${NEVERLAUNCHER_E2E_RESOLVED_LOADER_VERSION:-}"
CLIENT_PROFILE_ID="${NEVERLAUNCHER_E2E_LOADER_CLIENT_PROFILE_ID:-}"
JAVA_BIN="${NEVERLAUNCHER_E2E_JAVA:-}"
JAVA_MAJOR="${NEVERLAUNCHER_E2E_JAVA_MAJOR:-}"
SERVER_PORT="25580"
MAX_RUNTIME_SECONDS="${NEVERLAUNCHER_E2E_LOADER_NATIVE_CLIENT_SECONDS:-45}"
PLAYER_USERNAME="NeverLauncherCertification"

case "$LOADER" in fabric|quilt|forge|neoforge) ;; *) echo "[loader-native] unsupported loader: $LOADER" >&2; exit 2 ;; esac
[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[loader-native] invalid Minecraft version" >&2; exit 2; }
[[ "$LOADER_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,95}$ ]] || { echo "[loader-native] immutable loader version is required" >&2; exit 2; }
case "$(printf '%s' "$LOADER_VERSION" | tr '[:upper:]' '[:lower:]')" in latest|latest-stable|stable|recommended) echo "[loader-native] mutable loader selector is forbidden" >&2; exit 2 ;; esac
[[ "$CLIENT_PROFILE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$ ]] || { echo "[loader-native] invalid client profile id" >&2; exit 2; }
[[ "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || { echo "[loader-native] Java major is required" >&2; exit 2; }
[[ -x "$JAVA_BIN" ]] || { echo "[loader-native] target Java executable is unavailable: $JAVA_BIN" >&2; exit 2; }
[[ "$SERVER_PORT" =~ ^[0-9]+$ ]] && (( SERVER_PORT > 0 && SERVER_PORT < 65536 )) || { echo "[loader-native] invalid server port" >&2; exit 2; }
[[ "$MAX_RUNTIME_SECONDS" =~ ^[0-9]+$ ]] && (( MAX_RUNTIME_SECONDS >= 15 )) || { echo "[loader-native] invalid client runtime" >&2; exit 2; }
for cmd in docker python3 cargo xvfb-run sha256sum jq; do command -v "$cmd" >/dev/null 2>&1 || { echo "[loader-native] required command missing: $cmd" >&2; exit 1; }; done
docker compose version >/dev/null

case "$LOADER" in
  fabric) SERVER_TYPE=FABRIC; ARTIFACT_REL="libraries/net/fabricmc/fabric-loader" ;;
  quilt) SERVER_TYPE=QUILT; ARTIFACT_REL="libraries/org/quiltmc/quilt-loader" ;;
  forge) SERVER_TYPE=FORGE; ARTIFACT_REL="libraries/net/minecraftforge/forge" ;;
  neoforge) SERVER_TYPE=NEOFORGE; ARTIFACT_REL="libraries/net/neoforged/neoforge" ;;
esac

export NEVERLAUNCHER_E2E_NATIVE_SERVER_TYPE="$SERVER_TYPE"
export NEVERLAUNCHER_E2E_NATIVE_MINECRAFT_VERSION="$MINECRAFT_VERSION"
export NEVERLAUNCHER_E2E_NATIVE_LOADER_VERSION="$LOADER_VERSION"

compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup() {
  compose stop loader-native >/dev/null 2>&1 || true
  compose rm -sf loader-native >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$SERVER_DIR"
mkdir -p "$SERVER_DIR"
compose rm -sf loader-native >/dev/null 2>&1 || true
printf '[loader-native] start %s %s / loader %s dedicated server\n' "$LOADER" "$MINECRAFT_VERSION" "$LOADER_VERSION"
compose up -d loader-native >/dev/null
CONTAINER_ID="$(compose ps -q loader-native)"
[[ -n "$CONTAINER_ID" ]] || { echo "[loader-native] container was not created" >&2; exit 1; }

HEALTH=""
for _ in $(seq 1 120); do
  HEALTH="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER_ID" 2>/dev/null || true)"
  [[ "$HEALTH" == healthy ]] && break
  state="$(docker inspect --format '{{.State.Status}}' "$CONTAINER_ID" 2>/dev/null || true)"
  if [[ "$state" == exited || "$state" == dead ]]; then break; fi
  sleep 3
done
compose logs --no-color loader-native > "$RUNTIME_DIR/loader-native-server.log" 2>&1 || true
if [[ "$HEALTH" != healthy ]]; then
  echo "[loader-native] dedicated server did not become healthy" >&2
  cat "$RUNTIME_DIR/loader-native-server.log" >&2
  exit 1
fi

docker inspect --format '{{json .State.Health}}' "$CONTAINER_ID" > "$RUNTIME_DIR/health-loader-native.json"
jq -e '.Status == "healthy" and .FailingStreak == 0' "$RUNTIME_DIR/health-loader-native.json" >/dev/null

ARTIFACT_ROOT="$SERVER_DIR/$ARTIFACT_REL"
[[ -d "$ARTIFACT_ROOT" ]] || { echo "[loader-native] loader runtime artifacts missing: $ARTIFACT_ROOT" >&2; find "$SERVER_DIR" -maxdepth 5 -type f | head -200 >&2 || true; exit 1; }
find "$ARTIFACT_ROOT" -type f -print | sort > "$RUNTIME_DIR/loader-native-server-artifacts.txt"
python3 - "$RUNTIME_DIR/loader-native-server-artifacts.txt" "$LOADER_VERSION" <<'PY'
import sys
paths=open(sys.argv[1],encoding='utf-8',errors='replace').read().splitlines()
version=sys.argv[2]
if not paths:
    raise SystemExit('loader server artifact list is empty')
needle='/' + version + '/'
if not any(needle in p.replace('\\','/') or version in p.rsplit('/',1)[-1] for p in paths):
    raise SystemExit(f'exact loader version {version!r} is not present in server runtime artifact paths')
PY

printf '[loader-native] launch actual %s client profile %s -> 127.0.0.1:%s\n' "$LOADER" "$CLIENT_PROFILE_ID" "$SERVER_PORT"
export NEVERLAUNCHER_RESOLUTION_WIDTH=854
export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
export LIBGL_ALWAYS_SOFTWARE=1
xvfb-run -a -s '-screen 0 1280x720x24' \
  cargo run --quiet --manifest-path "$ROOT/runtime/neverruntime/Cargo.toml" --bin neverruntime -- certify-vanilla \
    --root "$RUNTIME_DIR/materialized-client" \
    --version "$CLIENT_PROFILE_ID" \
    --java "$JAVA_BIN" \
    --required-java-major "$JAVA_MAJOR" \
    --max-runtime-seconds "$MAX_RUNTIME_SECONDS" \
    --server 127.0.0.1 \
    --server-port "$SERVER_PORT" \
    > "$RUNTIME_DIR/loader-native-client.json"

JOINED=false
for _ in $(seq 1 30); do
  compose logs --no-color loader-native > "$RUNTIME_DIR/loader-native-server.log" 2>&1 || true
  if grep -Fq "$PLAYER_USERNAME joined the game" "$RUNTIME_DIR/loader-native-server.log"; then JOINED=true; break; fi
  sleep 1
done
[[ "$JOINED" == true ]] || { echo "[loader-native] actual client did not join loader server" >&2; tail -200 "$RUNTIME_DIR/loader-native-server.log" >&2; exit 1; }

IMAGE_REF="$(docker inspect --format '{{.Config.Image}}' "$CONTAINER_ID")"
IMAGE_ID="$(docker inspect --format '{{.Image}}' "$CONTAINER_ID")"
PROCESS_ARGS="$(docker top "$CONTAINER_ID" -eo args 2>/dev/null | tail -n +2 || true)"
printf '%s\n' "$PROCESS_ARGS" > "$RUNTIME_DIR/loader-native-server-process.txt"

python3 - "$RUNTIME_DIR/loader-native-client.json" "$RUNTIME_DIR/loader-native-server.log" "$RUNTIME_DIR/loader-native-server-artifacts.txt" "$RUNTIME_DIR/health-loader-native.json" "$RUNTIME_DIR/loader-native-server.json" "$LOADER" "$MINECRAFT_VERSION" "$LOADER_VERSION" "$CLIENT_PROFILE_ID" "$JAVA_MAJOR" "$SERVER_PORT" "$IMAGE_REF" "$IMAGE_ID" <<'PY'
import hashlib,json,re,sys
client_p,log_p,art_p,health_p,out_p,loader,mc,loader_ver,profile,java,port,image_ref,image_id=sys.argv[1:]
java=int(java); port=int(port)
client=json.load(open(client_p,encoding='utf-8'))
health=json.load(open(health_p,encoding='utf-8'))
log_raw=open(log_p,'rb').read(); art_raw=open(art_p,'rb').read()
log=log_raw.decode('utf-8','replace')
paths=[x for x in art_raw.decode('utf-8','replace').splitlines() if x]
if client.get('status')!='passed' or client.get('minecraftVersion')!=profile:
    raise SystemExit('loader-native client certification failed')
if client.get('requiredJavaMajor')!=java or client.get('detectedJavaMajor')!=java:
    raise SystemExit('loader-native client Java mismatch')
if client.get('matchingServer')!='127.0.0.1' or client.get('matchingServerPort')!=port:
    raise SystemExit('loader-native client did not target dedicated loader server')
if not (client.get('timedOut') is True or client.get('success') is True):
    raise SystemExit('loader-native client did not stay alive or exit successfully')
if int(client.get('classpathEntries') or 0)<=0:
    raise SystemExit('loader-native client classpath is empty')
if health.get('Status')!='healthy' or int(health.get('FailingStreak') or 0)!=0:
    raise SystemExit('loader-native server is not healthy')
if 'NeverLauncherCertification joined the game' not in log:
    raise SystemExit('loader-native server log does not prove actual client join')
needle='/' + loader_ver + '/'
if not any(needle in p.replace('\\','/') or loader_ver in p.rsplit('/',1)[-1] for p in paths):
    raise SystemExit('loader-native server exact loader artifact missing')
family_markers={'fabric':['fabric'],'quilt':['quilt'],'forge':['forge'],'neoforge':['neoforge','neo forge']}
low=log.lower()
if not any(marker in low for marker in family_markers[loader]):
    raise SystemExit(f'loader-native server log has no {loader} runtime marker')
payload={
 'schemaVersion':'1.0','status':'passed','loader':loader,'minecraftVersion':mc,'resolvedLoaderVersion':loader_ver,
 'clientProfileId':profile,'clientMainClass':client.get('mainClass'),'clientJoined':True,'serverHealthy':True,
 'serverPort':port,'serverImage':image_ref,'serverImageId':image_id,
 'loaderArtifactCount':len(paths),'loaderArtifactsSha256':hashlib.sha256(art_raw).hexdigest(),
 'serverLogSha256':hashlib.sha256(log_raw).hexdigest(),'clientEvidenceSha256':hashlib.sha256(open(client_p,'rb').read()).hexdigest(),
 'nativeHandshake':'actual-client-joined-dedicated-loader-server'
}
open(out_p,'w',encoding='utf-8').write(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
PY

printf '[loader-native] PASS %s client ↔ %s server / Minecraft %s / loader %s\n' "$LOADER" "$LOADER" "$MINECRAFT_VERSION" "$LOADER_VERSION"
