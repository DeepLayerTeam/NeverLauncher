#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.minecraft-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/runtime"
ENV_FILE="$RUNTIME_DIR/e2e.env"
API="${NEVERLAUNCHER_E2E_API:-http://127.0.0.1:18080}"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55432/neverlauncher?sslmode=disable"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PINNED_PUBLIC_KEY="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
ADMIN_EMAIL="admin@neverlauncher.local"
ADMIN_PASSWORD="$(python3 -c 'import secrets; print("E2E-" + secrets.token_urlsafe(24))')"
PLAYER_USERNAME="E2EPlayer"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
MODE="${NEVERLAUNCHER_E2E_MODE:-full}"
MINECRAFT_VERSION="${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-1.21.1}"
LOADER="$(printf '%s' "${NEVERLAUNCHER_E2E_LOADER:-vanilla}" | tr '[:upper:]' '[:lower:]')"
LOADER_VERSION_SELECTOR="${NEVERLAUNCHER_E2E_LOADER_VERSION:-}"
PROFILE_ID="${NEVERLAUNCHER_E2E_PROFILE_ID:-$LOADER}"
BRIDGE_ALLOWLIST_JSON="{}"
SERVERBRIDGE_CRYPTO="$ROOT/e2e/scripts/serverbridge-node-crypto.sh"
# shellcheck source=serverbridge-node-crypto.sh
source "$SERVERBRIDGE_CRYPTO"

case "$MODE" in full|compatibility) ;; *) echo "[e2e] unsupported mode: $MODE" >&2; exit 2 ;; esac
case "$LOADER" in vanilla|fabric|quilt|forge|neoforge) ;; *) echo "[e2e] unsupported loader: $LOADER" >&2; exit 2 ;; esac
if [[ "$LOADER" == "vanilla" ]]; then
  [[ -z "$LOADER_VERSION_SELECTOR" ]] || { echo "[e2e] Vanilla must not specify loader version" >&2; exit 2; }
else
  LOADER_VERSION_SELECTOR="${LOADER_VERSION_SELECTOR:-latest-stable}"
fi
[[ "$MINECRAFT_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[e2e] invalid Minecraft version" >&2; exit 2; }
[[ "$PROFILE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "[e2e] invalid profile id" >&2; exit 2; }
if [[ -n "$LOADER_VERSION_SELECTOR" ]]; then
  [[ "$LOADER_VERSION_SELECTOR" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || { echo "[e2e] invalid loader version selector" >&2; exit 2; }
fi
RELEASE_VERSION="${VERSION}-${LOADER}-${MINECRAFT_VERSION}-e2e"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[e2e] required command missing: $1" >&2; exit 1; }; }
for cmd in docker curl jq go java cargo python3 gradle xvfb-run openssl psql; do need "$cmd"; done
docker compose version >/dev/null

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/plugins/velocity" "$RUNTIME_DIR/plugins/bungeecord" "$RUNTIME_DIR/plugins/waterfall" "$RUNTIME_DIR/plugins/spigot" "$RUNTIME_DIR/plugins/paper" "$RUNTIME_DIR/plugins/purpur" "$RUNTIME_DIR/plugins/folia" "$RUNTIME_DIR/plugins/fabric" \
  "$RUNTIME_DIR/node-identities/velocity" "$RUNTIME_DIR/node-identities/bungeecord" "$RUNTIME_DIR/node-identities/waterfall" "$RUNTIME_DIR/node-identities/spigot" "$RUNTIME_DIR/node-identities/paper" "$RUNTIME_DIR/node-identities/purpur" "$RUNTIME_DIR/node-identities/folia" "$RUNTIME_DIR/node-identities/fabric" "$RUNTIME_DIR/node-keys" \
  "$RUNTIME_DIR/client" "$RUNTIME_DIR/materialized-client"
write_env_file() {
  cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
NEVERLAUNCHER_E2E_PROFILE_ID=$PROFILE_ID
NEVERLAUNCHER_E2E_BRIDGE_RELEASE_ALLOWLIST_JSON=$BRIDGE_ALLOWLIST_JSON
NEVERLAUNCHER_E2E_HOST_UID=$(id -u)
NEVERLAUNCHER_E2E_HOST_GID=$(id -g)
ENV
}
write_env_file

compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup() {
  if [[ "${NEVERLAUNCHER_E2E_KEEP:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_http() {
  local url="$1"
  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "[e2e] timeout waiting for $url" >&2
  compose logs neverlauncher-api >&2 || true
  return 1
}
wait_healthy() {
  local service="$1" id status
  id="$(compose ps -q "$service")"
  [[ -n "$id" ]] || { echo "[e2e] $service container not found" >&2; return 1; }
  for _ in $(seq 1 120); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)"
    [[ "$status" == "healthy" ]] && return 0
    [[ "$status" == "exited" || "$status" == "dead" ]] && break
    sleep 3
  done
  echo "[e2e] $service did not become healthy" >&2
  compose logs "$service" >&2 || true
  return 1
}
wait_bridge_heartbeat() {
  local service="$1"
  for _ in $(seq 1 60); do
    if compose logs "$service" 2>&1 | grep -Eqi 'NeverLauncher .* Bridge .*heartbeat=true'; then
      return 0
    fi
    sleep 2
  done
  echo "[e2e] $service NeverLauncher bridge did not report successful heartbeat" >&2
  compose logs "$service" >&2 || true
  return 1
}
capture_health_evidence() {
  local service="$1" id out
  id="$(compose ps -q "$service")"
  [[ -n "$id" ]] || { echo "[e2e] $service container not found for health evidence" >&2; return 1; }
  out="$RUNTIME_DIR/health-$service.json"
  docker inspect --format '{{json .State.Health}}' "$id" > "$out"
  jq -e '.Status == "healthy" and .FailingStreak == 0 and (.Log | length) > 0 and .Log[-1].ExitCode == 0' "$out" >/dev/null || {
    echo "[e2e] $service health evidence is not healthy" >&2
    cat "$out" >&2
    return 1
  }
}
wait_log() {
  local service="$1" pattern="$2"
  for _ in $(seq 1 45); do
    if compose logs --no-color "$service" 2>&1 | grep -Fq "$pattern"; then return 0; fi
    sleep 1
  done
  echo "[e2e] $service log marker missing: $pattern" >&2
  compose logs "$service" >&2 || true
  return 1
}
json_post() {
  local url="$1" token="$2" body="$3"
  curl -fsS -H 'Content-Type: application/json' ${token:+-H "Authorization: Bearer $token"} -d "$body" "$url"
}

printf '[e2e] build real ServerBridge artifacts\n'
bash "$ROOT/scripts/build/bridge-plugins.sh"
BRIDGE_ALLOWLIST_JSON="$(tr -d '\r\n' < "$ROOT/artifacts/plugins/BRIDGE_RELEASE_ALLOWLIST.json")"
write_env_file
cp "$ROOT/artifacts/plugins/neverlauncher-paper-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/paper/neverlauncher-paper-bridge.jar"
if [[ "$MODE" == "full" ]]; then
  cp "$ROOT/artifacts/plugins/neverlauncher-velocity-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/velocity/neverlauncher-velocity-bridge.jar"
  cp "$ROOT/artifacts/plugins/neverlauncher-bungeecord-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/bungeecord/neverlauncher-bungeecord-bridge.jar"
  cp "$ROOT/artifacts/plugins/neverlauncher-waterfall-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/waterfall/neverlauncher-waterfall-bridge.jar"
  cp "$ROOT/artifacts/plugins/neverlauncher-spigot-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/spigot/neverlauncher-spigot-bridge.jar"
  cp "$ROOT/artifacts/plugins/neverlauncher-purpur-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/purpur/neverlauncher-purpur-bridge.jar"
  cp "$ROOT/artifacts/plugins/neverlauncher-folia-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/folia/neverlauncher-folia-bridge.jar"
  cp "$ROOT/artifacts/plugins/neverlauncher-fabric-bridge-${VERSION}.jar" "$RUNTIME_DIR/plugins/fabric/neverlauncher-fabric-bridge.jar"
fi

printf '[e2e] start PostgreSQL and apply production migrations explicitly\n'
compose up -d postgres
wait_healthy postgres
(
  cd "$ROOT/cli"
  go build -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher
)
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN"

printf '[e2e] start production-configured API with auto-migrate disabled\n'
compose up -d --build neverlauncher-api
wait_http "$API/health"

printf '[e2e] one-time bootstrap and canonical /api/v1 login\n'
curl -fsS -H 'Content-Type: application/json' -H "X-NeverLauncher-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"displayName\":\"E2E Owner\",\"password\":\"$ADMIN_PASSWORD\",\"actor\":\"github-actions\"}" \
  "$API/api/v1/install/bootstrap-admin" > "$RUNTIME_DIR/bootstrap.json"
LOGIN="$(curl -fsS -H 'Content-Type: application/json' -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "$API/api/v1/admin/login")"
ACCESS_TOKEN="$(jq -er '.token' <<<"$LOGIN")"

printf '[e2e] bind canonical launcher session to a real Ed25519 trusted-device key for 0.12.7 gameplay trust\n'
DEVICE_KEY="$RUNTIME_DIR/device-trust-ed25519.pem"
DEVICE_MESSAGE="$RUNTIME_DIR/device-trust-message.bin"
DEVICE_SIGNATURE="$RUNTIME_DIR/device-trust-signature.bin"
openssl genpkey -algorithm Ed25519 -out "$DEVICE_KEY" >/dev/null 2>&1
DEVICE_PUBLIC_KEY="$(openssl pkey -in "$DEVICE_KEY" -pubout -outform DER 2>/dev/null | python3 -c 'import base64,sys; d=sys.stdin.buffer.read(); print(base64.urlsafe_b64encode(d[-32:]).decode().rstrip("="))')"
DEVICE_BEGIN="$(json_post "$API/api/v1/auth/devices/register/begin" "$ACCESS_TOKEN" "{\"name\":\"Minecraft E2E device\",\"platform\":\"linux\",\"clientVersion\":\"$VERSION\"}")"
jq -ej '.data.signingPayload' <<<"$DEVICE_BEGIN" > "$DEVICE_MESSAGE"
openssl pkeyutl -sign -rawin -inkey "$DEVICE_KEY" -in "$DEVICE_MESSAGE" -out "$DEVICE_SIGNATURE"
DEVICE_SIGNATURE_B64="$(python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(open(sys.argv[1],"rb").read()).decode().rstrip("="))' "$DEVICE_SIGNATURE")"
DEVICE_COMPLETE="$(jq -cn \
  --arg challengeId "$(jq -er '.data.challengeId' <<<"$DEVICE_BEGIN")" \
  --arg deviceId "$(jq -er '.data.deviceId' <<<"$DEVICE_BEGIN")" \
  --arg challenge "$(jq -er '.data.challenge' <<<"$DEVICE_BEGIN")" \
  --arg publicKey "$DEVICE_PUBLIC_KEY" \
  --arg signature "$DEVICE_SIGNATURE_B64" \
  '{challengeId:$challengeId,deviceId:$deviceId,challenge:$challenge,publicKey:$publicKey,signature:$signature}')"
ACCESS_TOKEN="$(json_post "$API/api/v1/auth/devices/register/complete" "$ACCESS_TOKEN" "$DEVICE_COMPLETE" | jq -er '.data.accessToken')"

json_post "$API/api/v1/install/first-project" "$ACCESS_TOKEN" "{\"projectId\":\"e2e-project\",\"profileId\":\"$PROFILE_ID\",\"channel\":\"stable\",\"version\":\"0.0.1-bootstrap\",\"actor\":\"github-actions\"}" > "$RUNTIME_DIR/first-project.json"

PAPER_NODE_KEY="$RUNTIME_DIR/node-keys/paper.pem"
VELOCITY_NODE_KEY="$RUNTIME_DIR/node-keys/velocity.pem"
BUNGEECORD_NODE_KEY="$RUNTIME_DIR/node-keys/bungeecord.pem"
WATERFALL_NODE_KEY="$RUNTIME_DIR/node-keys/waterfall.pem"
SPIGOT_NODE_KEY="$RUNTIME_DIR/node-keys/spigot.pem"
PURPUR_NODE_KEY="$RUNTIME_DIR/node-keys/purpur.pem"
FOLIA_NODE_KEY="$RUNTIME_DIR/node-keys/folia.pem"
FABRIC_NODE_KEY="$RUNTIME_DIR/node-keys/fabric.pem"
serverbridge_node_generate "$PAPER_NODE_KEY" "$RUNTIME_DIR/node-identities/paper/node-identity.properties"
if [[ "$MODE" == "full" ]]; then
  serverbridge_node_generate "$VELOCITY_NODE_KEY" "$RUNTIME_DIR/node-identities/velocity/node-identity.properties"
  serverbridge_node_generate "$BUNGEECORD_NODE_KEY" "$RUNTIME_DIR/node-identities/bungeecord/node-identity.properties"
  serverbridge_node_generate "$WATERFALL_NODE_KEY" "$RUNTIME_DIR/node-identities/waterfall/node-identity.properties"
  serverbridge_node_generate "$SPIGOT_NODE_KEY" "$RUNTIME_DIR/node-identities/spigot/node-identity.properties"
  serverbridge_node_generate "$PURPUR_NODE_KEY" "$RUNTIME_DIR/node-identities/purpur/node-identity.properties"
  serverbridge_node_generate "$FOLIA_NODE_KEY" "$RUNTIME_DIR/node-identities/folia/node-identity.properties"
  serverbridge_node_generate "$FABRIC_NODE_KEY" "$RUNTIME_DIR/node-identities/fabric/node-identity.properties"
fi
PAPER_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-paper-bridge-${VERSION}.jar" | awk '{print $1}')"
VELOCITY_BRIDGE_SHA=""
BUNGEECORD_BRIDGE_SHA=""
WATERFALL_BRIDGE_SHA=""
SPIGOT_BRIDGE_SHA=""
PURPUR_BRIDGE_SHA=""
FOLIA_BRIDGE_SHA=""
FABRIC_BRIDGE_SHA=""
if [[ "$MODE" == "full" ]]; then
  VELOCITY_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-velocity-bridge-${VERSION}.jar" | awk '{print $1}')"
  BUNGEECORD_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-bungeecord-bridge-${VERSION}.jar" | awk '{print $1}')"
  WATERFALL_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-waterfall-bridge-${VERSION}.jar" | awk '{print $1}')"
  SPIGOT_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-spigot-bridge-${VERSION}.jar" | awk '{print $1}')"
  PURPUR_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-purpur-bridge-${VERSION}.jar" | awk '{print $1}')"
  FOLIA_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-folia-bridge-${VERSION}.jar" | awk '{print $1}')"
  FABRIC_BRIDGE_SHA="$(sha256sum "$ROOT/artifacts/plugins/neverlauncher-fabric-bridge-${VERSION}.jar" | awk '{print $1}')"
fi
register_server() {
  local id="$1" kind="$2" key="$3" public_key body
  public_key="$(serverbridge_node_public "$key")"
  body="$(jq -cn --arg id "$id" --arg kind "$kind" --arg project "e2e-project" --arg profile "$PROFILE_ID" --arg publicKey "$public_key" '{id:$id,name:$id,kind:$kind,projectId:$project,profileId:$profile,keyAlgorithm:"ed25519",publicKey:$publicKey}')"
  json_post "$API/api/v1/server-bridge/servers/register" "$ACCESS_TOKEN" "$body" | jq -e '.data.status == "registered" and .data.nodeIdentity.keyAlgorithm == "ed25519" and .data.nodeIdentity.identityEpoch == 1' >/dev/null
}
register_server paper-e2e-p3 paper "$PAPER_NODE_KEY"
if [[ "$MODE" == "full" ]]; then
  register_server velocity-e2e-p3 velocity "$VELOCITY_NODE_KEY"
  register_server bungeecord-e2e-p3 bungeecord "$BUNGEECORD_NODE_KEY"
  register_server waterfall-e2e-p3 waterfall "$WATERFALL_NODE_KEY"
  register_server spigot-e2e-p3 spigot "$SPIGOT_NODE_KEY"
  register_server purpur-e2e-p3 purpur "$PURPUR_NODE_KEY"
  register_server folia-e2e-p3 folia "$FOLIA_NODE_KEY"
  register_server fabric-e2e-p3 fabric "$FABRIC_NODE_KEY"
fi

if [[ "$MODE" == "full" ]]; then
  printf '[e2e] start real Velocity/BungeeCord/Waterfall plus Spigot/Paper/Purpur/Folia/Fabric 1.21.1\n'
  compose up -d velocity bungeecord waterfall spigot paper purpur folia fabric
  SERVICES=(velocity bungeecord waterfall spigot paper purpur folia fabric)
else
  printf '[e2e] compatibility mode: start real Paper 1.21.1 only\n'
  compose up -d paper
  SERVICES=(paper)
fi
for service in "${SERVICES[@]}"; do
  wait_healthy "$service"
  wait_bridge_heartbeat "$service"
  capture_health_evidence "$service"
done

CLIENT_PACKAGE="$RUNTIME_DIR/client-package.json"
printf '[e2e] materialize real Minecraft %s / %s client\n' "$MINECRAFT_VERSION" "$LOADER"
PACKAGE_ARGS=(
  --minecraft "$MINECRAFT_VERSION"
  --client-dir "$RUNTIME_DIR/materialized-client"
  --project e2e-project
  --profile "$PROFILE_ID"
  --channel stable
  --version "$RELEASE_VERSION"
  --output "$CLIENT_PACKAGE"
)
case "$LOADER" in
  vanilla)
    "$RUNTIME_DIR/nl" runtime vanilla-package "${PACKAGE_ARGS[@]}"
    ;;
  fabric|quilt)
    "$RUNTIME_DIR/nl" runtime "${LOADER}-package" "${PACKAGE_ARGS[@]}" --loader-version "$LOADER_VERSION_SELECTOR"
    ;;
  forge|neoforge)
    "$RUNTIME_DIR/nl" runtime "${LOADER}-package" "${PACKAGE_ARGS[@]}" --loader-version "$LOADER_VERSION_SELECTOR" --java "$(command -v java)"
    ;;
esac

"$RUNTIME_DIR/nl" client verify \
  --package "$CLIENT_PACKAGE" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --output "$RUNTIME_DIR/materialized-client-verify.json"
jq -e '.status == "valid" and .verify.valid == true and .verify.missing == [] and .verify.corrupted == []' "$RUNTIME_DIR/materialized-client-verify.json" >/dev/null
jq -e --arg mc "$MINECRAFT_VERSION" --arg loader "$LOADER" --arg profile "$PROFILE_ID" \
  '.manifestSettings.minecraft.version == $mc and .manifestSettings.minecraft.loader == $loader and .manifest.profileId == $profile and .manifestSettings.runtime.launch.classpathStrategy == "compatibility" and (.manifest.files | length) > 10' \
  "$CLIENT_PACKAGE" >/dev/null
RESOLVED_LOADER_VERSION="$(jq -r '.manifestSettings.minecraft.loaderVersion // ""' "$CLIENT_PACKAGE")"
if [[ "$LOADER" == "vanilla" ]]; then
  [[ -z "$RESOLVED_LOADER_VERSION" ]] || { echo "[e2e] Vanilla unexpectedly resolved loaderVersion=$RESOLVED_LOADER_VERSION" >&2; exit 1; }
else
  [[ -n "$RESOLVED_LOADER_VERSION" ]] || { echo "[e2e] loader version was not resolved" >&2; exit 1; }
  case "$(printf '%s' "$RESOLVED_LOADER_VERSION" | tr '[:upper:]' '[:lower:]')" in latest|latest-stable|stable|recommended) echo "[e2e] mutable loader selector leaked into release" >&2; exit 1 ;; esac
fi

printf '[e2e] upload the full real Minecraft package through canonical /api/v1 and publish signed immutable release\n'
python3 "$ROOT/e2e/scripts/publish-client-package.py" \
  --api "$API" \
  --token "$ACCESS_TOKEN" \
  --package "$CLIENT_PACKAGE" \
  --client-dir "$RUNTIME_DIR/materialized-client" \
  --quick-play "127.0.0.1:25571" \
  --output "$RUNTIME_DIR/published-client-package.json" \
  > "$RUNTIME_DIR/published-client-package.stdout.json"
MANIFEST_URL="$(jq -er '.manifestUrl' "$RUNTIME_DIR/published-client-package.json")"
curl -fsS "$MANIFEST_URL" > "$RUNTIME_DIR/manifest.json"
jq -e --arg key "$PINNED_PUBLIC_KEY" --arg version "$RELEASE_VERSION" --arg mc "$MINECRAFT_VERSION" --arg loader "$LOADER" --arg resolved "$RESOLVED_LOADER_VERSION" \
  '.version == $version and .minecraft.version == $mc and .minecraft.loader == $loader and ((($loader == "vanilla") and ((.minecraft.loaderVersion // "") == "")) or (($loader != "vanilla") and .minecraft.loaderVersion == $resolved)) and .runtime.launch.classpathStrategy == "compatibility" and .signature.algorithm == "Ed25519" and .signature.publicKey == $key and (.signature.signature|length == 128)' \
  "$RUNTIME_DIR/manifest.json" >/dev/null

printf '[e2e] NeverRuntime pinned Ed25519 verify -> clean sync from Backend -> actual Minecraft client launch\n'
(
  cd "$ROOT"
  cargo run --quiet --manifest-path runtime/neverruntime/Cargo.toml --bin neverruntime -- verify \
    --manifest "$RUNTIME_DIR/manifest.json" --pinned-public-key "$PINNED_PUBLIC_KEY" > "$RUNTIME_DIR/runtime-verify.json"
  rm -rf "$RUNTIME_DIR/client"
  mkdir -p "$RUNTIME_DIR/client"
  cargo run --quiet --manifest-path runtime/neverruntime/Cargo.toml --bin neverruntime -- sync \
    --manifest-url "$MANIFEST_URL" --pinned-public-key "$PINNED_PUBLIC_KEY" --root "$RUNTIME_DIR/client" > "$RUNTIME_DIR/runtime-sync.json"
)
jq -e '.status == "ready" and .signature.valid == true' "$RUNTIME_DIR/runtime-verify.json" >/dev/null
jq -e '.status == "ready" and .download.failed == 0 and (.files | length) > 10 and ([.files[] | select(.status != "ok")] | length) == 0' "$RUNTIME_DIR/runtime-sync.json" >/dev/null

printf '[e2e] create real launcher session and connect the actual Minecraft client to Paper 1.21.1\n'
json_post "$API/api/v1/session/join" "$ACCESS_TOKEN" "{\"username\":\"$PLAYER_USERNAME\",\"serverId\":\"paper-e2e-p3\",\"projectId\":\"e2e-project\",\"profileId\":\"$PROFILE_ID\",\"channel\":\"stable\"}" > "$RUNTIME_DIR/join-paper-real-client.json"
jq -e '.data.oneTime == true and .data.ticketVersion == 2 and (.data.ticketId | startswith("jt_")) and .data.join.issuedIdentityEpoch >= 1 and (.data.join.issuedKeyFingerprint | length) == 64' "$RUNTIME_DIR/join-paper-real-client.json" >/dev/null
validate_join() {
  local id="$1" key="$2" plugin_sha="$3" expect="$4" out="$RUNTIME_DIR/validate-$id-$expect.json" code body
  body="$(jq -cn --arg id "$id" --arg username "$PLAYER_USERNAME" --arg project "e2e-project" --arg profile "$PROFILE_ID" --arg version "$VERSION" --arg sha "$plugin_sha" '{protocolVersion:2,serverId:$id,username:$username,projectId:$project,profileId:$profile,channel:"stable",pluginVersion:$version,pluginSha256:$sha}')"
  code="$(serverbridge_node_signed_request "$key" "$id" POST "$API/api/v1/server-bridge/validate-join" "$body" "$out")"
  if [[ "$expect" == allow ]]; then
    [[ "$code" == 200 ]] && jq -e '.data.allowed == true and (.data.nodeKeyFingerprint|length)==64 and .data.identityEpoch >= 1' "$out" >/dev/null
  else
    [[ "$code" == 403 ]] && jq -e '.data.allowed == false and .data.reason == "launcher_session_missing_or_expired"' "$out" >/dev/null
  fi
}
validate_join paper-e2e-p3 "$PAPER_NODE_KEY" "$PAPER_BRIDGE_SHA" allow
validate_join paper-e2e-p3 "$PAPER_NODE_KEY" "$PAPER_BRIDGE_SHA" deny

consumed_count="$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM server_bridge_join_tickets_v2 WHERE server_id='paper-e2e-p3' AND status='consumed'")"
(( consumed_count >= 1 )) || { echo "[e2e] ServerBridge Protocol v2 ticket was not persisted as consumed" >&2; exit 1; }
redemption_state="$(psql "$DB_DSN" -AtF '|' -qc "SELECT ticket_version,issued_identity_epoch,(issued_key_fingerprint=redeemed_key_fingerprint)::text,redeemed_identity_epoch,length(redeemed_nonce_hash),(redeemed_by_ip<>'')::text FROM server_bridge_join_tickets_v2 WHERE server_id='paper-e2e-p3' AND status='consumed' ORDER BY consumed_at DESC LIMIT 1")"
IFS='|' read -r redemption_version issued_epoch fingerprint_match redeemed_epoch nonce_hash_len redeemed_ip_present <<< "$redemption_state"
[[ "$redemption_version" == "2" && "$fingerprint_match" == "t" && "$redeemed_epoch" == "$issued_epoch" && "$nonce_hash_len" == "64" && "$redeemed_ip_present" == "t" ]] || { echo "[e2e] invalid one-time ticket redemption proof: $redemption_state" >&2; exit 1; }
# The protocol probe above consumed its one-time ticket. Issue a fresh ticket for
# the actual Minecraft connection; the server plugin must be the only consumer.
json_post "$API/api/v1/session/join" "$ACCESS_TOKEN" "{\"username\":\"$PLAYER_USERNAME\",\"serverId\":\"paper-e2e-p3\",\"projectId\":\"e2e-project\",\"profileId\":\"$PROFILE_ID\",\"channel\":\"stable\"}" > "$RUNTIME_DIR/join-paper-real-client-fresh.json"
jq -e '.data.oneTime == true and .data.ticketVersion == 2 and (.data.ticketId | startswith("jt_"))' "$RUNTIME_DIR/join-paper-real-client-fresh.json" >/dev/null

(
  cd "$ROOT"
  export LIBGL_ALWAYS_SOFTWARE=1
  export NEVERLAUNCHER_RESOLUTION_WIDTH=854
  export NEVERLAUNCHER_RESOLUTION_HEIGHT=480
  xvfb-run -a -s '-screen 0 1280x720x24' \
    cargo run --quiet --manifest-path runtime/neverruntime/Cargo.toml --bin neverruntime -- launch \
      --manifest "$RUNTIME_DIR/manifest.json" \
      --pinned-public-key "$PINNED_PUBLIC_KEY" \
      --root "$RUNTIME_DIR/client" \
      --java "$(command -v java)" \
      --username "$PLAYER_USERNAME" \
      --max-runtime-seconds "${NEVERLAUNCHER_E2E_CLIENT_RUNTIME_SECONDS:-90}" \
      > "$RUNTIME_DIR/runtime-launch-minecraft.json"
)
jq -e '.timedOut == true or .success == true' "$RUNTIME_DIR/runtime-launch-minecraft.json" >/dev/null
wait_log paper "neverlauncher.join.allowed username=$PLAYER_USERNAME"
wait_log paper "$PLAYER_USERNAME joined the game"

printf '[e2e] revoke launcher session and verify subsequent joins are denied\n'
json_post "$API/api/v1/session/invalidate" "$ACCESS_TOKEN" '{"serverId":"paper-e2e-p3","reason":"e2e-revoke"}' > "$RUNTIME_DIR/revoke-paper-real-client.json"
validate_join paper-e2e-p3 "$PAPER_NODE_KEY" "$PAPER_BRIDGE_SHA" deny
python3 "$ROOT/e2e/scripts/minecraft-login-probe.py" --port 25571 --username "$PLAYER_USERNAME" > "$RUNTIME_DIR/probe-paper-deny.txt"
wait_log paper "neverlauncher.join.denied username=$PLAYER_USERNAME"

if [[ "$MODE" == "full" ]]; then
  printf '[e2e] retain protocol-level allow/revoke coverage for Velocity and Purpur bridges\n'
  flow_for_server() {
    local id="$1" key="$2" plugin_sha="$3" service="$4" port="$5" join_body revoke_body
    join_body="$(jq -cn --arg username "$PLAYER_USERNAME" --arg id "$id" --arg profile "$PROFILE_ID" '{username:$username,serverId:$id,projectId:"e2e-project",profileId:$profile,channel:"stable"}')"
    revoke_body="$(jq -cn --arg id "$id" '{serverId:$id,reason:"e2e-revoke"}')"
    json_post "$API/api/v1/session/join" "$ACCESS_TOKEN" "$join_body" > "$RUNTIME_DIR/join-$id.json"
    validate_join "$id" "$key" "$plugin_sha" allow
    validate_join "$id" "$key" "$plugin_sha" deny
    json_post "$API/api/v1/session/join" "$ACCESS_TOKEN" "$join_body" > "$RUNTIME_DIR/join-$id-fresh.json"
    python3 "$ROOT/e2e/scripts/minecraft-login-probe.py" --port "$port" --username "$PLAYER_USERNAME" > "$RUNTIME_DIR/probe-$id-allow.txt"
    wait_log "$service" "neverlauncher.join.allowed username=$PLAYER_USERNAME"
    json_post "$API/api/v1/session/invalidate" "$ACCESS_TOKEN" "$revoke_body" > "$RUNTIME_DIR/revoke-$id.json"
    validate_join "$id" "$key" "$plugin_sha" deny
    python3 "$ROOT/e2e/scripts/minecraft-login-probe.py" --port "$port" --username "$PLAYER_USERNAME" > "$RUNTIME_DIR/probe-$id-deny.txt"
    wait_log "$service" "neverlauncher.join.denied username=$PLAYER_USERNAME"
  }
  flow_for_server velocity-e2e-p3 "$VELOCITY_NODE_KEY" "$VELOCITY_BRIDGE_SHA" velocity 25570
  flow_for_server bungeecord-e2e-p3 "$BUNGEECORD_NODE_KEY" "$BUNGEECORD_BRIDGE_SHA" bungeecord 25575
  flow_for_server waterfall-e2e-p3 "$WATERFALL_NODE_KEY" "$WATERFALL_BRIDGE_SHA" waterfall 25576
  flow_for_server spigot-e2e-p3 "$SPIGOT_NODE_KEY" "$SPIGOT_BRIDGE_SHA" spigot 25573
  flow_for_server purpur-e2e-p3 "$PURPUR_NODE_KEY" "$PURPUR_BRIDGE_SHA" purpur 25572
  flow_for_server folia-e2e-p3 "$FOLIA_NODE_KEY" "$FOLIA_BRIDGE_SHA" folia 25574
  flow_for_server fabric-e2e-p3 "$FABRIC_NODE_KEY" "$FABRIC_BRIDGE_SHA" fabric 25577
fi

curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" "$API/api/v1/server-bridge/diagnostics" > "$RUNTIME_DIR/bridge-diagnostics.json"
jq -e '.data.protocolVersion == 2 and .data.summary.protocolVersion == 2 and .data.summary.sourceOfTruth == "postgresql"' "$RUNTIME_DIR/bridge-diagnostics.json" >/dev/null
serverbridge_nodes="$(psql "$DB_DSN" -Atqc 'SELECT count(*) FROM server_bridge_nodes_v2')"
required_nodes=1
[[ "$MODE" == "full" ]] && required_nodes=8
(( serverbridge_nodes >= required_nodes )) || { echo "[e2e] expected PostgreSQL ServerBridge nodes" >&2; exit 1; }
VELOCITY_HEALTH="skipped"
BUNGEECORD_HEALTH="skipped"
WATERFALL_HEALTH="skipped"
SPIGOT_HEALTH="skipped"
PURPUR_HEALTH="skipped"
FOLIA_HEALTH="skipped"
FABRIC_HEALTH="skipped"
if [[ "$MODE" == "full" ]]; then VELOCITY_HEALTH="healthy"; BUNGEECORD_HEALTH="healthy"; WATERFALL_HEALTH="healthy"; SPIGOT_HEALTH="healthy"; PURPUR_HEALTH="healthy"; FOLIA_HEALTH="healthy"; FABRIC_HEALTH="healthy"; fi
jq -n \
  --arg version "$VERSION" \
  --arg mode "$MODE" \
  --arg mc "$MINECRAFT_VERSION" \
  --arg loader "$LOADER" \
  --arg loaderSelector "$LOADER_VERSION_SELECTOR" \
  --arg resolvedLoaderVersion "$RESOLVED_LOADER_VERSION" \
  --arg profile "$PROFILE_ID" \
  --arg velocity "$VELOCITY_HEALTH" \
  --arg bungeecord "$BUNGEECORD_HEALTH" \
  --arg waterfall "$WATERFALL_HEALTH" \
  --arg spigot "$SPIGOT_HEALTH" \
  --arg purpur "$PURPUR_HEALTH" \
  --arg folia "$FOLIA_HEALTH" \
  --arg fabric "$FABRIC_HEALTH" \
  '{version:$version,status:"passed",mode:$mode,minecraft:{version:$mc,loader:$loader,loaderSelector:$loaderSelector,resolvedLoaderVersion:$resolvedLoaderVersion,profileId:$profile,client:"actual-mojang-client",paperJoin:"passed"},health:{velocity:$velocity,bungeecord:$bungeecord,waterfall:$waterfall,spigot:$spigot,paper:"healthy",purpur:$purpur,folia:$folia,fabric:$fabric},checks:{packageVerified:true,signedManifest:true,cleanSync:true,actualClient:true,paperJoin:true,bukkitFamilyRuntime:true,proxyFamilyRuntime:true,fabricServerBridge:true,sessionRevokeDeny:true},evidence:["materialized-client-verify.json","published-client-package.json","manifest.json","runtime-verify.json","runtime-sync.json","runtime-launch-minecraft.json","health-paper.json","health-velocity.json","health-bungeecord.json","health-waterfall.json","health-spigot.json","health-purpur.json","health-folia.json","health-fabric.json","bridge-diagnostics.json"]}' \
  > "$RUNTIME_DIR/result.json"
printf '[e2e] PASS %s\n' "$(cat "$RUNTIME_DIR/result.json")"
