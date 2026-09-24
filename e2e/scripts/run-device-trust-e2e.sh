#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/e2e/docker-compose.federation-e2e.yml"
RUNTIME_DIR="$ROOT/e2e/device-trust-runtime"
RESULT_DIR="$ROOT/e2e/device-trust-result"
ENV_FILE="$RUNTIME_DIR/e2e.env"
API="http://127.0.0.1:18081"
DB_DSN="postgres://neverlauncher:neverlauncher@127.0.0.1:55433/neverlauncher?sslmode=disable"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
TARGET_ID="${NEVERLAUNCHER_DEVICE_TRUST_TARGET_ID:-postgres-protocol-linux-x64}"
RESULT_COMMIT="${NEVERLAUNCHER_DEVICE_TRUST_COMMIT:-${GITHUB_SHA:-local}}"
RESULT_RUN_ID="${NEVERLAUNCHER_DEVICE_TRUST_RUN_ID:-${GITHUB_RUN_ID:-local}}"
AUTH_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
BOOTSTRAP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
SIGNING_SEED="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
ADMIN_EMAIL="device-trust-e2e@neverlauncher.local"
ADMIN_PASSWORD="$(python3 -c 'import secrets; print("DT-E2E-" + secrets.token_urlsafe(24))')"
CRYPTO="$ROOT/e2e/scripts/device-trust-crypto.py"
WEBAUTHN="$ROOT/e2e/scripts/webauthn-test-authenticator.py"
SERVERBRIDGE_CRYPTO="$ROOT/e2e/scripts/serverbridge-node-crypto.sh"
# shellcheck source=serverbridge-node-crypto.sh
source "$SERVERBRIDGE_CRYPTO"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[device-trust-e2e] required command missing: $1" >&2; exit 1; }; }
for cmd in docker curl jq go psql python3 openssl sha256sum; do need "$cmd"; done
docker compose version >/dev/null

rm -rf "$RUNTIME_DIR" "$RESULT_DIR"
mkdir -p "$RUNTIME_DIR/keys" "$RESULT_DIR"
chmod 0700 "$RUNTIME_DIR" "$RUNTIME_DIR/keys"
cat > "$ENV_FILE" <<ENV
NEVERLAUNCHER_E2E_AUTH_SECRET=$AUTH_SECRET
NEVERLAUNCHER_E2E_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
NEVERLAUNCHER_E2E_REDIS_PASSWORD=$REDIS_PASSWORD
NEVERLAUNCHER_E2E_SIGNING_SEED=$SIGNING_SEED
ENV
chmod 0600 "$ENV_FILE"
compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
cleanup() {
  if [[ "${NEVERLAUNCHER_E2E_KEEP:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUNTIME_DIR"
  fi
}
trap cleanup EXIT

wait_http() {
  for _ in $(seq 1 90); do
    if curl -fsS "$API/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  compose logs api-a >&2 || true
  echo "[device-trust-e2e] timeout waiting for Backend" >&2
  return 1
}
json_post() {
  local url="$1" token="$2" body="$3"
  curl -fsS -H 'Content-Type: application/json' ${token:+-H "Authorization: Bearer $token"} -d "$body" "$url"
}
request_code() {
  local method="$1" url="$2" token="$3" body="$4" out="$5" user_agent="${6:-}"
  local args=(-sS -o "$out" -w '%{http_code}' -X "$method")
  [[ -n "$token" ]] && args+=(-H "Authorization: Bearer $token")
  [[ -n "$user_agent" ]] && args+=(-H "User-Agent: $user_agent")
  if [[ -n "$body" ]]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  curl "${args[@]}" "$url"
}
expect_code() {
  local expected="$1" actual="$2" context="$3"
  [[ "$actual" == "$expected" ]] || { echo "[device-trust-e2e] $context: expected HTTP $expected, got $actual" >&2; exit 1; }
}
login() {
  local label="$1"
  curl -fsS -H 'Content-Type: application/json' -d "$(jq -cn --arg email "$ADMIN_EMAIL" --arg password "$ADMIN_PASSWORD" --arg device "$label" '{email:$email,password:$password,deviceId:$device}')" "$API/api/v1/auth/login"
}
sign_payload() {
  local algorithm="$1" key="$2" payload="$3" file="$RUNTIME_DIR/payload-$RANDOM-$RANDOM.txt"
  printf '%s' "$payload" > "$file"
  python3 "$CRYPTO" sign --algorithm "$algorithm" --key "$key" --payload "$file"
  rm -f "$file"
}
refresh_payload() {
  local user="$1" session="$2" device="$3" epoch="$4" refresh="$5" hash
  hash="$(printf '%s' "$refresh" | sha256sum | awk '{print $1}')"
  printf 'NeverLauncher Session Device Binding v1\npurpose=refresh\nuser=%s\nsession=%s\ndevice=%s\nbinding-epoch=%s\nrefresh-token-sha256=%s\n' "$user" "$session" "$device" "$epoch" "$hash"
}
sanitize_registration() { jq '{data:{device:.data.device,session:(.data.session|del(.refreshToken?)),accessTokenIssued:(.data.accessToken|type=="string")}}'; }
sanitize_rotation() { jq '{data:{mode:.data.mode,oldDevice:.data.oldDevice,device:.data.device,session:.data.session,oldFingerprintPermanentTombstone:.data.oldFingerprintPermanentTombstone,revokedSessions:.data.revokedSessions,revokedRefreshFamilies:.data.revokedRefreshFamilies,revokedMinecraftSessions:.data.revokedMinecraftSessions,invalidatedChallenges:.data.invalidatedChallenges,invalidatedBridgeJoins:.data.invalidatedBridgeJoins,accessTokenIssued:(.data.accessToken|type=="string")}}'; }

printf '[device-trust-e2e] build CLI, start PostgreSQL/Redis, apply sealed migrations\n'
( cd "$ROOT/cli" && go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$RUNTIME_DIR/nl" ./cmd/neverlauncher )
compose up -d postgres redis volume-init
for _ in $(seq 1 60); do
  if psql "$DB_DSN" -Atqc 'select 1' >/dev/null 2>&1; then break; fi
  sleep 1
done
psql "$DB_DSN" -Atqc 'select 1' >/dev/null
"$RUNTIME_DIR/nl" db migrate apply --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-apply.json"
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify.json"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify.json"
[[ "$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM schema_migrations WHERE version='0018_device_trust_stabilization_01210' AND checksum<>''")" == "1" ]]

printf '[device-trust-e2e] start production PostgreSQL Backend and bootstrap account\n'
compose up -d --build api-a
wait_http
curl -fsS -H 'Content-Type: application/json' -H "X-NeverLauncher-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d "$(jq -cn --arg email "$ADMIN_EMAIL" --arg password "$ADMIN_PASSWORD" '{email:$email,displayName:"Device Trust E2E",password:$password,actor:"device-trust-e2e"}')" \
  "$API/api/v1/install/bootstrap-admin" > "$RUNTIME_DIR/bootstrap.json"
repo_driver="$(psql "$DB_DSN" -Atqc "SELECT current_database()")"
[[ "$repo_driver" == "neverlauncher" ]]

printf '[device-trust-e2e] verify 0.13.0 runtime release/readiness contract\n'
curl -fsS "$API/api/v1/auth/capabilities" > "$RESULT_DIR/release-capabilities.json"
jq -e --arg version "$VERSION" '.data.deviceTrustRelease.status=="released" and .data.deviceTrustRelease.releaseVersion=="0.13.0" and .data.deviceTrustRelease.runtimeVersion==$version and .data.deviceTrustRelease.schemaMigration=="0018_device_trust_stabilization_01210" and .data.deviceTrustRelease.schemaFrozen==true and .data.deviceTrustRelease.enforcement.sessionDeviceBinding==true and .data.deviceTrustRelease.enforcement.deviceBoundRefresh==true and .data.deviceTrustRelease.enforcement.riskActions==true and .data.deviceTrustRelease.enforcement.minecraftServerBridge==true and .data.deviceTrustRelease.releaseCertification.required==true and .data.deviceTrustRelease.attestation.vendorProvenance=="not-remotely-verified"' "$RESULT_DIR/release-capabilities.json" >/dev/null
curl -fsS "$API/ready" > "$RESULT_DIR/release-readiness.json"
jq -e '.status=="ready" and .checks.migrations=="0018_device_trust_stabilization_01210" and .repository=="pgx"' "$RESULT_DIR/release-readiness.json" >/dev/null

printf '[device-trust-e2e] real Ed25519 registration, binding epoch and replay protection\n'
LOGIN1="$(login dt-primary)"
ACCESS_PRE="$(jq -er '.data.tokens.accessToken' <<<"$LOGIN1")"
REFRESH1="$(jq -er '.data.tokens.refreshToken' <<<"$LOGIN1")"
SESSION_ID="$(jq -er '.data.session.id' <<<"$LOGIN1")"
USER_ID="$(jq -er '.data.session.userId' <<<"$LOGIN1")"
KEY1="$RUNTIME_DIR/keys/device-1-ed25519.pem"
KEY2="$RUNTIME_DIR/keys/device-2-ed25519.pem"
openssl genpkey -algorithm Ed25519 -out "$KEY1" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$KEY2" >/dev/null 2>&1
PUB1="$(python3 "$CRYPTO" public --algorithm ed25519 --key "$KEY1")"
PUB2="$(python3 "$CRYPTO" public --algorithm ed25519 --key "$KEY2")"
SERVER_NODE_KEY="$RUNTIME_DIR/keys/serverbridge-node-ed25519.pem"
SERVER_NODE_IDENTITY="$RUNTIME_DIR/keys/serverbridge-node-identity.properties"
serverbridge_node_generate "$SERVER_NODE_KEY" "$SERVER_NODE_IDENTITY"
SERVER_NODE_PUBLIC="$(serverbridge_node_public "$SERVER_NODE_KEY")"
BEGIN1="$(json_post "$API/api/v1/auth/devices/register/begin" "$ACCESS_PRE" "$(jq -cn --arg v "$VERSION" '{name:"Device Trust E2E primary",platform:"linux",clientVersion:$v,keyAlgorithm:"ed25519",keyBinding:"software"}')")"
SIG1="$(sign_payload ed25519 "$KEY1" "$(jq -er '.data.signingPayload' <<<"$BEGIN1")")"
COMPLETE_BODY1="$(jq -cn --arg challengeId "$(jq -er '.data.challengeId' <<<"$BEGIN1")" --arg deviceId "$(jq -er '.data.deviceId' <<<"$BEGIN1")" --arg challenge "$(jq -er '.data.challenge' <<<"$BEGIN1")" --arg publicKey "$PUB1" --arg signature "$SIG1" '{challengeId:$challengeId,deviceId:$deviceId,challenge:$challenge,publicKey:$publicKey,signature:$signature}')"
COMPLETE1="$(json_post "$API/api/v1/auth/devices/register/complete" "$ACCESS_PRE" "$COMPLETE_BODY1")"
ACCESS1="$(jq -er '.data.accessToken' <<<"$COMPLETE1")"
DEVICE1="$(jq -er '.data.device.id' <<<"$COMPLETE1")"
EPOCH1="$(jq -er '.data.session.bindingEpoch' <<<"$COMPLETE1")"
[[ "$EPOCH1" -ge 2 ]]
printf '%s' "$COMPLETE1" | sanitize_registration > "$RESULT_DIR/registration.json"
code="$(request_code GET "$API/api/v1/auth/device-trust" "$ACCESS_PRE" '' "$RUNTIME_DIR/prebind-access.json")"; expect_code 401 "$code" 'pre-bind access survived binding epoch change'
code="$(request_code POST "$API/api/v1/auth/devices/register/complete" "$ACCESS1" "$COMPLETE_BODY1" "$RUNTIME_DIR/registration-replay.json")"; expect_code 401 "$code" 'registration challenge replay'
TRUST1="$(curl -fsS -H "Authorization: Bearer $ACCESS1" "$API/api/v1/auth/device-trust")"
jq -e --arg dev "$DEVICE1" '.data.deviceTrustState=="verified" and .data.trustedDeviceId==$dev' <<<"$TRUST1" >/dev/null
jq '{data:{deviceTrustState:.data.deviceTrustState,trustedDeviceId:.data.trustedDeviceId,deviceAttestationState:.data.deviceAttestationState}}' <<<"$TRUST1" > "$RESULT_DIR/trust-after-registration.json"

printf '[device-trust-e2e] bound refresh requires possession of the current key\n'
code="$(request_code POST "$API/api/v1/auth/refresh" '' "$(jq -cn --arg refresh "$REFRESH1" '{refreshToken:$refresh}')" "$RUNTIME_DIR/refresh-without-proof.json")"; expect_code 428 "$code" 'bound refresh without device proof'
REFRESH_PAYLOAD1="$(refresh_payload "$USER_ID" "$SESSION_ID" "$DEVICE1" "$EPOCH1" "$REFRESH1")"
REFRESH_SIG1="$(sign_payload ed25519 "$KEY1" "$REFRESH_PAYLOAD1")"
REFRESH_OK1="$(json_post "$API/api/v1/auth/refresh" '' "$(jq -cn --arg refresh "$REFRESH1" --arg device "$DEVICE1" --arg sig "$REFRESH_SIG1" '{refreshToken:$refresh,deviceId:$device,deviceSignature:$sig}')")"
ACCESS1R="$(jq -er '.data.tokens.accessToken' <<<"$REFRESH_OK1")"
REFRESH2="$(jq -er '.data.tokens.refreshToken' <<<"$REFRESH_OK1")"
[[ "$REFRESH2" != "$REFRESH1" ]]

printf '[device-trust-e2e] ServerBridge join is live-bound to device identity and epoch\n'
json_post "$API/api/v1/install/first-project" "$ACCESS1R" '{"projectId":"dt-e2e-project","profileId":"vanilla","channel":"stable","version":"0.0.1-device-trust","actor":"device-trust-e2e"}' > "$RUNTIME_DIR/first-project.json"
SERVER_REG_BODY="$(jq -cn --arg publicKey "$SERVER_NODE_PUBLIC" '{id:"dt-e2e-paper",name:"Device Trust E2E Paper",kind:"paper",projectId:"dt-e2e-project",profileId:"vanilla",keyAlgorithm:"ed25519",publicKey:$publicKey}')"
SERVER_REG="$(json_post "$API/api/v1/server-bridge/servers/register" "$ACCESS1R" "$SERVER_REG_BODY")"
jq -e '.data.status=="registered" and .data.nodeIdentity.keyAlgorithm=="ed25519" and .data.nodeIdentity.identityEpoch==1' <<<"$SERVER_REG" >/dev/null
json_post "$API/api/v1/session/join" "$ACCESS1R" '{"username":"DeviceTrustE2E","serverId":"dt-e2e-paper","projectId":"dt-e2e-project","profileId":"vanilla","channel":"stable"}' > "$RUNTIME_DIR/join-before-rotation.json"
BRIDGE_VALIDATE_BODY='{"protocolVersion":2,"serverId":"dt-e2e-paper","username":"DeviceTrustE2E","projectId":"dt-e2e-project","profileId":"vanilla","channel":"stable"}'
code="$(serverbridge_node_signed_request "$SERVER_NODE_KEY" dt-e2e-paper POST "$API/api/v1/server-bridge/validate-join" "$BRIDGE_VALIDATE_BODY" "$RESULT_DIR/bridge-before-rotation.json")"
expect_code 200 "$code" 'trusted ServerBridge validate before rotation'
jq -e '.data.allowed==true' "$RESULT_DIR/bridge-before-rotation.json" >/dev/null

printf '[device-trust-e2e] key rotation requires BOTH old/new proofs and burns failed challenge\n'
rotation_begin() {
  json_post "$API/api/v1/auth/devices/key-rotation/begin" "$ACCESS1R" "$(jq -cn --arg old "$DEVICE1" --arg pub "$PUB2" --arg v "$VERSION" '{oldDeviceId:$old,name:"Device Trust E2E rotated",platform:"linux",clientVersion:$v,publicKey:$pub,keyAlgorithm:"ed25519",keyBinding:"software"}')"
}
ROT1="$(rotation_begin)"
ROT_PAYLOAD1="$(jq -er '.data.signingPayload' <<<"$ROT1")"
NEW_SIG_ONLY="$(sign_payload ed25519 "$KEY2" "$ROT_PAYLOAD1")"
ROT_FAIL_BODY="$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$ROT1")" --arg ch "$(jq -er '.data.challenge' <<<"$ROT1")" --arg ns "$NEW_SIG_ONLY" '{challengeId:$id,challenge:$ch,newSignature:$ns}')"
code="$(request_code POST "$API/api/v1/auth/devices/$DEVICE1/key-rotation/complete" "$ACCESS1R" "$ROT_FAIL_BODY" "$RUNTIME_DIR/rotation-missing-old-proof.json")"; expect_code 401 "$code" 'rotation without old key proof'
OLD_SIG_BURNED="$(sign_payload ed25519 "$KEY1" "$ROT_PAYLOAD1")"
ROT_REPLAY_BODY="$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$ROT1")" --arg ch "$(jq -er '.data.challenge' <<<"$ROT1")" --arg os "$OLD_SIG_BURNED" --arg ns "$NEW_SIG_ONLY" '{challengeId:$id,challenge:$ch,oldSignature:$os,newSignature:$ns}')"
code="$(request_code POST "$API/api/v1/auth/devices/$DEVICE1/key-rotation/complete" "$ACCESS1R" "$ROT_REPLAY_BODY" "$RUNTIME_DIR/rotation-burned-replay.json")"; expect_code 401 "$code" 'failed rotation challenge replay'
ROT2="$(rotation_begin)"
ROT_PAYLOAD2="$(jq -er '.data.signingPayload' <<<"$ROT2")"
OLD_SIG2="$(sign_payload ed25519 "$KEY1" "$ROT_PAYLOAD2")"
NEW_SIG2="$(sign_payload ed25519 "$KEY2" "$ROT_PAYLOAD2")"
ROT_OK_BODY="$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$ROT2")" --arg ch "$(jq -er '.data.challenge' <<<"$ROT2")" --arg os "$OLD_SIG2" --arg ns "$NEW_SIG2" '{challengeId:$id,challenge:$ch,oldSignature:$os,newSignature:$ns}')"
ROT_OK="$(json_post "$API/api/v1/auth/devices/$DEVICE1/key-rotation/complete" "$ACCESS1R" "$ROT_OK_BODY")"
ACCESS2="$(jq -er '.data.accessToken' <<<"$ROT_OK")"
DEVICE2="$(jq -er '.data.device.id' <<<"$ROT_OK")"
EPOCH2="$(jq -er '.data.session.bindingEpoch' <<<"$ROT_OK")"
[[ "$DEVICE2" != "$DEVICE1" && "$EPOCH2" -gt "$EPOCH1" ]]
jq -e '.data.oldFingerprintPermanentTombstone==true and .data.mode=="rotate"' <<<"$ROT_OK" >/dev/null
printf '%s' "$ROT_OK" | sanitize_rotation > "$RESULT_DIR/rotation.json"
code="$(request_code GET "$API/api/v1/auth/device-trust" "$ACCESS1R" '' "$RUNTIME_DIR/pre-rotation-access.json")"; expect_code 401 "$code" 'pre-rotation access survived binding epoch change'
code="$(serverbridge_node_signed_request "$SERVER_NODE_KEY" dt-e2e-paper POST "$API/api/v1/server-bridge/validate-join" "$BRIDGE_VALIDATE_BODY" "$RESULT_DIR/bridge-after-rotation.json")"
expect_code 403 "$code" 'old ServerBridge join survived rotation'
jq -e '.data.allowed==false and (.data.reason=="launcher_session_missing_or_expired" or .data.reason=="session_binding_changed" or .data.reason=="session_device_changed")' "$RESULT_DIR/bridge-after-rotation.json" >/dev/null

printf '[device-trust-e2e] same refresh family now requires replacement key and replacement device id\n'
OLD_REFRESH_PAYLOAD="$(refresh_payload "$USER_ID" "$SESSION_ID" "$DEVICE1" "$EPOCH1" "$REFRESH2")"
OLD_REFRESH_SIG="$(sign_payload ed25519 "$KEY1" "$OLD_REFRESH_PAYLOAD")"
code="$(request_code POST "$API/api/v1/auth/refresh" '' "$(jq -cn --arg refresh "$REFRESH2" --arg device "$DEVICE1" --arg sig "$OLD_REFRESH_SIG" '{refreshToken:$refresh,deviceId:$device,deviceSignature:$sig}')" "$RUNTIME_DIR/refresh-old-key-after-rotation.json")"; expect_code 428 "$code" 'old key refreshed rebound session'
REFRESH_PAYLOAD2="$(refresh_payload "$USER_ID" "$SESSION_ID" "$DEVICE2" "$EPOCH2" "$REFRESH2")"
REFRESH_SIG2="$(sign_payload ed25519 "$KEY2" "$REFRESH_PAYLOAD2")"
REFRESH_OK2="$(json_post "$API/api/v1/auth/refresh" '' "$(jq -cn --arg refresh "$REFRESH2" --arg device "$DEVICE2" --arg sig "$REFRESH_SIG2" '{refreshToken:$refresh,deviceId:$device,deviceSignature:$sig}')")"
ACCESS2R="$(jq -er '.data.tokens.accessToken' <<<"$REFRESH_OK2")"
REFRESH3="$(jq -er '.data.tokens.refreshToken' <<<"$REFRESH_OK2")"

printf '[device-trust-e2e] old fingerprint remains a permanent tombstone\n'
TOMB_LOGIN="$(login dt-tombstone)"; TOMB_ACCESS="$(jq -er '.data.tokens.accessToken' <<<"$TOMB_LOGIN")"
TOMB_BEGIN="$(json_post "$API/api/v1/auth/devices/register/begin" "$TOMB_ACCESS" "$(jq -cn --arg v "$VERSION" '{name:"Old key reuse attempt",platform:"linux",clientVersion:$v,keyAlgorithm:"ed25519",keyBinding:"software"}')")"
TOMB_SIG="$(sign_payload ed25519 "$KEY1" "$(jq -er '.data.signingPayload' <<<"$TOMB_BEGIN")")"
TOMB_BODY="$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$TOMB_BEGIN")" --arg dev "$(jq -er '.data.deviceId' <<<"$TOMB_BEGIN")" --arg ch "$(jq -er '.data.challenge' <<<"$TOMB_BEGIN")" --arg pub "$PUB1" --arg sig "$TOMB_SIG" '{challengeId:$id,deviceId:$dev,challenge:$ch,publicKey:$pub,signature:$sig}')"
code="$(request_code POST "$API/api/v1/auth/devices/register/complete" "$TOMB_ACCESS" "$TOMB_BODY" "$RESULT_DIR/old-key-tombstone.json")"; expect_code 409 "$code" 'revoked fingerprint was re-enrolled'

printf '[device-trust-e2e] risk integration persists drift and blocks sensitive gameplay until step-up\n'
RISK_LOGIN="$(login dt-risk)"; RISK_ACCESS_PRE="$(jq -er '.data.tokens.accessToken' <<<"$RISK_LOGIN")"; RISK_SESSION="$(jq -er '.data.session.id' <<<"$RISK_LOGIN")"
RISK_BEGIN="$(json_post "$API/api/v1/auth/devices/$DEVICE2/verify/begin" "$RISK_ACCESS_PRE" '{}')"
RISK_SIG="$(sign_payload ed25519 "$KEY2" "$(jq -er '.data.signingPayload' <<<"$RISK_BEGIN")")"
RISK_COMPLETE="$(json_post "$API/api/v1/auth/devices/$DEVICE2/verify/complete" "$RISK_ACCESS_PRE" "$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$RISK_BEGIN")" --arg ch "$(jq -er '.data.challenge' <<<"$RISK_BEGIN")" --arg sig "$RISK_SIG" '{challengeId:$id,challenge:$ch,signature:$sig}')")"
RISK_ACCESS="$(jq -er '.data.accessToken' <<<"$RISK_COMPLETE")"
RISK_UA="NeverLauncher-DeviceTrust-E2E/${VERSION}-risk"
code="$(request_code GET "$API/api/v1/auth/sessions" "$RISK_ACCESS" '' "$RUNTIME_DIR/risk-sessions.json" "$RISK_UA")"; expect_code 200 "$code" 'risk observation request'
jq -e --arg sid "$RISK_SESSION" '.data.items[] | select(.id==$sid) | .riskAction=="step-up" and .riskState=="elevated" and .riskScore>=35' "$RUNTIME_DIR/risk-sessions.json" >/dev/null
jq --arg sid "$RISK_SESSION" '{data:{session:(.data.items[]|select(.id==$sid)|{id,riskState,riskScore,riskAction,riskReasons})}}' "$RUNTIME_DIR/risk-sessions.json" > "$RESULT_DIR/risk-step-up.json"
code="$(request_code POST "$API/api/v1/session/join" "$RISK_ACCESS" '{"username":"RiskPlayer","serverId":"dt-e2e-paper","projectId":"dt-e2e-project","profileId":"vanilla","channel":"stable"}' "$RUNTIME_DIR/risk-join-denied.json" "$RISK_UA")"; expect_code 428 "$code" 'elevated-risk gameplay join'

printf '[device-trust-e2e] P-256 hardware-bound protocol attestation, without claiming vendor provenance\n'
HW_LOGIN="$(login dt-hardware)"; HW_ACCESS_PRE="$(jq -er '.data.tokens.accessToken' <<<"$HW_LOGIN")"
HW_KEY="$RUNTIME_DIR/keys/device-hardware-p256.pem"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$HW_KEY" >/dev/null 2>&1
HW_PUB="$(python3 "$CRYPTO" public --algorithm p256 --key "$HW_KEY")"
HW_BEGIN="$(json_post "$API/api/v1/auth/devices/register/begin" "$HW_ACCESS_PRE" "$(jq -cn --arg v "$VERSION" '{name:"CI P-256 protocol identity",platform:"linux",clientVersion:$v,keyAlgorithm:"p256",keyBinding:"hardware",hardwareProvider:"ci-protocol-p256"}')")"
HW_SIG="$(sign_payload p256 "$HW_KEY" "$(jq -er '.data.signingPayload' <<<"$HW_BEGIN")")"
HW_COMPLETE="$(json_post "$API/api/v1/auth/devices/register/complete" "$HW_ACCESS_PRE" "$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$HW_BEGIN")" --arg dev "$(jq -er '.data.deviceId' <<<"$HW_BEGIN")" --arg ch "$(jq -er '.data.challenge' <<<"$HW_BEGIN")" --arg pub "$HW_PUB" --arg sig "$HW_SIG" '{challengeId:$id,deviceId:$dev,challenge:$ch,publicKey:$pub,signature:$sig}')")"
HW_ACCESS="$(jq -er '.data.accessToken' <<<"$HW_COMPLETE")"; HW_DEVICE="$(jq -er '.data.device.id' <<<"$HW_COMPLETE")"
jq -e '.data.device.keyAlgorithm=="p256" and .data.device.keyBinding=="hardware" and .data.device.assurance=="proof-of-possession" and .data.device.attestationState=="unattested"' <<<"$HW_COMPLETE" >/dev/null
ATT_BEGIN="$(json_post "$API/api/v1/auth/devices/$HW_DEVICE/attest/begin" "$HW_ACCESS" '{}')"
jq -e '.data.hardwareProvenance=="not-remotely-verified" and .data.privateKeyServerExposed==false and .data.attestationMethod=="hardware-key-challenge-response-v1"' <<<"$ATT_BEGIN" >/dev/null
ATT_SIG="$(sign_payload p256 "$HW_KEY" "$(jq -er '.data.signingPayload' <<<"$ATT_BEGIN")")"
ATT_BODY="$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$ATT_BEGIN")" --arg ch "$(jq -er '.data.challenge' <<<"$ATT_BEGIN")" --arg sig "$ATT_SIG" '{challengeId:$id,challenge:$ch,signature:$sig}')"
ATT_OK="$(json_post "$API/api/v1/auth/devices/$HW_DEVICE/attest/complete" "$HW_ACCESS" "$ATT_BODY")"
HW_ACCESS_ATTESTED="$(jq -er '.data.accessToken' <<<"$ATT_OK")"
jq -e '.data.attestationState=="verified" and .data.device.assurance=="challenge-response-attested" and .data.hardwareProvenance=="not-remotely-verified" and .data.authorizationElevation==false' <<<"$ATT_OK" >/dev/null
jq '{data:{device:.data.device,attestationState:.data.attestationState,attestationMethod:.data.attestationMethod,hardwareProvenance:.data.hardwareProvenance,authorizationElevation:.data.authorizationElevation,phishingResistantElevation:.data.phishingResistantElevation}}' <<<"$ATT_OK" > "$RESULT_DIR/p256-attestation.json"
code="$(request_code POST "$API/api/v1/auth/devices/$HW_DEVICE/attest/complete" "$HW_ACCESS_ATTESTED" "$ATT_BODY" "$RUNTIME_DIR/attestation-replay.json")"; expect_code 401 "$code" 'attestation replay'
code="$(request_code POST "$API/api/v1/auth/devices/key-recovery/begin" "$HW_ACCESS_ATTESTED" '{}' "$RESULT_DIR/recovery-step-up-required.json")"; expect_code 428 "$code" 'recovery without phishing-resistant step-up'

printf '[device-trust-e2e] real WebAuthn assertion unlocks key recovery, then old hardware identity is tombstoned\n'
PASS_LOGIN="$(login dt-passkey-bootstrap)"; PASS_ACCESS="$(jq -er '.data.tokens.accessToken' <<<"$PASS_LOGIN")"
PK_BEGIN="$(json_post "$API/api/v1/auth/passkeys/register/begin" "$PASS_ACCESS" '{}')"
PK_STATE="$RUNTIME_DIR/keys/passkey-state.json"; PK_KEY="$RUNTIME_DIR/keys/passkey-p256.pem"
PK_BODY="$(python3 "$WEBAUTHN" register \
  --transaction-token "$(jq -er '.data.transactionToken' <<<"$PK_BEGIN")" \
  --challenge "$(jq -er '.data.publicKey.challenge' <<<"$PK_BEGIN")" \
  --rp-id "$(jq -er '.data.publicKey.rp.id' <<<"$PK_BEGIN")" \
  --origin "$API" \
  --user-handle "$(jq -er '.data.publicKey.user.id' <<<"$PK_BEGIN")" \
  --state "$PK_STATE" --key "$PK_KEY")"
PK_COMPLETE="$(json_post "$API/api/v1/auth/passkeys/register/complete" "$PASS_ACCESS" "$PK_BODY")"
jq -e '.data.status=="registered" and (.data.accessToken|type=="string") and .data.session.authStrength=="phishing-resistant"' <<<"$PK_COMPLETE" >/dev/null
STEP_BEGIN="$(json_post "$API/api/v1/auth/passkeys/step-up/begin" "$HW_ACCESS_ATTESTED" '{}')"
STEP_BODY="$(python3 "$WEBAUTHN" assert \
  --transaction-token "$(jq -er '.data.transactionToken' <<<"$STEP_BEGIN")" \
  --challenge "$(jq -er '.data.publicKey.challenge' <<<"$STEP_BEGIN")" \
  --state "$PK_STATE" --sign-count 1)"
STEP_OK="$(json_post "$API/api/v1/auth/passkeys/step-up/complete" "$HW_ACCESS_ATTESTED" "$STEP_BODY")"
HW_STEPPED_ACCESS="$(jq -er '.data.accessToken' <<<"$STEP_OK")"
jq -e '.data.status=="stepped-up" and .data.session.authStrength=="phishing-resistant"' <<<"$STEP_OK" >/dev/null
RECOVERY_KEY="$RUNTIME_DIR/keys/device-recovered-ed25519.pem"
openssl genpkey -algorithm Ed25519 -out "$RECOVERY_KEY" >/dev/null 2>&1
RECOVERY_PUB="$(python3 "$CRYPTO" public --algorithm ed25519 --key "$RECOVERY_KEY")"
REC_BEGIN="$(json_post "$API/api/v1/auth/devices/key-recovery/begin" "$HW_STEPPED_ACCESS" "$(jq -cn --arg old "$HW_DEVICE" --arg pub "$RECOVERY_PUB" --arg v "$VERSION" '{oldDeviceId:$old,name:"Recovered Device Trust E2E identity",platform:"linux",clientVersion:$v,publicKey:$pub,keyAlgorithm:"ed25519",keyBinding:"software"}')")"
REC_SIG="$(sign_payload ed25519 "$RECOVERY_KEY" "$(jq -er '.data.signingPayload' <<<"$REC_BEGIN")")"
REC_BODY="$(jq -cn --arg id "$(jq -er '.data.challengeId' <<<"$REC_BEGIN")" --arg ch "$(jq -er '.data.challenge' <<<"$REC_BEGIN")" --arg sig "$REC_SIG" '{challengeId:$id,challenge:$ch,newSignature:$sig}')"
REC_OK="$(json_post "$API/api/v1/auth/devices/$HW_DEVICE/key-recovery/complete" "$HW_STEPPED_ACCESS" "$REC_BODY")"
REC_DEVICE="$(jq -er '.data.device.id' <<<"$REC_OK")"
[[ "$REC_DEVICE" != "$HW_DEVICE" ]]
jq -e '.data.mode=="recover" and .data.oldFingerprintPermanentTombstone==true and .data.session.authStrength=="phishing-resistant"' <<<"$REC_OK" >/dev/null
printf '%s' "$REC_OK" | sanitize_rotation > "$RESULT_DIR/recovery.json"
code="$(request_code GET "$API/api/v1/auth/device-trust" "$HW_STEPPED_ACCESS" '' "$RUNTIME_DIR/pre-recovery-access.json")"; expect_code 401 "$code" 'pre-recovery access survived binding epoch change'
code="$(request_code POST "$API/api/v1/auth/devices/$HW_DEVICE/key-recovery/complete" "$(jq -er '.data.accessToken' <<<"$REC_OK")" "$REC_BODY" "$RUNTIME_DIR/recovery-replay.json")"; expect_code 401 "$code" 'recovery challenge replay'

printf '[device-trust-e2e] permanent device revoke cascades to access and refresh credentials\n'
REVOKE="$(json_post "$API/api/v1/auth/devices/$DEVICE2/revoke" "$ACCESS2R" '{"reason":"device-trust-e2e-revoke"}')"
jq -e '.data.device.status=="revoked" and .data.reEnrollmentRequiresNewKey==true and .data.revokedRefreshFamilies>=1' <<<"$REVOKE" >/dev/null
jq '{data:{device:.data.device,alreadyRevoked:.data.alreadyRevoked,revokedSessions:.data.revokedSessions,revokedRefreshFamilies:.data.revokedRefreshFamilies,revokedMinecraftSessions:.data.revokedMinecraftSessions,invalidatedChallenges:.data.invalidatedChallenges,invalidatedBridgeJoins:.data.invalidatedBridgeJoins,reEnrollmentRequiresNewKey:.data.reEnrollmentRequiresNewKey}}' <<<"$REVOKE" > "$RESULT_DIR/revocation.json"
code="$(request_code GET "$API/api/v1/auth/device-trust" "$ACCESS2R" '' "$RUNTIME_DIR/revoked-access.json")"; expect_code 401 "$code" 'revoked device access survived'
REVOKED_REFRESH_PAYLOAD="$(refresh_payload "$USER_ID" "$SESSION_ID" "$DEVICE2" "$EPOCH2" "$REFRESH3")"
REVOKED_REFRESH_SIG="$(sign_payload ed25519 "$KEY2" "$REVOKED_REFRESH_PAYLOAD")"
code="$(request_code POST "$API/api/v1/auth/refresh" '' "$(jq -cn --arg refresh "$REFRESH3" --arg device "$DEVICE2" --arg sig "$REVOKED_REFRESH_SIG" '{refreshToken:$refresh,deviceId:$device,deviceSignature:$sig}')" "$RUNTIME_DIR/revoked-refresh.json")"; expect_code 401 "$code" 'revoked device refresh survived'

printf '[device-trust-e2e] require 0.12.9 -> 0.12.10 upgrade evidence\n'
MIGRATION_UPGRADE_EVIDENCE="$ROOT/e2e/device-trust-migration-result/migration-stabilization.json"
[[ -f "$MIGRATION_UPGRADE_EVIDENCE" ]] || { echo '[device-trust-e2e] migration upgrade evidence missing; run run-device-trust-migration-e2e.sh first' >&2; exit 1; }
jq -e --arg version "$VERSION" '.status=="passed" and .version==$version and .upgrade.fromMigration=="0017_device_key_recovery_rotation_0128" and .upgrade.toMigration=="0018_device_trust_stabilization_01210" and .upgrade.sealedChecksum==true and .ownershipEnforcement.constraints==7' "$MIGRATION_UPGRADE_EVIDENCE" >/dev/null
cp "$MIGRATION_UPGRADE_EVIDENCE" "$RESULT_DIR/migration-upgrade-e2e.json"

printf '[device-trust-e2e] verify runtime really used PostgreSQL and migrations remain sealed\n'
[[ "$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM trusted_devices WHERE user_id='$USER_ID'")" -ge 4 ]]
[[ "$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM trusted_devices WHERE id='$DEVICE1' AND status='revoked' AND replaced_by_device_id='$DEVICE2' AND replacement_reason='rotate'")" == "1" ]]
[[ "$(psql "$DB_DSN" -Atqc "SELECT count(*) FROM trusted_devices WHERE id='$HW_DEVICE' AND status='revoked' AND replaced_by_device_id='$REC_DEVICE' AND replacement_reason='recover'")" == "1" ]]
"$RUNTIME_DIR/nl" db migrate verify --dsn "$DB_DSN" > "$RUNTIME_DIR/migrate-verify-after.json"
grep -q 'verified' "$RUNTIME_DIR/migrate-verify-after.json"
psql "$DB_DSN" -Atqc "SELECT json_build_object(
  'migration','0018_device_trust_stabilization_01210',
  'sealed',(SELECT checksum<>'' FROM schema_migrations WHERE version='0018_device_trust_stabilization_01210'),
  'replacementChallengePurposes',(SELECT position('key-rotate' in pg_get_constraintdef(oid))>0 AND position('key-recover' in pg_get_constraintdef(oid))>0 FROM pg_constraint WHERE conname='device_challenges_purpose_check'),
  'ownershipConstraints',(SELECT count(*) FROM pg_constraint WHERE conname IN ('auth_sessions_trusted_device_owner_fk','trusted_devices_replacement_owner_fk','minecraft_sessions_never_session_owner_fk','minecraft_sessions_device_owner_fk','minecraft_sessions_profile_owner_fk')),
  'bindingShapeConstraint',(SELECT count(*)=1 FROM pg_constraint WHERE conname='auth_sessions_device_binding_shape_check'),
  'replacementShapeConstraint',(SELECT count(*)=1 FROM pg_constraint WHERE conname='trusted_devices_replacement_shape_check')
)::text" | jq -c . > "$RESULT_DIR/migration-stabilization.json"
jq -e '.sealed==true and .replacementChallengePurposes==true and .ownershipConstraints==5 and .bindingShapeConstraint==true and .replacementShapeConstraint==true' "$RESULT_DIR/migration-stabilization.json" >/dev/null

EVIDENCE_FILES=(
  registration.json trust-after-registration.json bridge-before-rotation.json rotation.json
  bridge-after-rotation.json old-key-tombstone.json risk-step-up.json p256-attestation.json
  recovery-step-up-required.json recovery.json revocation.json migration-stabilization.json migration-upgrade-e2e.json
  release-capabilities.json release-readiness.json
)
EVIDENCE_FILES_JSON="$(printf '%s\n' "${EVIDENCE_FILES[@]}" | jq -R . | jq -s -c .)"
EVIDENCE_SHA_JSON='{}'
for evidence_name in "${EVIDENCE_FILES[@]}"; do
  [[ -f "$RESULT_DIR/$evidence_name" ]] || { echo "[device-trust-e2e] missing evidence file: $evidence_name" >&2; exit 1; }
  evidence_sha="$(sha256sum "$RESULT_DIR/$evidence_name" | awk '{print $1}')"
  EVIDENCE_SHA_JSON="$(jq -cn --argjson current "$EVIDENCE_SHA_JSON" --arg name "$evidence_name" --arg digest "$evidence_sha" '$current + {($name):$digest}')"
done

jq -n \
  --arg version "$VERSION" --arg target "$TARGET_ID" --arg commit "$RESULT_COMMIT" --arg run "$RESULT_RUN_ID" \
  --argjson evidenceFiles "$EVIDENCE_FILES_JSON" --argjson evidenceSha "$EVIDENCE_SHA_JSON" \
  '{schemaVersion:"1.0",productVersion:$version,targetId:$target,kind:"protocol-e2e",os:"linux",arch:"x86_64",runtimeArch:"x86_64",commit:$commit,runId:$run,status:"passed",exitCode:0,
    checks:{postgresRepository:true,migrationStabilization01210:true,registrationReplayDenied:true,sessionBindingEpoch:true,boundRefreshProof:true,rotationDualProof:true,oldKeyTombstone:true,serverBridgeBindingDeny:true,revocationCascade:true,riskStepUp:true,p256AttestationProtocol:true,attestationReplayDenied:true,recoveryRequiresPhishingResistantStepUp:true,recoveryPhishingResistantEndToEnd:true,deviceTrustRelease0130:true},
    evidence:{files:$evidenceFiles,sha256:$evidenceSha},
    claims:{repository:"postgresql",vendorHardwareProvenance:"not-verified",privateKeyServerExposed:false,deviceTrustRelease:$version}}' > "$RESULT_DIR/device-trust-result.json"

# Ensure public evidence cannot accidentally contain bearer/refresh/private-key material.
if grep -RIEq 'accessToken"[[:space:]]*:[[:space:]]*"|refreshToken"[[:space:]]*:[[:space:]]*"|BEGIN (EC |ED25519 |)PRIVATE KEY' "$RESULT_DIR"; then
  echo '[device-trust-e2e] secret material leaked into public evidence' >&2
  exit 1
fi
printf '[device-trust-e2e] PASS %s\n' "$(cat "$RESULT_DIR/device-trust-result.json")"
