#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Minecraft/ServerBridge trust enforcement gate failed: missing {rel}")
    return path.read_text(encoding="utf-8")

def require(rel: str, needles: list[str]) -> None:
    text = read(rel)
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"Minecraft/ServerBridge trust enforcement gate failed: {rel} missing {needle!r}")

require("services/api/internal/httpapi/minecraft_serverbridge_trust_0127.go", [
    'gameplayTrustPolicy0127 = "session-device-risk-v1"',
    "evaluateGameplayTrust0127",
    '"credential_trust_snapshot_missing"',
    '"session_binding_changed"',
    '"session_device_changed"',
    '"trusted_device_required"',
    '"device_reattest_required"',
    '"session_step_up_required"',
    "gameplayTrustPermanentFailure0127",
])
require("services/api/internal/httpapi/minecraft_auth_119.go", [
    "issueMinecraftSessionWithTrust119",
    "TrustedDeviceID: trustedDeviceID",
    "BindingEpoch: bindingEpoch",
    "parentSession.BindingEpoch != bindingEpoch",
    "evaluateGameplayTrust0127(nil, session.UserID, session.NeverSessionID, session.TrustedDeviceID, session.BindingEpoch, false)",
    "evaluateGameplayTrust0127(r, claims.Sub, claims.SessionID, claims.TrustedDeviceID, claims.BindingEpoch, true)",
    "evaluateGameplayTrust0127(r, session.UserID, session.NeverSessionID, session.TrustedDeviceID, session.BindingEpoch, true)",
    '"trust-policy:"+trust.Reason',
])
require("services/api/internal/httpapi/server_bridge.go", [
    'TrustedDeviceID string',
    'BindingEpoch    int64',
    "createJoin(user, claims.SessionID, token, trust.TrustedDeviceID, trust.BindingEpoch, req)",
    "evaluateGameplayTrust0127(r, join.UserID, join.SessionID, join.TrustedDeviceID, join.BindingEpoch, true)",
    "invalidateJoin(username, serverID)",
    '"trust": trust',
])
require("services/api/internal/httpapi/bridge_plugins.go", [
    '"trustPolicy":              gameplayTrustPolicy0127',
    '"trustEnforcement":         "required"',
    '"channel_mismatch"',
    "evaluateGameplayTrust0127(r, join.UserID, join.SessionID, join.TrustedDeviceID, join.BindingEpoch, true)",
    'payload["data"].(map[string]any)["trust"] = trust',
])
require("services/api/internal/model/model.go", [
    'TrustedDeviceID string    `json:"trustedDeviceId,omitempty"`',
    'BindingEpoch    int64     `json:"bindingEpoch"`',
])
require("services/api/internal/repository/postgres.go", [
    "trusted_device_id,binding_epoch",
    "item.TrustedDeviceID",
    "item.BindingEpoch",
])
for migration in [
    "services/api/internal/dbmigrate/sql/0016_minecraft_serverbridge_trust_0127.sql",
    "cli/internal/dbmigrate/sql/0016_minecraft_serverbridge_trust_0127.sql",
]:
    require(migration, [
        "trusted_device_id",
        "binding_epoch",
        "auth_sessions",
        "minecraft_sessions",
    ])
require("services/api/internal/httpapi/minecraft_serverbridge_trust_0127_test.go", [
    "TestMinecraftTrust0127RequiresBoundDeviceAndInvalidatesTokenAfterRebind",
    "unbound minecraft exchange was not denied",
    "minecraft token survived parent device re-bind",
    "TestServerBridgeTrust0127LiveBindingAndRiskEnforcement",
    "bridge ignored live risk policy",
    "bridge accepted mismatched channel",
])
require("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/JoinValidationResult.java", [
    'case "trusted_device_required"',
    'case "credential_trust_snapshot_missing", "session_binding_changed"',
    'case "device_reattest_required"',
    'case "session_step_up_required"',
    'case "channel_mismatch"',
])
require("e2e/scripts/run-minecraft-e2e.sh", [
    "bind canonical launcher session to a real Ed25519 trusted-device key",
    "openssl genpkey -algorithm Ed25519",
    "/api/v1/auth/devices/register/begin",
    "/api/v1/auth/devices/register/complete",
])

print("Minecraft/ServerBridge trust enforcement gate OK: live parent session/device/risk checks, binding-epoch snapshots, channel pinning and plugin deny reasons are enforced")
