#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
errors: list[str] = []


def need(rel: str, needles: list[str]) -> None:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"{rel}: файл отсутствует")
        return
    text = path.read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            errors.append(f"{rel}: отсутствует {needle!r}")

need("services/api/internal/dbmigrate/sql/0015_session_device_risk_0126.sql", [
    "binding_epoch BIGINT NOT NULL DEFAULT 1",
    "risk_score SMALLINT NOT NULL DEFAULT 0",
    "risk_action TEXT NOT NULL DEFAULT 'allow'",
    "risk_evaluated_at TIMESTAMPTZ",
    "'allow','step-up','reattest','revoke'",
])
need("cli/internal/dbmigrate/sql/0015_session_device_risk_0126.sql", ["binding_epoch", "risk_action", "risk_evaluated_at"])
need("services/api/internal/httpapi/auth.go", [
    'json:"binding_epoch"', 'json:"risk_state,omitempty"', 'json:"risk_score,omitempty"', 'json:"risk_action,omitempty"',
    "sessionBindingClaimsMatch0126(claims, session)", "reconcileSessionDeviceRisk0126(r, session)",
])
need("services/api/internal/httpapi/auth_sessions.go", [
    "BindingEpoch", "RiskScore", "RiskAction", "RiskEvaluatedAt", "rec.BindingEpoch++", "previewRefresh0126",
])
need("services/api/internal/httpapi/session_management_postgres_118.go", [
    "binding_epoch,risk_score,risk_action,risk_evaluated_at",
    "binding_epoch=GREATEST(binding_epoch,1)+1",
    "applyRisk0126", "previewRefresh0126",
])
need("services/api/internal/httpapi/session_device_risk_0126.go", [
    "NeverLauncher Session Device Binding v1",
    "refresh-token-sha256=",
    "verifyRefreshDeviceProof0126",
    "device-attestation-stale",
    'return "compromised", 100, "revoke"',
    'return "elevated", score, "step-up"',
    'return "elevated", score, "reattest"',
])
need("services/api/internal/httpapi/auth_accounts.go", [
    'DeviceSignature string `json:"deviceSignature,omitempty"`',
    "previewRefresh0126(req.RefreshToken)",
    "verifyRefreshDeviceProof0126",
    "http.StatusPreconditionRequired",
    "device-bound-refresh",
    '"riskActions": []string{"allow", "step-up", "reattest", "revoke"}',
])
need("services/api/internal/httpapi/webauthn_handlers_117.go", ["writeRiskRequirement0126(w, claims)"])
need("apps/desktop/src-tauri/src/device_keys.rs", [
    "session_refresh_payload", "sign_session_refresh", "refresh-token-sha256", "binding_epoch", "Sha256::digest(refresh_token.as_bytes())",
])
need("apps/desktop/src-tauri/src/main.rs", ["async fn sign_session_refresh", "sign_session_refresh"])
need("apps/desktop/src/main.tsx", [
    "accessTokenBindingEpoch", "accessTokenDeviceId", "'sign_session_refresh'", "deviceSignature", "device_key_status",
])
need("services/api/internal/httpapi/session_device_risk_0126_test.go", [
    "TestSessionDeviceBindingInvalidatesPreBindTokenAndRequiresRefreshProof0126",
    "bound refresh succeeded without device proof",
    "access token minted before device binding survived binding_epoch change",
    "refresh family survived replay compromise",
    "TestSessionRiskUserAgentDriftIsPersistedAndRequiresStepUp0126",
    "TestRefreshProofCanonicalPayloadDoesNotContainRefreshSecret0126",
])
need("scripts/contracts/generate_openapi.py", [
    '"deviceSignature":{"type":"string"', '"deviceId":{"type":"string"', "NeverLauncher Session Device Binding v1",
])

api_migration = ROOT / "services/api/internal/dbmigrate/sql/0015_session_device_risk_0126.sql"
cli_migration = ROOT / "cli/internal/dbmigrate/sql/0015_session_device_risk_0126.sql"
if api_migration.is_file() and cli_migration.is_file() and api_migration.read_bytes() != cli_migration.read_bytes():
    errors.append("0015 migration drift: API и CLI содержат разные SQL")

if errors:
    print("Session <-> Device binding + risk integration gate FAILED:", file=sys.stderr)
    for item in errors:
        print(" - " + item, file=sys.stderr)
    raise SystemExit(1)

print("Session <-> Device binding + risk integration gate OK: binding epochs invalidate stale access tokens, bound refresh requires current device-key proof, and risk actions enforce step-up/reattest/revoke")
