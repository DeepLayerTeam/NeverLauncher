#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys

ROOT = Path(__file__).resolve().parents[3]

def read(path):
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"missing required file: {path}")
    return p.read_text(encoding="utf-8")

def require(text, needles, label):
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label} missing: {', '.join(missing)}")

version = (ROOT / "VERSION").read_text().strip()
try:
    version_tuple = tuple(int(part) for part in version.split("."))
except ValueError as exc:
    raise SystemExit(f"invalid VERSION: {version}") from exc
if version_tuple < (0, 12, 8):
    raise SystemExit(f"VERSION must be >= 0.12.8, got {version}")

handler = read("services/api/internal/httpapi/device_key_recovery_0128.go")
repo = read("services/api/internal/repository/devices_0121.go")
model = read("services/api/internal/model/model.go")
routes = read("services/api/internal/httpapi/routes_auth.go")
native = read("apps/desktop/src-tauri/src/device_keys.rs")
tauri = read("apps/desktop/src-tauri/src/main.rs")
desktop = read("apps/desktop/src/main.tsx")
migration_api = read("services/api/internal/dbmigrate/sql/0017_device_key_recovery_rotation_0128.sql")
migration_cli = read("cli/internal/dbmigrate/sql/0017_device_key_recovery_rotation_0128.sql")
tests = read("services/api/internal/httpapi/device_key_recovery_0128_test.go")

require(handler, [
    "NeverLauncher Device Key Replacement v1", 'purpose := "key-" + mode',
    "oldSignature", "newSignature", "phishing-resistant", "ConsumeDeviceChallenge",
    "ReplaceTrustedDeviceKey", "oldFingerprintPermanentTombstone",
], "replacement ceremony")
require(routes, ["key-rotation/begin", "key-rotation/complete", "key-recovery/begin", "key-recovery/complete"], "routes")
require(repo, [
    "func (r *SQLRepository) ReplaceTrustedDeviceKey", "BeginTx", "FOR UPDATE",
    "SET CONSTRAINTS ALL DEFERRED", "ON CONFLICT DO NOTHING RETURNING",
    "binding_epoch=GREATEST(binding_epoch,1)+1", "current session changed during replacement",
    "replaced_by_device_id", "refresh_token_families", "minecraft_sessions",
    "trusted-device-key-replaced", "replace trusted device: commit: %w",
], "atomic SQL key replacement")
require(model, ["ReplacedAt", "ReplacedByDeviceID", "ReplacementReason", "DeviceKeyReplacementResult"], "device replacement model")
if migration_api != migration_cli:
    raise SystemExit("API and CLI migration 0017 differ")
require(migration_api, ["replaced_at", "replaced_by_device_id", "replacement_reason", "idx_trusted_devices_replacement"], "migration 0017")
require(native, [
    "hardware_key_label_generation", "stage_device_key_replacement", "sign_staged_device_replacement",
    "sign_current_device_replacement", "commit_staged_device_key", "abort_staged_device_key",
    "random_key_generation", "staged_keyring_entry",
], "native staged-key lifecycle")
require(tauri, [
    "stage_device_key_replacement", "sign_staged_device_replacement", "sign_current_device_replacement",
    "commit_staged_device_key", "abort_staged_device_key",
], "Tauri command boundary")
require(desktop, [
    "replaceDesktopDeviceKey", "passkeyStepUp", "reconcileStagedReplacement",
    "key-rotation/begin", "key-recovery/begin", "stage_device_key_replacement",
    "commit_staged_device_key", "serverCommitted",
], "desktop replacement flow")
require(tests, [
    "TestDeviceKeyRotationRequiresOldAndNewProofAndTombstonesOldIdentity0128",
    "TestDeviceKeyRecoveryRequiresFreshPhishingResistantAuthAndOnlyNewKeyProof0128",
    "TestBoundSessionCannotBypassReplacementViaOrdinaryRegistration0128",
], "0.12.8 regressions")

subprocess.run([
    "go", "test", "-tags", "neverlauncher_nopgx", "./internal/httpapi",
    "-run", "TestDeviceKey(Rotation|Recovery)|TestBoundSessionCannot", "-count=1",
], cwd=ROOT / "services/api", check=True)
subprocess.run(["go", "test", "-tags", "neverlauncher_nopgx", "./internal/dbmigrate"], cwd=ROOT / "services/api", check=True)
subprocess.run(["go", "test", "./internal/dbmigrate"], cwd=ROOT / "cli", check=True)
print("[NeverLauncher] Cross-platform hardening + key recovery/rotation 0.12.8 gate OK")
