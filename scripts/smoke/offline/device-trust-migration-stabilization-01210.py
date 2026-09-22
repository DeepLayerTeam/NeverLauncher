#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"missing required file: {path}")
    return p.read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [item for item in needles if item not in text]
    if missing:
        raise SystemExit(f"{label} missing: {', '.join(missing)}")


version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
try:
    version_tuple = tuple(int(part) for part in version.split("."))
except ValueError as exc:
    raise SystemExit(f"invalid VERSION: {version}") from exc
if version_tuple < (0, 12, 10):
    raise SystemExit(f"VERSION must be >= 0.12.10, got {version}")

migration_api = read("services/api/internal/dbmigrate/sql/0018_device_trust_stabilization_01210.sql")
migration_cli = read("cli/internal/dbmigrate/sql/0018_device_trust_stabilization_01210.sql")
if migration_api != migration_cli:
    raise SystemExit("0.12.10 API/CLI migration 0018 differs")
require(migration_api, [
    "key-rotate", "key-recover", "device_challenges_purpose_check",
    "trusted_devices_lifecycle_check", "trusted_devices_replacement_shape_check",
    "auth_sessions_device_binding_shape_check", "trusted_devices_id_user_key",
    "auth_sessions_trusted_device_owner_fk", "trusted_devices_replacement_owner_fk",
    "minecraft_sessions_never_session_owner_fk", "minecraft_sessions_device_owner_fk",
    "minecraft_sessions_profile_owner_fk", "legacy-device-revoked",
    "UPDATE minecraft_sessions SET trusted_device_id=NULL",
], "0.12.10 stabilization migration")

repo_devices = read("services/api/internal/repository/devices_0121.go")
repo_postgres = read("services/api/internal/repository/postgres.go")
require(repo_devices, [
    "var replacedBy sql.NullString", "d.ReplacedByDeviceID = replacedBy.String",
    "NULL,NULL,'')`, replacement.ID",
], "nullable replacement repository path")
require(repo_postgres, [
    "func nullText(value string) any", "nullText(item.TrustedDeviceID)",
    "var trustedDeviceID sql.NullString", "item.TrustedDeviceID = trustedDeviceID.String",
], "nullable Minecraft trust snapshot repository path")

upgrade_e2e = read("e2e/scripts/run-device-trust-migration-e2e.sh")
require(upgrade_e2e, [
    "0017_device_key_recovery_rotation_0128", "0018_device_trust_stabilization_01210",
    "0.12.9 schema (0001..0017)", "key-rotate", "key-recover",
    "cross-user auth session/device binding unexpectedly succeeded",
    "cross-user replacement link unexpectedly succeeded",
    "cross-user Minecraft device snapshot unexpectedly succeeded",
    "migration-stabilization.json",
], "0.12.10 PostgreSQL upgrade E2E")

protocol_e2e = read("e2e/scripts/run-device-trust-e2e.sh")
require(protocol_e2e, [
    "migrationStabilization01210:true", "migration-upgrade-e2e.json",
    "run-device-trust-migration-e2e.sh first", "0018_device_trust_stabilization_01210",
], "0.12.10 public protocol evidence")

targets = json.loads(read("device-trust/targets.json"))
if targets.get("productVersion") != version:
    raise SystemExit("Device Trust targets must track canonical VERSION")
protocol_targets = [row for row in targets.get("targets", []) if row.get("kind") == "protocol-e2e"]
if len(protocol_targets) != 1 or "migrationStabilization01210" not in protocol_targets[0].get("requiredChecks", []):
    raise SystemExit("public protocol trust target must require migrationStabilization01210")

matrix = read("scripts/device_trust/matrix.py")
require(matrix, ["migrationStabilization01210", "migration stabilization 0.12.10"], "public trust matrix")

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
workflow = read(".github/workflows/device-trust.yml")
for text, label in [(preflight, "preflight"), (ci, "main CI")]:
    if "device-trust-migration-stabilization-01210.py" not in text:
        raise SystemExit(f"0.12.10 release gate is not wired into {label}")
    if "run-device-trust-migration-e2e.sh" not in text:
        raise SystemExit(f"0.12.10 upgrade E2E is not wired into {label}")
require(workflow, [
    "run-device-trust-migration-e2e.sh", "run-device-trust-e2e.sh",
    "e2e/device-trust-migration-result/", "matrix.py aggregate",
], "public Device Trust workflow")

production_readme = read("deploy/production/README.md")
production_readme_template = read("cli/cmd/neverlauncher/templates/production/README.md")
production_checklist = read("deploy/production/production-checklist.md")
production_checklist_template = read("cli/cmd/neverlauncher/templates/production/production-checklist.md")
if production_readme != production_readme_template or production_checklist != production_checklist_template:
    raise SystemExit("production migration documentation/templates drifted")
require(production_readme, [
    "Upgrade 0.12.9 → 0.12.10", "0018_device_trust_stabilization_01210",
    "nl db migrate apply", "nl db migrate verify", "остановите старые API instance",
], "0.12.10 production upgrade runbook")
require(production_checklist, [
    "upgrade с 0.12.9", "0018_device_trust_stabilization_01210",
    "nl db migrate apply", "nl db migrate verify",
], "0.12.10 production upgrade checklist")

subprocess.run(["bash", "-n", str(ROOT / "e2e/scripts/run-device-trust-migration-e2e.sh")], check=True)
subprocess.run(["bash", "-n", str(ROOT / "e2e/scripts/run-device-trust-e2e.sh")], check=True)
subprocess.run(["go", "test", "-tags", "neverlauncher_nopgx", "./internal/dbmigrate", "./internal/repository", "./internal/httpapi"], cwd=ROOT / "services/api", check=True)
subprocess.run(["go", "test", "./internal/dbmigrate"], cwd=ROOT / "cli", check=True)
subprocess.run([sys.executable, str(ROOT / "scripts/device_trust/matrix.py"), "validate", "--targets", str(ROOT / "device-trust/targets.json")], check=True)
subprocess.run([sys.executable, str(ROOT / "scripts/device_trust/test_matrix.py")], check=True)
print(f"[NeverLauncher] Device Trust migration + stabilization 0.12.10 gate OK ({version})")
