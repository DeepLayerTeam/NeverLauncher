#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def require(text: str, path: str, needles: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"[NeverLauncher] Attestation v2 0.18.10 gate: {path} missing: {', '.join(missing)}")

def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"invalid VERSION: {value}")
    return tuple(int(part) for part in match.groups())

version = read("VERSION").strip()
if version_tuple(version) < (0, 18, 10):
    raise SystemExit(f"Attestation v2 gate requires >=0.18.10, got {version}")

runtime = read("runtime/neverruntime/src/windows_attestation_v2.rs")
require(runtime, "runtime/neverruntime/src/windows_attestation_v2.rs", [
    'neverguard/windows-continuous-evidence/v2',
    'neverguard/windows-guard-attestation/v2',
    'collect_windows_continuous_evidence_v2',
    'validate_continuous_evidence_v2',
    'recompute_continuous_evidence_sha256',
    'sensor_heartbeat_count != evidence.guard_heartbeat_count',
    'CONTINUOUS_EVIDENCE_MAX_STALENESS_MS',
    'foreign_executable_transition_count != 0',
    'debug.debugger_present',
    'threads.breakaway_allowed',
    'build_windows_attestation_v2',
])

desktop_native = read("apps/desktop/src-tauri/src/main.rs")
require(desktop_native, "apps/desktop/src-tauri/src/main.rs", [
    'neverguard_guard_attestation_v2',
    'supervisor.status(&process_id).await',
    'collect_windows_continuous_evidence_v2',
    'build_windows_attestation_v2',
    'sign_guard_attestation_v2',
])

device_keys = read("apps/desktop/src-tauri/src/device_keys.rs")
require(device_keys, "apps/desktop/src-tauri/src/device_keys.rs", [
    'NeverLauncher Guard Attestation Device Binding v2',
    'purpose=guard-attest-v2',
    'continuous-evidence-sha256=',
    'base-attestation-sha256=',
    'runtime-pid=',
    'sign_guard_attestation_v2',
])

backend = read("services/api/internal/httpapi/guard_attestation_v2_01810.go")
require(backend, "services/api/internal/httpapi/guard_attestation_v2_01810.go", [
    'guardAttestationV2Purpose01810',
    'guardContinuousJoinPurpose01810',
    'validateGuardContinuousEvidence01810',
    'recomputeGuardContinuousEvidenceSHA25601810',
    'validateGuardAttestationV201810',
    'guardDeviceSigningPayloadV201810',
    'authGuardAttestationV2Begin01810',
    'authGuardAttestationV2Complete01810',
    'consumeGuardContinuousJoinTicket01810',
    'SensorHeartbeatCount != e.GuardHeartbeatCount',
    'guardContinuousMaxStaleness01810',
])

routes = read("services/api/internal/httpapi/routes_auth.go")
require(routes, "services/api/internal/httpapi/routes_auth.go", [
    '/guard-attest-v2/begin', '/guard-attest-v2/complete',
])
bridge = read("services/api/internal/httpapi/server_bridge.go")
require(bridge, "services/api/internal/httpapi/server_bridge.go", [
    'ContinuousGuardTicket',
    'continuousGuardRequiredForJoin01810',
    'consumeGuardContinuousJoinTicket01810',
    'validateContinuousGuardTicketForMinecraftSession01810',
])
require(backend, "services/api/internal/httpapi/guard_attestation_v2_01810.go", [
    '"guardSha256"', '"launcherSha256"', 'validateContinuousGuardTicketForMinecraftSession01810',
])

frontend = read("apps/desktop/src/main.tsx")
require(frontend, "apps/desktop/src/main.tsx", [
    'createContinuousGuardTicket',
    "'neverguard_guard_attestation_v2'",
    '/guard-attest-v2/begin',
    '/guard-attest-v2/complete',
    "stop_runtime_process",
    'createServerJoinAfterLaunch',
    'continuousGuardTicket',
    'ServerBridge join после Attestation v2 не подтверждён',
])

migration_api = read("services/api/internal/dbmigrate/sql/0032_guard_attestation_v2_01810.sql")
migration_cli = read("cli/internal/dbmigrate/sql/0032_guard_attestation_v2_01810.sql")
if migration_api != migration_cli:
    raise SystemExit("[NeverLauncher] Attestation v2 0.18.10 gate: API/CLI migration 0032 differs")
require(migration_api, "0032_guard_attestation_v2_01810.sql", [
    'guard-attest-v2', 'guard-continuous-join-v2', 'guard-attest-v1', 'guard-launch-v1',
])

tests = read("services/api/internal/httpapi/guard_attestation_v2_01810_test.go")
require(tests, "guard_attestation_v2_01810_test.go", [
    'TestGuardAttestationV2ValidatesFreshContinuousEvidence01810',
    'TestGuardAttestationV2RejectsStaleAndDivergedContinuousEvidence01810',
    'TestGuardAttestationV2EndpointIssuesOneTimeContinuousTicket01810',
    'replayed Continuous Guard ticket was accepted',
])

openapi_generator = read("scripts/contracts/generate_openapi.py")
require(openapi_generator, "scripts/contracts/generate_openapi.py", [
    '/guard-attest-v2/begin', '/guard-attest-v2/complete', 'GuardAttestationV2CompleteRequest', 'continuousGuardTicket',
])

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
require(ci, ".github/workflows/ci.yml", [
    'neverguard-attestation-v2-01810.py',
    'TestGuardAttestationV2',
    'windows_attestation_v2::tests',
])
if "neverguard-attestation-v2-01810.py" not in preflight:
    raise SystemExit("[NeverLauncher] Attestation v2 0.18.10 gate: release preflight wiring missing")

for rel, text in [
    ("runtime/neverruntime/src/windows_attestation_v2.rs", runtime),
    ("services/api/internal/httpapi/guard_attestation_v2_01810.go", backend),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(f"[NeverLauncher] Attestation v2 0.18.10 gate: placeholder {placeholder!r} in {rel}")

print(f"[NeverLauncher] Guard Attestation v2 + continuous Windows evidence 0.18.10 gate: OK ({version})")
