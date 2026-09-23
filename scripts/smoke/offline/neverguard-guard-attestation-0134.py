#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label} missing: {', '.join(missing)}")


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"invalid VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 13, 4):
    raise SystemExit(f"NeverGuard Guard Attestation gate requires >=0.13.4, got {version}")

attestation = read("runtime/neverruntime/src/attestation.rs")
require(attestation, [
    'neverguard/windows-guard-attestation/v1',
    'NeverLauncher Guard Attestation Core v1',
    'challenge_sha256',
    'recompute_attestation_sha256',
    'process_policy',
    'evidence_sha256',
    'session_proof',
], "NeverGuard challenge-bound attestation")

guard = read("runtime/neverruntime/src/guard_ipc.rs")
require(guard, [
    'NEVERGUARD_PROTOCOL_VERSION: u32 = 4',
    'send_command_with_payload',
    '"guard-attestation"',
    'GuardAttestationRequest',
    'NeverGuardRemoteAttestation',
    'attestation_session_proof',
    'validate_remote_attestation',
], "NeverGuard authenticated attestation IPC")

desktop = read("apps/desktop/src-tauri/src/main.rs")
require(desktop, [
    'neverguard_guard_attestation',
    '.remote_attestation(',
    'sign_guard_attestation',
    'hardware_bound',
], "Desktop Guard Attestation command")

device_keys = read("apps/desktop/src-tauri/src/device_keys.rs")
require(device_keys, [
    'NeverLauncher Guard Attestation Device Binding v1',
    'purpose=guard-attest',
    'sign_guard_attestation',
    'attestation-sha256=',
    'evidence-sha256=',
], "Hardware device-key Guard binding")

frontend = read("apps/desktop/src/main.tsx")
require(frontend, [
    'createGuardLaunchTicket',
    '/guard-attest/begin',
    'neverguard_guard_attestation',
    '/guard-attest/complete',
    'guardAttestationTicket',
], "Desktop end-to-end Guard verification flow")

backend = read("services/api/internal/httpapi/guard_attestation_0134.go")
require(backend, [
    'guardAttestationChallengeTTL0134',
    'guardLaunchTicketTTL0134',
    'SaveDeviceChallenge',
    'ConsumeDeviceChallenge',
    'validateGuardAttestation0134',
    'verifyDeviceSignature0123',
    'NeverGuard/Desktop release hash is not allowlisted',
    'guard-launch-v1',
    'consumeGuardLaunchTicket0134',
    'isWindowsDevicePlatform0134',
], "Backend Guard verification and anti-replay")

minecraft = read("services/api/internal/httpapi/minecraft_auth_119.go")
require(minecraft, [
    'GuardAttestationTicket',
    'guardAttestationRequiredForSession0134',
    'consumeGuardLaunchTicket0134',
], "Minecraft session Guard-ticket enforcement")

config = read("services/api/internal/config/config.go")
require(config, [
    'GuardReleaseAllowlistJSON',
    'NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON',
    'обязателен в production',
], "Production release allowlist configuration")

backend_test = read("services/api/internal/httpapi/guard_attestation_0134_test.go")
require(backend_test, [
    'TestGuardAttestationBackendVerificationAndOneTimeLaunchTicket0134',
    'guardAttestationTicket',
    'http.StatusCreated',
    'http.StatusPreconditionFailed',
    'TestGuardAttestationRejectsReleaseHashOutsideAllowlist0134',
], "Backend Guard Attestation E2E tests")

integration = read("runtime/neverruntime/tests/neverguard_windows.rs")
require(integration, [
    '.remote_attestation(',
    'NEVERGUARD_REMOTE_ATTESTATION_SCHEMA',
    'attestation.attestation_sha256.len()',
], "Windows NeverGuard remote-attestation integration test")

release = read("scripts/release/build-windows-desktop.ps1")
require(release, [
    'neverGuardProtocolVersion = 4',
    'windows-named-pipe+current-user-system-acl+hmac-sha256-v4',
    'GUARD_RELEASE_ALLOWLIST.json',
    'guardSha256',
    'launcherSha256',
], "Windows release allowlist generation")

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "neverguard-guard-attestation-0134.py" not in ci:
    raise SystemExit("NeverGuard 0.13.4 Guard Attestation gate is not wired into CI")
if "neverguard-guard-attestation-0134.py" not in preflight:
    raise SystemExit("NeverGuard 0.13.4 Guard Attestation gate is not wired into release preflight")
require(ci, [
    'cargo test --manifest-path runtime/neverruntime/Cargo.toml --lib attestation::tests',
    'cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_windows',
], "Windows Guard Attestation native CI")

security = read("SECURITY.md")
require(security, [
    'NeverGuard: Guard Attestation и Backend verification — 0.13.4',
    'single-use',
    'release allowlist',
    'TPM',
], "0.13.4 security boundary")

print(f"[NeverLauncher] NeverGuard Guard Attestation + Backend verification 0.13.4 gate OK: {version}")
