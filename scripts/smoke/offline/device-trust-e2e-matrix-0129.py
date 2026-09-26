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
if version_tuple < (0, 12, 9):
    raise SystemExit(f"VERSION must be >= 0.12.9, got {version}")

targets_path = ROOT / "device-trust/targets.json"
targets = json.loads(read("device-trust/targets.json"))
if targets.get("productVersion") != version or targets.get("schemaVersion") != "1.0":
    raise SystemExit("Device Trust target document version/schema mismatch")
rows = targets.get("targets")
if not isinstance(rows, list) or len(rows) != 4:
    raise SystemExit("public Device Trust matrix must define exactly four required Device Trust targets")
if any(row.get("required") is not True for row in rows):
    raise SystemExit("every Device Trust target must be required")
if any("status" in row or "passed" in row for row in rows):
    raise SystemExit("Device Trust targets must not contain editable pass/fail state")
expected = {
    "postgres-protocol-linux-x64": ("protocol-e2e", "linux"),
    "native-linux": ("native-tests", "linux"),
    "native-windows": ("native-tests", "windows"),
    "native-macos": ("native-tests", "macos"),
}
actual = {str(row.get("id")): (row.get("kind"), row.get("os")) for row in rows}
if actual != expected:
    raise SystemExit(f"unexpected public Device Trust targets: {actual!r}")

matrix = read("scripts/device_trust/matrix.py")
require(matrix, [
    "verify_result", "missing required device trust result", "evidenceSha256", "evidence SHA-256 mismatch",
    'claims.get("repository") != "postgresql"', 'vendorHardwareProvenance',
    "headless-ci-does-not-prove-os-secure-storage-runtime", "exact commit/run ID", "safe-basename",
], "public Device Trust matrix aggregator")

protocol = read("e2e/scripts/run-device-trust-e2e.sh")
require(protocol, [
    "docker-compose.federation-e2e.yml", "db migrate apply", "db migrate verify",
    "/api/v1/auth/devices/register/begin", "/api/v1/auth/devices/register/complete",
    "/api/v1/auth/refresh", "NeverLauncher Session Device Binding v1",
    "/api/v1/auth/devices/key-rotation/begin", "oldSignature", "newSignature",
    "/api/v1/server-bridge/validate-join", "old-key-tombstone.json",
    "/api/v1/auth/sessions", "riskAction", "/attest/begin", "/attest/complete",
    "not-remotely-verified", "/api/v1/auth/devices/key-recovery/begin",
    "/api/v1/auth/passkeys/register/begin", "/api/v1/auth/passkeys/step-up/begin",
    "recoveryPhishingResistantEndToEnd:true", "replacement_reason='recover'",
    "/revoke", "psql", "openssl genpkey", "secret material leaked into public evidence",
    'claims:{repository:"postgresql",vendorHardwareProvenance:"not-verified",privateKeyServerExposed:false',
    'printf \'%s\\n\' "$payload"',
    'POST ${url#${API}} failed: HTTP $code',
], "PostgreSQL Device Trust E2E")

crypto = read("e2e/scripts/device-trust-crypto.py")
require(crypto, ["Ed25519", "p256", "der_ecdsa_to_p1363", '"openssl", "pkeyutl"', '"openssl", "dgst"'], "E2E crypto helper")
crypto_tests = read("e2e/scripts/test_device_trust_crypto.py")
require(crypto_tests, ["test_ed25519_public_and_signature_are_backend_wire_format", "test_p256_public_and_p1363_signature_verify", "p1363_to_der"], "E2E crypto helper tests")
webauthn = read("e2e/scripts/webauthn-test-authenticator.py")
require(webauthn, ["webauthn.create", "webauthn.get", "registration_auth_data", "assertion_auth_data", '"openssl", "dgst", "-sha256", "-sign"'], "E2E WebAuthn authenticator")
webauthn_tests = read("e2e/scripts/test_webauthn_test_authenticator.py")
require(webauthn_tests, ["test_registration_and_signed_assertion", "Verified OK"], "E2E WebAuthn authenticator tests")

native_result = read("e2e/scripts/write-device-trust-native-result.py")
require(native_result, [
    "hardware_generation_labels_are_scoped_and_rotate",
    "replacement_payload_is_canonical_and_user_scoped",
    "refresh_payload_binds_session_device_epoch_and_token_hash_without_token_disclosure",
    "attestation_payload_is_hardware_only_and_identity_bound",
    "headless-ci-does-not-prove-os-secure-storage-runtime", "hashlib.sha256",
], "native Device Trust result writer")

workflow = read(".github/workflows/device-trust.yml")
require(workflow, [
    "matrix.py plan", "runs-on: ${{ matrix.runner }}", "run-device-trust-e2e.sh",
    "cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml device_keys::tests",
    "write-device-trust-native-result.py", "actions/upload-artifact@v4",
    "actions/download-artifact@v4", "matrix.py aggregate", "GITHUB_SHA", "GITHUB_RUN_ID",
    "GITHUB_STEP_SUMMARY",
], "public Device Trust workflow")

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "device-trust-e2e-matrix-0129.py" not in ci or "device-trust-e2e-matrix-0129.py" not in preflight:
    raise SystemExit("0.12.9 release gate is not wired into CI/preflight")
if "run-device-trust-e2e.sh" not in ci:
    raise SystemExit("main CI production E2E does not execute Device Trust PostgreSQL lifecycle")
if "RUN_DEVICE_TRUST_E2E" not in preflight:
    raise SystemExit("strict preflight does not expose Device Trust E2E execution")

subprocess.run(["bash", "-n", str(ROOT / "e2e/scripts/run-device-trust-e2e.sh")], check=True)
subprocess.run([sys.executable, str(ROOT / "e2e/scripts/test_device_trust_crypto.py")], check=True)
subprocess.run([sys.executable, str(ROOT / "e2e/scripts/test_webauthn_test_authenticator.py")], check=True)
subprocess.run([sys.executable, str(ROOT / "scripts/device_trust/matrix.py"), "validate", "--targets", str(targets_path)], check=True)
subprocess.run([sys.executable, str(ROOT / "scripts/device_trust/test_matrix.py")], check=True)
print(f"[NeverLauncher] Device Trust E2E + public trust matrix 0.12.9+ gate OK ({version})")
