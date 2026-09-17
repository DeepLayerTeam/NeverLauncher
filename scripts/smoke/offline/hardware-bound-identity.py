#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
errors: list[str] = []

def need(rel: str, needles: list[str]) -> None:
    text = (ROOT / rel).read_text(encoding='utf-8')
    for needle in needles:
        if needle not in text:
            errors.append(f'{rel}: отсутствует {needle!r}')

need('apps/desktop/src-tauri/Cargo.toml', [
    'hardware-enclave = { version = "=0.2.10"',
    'features = ["signing", "linux-tpm"]',
    'p256 = { version = "0.13", features = ["ecdsa"] }',
])
need('apps/desktop/src-tauri/src/device_keys.rs', [
    'create_signer',
    'AccessPolicy::None',
    'key_algorithm: "p256".into()',
    'key_binding: "hardware".into()',
    'private_seed_hex: String::new()',
    'signer.public_key',
    'signer.sign',
    'P256Signature::from_der',
    'p.contains("tpm")',
    '!p.contains("keyring")',
    '!p.contains("software")',
    'try_new_hardware_record',
    'is_hardware_backend_kind',
    'hardware_backend_classification_is_fail_closed',
])
need('services/api/internal/httpapi/device_trust_0121.go', [
    'case "p256"',
    'ecdsa.Verify',
    'elliptic.Unmarshal(elliptic.P256()',
    'keyBinding',
    'hardwareProvider',
])
need('services/api/internal/httpapi/device_trust_0121_test.go', [
    'TestDeviceTrustHardwareP256RegistrationAndBinding0123',
    'signP256P1363Test0123',
    '"keyBinding":       "hardware"',
    '"assurance"] != "proof-of-possession"',
])
need('services/api/internal/repository/devices_0121.go', [
    'device.KeyAlgorithm != "ed25519" && device.KeyAlgorithm != "p256"',
    'device.KeyBinding != "software" && device.KeyBinding != "hardware"',
    'hardware-bound device keys must use p256',
])
need('services/api/internal/dbmigrate/sql/0013_hardware_bound_identities_0123.sql', [
    "key_algorithm IN ('ed25519','p256')",
    "key_binding IN ('software','hardware')",
    "key_binding='hardware' AND key_algorithm='p256'",
])
need('services/api/internal/httpapi/auth.go', [
    'DeviceKeyBinding',
    'DeviceHardwareProvider',
    'possession/freshness of the registered key, not vendor TPM/Secure Enclave provenance',
])
need('.github/workflows/ci.yml', [
    'scripts/smoke/offline/hardware-bound-identity.py',
    'libtss2-dev',
    'cargo test --manifest-path src-tauri/Cargo.toml',
])

# The backend must never treat a self-reported hardware binding as remote
# attestation or phishing-resistant authentication in this release.
server = (ROOT / 'services/api/internal/httpapi/device_trust_0121.go').read_text(encoding='utf-8')
if 'Assurance:         "hardware"' in server or 'Assurance:         "attested"' in server:
    errors.append('device trust handler: unattested hardware binding повышает assurance')

migration_api = (ROOT / 'services/api/internal/dbmigrate/sql/0013_hardware_bound_identities_0123.sql').read_bytes()
migration_cli = (ROOT / 'cli/internal/dbmigrate/sql/0013_hardware_bound_identities_0123.sql').read_bytes()
if migration_api != migration_cli:
    errors.append('migration 0013 differs between API and CLI catalogs')

if errors:
    print('Hardware-bound identity gate FAILED:', file=sys.stderr)
    for item in errors:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)

print('Hardware-bound identity gate OK: P-256 HSM path is wired, software fallback is explicit, hardware binding alone does not forge remote provenance')
