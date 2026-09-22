#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
errors: list[str] = []


def need(rel: str, needles: list[str]) -> None:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f'{rel}: файл отсутствует')
        return
    text = path.read_text(encoding='utf-8')
    for needle in needles:
        if needle not in text:
            errors.append(f'{rel}: отсутствует {needle!r}')


need('services/api/internal/httpapi/routes_auth.go', [
    '/api/v1/auth/devices/{deviceId}/attest/begin',
    '/api/v1/auth/devices/{deviceId}/attest/complete',
])
need('services/api/internal/httpapi/device_attestation_0124.go', [
    'deviceAttestationChallengeTTL0124 = 2 * time.Minute',
    'deviceAttestationValidity0124     = 12 * time.Hour',
    'Purpose:       "attest"',
    'ConsumeDeviceChallenge',
    'sessionBoundToDevice0124',
    'verifyDeviceSignature0123',
    'AttestTrustedDevice',
    'challenge-response-v1',
    'hardwareProvenance',
    'not-remotely-verified',
    'authorizationElevation',
    'phishingResistantElevation',
])
need('services/api/internal/repository/devices_0121.go', [
    'challenge-response-attested',
    'AttestTrustedDevice',
    'attestation_state',
    'attestation_expires_at',
])
need('services/api/internal/httpapi/auth.go', [
    'DeviceAttestationState',
    'DeviceAttestationMethod',
    'DeviceAttestationExpiresAt',
    'effectiveDeviceAttestation0124',
    'not vendor TPM/Secure Enclave provenance',
])
need('apps/desktop/src-tauri/src/device_keys.rs', [
    'validate_device_attestation_payload',
    'pub fn attest_device_payload',
    'device attestation требует hardware-bound P-256 key',
    'validate_hardware_record(&record)',
    'hardware device attestation signing failed',
    'attestation_payload_is_hardware_only_and_identity_bound',
])
need('apps/desktop/src-tauri/src/main.rs', [
    'async fn attest_device_payload',
    'device_keys::attest_device_payload',
    'sign_device_payload',
    'attest_device_payload',
    'bind_device_key',
])
need('apps/desktop/src/main.tsx', [
    'attestDesktopDeviceKey',
    '/attest/begin',
    '/attest/complete',
    "callTauri<DeviceSignatureResult>('attest_device_payload'",
    "hardwareProvenance !== 'not-remotely-verified'",
    'vendor TPM/Secure Enclave provenance не заявляется',
])
need('services/api/internal/httpapi/device_attestation_0124_test.go', [
    'TestDeviceChallengeResponseAttestation0124',
    'attestation replay accepted',
    'wrong attestation signature accepted',
    'unbound session obtained attestation challenge',
    'TestDeviceChallengeResponseAttestationRejectsSoftwareKey0124',
])
need('services/api/internal/dbmigrate/sql/0014_challenge_response_attestation_0124.sql', [
    "assurance IN ('proof-of-possession','challenge-response-attested')",
    "attestation_state IN ('unattested','verified','revoked')",
    "purpose IN ('register','session-bind','attest')",
])

api = ROOT / 'services/api/internal/dbmigrate/sql/0014_challenge_response_attestation_0124.sql'
cli = ROOT / 'cli/internal/dbmigrate/sql/0014_challenge_response_attestation_0124.sql'
if not api.is_file() or not cli.is_file() or api.read_bytes() != cli.read_bytes():
    errors.append('migration 0014 differs between API and CLI catalogs')

native = (ROOT / 'apps/desktop/src-tauri/src/device_keys.rs').read_text(encoding='utf-8')
start = native.find('pub fn attest_device_payload')
end = native.find('fn validate_device_replacement_payload', start)
if end < 0:
    end = native.find('pub fn bind_device_key', start)
attest = native[start:end]
if 'validate_software_record' in attest or 'new_software_record' in attest or 'try_new_hardware_record' in attest:
    errors.append('native attestation signer contains software/create fallback')

if errors:
    print('Challenge-response attestation gate FAILED:', file=sys.stderr)
    for item in errors:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)

print('Challenge-response attestation gate OK: single-use, session-bound hardware-key freshness proof is persisted without claiming vendor remote provenance')
