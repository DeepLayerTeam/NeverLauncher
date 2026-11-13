#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
errors: list[str] = []


def need(rel: str, needles: list[str]) -> None:
    path = ROOT / rel
    if not resource_exists(ROOT, rel):
        errors.append(f'{rel}: файл отсутствует')
        return
    text = resource_read_text(ROOT, rel)
    for needle in needles:
        if needle not in text:
            errors.append(f'{rel}: отсутствует {needle!r}')


need('services/api/internal/httpapi/routes_auth.go', [
    '/api/v1/auth/devices/{deviceId}/attest/begin',
    '/api/v1/auth/devices/{deviceId}/attest/complete',
])
need('services/api/internal/httpapi/device_attestation.go', [
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
    'canonicalDeviceAttestationTime0124',
    'Truncate(time.Microsecond)',
    'now := canonicalDeviceAttestationTime0124(time.Now())',
    'challengeExpires := canonicalDeviceAttestationTime0124(now.Add(deviceAttestationChallengeTTL0124))',
    'validUntil := canonicalDeviceAttestationTime0124(now.Add(deviceAttestationValidity0124))',
])
need('services/api/internal/repository/devices.go', [
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
    'а не происхождение из TPM/Secure',
])
need('apps/desktop/src-tauri/src/device_keys.rs', [
    'validate_device_attestation_payload',
    'pub fn attest_device_payload',
    'Для аттестации устройства требуется аппаратно привязанный ключ P-256',
    'validate_hardware_record(&record)',
    'Ошибка: аппаратная подпись аттестации устройства',
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
    '"attest_device_payload",',
    'hardwareProvenance !== "not-remotely-verified"',
    'происхождение ключа в TPM или Secure Enclave производителем не подтверждено',
])
need('services/api/internal/httpapi/device_attestation_test.go', [
    'TestDeviceChallengeResponseAttestation0124',
    'Принято повторное использование аттестации',
    'Принята неверная подпись аттестации',
    'Непривязанная сессия получила запрос аттестации',
    'TestDeviceChallengeResponseAttestationRejectsSoftwareKey0124',
    'TestDeviceAttestationPayloadStableAcrossPostgresTimestampPrecision0124',
])
need('services/api/internal/dbmigrate/sql/0014_challenge_response_attestation.sql', [
    "assurance IN ('proof-of-possession','challenge-response-attested')",
    "attestation_state IN ('unattested','verified','revoked')",
    "purpose IN ('register','session-bind','attest')",
])

api = ROOT / 'services/api/internal/dbmigrate/sql/0014_challenge_response_attestation.sql'
cli = 'cli/internal/dbmigrate/sql/0014_challenge_response_attestation.sql'
if not api.is_file() or not resource_exists(ROOT, cli) or api.read_bytes() != resource_read_bytes(ROOT, cli):
    errors.append('SQL-миграция 0014 различается в каталогах API и CLI')

native = (ROOT / 'apps/desktop/src-tauri/src/device_keys.rs').read_text(encoding='utf-8')
start = native.find('pub fn attest_device_payload')
end = native.find('fn validate_device_replacement_payload', start)
if end < 0:
    end = native.find('pub fn bind_device_key', start)
attest = native[start:end]
if 'validate_software_record' in attest or 'new_software_record' in attest or 'try_new_hardware_record' in attest:
    errors.append('в нативном модуле подписи аттестации обнаружен резервный путь через программную реализацию или создание ключа')

if errors:
    print('Проверка аттестации запрос–ответ не пройдена:', file=sys.stderr)
    for item in errors:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)

print('Проверка аттестации запрос–ответ пройдена: сохранено одноразовое подтверждение актуальности аппаратного ключа, привязанное к сессии, без заявлений о подтверждении происхождения производителем')
print('Challenge-response attestation gate OK')
