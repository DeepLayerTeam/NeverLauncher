#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
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
    'features = ["signing", "encryption", "linux-tpm"]',
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
need('services/api/internal/httpapi/device_trust.go', [
    'case "p256"',
    'ecdsa.Verify',
    'elliptic.Unmarshal(elliptic.P256()',
    'keyBinding',
    'hardwareProvider',
])
need('services/api/internal/httpapi/device_trust_test.go', [
    'TestDeviceTrustHardwareP256RegistrationAndBinding0123',
    'signP256P1363Test0123',
    '"keyBinding":       "hardware"',
    '"assurance"] != "proof-of-possession"',
])
need('services/api/internal/repository/devices.go', [
    'device.KeyAlgorithm != "ed25519" && device.KeyAlgorithm != "p256"',
    'device.KeyBinding != "software" && device.KeyBinding != "hardware"',
    'hardware-bound device keys must use p256',
])
need('services/api/internal/dbmigrate/sql/0013_hardware_bound_identities.sql', [
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

# В этом выпуске бэкенд никогда не должен считать заявленную устройством аппаратную
# привязку удалённой аттестацией или устойчивой к фишингу аутентификацией.
server = (ROOT / 'services/api/internal/httpapi/device_trust.go').read_text(encoding='utf-8')
if 'Assurance:         "hardware"' in server or 'Assurance:         "attested"' in server:
    errors.append('обработчик доверия к устройству: аппаратная привязка без аттестации необоснованно повышает уровень доверия')

migration_api = (ROOT / 'services/api/internal/dbmigrate/sql/0013_hardware_bound_identities.sql').read_bytes()
migration_cli = resource_read_bytes(ROOT, 'cli/internal/dbmigrate/sql/0013_hardware_bound_identities.sql')
if migration_api != migration_cli:
    errors.append('SQL-миграция 0013 различается в каталогах API и CLI')

if errors:
    print('проверка идентичности с аппаратной привязкой НЕ ПРОЙДЕНА:', file=sys.stderr)
    for item in errors:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)

print('проверка идентичности с аппаратной привязкой пройдена: подключён путь P-256 через аппаратный модуль защиты ключей, программный резервный механизм указан явно, сама по себе аппаратная привязка не подтверждает происхождение ключа удалённой аттестацией')
print('Hardware-bound identity gate OK')
