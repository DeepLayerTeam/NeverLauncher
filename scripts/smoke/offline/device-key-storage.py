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
    'keyring = "4.2.0"',
    'ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }',
    'zeroize = "1"',
])
need('apps/desktop/src-tauri/src/device_keys.rs', [
    'SigningKey::generate',
    'DEVICE_KEY_SERVICE',
    'keyring::v1::Entry::new',
    'private_seed_hex',
    'seed.zeroize()',
    'secret.zeroize()',
    'private_key_exposed_to_frontend: false',
    'sign_device_payload',
    'bind_device_key',
])
need('apps/desktop/src-tauri/src/main.rs', [
    'ensure_device_key',
    'device_key_status',
    'sign_device_payload',
    'bind_device_key',
    'reset_device_key',
    'delete_device_key',
])
need('apps/desktop/src/main.tsx', [
    'ensureDesktopDeviceTrust',
    '/api/v1/auth/devices/register/begin',
    '/api/v1/auth/devices/register/complete',
    '/verify/begin',
    '/verify/complete',
    "callTauri<DeviceSignatureResult>('sign_device_payload'",
    'privateKeyExposedToFrontend',
])

frontend = (ROOT / 'apps/desktop/src/main.tsx').read_text(encoding='utf-8')
for forbidden in ['privateSeed', 'private_seed', 'privateKey:', 'localStorage.setItem(\'neverlauncher.device']:
    if forbidden in frontend:
        errors.append(f'apps/desktop/src/main.tsx: private device key material leaked into frontend: {forbidden!r}')

if errors:
    print('Device key / OS secure storage gate FAILED:', file=sys.stderr)
    for item in errors:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)

print('Device key / OS secure storage gate OK: private key stays in Tauri native keyring and proof flow is wired')
