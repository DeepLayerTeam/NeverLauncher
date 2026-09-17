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
    'POST /api/v1/auth/devices/{deviceId}/revoke',
    'POST /api/v1/auth/devices/revoke-others',
    'POST /api/v1/admin/auth/devices/{deviceId}/revoke',
    'requireFreshAuth117("users:manage", "phishing-resistant", 5*time.Minute',
])
need('services/api/internal/httpapi/device_management_0125.go', [
    'authDeviceRevoke0125',
    'authDeviceRevokeOthers0125',
    'currentTrustedDeviceID0125',
    'RevokeOtherTrustedDevices',
    'revokedRefreshFamilies',
    'revokedMinecraftSessions',
    'invalidatedChallenges',
    'invalidatedBridgeJoins',
    'reEnrollmentRequiresNewKey',
    'ServerBridge.invalidateSession',
    'revocationPermanent',
])
need('services/api/internal/repository/devices_0121.go', [
    'func (r *SQLRepository) RevokeTrustedDevice',
    'func (r *SQLRepository) RevokeOtherTrustedDevices',
    "assurance='proof-of-possession'",
    "attestation_state='revoked'",
    'UPDATE device_challenges SET consumed_at=',
    'UPDATE auth_sessions SET status=\'revoked\'',
    'UPDATE refresh_token_families SET status=\'revoked\'',
    'UPDATE refresh_tokens SET status=\'revoked\'',
    'UPDATE minecraft_sessions SET status=\'revoked\'',
    'FOR UPDATE',
    'CascadeHandled: true',
])
need('services/api/internal/httpapi/device_management_0125_test.go', [
    'TestDeviceManagementRevokeOthersAndChallengeInvalidation0125',
    'TestDeviceManagementSelfRevokeIsPermanentAndIdempotent0125',
    'revoke-others',
    'pre-revocation challenge completed after revoke',
    'revoked device key was re-enrolled',
    'repeat revoke is not idempotent',
    'self-revoked session remained active',
])
need('apps/desktop/src/main.tsx', [
    'loadManagedDevices',
    'renameManagedDevice',
    'revokeManagedDevice',
    'revokeOtherManagedDevices',
    "callTauri<void>('delete_device_key'",
    "callTauri<void>('delete_auth_session'",
    '/auth/devices/revoke-others',
    '/revoke`, authSession.accessToken',
    'revoke необратим для старого ключа',
])
need('apps/admin/src/main.tsx', [
    "{ id: 'devices', title: 'Устройства' }",
    "devices: '/api/v1/admin/auth/devices'",
    'loadTrustedDevices',
    'revokeTrustedDevice',
    '/api/v1/admin/auth/devices/${encodeURIComponent(item.id)}/revoke',
    'fresh phishing-resistant step-up',
])
need('scripts/contracts/generate_openapi.py', [
    'TrustedDeviceRevokeRequest',
    '/api/v1/auth/devices/revoke-others',
    '/api/v1/admin/auth/devices/{deviceId}/revoke',
])

if errors:
    print('Device Management + Revocation gate FAILED:', file=sys.stderr)
    for item in errors:
        print(' - ' + item, file=sys.stderr)
    raise SystemExit(1)

print('Device Management + Revocation gate OK: permanent device tombstones cascade to sessions, refresh families, Minecraft sessions, challenges and ServerBridge joins')
