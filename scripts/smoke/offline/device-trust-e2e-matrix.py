#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"Отсутствует обязательный файл: {path}")
    return p.read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [item for item in needles if item not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствуют {', '.join(missing)}")


version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
try:
    version_tuple = tuple(int(part) for part in version.split("."))
except ValueError as exc:
    raise SystemExit(f"Некорректное значение VERSION: {version}") from exc
if version_tuple < (0, 12, 9):
    raise SystemExit(f"Версия: требуется версия не ниже 0.12.9, получено {version}")

targets_path = ROOT / "device-trust/targets.json"
targets = json.loads(read("device-trust/targets.json"))
if targets.get("productVersion") != version or targets.get("schemaVersion") != "1.0":
    raise SystemExit("Несовпадение: «версия и схема документа целевых платформ доверия к устройству»")
rows = targets.get("targets")
if not isinstance(rows, list) or len(rows) < 4:
    raise SystemExit("В публичной матрице доверия устройств отсутствуют обязательные базовые цели")
if any(row.get("required") is not True for row in rows):
    raise SystemExit("Для каждой цели проверки доверия к устройствам требуется «required»")
if any("status" in row or "passed" in row for row in rows):
    raise SystemExit("«целевые платформы доверия к устройствам»: запрещено «содержать редактируемый статус прохождения проверки»")
expected = {
    "postgres-protocol-linux-x64": ("protocol-e2e", "linux"),
    "native-linux-x64": ("native-tests", "linux"),
    "native-linux-arm64": ("native-tests", "linux"),
    "native-windows-x64": ("native-tests", "windows"),
    "native-windows-arm64": ("native-tests", "windows"),
    "native-macos-x64": ("native-tests", "macos"),
    "native-macos-arm64": ("native-tests", "macos"),
}
actual = {str(row.get("id")): (row.get("kind"), row.get("os")) for row in rows}
if len(actual) != len(rows):
    raise SystemExit("Обнаружен дубликат: «идентификатор целевой платформы доверия к устройству»")
for target_id, identity in expected.items():
    if actual.get(target_id) != identity:
        raise SystemExit(f"Отсутствует: «или изменена обязательная базовая платформа проверки доверия к устройству»: {target_id}")
# Новые обязательные платформы также проверяются scripts/device_trust/matrix.py;
# исторический этап не должен отклонять законно расширенный охват защиты.

matrix = read("scripts/device_trust/matrix.py")
require(
    matrix,
    [
        "verify_result",
        "Отсутствует обязательный результат проверки доверия к устройствам",
        "evidenceSha256",
        "контрольная сумма SHA-256 свидетельства {name} не совпадает",
        'claims.get("repository") != "postgresql"',
        "vendorHardwareProvenance",
        "headless-ci-does-not-prove-os-secure-storage-runtime",
        "точного идентификатора коммита и запуска",
        "safe-basename",
    ],
    "агрегатор публичной матрицы доверия устройств",
)

protocol = read("e2e/scripts/run-device-trust-e2e.sh")
require(
    protocol,
    [
        "docker-compose.federation-e2e.yml",
        "db migrate apply",
        "db migrate verify",
        "/api/v1/auth/devices/register/begin",
        "/api/v1/auth/devices/register/complete",
        "/api/v1/auth/refresh",
        "Launcher Session Device Binding v1",
        "/api/v1/auth/devices/key-rotation/begin",
        "oldSignature",
        "newSignature",
        "/api/v1/server-bridge/validate-join",
        "old-key-tombstone.json",
        "/api/v1/auth/sessions",
        "riskAction",
        "/attest/begin",
        "/attest/complete",
        "not-remotely-verified",
        "/api/v1/auth/devices/key-recovery/begin",
        "/api/v1/auth/passkeys/register/begin",
        "/api/v1/auth/passkeys/step-up/begin",
        "recoveryPhishingResistantEndToEnd:true",
        "replacement_reason='recover'",
        "/revoke",
        "psql",
        "openssl genpkey",
        "secret material leaked into public evidence",
        'claims:{repository:"postgresql",vendorHardwareProvenance:"not-verified",privateKeyServerExposed:false',
        "printf '%s\\n' \"$payload\"",
        "POST ${url#${API}} failed: HTTP $code",
        "/guard-attest/begin",
        "/guard-attest/complete",
        "guardAttestationTicket",
        "/api/v1/minecraft/session",
        "minecraftAccessToken",
        "software-device-guard-required.json",
        'GUARD_E2E_VERSION="$VERSION"',
        "guard-policy.override.yml",
        "GUARD_RELEASE_ALLOWLIST_JSON",
        "guard-attestation-e2e.py",
        "bridge-after-recovery.json",
        "launcher_session_or_handoff_missing_or_expired",
        "recovery-replay.json",
        "expect_code 404 \"$code\" 'recovery challenge replay after source-device tombstone'",
        "purpose='key-recover' AND consumed_at IS NOT NULL",
        "активное исходное устройство не найдено",
        "require 0.12.9 -> current shipping migration upgrade evidence",
        '--arg migration "$EXPECTED_CURRENT_MIGRATION"',
        ".upgrade.toMigration==$migration",
        ".upgrade.guardPurposeMigrationSealed==true",
    ],
    "E2E-проверка доверия устройств с PostgreSQL",
)

crypto = read("e2e/scripts/device-trust-crypto.py")
require(
    crypto,
    [
        "Ed25519",
        "p256",
        "der_ecdsa_to_p1363",
    ],
    "криптографическая утилита E2E",
)
for command in ("pkeyutl", "dgst"):
    if not re.search(r'"openssl"\s*,\s*"' + command + r'"', crypto):
        raise SystemExit(f"В криптографической утилите E2E отсутствует реальный вызов openssl {command}")
crypto_tests = read("e2e/scripts/test_device_trust_crypto.py")
require(
    crypto_tests,
    [
        "test_ed25519_public_and_signature_are_backend_wire_format",
        "test_p256_public_and_p1363_signature_verify",
        "p1363_to_der",
    ],
    "тесты криптографической утилиты E2E",
)
webauthn = read("e2e/scripts/webauthn-test-authenticator.py")
require(
    webauthn,
    [
        "webauthn.create",
        "webauthn.get",
        "registration_auth_data",
        "assertion_auth_data",
        '"openssl", "dgst", "-sha256", "-sign"',
    ],
    "аутентификатор WebAuthn для E2E",
)
webauthn_tests = read("e2e/scripts/test_webauthn_test_authenticator.py")
require(
    webauthn_tests,
    ["test_registration_and_signed_assertion", "Verified OK"],
    "тесты аутентификатора WebAuthn для E2E",
)

native_result = read("e2e/scripts/write-device-trust-native-result.py")
require(
    native_result,
    [
        "hardware_generation_labels_are_scoped_and_rotate",
        "replacement_payload_is_canonical_and_user_scoped",
        "refresh_payload_binds_session_device_epoch_and_token_hash_without_token_disclosure",
        "attestation_payload_is_hardware_only_and_identity_bound",
        "headless-ci-does-not-prove-os-secure-storage-runtime",
        "hashlib.sha256",
    ],
    "запись результатов проверки доверия устройств",
)

workflow = read(".github/workflows/device-trust.yml")
require(
    workflow,
    [
        "matrix.py plan",
        "runs-on: ${{ matrix.runner }}",
        "run-device-trust-e2e.sh",
        "cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml device_keys::tests",
        "write-device-trust-native-result.py",
        "actions/upload-artifact@v4",
        "actions/download-artifact@v4",
        "matrix.py aggregate",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_STEP_SUMMARY",
    ],
    "публичный сценарий проверки доверия к устройствам",
)

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if (
    "device-trust-e2e-matrix.py" not in ci
    or "device-trust-e2e-matrix.py" not in preflight
):
    raise SystemExit("Проверка релиза 0.12.9 не подключена к CI или предварительным проверкам")
if "run-device-trust-e2e.sh" not in ci:
    raise SystemExit(
        "Основная производственная E2E-проверка CI не запускает жизненный цикл Device Trust для PostgreSQL"
    )
if "RUN_DEVICE_TRUST_E2E" not in preflight:
    raise SystemExit("Строгая предварительная проверка не запускает сквозные тесты доверия устройств")

subprocess.run(
    ["bash", "-n", str(ROOT / "e2e/scripts/run-device-trust-e2e.sh")], check=True
)
subprocess.run(
    [sys.executable, str(ROOT / "e2e/scripts/test_device_trust_crypto.py")], check=True
)
subprocess.run(
    [sys.executable, str(ROOT / "e2e/scripts/test_webauthn_test_authenticator.py")],
    check=True,
)
subprocess.run(
    [
        sys.executable,
        str(ROOT / "scripts/device_trust/matrix.py"),
        "validate",
        "--targets",
        str(targets_path),
    ],
    check=True,
)
subprocess.run(
    [sys.executable, str(ROOT / "scripts/device_trust/test_matrix.py")], check=True
)
print(f"[Launcher] Доверие к устройствам: сквозные тесты и публичная матрица доверия 0.12.9+ проверены: OK ({version})")
