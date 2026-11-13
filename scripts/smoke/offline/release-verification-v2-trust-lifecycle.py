#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 8):
    raise SystemExit(
        f"Release Verification v2: требуется версия не ниже 0.15.8, получено {VERSION}"
    )


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


v2 = read("cli/cmd/launcher/release_verification_v2.go")
require(
    v2,
    [
        "RELEASE_TRUST_POLICY.json",
        "launcher.release.v2",
        "TrustEpoch",
        "verifyReleaseTrustPolicy0158",
        "signReleaseBundleV20158",
        "verifyReleaseSignatureV20158",
        "verify-only",
        "revoked",
        "Откат эпохи доверия",
        "Откат релиза заблокирован",
        "LAUNCHER_RELEASE_TRUST_STATE_FILE",
        "требуется внешняя текущая политика доверия",
        "корневому якорю доверия",
    ],
    "Ядро проверки релиза v2",
)

keyring = read("cli/cmd/launcher/security_keyring.go")
require(
    keyring,
    ["TrustEpoch", "reg.TrustEpoch++", 'Status: "active"'],
    "Реестр жизненного цикла ключей",
)

release = read("cli/cmd/launcher/release_commands.go")
require(
    release,
    [
        "releaseVerificationV2Required0158",
        "verifyReleaseBundleWithTrustState",
        "release-verification-v2-trust-lifecycle-anti-rollback",
        "--trust-state",
    ],
    "Интеграция релиза",
)

build = read("scripts/release/build-release.sh")
require(
    build,
    [
        "LAUNCHER_RELEASE_ROOT_PUBLIC_KEY_FILE",
        "LAUNCHER_RELEASE_TRUST_POLICY_FILE",
        "LAUNCHER_RELEASE_TRUST_STATE_FILE",
        '--trust-policy "${TRUST_POLICY}"',
    ],
    "Скрипт промышленного релиза",
)

bundle_gate = read("scripts/smoke/release-required/release-bundle.sh")
require(
    bundle_gate,
    ["RELEASE_TRUST_POLICY.json", "TRUST_STATE", "--trust-state"],
    "Обязательная проверка комплекта релиза",
)

tests = read("cli/cmd/launcher/release_verification_v2_test.go")
require(
    tests,
    [
        "TestReleaseVerificationV2TrustLifecycleAndAntiRollback",
        "TestReleaseTrustPolicyRejectsTampering",
    ],
    "Тесты проверки релиза v2",
)

subprocess.run(
    [
        "go",
        "test",
        "./cmd/launcher",
        "-run",
        "TestReleaseVerificationV2|TestReleaseTrustPolicy",
        "-count=1",
    ],
    cwd=ROOT / "cli",
    check=True,
)

print(f"Launcher {VERSION}: проверка выпуска v2 и жизненного цикла ключей доверия: OK")
print('Release Verification v2 + trust/key lifecycle gate: OK')
