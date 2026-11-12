#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def version_tuple(value: str) -> tuple[int, int, int]:
    core = value.split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) != 3:
        raise SystemExit(f"Некорректное значение VERSION: {value}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"Отсутствует обязательный файл: {path}")
    return p.read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


if version_tuple(VERSION) < (0, 15, 10):
    raise SystemExit(f"VERSION ниже 0.15.10: {VERSION}")

stabilization = read("cli/cmd/launcher/migration_stabilization.go")
trust = read("cli/cmd/launcher/release_verification_v2.go")
updater = read("cli/cmd/launcher/transactional_updater.go")
component = read("cli/cmd/launcher/component_update.go")
main = read("cli/cmd/launcher/main.go")
release = read("cli/cmd/launcher/release_commands.go")
tests = read("cli/cmd/launcher/migration_stabilization_test.go")
preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
policy = read("scripts/smoke/offline/repository-policy.py")

require(
    stabilization,
    [
        'releaseTrustStateSchema01510 = "2.1"',
        "withReleaseTrustStateLock01510",
        "migrateComponentUpdateState01510",
        "stabilizeTerminalPayloads01510",
        "migrateUpdaterState01510",
        "runMigrationStabilizationSelfTest01510",
        "Противоречивые манифесты релиза одной версии не были отклонены",
    ],
    "Ядро стабилизации 0.15.10",
)
require(
    trust,
    [
        "HighestReleaseManifestSHA256",
        "StateRevision",
        "same-version release manifest mismatch",
        "releaseTrustStateSchema01510",
    ],
    "Состояние доверия 0.15.10",
)
require(
    updater,
    [
        "automatic updater terminal cleanup",
        "removeUpdaterTerminalPayload01510",
        "componentStateMigration",
        "terminalPayloadsCleaned",
    ],
    "Интеграция обновления 0.15.10",
)
require(
    component,
    [
        "migrateComponentUpdateState01510(root)",
        "persist canonical component update state",
        "removeSafeComponentTreePayload01510",
    ],
    "Интеграция обновления компонентов 0.15.10",
)
require(
    main, ['case "migrate-state":', 'case "stabilization-self-test":'], "Интерфейс командной строки 0.15.10"
)
require(
    release,
    [
        "migrationStabilizationRequired01510",
        "runMigrationStabilizationSelfTest01510",
        "migration stabilization",
    ],
    "Интеграция релиза 0.15.10",
)
require(
    tests,
    [
        "TestMigrationStabilization01510MigratesLegacyComponentState",
        "TestReleaseTrustState01510MigratesAndBindsSameVersionManifest",
        "TestReleaseTrustStateLock01510RejectsConcurrentVerifier",
        "TestTransactionalUpdater01510CleansRollbackPayload",
    ],
    "Регрессионные тесты версии 0.15.10",
)
require(preflight, ["migration-stabilization.py"], "Предварительная проверка релиза")
require(ci, ["migration-stabilization.py"], "CI")
require(
    policy,
    ["0.15.10 Migration + stabilization", "migration-stabilization.py"],
    "Политика хранилища",
)

subprocess.run(
    ["go", "test", "./cmd/launcher", "-run", "01510", "-count=1"],
    cwd=ROOT / "cli",
    check=True,
)
subprocess.run(
    ["go", "run", "./cmd/launcher", "update", "stabilization-self-test"],
    cwd=ROOT / "cli",
    check=True,
    stdout=subprocess.DEVNULL,
)

print(f"[Launcher] Проверка миграции и стабилизации 0.15.10: успешно ({VERSION})")
