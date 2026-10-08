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
        raise SystemExit(f"invalid VERSION: {value}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise SystemExit(f"missing required file: {path}")
    return p.read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


if version_tuple(VERSION) < (0, 15, 10):
    raise SystemExit(f"VERSION is older than 0.15.10: {VERSION}")

stabilization = read("cli/cmd/neverlauncher/migration_stabilization_01510.go")
trust = read("cli/cmd/neverlauncher/release_verification_v2.go")
updater = read("cli/cmd/neverlauncher/transactional_updater.go")
component = read("cli/cmd/neverlauncher/component_update.go")
main = read("cli/cmd/neverlauncher/main.go")
release = read("cli/cmd/neverlauncher/release_commands.go")
tests = read("cli/cmd/neverlauncher/migration_stabilization_01510_test.go")
preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
policy = read("scripts/smoke/offline/repository-policy.py")

require(stabilization, [
    "releaseTrustStateSchema01510 = \"2.1\"",
    "withReleaseTrustStateLock01510",
    "migrateComponentUpdateState01510",
    "stabilizeTerminalPayloads01510",
    "migrateUpdaterState01510",
    "runMigrationStabilizationSelfTest01510",
    "same-version release manifest equivocation was not rejected",
], "0.15.10 stabilization core")
require(trust, [
    "HighestReleaseManifestSHA256",
    "StateRevision",
    "same-version release manifest mismatch",
    "releaseTrustStateSchema01510",
], "0.15.10 trust state")
require(updater, [
    "automatic updater terminal cleanup",
    "removeUpdaterTerminalPayload01510",
    "componentStateMigration",
    "terminalPayloadsCleaned",
], "0.15.10 updater integration")
require(component, [
    "migrateComponentUpdateState01510(root)",
    "persist canonical component update state",
    "removeSafeComponentTreePayload01510",
], "0.15.10 component update integration")
require(main, ['case "migrate-state":', 'case "stabilization-self-test":'], "0.15.10 CLI")
require(release, [
    "migrationStabilizationRequired01510",
    "runMigrationStabilizationSelfTest01510",
    "migration stabilization",
], "0.15.10 release integration")
require(tests, [
    "TestMigrationStabilization01510MigratesLegacyComponentState",
    "TestReleaseTrustState01510MigratesAndBindsSameVersionManifest",
    "TestReleaseTrustStateLock01510RejectsConcurrentVerifier",
    "TestTransactionalUpdater01510CleansRollbackPayload",
], "0.15.10 regression tests")
require(preflight, ["migration-stabilization-01510.py"], "release preflight")
require(ci, ["migration-stabilization-01510.py"], "CI")
require(policy, ["0.15.10 Migration + stabilization", "migration-stabilization-01510.py"], "repository policy")

subprocess.run(["go", "test", "./cmd/neverlauncher", "-run", "01510", "-count=1"], cwd=ROOT / "cli", check=True)
subprocess.run(["go", "run", "./cmd/neverlauncher", "update", "stabilization-self-test"], cwd=ROOT / "cli", check=True, stdout=subprocess.DEVNULL)

print(f"[NeverLauncher] Migration + stabilization 0.15.10 gate: OK ({VERSION})")
