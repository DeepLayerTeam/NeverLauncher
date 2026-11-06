#!/usr/bin/env python3
"""Шлюз запуска Launcher 0.32.16 с блокировкой при неопределённости.

Запускает настоящие Go-тесты (включая живые PostgreSQL, Redis и S3) и проверяет отдельные
JSON-события Go-тестов. Чистое завершение процесса при пропущенных, отсутствующих или невыполненных
тестах НЕ является сертификацией. Свидетельства локальные и не служат криптографической аттестацией
или разрешением публиковать GA.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import rc_supported, rc_extended
from certification_run import identity

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "services/api"
REQUIRED_ENV = (
    "LAUNCHER_SQLITE_TEST_ROOT",
    "LAUNCHER_PG_TEST_DSN",
    "LAUNCHER_GROWTH_TEST_PG_DSN",
    "LAUNCHER_GROWTH_TEST_REDIS_URL",
    "LAUNCHER_RC_S3_ENDPOINT",
    "LAUNCHER_RC_S3_BUCKET",
    "LAUNCHER_RC_S3_REGION",
    "LAUNCHER_RC_S3_ACCESS_KEY",
    "LAUNCHER_RC_S3_SECRET_KEY",
)


@dataclass(frozen=True)
class Suite:
    name: str
    package: str
    tests: tuple[str, ...]


SUITES = (
    Suite(
        "auth-replay-mfa-and-minecraft",
        "./internal/sqlitecore",
        (
            "TestAuthRotateReplayAndRestart",
            "TestRefreshConcurrentReplayIsFailClosed",
            "TestSQLiteMFAEnrollmentRecoveryAndRevocation",
            "TestMinecraftCascadeRevokeUserAndStaleSession",
            "TestJoinAtomicRaceCrashRestartAndReplay",
            "TestNodeNonceReplaySignatureAndTamper",
            "TestRevokedAuthenticationRejectsPendingTicket",
            "TestReplayNonceRemainsSpentAfterReopen",
        ),
    ),
    Suite(
        "jobs-lease-fencing-and-outbox",
        "./internal/sqlitecore",
        (
            "TestDurableJobIdempotencyConcurrentLeaseAndCrash",
            "TestFencedCommitStaleEpochAfterReacquisition",
            "TestOutboxAtLeastOnceRestartAndIdempotentDelivery",
            "TestFullStateBridgeSignedRuntimeNoRedelivery",
            "TestFullStatePackagesSignaturesCASRestartAndRevocation",
        ),
    ),
    Suite(
        "sqlite-real-crash-and-backup",
        "./internal/sqlitedurable",
        (
            "TestAbruptExitRecovery",
            "TestExclusiveOwner",
            "TestOnlineBackupWALAndVerifiedRestore",
            "TestBackupTamperingAndOfflineLock",
        ),
    ),
    Suite(
        "single-node-coordinator",
        "./internal/sqlitecoord",
        (
            "TestRateLimitAtomicAndRestart",
            "TestLeaseFencingAndRestart",
            "TestSingleOwnerAndChannel",
            "TestLeaseExpiryFencingAndPrune",
            "TestProductionRCConcurrentRateLimitStress",
        ),
    ),
    Suite(
        "postgres-transfer-invariants",
        "./internal/sqlitepg",
        ("TestPGStagingMigration",),
    ),
    Suite(
        "actual-postgres-redis-and-s3",
        "./internal/deployment",
        (
            "TestGrowthLivePostgresRedis03212",
            "TestProductionRCLiveS3Growth",
            "TestGrowthFailsClosedOnMissingPostgres03212",
            "TestExplicitModeRejectsUnsafeCombinations",
        ),
    ),
    Suite(
        "http-security-and-minecraft",
        "./internal/httpapi",
        (
            "TestSecurityRealAuthHTTP02912",
            "TestMinecraftAuth119NeverSessionExchangeJoinAndParentRevoke",
            "TestServerBridgeNodeIdentity0142RejectsSignatureReplayAndStaleTimestamp",
            "TestCanonicalStatusReadyAndMetrics",
        ),
    ),
    Suite(
        "measured-load-safety",
        "./cmd/launcher-capacity-bench",
        (
            "TestMeasuredSuccessAndFailures",
            "TestProductionRCRejectsEveryUnexpectedResponse",
            "TestProductionRCMixedSuccessAndErrorsFails",
        ),
    ),
)

# Версия 0.35.14 выполняет эти дополнительные НАСТОЯЩИЕ тесты Go, прежде чем
# ей позволено повторно использовать историческую сертификацию устойчивости к
# сбоям и нагрузки Redis/S3.
RC_03514_SUITES = (
    Suite(
        "35.14-protected-release-and-operator-journey",
        "./internal/httpapi",
        (
            "TestRollbackOperationIdempotency0217",
            "TestReleaseWorkspaceDraftOwnershipAndResume0218",
            "TestDurablePublishRechecksAuthorizationBeforeCommit0213",
            "TestCanonicalPackageProductUploadValidatePublish",
            "TestSupportReportSubmitRequiresLoginAndConsent03510",
            "TestSupportReportRejectsUnknownFields03510",
            "TestOperatorDiagnosticsDoesNotLeakInfrastructure03510",
            "TestProductionGateFailClosedWithoutTargets03411",
            "TestProductionGateUnknownEvidenceFieldsRejected03411",
        ),
    ),
    Suite(
        "35.14-real-postgres-stable-snapshot",
        "./internal/repository",
        (
            "TestGAStableSnapshotImmutablePostgres0350",
            "TestStableSQLTriggersRejectAllHeadAndManualStatusWrites0341",
        ),
    ),
)


def suites_for_version(version: str) -> tuple[Suite, ...]:
    if not rc_supported(version):
        raise GateError("Неподдерживаемая точная версия RC; автоматический перенос подтверждения GA запрещён")
    return SUITES + (RC_03514_SUITES if rc_extended(version) else ())


class GateError(RuntimeError):
    pass


def validate_events(lines: str, suite: Suite, returncode: int) -> dict:
    expected = set(suite.tests)
    finished: dict[str, str] = {}
    violations: list[str] = []
    for line in lines.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue  # Go может выводить сообщения сборки до событий JSON
        if not isinstance(event, dict):
            continue
        test = event.get("Test")
        action = event.get("Action")
        if test and action in ("pass", "fail", "skip"):
            if action != "pass":
                violations.append(f"{test}:{action}")
            if test in expected:
                if test in finished:
                    violations.append(f"{test}:повторяющийся результат")
                finished[test] = action
        if not test and action == "fail":
            violations.append("package:fail")
    missing = sorted(expected - finished.keys())
    wrong = sorted(k for k, v in finished.items() if v != "pass")
    if returncode != 0 or missing or wrong or violations:
        raise GateError(
            f"{suite.name}: exit={returncode}, отсутствует={missing}, не пройдено={wrong}, проблемы={violations[:16]}"
        )
    return {
        "suite": suite.name,
        "package": suite.package,
        "passed": sorted(expected),
        "count": len(expected),
    }


def validate_preflight(env: dict[str, str]) -> str:
    missing = [k for k in REQUIRED_ENV if not env.get(k)]
    if missing:
        raise GateError("Отсутствуют рабочие зависимости:" + ", ".join(missing))
    if env.get("LAUNCHER_SQLITE_REQUIRE_SUPPORTED_FS") != "1":
        raise GateError("Проверка поддержки файловой системы SQLite обязательна; пропуск запрещён")
    root = Path(env["LAUNCHER_SQLITE_TEST_ROOT"])
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise GateError("Для тестового тома SQLite требуется существующий абсолютный путь к каталогу")
    if root.stat().st_mode & 0o077:
        raise GateError("SQLite test root: требуется приватные права 0700")
    return str(root.resolve())


def run_gate(output: Path, env: dict[str, str]) -> None:
    root = validate_preflight(env)
    canonical = (ROOT / "VERSION").read_text().strip()
    selected = suites_for_version(canonical)
    current_run = identity(canonical, env.get("GITHUB_SHA", ""), env, root=ROOT)
    if rc_extended(canonical) and not env.get("LAUNCHER_TEST_POSTGRES_DSN"):
        raise GateError("Требуется реальный DSN PostgreSQL для сертификации стабильной неизменяемой сборки")
    git_sha = env.get("GITHUB_SHA", "")
    if git_sha:
        git = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
        )
        if git.returncode or git.stdout.strip() != git_sha:
            raise GateError("Данные CI с неожиданной ревизией Git отклонены")
    version = subprocess.run(["go", "version"], cwd=API, capture_output=True, text=True)
    if version.returncode or not re.search(
        r"go1\.(?:2[7-9]|[3-9]\d)\.", version.stdout
    ):
        raise GateError(
            "Требуется реальная среда Go 1.27+ (без подмены зависимостей)"
        )
    env = dict(env)
    env["TMPDIR"] = root
    receipts = []
    for suite in selected:
        pattern = "^(" + "|".join(map(re.escape, suite.tests)) + ")$"
        cmd = [
            "go",
            "test",
            "-json",
            "-race",
            "-count=1",
            "-timeout=12m",
            "-run",
            pattern,
            suite.package,
        ]
        try:
            result = subprocess.run(
                cmd, cwd=API, env=env, capture_output=True, text=True, timeout=900
            )
        except subprocess.TimeoutExpired as exc:
            raise GateError(f"{suite.name}: превышено время ожидания") from exc
        receipts.append(validate_events(result.stdout, suite, result.returncode))
        print(f"{suite.name}: пройдено {receipts[-1]['count']} реальных тестов", flush=True)
    receipt = {
        "format": "launcher-03216-rc-test-evidence-v1",
        "version": canonical,
        "commit": git_sha or None,
        "certificationRun": current_run,
        "sqlite_root": root,
        "toolchain": version.stdout.strip(),
        "suites": receipts,
        "disclaimer": "Тесты обязательны, но не подтверждают высокую доступность на нескольких узлах или полную сертификацию продукта для общего выпуска.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, prefix=".rc-", delete=False
    ) as f:
        staged = Path(f.name)
        os.chmod(staged, 0o600)
        json.dump(receipt, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(staged, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        run_gate(args.output, dict(os.environ))
    except (GateError, OSError, ValueError) as exc:
        print(f"RC BLOCKED: {exc}", file=sys.stderr)
        return 2
    print("Тесты RC пройдены; остальные проверки готовности GA по-прежнему обязательны.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
