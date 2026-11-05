#!/usr/bin/env python3
"""Требовать живые независимо подписанные свидетельства возможностей безопасности для GA 0.43.1+.

Возможности безопасности не выводятся из платформенных манифестов или общих проверок `security`. Для
каждой обязательной возможности нужны успешный разрешённый сценарий и независимо наблюдаемый отказ.
Подпись Ed25519 одобрения привязывает исходную трассу; трасса — исходный журнал исполнения и
финальные байты пакета. Отсутствующий, неподдерживаемый или пропущенный результат не может стать
сертификатом.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import parsed

# Это доверенные минимальные требования, встроенные в верификатор. Недоверенный каталог
# выпуска или доказательств не вправе их убирать или переименовывать. Песочница оценивается
# на Backend-хосте расширений, а не в процессе Desktop.
SCENARIOS = {
    "securityDeviceTrust": ("deviceEnrollmentAllowed", "staleDeviceEpochDenied"),
    "securityHwidPolicy": ("knownDeviceLoginAllowed", "unapprovedHardwareChangeDenied"),
    "securityNeverGuard": ("protectedGameJoinAllowed", "tamperedGuardJoinDenied"),
    "securityKeyRevocation": ("currentKeyJoinAllowed", "revokedKeyJoinDenied"),
    "securityAccountRecovery": ("newDeviceRecoveryAllowed", "oldRecoveryKeyDenied"),
    "securityNativeSandbox": ("authorizedExtensionBrokerAllowed", "unauthorizedExtensionAccessDenied"),
}
# В 0.43.8 добавлена непрерывная проверка игры; одного стартового билета Guard недостаточно
# для сертификации завершения игры при потере Guard во время работы.
GAMEPLAY_SCENARIOS_0438 = {
    "securityGuardLifetime": (
        "healthyGuardAllowsOngoingGameplay", "lostGuardStopsOngoingGameplay"
    ),
}
# Успешный запуск песочницы не доказывает, что отзыв завершает выполняющееся
# расширение или предотвращает доставку уже выполняемого ответа брокера. Оба
# наблюдения должны происходить из нативного исполнения.
EXTENSION_LIFETIME_SCENARIOS_04312 = {
    "securityNativeRevocation": (
        "authorizedNativeExtensionContinuesRunning", "revokedNativeExtensionTerminated"
    ),
}
CLIENT = (frozenset(SCENARIOS) | frozenset(GAMEPLAY_SCENARIOS_0438)) - {"securityNativeSandbox"}


def scenarios_for_version(version: str) -> dict[str, tuple[str, str]]:
    number, prerelease = parsed(version)
    if prerelease is None and number >= (0, 43, 12):
        return {**SCENARIOS, **GAMEPLAY_SCENARIOS_0438, **EXTENSION_LIFETIME_SCENARIOS_04312}
    if prerelease is None and number >= (0, 43, 8):
        return {**SCENARIOS, **GAMEPLAY_SCENARIOS_0438}
    return SCENARIOS
SCHEMA = "launcher.security.capability.0431.v1"
LOG_SCHEMA = "launcher.security.observation.0431.v1"
SHA = re.compile(r"[a-f0-9]{64}\Z")
EXECUTION = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
MAX_LOG = 32 * 1024 * 1024


def required(version: str) -> bool:
    number, prerelease = parsed(version)
    return prerelease is None and number >= (0, 43, 1)


def checks(version: str) -> tuple[str, ...]:
    return tuple(scenarios_for_version(version)) if required(version) else ()


def blocked(message: str) -> None:
    raise ValueError("Сертификация возможностей защиты GA ЗАБЛОКИРОВАНА: " + message)


def ci_identity(run_id=None, run_attempt=None) -> tuple[str, int]:
    # Нет режима «локальной сертификации» или обхода, предоставленного вызывающей стороной;
    # авторизованный запуск GitHub привязывается к каждому отчёту, одобренному оператором.
    rid = run_id if run_id is not None else os.environ.get("GITHUB_RUN_ID", "")
    attempt = run_attempt if run_attempt is not None else os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if isinstance(attempt, int):
        attempt = str(attempt)
    if not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
        blocked("Требуется актуальное значение GITHUB_RUN_ID")
    if not isinstance(attempt, str) or not RUN_ID.fullmatch(attempt):
        blocked("Требуется актуальное значение GITHUB_RUN_ATTEMPT")
    return rid, int(attempt)


def load_json(path: Path, limit: int = 1024 * 1024) -> dict:
    if (path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit):
        blocked("missing, symlinked or invalid evidence: " + str(path))

    def unique_pairs(pairs):
        doc = {}
        for key, value in pairs:
            if key in doc:
                blocked("duplicate evidence key: " + key)
            doc[key] = value
        return doc

    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeDecodeError) as exc:
        blocked("malformed JSON evidence: " + str(exc))
    if not isinstance(value, dict):
        blocked("Требуется объект свидетельства")
    return value


def timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        blocked("Требуется временная метка наблюдения в UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        blocked("Недопустимая временная метка наблюдения в UTC")


def expected_scope(check: str) -> str:
    return "client" if check in CLIENT else "backend-native-extension"


def verify_trace(
    evidence: Path,
    trace: dict,
    *,
    version: str,
    commit: str,
    target: str,
    check: str,
    binary_sha: str,
    package_sha: str,
    issued_at: datetime,
    expires_at: datetime,
    now: datetime | None = None,
    run_id: str | None = None,
    run_attempt: int | str | None = None,
) -> None:
    scenarios = scenarios_for_version(version)
    if check not in scenarios:
        blocked("unknown security capability: " + check)
    rid, attempt = ci_identity(run_id, run_attempt)
    try:
        osname, arch = target.split("-", 1)
    except ValueError:
        blocked("Недопустимая целевая платформа безопасности")
    if (osname, arch) not in {
        ("windows", "x64"), ("windows", "arm64"),
        ("linux", "x64"), ("linux", "arm64"),
        ("darwin", "x64"), ("darwin", "arm64"),
    }:
        blocked("Неутверждённая целевая платформа безопасности")
    fields = {
        "schemaVersion", "version", "commit", "target", "kind", "status",
        "actualExecution", "simulated", "artifactSha256", "packageSha256",
        "executionId", "runId", "runAttempt", "scope", "observedAtUtc",
        "runtimeLogSha256", "scenarios",
    }
    if set(trace) != fields:
        blocked(target + ": Отсутствуют или присутствуют лишние поля в " + check)
    expected_values = {
        "schemaVersion": SCHEMA, "version": version, "commit": commit,
        "target": target, "kind": check, "status": "passed",
        "actualExecution": True, "simulated": False,
        "artifactSha256": binary_sha, "packageSha256": package_sha,
        "runId": rid, "runAttempt": attempt, "scope": expected_scope(check),
    }
    for key, expected in expected_values.items():
        if type(trace[key]) is not type(expected) or trace[key] != expected:
            blocked(target + ": invalid " + key + " for " + check)
    if not isinstance(trace["executionId"], str) or not EXECUTION.fullmatch(trace["executionId"]):
        blocked(target + ": Недопустимая корреляция выполнения для " + check)
    if not isinstance(trace["runtimeLogSha256"], str) or not SHA.fullmatch(trace["runtimeLogSha256"]):
        blocked(target + ": Недопустимый хеш журнала для " + check)
    observation_time = timestamp(trace["observedAtUtc"])
    current_time = now or datetime.now(timezone.utc)
    # Независимое одобрение оператора должно выдаваться ПОСЛЕ наблюдавшегося исполнения.
    if not observation_time <= issued_at <= current_time <= expires_at or current_time - observation_time > timedelta(hours=24):
        blocked(target + ": stale, future or out-of-approval observation: " + check)
    positive, negative = scenarios[check]
    expected_scenarios = {positive: "allowed", negative: "denied"}
    if trace["scenarios"] != expected_scenarios:
        blocked(target + ": Требуются результаты положительного и отрицательного сценариев: " + check)

    log_dir = evidence / "targets" / target / "security-0431"
    if log_dir.is_symlink() or not log_dir.is_dir() or (log_dir / (check + ".jsonl")).is_symlink():
        blocked(target + ": unsafe security log path: " + check)
    log = log_dir / (check + ".jsonl")
    if not log.is_file() or not 0 < log.stat().st_size <= MAX_LOG:
        blocked(target + ": Журнал нативного наблюдения отсутствует, пуст или слишком велик: " + check)
    import hashlib
    raw_log = log.read_bytes()
    if hashlib.sha256(raw_log).hexdigest() != trace["runtimeLogSha256"]:
        blocked(target + ": altered security observation log: " + check)
    lines = raw_log.splitlines()
    if len(lines) != len(expected_scenarios):
        blocked(target + ": Отсутствуют обязательные или присутствуют лишние нативные наблюдения: " + check)
    found = set()
    for line in lines:
        if not line:
            blocked("blank native observation record")
        def pairs(entries):
            obj = {}
            for key, value in entries:
                if key in obj:
                    blocked("duplicate native observation key")
                obj[key] = value
            return obj
        try:
            event = json.loads(line, object_pairs_hook=pairs)
        except (ValueError, UnicodeDecodeError):
            blocked("malformed native observation event")
        if not isinstance(event, dict) or set(event) != {
            "schemaVersion", "executionId", "runId", "runAttempt", "target",
            "packageSha256", "scenario", "observedDecision", "observedAtUtc",
            "actualExecution", "simulated",
        }:
            blocked("Недопустимые поля нативного события: " + check)
        scenario = event["scenario"]
        if not isinstance(scenario, str) or scenario not in expected_scenarios or scenario in found:
            blocked("duplicate or unrecognized security event: " + check)
        found.add(scenario)
        for field, value in {
            "schemaVersion": LOG_SCHEMA,
            "executionId": trace["executionId"], "runId": rid,
            "runAttempt": attempt, "target": target,
            "packageSha256": package_sha, "observedDecision": expected_scenarios[scenario],
            "observedAtUtc": trace["observedAtUtc"],
            "actualExecution": True, "simulated": False,
        }.items():
            if type(event[field]) is not type(value) or event[field] != value:
                blocked(target + ": native observation disagrees: " + field + "/" + check)
    if found != set(expected_scenarios):
        blocked(target + ": incomplete positive/negative native scenario " + check)


def verify_all(evidence: Path, approval: dict, *, now=None, run_id=None, run_attempt=None) -> None:
    """Останавливать предварительную проверку без подготовленного пакета; полный шлюз отдельно проверяет байты."""
    if not required(approval["version"]):
        return
    current = now or datetime.now(timezone.utc)
    issued_at = timestamp(approval["issuedAtUtc"])
    expires_at = timestamp(approval["expiresAtUtc"])
    if evidence.is_symlink() or (evidence / "targets").is_symlink():
        blocked("Корень свидетельств безопасности или набор целевых платформ не может быть символической ссылкой")
    targets = approval.get("targets")
    if not isinstance(targets, list) or len(targets) != 6:
        blocked("Требуются шесть сертификатов безопасности по платформам")
    expected_targets = {
        "windows-x64", "windows-arm64", "linux-x64", "linux-arm64",
        "darwin-x64", "darwin-arm64",
    }
    if any(not isinstance(row, dict) for row in targets) or {r.get("target") for r in targets} != expected_targets:
        blocked("wrong, duplicate or incomplete platform evidence")
    import hashlib
    mandatory = scenarios_for_version(approval["version"])
    for row in targets:
        target = row["target"]
        hashes = row.get("checks")
        if not isinstance(hashes, dict) or any(check not in hashes for check in mandatory):
            blocked(target + ": Отсутствует обязательное свидетельство возможностей защиты")
        for check in mandatory:
            info = hashes[check]
            if not isinstance(info, dict) or set(info) != {"sha256"} or not isinstance(info["sha256"], str) or not SHA.fullmatch(info["sha256"]):
                blocked(target + ": Отсутствует хеш подписанного свидетельства безопасности: " + check)
            directory = evidence / "targets" / target
            if directory.is_symlink() or not directory.is_dir():
                blocked(target + ": Небезопасный каталог целевой платформы безопасности")
            path = directory / (check + ".json")
            trace = load_json(path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != info["sha256"]:
                blocked(target + ": signed security capability report changed: " + check)
            verify_trace(
                evidence, trace, version=approval["version"], commit=approval["commit"],
                target=target, check=check, binary_sha=row.get("binarySha256"),
                package_sha=row.get("packageSha256"), issued_at=issued_at,
                expires_at=expires_at, now=current, run_id=run_id,
                run_attempt=run_attempt,
            )
