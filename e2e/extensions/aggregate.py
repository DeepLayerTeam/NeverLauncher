#!/usr/bin/env python3
"""Отклоняет неполные, неправильно размеченные или устаревшие свидетельства E2E-проверок расширений по платформам."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

TARGETS = (
    "linux-x64",
    "linux-arm64",
    "windows-x64",
    "windows-arm64",
    "macos-x64",
    "macos-arm64",
)
CASES = ("java-host", "java-runtime", "java-lifecycle", "gravit-port")


def validate(folder, source_commit, version, run_id, run_attempt):
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", source_commit):
        raise ValueError("Некорректный коммит исходного кода")
    if not version or not run_id or not run_attempt:
        raise ValueError("Версия, идентификатор запуска CI и номер попытки обязательны")
    folder = Path(folder)
    present = {p.stem for p in folder.glob("*.json")}
    # Итоговый сертификат скачивается Actions в тот же каталог. Не считайте его
    # седьмой платформой; отклоняйте любой другой неожиданный JSON.
    present.discard("extension-acceptance-certificate")
    if present != set(TARGETS):
        raise ValueError(
            f"Отсутствующие и неожиданные платформы в свидетельствах: {sorted(set(TARGETS) - present)} / {sorted(present - set(TARGETS))}"
        )
    result = {}
    for name in TARGETS:
        report = json.loads((folder / f"{name}.json").read_text())
        if (
            report.get("target") != name
            or report.get("version") != version
            or report.get("status") != "pass"
            or report.get("sourceCommit") != source_commit
            or report.get("runId") != run_id
            or report.get("runAttempt") != run_attempt
        ):
            raise ValueError(
                f"{name}: неверный статус, версия, коммит источников или идентификатор запуска CI"
            )
        if tuple(map(int, version.split("."))) >= (0, 43, 0):
            audit = report.get("gravitMatrixAudit", {})
            matrix_sha = hashlib.sha256(
                (
                    Path(__file__).resolve().parents[2]
                    / "compatibility/gravit/module-parity-04211.json"
                ).read_bytes()
            ).hexdigest()
            if (
                audit.get("status") != "source-verified-not-equivalent"
                or audit.get("modules") != 19
                or audit.get("sha256") != matrix_sha
            ):
                raise ValueError(f"{name}: отсутствует исполняемая проверка 19 модулей Gravit")
        checks = report.get("checks")
        if not isinstance(checks, dict) or set(checks) != set(CASES):
            raise ValueError(f"{name}: исполняемые тесты завершены не полностью")
        for case, check in checks.items():
            if check.get("runtime") != "pass" or not re.fullmatch(
                "[0-9a-f]{64}", check.get("jarSha256", "")
            ):
                raise ValueError(f"{name}/{case}: выполнение JVM не подтверждено")
            if case in ("java-host", "gravit-port"):
                signature = check.get("signing", {})
                if (
                    not re.fullmatch("[0-9a-f]{64}", signature.get("sha256", ""))
                    or signature.get("wrongKeyDenied") is not True
                    or signature.get("tamperDenied") is not True
                ):
                    raise ValueError(
                        f"{name}/{case}: отсутствуют негативные тесты подписанного пакета"
                    )
        result[name] = {
            "status": "pass",
            "checks": len(checks),
            "evidenceSha256": hashlib.sha256(
                (folder / f"{name}.json").read_bytes()
            ).hexdigest(),
            "jars": {
                case: check["jarSha256"] for case, check in sorted(checks.items())
            },
        }
    return {
        "schemaVersion": "launcher.extensions.acceptance.v1",
        "version": version,
        "sourceCommit": source_commit,
        "runId": run_id,
        "runAttempt": run_attempt,
        "status": "pass",
        "platforms": result,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence-dir", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-attempt", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = validate(
            args.evidence_dir, args.commit, args.version, args.run_id, args.run_attempt
        )
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"E2E-сертификация расширений заблокирована: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("PASS: шесть результатов проверок реальных JVM и негативные проверки подписанных пакетов")
    return 0


if __name__ == "__main__":
    sys.exit(main())
