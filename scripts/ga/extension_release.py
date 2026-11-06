#!/usr/bin/env python3
"""Привязать выполненную приёмку расширений для шести целей к *реальным* подписанным файлам .nlext.

Здесь проверяется происхождение запуска CI; подлинность CI-артефакта обеспечивают неизменяемые
артефакты того же запуска GitHub Actions и защищённое задание выпуска. Квитанция не выдаётся за
независимо подписанную оператором аттестацию.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "e2e/extensions"))
from aggregate_04212 import validate, TARGETS  # noqa: E402

PACKAGES = {
    "java-host": ("launcher-example-java-host.nlext", "backend/java-host.jar"),
    "gravit-port": ("launcher-example-gravit-port.nlext", "backend/gravit-port.jar"),
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_file(path: Path) -> Path:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"Файл отсутствует, пуст либо является символической ссылкой: {path}")
    return path


def verify_matrix(path: Path) -> str:
    checked_file(path)
    data = json.loads(path.read_bytes())
    rows = data.get("modules")
    if (
        not isinstance(rows, list)
        or len(rows) != 19
        or {m.get("id") for m in rows if isinstance(m, dict)}
        != {f"M{i:02}" for i in range(1, 20)}
    ):
        raise ValueError("Матрица Gravit должна содержать 19 уникальных именованных результатов модулей")
    for m in rows:
        if m.get("status") not in ("partial", "blocked", "verified") or not m.get(
            "limitations"
        ):
            raise ValueError(
                f"Модуль {m.get('id')}: отсутствует явный результат или описание ограничения"
            )
        if m.get("status") == "verified":
            raise ValueError(
                f"Модуль {m['id']}: для полной эквивалентности требуется отдельное реальное подтверждение для этого модуля"
            )
        if not m.get("sourceRefs") or not m.get("testRefs"):
            raise ValueError(
                f"Модуль {m['id']}: отсутствуют ссылки на исполняемые исходники или тесты"
            )
        for rel in m["sourceRefs"] + m["testRefs"]:
            candidate = ROOT / rel
            if not checked_file(candidate).resolve().is_relative_to(ROOT.resolve()):
                raise ValueError("Ссылка на модуль вышла за пределы корня исходников")
    if (
        next(m for m in rows if m["upstreamModule"] == "UnsafeCommandPack")["status"]
        != "blocked"
    ):
        raise ValueError("UnsafeCommandPack должен оставаться явно заблокированным")
    return sha(path)


def certify(
    *,
    evidence: Path,
    bundle: Path,
    cli: Path,
    publisher_key: Path,
    version: str,
    commit: str,
    run_id: str,
    attempt: str,
    matrix: Path,
) -> dict:
    checked_file(evidence / "extension-acceptance-certificate.json")
    cert_file = evidence / "extension-acceptance-certificate.json"
    cert = json.loads(cert_file.read_text())
    actual = validate(evidence, commit, version, run_id, attempt)
    if cert != actual:
        raise ValueError(
            "Сертификат расширения не соответствует шести исходным результатам запуска JVM"
        )
    if cert.get("schemaVersion") != "launcher.extensions.acceptance.v1":
        raise ValueError("Не поддерживается: «сертификат приёмки расширения»")
    matrix_hash = verify_matrix(matrix)
    checked_file(cli)
    checked_file(publisher_key)
    packages = {}
    for identifier, (filename, inner_jar) in PACKAGES.items():
        package = checked_file(bundle / filename)
        proc = subprocess.run(
            [
                str(cli),
                "extension",
                "verify",
                str(package),
                "--public-key",
                str(publisher_key),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise ValueError(
                f"{identifier}: проверка подписи пакета завершилась ошибкой: {proc.stderr[-600:]}"
            )
        with zipfile.ZipFile(package) as zf:
            if f"payload/{inner_jar}" not in zf.namelist():
                raise ValueError(
                    f"{identifier}: в подписанном пакете отсутствует исполняемый JAR"
                )
            digest = hashlib.sha256(zf.read(f"payload/{inner_jar}")).hexdigest()
            if not re.fullmatch("[0-9a-f]{64}", digest):
                raise ValueError(f"{identifier}: некорректный JAR-файл")
        packages[identifier] = {
            "file": filename,
            "sha256": sha(package),
            "jarSha256": digest,
            "verifiedWithPinnedPublisherKey": True,
        }
    return {
        "schemaVersion": "launcher.extensions.release.v1",
        "status": "passed",
        "version": version,
        "sourceCommit": commit,
        "runId": run_id,
        "runAttempt": attempt,
        "targetCount": len(TARGETS),
        "platformEvidenceSha256": {
            t: actual["platforms"][t]["evidenceSha256"] for t in TARGETS
        },
        "acceptanceSha256": sha(cert_file),
        "publisherKeySha256": sha(publisher_key),
        "gravitMatrixSha256": matrix_hash,
        "modulesAudited": 19,
        "fullGravitBinaryCompatibility": False,
        "signedPackages": packages,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    for option in ("evidence", "bundle", "cli", "publisher-key", "matrix", "output"):
        ap.add_argument("--" + option, type=Path, required=True)
    for option in ("version", "commit", "run-id", "run-attempt"):
        ap.add_argument("--" + option, required=True)
    args = ap.parse_args()
    try:
        result = certify(
            evidence=args.evidence,
            bundle=args.bundle,
            cli=args.cli,
            publisher_key=args.publisher_key,
            version=args.version,
            commit=args.commit,
            run_id=args.run_id,
            attempt=args.run_attempt,
            matrix=args.matrix,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    except (
        ValueError,
        OSError,
        KeyError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
        subprocess.TimeoutExpired,
    ) as err:
        print(f"Производственная сертификация расширения заблокирована: {err}", file=sys.stderr)
        return 2
    print(
        "PASS: шесть результатов E2E для реальных целей И точно соответствующие подписанные пакеты расширений"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
