#!/usr/bin/env python3
"""Предварительная проверка выпуска GA с блокировкой при неопределённости через доверенный оценщик
живого Backend.

Это НЕ сертификат и не замена атомарному шлюзу текущего состояния PostgreSQL. Ничто на данном
CI-исполнителе не может подписывать ValidationEvidence или разрешать публикацию.
"""

import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9_.:@+-]{1,160}$")
STAGES = frozenset(
    (
        "manifest-files",
        "materialization",
        "startup",
        "loader-readiness",
        "authentication",
        "server-readiness",
        "matching-server",
        "gameplay-smoke",
        "update-recovery",
    )
)


class Blocked(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def timestamp(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (TypeError, ValueError, AttributeError):
        raise Blocked("Некорректное значение: «время истечения срока»") from None


def assess(package, validations, report, package_id, version, source_sha, now=None):
    """Проверять независимые представления API. При отсутствии, устаревании или синтетическом покрытии
блокировать выпуск."""
    now = now or datetime.now(timezone.utc)
    require(
        isinstance(package, dict) and package.get("packageId") == package_id,
        "Неверный идентификатор пакета",
    )
    require(package.get("version") == version, "Неверная версия выпуска")
    require(package.get("channel") == "stable", "Релиз не является стабильным")
    require(
        package.get("status") == "integrity-passed",
        "Выпуск не подготовлен с актуальным подтверждением целостности PASS",
    )
    require(isinstance(validations, dict), "Отсутствуют данные для проверки")
    integrity = validations.get("integrity")
    require(
        isinstance(integrity, dict) and integrity.get("result") == "passed",
        "Проверка целостности не пройдена",
    )
    policy = validations.get("effectivePolicy")
    require(
        isinstance(policy, dict)
        and policy.get("source") == "production-runtime-gate-0.34.11"
        and policy.get("requiredLevel") == "trusted-runtime",
        "Не используется доверенный модуль оценки среды выполнения",
    )
    require(
        policy.get("sourceSha") == source_sha, "Исходный коммит отличается от коммита финального выпуска"
    )
    require(
        policy.get("publishEligible") is True,
        "Политика стабильного выпуска Backend запрещает публикацию",
    )
    require(
        isinstance(report, dict)
        and report.get("packageId") == package_id
        and report.get("manualCertificationAllowed") is False,
        "Недопустимый отчёт аудита или ручная сертификация",
    )
    coverage = report.get("coverage")
    require(
        isinstance(coverage, dict) and coverage.get("stablePublishEligible") is True,
        "Текущая проверка аудита не соответствует условиям допуска",
    )
    require(coverage.get("sourceSha") == source_sha, "Коммит источника аудита не совпадает")
    matrix = policy.get("matrixSha256")
    require(
        isinstance(matrix, str)
        and SHA256.fullmatch(matrix)
        and coverage.get("matrixSha256") == matrix,
        "Матрица обязательных целевых платформ изменена или отсутствует",
    )
    count = policy.get("requiredTargets")
    require(
        type(count) is int
        and 0 < count <= 128
        and policy.get("verifiedTargets") == count,
        "Неполное количество обязательных целевых платформ",
    )
    require(
        coverage.get("required") == count and coverage.get("verified") == count,
        "Количество целевых платформ реального запуска не совпадает",
    )
    covered = policy.get("targetCoverage")
    require(
        isinstance(covered, dict)
        and len(covered) == count
        and all(ID.fullmatch(k) and v is True for k, v in covered.items()),
        "Целевая платформа отсутствует или проверка не пройдена",
    )
    require(
        coverage.get("targetCoverage") == covered,
        "Охват целевых платформ в отчёте и проверке не совпадает",
    )
    require(
        policy.get("targetBlockers") == {} and coverage.get("targetBlockers") == {},
        "Остались заблокированные целевые платформы",
    )
    evidence = report.get("evidence")
    require(isinstance(evidence, list), "Отсутствует доверенная история подтверждений")
    accepted = {}
    run_ids = set()
    for item in evidence:
        if (
            not isinstance(item, dict)
            or item.get("status") != "signature-and-execution-verified"
        ):
            continue
        target_id = item.get("targetId")
        if target_id not in covered:
            continue
        run_id = item.get("runId")
        require(
            isinstance(run_id, str) and ID.fullmatch(run_id), "Недопустимый идентификатор доверенного запуска"
        )
        require(
            timestamp(item.get("expiresAt")) > now + timedelta(minutes=15),
            "Срок действия свидетельства истекает во время финального выпуска",
        )
        require(run_id not in run_ids, "Повторное использование аттестации среды выполнения")
        run_ids.add(run_id)
        accepted.setdefault(target_id, []).append(run_id)
    require(set(accepted) == set(covered), "Не для каждой цели есть новый подписанный результат выполнения")
    runs = report.get("runs")
    require(isinstance(runs, list), "Отсутствует журнал выполнения среды")
    by_run = {r.get("runId"): r for r in runs if isinstance(r, dict)}
    for target, ids in accepted.items():
        require(
            any(
                all(
                    isinstance(by_run.get(run), dict)
                    and isinstance(by_run[run].get("stages"), dict)
                    and stage in by_run[run]["stages"]
                    and by_run[run]["stages"][stage].get("status") == "passed"
                    for stage in STAGES
                )
                for run in ids
            ),
            "Отсутствуют этапы среды выполнения для " + target,
        )
    return {
        "schemaVersion": "launcher.ga-runtime-preflight.v1",
        "status": "backend-eligible-not-published",
        "packageId": package_id,
        "productVersion": version,
        "sourceSha": source_sha,
        "matrixSha256": matrix,
        "verifiedTargets": count,
        "note": "Этот снимок только для чтения не разрешает публикацию; PostgreSQL повторно проверит данные при фиксации транзакции.",
    }


def get_json(backend, endpoint, bearer):
    req = Request(
        backend.rstrip("/") + endpoint,
        headers={
            "Authorization": "Bearer " + bearer,
            "Accept": "application/json",
            "Cache-Control": "no-cache",
        },
        method="GET",
    )

    class RejectRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise Blocked(
                "Переадресация Backend отклонена: токен доступа не должен покидать закреплённый адрес"
            )

    opener = build_opener(
        HTTPSHandler(context=ssl.create_default_context()), RejectRedirect()
    )
    with opener.open(req, timeout=30) as response:
        require(response.status == 200, "Backend вернул HTTP-статус, отличный от 200")
        raw = response.read((16 << 20) + 1)
    require(len(raw) <= (16 << 20), "Отчёт Backend превышает допустимый размер")
    data = json.loads(raw)
    require(
        isinstance(data, dict) and isinstance(data.get("data"), dict),
        "Отсутствуют данные Backend",
    )
    return data["data"]


def supported_runtime_release(version: str) -> bool:
    """Доверенный шлюз Runtime обязателен для ВСЕХ выпусков после 0.35.0.

    Исторические фикстуры остаются допустимыми для 0.35.0, но текущий защищённый оценщик обязан
    каждый раз перепроверять *настоящие* подготовленные версию и коммит.
    """
    matched = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
        version,
    )
    return matched is not None and tuple(map(int, matched.groups())) >= (0, 35, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        require(ID.fullmatch(args.package_id), "Недопустимый идентификатор пакета")
        require(SOURCE.fullmatch(args.source_sha), "Недопустимый SHA исходников")
        require(
            supported_runtime_release(args.version),
            "Выпуск создан до внедрения защищённой проверки среды выполнения или имеет недопустимую версию",
        )
        url = urlsplit(args.backend)
        require(
            url.scheme == "https"
            and bool(url.hostname)
            and not url.username
            and not url.password
            and not url.query
            and not url.fragment
            and not url.path.rstrip("/"),
            "Backend должен использовать источник с HTTPS",
        )
        token = os.environ.get("NL_GA_OPERATOR_TOKEN", "").strip()
        require(
            bool(token) and "\n" not in token and "\r" not in token,
            "Отсутствует защищённый токен чтения",
        )
        base = "/api/v1/packages/" + quote(args.package_id, safe="")
        pkg = get_json(args.backend, base, token)
        validations = get_json(args.backend, base + "/validations", token)
        report = get_json(args.backend, base + "/validation-report", token)
        decision = assess(
            pkg, validations, report, args.package_id, args.version, args.source_sha
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            "Предварительная проверка среды выполнения: допускается атомарная проверка Backend (не является сертификацией CI)"
        )
        return 0
    except (Blocked, OSError, ValueError, json.JSONDecodeError) as ex:
        print("Предварительная проверка GA Runtime ЗАБЛОКИРОВАНА: " + str(ex), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
