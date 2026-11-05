#!/usr/bin/env python3
"""Свидетельство GA с блокировкой при неопределённости: требовать PASS (не SKIP/отсутствие) для
указанных живых Go-тестов.

Читает неизменённый вывод `go test -json`. Это проверка фактических запусков, а не аттестация и не
замена кода завершения тестового раннера.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def verify(path: Path, required: list[str]) -> None:
    if not required:
        raise ValueError("Необходимо указать хотя бы один обязательный тест")
    wanted = set(required)
    if len(wanted) != len(required):
        raise ValueError("«duplicate --require names»: не разрешено")
    observed: dict[str, str] = {}
    packages: dict[str, str] = {}
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError("go test JSON line: требуется «object»")
        action = obj.get("Action")
        test = obj.get("Test")
        pkg = obj.get("Package")
        if not isinstance(action, str) or not isinstance(pkg, str):
            raise ValueError("Некорректное значение: «or truncated Go test event»")
        count += 1
        if action in {"fail", "skip", "pass"}:
            if isinstance(test, str) and test in wanted:
                # Отказ или пропуск окончателен, даже если другой пакет с тем же именем или
                # поддельный последующий 'pass' появляется в потоке.
                previous = observed.get(test)
                if previous in {"fail", "skip"}:
                    continue
                observed[test] = action
            if test is None:
                packages[pkg] = action
    if not count:
        raise ValueError("Пустое значение: «Go test evidence»")
    incomplete = sorted(name for name in wanted if observed.get(name) != "pass")
    failed_packages = sorted(pkg for pkg, action in packages.items() if action != "pass")
    if incomplete or failed_packages:
        raise ValueError(f"GA не сертифицирован: тесты без PASS={incomplete}, пакеты с ошибками или пропусками={failed_packages}")
    if not packages or not any(v == "pass" for v in packages.values()):
        raise ValueError("Отсутствует: «successful Go package result»")
    print(f"Подтверждено прохождение обязательных тестов Go: {len(wanted)}; пакетов={len(packages)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--require", action="append", required=True)
    args = ap.parse_args()
    try:
        verify(args.report, args.require)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Доступ запрещён: «GA gate»: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
