#!/usr/bin/env python3
"""Запустить поставляемую Rust-диагностику Guard либо объединить независимые нативные отчёты.

Отчёты — *наблюдения*, а не приёмка игровых сеансов или подписанные квитанции GA. В матрице
отсутствующие платформы и непроверенные сенсоры явно остаются BLOCKED.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
SCHEMA = "guard/local-inventory/v1"
MATRIX_SCHEMA = "guard/inventory-matrix/v1"
REQUIRED = {
    "java.execution", "minecraft.loader.metadata", "guard.authenticated-ipc",
    "guard.process-policy", "guard.integrity-evidence", "guard.remote-attestation",
    "guard.release-package", "sensor.windows.in-process", "sensor.jvm-awareness",
    "sensor.continuous", "minecraft.real-join", "minecraft.authorized-javaagent",
}
# Заявленный набор целей выпуска НЕ ограничен машиной разработчика.
TARGETS = (
    ("linux", "x86_64"), ("linux", "aarch64"),
    ("windows", "x86_64"), ("windows", "aarch64"),
    ("macos", "x86_64"), ("macos", "aarch64"),
)
STATUSES = {"PASS", "BLOCKED", "UNSUPPORTED"}


def validate_report(raw: object) -> dict:
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        raise ValueError("Некорректная схема инвентаризации Guard")
    if raw.get("productVersion") != EXPECTED_VERSION:
        raise ValueError(f"Инвентаризация Guard должна использовать версию продукта {EXPECTED_VERSION}")
    target = (raw.get("os"), raw.get("architecture"))
    if target not in TARGETS:
        raise ValueError(f"Неизвестное значение: цель {target}")
    checks = raw.get("checks")
    if not isinstance(checks, list):
        raise ValueError("Отсутствуют проверки инвентаризации Guard")
    by_id = {}
    for item in checks:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("Некорректный формат: проверка Guard")
        if item["id"] in by_id:
            raise ValueError(f"Обнаружен дубликат: проверка Guard: {item['id']}")
        if item.get("status") not in STATUSES or not isinstance(item.get("detail"), str):
            raise ValueError(f"Некорректный формат: «Guard check status»: {item['id']}")
        by_id[item["id"]] = item
    if missing := REQUIRED - by_id.keys():
        raise ValueError(f"Отсутствуют проверки Guard: {sorted(missing)}")
    # Это диагностика до игры: внутрипроцессные датчики ещё не задействованы.
    for sensor in ("sensor.windows.in-process", "sensor.jvm-awareness", "sensor.continuous"):
        required_status = "BLOCKED" if raw["os"] == "windows" else "UNSUPPORTED"
        if by_id[sensor]["status"] != required_status:
            raise ValueError(f"«in-process sensor»: запрещено «claim {by_id[sensor]['status']}:» {sensor}")
    for loader in ("vanilla", "fabric", "quilt", "forge", "neoforge"):
        key = f"loader.runtime.{loader}"
        if key not in by_id or by_id[key]["status"] != "BLOCKED":
            raise ValueError(f"«local inventory»: запрещено «certify» {key}")
    # Опись никогда не запускает игру. Этот инструмент не может сертифицировать
    # настоящий вход, работу загрузчика или разрешённого Java-агента.
    for item_id in ("minecraft.real-join", "minecraft.authorized-javaagent"):
        if by_id[item_id]["status"] != "BLOCKED":
            raise ValueError(f"«local inventory»: запрещено «certify» {item_id}")
    is_blocked = any(c["status"] == "BLOCKED" for c in checks)
    if raw.get("status") != ("BLOCKED" if is_blocked else "PASS"):
        raise ValueError("Итоги инвентаризации не соответствуют фактическим проверкам")
    return raw


def run_local(args: argparse.Namespace) -> int:
    runtime = Path(args.runtime).resolve(strict=True)
    guard = Path(args.guard).resolve(strict=True)
    if not runtime.is_file() or not guard.is_file():
        raise ValueError("Необходимы нативные исполняемые файлы Runtime и Guard")
    command = [str(runtime), "guard-inventory", "--guard-executable", str(guard)]
    if args.java:
        command.extend(("--java", args.java))
    if args.game_root or args.minecraft_version:
        if not args.game_root or not args.minecraft_version:
            raise ValueError("Параметры --game-root и --minecraft-version необходимо указывать вместе")
        command.extend(("--game-root", args.game_root, "--minecraft-version", args.minecraft_version))
    # Linux IPC Guard требует принадлежащий процессу каталог Runtime с правами 0700. Изолируйте
    # его для этого вызова и очищайте после остановки процесса Guard.
    with tempfile.TemporaryDirectory(prefix="launcher-inventory-0501-") as private:
        os.chmod(private, 0o700)
        env = os.environ.copy()
        if sys.platform.startswith("linux"):
            env["XDG_RUNTIME_DIR"] = private
        proc = subprocess.run(command, env=env, text=True, capture_output=True, timeout=50, check=False)
    if proc.returncode:
        raise ValueError(f"Нативная инвентаризация Guard завершилась с кодом {proc.returncode}: {proc.stderr[-2000:]}")
    report = validate_report(json.loads(proc.stdout))
    if (report["os"], report["architecture"]) != (
        {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(sys.platform, sys.platform),
        {"AMD64": "x86_64", "ARM64": "aarch64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(platform.machine(), platform.machine()),
    ):
        raise ValueError("Целевая платформа нативного Guard не совпадает с выполняющей машиной")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Операция без разрушений и атомарна; отчёт не содержит токенов и закрытых ключей.
    scratch = output.with_name(output.name + f".{os.getpid()}.tmp")
    try:
        with scratch.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(scratch, output)
    finally:
        scratch.unlink(missing_ok=True)
    print(f"{report['os']}/{report['architecture']}: {report['status']} (инвентаризация нативной ОС; НЕ сертификация игры или GA)")
    return 0


def merge(args: argparse.Namespace) -> int:
    reports = {}
    for filename in args.reports:
        doc = validate_report(json.loads(Path(filename).read_text(encoding="utf-8")))
        key = (doc["os"], doc["architecture"])
        if key in reports:
            raise ValueError(f"Обнаружен дубликат: «native target report» {key}")
        reports[key] = doc
    if len({doc["productVersion"] for doc in reports.values()}) > 1:
        raise ValueError("В одной матрице инвентаризации Guard указаны разные версии продукта")
    rows = []
    for os_name, arch in TARGETS:
        item = reports.get((os_name, arch))
        rows.append({
            "os": os_name, "architecture": arch,
            "status": item["status"] if item else "BLOCKED",
            "reason": "native local probe; not a game certification" if item else "Отсутствует отчёт нативного исполняющего компонента",
            "javaMajor": item.get("javaMajor") if item else None,
            "minecraftVersion": item.get("minecraftVersion") if item else None,
            "loader": item.get("loader") if item else None,
            "checks": item["checks"] if item else [],
        })
    result = {
        "schema": MATRIX_SCHEMA,
        "productVersion": next(iter(reports.values()))["productVersion"] if reports else None,
        "status": "BLOCKED" if any(row["status"] != "PASS" for row in rows) else "PASS",
        "certified": False,
        "note": "Untrusted local observations only; real game, signed packages and independent review remain mandatory",
        "targets": rows,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Матрица: {result['status']}; отчётов ОС/ЦП: {len(reports)}/{len(TARGETS)}; сертифицировано=false")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    local = sub.add_parser("local", help="Выполнить настоящую нативную проверку IPC Guard")
    local.add_argument("--runtime", required=True)
    local.add_argument("--guard", required=True)
    local.add_argument("--java")
    local.add_argument("--game-root")
    local.add_argument("--minecraft-version")
    local.add_argument("--output", required=True)
    local.set_defaults(handler=run_local)
    matrix = sub.add_parser("matrix", help="Объединить нативные отчёты без выдумывания отсутствующих платформ")
    matrix.add_argument("--output", required=True)
    matrix.add_argument("reports", nargs="*")
    matrix.set_defaults(handler=merge)
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"Инвентаризация Guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
