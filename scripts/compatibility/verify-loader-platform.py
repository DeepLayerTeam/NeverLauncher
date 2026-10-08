#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ALLOWED_LOADERS = {"fabric", "quilt", "forge", "neoforge"}
ALLOWED_OS = {"linux", "windows", "macos"}
ALLOWED_ARCH = {"x86_64", "aarch64"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"загрузчик-платформа: {message}")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"не может чтение {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} должен contain объект")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверять загрузчик пакет нативный материализация для один OS/architecture")
    parser.add_argument("--install", type=Path, required=True)
    parser.add_argument("--certification", type=Path, required=True)
    parser.add_argument("--loader", required=True)
    parser.add_argument("--os", dest="os_name", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    loader = args.loader.strip().lower()
    os_name = args.os_name.strip().lower()
    arch = args.arch.strip().lower()
    if loader not in ALLOWED_LOADERS:
        fail(f"неподдерживаемый загрузчик {loader!r}")
    if os_name not in ALLOWED_OS:
        fail(f"неподдерживаемый OS {os_name!r}")
    if arch not in ALLOWED_ARCH:
        fail(f"неподдерживаемый архитектура {arch!r}")

    install = load(args.install)
    cert = load(args.certification)
    if install.get("status") != "installed-and-verified" or install.get("loader") != loader:
        fail("загрузчик установка свидетельство является не установленный-и-проверен")
    if cert.get("status") != "passed":
        fail("NeverRuntime сертификация сделал не успешно")

    vanilla = install.get("vanilla")
    if not isinstance(vanilla, dict) or vanilla.get("status") != "installed-and-verified":
        fail("встроенный Vanilla материализация свидетельство является отсутствующий")
    internal_os = "osx" if os_name == "macos" else os_name
    targets = vanilla.get("targets")
    if not isinstance(targets, list):
        fail("Vanilla цель свидетельство является отсутствующий")
    expected_target = {"os": internal_os, "arch": arch}
    normalized_targets = [
        {"os": str(row.get("os", "")), "arch": str(row.get("arch", ""))}
        for row in targets if isinstance(row, dict)
    ]
    if normalized_targets != [expected_target]:
        fail(f"материализатор цель несоответствие: получил={normalized_targets!r} ожидаемый={[expected_target]!r}")

    files = vanilla.get("files")
    if not isinstance(files, list):
        fail("Vanilla файл свидетельство является отсутствующий")
    prefix = f"natives/{internal_os}/{arch}/"
    native_rows: list[dict[str, Any]] = []
    for row in files:
        if not isinstance(row, dict) or row.get("kind") != "native":
            continue
        path = str(row.get("path", "")).replace("\\", "/")
        if not path.startswith(prefix):
            fail(f"внешний нативный путь в единый-цель пакет: {path!r}, ожидаемый prefix {prefix!r}")
        sha = str(row.get("sha256", "")).lower()
        if not SHA256_RE.fullmatch(sha):
            fail(f"нативный файл {path!r} имеет недопустимый SHA-256")
        native_rows.append({"path": path, "size": int(row.get("size") or 0), "sha256": sha})
    if not native_rows:
        fail(f"нет материализовать нативный файлы found ниже {prefix}")

    expected_suffix = f"/natives/{internal_os}/{arch}".lower()
    actual_natives = str(cert.get("nativesDirectory") or "").replace("\\", "/").rstrip("/").lower()
    if not actual_natives.endswith(expected_suffix):
        fail(f"NeverRuntime selected nativesDirectory={actual_natives!r}, ожидаемый suffix {expected_suffix!r}")
    if int(cert.get("classpathEntries") or 0) <= 0:
        fail("NeverRuntime путь классов является пустой")

    native_rows.sort(key=lambda row: row["path"])
    identity = hashlib.sha256()
    for row in native_rows:
        identity.update(row["path"].encode("utf-8"))
        identity.update(b"\0")
        identity.update(str(row["size"]).encode("ascii"))
        identity.update(b"\0")
        identity.update(row["sha256"].encode("ascii"))
        identity.update(b"\n")

    payload = {
        "schemaVersion": "1.0",
        "status": "passed",
        "loader": loader,
        "minecraftVersion": str(install.get("minecraftVersion") or ""),
        "resolvedLoaderVersion": str(install.get("loaderVersion") or ""),
        "targetOS": os_name,
        "targetArch": arch,
        "materializerOS": internal_os,
        "materializerTargets": normalized_targets,
        "nativeDirectory": str(cert.get("nativesDirectory") or ""),
        "nativeFileCount": len(native_rows),
        "nativeTreeSha256": identity.hexdigest(),
        "clientMainClass": str(cert.get("mainClass") or ""),
        "classpathEntries": int(cert.get("classpathEntries") or 0),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
