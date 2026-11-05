#!/usr/bin/env python3
"""Собрать и проверить два детерминированных, независимо встроенных пакета ресурсов CLI.

Канонические источники: services/api/internal/dbmigrate/sql и deploy/production.
`--check` ничего не меняет и блокирует при отсутствии/устаревании ресурсов; `--write` явно
перегенерирует пакеты как изменение исходников до проверки CI/выпуска.
"""
from __future__ import annotations
import argparse
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = (
    (
        "services/api/internal/dbmigrate/sql",
        "cli/internal/dbmigrate/catalog.zip",
        "sql/",
        "*.sql",
    ),
    (
        "deploy/production",
        "cli/cmd/launcher/templates/production.zip",
        "production/",
        "*",
    ),
)
PRODUCTION_FILES = {"docker-compose.yml", "nginx.conf", "env.production.example"}


def bundle(source: Path, prefix: str, pattern: str) -> tuple[bytes, int]:
    files = sorted((p for p in source.glob(pattern) if prefix != "production/" or p.name in PRODUCTION_FILES), key=lambda p: p.name)
    if prefix == "sql/" and len(files) < 100:
        raise ValueError("migration catalog unexpectedly incomplete (fewer than 100 SQL files)")
    if prefix == "production/" and {f.name for f in files} != PRODUCTION_FILES:
        raise ValueError("production template list drift")
    if any(not p.is_file() or p.is_symlink() for p in files):
        raise ValueError("resource bundle contains a symlink or non-file")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            info = zipfile.ZipInfo(prefix + path.name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buffer.getvalue(), len(files)


def verify_or_write(write: bool) -> None:
    for source_rel, target_rel, prefix, pattern in ASSETS:
        data, count = bundle(ROOT / source_rel, prefix, pattern)
        target = ROOT / target_rel
        if write:
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.is_file() or target.read_bytes() != data:
                target.write_bytes(data)
        elif not target.is_file() or target.read_bytes() != data:
            raise ValueError(f"stale embedded CLI bundle: {target_rel}; run --write and review the diff")
        print(f"PASS: {target_rel}: {count} canonical files")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Проверить пакеты без изменений (по умолчанию)")
    group.add_argument("--write", action="store_true", help="Создать пакеты из канонических источников")
    args = parser.parse_args()
    try:
        verify_or_write(write=args.write)
        return 0
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"EMBEDDED CLI RESOURCES BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
