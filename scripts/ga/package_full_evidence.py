#!/usr/bin/env python3
"""Поставить и независимо перепроверить точные подписанные входные данные выполнения для GA.

Архив содержит исходные трассы проверок с привязкой к хешам, отчёты/журналы игроков и наблюдения
безопасности. Одобрение Ed25519 оператора и настоящие байты установщика остаются вне этого ZIP, в
отдельно подписанном финальном выпуске. Синтетические PASS не создаются.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from verified_targets import (
    TARGETS, PLAYER_CHECKS_0400, checks_for, verify,
)
from security_capabilities_0431 import checks as security_checks

ARCHIVE_NAME = "GA_EXECUTION_EVIDENCE_04315.zip"
MAX_MEMBER = 32 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def evidence_files(version: str) -> tuple[str, ...]:
    names: set[str] = set()
    for target in TARGETS:
        for check in checks_for(version):
            names.add(f"targets/{target}/{check}.json")
            if check in PLAYER_CHECKS_0400:
                names.add(f"targets/{target}/player-0400/{check}.json")
                names.add(f"targets/{target}/player-0400/{check}.log")
            if check in security_checks(version):
                names.add(f"targets/{target}/security-0431/{check}.jsonl")
    return tuple(sorted(names))


def safe_member(path: Path) -> bytes:
    # Отклоняйте символьные ссылки в любых родительских каталогах доказательств, а не только конечную ссылку.
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Небезопасное значение: «symlink in GA evidence:»" + str(path))
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_MEMBER:
        raise ValueError("Подтверждение выполнения GA отсутствует, пустое или слишком большое: " + str(path))
    data = path.read_bytes()
    if not 0 < len(data) <= MAX_MEMBER:
        raise ValueError("Подтверждение выполнения GA изменилось во время чтения: " + str(path))
    return data


def package(bundle: Path, evidence: Path, key: Path, version: str, commit: str, output: Path, *, now=None) -> None:
    # Проверяйте реальные упакованные бинарные файлы и независимую подпись ДО архивирования.
    verify(bundle, evidence, key, version, commit, now=now)
    members = evidence_files(version)
    output.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with tempfile.NamedTemporaryFile(prefix=".ga04315-", suffix=".zip", dir=output.parent, delete=False) as tmp:
        temp = Path(tmp.name)
    try:
        with ZipFile(temp, "w", compression=ZIP_DEFLATED, compresslevel=9, allowZip64=True) as archive:
            for name in members:
                raw = safe_member(evidence / name)
                total += len(raw)
                if total > MAX_TOTAL:
                    raise ValueError("Общий размер подтверждений выполнения GA превышает лимит")
                info = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                archive.writestr(info, raw, compress_type=ZIP_DEFLATED, compresslevel=9)
        # Завершайте с отказом, если исходник изменился между проверкой и упаковкой: вызывающая
        # сторона затем подпишет только байты запечатанного архива.
        with tempfile.TemporaryDirectory(prefix="ga04315-recheck-") as folder:
            root = Path(folder)
            (root / "approval.json").write_bytes((evidence / "approval.json").read_bytes())
            (root / "approval.sig").write_bytes((evidence / "approval.sig").read_bytes())
            extract_verified(temp, root, version)
            verify(bundle, root, key, version, commit, now=now)
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)


def extract_verified(archive_path: Path, destination: Path, version: str) -> None:
    if (archive_path.is_symlink() or not archive_path.is_file()
            or not 0 < archive_path.stat().st_size <= MAX_TOTAL):
        raise ValueError("Архив выполнения GA отсутствует или небезопасен")
    expected = set(evidence_files(version))
    with ZipFile(archive_path, "r") as archive:
        entries = archive.infolist()
        if len(entries) != len(expected) or {entry.filename for entry in entries} != expected:
            raise ValueError("В архиве выполнения GA отсутствуют обязательные элементы либо найдены повторяющиеся или лишние")
        total = 0
        for entry in entries:
            mode = (entry.external_attr >> 16) & 0o170000
            if (entry.is_dir() or mode not in (0, 0o100000)
                    or not 0 < entry.file_size <= MAX_MEMBER):
                raise ValueError("Небезопасное значение: «GA execution archive entry:»" + entry.filename)
            total += entry.file_size
            if total > MAX_TOTAL:
                raise ValueError("Размер распакованных подтверждений выполнения GA превышает лимит")
            # Имена берутся из evidence_files(), а не из произвольных путей.
            target = destination / entry.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as stream, target.open("xb") as out:
                remaining = entry.file_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Данные выполнения GA обрезаны")
                    out.write(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    raise ValueError("Подтверждающие данные выполнения GA превышают допустимый размер")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        package(args.bundle, args.evidence, args.trusted_key, args.version, args.commit, args.output)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Полный комплект доказательств GA ЗАБЛОКИРОВАН: " + str(exc), file=sys.stderr)
        return 3
    print("Полные данные выполнения GA проверены, упакованы и повторно проверены")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
