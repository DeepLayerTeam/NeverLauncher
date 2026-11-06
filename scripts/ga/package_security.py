#!/usr/bin/env python3
"""Упаковать только независимо одобренные и проверенные исходные свидетельства безопасности 0.43.1+.

Полученный архив становится обычным *подписанным ресурсом выпуска*. Его исходные трассы и наблюдения
исполнения перепроверяются до публичной публикации. Не помещать токены или аппаратные идентификаторы
в эти строго структурированные журналы.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_capabilities_0431 import checks, required, verify_all
from verified_targets import approval_data, TARGETS


def evidence_files(version: str = "0.43.1") -> tuple[str, ...]:
    return tuple(
        name
        for target in TARGETS
        for check in checks(version)
        for name in (
            f"targets/{target}/{check}.json",
            f"targets/{target}/security-0431/{check}.jsonl",
        )
    )


def package(evidence: Path, approval: dict, destination: Path, *, now=None) -> None:
    if not required(approval["version"]):
        raise ValueError("security evidence bundling: требуется «0.43.1+»")
    verify_all(evidence, approval, now=now)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with ZipFile(temporary, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for relative in evidence_files(approval["version"]):
                path = evidence / relative
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Отсутствует: «свидетельство безопасности для архива:»" + relative)
                info = ZipInfo(relative, (1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                archive.writestr(info, path.read_bytes(), compress_type=ZIP_DEFLATED, compresslevel=9)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        approval, _, _ = approval_data(args.evidence, args.trusted_key, args.version, args.commit)
        package(args.evidence, approval, args.output)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Поставка подтверждений безопасности ЗАБЛОКИРОВАНА: " + str(exc), file=sys.stderr)
        return 3
    print("Независимые подтверждения безопасности привязаны к точным подписанным целям и упакованы")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
