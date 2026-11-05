#!/usr/bin/env python3
"""Включить закреплённые автономные зависимости JAR внутрь Java Extension Host JAR.

Создаётся структура Runtime, которую независимо проверяют Go-установщик и Java Host. Результат всё
ещё требует обычной упаковки в подписанный .nlext. При установке и запуске разрешение Maven/сети не
выполняется.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import zipfile

PREFIX = "META-INF/launcher/libs/"
LOCK = "META-INF/launcher/libraries.lock"
COORD = re.compile(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+\Z")
VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?\Z")


def bundle(host: Path, output: Path, specs: list[str]) -> None:
    if host.resolve() == output.resolve():
        raise ValueError("output must not overwrite input host JAR")
    if not 1 <= len(specs) <= 64:
        raise ValueError("provide 1..64 locked dependencies")
    libraries = []
    identities = set()
    total = 0
    for raw in specs:
        parts = raw.split("@", 3)
        if len(parts) != 4:
            raise ValueError("library format: group:artifact@version@api-range@/path/file.jar")
        coord, version, api, filename = parts
        if not COORD.fullmatch(coord) or not VERSION.fullmatch(version) or not api or any(c in api for c in "\r\n\t"):
            raise ValueError(f"invalid library coordinate/version/API range: {coord}")
        if coord in identities:
            raise ValueError("duplicate library coordinate: " + coord)
        identities.add(coord)
        data = Path(filename).read_bytes()
        if not 0 < len(data) <= 16 * 1024 * 1024:
            raise ValueError("library JAR must be 1..16 MiB")
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise ValueError("library collection too large")
        with zipfile.ZipFile(Path(filename)) as library:
            if library.testzip() is not None:
                raise ValueError("corrupt library JAR " + filename)
        digest = hashlib.sha256(data).hexdigest()
        name = PREFIX + coord.replace(":", "-") + "-" + version + ".jar"
        if not re.fullmatch(r"META-INF/launcher/libs/[A-Za-z0-9._-]+\.jar", name):
            raise ValueError("invalid library filename")
        libraries.append((name, coord, version, digest, api, data))
    if len({row[0] for row in libraries}) != len(libraries):
        raise ValueError("two dependency coordinates map to the same JAR path")
    libraries.sort(key=lambda row: row[0])
    lock = "".join("\t".join(row[:5]) + "\n" for row in libraries).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(host) as source, zipfile.ZipFile(output, "w") as target:
            names = source.namelist()
            if len(names) != len(set(names)) or any(n == LOCK or n.startswith(PREFIX) for n in names):
                raise ValueError("input host already has bundled dependencies or duplicate entries")
            if "META-INF/MANIFEST.MF" not in names:
                raise ValueError("host manifest missing")
            for info in source.infolist():
                target.writestr(info, source.read(info))
            for name, coord, version, digest, api, data in libraries:
                target.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data, compress_type=zipfile.ZIP_DEFLATED)
            target.writestr(zipfile.ZipInfo(LOCK, (1980, 1, 1, 0, 0, 0)), lock, compress_type=zipfile.ZIP_DEFLATED)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--library", action="append", required=True)
    args = parser.parse_args()
    try:
        bundle(args.host, args.output, args.library)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    print(f"Packed {len(args.library)} pinned dependencies into {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
