#!/usr/bin/env python3
"""Production ZIP writer with stable, explicitly documented metadata.

The release timestamp is SOURCE_DATE_EPOCH (UTC), rounded down to the ZIP
2-second precision. The default is the ZIP epoch, making no VCS requirement.
Only regular files are accepted; symlinks and unusual filesystem nodes fail
closed, including when an intermediate path is a symlink.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile

ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z, oldest ZIP date


def timestamp() -> tuple[int, int, int, int, int, int]:
    raw = os.environ.get('SOURCE_DATE_EPOCH', str(ZIP_EPOCH))
    try:
        epoch = int(raw)
        dt = datetime.fromtimestamp(epoch, timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError('invalid SOURCE_DATE_EPOCH') from exc
    if not 1980 <= dt.year <= 2107:
        raise ValueError('SOURCE_DATE_EPOCH outside ZIP supported dates')
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second // 2 * 2)


def safe_member(name: str) -> str:
    if (not name or '\\' in name or '\\x00' in name or name.startswith('/')
            or name.endswith('/') or ':' in name):
        raise ValueError('unsafe ZIP member name')
    parts = PurePosixPath(name).parts
    if any(part in ('.', '..', '') for part in name.split('/')) or not parts:
        raise ValueError('unsafe ZIP member path')
    return name


def safe_file(root: Path, rel: str) -> tuple[Path, int]:
    safe_member(rel)
    current = root
    for part in rel.split('/'):
        current = current / part
        mode = current.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(f'symlink forbidden in release payload: {rel}')
    mode = current.stat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f'non-regular release payload: {rel}')
    return current, mode


def write_zip(root: Path, output: Path, members: list[tuple[str, str]]) -> None:
    """members contain (relative source, destination archive path)."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError('unsafe release source directory')
    moment = timestamp()
    normalized = sorted((safe_member(arc), rel) for rel, arc in members)
    if len({arc for arc, _ in normalized}) != len(normalized):
        raise ValueError('duplicate release archive member')
    # Production source-package places output in ROOT/dist; that is safe if
    # the output itself is not an input to the same archive.
    if any((root / rel).resolve() == output.resolve() for _, rel in normalized):
        raise ValueError('release archive cannot contain itself')
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(output.name + '.partial')
    try:
        with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9,
                             allowZip64=True, strict_timestamps=True) as archive:
            for arc, rel in normalized:
                path, mode = safe_file(root, rel)
                info = zipfile.ZipInfo(arc, date_time=moment)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ((0o100755 if mode & 0o111 else 0o100644) << 16)
                info.flag_bits |= 0x800
                with path.open('rb') as src, archive.open(info, 'w', force_zip64=True) as dest:
                    shutil.copyfileobj(src, dest, length=1024 * 1024)
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)
