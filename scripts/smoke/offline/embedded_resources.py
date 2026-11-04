"""Read canonical CLI-embedded resources in source smoke tests without file mirrors.

The shipped CLI uses the same two deterministic ZIP bundles. Release and CI
also run `embedded_cli_assets.py --check` to ensure every member matches the
single canonical source; tests below inspect the *actual embedded payload*.
"""
from __future__ import annotations
from pathlib import Path
import zipfile

SQL_ALIAS = 'cli/internal/dbmigrate/sql/'
TEMPLATE_ALIAS = 'cli/cmd/launcher/templates/production/'
SQL_BUNDLE = 'cli/internal/dbmigrate/catalog.zip'
TEMPLATE_BUNDLE = 'cli/cmd/launcher/templates/production.zip'


def _entry(rel: str) -> tuple[str, str] | None:
    if rel.startswith(SQL_ALIAS):
        name = rel.removeprefix(SQL_ALIAS)
        if name.endswith('.sql') and name and '/' not in name and '..' not in name:
            return SQL_BUNDLE, 'sql/' + name
        raise ValueError(f'invalid embedded SQL path: {rel}')
    if rel.startswith(TEMPLATE_ALIAS):
        name = rel.removeprefix(TEMPLATE_ALIAS)
        if name in {'docker-compose.yml', 'nginx.conf', 'env.production.example'}:
            return TEMPLATE_BUNDLE, 'production/' + name
        raise ValueError(f'invalid embedded template path: {rel}')
    return None


def resource_read_bytes(root: Path, rel: str) -> bytes:
    entry = _entry(rel)
    if entry is None:
        return (root / rel).read_bytes()
    archive, member = entry
    with zipfile.ZipFile(root / archive) as payload:
        return payload.read(member)


def resource_read_text(root: Path, rel: str) -> str:
    return resource_read_bytes(root, rel).decode('utf-8')


def resource_exists(root: Path, rel: str) -> bool:
    entry = _entry(rel)
    if entry is None:
        return (root / rel).is_file()
    archive, member = entry
    if not (root / archive).is_file():
        return False
    try:
        with zipfile.ZipFile(root / archive) as payload:
            return member in payload.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def migration_catalog(root: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(root / SQL_BUNDLE) as payload:
        return {entry.filename.removeprefix('sql/'): payload.read(entry)
                for entry in payload.infolist()}
