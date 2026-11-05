#!/usr/bin/env python3
"""Проводить нативные обновления хостов 0.48.0 на независимо закреплённых старых установках.

Здесь не генерируются фикстуры. Каждая запись манифеста — настоящее ранее установленное дерево CLI
Launcher на Linux (ZIP) с запускаемым бинарным файлом прежней версии. Отсутствующая/неподдерживаемая
базовая версия — ошибка, а не пропуск или имитация успеха.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/operations'))
import legacy_upgrade_0476 as upgrade

VERSIONS = ('0.45.14',) + tuple(f'0.46.{n}' for n in range(4)) + tuple(f'0.47.{n}' for n in range(9))
MAX_BYTES = 4 * 1024**3
MAX_FILES = 150_000

class MatrixError(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise MatrixError(message)

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def load_manifest(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    require(data.get('target') == upgrade.TARGET and isinstance(data.get('baselines'), list), 'Некорректный манифест исходной версии')
    rows = data['baselines']
    require(len(rows) == len(VERSIONS) and {x.get('version') for x in rows if isinstance(x, dict)} == set(VERSIONS), 'Для каждой поддерживаемой исходной версии требуется единственная закреплённая эталонная сборка')
    for x in rows:
        require(isinstance(x.get('sha256'), str) and len(x['sha256']) == 64 and all(c in '0123456789abcdef' for c in x['sha256']), 'Некорректная контрольная сумма SHA-256 эталонной сборки')
        require(isinstance(x.get('url'), str) and x['url'].startswith('https://') and ' ' not in x['url'], 'Для эталонной сборки необходим закреплённый HTTPS-адрес загрузки')
        require(isinstance(x.get('binary'), str) and x['binary'], 'Не указан путь к исполняемому файлу старой версии')
        safe_member(x['binary'])
        additional = x.get('protectedPaths', [])
        require(isinstance(additional, list) and all(isinstance(n, str) for n in additional), 'Список защищённых путей должен быть массивом')
        for name in additional:
            safe_member(name)
    return rows

def safe_member(name):
    require(name and '\\' not in name and '\0' not in name and not name.startswith('/'), 'Небезопасное имя ZIP-файла эталонной сборки')
    parts = name.rstrip('/').split('/')
    require(parts and all(p not in ('', '..', '.') for p in parts), 'Обнаружен выход за пределы каталога через путь в ZIP')
    return parts

def extract(source, target):
    target.mkdir(mode=0o700)
    with zipfile.ZipFile(source) as z:
        items = z.infolist()
        require(len(items) <= MAX_FILES and sum(i.file_size for i in items) <= MAX_BYTES, 'Распаковка эталонной сборки превышает допустимые ограничения')
        seen = set()
        for item in items:
            parts = safe_member(item.filename)
            require(tuple(parts) not in seen, 'Повторяющаяся запись в архиве эталонной сборки')
            seen.add(tuple(parts))
            mode = (item.external_attr >> 16)
            require(stat.S_IFMT(mode) not in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK), 'Недопустимый тип элемента ZIP-архива')
            dest = target.joinpath(*parts)
            if item.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as src, dest.open('xb') as out:
                shutil.copyfileobj(src, out, 1024*1024)
                out.flush(); os.fsync(out.fileno())
            if mode & 0o111:
                dest.chmod(0o700)

def fetch(row, dest):
    request = urllib.request.Request(row['url'], headers={'User-Agent':'NeverLauncher-0480-integration'})
    with urllib.request.urlopen(request, timeout=120) as source, dest.open('xb') as out:
        require(source.geturl().startswith('https://'), 'Адрес эталонной сборки перенаправлен на соединение без TLS')
        length = 0
        while block := source.read(1024 * 1024):
            length += len(block)
            require(length <= MAX_BYTES, 'Размер загружаемой эталонной сборки превышает ограничение')
            out.write(block)
        out.flush(); os.fsync(out.fileno())
    require(digest(dest) == row['sha256'], f"baseline checksum mismatch for {row['version']}")

def inventory(tree, data_dirs):
    return upgrade.enumerate_data(tree, data_dirs)

def run_one(row, current, workdir):
    version = row['version']
    folder = workdir / version
    folder.mkdir(mode=0o700)
    archive = folder / 'source.zip'
    fetch(row, archive)
    install = folder / 'installed'
    extract(archive, install)
    binary = install.joinpath(*safe_member(row['binary']))
    require(binary.is_file() and not binary.is_symlink(), 'Исполняемый файл нативного CLI исходной версии отсутствует')
    require(upgrade.native_binary_version(binary) == version, 'Исполняемый файл старой версии сообщает неверный номер выпуска')
    require(binary.parent == install, 'В этой матрице поддерживается обновление CLI хоста только из корневого каталога')
    protected = list(dict.fromkeys([x for x in upgrade.DEFAULT_DATA if (install / x).exists()] + row.get('protectedPaths', [])))
    for extra in row.get('protectedPaths', []):
        require((install / extra).exists(), f'missing required protected installed path: {extra}')
    require('profiles' in protected and 'settings' in protected, 'Эталонная сборка должна содержать данные проекта, профиля и настроек')
    before = inventory(install, protected)
    require(any(k.startswith('profiles/') for k in before) and any(k.startswith('settings/') for k in before), 'Эталонная сборка содержит пустые демонстрационные каталоги')
    backup = folder / 'backup'
    cmd = [sys.executable, str(ROOT/'scripts/operations/legacy_upgrade_0476.py'), 'host',
           '--root', str(install), '--backup', str(backup), '--component', 'cli',
           '--from-version', version, '--install', str(binary),
           '--executable', str(current), '--sha256', digest(current)]
    proc = subprocess.run(cmd, capture_output=True, timeout=1200)
    require(proc.returncode == 0, f'Нативное обновление {version} завершилось ошибкой (код выхода {proc.returncode})')
    result = json.loads(proc.stdout)
    require(result.get('status') == 'upgraded' and result.get('sourceVersion') == version and result.get('targetVersion') == upgrade.TARGET, 'Некорректный результат нативного обновления')
    require(upgrade.native_binary_version(binary, allow_target=True) == upgrade.TARGET, 'Обновлённый исполняемый файл не запускается как кандидатная сборка')
    require(before == inventory(install, protected), 'После нативного обновления изменились данные проекта, профиля или настроек')
    journal = json.loads((backup/'journal.json').read_text())
    require(journal.get('phase') == 'verified' and journal.get('source') == version, 'Журнал нативного обновления не прошёл проверку')
    snap = json.loads((backup/'inventory.json').read_text())
    require(snap.get('files') == before, 'Содержимое резервной копии не совпадает с исходной установкой')
    require(before == inventory(backup/'user-data', protected), 'Физическая резервная копия отличается от исходных данных')
    return {'version': version, 'originalSha256': row['sha256'], 'beforeFiles': len(before),
            'oldExecutableSha256': digest(binary.with_name(binary.name+'.previous-0480')),
            'newExecutableSha256': digest(binary), 'nativeVerified': True, 'userDataVerified': True}

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--candidate-cli', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args(argv)
    try:
        rows = load_manifest(args.manifest)
        require(args.candidate_cli.is_file() and not args.candidate_cli.is_symlink(), 'Исполняемый файл кандидатной версии CLI отсутствует')
        require(upgrade.native_binary_version(args.candidate_cli, allow_target=True) == upgrade.TARGET, 'Несовпадение версии кандидатной сборки')
        # Все артефакты распаковываются в отдельной закрытой тестовой файловой системе.
        with tempfile.TemporaryDirectory(prefix='nl-0480-real-legacy-') as tmp:
            workdir = Path(tmp)
            results = [run_one(row, args.candidate_cli.resolve(), workdir) for row in rows]
        payload = {'schemaVersion': 1, 'status': 'passed', 'targetVersion': upgrade.TARGET,
                   'type': 'native-legacy-upgrade', 'results': results}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True)+'\n')
        return 0
    except (MatrixError, upgrade.LegacyUpgradeError, ValueError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired, zipfile.BadZipFile) as e:
        print(f'Матрица совместимости с предыдущими версиями 0.48.0 не прошла проверку: {e}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
