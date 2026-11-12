#!/usr/bin/env python3
"""0.48.0: обновление унаследованной установки на месте штатными промышленными обновляющими компонентами.

Операторы предоставляют независимо закреплённые подписанные пакеты/образы. Никакой установки из
дерева исходников, подставной демо-конфигурации, обхода политики доверия или неявной миграции БД.
Закрытая побайтовая копия выбранных *пользовательских данных* создаётся ДО запуска любого нативного
обновления. Журнал запрещает опасное автоматическое воспроизведение после сбоя.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

import component_upgrade as native

TARGET = '0.48.0'
# Поддерживаемая версия здесь означает допустимый формат входных данных для нативного обновлятора,
# а не гарантию ABI-совместимости каждого стороннего расширения.
SUPPORTED = {f'0.47.{n}' for n in range(9)} | {f'0.46.{n}' for n in range(4)} | {'0.45.14'}
RELEASE_RE = re.compile(r'^0\.(?:45\.14|46\.[0-3]|47\.[0-8])$')
MAX_FILES = 150_000
MAX_INVENTORY = 8 * 1024 * 1024
DEFAULT_DATA = ('profiles', 'data', 'settings', 'instances', 'worlds', 'game', 'saves', 'config', 'user-data')
BRIDGE_TARGETS = {'velocity', 'bungeecord', 'waterfall', 'bukkit', 'spigot', 'paper',
                  'purpur', 'folia', 'fabric', 'quilt', 'forge', 'neoforge', 'sponge', 'vanilla'}


class LegacyUpgradeError(RuntimeError):
    pass


def require(ok: bool, message: str):
    if not ok:
        raise LegacyUpgradeError(message)


def checked_dir(path: Path, *, create=False):
    require(path.is_absolute(), 'Требуется абсолютный путь к каталогу')
    if create and not path.exists():
        path.mkdir(mode=0o700, parents=False)
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and not path.is_symlink(), f'Небезопасный каталог: {path}')
    return path


def private_dir(path: Path):
    checked_dir(path)
    require(path.stat().st_mode & 0o077 == 0, 'Каталог резервной копии или журнала должен иметь права 0700')
    return path


def sha_file(path: Path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fsync_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path: Path, doc: dict):
    private_dir(path.parent)
    require(not path.is_symlink(), 'Путь журнала является символьной ссылкой')
    fd, tmp = tempfile.mkstemp(prefix='.legacy-0476-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(doc, out, sort_keys=True, ensure_ascii=False, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        fsync_directory(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def exclusive(directory: Path):
    private_dir(directory)
    fd = os.open(directory / '.legacy-upgrade.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1, 'небезопасная блокировка')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LegacyUpgradeError('Уже выполняется другое обновление с предыдущей версии') from exc
        yield
    finally:
        os.close(fd)


def version_ok(value):
    require(isinstance(value, str) and RELEASE_RE.fullmatch(value),
            'Исходная версия неизвестна или не поддерживается; автоматическая переустановка и понижение версии запрещены')
    return value


def read_json(path: Path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_size <= 1024 * 1024 and st.st_nlink == 1,
            'Некорректные метаданные установленной версии')
    value = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(value, dict), 'Метаданные установки должны быть объектом')
    return value


def client_source_version(root: Path, *, allow_target=False):
    """Использовать штатную запись состояния компонента, а не пользовательские демонстрационные манифесты."""
    path = root / '.launcher' / 'component-update-state.json'
    require(path.is_file() and not path.is_symlink(),
            'Нет существующего состояния нативного обновления компонентов; устаревшая структура требует отдельного проверенного преобразования')
    data = read_json(path)
    require(data.get('schemaVersion') == '1.0', 'Неподдерживаемая схема состояния компонента')
    require(isinstance(data.get('components'), list) and len(data['components']) >= 3,
            'Неполное состояние компонента не подтверждает установленное приложение')
    if allow_target and data.get('version') == TARGET:
        return TARGET
    return version_ok(data.get('version'))


def prestarter_source(root: Path):
    """Проверять существующие резервные слоты установщика; штатный verify-installed проверяет подписи."""
    base = root / '.launcher-installer'
    checked_dir(base)
    slots = []
    for num in (0, 1):
        path = base / f'active-{num}.json'
        if not path.exists():
            continue
        data = read_json(path)
        if isinstance(data.get('generation'), int) and data['generation'] > 0 and \
                isinstance(data.get('release'), str) and re.fullmatch(r'[a-f0-9]{64}-(?:linux|windows|darwin)-(?:amd64|arm64)', data['release']) and \
                isinstance(data.get('configHash'), str) and re.fullmatch(r'[a-f0-9]{64}', data['configHash']):
            slots.append(data)
    require(slots, 'Отсутствует действительный активный слот Prestarter')
    slots.sort(key=lambda row: row['generation'], reverse=True)
    return slots[0]


def native_binary_version(path: Path, *, allow_target=False):
    require(path.is_file() and not path.is_symlink(), 'Установленный исполняемый файл отсутствует')
    output = native.run([str(path), 'version'], timeout=30).decode('utf-8', errors='replace')
    matches = re.findall(r'(?<![\d.])0\.(?:45|46|47|48)\.\d+(?![\d.])', output)
    require(len(set(matches)) == 1, 'Неоднозначная версия исполняемого файла')
    if allow_target and matches[0] == TARGET:
        return TARGET
    return version_ok(matches[0])


def validate_data_path(root: Path, relative: str):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute() and '\\' not in relative,
            'Путь защищённых данных должен быть относительным к существующей установке')
    pieces = Path(relative).parts
    require(all(part not in ('', '.', '..') for part in pieces) and pieces[0] not in ('.launcher', '.launcher-installer', '.launcher-prestarter'),
            'Небезопасный или управляемый путь состояния внутри защищённых пользовательских данных')
    path = root
    for part in pieces:
        path = path / part
        if path.exists() or path.is_symlink():
            require(not path.is_symlink(), 'В пути защищённых данных обнаружена символьная ссылка')
    return root.joinpath(*pieces)


def enumerate_data(root: Path, names: list[str]):
    """Проверять каждый заявленный защищённым байт; отклонять символьные ссылки и устройства."""
    require(len(set(names)) == len(names), 'Повторяющийся путь защищённых пользовательских данных')
    for left in names:
        for right in names:
            if left != right and (right.startswith(left.rstrip('/') + '/')):
                raise LegacyUpgradeError('Пересекающиеся пути защищённых данных')
    result = {}
    for rel in names:
        base = validate_data_path(root, rel)
        if not base.exists():
            continue
        paths = [base]
        if base.is_dir():
            paths.extend(sorted(base.rglob('*')))
        for path in paths:
            entry = path.relative_to(root).as_posix()
            require(len(result) < MAX_FILES, 'Объём инвентаризации пользовательских данных превышает безопасное ограничение')
            st = path.lstat()
            require(st.st_nlink == 1 or stat.S_ISDIR(st.st_mode), 'Защищённый пользовательский файл имеет жёсткую ссылку')
            if stat.S_ISDIR(st.st_mode):
                result[entry] = {'kind': 'dir', 'mode': stat.S_IMODE(st.st_mode)}
            elif stat.S_ISREG(st.st_mode):
                result[entry] = {'kind': 'file', 'size': st.st_size, 'sha256': sha_file(path),
                                 'mode': stat.S_IMODE(st.st_mode)}
            else:
                raise LegacyUpgradeError('Символическая ссылка или специальный файл в данных пользователя: ' + entry)
    require(result, 'Не найдены данные старой версии; укажите --data для фактической структуры установки')
    require(len(json.dumps(result)) < MAX_INVENTORY, 'Инвентаризация пользовательских файлов слишком велика')
    return result


def copy_data(root: Path, snapshot: Path, original: dict):
    """Создавать независимые копии, а не жёсткие ссылки на изменяемую установку."""
    for name, info in sorted(original.items(), key=lambda it: (it[0].count('/'), it[0])):
        dst = snapshot / name
        if info['kind'] == 'dir':
            dst.mkdir(parents=True, exist_ok=True)
            dst.chmod(0o700)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            with (root / name).open('rb') as inp, dst.open('xb') as out:
                shutil.copyfileobj(inp, out, length=1024 * 1024)
                out.flush(); os.fsync(out.fileno())
            dst.chmod(info['mode'])
            require(sha_file(dst) == info['sha256'], 'Проверка резервной копии завершилась ошибкой: ' + name)
    # Метаданные каталога не являются выпуском приложения: определяющими являются содержимое байтов и права доступа.
    for d in sorted((p for p in snapshot.rglob('*') if p.is_dir()), key=lambda p: -len(p.parts)):
        fsync_directory(d)
        d.chmod(original[d.relative_to(snapshot).as_posix()]['mode'] if d.relative_to(snapshot).as_posix() in original else 0o700)
    fsync_directory(snapshot)


def create_backup(root: Path, backup: Path, original: dict, source: str, operation: str, paths: list[str]):
    private_dir(backup.parent)
    require(not backup.exists() and not backup.is_symlink(), 'Резервная копия ещё не должна существовать')
    stage = Path(tempfile.mkdtemp(prefix='.legacy-backup-', dir=backup.parent))
    try:
        (stage / 'user-data').mkdir(mode=0o700)
        copy_data(root, stage / 'user-data', original)
        atomic_json(stage / 'inventory.json', {'sourceVersion': source, 'targetVersion': TARGET,
                        'operation': operation, 'protectedPaths': paths, 'files': original})
        require(enumerate_data(stage / 'user-data', paths) == original,
                'Побайтовая проверка чтения резервной копии выявила несовпадение')
        os.replace(stage, backup)
        fsync_directory(backup.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def run_updater(command: list[str], *, timeout=1800, json_response=False):
    # Не выводить stdout/stderr: они могут содержать секреты и учётные данные, зависящие от пути.
    p = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    require(p.returncode == 0, f'Обновляющий компонент {Path(command[0]).name} завершился с кодом {p.returncode}')
    if json_response:
        require(len(p.stdout) <= 1024 * 1024, 'Отчёт нативного обновления превышает допустимый размер')
        return json.loads(p.stdout)
    return None


def verify_preservation(root: Path, original: dict, paths: list[str]):
    actual = enumerate_data(root, paths)
    require(actual == original, 'Обновление изменило защищённые данные пользователя; перед продолжением восстановите их из закрытой резервной копии')


def client_update(root: Path, args, source):
    require(args.cli and args.cli_sha256 and args.package and args.sha256 and args.delivery_manifest,
            'Требуются подписанный нативный пакет, закреплённая сумма SHA-256 CLI и манифест поставки')
    native.checked_file(Path(args.cli), args.cli_sha256)
    result = native.client_package(Path(args.cli), Path(args.package), args.sha256,
                                   Path(args.delivery_manifest), root, target_version=TARGET)
    require(client_source_version(root, allow_target=True) == TARGET, 'Состояние установленного компонента не обновилось до целевой версии')
    return {'nativeStatus': result['nativeReport'].get('status'), 'components': ['Desktop', 'Runtime', 'Guard']}


def prestarter_update(root: Path, args, source):
    require(args.installer and args.installer_sha256 and args.bundle,
            'Требуются подписанный installer, независимая закреплённая сумма SHA-256 и пакет')
    old = prestarter_source(root)
    installer = Path(args.installer)
    bundle = Path(args.bundle)
    native.checked_file(installer, args.installer_sha256)
    checked_dir(bundle)
    run_updater([str(installer), 'verify', '--bundle', str(bundle), '--root', str(root)])
    run_updater([str(installer), 'verify-installed', '--root', str(root)])
    run_updater([str(installer), 'update', '--bundle', str(bundle), '--root', str(root), '--no-start'], timeout=2400)
    run_updater([str(installer), 'verify-installed', '--root', str(root)])
    new = prestarter_source(root)
    require(new['generation'] > old['generation'], 'Установщик Prestarter не обновил поколение')
    return {'nativeStatus': 'verified', 'component': 'Prestarter', 'newGeneration': new['generation']}


def host_update(root: Path, args, source):
    require(args.component in ('api', 'cli', 'bridge') and args.executable and args.install and args.sha256,
            'Требуются компонент, закреплённый исполняемый файл, путь установки и SHA-256')
    install = Path(args.install)
    require(install.is_absolute() and install.is_relative_to(root), 'Исполняемый файл хоста должен находиться внутри корневого каталога установки')
    require(native_binary_version(install) == source, 'Версия установленного исполняемого файла хоста не совпадает')
    result = native.host_binary(args.component, Path(args.executable), install, args.sha256,
                                service=args.service, ready_url=args.ready_url,
                                source_version=source, target_version=TARGET, backup_tag='0480')
    return {'nativeStatus': result['status'], 'component': args.component,
            'oldBinarySha256': result['fromSha256'], 'newBinarySha256': result['toSha256']}



def jar_metadata_version(jar: Path):
    """Читать реальный дескриптор установленного плагина; при неизвестном формате запрещать продолжение."""
    require(jar.is_file() and not jar.is_symlink(), 'Установленный плагин Bridge отсутствует')
    try:
        with zipfile.ZipFile(jar) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'Повторяющиеся записи JAR-архива')
            require(archive.testzip() is None, 'JAR-файл Bridge повреждён')
            for descriptor in ('plugin.yml', 'bungee.yml', 'velocity-plugin.json',
                               'fabric.mod.json', 'META-INF/MANIFEST.MF'):
                if descriptor not in archive.namelist():
                    continue
                raw = archive.read(descriptor)
                require(len(raw) <= 128*1024, 'Дескриптор Bridge превышает допустимый размер')
                if descriptor.endswith('.json'):
                    version = json.loads(raw).get('version')
                else:
                    pattern = (r'(?mi)^Implementation-Version:\s*([0-9.]+)\s*$' if descriptor.endswith('MF')
                               else r"(?mi)^version:\s*['\"]?([0-9.]+)['\"]?\s*$")
                    found = re.search(pattern, raw.decode('utf-8', errors='strict'))
                    version = found.group(1) if found else None
                if isinstance(version, str) and re.fullmatch(r'0\.\d+\.\d+', version):
                    return version
    except (zipfile.BadZipFile, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LegacyUpgradeError('Не удалось прочитать метаданные JAR моста') from exc
    raise LegacyUpgradeError('В JAR моста не найдено распознаваемой встроенной версии; не определяйте её предположительно')


def bridge_jar_update(root: Path, args, source: str):
    require(os.geteuid() == 0, 'Для управляемого обновления плагина Java ServerBridge через systemd требуются права root')
    require(args.plugin_type in BRIDGE_TARGETS and args.executable and args.install and args.service,
            'Требуются целевой Bridge, JAR выпуска, установленный JAR и служба systemd')
    require(args.release_manifest and args.manifest_sha256 and re.fullmatch('[a-f0-9]{64}', args.manifest_sha256),
            'Требуется внешне утверждённая сумма SHA-256 манифеста выпуска')
    manifest_path, jar, install = Path(args.release_manifest), Path(args.executable), Path(args.install)
    require(manifest_path.is_file() and not manifest_path.is_symlink() and
            sha_file(manifest_path) == args.manifest_sha256, 'Контрольная сумма манифеста выпуска не совпадает')
    native.checked_file(manifest_path, args.manifest_sha256, must_be_root=True)
    manifest = read_json(manifest_path)
    require(manifest.get('toolVersion') == TARGET, 'Некорректная версия подписанного манифеста выпуска')
    rows = manifest.get('artifacts')
    require(isinstance(rows, list) and len(rows) == len(BRIDGE_TARGETS) and
            {r.get('id') for r in rows if isinstance(r, dict)} == BRIDGE_TARGETS,
            'Матрица артефактов Bridge неполная или содержит повторы')
    row = next(r for r in rows if r['id'] == args.plugin_type)
    expected_name = f'launcher-{args.plugin_type}-bridge-{TARGET}.jar'
    require(row.get('file') == expected_name and jar.name == expected_name and
            re.fullmatch('[a-f0-9]{64}', row.get('sha256', '')),
            'Отсутствует имя или контрольная сумма артефакта выпуска Bridge')
    native.checked_file(jar, row['sha256'], must_be_root=True)
    require(install.is_absolute() and install.is_relative_to(root) and
            install.parent.is_dir() and not install.parent.is_symlink() and
            install.parent.stat().st_uid == 0 and not install.parent.stat().st_mode & 0o022,
            'Каталог установки плагина должен принадлежать root и быть защищён')
    require(native.SERVICE_RE.fullmatch(args.service), 'Недопустимая служба systemd')
    require(jar_metadata_version(jar) == TARGET, 'В новом JAR-файле Bridge указана неверная версия')
    require(jar_metadata_version(install) == source, 'Версия установленного JAR-файла Bridge не совпадает с выпуском')
    require(native.systemctl_is_active(args.service), 'Перед переключением Bridge должен быть активен')
    oldstat = install.lstat()
    require(stat.S_ISREG(oldstat.st_mode) and oldstat.st_nlink == 1 and oldstat.st_uid == 0,
            'Небезопасный установленный JAR-файл Bridge')
    backup = install.with_name(install.name + '.previous-0480')
    require(not backup.exists() and not backup.is_symlink(), 'Резервная копия предыдущего JAR уже существует')
    oldsha = sha_file(install)
    native.run(['systemctl', 'stop', args.service], timeout=90)
    try:
        os.replace(install, backup)
        native.fsync_dir(install.parent)
        fd, stage = tempfile.mkstemp(prefix='.bridge-0476-', dir=install.parent)
        try:
            with os.fdopen(fd, 'wb') as out, jar.open('rb') as inp:
                shutil.copyfileobj(inp, out, length=1024*1024)
                out.flush(); os.fchmod(out.fileno(), stat.S_IMODE(oldstat.st_mode)); os.fsync(out.fileno())
            require(sha_file(Path(stage)) == row['sha256'], 'Контрольная сумма подготовленного JAR Bridge не совпадает')
            os.replace(stage, install)
            native.fsync_dir(install.parent)
        finally:
            if os.path.exists(stage):
                os.unlink(stage)
        require(jar_metadata_version(install) == TARGET, 'Новый установленный JAR-файл Bridge повреждён')
        native.run(['systemctl', 'start', args.service], timeout=90)
        require(native.systemctl_is_active(args.service), 'Перезапуск Bridge завершился ошибкой')
        return {'nativeStatus': 'service-started', 'component': 'ServerBridge JAR',
                'pluginType': args.plugin_type, 'previousSha256': oldsha,
                'installedSha256': row['sha256'], 'runtimeJoinVerified': False}
    except Exception as exc:
        try:
            try:
                native.run(['systemctl', 'stop', args.service], timeout=60)
            except Exception:
                pass
            if backup.exists():
                if install.exists():
                    install.unlink()
                os.replace(backup, install)
                native.fsync_dir(install.parent)
            require(sha_file(install) == oldsha, 'Контрольная сумма восстановленного старого JAR-файла Bridge не совпадает')
            native.run(['systemctl', 'start', args.service], timeout=90)
            require(native.systemctl_is_active(args.service), 'Не удалось перезапустить старый JAR-файл Bridge')
        except Exception as restore_exc:
            raise LegacyUpgradeError('Обновление и откат моста завершились ошибкой; не запускайте сервер') from restore_exc
        raise LegacyUpgradeError('Обновление моста завершилось ошибкой; предыдущий JAR восстановлен') from exc


def determine_source(mode, root, args):
    if mode == 'client':
        detected = client_source_version(root)
    elif mode == 'prestarter':
        prestarter_source(root)
        # В записях Prestarter используются непрозрачные хеши подписанных выпусков, а не SemVer.
        # Если состояние клиента недоступно, только зафиксированные входные данные оператора вместе с
        # фактической нативной проверкой verify-installed могут подтвердить источник обновления.
        state = root / '.launcher' / 'component-update-state.json'
        if state.exists():
            detected = client_source_version(root)
        else:
            require(args.from_version, 'Не удалось определить исходную версию Prestarter: требуется --from-version')
            detected = version_ok(args.from_version)
    elif mode == 'bridge-jar':
        require(args.install, 'Требуется установленный JAR-файл Bridge')
        detected = version_ok(jar_metadata_version(Path(args.install)))
    elif mode == 'host':
        detected = native_binary_version(Path(args.install))
    else:
        raise LegacyUpgradeError('Неподдерживаемый режим обновления')
    if args.from_version:
        require(args.from_version == detected, 'Заявленный исходный релиз отличается от установленного')
    return detected


def backend_upgrade(args):
    require(args.project and args.confirm and args.source_env and args.target_env,
            'Требуются существующий проект Compose, подтверждение и закреплённые исходное и целевое окружения')
    source_env, target_env = Path(args.source_env).absolute(), Path(args.target_env).absolute()
    source_settings, detected = native.read_version(source_env)
    version_ok(detected)
    if args.from_version:
        require(args.from_version == detected, 'Исходное окружение не соответствует ожидаемой версии')
    native.assert_same_config(source_env, target_env, source_version=detected, target_version=TARGET)
    snapshot = Path(args.backup).absolute()
    require(not snapshot.exists(), 'Требуется новый закрытый путь контрольной точки нативного аварийного восстановления')
    result = native.standard(args.project, args.confirm, source_env, target_env, snapshot,
                             production=args.production_source, approved=args.maintenance_approved,
                             source_version=detected, target_version=TARGET)
    require(result.get('status') == 'upgraded' and result.get('backendVerified') is True,
            'Нативное обновление Backend не прошло реальные проверки работоспособности')
    return {'status': 'upgraded', 'sourceVersion': detected, 'targetVersion': TARGET,
            'mode': 'backend', 'snapshot': str(snapshot), 'nativeResult': result}



def rollback_host(args):
    """Восстановить Linux-файл 0.48.0 из исходной закреплённой квитанции резервирования."""
    require(args.root and args.install and args.component in ('api', 'cli', 'bridge'),
            'Для отката хоста требуются существующий корневой каталог, установленный исполняемый файл и компонент')
    root = checked_dir(Path(args.root).absolute())
    backup = Path(args.backup).absolute()
    private_dir(backup.parent)
    with exclusive(backup.parent):
        journal = read_json(backup / 'journal.json')
        require(journal.get('schema') == 1 and journal.get('mode') == 'host'
                and journal.get('root') == str(root) and journal.get('target') == TARGET,
                'Резервная копия не относится к запрошенному обновлению хоста')
        phase = journal.get('phase')
        require(phase in ('verified', 'manual-reconciliation-required'),
                'Обновление не достигло этапа, на котором возможно восстановление')
        result = journal.get('result')
        # Если переключение не зарегистрировало завершённую смену бинарника,
        # независимо считайте закреплённый старый дайджест из исходного сохранённого
        # файла резервной копии.
        sha = result.get('oldBinarySha256') if isinstance(result, dict) else None
        require(sha and re.fullmatch('[a-f0-9]{64}', sha),
                'В подтверждённой квитанции нет проверенной суммы SHA предыдущего файла; используйте нативное аварийное восстановление')
        install = Path(args.install)
        require(install.is_absolute() and install.is_relative_to(root), 'Небезопасный путь установленного исполняемого файла')
        require(result.get('component') == args.component, 'Компонент не соответствует квитанции')
        restored = native.rollback_linux_host(args.component, install, sha, service=args.service,
                    ready_url=args.ready_url, source_version=journal['source'], backup_tag='0480')
        inventory = read_json(backup / 'inventory.json')
        require(inventory.get('files') and inventory.get('protectedPaths'),
                'Отсутствует исходная инвентаризация пользовательских данных')
        verify_preservation(root, inventory['files'], inventory['protectedPaths'])
        journal['phase'] = 'reverted-and-verified'
        atomic_json(backup / 'journal.json', journal)
        return {'status': 'rolled-back', 'sourceVersion': journal['source'],
                'restoredSha256': restored['restoredSha256'], 'userDataVerified': True}


def execute(args):
    if args.mode == 'backend':
        return backend_upgrade(args)
    if args.mode == 'rollback-host':
        return rollback_host(args)
    require(args.root, 'Требуется существующий корневой каталог установки')
    root = checked_dir(Path(args.root).absolute())
    backup = Path(args.backup).absolute()
    private_dir(backup.parent)
    require(not backup.is_relative_to(root) and not root.is_relative_to(backup),
            'Резервная копия должна находиться за пределами каталога установки')
    with exclusive(backup.parent):
        require(not backup.exists(), 'Резервная копия уже существует; не повторяйте попытку обновления и не перезаписывайте её')
        source = determine_source(args.mode, root, args)
        # Явно заданные пользовательские пути дополняют стандартные каталоги, а не незаметно
        # заменяют их.
        paths = list(dict.fromkeys([name for name in DEFAULT_DATA if (root / name).exists()] + (args.data or [])))
        original = enumerate_data(root, paths)
        create_backup(root, backup, original, source, args.mode, paths)
        journal = backup / 'journal.json'
        state = {'schema': 1, 'mode': args.mode, 'source': source, 'target': TARGET,
                 'root': str(root), 'phase': 'backup-verified',
                 'backup': str(backup), 'at': datetime.now(timezone.utc).isoformat()}
        atomic_json(journal, state)
        try:
            state['phase'] = 'updater-invoked'
            atomic_json(journal, state)
            if args.mode == 'client':
                result = client_update(root, args, source)
            elif args.mode == 'prestarter':
                result = prestarter_update(root, args, source)
            elif args.mode == 'host':
                result = host_update(root, args, source)
            else:
                result = bridge_jar_update(root, args, source)
            state['phase'] = 'native-committed'
            atomic_json(journal, state)
            verify_preservation(root, original, paths)
            state['phase'] = 'verified'
            state['result'] = result
            atomic_json(journal, state)
            return {'status': 'upgraded', 'sourceVersion': source, 'targetVersion': TARGET,
                    'mode': args.mode, 'protectedEntries': len(original), 'backup': str(backup), **result}
        except Exception:
            # Никогда не повторяйте частично зафиксированную нативную транзакцию. Её
            # нужно восстанавливать нативным обновлятором/установщиком и закрытой
            # резервной копией.
            state['phase'] = 'manual-reconciliation-required'
            atomic_json(journal, state)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['backend', 'client', 'prestarter', 'host', 'bridge-jar', 'rollback-host'])
    parser.add_argument('--root', help="Существующая установка (не новая)")
    parser.add_argument('--backup', required=True, help="Новый внешний каталог под защищённым родителем с правами 0700")
    parser.add_argument('--data', action='append', help="Относительный неизменяемый путь пользовательских данных; повторить для всех каталогов")
    parser.add_argument('--from-version', help="Независимо закреплённый старый выпуск, проверенный по установленному состоянию")
    parser.add_argument('--cli'); parser.add_argument('--cli-sha256')
    parser.add_argument('--package'); parser.add_argument('--sha256'); parser.add_argument('--installer-sha256')
    parser.add_argument('--delivery-manifest'); parser.add_argument('--installer'); parser.add_argument('--bundle')
    parser.add_argument('--component', choices=['api', 'cli', 'bridge'])
    parser.add_argument('--executable'); parser.add_argument('--install'); parser.add_argument('--service')
    parser.add_argument('--plugin-type', choices=sorted(BRIDGE_TARGETS))
    parser.add_argument('--release-manifest'); parser.add_argument('--manifest-sha256')
    parser.add_argument('--ready-url', default='http://127.0.0.1:8080/ready')
    parser.add_argument('--project'); parser.add_argument('--confirm')
    parser.add_argument('--source-env'); parser.add_argument('--target-env')
    parser.add_argument('--production-source', action='store_true')
    parser.add_argument('--maintenance-approved', action='store_true')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(execute(args), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (LegacyUpgradeError, native.ComponentError, OSError, subprocess.TimeoutExpired, ValueError, UnicodeError) as exc:
        print('Обновление с предыдущей версии заблокировано: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
