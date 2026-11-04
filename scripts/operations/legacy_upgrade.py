#!/usr/bin/env python3
"""0.48.0 in-place legacy upgrade using the existing production updaters.

Operators provide independently pinned signed packages/images. No source-tree
installation, replacement demo config, trust-policy bypass or implicit DB migration.
A private byte-for-byte backup of selected *user data* is created BEFORE any
native updater runs; the journal refuses unsafe automatic replay after a crash.
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

import component_upgrade_0458 as native

TARGET = '0.48.0'
# A supported version here means an accepted input layout for the native updater,
# not a promise that every third-party extension is ABI-compatible.
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
    require(path.is_absolute(), 'absolute directory required')
    if create and not path.exists():
        path.mkdir(mode=0o700, parents=False)
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and not path.is_symlink(), f'unsafe directory: {path}')
    return path


def private_dir(path: Path):
    checked_dir(path)
    require(path.stat().st_mode & 0o077 == 0, 'backup/journal directory must be 0700')
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
    require(not path.is_symlink(), 'journal path is symlink')
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
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1, 'unsafe lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LegacyUpgradeError('another legacy upgrade is active') from exc
        yield
    finally:
        os.close(fd)


def version_ok(value):
    require(isinstance(value, str) and RELEASE_RE.fullmatch(value),
            'unsupported or unknown source version; no automatic reinstall/downgrade')
    return value


def read_json(path: Path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_size <= 1024 * 1024 and st.st_nlink == 1,
            'invalid installed metadata')
    value = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(value, dict), 'installed metadata is not an object')
    return value


def client_source_version(root: Path, *, allow_target=False):
    """Use the native component-state record, not user-written demo manifests."""
    path = root / '.launcher' / 'component-update-state.json'
    require(path.is_file() and not path.is_symlink(),
            'no existing native component-update-state; legacy layout requires separate verified conversion')
    data = read_json(path)
    require(data.get('schemaVersion') == '1.0', 'unsupported component state schema')
    require(isinstance(data.get('components'), list) and len(data['components']) >= 3,
            'partial component-state is not an installed application')
    if allow_target and data.get('version') == TARGET:
        return TARGET
    return version_ok(data.get('version'))


def prestarter_source(root: Path):
    """Validate existing redundant installer slots; native verify-installed checks signatures."""
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
    require(slots, 'no valid existing Prestarter active slot')
    slots.sort(key=lambda row: row['generation'], reverse=True)
    return slots[0]


def native_binary_version(path: Path, *, allow_target=False):
    require(path.is_file() and not path.is_symlink(), 'installed executable missing')
    output = native.run([str(path), 'version'], timeout=30).decode('utf-8', errors='replace')
    matches = re.findall(r'(?<![\d.])0\.(?:45|46|47|48)\.\d+(?![\d.])', output)
    require(len(set(matches)) == 1, 'ambiguous executable version')
    if allow_target and matches[0] == TARGET:
        return TARGET
    return version_ok(matches[0])


def validate_data_path(root: Path, relative: str):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute() and '\\' not in relative,
            'protected data path must be relative to existing installation')
    pieces = Path(relative).parts
    require(all(part not in ('', '.', '..') for part in pieces) and pieces[0] not in ('.launcher', '.launcher-installer', '.launcher-prestarter'),
            'unsafe or managed state path in protected user data')
    path = root
    for part in pieces:
        path = path / part
        if path.exists() or path.is_symlink():
            require(not path.is_symlink(), 'symlink in protected data path')
    return root.joinpath(*pieces)


def enumerate_data(root: Path, names: list[str]):
    """Inspect every byte that is claimed protected; reject symlinks/devices."""
    require(len(set(names)) == len(names), 'duplicate protected user data path')
    for left in names:
        for right in names:
            if left != right and (right.startswith(left.rstrip('/') + '/')):
                raise LegacyUpgradeError('overlapping protected data paths')
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
            require(len(result) < MAX_FILES, 'user data inventory exceeds safe bound')
            st = path.lstat()
            require(st.st_nlink == 1 or stat.S_ISDIR(st.st_mode), 'hardlinked protected user file')
            if stat.S_ISDIR(st.st_mode):
                result[entry] = {'kind': 'dir', 'mode': stat.S_IMODE(st.st_mode)}
            elif stat.S_ISREG(st.st_mode):
                result[entry] = {'kind': 'file', 'size': st.st_size, 'sha256': sha_file(path),
                                 'mode': stat.S_IMODE(st.st_mode)}
            else:
                raise LegacyUpgradeError('symlink or special file in user data: ' + entry)
    require(result, 'no old user data located; supply --data for the actual installation layout')
    require(len(json.dumps(result)) < MAX_INVENTORY, 'user inventory too large')
    return result


def copy_data(root: Path, snapshot: Path, original: dict):
    """Independent copies, never hard links into mutable installation."""
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
            require(sha_file(dst) == info['sha256'], 'backup verification failed: ' + name)
    # Directory metadata is not an application release: byte content and mode are authoritative.
    for d in sorted((p for p in snapshot.rglob('*') if p.is_dir()), key=lambda p: -len(p.parts)):
        fsync_directory(d)
        d.chmod(original[d.relative_to(snapshot).as_posix()]['mode'] if d.relative_to(snapshot).as_posix() in original else 0o700)
    fsync_directory(snapshot)


def create_backup(root: Path, backup: Path, original: dict, source: str, operation: str, paths: list[str]):
    private_dir(backup.parent)
    require(not backup.exists() and not backup.is_symlink(), 'backup must not exist')
    stage = Path(tempfile.mkdtemp(prefix='.legacy-backup-', dir=backup.parent))
    try:
        (stage / 'user-data').mkdir(mode=0o700)
        copy_data(root, stage / 'user-data', original)
        atomic_json(stage / 'inventory.json', {'sourceVersion': source, 'targetVersion': TARGET,
                        'operation': operation, 'protectedPaths': paths, 'files': original})
        require(enumerate_data(stage / 'user-data', paths) == original,
                'backup byte-level readback mismatch')
        os.replace(stage, backup)
        fsync_directory(backup.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def run_updater(command: list[str], *, timeout=1800, json_response=False):
    # No stdout/stderr echo: may contain secrets and path-specific credentials.
    p = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    require(p.returncode == 0, f'updater {Path(command[0]).name} failed with exit {p.returncode}')
    if json_response:
        require(len(p.stdout) <= 1024 * 1024, 'native updater report oversized')
        return json.loads(p.stdout)
    return None


def verify_preservation(root: Path, original: dict, paths: list[str]):
    actual = enumerate_data(root, paths)
    require(actual == original, 'upgrade altered protected user data; restore from private backup before continuing')


def client_update(root: Path, args, source):
    require(args.cli and args.cli_sha256 and args.package and args.sha256 and args.delivery_manifest,
            'native signed package, pinned CLI SHA-256 and delivery manifest required')
    native.checked_file(Path(args.cli), args.cli_sha256)
    result = native.client_package(Path(args.cli), Path(args.package), args.sha256,
                                   Path(args.delivery_manifest), root, target_version=TARGET)
    require(client_source_version(root, allow_target=True) == TARGET, 'installed component state did not advance to target')
    return {'nativeStatus': result['nativeReport'].get('status'), 'components': ['Desktop', 'Runtime', 'Guard']}


def prestarter_update(root: Path, args, source):
    require(args.installer and args.installer_sha256 and args.bundle,
            'signed neverinstaller and its independently pinned SHA-256 and bundle required')
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
    require(new['generation'] > old['generation'], 'Prestarter installer did not advance generation')
    return {'nativeStatus': 'verified', 'component': 'Prestarter', 'newGeneration': new['generation']}


def host_update(root: Path, args, source):
    require(args.component in ('api', 'cli', 'bridge') and args.executable and args.install and args.sha256,
            'component, pinned executable, installation path and SHA-256 required')
    install = Path(args.install)
    require(install.is_absolute() and install.is_relative_to(root), 'host binary must reside under installed root')
    require(native_binary_version(install) == source, 'installed host binary version drift')
    result = native.host_binary(args.component, Path(args.executable), install, args.sha256,
                                service=args.service, ready_url=args.ready_url,
                                source_version=source, target_version=TARGET, backup_tag='0480')
    return {'nativeStatus': result['status'], 'component': args.component,
            'oldBinarySha256': result['fromSha256'], 'newBinarySha256': result['toSha256']}



def jar_metadata_version(jar: Path):
    """Read the real installed plugin descriptor; unknown formats fail closed."""
    require(jar.is_file() and not jar.is_symlink(), 'installed Bridge plugin missing')
    try:
        with zipfile.ZipFile(jar) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'duplicate JAR entries')
            require(archive.testzip() is None, 'Bridge JAR corrupt')
            for descriptor in ('plugin.yml', 'bungee.yml', 'velocity-plugin.json',
                               'fabric.mod.json', 'META-INF/MANIFEST.MF'):
                if descriptor not in archive.namelist():
                    continue
                raw = archive.read(descriptor)
                require(len(raw) <= 128*1024, 'Bridge descriptor oversized')
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
        raise LegacyUpgradeError('Bridge JAR metadata unreadable') from exc
    raise LegacyUpgradeError('Bridge JAR has no recognized embedded release; do not guess its version')


def bridge_jar_update(root: Path, args, source: str):
    require(os.geteuid() == 0, 'Java ServerBridge plugin requires root for managed systemd upgrade')
    require(args.plugin_type in BRIDGE_TARGETS and args.executable and args.install and args.service,
            'Bridge target, release JAR, installed JAR and systemd service required')
    require(args.release_manifest and args.manifest_sha256 and re.fullmatch('[a-f0-9]{64}', args.manifest_sha256),
            'externally approved SHA-256 of release manifest required')
    manifest_path, jar, install = Path(args.release_manifest), Path(args.executable), Path(args.install)
    require(manifest_path.is_file() and not manifest_path.is_symlink() and
            sha_file(manifest_path) == args.manifest_sha256, 'release manifest hash mismatch')
    native.checked_file(manifest_path, args.manifest_sha256, must_be_root=True)
    manifest = read_json(manifest_path)
    require(manifest.get('toolVersion') == TARGET, 'incorrect signed release-manifest version')
    rows = manifest.get('artifacts')
    require(isinstance(rows, list) and len(rows) == len(BRIDGE_TARGETS) and
            {r.get('id') for r in rows if isinstance(r, dict)} == BRIDGE_TARGETS,
            'incomplete or duplicated Bridge artifact matrix')
    row = next(r for r in rows if r['id'] == args.plugin_type)
    expected_name = f'launcher-{args.plugin_type}-bridge-{TARGET}.jar'
    require(row.get('file') == expected_name and jar.name == expected_name and
            re.fullmatch('[a-f0-9]{64}', row.get('sha256', '')),
            'Bridge release artifact name or checksum missing')
    native.checked_file(jar, row['sha256'], must_be_root=True)
    require(install.is_absolute() and install.is_relative_to(root) and
            install.parent.is_dir() and not install.parent.is_symlink() and
            install.parent.stat().st_uid == 0 and not install.parent.stat().st_mode & 0o022,
            'plugin installation directory must be root-owned and protected')
    require(native.SERVICE_RE.fullmatch(args.service), 'invalid systemd service')
    require(jar_metadata_version(jar) == TARGET, 'new Bridge JAR embeds the wrong version')
    require(jar_metadata_version(install) == source, 'installed Bridge JAR release drift')
    require(native.systemctl_is_active(args.service), 'Bridge must be active before cutover')
    oldstat = install.lstat()
    require(stat.S_ISREG(oldstat.st_mode) and oldstat.st_nlink == 1 and oldstat.st_uid == 0,
            'unsafe installed Bridge JAR')
    backup = install.with_name(install.name + '.previous-0480')
    require(not backup.exists() and not backup.is_symlink(), 'previous JAR backup exists')
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
            require(sha_file(Path(stage)) == row['sha256'], 'Bridge staged JAR hash mismatch')
            os.replace(stage, install)
            native.fsync_dir(install.parent)
        finally:
            if os.path.exists(stage):
                os.unlink(stage)
        require(jar_metadata_version(install) == TARGET, 'installed new Bridge JAR corrupt')
        native.run(['systemctl', 'start', args.service], timeout=90)
        require(native.systemctl_is_active(args.service), 'Bridge did not restart successfully')
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
            require(sha_file(install) == oldsha, 'old Bridge JAR recovery checksum mismatch')
            native.run(['systemctl', 'start', args.service], timeout=90)
            require(native.systemctl_is_active(args.service), 'old Bridge JAR restart failed')
        except Exception as restore_exc:
            raise LegacyUpgradeError('Bridge update AND rollback failed; keep server offline') from restore_exc
        raise LegacyUpgradeError('Bridge update failed; prior JAR restored') from exc


def determine_source(mode, root, args):
    if mode == 'client':
        detected = client_source_version(root)
    elif mode == 'prestarter':
        prestarter_source(root)
        # Prestarter records have opaque signed release hashes rather than SemVer.
        # If client state is unavailable, only a pinned operator input plus the
        # actual native verify-installed can establish an upgrade source.
        state = root / '.launcher' / 'component-update-state.json'
        if state.exists():
            detected = client_source_version(root)
        else:
            require(args.from_version, 'Prestarter source version is opaque: --from-version required')
            detected = version_ok(args.from_version)
    elif mode == 'bridge-jar':
        require(args.install, 'installed Bridge JAR required')
        detected = version_ok(jar_metadata_version(Path(args.install)))
    elif mode == 'host':
        detected = native_binary_version(Path(args.install))
    else:
        raise LegacyUpgradeError('unsupported upgrade mode')
    if args.from_version:
        require(args.from_version == detected, 'declared source release differs from installed release')
    return detected


def backend_upgrade(args):
    require(args.project and args.confirm and args.source_env and args.target_env,
            'existing Compose project, confirmation and pinned source/target environments required')
    source_env, target_env = Path(args.source_env).absolute(), Path(args.target_env).absolute()
    source_settings, detected = native.read_version(source_env)
    version_ok(detected)
    if args.from_version:
        require(args.from_version == detected, 'source environment differs from expected version')
    native.assert_same_config(source_env, target_env, source_version=detected, target_version=TARGET)
    snapshot = Path(args.backup).absolute()
    require(not snapshot.exists(), 'new private native DR checkpoint path required')
    result = native.standard(args.project, args.confirm, source_env, target_env, snapshot,
                             production=args.production_source, approved=args.maintenance_approved,
                             source_version=detected, target_version=TARGET)
    require(result.get('status') == 'upgraded' and result.get('backendVerified') is True,
            'native backend upgrade did not pass its actual health checks')
    return {'status': 'upgraded', 'sourceVersion': detected, 'targetVersion': TARGET,
            'mode': 'backend', 'snapshot': str(snapshot), 'nativeResult': result}



def rollback_host(args):
    """Recover a 0.48.0 Linux executable using the original pinned backup receipt."""
    require(args.root and args.install and args.component in ('api', 'cli', 'bridge'),
            'host rollback requires existing root, installed binary and component')
    root = checked_dir(Path(args.root).absolute())
    backup = Path(args.backup).absolute()
    private_dir(backup.parent)
    with exclusive(backup.parent):
        journal = read_json(backup / 'journal.json')
        require(journal.get('schema') == 1 and journal.get('mode') == 'host'
                and journal.get('root') == str(root) and journal.get('target') == TARGET,
                'backup does not belong to requested host upgrade')
        phase = journal.get('phase')
        require(phase in ('verified', 'manual-reconciliation-required'),
                'upgrade has not reached a recoverable phase')
        result = journal.get('result')
        # Если переключение не зарегистрировало завершённую смену бинарника,
        # независимо считайте закреплённый старый дайджест из исходного сохранённого
        # файла резервной копии.
        sha = result.get('oldBinarySha256') if isinstance(result, dict) else None
        require(sha and re.fullmatch('[a-f0-9]{64}', sha),
                'no verified prior binary SHA in committed receipt; use native forensic recovery')
        install = Path(args.install)
        require(install.is_absolute() and install.is_relative_to(root), 'unsafe installed binary path')
        require(result.get('component') == args.component, 'component mismatch with receipt')
        restored = native.rollback_linux_host(args.component, install, sha, service=args.service,
                    ready_url=args.ready_url, source_version=journal['source'], backup_tag='0480')
        inventory = read_json(backup / 'inventory.json')
        require(inventory.get('files') and inventory.get('protectedPaths'),
                'original user-data inventory absent')
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
    require(args.root, 'existing installation root required')
    root = checked_dir(Path(args.root).absolute())
    backup = Path(args.backup).absolute()
    private_dir(backup.parent)
    require(not backup.is_relative_to(root) and not root.is_relative_to(backup),
            'backup must be outside the installation tree')
    with exclusive(backup.parent):
        require(not backup.exists(), 'backup already exists; do not replay or overwrite an attempted upgrade')
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
    parser.add_argument('--root', help='existing installation (no new install)')
    parser.add_argument('--backup', required=True, help='new external directory under protected 0700 parent')
    parser.add_argument('--data', action='append', help='relative immutable user-data path; repeat for all user directories')
    parser.add_argument('--from-version', help='independently pinned old release, checked against installed state')
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
        print('legacy upgrade blocked: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
