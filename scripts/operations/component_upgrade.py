#!/usr/bin/env python3
"""Operational component cutover, reusing NeverLauncher's actual updaters.

Standard: validated PostgreSQL cold checkpoint, API/Admin image switch and rollback.
Linux host: byte-verified CLI/ServerBridge update with crash-safe atomic replacement.
Desktop: delegate verified production component package to `nl update components`.
Extensions: invoke existing transactional server-side extension updater with fresh MFA.
No automatic database migrations, no bypass of release signatures or trust gates.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
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
from urllib.parse import urlsplit

import dr_03512 as dr
import db_upgrade_0457 as database

TARGET = '0.45.8'
SOURCE = '0.45.7'
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
SERVICE_RE = re.compile(r'^[A-Za-z0-9_.@-]+\.service$')
COMPONENTS = {'api', 'cli', 'bridge'}

class ComponentError(RuntimeError):
    pass


def must(test, message):
    if not test:
        raise ComponentError(message)


def run(args, *, timeout=600, env=None):
    # Никогда не выводите argv или stdout/stderr подпроцесса: в них могут быть
    # учётные данные.
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=timeout, env=env)
    if result.returncode:
        raise ComponentError(f'{args[0]} failed (exit={result.returncode})')
    return result.stdout


def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as inp:
        for buf in iter(lambda: inp.read(1024 * 1024), b''):
            sha.update(buf)
    return sha.hexdigest()


def checked_file(path: Path, sha: str, *, must_be_root=False):
    must(SHA_RE.fullmatch(sha) is not None, 'pinned SHA-256 must be 64 lowercase hexadecimal characters')
    st = path.lstat()
    must(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size > 0,
         'source must be a nonempty regular file (no symlink/hardlink)')
    if must_be_root:
        must(st.st_uid == 0 and not (st.st_mode & 0o022), 'source must be immutable to non-root users')
    must(digest(path) == sha, 'pinned SHA-256 mismatch')


def read_version(env_file):
    must(env_file.is_file() and not env_file.is_symlink(), 'environment file missing or symlinked')
    must(not env_file.stat().st_mode & 0o077, 'production environment file must be private')
    data = database.env_values(env_file)
    return data, data.get('LAUNCHER_IMAGE_TAG', '')


def assert_same_config(before, after, *, source_version=SOURCE, target_version=TARGET):
    old, version = read_version(before)
    new, target = read_version(after)
    must(version == source_version and target == target_version and version != target,
         'source/target versions do not match pinned upgrade intent')
    must(new.get('LAUNCHER_DATABASE_AUTO_MIGRATE') == 'false', 'automatic DDL is forbidden during component upgrade')
    # При переключении не меняйте одновременно учётные данные, хранилище, DNS, ключи
    # или политику подписи; для них нужны отдельные аудируемые операции.
    allowed = {'LAUNCHER_IMAGE_TAG', 'LAUNCHER_DATABASE_AUTO_MIGRATE'}
    must(all(old.get(key, '') == new.get(key, '') for key in set(old) | set(new) if key not in allowed),
         'source and target environment differ beyond image version and auto-migrate')
    return version


def image_id(tag):
    result = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag], timeout=30)
    value = result.decode('ascii', errors='strict').strip()
    must(value.startswith('sha256:') and SHA_RE.fullmatch(value[7:]) is not None, 'invalid image ID')
    return value


def verify_service_image(project, env, service, expected_version):
    """Check the actual running container ID, not merely a mutable image tag."""
    image_type = 'admin' if service == 'admin' else 'api'
    expected = image_id(f'launcher-{image_type}:{expected_version}')
    container = dr.compose(project, env, 'ps', '-q', service, timeout=30).stdout.decode('ascii').strip()
    must(re.fullmatch(r'[0-9a-f]{12,64}', container) is not None, 'running service container ID missing')
    actual = run(['docker', 'inspect', '--format', '{{.Image}}', container], timeout=30).decode('ascii').strip()
    must(actual == expected, 'running container uses unexpected image digest: ' + service)


def check_admin(project, env):
    result = dr.compose(project, env, 'exec', '-T', 'admin', 'wget', '-qO-',
                        'http://127.0.0.1:8080/', timeout=30).stdout
    must(b'<html' in result.lower() and len(result) > 80, 'Admin did not serve actual HTML')


def check_nginx(project, env):
    states = dr.compose_states(project, env)
    must(states.get('nginx') == 'running', 'Nginx has not started')
    dr.compose(project, env, 'exec', '-T', 'nginx', 'wget', '-qO-',
               'http://127.0.0.1/health', timeout=30)


def restore_service_set(project, env, original, *, expected):
    # Сначала обязательно поднимайте Admin/API. Не открывайте непроверенную целевую
    # версию через Nginx.
    for svc in ('admin', 'api'):
        if svc in original:
            dr.compose(project, env, 'up', '-d', '--no-build', '--force-recreate', svc)
    for svc in ('api', 'admin'):
        if svc in original:
            verify_service_image(project, env, svc, expected)
    if 'api' in original:
        dr.check_restored_backend(project, env, version=expected, storage='local')
    if 'admin' in original:
        check_admin(project, env)
    if 'nginx' in original:
        dr.compose(project, env, 'up', '-d', '--no-build', '--force-recreate', 'nginx')
        check_nginx(project, env)


def standard(project, confirm, source, target, snapshot, *, production=False, approved=False,
             source_version=SOURCE, target_version=TARGET):
    must(not dr.COMPOSE_PROFILES, 'component Standard updater refuses Network-HA overlays')
    dr.authorize_project(project, confirm, production=production, approved=approved)
    assert_same_config(source, target, source_version=source_version, target_version=target_version)
    must(snapshot.is_absolute() and not snapshot.exists() and snapshot.parent.is_dir()
         and not snapshot.parent.is_symlink(), 'snapshot must be an unused path on protected storage')
    must(snapshot.parent.stat().st_mode & 0o077 == 0, 'snapshot parent must be private (0700)')
    with database.lock(snapshot.parent):
        states = dr.compose_states(project, source)
        must(states.get('postgres') == 'running' and states.get('api') == 'running', 'source PostgreSQL/API must be running')
        must(not any(states.get(s) == 'running' for s in ('api-b', 'worker-a', 'worker-b', 'redis')),
             'unexpected Network-HA roles; cannot upgrade as Standard')
        for svc in ('api', 'admin', 'nginx'):
            must(states.get(svc, 'exited') not in ('paused', 'restarting'), 'unhealthy source service: ' + svc)
        original = [svc for svc in ('api', 'admin', 'nginx') if states.get(svc) == 'running']
        dr.check_restored_backend(project, source, version=source_version, storage='local')
        # Создайте и определите настоящие заменяющие образы ДО остановки работающего приложения.
        dr.compose(project, target, 'build', 'api', 'admin', timeout=2400)
        target_images = {svc: image_id('launcher-' + svc + ':' + target_version) for svc in ('api', 'admin')}
        source_images = {svc: image_id('launcher-' + svc + ':' + source_version) for svc in ('api', 'admin')}
        must(all(source_images[s] != target_images[s] for s in source_images), 'replacement image equals old image')
        # При ошибке snapshot() самостоятельно возобновляет ранее работавшие службы.
        dr.snapshot(project, source, snapshot, confirm, production=production,
                    approved=approved, resume_after=False, source_version=source_version)
        try:
            receipt = dr.verify_snapshot(snapshot)
            # Обнаруживайте внешнюю запись, даже если соответствующая сессия быстро
            # отключилась.
            must(dr.assert_quiescent(project, source) == receipt['postgresWalLsn'],
                 'PostgreSQL WAL advanced since component backup')
            must(all(image_id('launcher-' + svc + ':' + target_version) == target_images[svc]
                     for svc in target_images), 'target image changed after build')
            restore_service_set(project, target, original, expected=target_version)
            return {'status': 'upgraded', 'from': source_version, 'to': target_version,
                    'components': ['api', 'admin'], 'backup': str(snapshot),
                    'images': target_images, 'backendVerified': True}
        except Exception as problem:
            # Остановите всех потенциальных новых записывающих клиентов, прежде чем
            # рассматривать откат.
            for svc in ('nginx', 'admin', 'api'):
                try:
                    dr.compose(project, target, 'stop', '-t', '30', svc)
                except Exception:
                    pass
            try:
                # Переключение компонентов не переносит схему. Не восстанавливайте незаметно
                # старую базу данных с потерей подтверждённых записей, сделанных после снимка.
                must(all(image_id('launcher-' + svc + ':' + source_version) == source_images[svc]
                         for svc in source_images), 'source image digest changed; rollback unsafe')
                restore_service_set(project, source, original, expected=source_version)
            except Exception as recovery:
                raise ComponentError('component cutover failed AND old API could not be verified; keep Nginx stopped') from recovery
            raise ComponentError('component cutover failed; prior application images restored and verified') from problem



@contextmanager
def network_overlay():
    """Scope HA Compose configuration: no global mutation leaks into other operations."""
    old_files = dr.COMPOSE_FILES[:]
    old_profiles = dr.COMPOSE_PROFILES[:]
    try:
        dr.COMPOSE_FILES[:] = [dr.COMPOSE, dr.ROOT / 'deploy/production/docker-compose.network-ha.yml']
        dr.COMPOSE_PROFILES[:] = ['network-ha']
        yield
    finally:
        dr.COMPOSE_FILES[:] = old_files
        dr.COMPOSE_PROFILES[:] = old_profiles


def restore_ha_roles(project, env, *, expected):
    # Сохранённое состояние Redis остаётся при переключении только компонентов на
    # месте, в отличие от аварийного восстановления. Существующее разграничение
    # доступа Backend/Bridge продолжает действовать.
    dr.compose(project, env, 'up', '-d', '--no-build', 'redis')
    for svc in ('api', 'api-b', 'worker-a', 'worker-b', 'admin'):
        dr.compose(project, env, 'up', '-d', '--no-build', '--force-recreate', svc)
    for svc in ('api', 'api-b', 'worker-a', 'worker-b', 'admin'):
        verify_service_image(project, env, svc, expected)
    for svc in ('api', 'api-b'):
        dr.check_restored_backend(project, env, version=expected, storage='s3', service=svc)
    for svc in ('worker-a', 'worker-b'):
        dr.check_restored_worker_0455(project, env, svc)
    check_admin(project, env)
    dr.compose(project, env, 'up', '-d', '--no-build', '--force-recreate', 'nginx')
    check_nginx(project, env)


def network_ha(project, confirm, source, target, snapshot, world_backups,
               s3_bucket, s3_endpoint, *, production=False, approved=False,
               source_version=SOURCE, target_version=TARGET):
    """Cold component-only cutover; never restores old Redis leases or rewinds PG.

    World writers must already be stopped; DR validates their cold backups.
    This does NOT upgrade PostgreSQL schemas and is not a rolling upgrade.
    """
    dr.authorize_project(project, confirm, production=production, approved=approved)
    assert_same_config(source, target, source_version=source_version, target_version=target_version)
    must(world_backups and s3_bucket, 'HA upgrade requires confirmed stopped worlds and S3 snapshot')
    must(snapshot.is_absolute() and not snapshot.exists() and snapshot.parent.is_dir()
         and not snapshot.parent.is_symlink() and not (snapshot.parent.stat().st_mode & 0o077),
         'HA backup must be new and stored in private directory')
    with network_overlay(), database.lock(snapshot.parent):
        states = dr.compose_states(project, source)
        must(all(states.get(s) == 'running' for s in ('postgres', 'redis', 'api', 'api-b', 'worker-a', 'worker-b', 'admin', 'nginx')),
             'all Network-HA roles must be healthy/running before cutover')
        for svc in ('api', 'api-b'):
            dr.check_restored_backend(project, source, version=source_version, storage='s3', service=svc)
        for svc in ('worker-a', 'worker-b'):
            dr.check_restored_worker_0455(project, source, svc)
        dr.compose(project, target, 'build', 'api', 'admin', timeout=2400)
        new_images = {s: image_id('launcher-' + s + ':' + target_version) for s in ('api', 'admin')}
        old_images = {s: image_id('launcher-' + s + ':' + source_version) for s in ('api', 'admin')}
        must(all(new_images[s] != old_images[s] for s in new_images), 'new HA images equal previous images')
        dr.snapshot(project, source, snapshot, confirm, s3_bucket=s3_bucket, s3_endpoint=s3_endpoint,
                    production=production, approved=approved, world_backups=world_backups,
                    resume_after=False, source_version=source_version)
        try:
            receipt = dr.verify_snapshot(snapshot)
            must(dr.assert_quiescent(project, source) == receipt['postgresWalLsn'],
                 'PostgreSQL WAL advanced since HA component backup')
            must(all(image_id('launcher-' + s + ':' + target_version) == new_images[s] for s in new_images),
                 'HA target images changed after backup')
            restore_ha_roles(project, target, expected=target_version)
            return {'status': 'upgraded', 'mode': 'network-ha', 'from': source_version, 'to': target_version,
                    'components': ['api', 'api-b', 'worker-a', 'worker-b', 'admin'],
                    'snapshot': str(snapshot), 'images': new_images, 'runtimeVerified': True}
        except Exception as cause:
            for svc in ('nginx', 'admin', 'worker-a', 'worker-b', 'api', 'api-b'):
                try:
                    dr.compose(project, target, 'stop', '-t', '30', svc)
                except Exception:
                    pass
            try:
                must(all(image_id('launcher-' + s + ':' + source_version) == old_images[s] for s in old_images),
                     'previous HA image was replaced')
                restore_ha_roles(project, source, expected=source_version)
            except Exception as failure:
                raise ComponentError('HA cutover and prior-version recovery both failed; Nginx must stay disabled') from failure
            raise ComponentError('HA component cutover failed; original binaries restored and checked') from cause

def systemctl_is_active(service):
    return subprocess.run(['systemctl', 'is-active', '--quiet', service], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def host_binary(component, source: Path, install: Path, checksum, *, service=None, ready_url=None,
                source_version=SOURCE, target_version=TARGET, backup_tag='0458'):
    """Atomic executable replacement with verified rollback on service failure.

    Must be run as root in a controlled maintenance window; the old executable
    is moved to a private backup next to its installed path (same filesystem).
    """
    must(os.geteuid() == 0, 'host executable upgrade requires root')
    must(re.fullmatch(r'0\.\d+\.\d+', source_version) and re.fullmatch(r'0\.\d+\.\d+', target_version),
         'source/target binary version invalid')
    must(re.fullmatch(r'\d{4}', backup_tag), 'invalid backup tag')
    must(component in COMPONENTS, 'unsupported host component')
    must(component != 'api' or service == 'launcher.service', 'minimal API must use managed launcher.service')
    must(component != 'bridge' or bool(service), 'ServerBridge upgrade requires a systemd unit')
    must(install.is_absolute() and source.is_absolute(), 'binary paths must be absolute')
    must(install != source and install.parent.is_dir(), 'source must differ from destination')
    must(not install.parent.is_symlink() and install.parent.stat().st_uid == 0
         and not install.parent.stat().st_mode & 0o022, 'install directory must be root owned and protected')
    checked_file(source, checksum, must_be_root=True)
    old = install.lstat()
    must(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and old.st_nlink == 1
         and not (old.st_mode & 0o022), 'existing binary must be root-owned regular file')
    must(not install.with_name(install.name + '.previous-' + backup_tag).exists(), 'previous backup exists; resolve prior upgrade first')
    if service:
        must(SERVICE_RE.fullmatch(service) is not None, 'invalid systemd service')
    old_active = bool(service and systemctl_is_active(service))
    must(component != 'api' or old_active, 'managed API must be running for verified cutover')
    backup = install.with_name(install.name + '.previous-' + backup_tag)
    with database.lock(install.parent):
        # Нельзя сочетать работающий процесс Runtime с частично скопированным файлом.
        if old_active:
            run(['systemctl', 'stop', service], timeout=90)
        os.replace(install, backup)
        fsync_dir(install.parent)
        try:
            with source.open('rb') as reader:
                fd, stage = tempfile.mkstemp(prefix='.launcher-component-', dir=install.parent)
                try:
                    with os.fdopen(fd, 'wb') as out:
                        shutil.copyfileobj(reader, out, length=1024 * 1024)
                        out.flush(); os.fchmod(out.fileno(), 0o755); os.fsync(out.fileno())
                    must(digest(Path(stage)) == checksum, 'staged binary digest changed')
                    os.replace(stage, install); fsync_dir(install.parent)
                finally:
                    if os.path.exists(stage):
                        os.unlink(stage)
            if component != 'api':
                version_output = run([str(install), 'version'], timeout=30).decode('utf-8', errors='replace')
                must(target_version in version_output, 'new CLI/Bridge executable reports unexpected version')
            if old_active:
                run(['systemctl', 'start', service], timeout=90)
                must(systemctl_is_active(service), 'upgraded systemd service is not active')
                if component == 'api':
                    database.wait_loopback_ready(ready_url or 'http://127.0.0.1:8080/ready', expected_version=target_version)
            elif component == 'api':
                raise ComponentError('minimal API service must be active for verified cutover')
            return {'status': 'upgraded', 'component': component,
                    'fromSha256': digest(backup), 'toSha256': checksum,
                    'rollbackExecutable': str(backup), 'serviceVerified': bool(old_active)}
        except Exception as error:
            if service:
                try:
                    run(['systemctl', 'stop', service], timeout=60)
                except Exception:
                    pass
            try:
                if install.exists():
                    install.unlink()
                os.replace(backup, install); fsync_dir(install.parent)
                if old_active:
                    run(['systemctl', 'start', service], timeout=90)
                    must(systemctl_is_active(service), 'old service failed after rollback')
                    if component == 'api':
                        database.wait_loopback_ready(ready_url or 'http://127.0.0.1:8080/ready', expected_version=source_version)
            except Exception as rollback_error:
                raise ComponentError('host upgrade failed; previous executable could not be verified, service must stay down') from rollback_error
            raise ComponentError('host upgrade failed, old binary restored') from error


def rollback_linux_host(component, install: Path, expected_previous_sha, *, service=None,
                        ready_url='http://127.0.0.1:8080/ready', source_version=SOURCE, backup_tag='0458'):
    """Explicit recovery after a process crash or a completed-but-bad rollout.

    Never accept an unidentified `.previous` byte sequence. A rollback keeps
    the 0.45.8 executable in a separate `.failed` file for incident analysis.
    """
    must(os.geteuid() == 0, 'host rollback requires root')
    must(re.fullmatch(r'0\.\d+\.\d+', source_version) and re.fullmatch(r'\d{4}', backup_tag),
         'invalid rollback version/tag')
    must(component in COMPONENTS, 'unsupported host component')
    must(install.is_absolute() and install.parent.is_dir()
         and not install.parent.is_symlink() and install.parent.stat().st_uid == 0
         and not install.parent.stat().st_mode & 0o022, 'unsafe host rollback destination')
    must(component != 'api' or service == 'launcher.service', 'minimal API must use launcher.service')
    must(component != 'bridge' or bool(service), 'ServerBridge rollback requires its systemd service')
    if service:
        must(SERVICE_RE.fullmatch(service) is not None, 'invalid systemd service')
    backup = install.with_name(install.name + '.previous-' + backup_tag)
    failed = install.with_name(install.name + '.failed-' + backup_tag)
    checked_file(backup, expected_previous_sha, must_be_root=True)
    must(not failed.exists() and not failed.is_symlink(), 'prior failed binary exists; manual intervention required')
    with database.lock(install.parent):
        was_active = bool(service and systemctl_is_active(service))
        if was_active:
            run(['systemctl', 'stop', service], timeout=90)
        have_current = install.exists() or install.is_symlink()
        if have_current:
            st = install.lstat()
            must(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1,
                 'current binary path is unsafe')
            os.replace(install, failed)
        os.replace(backup, install)
        fsync_dir(install.parent)
        try:
            must(digest(install) == expected_previous_sha, 'restored old bytes mismatch')
            if component != 'api':
                must(source_version in run([str(install), 'version'], timeout=30).decode('utf-8'),
                     'old CLI/Bridge version does not match')
            if was_active:
                run(['systemctl', 'start', service], timeout=90)
                must(systemctl_is_active(service), 'old service did not restart')
                if component == 'api':
                    database.wait_loopback_ready(ready_url, expected_version=SOURCE)
            return {'status': 'rolled-back', 'component': component,
                    'restoredSha256': expected_previous_sha, 'failedExecutable': str(failed) if have_current else None,
                    'serviceVerified': was_active}
        except Exception as problem:
            # Предыдущий исполняемый файл остаётся на диске для явного восстановления
            # оператором; никогда незаметно не запускайте снова непроверенную версию
            # 0.45.8.
            if service:
                try:
                    run(['systemctl', 'stop', service], timeout=60)
                except Exception:
                    pass
            raise ComponentError('old executable restored but health/version not verified; service must stay stopped') from problem


def client_package(cli: Path, package: Path, checksum, delivery: Path, root: Path, *, target_version=TARGET):
    """Calls the existing signed transactional component updater; not an alternate installer."""
    must(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'existing client installation root required')
    must(delivery.is_file() and not delivery.is_symlink(), 'independently approved delivery manifest required')
    checked_file(package, checksum)
    must(cli.is_file() and not cli.is_symlink(), 'installed NeverLauncher CLI required')
    output = run([str(cli), 'update', 'components', '--package', str(package),
                  '--expected-sha256', checksum, '--delivery-manifest', str(delivery),
                  '--root', str(root)], timeout=900)
    try:
        report = json.loads(output)
    except ValueError as exc:
        raise ComponentError('native updater did not return JSON report') from exc
    must(isinstance(report, dict) and report.get('status') == 'committed'
         and report.get('toVersion') == target_version, 'native updater did not commit required version')
    # Существующая проверка пакета обновления проверяет хеши каждого файла, подпись,
    # эпоху доверия, идентичность платформы и журнал отката. Эти проверки здесь не
    # переопределяются.
    return {'status': 'upgraded', 'nativeReport': report}


def extensions(cli: Path, backend: str, coords: list[str], channel: str):
    must(coords and all(re.fullmatch(r'[a-zA-Z0-9_.-]+@[0-9A-Za-z.+-]+', x) for x in coords),
         'supply explicit extension id@version coordinates')
    url = urlsplit(backend)
    must(url.scheme == 'https' and bool(url.hostname) and not url.username and not url.password
         and not url.query and not url.fragment and not url.path.rstrip('/'),
         'production extension backend must be an HTTPS origin')
    must(channel in ('stable', 'beta'), 'invalid extension channel')
    must(cli.is_file() and not cli.is_symlink(), 'NeverLauncher CLI missing')
    must(bool(os.environ.get('LAUNCHER_TOKEN')), 'provide a fresh MFA-authorized LAUNCHER_TOKEN in the operator environment')
    base = [str(cli), 'extension', 'updates']
    flags = ['--backend', backend, '--channel', channel]
    planned = json.loads(run(base + ['plan', *coords, *flags], timeout=120))
    must(isinstance(planned, dict) and isinstance(planned.get('data', {}).get('plan'), dict),
         'server did not produce a real extension plan')
    applied = json.loads(run(base + ['apply', *coords, *flags], timeout=360))
    tx = applied.get('data', {}).get('transaction') if isinstance(applied, dict) else None
    must(isinstance(tx, dict) and tx.get('status') in ('succeeded', 'completed'),
         'extension transaction did not commit')
    return {'status': 'upgraded', 'transactionId': tx.get('id'), 'extensions': coords}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    standard_cmd = sub.add_parser('standard', help='upgrade Standard API/Admin Compose images with cold backup and rollback')
    for key in ('project', 'confirm', 'source-env', 'target-env', 'backup'):
        standard_cmd.add_argument('--' + key, required=True,
                                  type=Path if key.endswith('env') or key == 'backup' else str)
    standard_cmd.add_argument('--from-version', default=SOURCE)
    standard_cmd.add_argument('--to-version', default=TARGET)
    standard_cmd.add_argument('--production-source', action='store_true')
    standard_cmd.add_argument('--maintenance-approved', action='store_true')
    ha = sub.add_parser('network-ha', help='cold upgrade of both APIs, both workers and Admin with world/S3 checkpoint')
    for key in ('project', 'confirm', 'source-env', 'target-env', 'backup', 's3-bucket'):
        ha.add_argument('--' + key, required=True, type=Path if key.endswith('env') or key == 'backup' else str)
    ha.add_argument('--s3-endpoint')
    ha.add_argument('--world-backup', action='append', required=True, metavar='NAME=BACKUP_ID_DIRECTORY')
    ha.add_argument('--from-version', default=SOURCE)
    ha.add_argument('--to-version', default=TARGET)
    ha.add_argument('--production-source', action='store_true')
    ha.add_argument('--maintenance-approved', action='store_true')
    native = sub.add_parser('linux-host', help='atomically upgrade real root-owned CLI/ServerBridge executable')
    native.add_argument('--component', choices=sorted(COMPONENTS), required=True)
    native.add_argument('--source', type=Path, required=True)
    native.add_argument('--install', type=Path, required=True)
    native.add_argument('--sha256', required=True)
    native.add_argument('--service', help='systemd unit for ServerBridge or minimal API')
    native.add_argument('--ready-url', default='http://127.0.0.1:8080/ready', help='minimal API readiness probe')
    rollback = sub.add_parser('rollback-linux-host', help='recover pinned previous host executable after failed/crashed upgrade')
    rollback.add_argument('--component', choices=sorted(COMPONENTS), required=True)
    rollback.add_argument('--install', type=Path, required=True)
    rollback.add_argument('--previous-sha256', required=True)
    rollback.add_argument('--service')
    rollback.add_argument('--ready-url', default='http://127.0.0.1:8080/ready')
    client = sub.add_parser('client', help='install signed Desktop/Runtime/Guard update via existing CLI')
    client.add_argument('--cli', type=Path, required=True)
    client.add_argument('--package', type=Path, required=True)
    client.add_argument('--sha256', required=True)
    client.add_argument('--delivery-manifest', type=Path, required=True)
    client.add_argument('--root', type=Path, required=True)
    ext = sub.add_parser('extensions', help='use real server-side extension transaction and health verification')
    ext.add_argument('--cli', type=Path, required=True)
    ext.add_argument('--backend', required=True)
    ext.add_argument('--channel', default='stable')
    ext.add_argument('coordinates', nargs='+')
    args = parser.parse_args(argv)
    try:
        if args.action == 'standard':
            result = standard(args.project, args.confirm, args.source_env.absolute(),
                              args.target_env.absolute(), args.backup.absolute(),
                              production=args.production_source, approved=args.maintenance_approved,
                              source_version=args.from_version, target_version=args.to_version)
        elif args.action == 'network-ha':
            result = network_ha(args.project, args.confirm, args.source_env.absolute(),
                                args.target_env.absolute(), args.backup.absolute(),
                                dr.parse_world_args(args.world_backup), args.s3_bucket, args.s3_endpoint,
                                production=args.production_source, approved=args.maintenance_approved,
                                source_version=args.from_version, target_version=args.to_version)
        elif args.action == 'linux-host':
            result = host_binary(args.component, args.source.absolute(), args.install.absolute(), args.sha256,
                                 service=args.service, ready_url=args.ready_url)
        elif args.action == 'rollback-linux-host':
            result = rollback_linux_host(args.component, args.install.absolute(), args.previous_sha256,
                                         service=args.service, ready_url=args.ready_url)
        elif args.action == 'client':
            result = client_package(args.cli.absolute(), args.package.absolute(), args.sha256,
                                    args.delivery_manifest.absolute(), args.root.absolute())
        else:
            result = extensions(args.cli.absolute(), args.backend, args.coordinates, args.channel)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ComponentError, dr.DrillError, database.UpgradeError, ValueError, OSError,
            subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError) as exc:
        print('component upgrade blocked: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
