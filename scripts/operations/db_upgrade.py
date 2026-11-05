#!/usr/bin/env python3
"""0.45.7: управляемое обновление схемы для существующей минимальной SQLite и Compose PostgreSQL.

Перед выполнением *настоящей* роли миграции нового Backend нужно создать холодную проверенную
резервную копию, хранящуюся независимо. Неудачная миграция или проверка готовности восстановленной
службы возвращает старую схему и приложение (либо оставляет всё остановленным, если восстановление
нельзя подтвердить). Утилита выполняется на хосте владельца БД в одобренное окно обслуживания.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from urllib.error import URLError, HTTPError
from urllib.request import build_opener, ProxyHandler

import dr_03512 as dr

MINIMAL_BACKUP = Path(__file__).resolve().parents[1] / 'install/minimal_backup.py'
TARGET = '0.45.7'
ROLES = ('api', 'api-b', 'worker-a', 'worker-b', 'admin', 'nginx')
UPGRADE_LOCK = '.launcher-db-upgrade.lock'

class UpgradeError(RuntimeError):
    pass


def require(condition: bool, message: str):
    if not condition:
        raise UpgradeError(message)


def exec_checked(command: list[str], *, timeout=1800):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        # Вывод инструментов может содержать учётные данные; никогда не печатайте
        # необработанные stdout/stderr.
        raise UpgradeError(f'{command[0]} exited {result.returncode}')
    return result.stdout


@contextmanager
def lock(directory: Path):
    directory = directory.resolve(strict=True)
    require(directory.is_dir() and not directory.is_symlink(), 'lock directory must exist')
    fd = os.open(directory / UPGRADE_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1, 'unsafe upgrade lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UpgradeError('Другое обновление базы данных уже выполняется') from exc
        yield
    finally:
        os.close(fd)


def schema_check_sqlite(root: Path, *, target_version: int | None = None):
    paths = [root / 'db/http.sqlite', root / 'db/coordinator.sqlite']
    for i, path in enumerate(paths):
        require(path.is_file() and not path.is_symlink(), 'SQLite database absent or unsafe')
        connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            require(connection.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SQLite integrity failed')
            require(connection.execute('PRAGMA foreign_key_check').fetchone() is None, 'SQLite foreign key check failed')
            if i == 0:
                version = connection.execute('PRAGMA user_version').fetchone()[0]
                require(version > 0, 'SQLite core schema is missing')
                if target_version is not None:
                    require(version == target_version, f'SQLite schema {version} != expected {target_version}')
            else:
                require(connection.execute("SELECT value FROM coord_meta WHERE key='version'").fetchone() == (1,), 'SQLite coordinator schema incompatible')
        finally:
            connection.close()


def wait_loopback_ready(url: str, *, timeout: int = 90, expected_version: str | None = None):
    require(re.fullmatch(r'http://127\.0\.0\.1:[0-9]{2,5}/ready', url) is not None,
            'SQLite health probe must be loopback HTTP /ready')
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=3) as response:
                payload = json.load(response)
                if (response.status == 200 and payload.get('status') == 'ready'
                        and isinstance(payload.get('version'), str)
                        and (expected_version is None or payload.get('version') == expected_version)):
                    return payload['version']
        except (URLError, HTTPError, TimeoutError, ValueError, OSError):
            pass
        time.sleep(1)
    raise UpgradeError('Backend SQLite не перешёл в состояние готовности после обновления схемы')


def run_minimal_backup(root: Path, destination: Path, service_user: str):
    exec_checked(['runuser', '-u', service_user, '--', sys.executable, str(MINIMAL_BACKUP),
                  'backup', '--root', str(root), '--destination', str(destination)])
    exec_checked(['runuser', '-u', service_user, '--', sys.executable, str(MINIMAL_BACKUP),
                  'verify', '--bundle', str(destination)])


def run_sqlite_migration(binary: Path, env: Path, root: Path, service_user: str):
    # systemd загружает секретный EnvironmentFile, не раскрывая его значения через
    # argv.
    exec_checked(['systemd-run', '--quiet', '--wait', '--collect',
                  '--unit=launcher-db-upgrade-0457', '-p', f'User={service_user}',
                  '-p', f'Group={service_user}',
                  '-p', f'EnvironmentFile={env}',
                  '-p', f'WorkingDirectory={root}',
                  '--', '/usr/bin/env', 'LAUNCHER_PROCESS_ROLE=migrate',
                  'LAUNCHER_DATABASE_AUTO_MIGRATE=true', str(binary)], timeout=240)



def switch_native_service(binary: Path, service: str, *, unit_root: Path = Path('/etc/systemd/system')) -> Path:
    """Закрепить проверенный исполняемый файл для systemd; допускается только одна управляемая замена
параметров выпуска.

    Старый ExecStart восстанавливается удалением этого drop-in после ошибки. Сбой после записи
    оставляет старую службу остановленной, а не создаёт ложное свидетельство успеха.
    """
    require(service == 'launcher.service', 'only managed launcher.service is eligible')
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(binary)) is not None, 'unsupported binary path')
    path = unit_root / (service + '.d')
    if path.exists():
        require(path.is_dir() and not path.is_symlink(), 'unsafe systemd drop-in directory')
    else:
        path.mkdir(mode=0o755)
    override = path / '20-database-upgrade-0457.conf'
    require(not override.exists() and not override.is_symlink(), 'database upgrade override already exists')
    fd = os.open(override, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as writer:
        writer.write('[Service]\nExecStart=\nExecStart=' + str(binary) + '\n')
        writer.flush()
        os.fsync(writer.fileno())
    try:
        exec_checked(['systemctl', 'daemon-reload'], timeout=30)
    except Exception:
        override.unlink(missing_ok=True)
        raise
    return override


def revert_native_service(override: Path | None):
    if override is not None:
        override.unlink(missing_ok=False)
        exec_checked(['systemctl', 'daemon-reload'], timeout=30)


def service_active(service: str) -> bool:
    return subprocess.run(['systemctl', 'is-active', '--quiet', service], check=False,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def upgrade_sqlite(root: Path, destination: Path, binary: Path, env: Path,
                   service: str, service_user: str, expect_schema: int, ready_url: str):
    import pwd
    require(os.geteuid() == 0, 'SQLite upgrade requires root for systemctl and transient service')
    require(service == 'launcher.service', 'only launcher.service is supported for managed upgrades')
    require(re.fullmatch(r'[a-z_][a-z0-9_-]*', service_user) is not None, 'invalid service user')
    pwd.getpwnam(service_user)
    require(root.is_dir() and not root.is_symlink(), 'existing minimal root required')
    require(env == root / 'config/backend.env', 'minimal environment must be the managed installation environment')
    require(binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK), 'target backend executable missing')
    require(binary.stat().st_uid == 0 and binary.stat().st_mode & 0o022 == 0, 'target binary must be root-owned and immutable to service user')
    require(destination.is_absolute() and destination.parent.is_dir() and not destination.exists(), 'new backup path outside root required')
    require(not destination.is_relative_to(root), 'backups must survive installation rollback')
    uid = pwd.getpwnam(service_user).pw_uid
    for folder in (root.parent, destination.parent):
        require(folder.stat().st_uid == uid and folder.stat().st_mode & 0o077 == 0,
                'backup and install parents must be private and owned by service user')
    originally_active = service_active(service)
    source_version = wait_loopback_ready(ready_url, timeout=10) if originally_active else None
    if originally_active:
        exec_checked(['systemctl', 'stop', service], timeout=90)
    backup_verified = False
    override = None
    try:
        with lock(root.parent):
            schema_check_sqlite(root)
            run_minimal_backup(root, destination, service_user)
            backup_verified = True
            try:
                run_sqlite_migration(binary, env, root, service_user)
                schema_check_sqlite(root, target_version=expect_schema)
                override = switch_native_service(binary, service)
                if originally_active:
                    exec_checked(['systemctl', 'start', service], timeout=90)
                    wait_loopback_ready(ready_url, expected_version=TARGET)
                return {'status': 'upgraded' if originally_active else 'migrated-offline', 'mode': 'minimal', 'backup': str(destination),
                        'schema': expect_schema, 'applicationVerified': originally_active}
            except Exception as primary:
                # Не утверждайте, что старый бинарник работает с частично обновлённой базой
                # данных.
                exec_checked(['systemctl', 'stop', service], timeout=90)
                revert_native_service(override)
                override = None
                failed = root.with_name(root.name + '.failed-upgrade-' + str(os.getpid()))
                require(not failed.exists(), 'failed upgrade directory already exists')
                root.rename(failed)
                try:
                    exec_checked(['runuser', '-u', service_user, '--', sys.executable,
                                  str(MINIMAL_BACKUP), 'restore', '--bundle', str(destination),
                                  '--target-root', str(root)])
                    schema_check_sqlite(root)
                    if originally_active:
                        exec_checked(['systemctl', 'start', service], timeout=90)
                        wait_loopback_ready(ready_url, expected_version=source_version)
                except Exception as recovery:
                    raise UpgradeError('Миграция SQLite завершилась ошибкой, автоматическое восстановление не подтверждено; служба остановлена') from recovery
                raise UpgradeError('Миграция SQLite завершилась ошибкой; восстановлена предыдущая резервная копия и проверена исходная служба') from primary
    finally:
        if not backup_verified and originally_active:
            # Изменения БД ещё не предпринимались. Возобновляйте только в случае сбоя до
            # миграции.
            exec_checked(['systemctl', 'start', service], timeout=90)


def env_values(path: Path):
    require(path.is_file() and not path.is_symlink(), 'Compose environment file must be real')
    values = {}
    for line in path.read_text().splitlines():
        item = line.strip()
        if not item or item.startswith('#'):
            continue
        require('=' in item, 'invalid Compose environment record')
        key, value = item.split('=', 1)
        require(re.fullmatch(r'[A-Z][A-Z0-9_]*', key) is not None and key not in values,
                'invalid/duplicate Compose environment key')
        values[key] = value.strip().strip('"').strip("'")
    return values


def validate_source_target(source: Path, target: Path, network_ha: bool):
    before, after = env_values(source), env_values(target)
    require(before.get('LAUNCHER_IMAGE_TAG') and after.get('LAUNCHER_IMAGE_TAG') == TARGET,
            'source image and target 0.45.7 image required')
    require(before['LAUNCHER_IMAGE_TAG'] != TARGET, 'source must be an earlier release')
    require(after.get('LAUNCHER_DATABASE_AUTO_MIGRATE') == 'false',
            'target env must persist LAUNCHER_DATABASE_AUTO_MIGRATE=false for all API replicas')
    # Рассматривайте неизменяемые секреты и топологию хранилища как единую область
    # согласованности.
    for name in ('POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DB',
                 'LAUNCHER_AUTH_TOKEN_SECRET', 'LAUNCHER_STORAGE_S3_BUCKET',
                 'LAUNCHER_STORAGE_S3_ENDPOINT', 'LAUNCHER_STORAGE_S3_ACCESS_KEY',
                 'LAUNCHER_STORAGE_S3_SECRET_KEY', 'REDIS_PASSWORD'):
        if before.get(name) != after.get(name):
            raise UpgradeError(f'Обновление не может изменить {name}; выполните ротацию отдельно')
    if network_ha:
        require(before.get('LAUNCHER_STORAGE_S3_BUCKET'), 'HA upgrade requires configured S3')
    return before['LAUNCHER_IMAGE_TAG']


def resume(project: str, env: Path, services: list[str], *, expected: str, network_ha: bool):
    # Отключите автоматические миграции на каждой реплике API: DDL разрешён только
    # одноразовому мигратору.
    old = os.environ.get('LAUNCHER_DATABASE_AUTO_MIGRATE')
    os.environ['LAUNCHER_DATABASE_AUTO_MIGRATE'] = 'false'
    try:
        for service in reversed(services):
            dr.compose(project, env, 'up', '-d', '--force-recreate', service)
        if 'api' in services:
            dr.check_restored_backend(project, env, version=expected,
                                      storage='s3' if network_ha else 'local')
        if 'api-b' in services:
            dr.check_restored_backend(project, env, version=expected, storage='s3', service='api-b')
        for svc in ('worker-a', 'worker-b'):
            if svc in services:
                dr.check_restored_worker_0455(project, env, svc)
    finally:
        if old is None:
            os.environ.pop('LAUNCHER_DATABASE_AUTO_MIGRATE', None)
        else:
            os.environ['LAUNCHER_DATABASE_AUTO_MIGRATE'] = old


def postgres_migrate(project: str, env: Path):
    for _ in range(2):
        # Второй запуск проверяет безопасность повторного применения миграций
        # (идемпотентность) и совместимость нового бинарника с итоговой схемой. Все
        # записывающие процессы приложения остановлены.
        dr.compose(project, env, 'run', '--rm', '--no-deps', '-T',
                   '-e', 'LAUNCHER_PROCESS_ROLE=migrate',
                   '-e', 'LAUNCHER_DATABASE_AUTO_MIGRATE=true', 'api', timeout=300)


def reset_postgres(project: str, env: Path, snapshot: Path):
    # Неудачная миграция могла создать объекты, которых нет в предыдущем дампе.
    # Полностью очистите базу приложения перед восстановлением. Никогда не
    # восстанавливайте поверх схемы, где могли появиться объекты и ограничения после
    # обновления.
    dr.compose(project, env, 'exec', '-T', 'postgres', 'sh', '-ec',
               'export PGPASSWORD="$POSTGRES_PASSWORD"; '
               'dropdb --if-exists --force -U "$POSTGRES_USER" "$POSTGRES_DB" && '
               'createdb -U "$POSTGRES_USER" -O "$POSTGRES_USER" "$POSTGRES_DB"', timeout=120)
    dr.compose_pg_restore(project, env, snapshot / 'database.dump')
    # Тома координатора и бинарных объектов должны происходить из ОДНОЙ контрольной
    # точки до обновления.
    for logical in dr.required_volumes():
        name = dr.volume_name(project, logical)
        dr.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
                f'type=volume,src={name},dst=/target', 'alpine:3.20',
                'sh', '-ec', 'find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'])
        dr.docker_tar_restore(name, snapshot / (logical + '.tar.gz'))
    if 'network-ha' in dr.COMPOSE_PROFILES:
        dr.ensure_empty_redis_volume(project)
        dr.fence_restored_serverbridge(project, env)


def upgrade_postgres(project: str, source: Path, target: Path, snapshot_dir: Path,
                     confirm: str, *, network_ha=False, production=False, approved=False,
                     s3_bucket: str | None = None, s3_endpoint: str | None = None):
    dr.authorize_project(project, confirm, production=production, approved=approved)
    source_version = validate_source_target(source, target, network_ha)
    require(snapshot_dir.is_absolute() and not snapshot_dir.exists(), 'snapshot must be new, absolute path')
    require(snapshot_dir.parent.is_dir() and not snapshot_dir.parent.is_symlink(), 'snapshot parent unsafe')
    if network_ha:
        raise UpgradeError('Network-HA schema upgrade requires world/server coordination; use maintenance-specific DR runbook, not this Standard upgrade path')
    # Блокировка должна быть независимой от самого снимка и сохраняться в течение всего DDL и
    # восстановления.
    with lock(snapshot_dir.parent):
        states = dr.compose_states(project, source)
        require(states.get('postgres') == 'running', 'source PostgreSQL must be running')
        for service in ROLES:
            require(states.get(service, 'exited') not in ('paused', 'restarting'), 'unhealthy writer: ' + service)
        original = [s for s in ('nginx', 'admin', 'api', 'api-b', 'worker-a', 'worker-b') if states.get(s) == 'running']
        require('api' in original, 'source API must be active before upgrade')
        require(not any(states.get(name) == 'running' for name in ('worker-a','worker-b','api-b')),
                'Standard upgrade refuses unexpected HA workers or API replicas')
        dr.check_restored_backend(project, source, version=source_version, storage='local')
        # Соберите настоящие целевые бинарники ДО простоя; одноразовая миграция
        # никогда не должна незаметно возвращаться к старому образу API.
        dr.compose(project, target, 'build', 'api', 'admin', timeout=2400)
        dr.run(['docker', 'image', 'inspect', 'launcher-api:' + TARGET], timeout=30)
        # Функция snapshot оставляет службы остановленными до конца миграции и
        # проверок; в отличие от обычной резервной копии DR она не должна
        # автоматически возобновлять их.
        dr.snapshot(project, source, snapshot_dir, confirm, production=production,
                    approved=approved, resume_after=False, source_version=source_version)
        try:
            dr.pg_validate(snapshot_dir / 'database.dump')
            postgres_migrate(project, target)
            resume(project, target, original, expected=TARGET, network_ha=network_ha)
            return {'status': 'upgraded', 'mode': 'standard', 'from': source_version,
                    'to': TARGET, 'backup': str(snapshot_dir), 'applicationVerified': True}
        except Exception as primary:
            # Гарантируйте, что записывающий процесс после миграции не сможет
            # конфликтовать с восстановлением.
            for svc in original:
                try:
                    dr.compose(project, target, 'stop', '-t', '30', svc)
                except Exception:
                    pass
            try:
                dr.verify_snapshot(snapshot_dir)
                reset_postgres(project, source, snapshot_dir)
                resume(project, source, original, expected=source_version, network_ha=network_ha)
            except Exception as recovery:
                raise UpgradeError('Миграция завершилась ошибкой, восстановление не подтверждено; службы должны оставаться остановленными') from recovery
            raise UpgradeError('Миграция завершилась ошибкой; прежняя БД, тома и API восстановлены и проверены') from primary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    sqlite_p = sub.add_parser('sqlite', help="Остановить службу systemd, сделать снимок, мигрировать и восстановить минимальную установку")
    for name in ('root', 'backup', 'binary', 'env'):
        sqlite_p.add_argument('--' + name, type=Path, required=True)
    sqlite_p.add_argument('--service', default='launcher.service')
    sqlite_p.add_argument('--service-user', default='launcher')
    sqlite_p.add_argument('--expect-schema', type=int, default=327)
    sqlite_p.add_argument('--ready-url', default='http://127.0.0.1:8080/ready')
    standard = sub.add_parser('postgres', help="Полное обновление Standard Compose с откатом")
    standard.add_argument('--project', required=True)
    standard.add_argument('--confirm', required=True)
    standard.add_argument('--source-env', type=Path, required=True)
    standard.add_argument('--target-env', type=Path, required=True)
    standard.add_argument('--snapshot', type=Path, required=True)
    standard.add_argument('--production-source', action='store_true')
    standard.add_argument('--maintenance-approved', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.mode == 'sqlite':
            output = upgrade_sqlite(args.root.resolve(), args.backup.absolute(), args.binary.absolute(),
                                    args.env.absolute(), args.service, args.service_user,
                                    args.expect_schema, args.ready_url)
        else:
            output = upgrade_postgres(args.project, args.source_env.absolute(), args.target_env.absolute(),
                                      args.snapshot.absolute(), args.confirm,
                                      production=args.production_source, approved=args.maintenance_approved)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (UpgradeError, dr.DrillError, OSError, ValueError, sqlite3.Error,
            subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print('Обновление БД остановлено с отказом по умолчанию: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
