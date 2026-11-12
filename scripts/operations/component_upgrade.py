#!/usr/bin/env python3
"""Эксплуатационное переключение компонентов через настоящие обновляющие механизмы Launcher.

Standard: проверенная холодная контрольная точка PostgreSQL, переключение и откат образов API/Admin.
Linux host: обновление CLI/ServerBridge с проверкой байтов и атомарной заменой, безопасной при сбое.
Desktop: передать проверенный промышленный пакет компонентов в `nl update components`.
Extensions: вызвать существующий транзакционный серверный обновляющий механизм расширений со свежим MFA.
Нет автоматических миграций БД или обхода подписей выпуска и шлюзов доверия.
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
        raise ComponentError(f'{args[0]} завершилась с ошибкой (код выхода={result.returncode})')
    return result.stdout


def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as inp:
        for buf in iter(lambda: inp.read(1024 * 1024), b''):
            sha.update(buf)
    return sha.hexdigest()


def checked_file(path: Path, sha: str, *, must_be_root=False):
    must(SHA_RE.fullmatch(sha) is not None, 'Закреплённый SHA-256 должен содержать 64 шестнадцатеричных символа в нижнем регистре')
    st = path.lstat()
    must(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size > 0,
         'Источник должен быть непустым обычным файлом (не символической и не жёсткой ссылкой)')
    if must_be_root:
        must(st.st_uid == 0 and not (st.st_mode & 0o022), 'Пользователи без прав root не должны иметь возможности изменять источник')
    must(digest(path) == sha, 'Несовпадение закреплённого SHA-256')


def read_version(env_file):
    must(env_file.is_file() and not env_file.is_symlink(), 'Файл окружения отсутствует или является символической ссылкой')
    must(not env_file.stat().st_mode & 0o077, 'Файл рабочего окружения должен иметь ограниченные права доступа')
    data = database.env_values(env_file)
    return data, data.get('LAUNCHER_IMAGE_TAG', '')


def assert_same_config(before, after, *, source_version=SOURCE, target_version=TARGET):
    old, version = read_version(before)
    new, target = read_version(after)
    must(version == source_version and target == target_version and version != target,
         'Исходная или целевая версия не соответствует закреплённому плану обновления')
    must(new.get('LAUNCHER_DATABASE_AUTO_MIGRATE') == 'false', 'Автоматическое выполнение DDL при обновлении компонентов запрещено')
    # При переключении не меняйте одновременно учётные данные, хранилище, DNS, ключи
    # или политику подписи; для них нужны отдельные аудируемые операции.
    allowed = {'LAUNCHER_IMAGE_TAG', 'LAUNCHER_DATABASE_AUTO_MIGRATE'}
    must(all(old.get(key, '') == new.get(key, '') for key in set(old) | set(new) if key not in allowed),
         'Исходное и целевое окружения отличаются не только версией образа и параметром auto-migrate')
    return version


def image_id(tag):
    result = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag], timeout=30)
    value = result.decode('ascii', errors='strict').strip()
    must(value.startswith('sha256:') and SHA_RE.fullmatch(value[7:]) is not None, 'Недопустимый идентификатор образа')
    return value


def verify_service_image(project, env, service, expected_version):
    """Проверять ID настоящего работающего контейнера, а не изменяемый тег образа."""
    image_type = 'admin' if service == 'admin' else 'api'
    expected = image_id(f'launcher-{image_type}:{expected_version}')
    container = dr.compose(project, env, 'ps', '-q', service, timeout=30).stdout.decode('ascii').strip()
    must(re.fullmatch(r'[0-9a-f]{12,64}', container) is not None, 'Отсутствует ID контейнера работающей службы')
    actual = run(['docker', 'inspect', '--format', '{{.Image}}', container], timeout=30).decode('ascii').strip()
    must(actual == expected, 'Работающий контейнер использует неожиданный хеш образа: ' + service)


def check_admin(project, env):
    result = dr.compose(project, env, 'exec', '-T', 'admin', 'wget', '-qO-',
                        'http://127.0.0.1:8080/', timeout=30).stdout
    must(b'<html' in result.lower() and len(result) > 80, 'Admin не отдал реальную HTML-страницу')


def check_nginx(project, env):
    states = dr.compose_states(project, env)
    must(states.get('nginx') == 'running', 'Nginx не запустился')
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
    must(not dr.COMPOSE_PROFILES, 'Стандартный обновляющий компонент не поддерживает наложения Network-HA')
    dr.authorize_project(project, confirm, production=production, approved=approved)
    assert_same_config(source, target, source_version=source_version, target_version=target_version)
    must(snapshot.is_absolute() and not snapshot.exists() and snapshot.parent.is_dir()
         and not snapshot.parent.is_symlink(), 'Путь снимка должен быть неиспользуемым и находиться на защищённом хранилище')
    must(snapshot.parent.stat().st_mode & 0o077 == 0, 'Родительский каталог снимка должен иметь права 0700')
    with database.lock(snapshot.parent):
        states = dr.compose_states(project, source)
        must(states.get('postgres') == 'running' and states.get('api') == 'running', 'Исходные PostgreSQL и API должны быть запущены')
        must(not any(states.get(s) == 'running' for s in ('api-b', 'worker-a', 'worker-b', 'redis')),
             'Неожиданные роли Network-HA; обновление в режиме Standard невозможно')
        for svc in ('api', 'admin', 'nginx'):
            must(states.get(svc, 'exited') not in ('paused', 'restarting'), 'Исходная служба неисправна: ' + svc)
        original = [svc for svc in ('api', 'admin', 'nginx') if states.get(svc) == 'running']
        dr.check_restored_backend(project, source, version=source_version, storage='local')
        # Создайте и определите настоящие заменяющие образы ДО остановки работающего приложения.
        dr.compose(project, target, 'build', 'api', 'admin', timeout=2400)
        target_images = {svc: image_id('launcher-' + svc + ':' + target_version) for svc in ('api', 'admin')}
        source_images = {svc: image_id('launcher-' + svc + ':' + source_version) for svc in ('api', 'admin')}
        must(all(source_images[s] != target_images[s] for s in source_images), 'Образ для замены совпадает со старым образом')
        # При ошибке snapshot() самостоятельно возобновляет ранее работавшие службы.
        dr.snapshot(project, source, snapshot, confirm, production=production,
                    approved=approved, resume_after=False, source_version=source_version)
        try:
            receipt = dr.verify_snapshot(snapshot)
            # Обнаруживайте внешнюю запись, даже если соответствующая сессия быстро
            # отключилась.
            must(dr.assert_quiescent(project, source) == receipt['postgresWalLsn'],
                 'После резервного копирования компонента продвинулся журнал WAL PostgreSQL')
            must(all(image_id('launcher-' + svc + ':' + target_version) == target_images[svc]
                     for svc in target_images), 'После сборки изменился целевой образ')
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
                         for svc in source_images), 'Контрольная сумма исходного образа изменилась; откат небезопасен')
                restore_service_set(project, source, original, expected=source_version)
            except Exception as recovery:
                raise ComponentError('Переключение компонента завершилось ошибкой, и старый API не удалось проверить; оставьте Nginx остановленным') from recovery
            raise ComponentError('Переключение компонента завершилось ошибкой; предыдущие образы приложения восстановлены и проверены') from problem



@contextmanager
def network_overlay():
    """Ограничить конфигурацию HA Compose текущей операцией: глобальные изменения не должны затрагивать
другие операции."""
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
    """Холодное переключение только компонентов; никогда не восстанавливать старые аренды Redis и не откатывать PG.

    Службы записи миров уже должны быть остановлены; DR проверяет их холодные копии. Схемы
    PostgreSQL НЕ обновляются; это не поэтапное обновление.
    """
    dr.authorize_project(project, confirm, production=production, approved=approved)
    assert_same_config(source, target, source_version=source_version, target_version=target_version)
    must(world_backups and s3_bucket, 'Для обновления HA требуются подтверждённая остановка миров и снимок S3')
    must(snapshot.is_absolute() and not snapshot.exists() and snapshot.parent.is_dir()
         and not snapshot.parent.is_symlink() and not (snapshot.parent.stat().st_mode & 0o077),
         'Резервная копия HA должна быть новой и храниться в закрытом каталоге')
    with network_overlay(), database.lock(snapshot.parent):
        states = dr.compose_states(project, source)
        must(all(states.get(s) == 'running' for s in ('postgres', 'redis', 'api', 'api-b', 'worker-a', 'worker-b', 'admin', 'nginx')),
             'Перед переключением все роли Network-HA должны быть исправны и запущены')
        for svc in ('api', 'api-b'):
            dr.check_restored_backend(project, source, version=source_version, storage='s3', service=svc)
        for svc in ('worker-a', 'worker-b'):
            dr.check_restored_worker_0455(project, source, svc)
        dr.compose(project, target, 'build', 'api', 'admin', timeout=2400)
        new_images = {s: image_id('launcher-' + s + ':' + target_version) for s in ('api', 'admin')}
        old_images = {s: image_id('launcher-' + s + ':' + source_version) for s in ('api', 'admin')}
        must(all(new_images[s] != old_images[s] for s in new_images), 'Новые образы HA совпадают с предыдущими')
        dr.snapshot(project, source, snapshot, confirm, s3_bucket=s3_bucket, s3_endpoint=s3_endpoint,
                    production=production, approved=approved, world_backups=world_backups,
                    resume_after=False, source_version=source_version)
        try:
            receipt = dr.verify_snapshot(snapshot)
            must(dr.assert_quiescent(project, source) == receipt['postgresWalLsn'],
                 'После резервного копирования компонента HA продвинулся WAL PostgreSQL')
            must(all(image_id('launcher-' + s + ':' + target_version) == new_images[s] for s in new_images),
                 'После резервного копирования изменились целевые образы HA')
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
                     'Предыдущий образ HA заменён')
                restore_ha_roles(project, source, expected=source_version)
            except Exception as failure:
                raise ComponentError('Переключение HA и восстановление предыдущей версии завершились ошибкой; Nginx должен оставаться отключённым') from failure
            raise ComponentError('Переключение HA-компонента завершилось ошибкой; исходные бинарные файлы восстановлены и проверены') from cause

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
    """Атомарная замена исполняемого файла с проверенным откатом при отказе службы.

    Выполнять от root в управляемое окно обслуживания; старый файл перемещается в закрытую резервную
    копию рядом с установленным путём (та же ФС).
    """
    must(os.geteuid() == 0, 'Для обновления исполняемого файла хоста требуются права root')
    must(re.fullmatch(r'0\.\d+\.\d+', source_version) and re.fullmatch(r'0\.\d+\.\d+', target_version),
         'Недопустимая версия исходного или целевого бинарного файла')
    must(re.fullmatch(r'\d{4}', backup_tag), 'Недопустимая метка резервной копии')
    must(component in COMPONENTS, 'Неподдерживаемый компонент узла')
    must(component != 'api' or service == 'launcher.service', 'Минимальный API должен использовать управляемую службу launcher.service')
    must(component != 'bridge' or bool(service), 'Для обновления ServerBridge требуется служба systemd')
    must(install.is_absolute() and source.is_absolute(), 'Пути к бинарным файлам должны быть абсолютными')
    must(install != source and install.parent.is_dir(), 'Исходный и целевой пути должны различаться')
    must(not install.parent.is_symlink() and install.parent.stat().st_uid == 0
         and not install.parent.stat().st_mode & 0o022, 'Каталог установки должен принадлежать root и быть защищён')
    checked_file(source, checksum, must_be_root=True)
    old = install.lstat()
    must(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and old.st_nlink == 1
         and not (old.st_mode & 0o022), 'Существующий бинарный файл должен быть обычным файлом, принадлежащим root')
    must(not install.with_name(install.name + '.previous-' + backup_tag).exists(), 'Резервная копия уже существует; сначала завершите предыдущее обновление')
    if service:
        must(SERVICE_RE.fullmatch(service) is not None, 'Недопустимая служба systemd')
    old_active = bool(service and systemctl_is_active(service))
    must(component != 'api' or old_active, 'Для проверенного переключения управляемый API должен работать')
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
                    must(digest(Path(stage)) == checksum, 'Изменилась контрольная сумма подготовленного исполняемого файла')
                    os.replace(stage, install); fsync_dir(install.parent)
                finally:
                    if os.path.exists(stage):
                        os.unlink(stage)
            if component != 'api':
                version_output = run([str(install), 'version'], timeout=30).decode('utf-8', errors='replace')
                must(target_version in version_output, 'Новый исполняемый файл CLI/Bridge сообщает неожиданную версию')
            if old_active:
                run(['systemctl', 'start', service], timeout=90)
                must(systemctl_is_active(service), 'Обновлённая служба systemd неактивна')
                if component == 'api':
                    database.wait_loopback_ready(ready_url or 'http://127.0.0.1:8080/ready', expected_version=target_version)
            elif component == 'api':
                raise ComponentError('Для проверенного переключения служба минимального API должна быть активна')
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
                    must(systemctl_is_active(service), 'Старая служба не запустилась после отката')
                    if component == 'api':
                        database.wait_loopback_ready(ready_url or 'http://127.0.0.1:8080/ready', expected_version=source_version)
            except Exception as rollback_error:
                raise ComponentError('Обновление узла завершилось ошибкой; предыдущий исполняемый файл не прошёл проверку, служба должна оставаться остановленной') from rollback_error
            raise ComponentError('Обновление узла завершилось ошибкой; старый бинарный файл восстановлен') from error


def rollback_linux_host(component, install: Path, expected_previous_sha, *, service=None,
                        ready_url='http://127.0.0.1:8080/ready', source_version=SOURCE, backup_tag='0458'):
    """Явное восстановление после сбоя процесса или завершённого, но неудачного развёртывания.

    Никогда не принимать неопознанную последовательность байтов `.previous`. При откате исполняемый
    файл 0.45.8 сохраняется отдельно как `.failed` для анализа инцидента.
    """
    must(os.geteuid() == 0, 'Для отката хоста требуются права root')
    must(re.fullmatch(r'0\.\d+\.\d+', source_version) and re.fullmatch(r'\d{4}', backup_tag),
         'Недопустимая версия или метка отката')
    must(component in COMPONENTS, 'Неподдерживаемый компонент узла')
    must(install.is_absolute() and install.parent.is_dir()
         and not install.parent.is_symlink() and install.parent.stat().st_uid == 0
         and not install.parent.stat().st_mode & 0o022, 'Небезопасный целевой путь отката хоста')
    must(component != 'api' or service == 'launcher.service', 'Минимальный API должен использовать launcher.service')
    must(component != 'bridge' or bool(service), 'Для отката ServerBridge требуется соответствующая служба systemd')
    if service:
        must(SERVICE_RE.fullmatch(service) is not None, 'Недопустимая служба systemd')
    backup = install.with_name(install.name + '.previous-' + backup_tag)
    failed = install.with_name(install.name + '.failed-' + backup_tag)
    checked_file(backup, expected_previous_sha, must_be_root=True)
    must(not failed.exists() and not failed.is_symlink(), 'Существует бинарный файл предыдущего неудачного обновления; требуется вмешательство оператора')
    with database.lock(install.parent):
        was_active = bool(service and systemctl_is_active(service))
        if was_active:
            run(['systemctl', 'stop', service], timeout=90)
        have_current = install.exists() or install.is_symlink()
        if have_current:
            st = install.lstat()
            must(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1,
                 'Текущий путь исполняемого файла небезопасен')
            os.replace(install, failed)
        os.replace(backup, install)
        fsync_dir(install.parent)
        try:
            must(digest(install) == expected_previous_sha, 'Восстановленные байты старой версии не совпадают')
            if component != 'api':
                must(source_version in run([str(install), 'version'], timeout=30).decode('utf-8'),
                     'Версия старого CLI или Bridge не совпадает')
            if was_active:
                run(['systemctl', 'start', service], timeout=90)
                must(systemctl_is_active(service), 'Старая служба не перезапустилась')
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
            raise ComponentError('Старый исполняемый файл восстановлен, но его состояние и версия не проверены; служба должна оставаться остановленной') from problem


def client_package(cli: Path, package: Path, checksum, delivery: Path, root: Path, *, target_version=TARGET):
    """Вызывает существующий подписанный транзакционный механизм обновления компонентов, а не
альтернативный установщик."""
    must(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'Требуется корневой каталог существующей установки клиента')
    must(delivery.is_file() and not delivery.is_symlink(), 'Требуется независимо утверждённый манифест поставки')
    checked_file(package, checksum)
    must(cli.is_file() and not cli.is_symlink(), 'Требуется установленный CLI Launcher')
    output = run([str(cli), 'update', 'components', '--package', str(package),
                  '--expected-sha256', checksum, '--delivery-manifest', str(delivery),
                  '--root', str(root)], timeout=900)
    try:
        report = json.loads(output)
    except ValueError as exc:
        raise ComponentError('Нативный модуль обновления не вернул JSON-отчёт') from exc
    must(isinstance(report, dict) and report.get('status') == 'committed'
         and report.get('toVersion') == target_version, 'Нативный обновлятор не зафиксировал требуемую версию')
    # Существующая проверка пакета обновления проверяет хеши каждого файла, подпись,
    # эпоху доверия, идентичность платформы и журнал отката. Эти проверки здесь не
    # переопределяются.
    return {'status': 'upgraded', 'nativeReport': report}


def extensions(cli: Path, backend: str, coords: list[str], channel: str):
    must(coords and all(re.fullmatch(r'[a-zA-Z0-9_.-]+@[0-9A-Za-z.+-]+', x) for x in coords),
         'Укажите точные координаты расширения в формате id@version')
    url = urlsplit(backend)
    must(url.scheme == 'https' and bool(url.hostname) and not url.username and not url.password
         and not url.query and not url.fragment and not url.path.rstrip('/'),
         'Рабочий Backend расширений должен использовать HTTPS')
    must(channel in ('stable', 'beta'), 'Недопустимый канал расширения')
    must(cli.is_file() and not cli.is_symlink(), 'CLI Launcher отсутствует')
    must(bool(os.environ.get('LAUNCHER_TOKEN')), 'Предоставьте новый LAUNCHER_TOKEN с подтверждённой MFA в окружении оператора')
    base = [str(cli), 'extension', 'updates']
    flags = ['--backend', backend, '--channel', channel]
    planned = json.loads(run(base + ['plan', *coords, *flags], timeout=120))
    must(isinstance(planned, dict) and isinstance(planned.get('data', {}).get('plan'), dict),
         'Сервер не предоставил реальный план расширения')
    applied = json.loads(run(base + ['apply', *coords, *flags], timeout=360))
    tx = applied.get('data', {}).get('transaction') if isinstance(applied, dict) else None
    must(isinstance(tx, dict) and tx.get('status') in ('succeeded', 'completed'),
         'Транзакция расширения не была зафиксирована')
    return {'status': 'upgraded', 'transactionId': tx.get('id'), 'extensions': coords}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    standard_cmd = sub.add_parser('standard', help="Обновить образы стандартных API и панели администратора в Docker Compose с холодной копией и возможностью отката")
    for key in ('project', 'confirm', 'source-env', 'target-env', 'backup'):
        standard_cmd.add_argument('--' + key, required=True,
                                  type=Path if key.endswith('env') or key == 'backup' else str)
    standard_cmd.add_argument('--from-version', default=SOURCE)
    standard_cmd.add_argument('--to-version', default=TARGET)
    standard_cmd.add_argument('--production-source', action='store_true')
    standard_cmd.add_argument('--maintenance-approved', action='store_true')
    ha = sub.add_parser('network-ha', help="Холодное обновление обоих API, обоих worker и Admin с контрольной точкой мира/S3")
    for key in ('project', 'confirm', 'source-env', 'target-env', 'backup', 's3-bucket'):
        ha.add_argument('--' + key, required=True, type=Path if key.endswith('env') or key == 'backup' else str)
    ha.add_argument('--s3-endpoint')
    ha.add_argument('--world-backup', action='append', required=True, metavar='NAME=BACKUP_ID_DIRECTORY')
    ha.add_argument('--from-version', default=SOURCE)
    ha.add_argument('--to-version', default=TARGET)
    ha.add_argument('--production-source', action='store_true')
    ha.add_argument('--maintenance-approved', action='store_true')
    native = sub.add_parser('linux-host', help="Атомарно обновить настоящий исполняемый файл CLI/ServerBridge с владельцем root")
    native.add_argument('--component', choices=sorted(COMPONENTS), required=True)
    native.add_argument('--source', type=Path, required=True)
    native.add_argument('--install', type=Path, required=True)
    native.add_argument('--sha256', required=True)
    native.add_argument('--service', help="Служба systemd для ServerBridge или минимального API")
    native.add_argument('--ready-url', default='http://127.0.0.1:8080/ready', help="Минимальная проверка готовности API")
    rollback = sub.add_parser('rollback-linux-host', help="Восстановить закреплённый прежний исполняемый файл после сбойного обновления")
    rollback.add_argument('--component', choices=sorted(COMPONENTS), required=True)
    rollback.add_argument('--install', type=Path, required=True)
    rollback.add_argument('--previous-sha256', required=True)
    rollback.add_argument('--service')
    rollback.add_argument('--ready-url', default='http://127.0.0.1:8080/ready')
    client = sub.add_parser('client', help="Установить подписанное обновление Desktop/Runtime/Guard штатным CLI")
    client.add_argument('--cli', type=Path, required=True)
    client.add_argument('--package', type=Path, required=True)
    client.add_argument('--sha256', required=True)
    client.add_argument('--delivery-manifest', type=Path, required=True)
    client.add_argument('--root', type=Path, required=True)
    ext = sub.add_parser('extensions', help="Использовать настоящую серверную транзакцию расширения и проверку здоровья")
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
        print('Обновление компонента заблокировано: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
