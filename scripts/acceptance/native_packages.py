#!/usr/bin/env python3
"""Приёмка 0.52.2 окончательных фирменных установщиков для шести ОС на реальных системах.

Исходный индекс закреплён по SHA-256 ВНЕ загружаемого индекса. Каждый пакет загружается по HTTPS,
сверяется по хешу, проверяется штатным механизмом подписей ОС, устанавливается и запускается на
*соответствующем* нативном одноразовом раннере. Имитированный пакет или кросс-сборка не проходят
проверку. Наблюдения CI НЕ заменяют независимую сертификацию GA/физической машины.
"""
from __future__ import annotations

import argparse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 'neverlauncher.native-final-packages/0.52.2'
REVIEW_DOMAIN = b'neverlauncher.native-final-package.review.0.52.2\x00'
RESULT_SCHEMA = 'neverlauncher.native-final-package-result/0.52.2'
SUMMARY_SCHEMA = 'neverlauncher.native-final-package-matrix/0.52.2'
TARGETS = {(osname, arch) for osname in ('windows', 'linux', 'macos') for arch in ('x64', 'arm64')}
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
PROJECT = re.compile(r'[a-z0-9][a-z0-9-]{1,45}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')
MAX_INDEX = 64 * 1024
MAX_PACKAGE = 4 * 1024 * 1024 * 1024
MAX_LOG = 8 * 1024 * 1024


class Blocked(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Blocked(why)


def unique(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, 'duplicate JSON key: ' + k)
        out[k] = v
    return out


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda x: (_ for _ in ()).throw(Blocked('nonfinite JSON')))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Blocked('Недопустимый JSON') from exc


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_hash(path):
    sha = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def regular(path, maximum):
    require(path.is_absolute() and not path.is_symlink() and path.is_file(), 'Файл отсутствует или небезопасен: ' + str(path))
    require(not any(p.is_symlink() for p in path.parents), 'symlink ancestor in ' + str(path))
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= maximum,
            'Недопустимый размер или число ссылок: ' + str(path))
    return path


def expected_filename(version, project, osname, arch):
    suffix = {'windows': ('.exe', 'windows'), 'linux': ('.deb', 'linux'),
              'macos': ('.pkg', 'macos')}[osname]
    return f'launcher-{version}-{project}-{suffix[1]}-{arch}{suffix[0]}'


def valid_https(url):
    require(type(url) is str and len(url) <= 4096, 'Недопустимый URL HTTPS')
    p = urllib.parse.urlsplit(url)
    require(p.scheme == 'https' and bool(p.hostname) and p.port in (None, 443)
            and not p.username and not p.password and not p.fragment,
            'Источник релиза должен использовать HTTPS без учётных данных, порта и фрагмента URL')
    require(not p.hostname.lower() in ('localhost', 'localhost.localdomain')
            and not p.hostname.endswith('.localhost'), 'Локальные URL релизов запрещены')
    # Запрещены буквальные IPv4/IPv6 адреса частных сетей, loopback и link-local.
    import ipaddress
    try:
        ip = ipaddress.ip_address(p.hostname)
    except ValueError:
        return url
    require(ip.is_global, 'URL релиза не должен вести на частный или локальный сетевой IP')
    return url


def read_index(data, expected_sha, version, commit, project):
    require(type(expected_sha) is str and SHA.fullmatch(expected_sha) and digest(data) == expected_sha,
            'release source index does not match independently pinned SHA-256')
    require(len(data) <= MAX_INDEX, 'source index too large')
    doc = parse_json(data)
    require(type(doc) is dict and set(doc) == {'schema', 'version', 'commit', 'project', 'assets'},
            'Неожиданные поля индекса источников')
    require(doc['schema'] == SCHEMA and doc['version'] == version and doc['commit'] == commit
            and doc['project'] == project and COMMIT.fullmatch(commit) and PROJECT.fullmatch(project),
            'Несовпадение источника, версии или проекта')
    assets = doc['assets']
    require(type(assets) is list and len(assets) == 6, 'Должно присутствовать ровно шесть финальных пакетов')
    seen, seen_urls = {}, set()
    for item in assets:
        require(type(item) is dict and set(item) in (
            {'platform', 'architecture', 'filename', 'url', 'sha256', 'size'},
            {'platform', 'architecture', 'filename', 'url', 'sha256', 'size', 'signatureUrl', 'signatureSha256', 'signatureSize'}
        ), 'Недопустимые поля источника пакета')
        target = (item.get('platform'), item.get('architecture'))
        require(target in TARGETS and target not in seen, 'Неподдерживаемая или повторяющаяся целевая платформа')
        require(item['filename'] == expected_filename(version, project, *target), 'Неожиданное имя пакета')
        require(type(item['sha256']) is str and SHA.fullmatch(item['sha256']), 'Недопустимый хеш пакета')
        require(type(item['size']) is int and 100 <= item['size'] <= MAX_PACKAGE, 'Недопустимый размер пакета')
        urls = [item['url']]
        if target[0] == 'linux':
            require(set(item) == {'platform', 'architecture', 'filename', 'url', 'sha256', 'size',
                                  'signatureUrl', 'signatureSha256', 'signatureSize'},
                    'Linux package requires detached GPG signature')
            require(SHA.fullmatch(item['signatureSha256']) and
                    type(item['signatureSize']) is int and 100 <= item['signatureSize'] <= 8192,
                    'Недопустимая контрольная сумма или размер подписи Linux')
            urls.append(item['signatureUrl'])
        else:
            require('signatureUrl' not in item, 'Windows and macOS use embedded platform signatures')
        for url in urls:
            valid_https(url)
            require(url not in seen_urls, 'reused package/source URL')
            seen_urls.add(url)
        seen[target] = item
    require(set(seen) == TARGETS, 'Отсутствует нативная платформа или архитектура')
    return seen


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        valid_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, destination, expected_sha, expected_size, *, opener=None):
    valid_https(url)
    require(not destination.exists() and not destination.is_symlink(), 'Путь загрузки уже существует')
    client = opener or urllib.request.build_opener(HTTPSOnly())
    total, sha = 0, hashlib.sha256()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out, client.open(urllib.request.Request(
                url, headers={'User-Agent': 'NeverLauncher-Native-Acceptance/0.52.2'}), timeout=45) as response:
            valid_https(response.geturl())
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                require(total <= expected_size, 'Загрузка превышает закреплённый размер')
                sha.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        require(total == expected_size and sha.hexdigest() == expected_sha, 'Несовпадение контрольной суммы или размера загрузки')
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {'sha256': sha.hexdigest(), 'size': total}


def host_target():
    osname = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system())
    arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    require((osname, arch) in TARGETS and sys.maxsize > 2**32,
            'Требуется нативный исполнитель на 64-разрядной ОС соответствующей архитектуры')
    if osname == 'windows':
        # 32-битный или эмулируемый Python-процесс не должен выдавать себя за нативный ARM64.
        require(os.environ.get('PROCESSOR_ARCHITECTURE', '').lower() in ('amd64', 'arm64') and
                os.environ.get('PROCESSOR_ARCHITECTURE', '').lower() in (
                    ('amd64',) if arch == 'x64' else ('arm64',)), 'Эмулированный исполнитель Windows запрещён')
    return (osname, arch)


def execute(argv, timeout, log):
    # Только фиксированные локально созданные массивы аргументов команд; предоставленные пользователем URL и
    # имена файлов никогда не подставляются в shell. stdout не отправляется в журналы CI.
    raw = log.with_suffix('.unredacted')
    start = time.monotonic()
    try:
        with raw.open('wb') as f:
            os.chmod(raw, 0o600)
            result = subprocess.run([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                    stdout=f, stderr=subprocess.STDOUT, timeout=timeout,
                                    check=False)
        require(raw.stat().st_size <= MAX_LOG, 'subprocess log too large')
        # Сохраняются или экспортируются только обезличенные журналы. URL могут
        # содержать временные параметры авторизации; удаляйте URL полностью, а не
        # только известные имена секретов в query.
        output = raw.read_text(encoding='utf-8', errors='replace')
        output = re.sub(r'https?://[^\s\x00-\x1f]+', '[URL REDACTED]', output)
        output = re.sub(r'(?im)^.*?\b(?:authorization|cookie|set-cookie)\s*[:=][^\r\n]*$',
                        '[CREDENTIAL REDACTED]', output)
        output = re.sub(r'(?im)\b(authorization|cookie|set-cookie|password|secret|token|api[_-]?key|refresh[_-]?token)\b\s*[:=]\s*[^\s]+',
                        '[CREDENTIAL REDACTED]', output)
        output = re.sub(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]+',
                        '[JWT REDACTED]', output)
        # Публикуйте только ограниченный по объёму непустой журнал исполнения с удалёнными секретами.
        log.write_text('command=' + log.stem + '\nexit=' + str(result.returncode) +
                       '\nduration-ms=' + str(int(1000 * (time.monotonic() - start))) + '\n' + output,
                       encoding='utf-8')
        os.chmod(log, 0o600)
        require(result.returncode == 0, 'Нативная команда завершилась ошибкой: ' + Path(str(argv[0])).name)
    except subprocess.TimeoutExpired as exc:
        raise Blocked('Превышено время ожидания нативной команды: ' + Path(str(argv[0])).name) from exc
    finally:
        raw.unlink(missing_ok=True)
    return {'sha256': file_hash(log), 'size': log.stat().st_size}


def native_verify(asset, package, work, a):
    osname, arch = host_target()
    logs = {}
    def cmd(label, arguments, timeout=120):
        logs[label] = execute(arguments, timeout, work / (label + '.log'))
    if osname == 'windows':
        thumb = (a.windows_thumbprint or '').upper().replace(' ', '')
        require(re.fullmatch('[A-F0-9]{40}', thumb) is not None,
                'Требуется независимо закреплённый отпечаток сертификата Authenticode')
        # -File передаёт буквальные позиционные параметры. -Command разбирал бы завершающие пути как
        # PowerShell-код и мог бы нарушить кавычки либо допустить инъекцию.
        script = work / 'verify-native-authenticode.ps1'
        script.write_text(r'''param([Parameter(Mandatory=$true)][string]$File,
      [Parameter(Mandatory=$true)][string]$Expected)
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $File
if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate) { throw 'Недопустимая цепочка сертификатов Authenticode' }
if ($signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $Expected) { throw 'wrong signer certificate' }
Write-Output 'verified Authenticode chain and independently pinned signer'
''', encoding='utf-8')
        try:
            cmd('native-signature', ['pwsh', '-NoProfile', '-NonInteractive', '-File',
                                     str(script), str(package), thumb])
        finally:
            script.unlink(missing_ok=True)
        installer = package
        cmd('bootstrap-verification', [installer, 'verify'])
    elif osname == 'linux':
        require(a.linux_keyring is not None, 'Требуется независимо закреплённый путь к хранилищу ключей Linux')
        keyring = regular(a.linux_keyring.absolute(), 4 * 1024 * 1024)
        require(SHA.fullmatch(a.linux_keyring_sha256 or '') and
                file_hash(keyring) == a.linux_keyring_sha256, 'untrusted Linux GPG keyring')
        fingerprint = (a.linux_fingerprint or '').upper()
        require(re.fullmatch('[0-9A-F]{40}', fingerprint) is not None, 'Требуется закреплённый отпечаток GPG Linux')
        sig = work / (asset['filename'] + '.asc')
        require(sig.is_file(), 'Отсутствует отдельная подпись пакета Linux')
        # gpgv запускается только с независимо подготовленным хранилищем ключей.
        cmd('native-signature', ['gpgv', '--keyring', str(keyring), '--status-fd', '1', str(sig), str(package)])
        status = (work / 'native-signature.log').read_text(errors='replace')
        require(re.search(r'^\[GNUPG:\] VALIDSIG ' + re.escape(fingerprint) + r'\b', status, re.M),
                'Linux signature not made by pinned GPG fingerprint')
        cmd('package-metadata', ['dpkg-deb', '--field', str(package)])
        meta = (work / 'package-metadata.log').read_text(errors='replace')
        require(re.search(r'^Package: launcher-' + re.escape(a.project) + r'$', meta, re.M) and
                re.search(r'^Version: ' + re.escape(a.version) + r'$', meta, re.M) and
                re.search(r'^Architecture: ' + ('amd64' if arch == 'x64' else 'arm64') + r'$', meta, re.M),
                'Linux .deb package metadata mismatches pinned project/version/architecture')
        # Выполняйте системный пакетный менеджер на одноразовом runner, а не на извлечённых поддельных данных.
        require(a.disposable_runner and os.environ.get('GITHUB_ACTIONS') == 'true',
                'system package install allowed ONLY on ephemeral GitHub native runner')
        cmd('system-install', ['sudo', 'dpkg', '-i', str(package)], 180)
        installer = Path('/usr/lib/launcher/bundle/neverinstaller')
        require(installer.is_file() and installer.stat().st_mode & stat.S_IXUSR,
                'Не найден установленный в системе Linux neverinstaller')
        cmd('bootstrap-verification', [str(installer), 'verify', '--bundle', '/usr/lib/launcher/bundle'])
    else:
        team = a.apple_team_id or ''
        require(re.fullmatch('[A-Z0-9]{10}', team) is not None, 'Требуется независимо закреплённый Apple Team ID')
        cmd('native-signature', ['pkgutil', '--check-signature', str(package)])
        output = (work / 'native-signature.log').read_text(errors='replace')
        require('Developer ID Installer:' in output and ('(' + team + ')') in output and
                ('trusted' in output.lower() or 'Status: signed' in output), 'Удостоверение или цепочка сертификатов установщика macOS отклонены')
        cmd('gatekeeper-package', ['spctl', '--assess', '--type', 'install', '--verbose=4', str(package)])
        cmd('notarization', ['xcrun', 'stapler', 'validate', str(package)])
        require(a.disposable_runner and os.environ.get('GITHUB_ACTIONS') == 'true',
                'system package install allowed ONLY on ephemeral GitHub native runner')
        app = Path('/Applications/Launcher.app')
        require(not app.exists() and not app.is_symlink(), 'pre-existing macOS app would be overwritten')
        cmd('system-install', ['sudo', 'installer', '-pkg', str(package), '-target', '/'], 300)
        installer = app / 'Contents/MacOS/Launcher'
        require(installer.is_file(), 'Исполняемый файл установленного приложения macOS отсутствует')
        cmd('codesign-app', ['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)])
        cmd('gatekeeper-app', ['spctl', '--assess', '--type', 'execute', '--verbose=4', str(app)])
        cmd('bootstrap-verification', [str(installer), 'verify'])
        cmd('app-signature-details', ['codesign', '-dv', '--verbose=4', str(app)])
        details = (work / 'app-signature-details.log').read_text(errors='replace')
        require('TeamIdentifier=' + team in details, 'installed app signed by wrong Apple team')

    # Windows .exe сам является установщиком. Linux/macOS используют настоящий исполняемый файл,
    # установленный средствами ОС, а не новую сборку исходников или тестовую заглушку.
    root = work / 'installation'
    root.mkdir(mode=0o700)
    target_bundle = ['/usr/lib/launcher/bundle'] if osname == 'linux' else []
    cmd('provision', [str(installer), 'install', '--root', str(root), '--no-start', *(
        ['--bundle', target_bundle[0]] if target_bundle else [])], 1200)
    cmd('verify-installed', [str(installer), 'verify-installed', '--root', str(root)])
    # Не считайте пустой маркер подтверждением установки. Этот путь
    # записывается лишь после успешного завершения Prestarter.
    active = root / '.launcher-installer'
    require(active.is_dir() and any(active.glob('active-*.json')), 'Не найдена подтверждённая установка')
    cmd('uninstall', [str(installer), 'uninstall', '--root', str(root)])
    return logs


def run(a):
    osname, arch = host_target()
    require(a.disposable_runner and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_TEMP'), 'requires confirmed disposable native CI runner')
    require(COMMIT.fullmatch(a.commit or '') and RUN.fullmatch(a.run_id or '') and
            RUN.fullmatch(a.attempt or ''), 'Необходимо закрепить исходный коммит и запуск/попытку CI')
    require(a.output.is_absolute() and not a.output.exists() and not a.output.is_symlink(),
            'Выходной каталог должен быть новым и абсолютным')
    require(a.output.parent.is_dir() and not a.output.parent.is_symlink(), 'unsafe output parent')
    # Размещайте временные данные исключительно под собственным каталогом одноразового runner.
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    require(a.output.resolve().is_relative_to(runner_temp), 'Результат приёмки должен оставаться в RUNNER_TEMP')
    a.output.mkdir(mode=0o700)
    try:
        data_path = a.output / 'sources.json'
        fetch(a.manifest_url, data_path, a.manifest_sha256, a.manifest_size)
        index = read_index(data_path.read_bytes(), a.manifest_sha256, a.version, a.commit, a.project)
        asset = index[osname, arch]
        package = a.output / asset['filename']
        fetch(asset['url'], package, asset['sha256'], asset['size'])
        if osname == 'linux':
            fetch(asset['signatureUrl'], a.output / (asset['filename'] + '.asc'),
                  asset['signatureSha256'], asset['signatureSize'])
        logs = native_verify(asset, package, a.output, a)
        report = {'schema': RESULT_SCHEMA, 'status': 'PASS', 'version': a.version,
                  'commit': a.commit, 'project': a.project, 'sourceIndexSha256': a.manifest_sha256,
                  'runId': a.run_id, 'attempt': a.attempt, 'platform': osname,
                  'architecture': arch, 'runner': platform.node(),
                  'observedAt': datetime.now(timezone.utc).isoformat(),
                  'package': {'filename': asset['filename'], 'sha256': asset['sha256'], 'size': asset['size']},
                  'checks': {key: {'sha256': value['sha256'], 'size': value['size']}
                             for key, value in sorted(logs.items())},
                  'nativeSigned': True, 'actuallyProvisioned': True,
                  'independentGA': False}
        (a.output / 'receipt.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        # Сохраняйте только обезличенные журналы команд, привязанные хешами, и квитанцию. Никогда не
        # загружайте в отчёты скачанные пакеты, исходные URL и подписанную конфигурацию.
        for p in a.output.iterdir():
            if p.name != 'receipt.json' and not p.name.endswith('.log'):
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                else:
                    p.unlink()
        return report
    except BaseException as exc:
        # Для заблокированных запусков сохраняйте только ограниченные обезличенные диагностические
        # журналы. Не оставляйте частичный PASS, пакет выпуска, подписанный исходный URL или
        # необработанный вывод процесса в приёмочных артефактах CI.
        for p in a.output.iterdir():
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            elif not p.name.endswith('.log'):
                p.unlink()
        failure = {'schema': RESULT_SCHEMA, 'status': 'BLOCKED',
                   'version': a.version, 'commit': a.commit, 'platform': osname,
                   'architecture': arch, 'reason': type(exc).__name__,
                   'runId': a.run_id, 'attempt': a.attempt}
        (a.output / 'blocked.json').write_text(json.dumps(failure, sort_keys=True) + '\n')
        raise


def aggregate(a):
    require(a.results.is_absolute() and a.results.is_dir() and not a.results.is_symlink(),
            'Требуется корневой каталог результатов')
    raw = regular(a.source_index.absolute(), MAX_INDEX).read_bytes()
    index = read_index(raw, a.manifest_sha256, a.version, a.commit, a.project)
    require(RUN.fullmatch(a.run_id or '') and RUN.fullmatch(a.attempt or ''), 'Требуется ожидаемый запуск/попытка')
    discovered, machines = {}, set()
    for item in a.results.iterdir():
        require(item.is_dir() and not item.is_symlink(), 'Неожиданный элемент подтверждающих данных')
        files = list(item.iterdir())
        require(all(p.is_file() and not p.is_symlink() for p in files), 'Неожиданный элемент подтверждающих данных')
        receipt_path = item / 'receipt.json'
        doc = parse_json(regular(receipt_path.resolve(), MAX_INDEX).read_bytes())
        require(type(doc) is dict and set(doc) == {'schema', 'status', 'version', 'commit', 'project',
                'sourceIndexSha256', 'runId', 'attempt', 'platform', 'architecture', 'runner',
                'observedAt', 'package', 'checks', 'nativeSigned', 'actuallyProvisioned', 'independentGA'},
                'Недопустимая структура нативного наблюдения')
        target = (doc['platform'], doc['architecture'])
        require(target in index and target not in discovered, 'duplicate/unknown native target')
        require(doc['schema'] == RESULT_SCHEMA and doc['status'] == 'PASS'
                and doc['version'] == a.version and doc['commit'] == a.commit
                and doc['project'] == a.project and doc['sourceIndexSha256'] == a.manifest_sha256
                and doc['runId'] == a.run_id and doc['attempt'] == a.attempt
                and doc['nativeSigned'] is True and doc['actuallyProvisioned'] is True
                and doc['independentGA'] is False, 'stale/forged native observation')
        require(doc['package'] == {k: index[target][k] for k in ('filename', 'sha256', 'size')},
                'report references different final bytes')
        checks = doc['checks']
        must = {'native-signature', 'bootstrap-verification', 'provision', 'verify-installed', 'uninstall'}
        if target[0] == 'linux':
            must |= {'system-install', 'package-metadata'}
        elif target[0] == 'macos':
            must |= {'system-install', 'notarization', 'gatekeeper-package', 'codesign-app',
                     'gatekeeper-app', 'app-signature-details'}
        require(type(checks) is dict and set(checks) == must and
                all(type(c) is dict and set(c) == {'sha256','size'} and
                    SHA.fullmatch(c['sha256']) and type(c['size']) is int and 0 < c['size'] <= MAX_LOG
                    for c in checks.values()), 'Отсутствуют квитанции нативных проверок')
        require({p.name for p in files} == {'receipt.json'} | {x + '.log' for x in must},
                'Отсутствует или не соответствует ожиданиям журнал нативного выполнения')
        for name, evidence in checks.items():
            log = regular((item / (name + '.log')).resolve(), MAX_LOG)
            require(log.stat().st_size == evidence['size'] and file_hash(log) == evidence['sha256'],
                    'modified native execution log: ' + name)
            first = log.read_bytes()[:1024]
            require(first.startswith(('command=' + name + '\nexit=0\n').encode()),
                    'native process did not report exit=0: ' + name)
        require(isinstance(doc['runner'], str) and 3 <= len(doc['runner']) <= 128 and
                doc['runner'] not in machines, 'Идентификатор исполнителя отсутствует или уже использован')
        machines.add(doc['runner'])
        try:
            observed = datetime.fromisoformat(doc['observedAt'].replace('Z', '+00:00'))
            require(observed.tzinfo is not None, 'observation timestamp without zone')
        except (ValueError, TypeError) as exc:
            raise Blocked('Недопустимая временная метка наблюдения') from exc
        discovered[target] = {'platform': target[0], 'architecture': target[1],
                              'receiptSha256': file_hash(receipt_path), 'runner': doc['runner'],
                              'packageSha256': doc['package']['sha256']}
    require(set(discovered) == TARGETS, 'Требуются шесть независимых наблюдений нативных пакетов')
    return {'schema': SUMMARY_SCHEMA, 'status': 'CI_OBSERVED_REVIEW_REQUIRED',
            'version': a.version, 'commit': a.commit, 'project': a.project,
            'sourceIndexSha256': a.manifest_sha256, 'runId': a.run_id,
            'attempt': a.attempt, 'nativeTargets': [discovered[k] for k in sorted(discovered)],
            'independentGA': False}


def build_index(a):
    """Перечень контрольных сумм шести фактических финальных файлов выпуска на стороне оператора.

    Само создание индекса НЕ разрешает использование пакетов. До нативной приёмки независимый
    оператор должен закрепить SHA-256 вне канала загрузки.
    """
    require(a.packages.is_absolute() and a.packages.is_dir() and not a.packages.is_symlink(),
            'Требуется каталог фактических финальных пакетов')
    require(COMMIT.fullmatch(a.commit or '') and PROJECT.fullmatch(a.project or '') and
            re.fullmatch(r'\d+\.\d+\.\d+', a.version or ''),
            'Требуются точные версия продукта, проект и коммит')
    valid_https(a.base_url)
    require(a.base_url.endswith('/') and not urllib.parse.urlsplit(a.base_url).query,
            'Базовый URL релиза должен заканчиваться на / и не содержать query')
    assets = []
    for osname, arch in sorted(TARGETS):
        filename = expected_filename(a.version, a.project, osname, arch)
        path = regular(a.packages / filename, MAX_PACKAGE)
        artifact = {'platform': osname, 'architecture': arch, 'filename': filename,
                    'url': a.base_url + filename, 'sha256': file_hash(path), 'size': path.stat().st_size}
        require(artifact['size'] >= 100, 'undersized final package')
        if osname == 'linux':
            sig = regular(a.packages / (filename + '.asc'), 8192)
            require(sig.stat().st_size >= 100, 'undersized Linux detached signature')
            artifact.update(signatureUrl=a.base_url + filename + '.asc',
                            signatureSha256=file_hash(sig), signatureSize=sig.stat().st_size)
        assets.append(artifact)
    result = {'schema': SCHEMA, 'version': a.version, 'commit': a.commit,
              'project': a.project, 'assets': assets}
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    read_index(raw, digest(raw), a.version, a.commit, a.project)
    require(a.output.is_absolute() and not a.output.exists() and not a.output.is_symlink(),
            'Путь индекса должен быть неиспользуемым и абсолютным')
    a.output.write_bytes(raw)
    return {'indexSha256': digest(raw), 'indexSize': len(raw), 'packages': len(assets),
            'note': 'Закрепите SHA-256 индекса через независимое утверждение релиза; создание индекса само по себе не подтверждает GA.'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def trusted_review_key(path, fingerprint):
    raw = regular(path.absolute(), 8192).read_bytes()
    key = serialization.load_pem_public_key(raw)
    require(isinstance(key, Ed25519PublicKey), 'Независимый проверяющий должен использовать Ed25519')
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(SHA.fullmatch(fingerprint or '') and digest(spki) == fingerprint,
            'reviewer public key does not match independently pinned SPKI SHA-256')
    return key


def sign_review(a):
    summary = aggregate(a)  # Не подписывать до повторной проверки всех шести исходных квитанций и журналов.
    reviewer = a.reviewer or ''
    require(re.fullmatch('[A-Za-z][A-Za-z0-9._-]{2,63}', reviewer) is not None,
            'Требуется идентификатор независимого проверяющего')
    require(a.private_key.is_absolute() and not a.private_key.resolve().is_relative_to(
            Path(__file__).resolve().parents[2]), 'Закрытый ключ проверяющего должен находиться вне рабочей копии репозитория')
    key_file = regular(a.private_key, 8192)
    require(key_file.stat().st_mode & 0o077 == 0, 'Закрытый ключ проверяющего должен иметь права 0600')
    private = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    public = trusted_review_key(a.public_key, a.public_key_sha256)
    require(isinstance(private, Ed25519PrivateKey) and
            private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            == public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            'Несовпадение ключевой пары проверяющего')
    payload = {'schema': 'neverlauncher.native-final-package-review/0.52.2',
               'reviewer': reviewer, 'reviewedAt': datetime.now(timezone.utc).isoformat(),
               'summary': summary, 'independentGA': False}
    sealed = {'payload': payload, 'signatureEd25519': private.sign(
        REVIEW_DOMAIN + canonical(payload)).hex(), 'publicKeySha256': a.public_key_sha256}
    require(a.output.is_absolute() and not a.output.exists() and not a.output.is_symlink(),
            'Путь результата независимого утверждения должен быть неиспользуемым абсолютным путём')
    fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(canonical(sealed) + b'\n')
        f.flush()
        os.fsync(f.fileno())
    return {'status': 'CI_OBSERVED_SIGNED_REVIEW_NOT_GA', 'version': a.version}


def verify_review(a):
    public = trusted_review_key(a.public_key, a.public_key_sha256)
    sealed = parse_json(regular(a.receipt, MAX_INDEX).read_bytes())
    require(type(sealed) is dict and set(sealed) == {'payload', 'signatureEd25519', 'publicKeySha256'}
            and sealed['publicKeySha256'] == a.public_key_sha256 and
            re.fullmatch(r'[0-9a-f]{128}', sealed['signatureEd25519'] or '') is not None,
            'Недопустимая оболочка утверждения')
    try:
        public.verify(bytes.fromhex(sealed['signatureEd25519']),
                      REVIEW_DOMAIN + canonical(sealed['payload']))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Blocked('Недопустимая подпись независимого проверяющего') from exc
    payload = sealed['payload']
    require(type(payload) is dict and set(payload) == {'schema','reviewer','reviewedAt','summary','independentGA'}
            and payload['schema'] == 'neverlauncher.native-final-package-review/0.52.2'
            and payload['reviewer'] == a.reviewer and payload['independentGA'] is False,
            'Утверждение выполнено не ожидаемым независимым проверяющим')
    try:
        timestamp = datetime.fromisoformat(payload['reviewedAt'].replace('Z', '+00:00'))
        age = datetime.now(timezone.utc) - timestamp
        require(timestamp.tzinfo and timedelta(minutes=-1) <= age <= timedelta(days=7),
                'review too old or from the future')
    except (ValueError, TypeError, AttributeError) as exc:
        raise Blocked('Недопустимая временная метка проверки') from exc
    require(payload['summary'] == aggregate(a), 'Подтверждения одобренного пакета больше не соответствуют исходным байтам')
    return {'status': 'CI_OBSERVED_SIGNED_REVIEW_NOT_GA', 'version': a.version,
            'reviewer': a.reviewer, 'independentGA': False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    runp = sub.add_parser('run')
    runp.add_argument('--manifest-url', required=True)
    runp.add_argument('--manifest-sha256', required=True)
    runp.add_argument('--manifest-size', type=int, required=True)
    runp.add_argument('--version', required=True)
    runp.add_argument('--commit', required=True)
    runp.add_argument('--project', required=True)
    runp.add_argument('--run-id', required=True)
    runp.add_argument('--attempt', required=True)
    runp.add_argument('--output', type=Path, required=True)
    runp.add_argument('--linux-keyring', type=Path)
    runp.add_argument('--linux-keyring-sha256')
    runp.add_argument('--linux-fingerprint')
    runp.add_argument('--windows-thumbprint')
    runp.add_argument('--apple-team-id')
    runp.add_argument('--disposable-runner', action='store_true')
    indexp = sub.add_parser('index')
    indexp.add_argument('--packages', type=Path, required=True)
    indexp.add_argument('--base-url', required=True)
    indexp.add_argument('--version', required=True)
    indexp.add_argument('--commit', required=True)
    indexp.add_argument('--project', required=True)
    indexp.add_argument('--output', type=Path, required=True)
    agg = sub.add_parser('aggregate')
    agg.add_argument('--results', type=Path, required=True)
    agg.add_argument('--source-index', type=Path, required=True)
    agg.add_argument('--manifest-sha256', required=True)
    agg.add_argument('--version', required=True)
    agg.add_argument('--commit', required=True)
    agg.add_argument('--project', required=True)
    agg.add_argument('--run-id', required=True)
    agg.add_argument('--attempt', required=True)
    agg.add_argument('--output', type=Path, required=True)
    for action in ('sign-review', 'verify-review'):
        r = sub.add_parser(action)
        r.add_argument('--results', type=Path, required=True)
        r.add_argument('--source-index', type=Path, required=True)
        r.add_argument('--manifest-sha256', required=True)
        r.add_argument('--version', required=True)
        r.add_argument('--commit', required=True)
        r.add_argument('--project', required=True)
        r.add_argument('--run-id', required=True)
        r.add_argument('--attempt', required=True)
        r.add_argument('--reviewer', required=True)
        r.add_argument('--public-key', type=Path, required=True)
        r.add_argument('--public-key-sha256', required=True)
        if action == 'sign-review':
            r.add_argument('--private-key', type=Path, required=True)
            r.add_argument('--output', type=Path, required=True)
        else:
            r.add_argument('--receipt', type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.action == 'index':
            result = build_index(args)
        elif args.action == 'sign-review':
            result = sign_review(args)
        elif args.action == 'verify-review':
            result = verify_review(args)
        elif args.action == 'run':
            require(type(args.manifest_size) is int and 100 <= args.manifest_size <= MAX_INDEX,
                    'Размер манифеста должен быть закреплён внешним способом')
            result = run(args)
        else:
            result = aggregate(args)
            require(args.output.is_absolute() and not args.output.exists() and
                    not args.output.is_symlink(), 'Путь отчёта должен быть неиспользуемым и абсолютным')
            args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        print(json.dumps(result if args.action in ('index','sign-review','verify-review') else {'status': result['status'], 'version': result['version']}, sort_keys=True))
        return 0
    except (Blocked, OSError, subprocess.SubprocessError, urllib.error.URLError,
            TypeError, KeyError) as exc:
        print('Нативная приёмка 0.52.2 заблокирована: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
