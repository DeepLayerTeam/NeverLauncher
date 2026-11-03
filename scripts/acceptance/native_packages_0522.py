#!/usr/bin/env python3
"""0.52.2 real six-OS final branded-installer acceptance.

The source index is pinned OUTSIDE the downloaded index by SHA-256. Every
package is fetched over HTTPS, hash checked, authenticated by the operating
system's native signature verifier, installed and executed on the *matching*
native, disposable runner. No simulated package or cross-build can pass.
CI observations are NOT independent GA/physical-machine certification.
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
        raise Blocked('invalid JSON') from exc


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_hash(path):
    sha = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def regular(path, maximum):
    require(path.is_absolute() and not path.is_symlink() and path.is_file(), 'missing/unsafe file: ' + str(path))
    require(not any(p.is_symlink() for p in path.parents), 'symlink ancestor in ' + str(path))
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= maximum,
            'invalid size/link count: ' + str(path))
    return path


def expected_filename(version, project, osname, arch):
    suffix = {'windows': ('.exe', 'windows'), 'linux': ('.deb', 'linux'),
              'macos': ('.pkg', 'macos')}[osname]
    return f'launcher-{version}-{project}-{suffix[1]}-{arch}{suffix[0]}'


def valid_https(url):
    require(type(url) is str and len(url) <= 4096, 'invalid HTTPS URL')
    p = urllib.parse.urlsplit(url)
    require(p.scheme == 'https' and bool(p.hostname) and p.port in (None, 443)
            and not p.username and not p.password and not p.fragment,
            'release input must be HTTPS, no credentials, port or fragment')
    require(not p.hostname.lower() in ('localhost', 'localhost.localdomain')
            and not p.hostname.endswith('.localhost'), 'no local release URLs')
    # No literal IPv4/IPv6 private, loopback or link-local hosts.
    import ipaddress
    try:
        ip = ipaddress.ip_address(p.hostname)
    except ValueError:
        return url
    require(ip.is_global, 'release URL must not target private/network-local IP')
    return url


def read_index(data, expected_sha, version, commit, project):
    require(type(expected_sha) is str and SHA.fullmatch(expected_sha) and digest(data) == expected_sha,
            'release source index does not match independently pinned SHA-256')
    require(len(data) <= MAX_INDEX, 'source index too large')
    doc = parse_json(data)
    require(type(doc) is dict and set(doc) == {'schema', 'version', 'commit', 'project', 'assets'},
            'unexpected source index fields')
    require(doc['schema'] == SCHEMA and doc['version'] == version and doc['commit'] == commit
            and doc['project'] == project and COMMIT.fullmatch(commit) and PROJECT.fullmatch(project),
            'source/version/project mismatch')
    assets = doc['assets']
    require(type(assets) is list and len(assets) == 6, 'must contain exactly six final packages')
    seen, seen_urls = {}, set()
    for item in assets:
        require(type(item) is dict and set(item) in (
            {'platform', 'architecture', 'filename', 'url', 'sha256', 'size'},
            {'platform', 'architecture', 'filename', 'url', 'sha256', 'size', 'signatureUrl', 'signatureSha256', 'signatureSize'}
        ), 'invalid package source fields')
        target = (item.get('platform'), item.get('architecture'))
        require(target in TARGETS and target not in seen, 'unsupported/duplicate target')
        require(item['filename'] == expected_filename(version, project, *target), 'unexpected package name')
        require(type(item['sha256']) is str and SHA.fullmatch(item['sha256']), 'invalid package digest')
        require(type(item['size']) is int and 100 <= item['size'] <= MAX_PACKAGE, 'invalid package size')
        urls = [item['url']]
        if target[0] == 'linux':
            require(set(item) == {'platform', 'architecture', 'filename', 'url', 'sha256', 'size',
                                  'signatureUrl', 'signatureSha256', 'signatureSize'},
                    'Linux package requires detached GPG signature')
            require(SHA.fullmatch(item['signatureSha256']) and
                    type(item['signatureSize']) is int and 100 <= item['signatureSize'] <= 8192,
                    'invalid Linux signature checksum/size')
            urls.append(item['signatureUrl'])
        else:
            require('signatureUrl' not in item, 'Windows and macOS use embedded platform signatures')
        for url in urls:
            valid_https(url)
            require(url not in seen_urls, 'reused package/source URL')
            seen_urls.add(url)
        seen[target] = item
    require(set(seen) == TARGETS, 'missing native platform/architecture')
    return seen


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        valid_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, destination, expected_sha, expected_size, *, opener=None):
    valid_https(url)
    require(not destination.exists() and not destination.is_symlink(), 'download path already exists')
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
                require(total <= expected_size, 'download exceeds pinned size')
                sha.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        require(total == expected_size and sha.hexdigest() == expected_sha, 'download checksum/size mismatch')
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {'sha256': sha.hexdigest(), 'size': total}


def host_target():
    osname = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system())
    arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    require((osname, arch) in TARGETS and sys.maxsize > 2**32,
            'native 64-bit operating system/architecture runner required')
    if osname == 'windows':
        # A 32-bit/emulated Python process must not masquerade as native ARM64.
        require(os.environ.get('PROCESSOR_ARCHITECTURE', '').lower() in ('amd64', 'arm64') and
                os.environ.get('PROCESSOR_ARCHITECTURE', '').lower() in (
                    ('amd64',) if arch == 'x64' else ('arm64',)), 'emulated Windows runner forbidden')
    return (osname, arch)


def execute(argv, timeout, log):
    # Only fixed locally constructed command arrays; user-supplied URLs/file names
    # are never interpolated into shell commands. No stdout is sent to CI logs.
    raw = log.with_suffix('.unredacted')
    start = time.monotonic()
    try:
        with raw.open('wb') as f:
            os.chmod(raw, 0o600)
            result = subprocess.run([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                    stdout=f, stderr=subprocess.STDOUT, timeout=timeout,
                                    check=False)
        require(raw.stat().st_size <= MAX_LOG, 'subprocess log too large')
        # Only redacted logs are ever retained or exported. URLs can contain
        # expiring auth query parameters; remove whole URLs rather than just
        # the most common query-string credential names.
        output = raw.read_text(encoding='utf-8', errors='replace')
        output = re.sub(r'https?://[^\s\x00-\x1f]+', '[URL REDACTED]', output)
        output = re.sub(r'(?im)^.*?\b(?:authorization|cookie|set-cookie)\s*[:=][^\r\n]*$',
                        '[CREDENTIAL REDACTED]', output)
        output = re.sub(r'(?im)\b(authorization|cookie|set-cookie|password|secret|token|api[_-]?key|refresh[_-]?token)\b\s*[:=]\s*[^\s]+',
                        '[CREDENTIAL REDACTED]', output)
        output = re.sub(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]+',
                        '[JWT REDACTED]', output)
        # Only a bounded, redacted and nonempty execution log is published.
        log.write_text('command=' + log.stem + '\nexit=' + str(result.returncode) +
                       '\nduration-ms=' + str(int(1000 * (time.monotonic() - start))) + '\n' + output,
                       encoding='utf-8')
        os.chmod(log, 0o600)
        require(result.returncode == 0, 'native command failed: ' + Path(str(argv[0])).name)
    except subprocess.TimeoutExpired as exc:
        raise Blocked('native command timed out: ' + Path(str(argv[0])).name) from exc
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
                'independently pinned Authenticode certificate thumbprint required')
        # -File passes literal positional parameters. -Command would parse
        # trailing paths as PowerShell source and can break or inject quoting.
        script = work / 'verify-native-authenticode.ps1'
        script.write_text(r'''param([Parameter(Mandatory=$true)][string]$File,
      [Parameter(Mandatory=$true)][string]$Expected)
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $File
if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate) { throw 'invalid Authenticode chain' }
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
        require(a.linux_keyring is not None, 'independently pinned Linux keyring path required')
        keyring = regular(a.linux_keyring.absolute(), 4 * 1024 * 1024)
        require(SHA.fullmatch(a.linux_keyring_sha256 or '') and
                file_hash(keyring) == a.linux_keyring_sha256, 'untrusted Linux GPG keyring')
        fingerprint = (a.linux_fingerprint or '').upper()
        require(re.fullmatch('[0-9A-F]{40}', fingerprint) is not None, 'pinned Linux GPG fingerprint required')
        sig = work / (asset['filename'] + '.asc')
        require(sig.is_file(), 'missing detached Linux package signature')
        # gpgv is invoked with only the independently provisioned keyring.
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
        # Execute OS package manager on disposable runner, not extracted fake bits.
        require(a.disposable_runner and os.environ.get('GITHUB_ACTIONS') == 'true',
                'system package install allowed ONLY on ephemeral GitHub native runner')
        cmd('system-install', ['sudo', 'dpkg', '-i', str(package)], 180)
        installer = Path('/usr/lib/launcher/bundle/neverinstaller')
        require(installer.is_file() and installer.stat().st_mode & stat.S_IXUSR,
                'Linux system-installed neverinstaller missing')
        cmd('bootstrap-verification', [str(installer), 'verify', '--bundle', '/usr/lib/launcher/bundle'])
    else:
        team = a.apple_team_id or ''
        require(re.fullmatch('[A-Z0-9]{10}', team) is not None, 'independently pinned Apple Team ID required')
        cmd('native-signature', ['pkgutil', '--check-signature', str(package)])
        output = (work / 'native-signature.log').read_text(errors='replace')
        require('Developer ID Installer:' in output and ('(' + team + ')') in output and
                ('trusted' in output.lower() or 'Status: signed' in output), 'macOS installer identity/chain rejected')
        cmd('gatekeeper-package', ['spctl', '--assess', '--type', 'install', '--verbose=4', str(package)])
        cmd('notarization', ['xcrun', 'stapler', 'validate', str(package)])
        require(a.disposable_runner and os.environ.get('GITHUB_ACTIONS') == 'true',
                'system package install allowed ONLY on ephemeral GitHub native runner')
        app = Path('/Applications/Launcher.app')
        require(not app.exists() and not app.is_symlink(), 'pre-existing macOS app would be overwritten')
        cmd('system-install', ['sudo', 'installer', '-pkg', str(package), '-target', '/'], 300)
        installer = app / 'Contents/MacOS/Launcher'
        require(installer.is_file(), 'macOS installed app executable missing')
        cmd('codesign-app', ['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)])
        cmd('gatekeeper-app', ['spctl', '--assess', '--type', 'execute', '--verbose=4', str(app)])
        cmd('bootstrap-verification', [str(installer), 'verify'])
        cmd('app-signature-details', ['codesign', '-dv', '--verbose=4', str(app)])
        details = (work / 'app-signature-details.log').read_text(errors='replace')
        require('TeamIdentifier=' + team in details, 'installed app signed by wrong Apple team')

    # Windows .exe itself is the installer. Linux/macOS use the actual OS-
    # installed executable, never a new source build or a test stub.
    root = work / 'installation'
    root.mkdir(mode=0o700)
    target_bundle = ['/usr/lib/launcher/bundle'] if osname == 'linux' else []
    cmd('provision', [str(installer), 'install', '--root', str(root), '--no-start', *(
        ['--bundle', target_bundle[0]] if target_bundle else [])], 1200)
    cmd('verify-installed', [str(installer), 'verify-installed', '--root', str(root)])
    # Do not count an empty marker as installation. This path is written only
    # after Prestarter has completed successfully.
    active = root / '.launcher-installer'
    require(active.is_dir() and any(active.glob('active-*.json')), 'no committed installation found')
    cmd('uninstall', [str(installer), 'uninstall', '--root', str(root)])
    return logs


def run(a):
    osname, arch = host_target()
    require(a.disposable_runner and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_TEMP'), 'requires confirmed disposable native CI runner')
    require(COMMIT.fullmatch(a.commit or '') and RUN.fullmatch(a.run_id or '') and
            RUN.fullmatch(a.attempt or ''), 'source commit and CI run/attempt must be pinned')
    require(a.output.is_absolute() and not a.output.exists() and not a.output.is_symlink(),
            'output directory must be new and absolute')
    require(a.output.parent.is_dir() and not a.output.parent.is_symlink(), 'unsafe output parent')
    # Force scratch under disposable runner's own directory.
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    require(a.output.resolve().is_relative_to(runner_temp), 'acceptance output must stay in RUNNER_TEMP')
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
        # Keep only redacted, hash-bound command logs and the receipt.
        # Never upload downloaded packages, source URLs or signed config.
        for p in a.output.iterdir():
            if p.name != 'receipt.json' and not p.name.endswith('.log'):
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                else:
                    p.unlink()
        return report
    except BaseException as exc:
        # Preserve only bounded, redacted diagnostic logs for blocked runs.
        # Never retain a partial PASS, release package, signed source URL or
        # the unredacted process output in CI acceptance artifacts.
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
            'results root required')
    raw = regular(a.source_index.absolute(), MAX_INDEX).read_bytes()
    index = read_index(raw, a.manifest_sha256, a.version, a.commit, a.project)
    require(RUN.fullmatch(a.run_id or '') and RUN.fullmatch(a.attempt or ''), 'expected run/attempt required')
    discovered, machines = {}, set()
    for item in a.results.iterdir():
        require(item.is_dir() and not item.is_symlink(), 'unexpected evidence entry')
        files = list(item.iterdir())
        require(all(p.is_file() and not p.is_symlink() for p in files), 'unexpected evidence entry')
        receipt_path = item / 'receipt.json'
        doc = parse_json(regular(receipt_path.resolve(), MAX_INDEX).read_bytes())
        require(type(doc) is dict and set(doc) == {'schema', 'status', 'version', 'commit', 'project',
                'sourceIndexSha256', 'runId', 'attempt', 'platform', 'architecture', 'runner',
                'observedAt', 'package', 'checks', 'nativeSigned', 'actuallyProvisioned', 'independentGA'},
                'invalid native observation structure')
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
                    for c in checks.values()), 'missing native check receipts')
        require({p.name for p in files} == {'receipt.json'} | {x + '.log' for x in must},
                'missing or unexpected native execution log')
        for name, evidence in checks.items():
            log = regular((item / (name + '.log')).resolve(), MAX_LOG)
            require(log.stat().st_size == evidence['size'] and file_hash(log) == evidence['sha256'],
                    'modified native execution log: ' + name)
            first = log.read_bytes()[:1024]
            require(first.startswith(('command=' + name + '\nexit=0\n').encode()),
                    'native process did not report exit=0: ' + name)
        require(isinstance(doc['runner'], str) and 3 <= len(doc['runner']) <= 128 and
                doc['runner'] not in machines, 'runner identity missing or reused')
        machines.add(doc['runner'])
        try:
            observed = datetime.fromisoformat(doc['observedAt'].replace('Z', '+00:00'))
            require(observed.tzinfo is not None, 'observation timestamp without zone')
        except (ValueError, TypeError) as exc:
            raise Blocked('invalid observation timestamp') from exc
        discovered[target] = {'platform': target[0], 'architecture': target[1],
                              'receiptSha256': file_hash(receipt_path), 'runner': doc['runner'],
                              'packageSha256': doc['package']['sha256']}
    require(set(discovered) == TARGETS, 'six independent native package observations required')
    return {'schema': SUMMARY_SCHEMA, 'status': 'CI_OBSERVED_REVIEW_REQUIRED',
            'version': a.version, 'commit': a.commit, 'project': a.project,
            'sourceIndexSha256': a.manifest_sha256, 'runId': a.run_id,
            'attempt': a.attempt, 'nativeTargets': [discovered[k] for k in sorted(discovered)],
            'independentGA': False}


def build_index(a):
    """Operator-side checksum inventory of the actual six final release files.

    Creating the index does NOT authorize any package. An independent operator
    must pin its SHA-256 outside the download channel before native acceptance.
    """
    require(a.packages.is_absolute() and a.packages.is_dir() and not a.packages.is_symlink(),
            'actual final package directory required')
    require(COMMIT.fullmatch(a.commit or '') and PROJECT.fullmatch(a.project or '') and
            re.fullmatch(r'\d+\.\d+\.\d+', a.version or ''),
            'exact product version, project and commit required')
    valid_https(a.base_url)
    require(a.base_url.endswith('/') and not urllib.parse.urlsplit(a.base_url).query,
            'release base URL must end in / without query')
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
            'index path must be unused and absolute')
    a.output.write_bytes(raw)
    return {'indexSha256': digest(raw), 'indexSize': len(raw), 'packages': len(assets),
            'note': 'Pin index SHA-256 via independent release approval; no GA from index generation.'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def trusted_review_key(path, fingerprint):
    raw = regular(path.absolute(), 8192).read_bytes()
    key = serialization.load_pem_public_key(raw)
    require(isinstance(key, Ed25519PublicKey), 'independent reviewer must use Ed25519')
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(SHA.fullmatch(fingerprint or '') and digest(spki) == fingerprint,
            'reviewer public key does not match independently pinned SPKI SHA-256')
    return key


def sign_review(a):
    summary = aggregate(a)  # No signature before all six raw receipts/logs replay.
    reviewer = a.reviewer or ''
    require(re.fullmatch('[A-Za-z][A-Za-z0-9._-]{2,63}', reviewer) is not None,
            'independent reviewer identifier required')
    require(a.private_key.is_absolute() and not a.private_key.resolve().is_relative_to(
            Path(__file__).resolve().parents[2]), 'private reviewer key must be outside checkout')
    key_file = regular(a.private_key, 8192)
    require(key_file.stat().st_mode & 0o077 == 0, 'independent reviewer key must be mode 0600')
    private = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    public = trusted_review_key(a.public_key, a.public_key_sha256)
    require(isinstance(private, Ed25519PrivateKey) and
            private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            == public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            'reviewer key pair mismatch')
    payload = {'schema': 'neverlauncher.native-final-package-review/0.52.2',
               'reviewer': reviewer, 'reviewedAt': datetime.now(timezone.utc).isoformat(),
               'summary': summary, 'independentGA': False}
    sealed = {'payload': payload, 'signatureEd25519': private.sign(
        REVIEW_DOMAIN + canonical(payload)).hex(), 'publicKeySha256': a.public_key_sha256}
    require(a.output.is_absolute() and not a.output.exists() and not a.output.is_symlink(),
            'independent approval output must be unused absolute path')
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
            'invalid approval envelope')
    try:
        public.verify(bytes.fromhex(sealed['signatureEd25519']),
                      REVIEW_DOMAIN + canonical(sealed['payload']))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Blocked('independent reviewer signature invalid') from exc
    payload = sealed['payload']
    require(type(payload) is dict and set(payload) == {'schema','reviewer','reviewedAt','summary','independentGA'}
            and payload['schema'] == 'neverlauncher.native-final-package-review/0.52.2'
            and payload['reviewer'] == a.reviewer and payload['independentGA'] is False,
            'approval is not by the expected independent reviewer')
    try:
        timestamp = datetime.fromisoformat(payload['reviewedAt'].replace('Z', '+00:00'))
        age = datetime.now(timezone.utc) - timestamp
        require(timestamp.tzinfo and timedelta(minutes=-1) <= age <= timedelta(days=7),
                'review too old or from the future')
    except (ValueError, TypeError, AttributeError) as exc:
        raise Blocked('invalid review timestamp') from exc
    require(payload['summary'] == aggregate(a), 'approved package evidence no longer matches raw bytes')
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
                    'manifest size must be pinned externally')
            result = run(args)
        else:
            result = aggregate(args)
            require(args.output.is_absolute() and not args.output.exists() and
                    not args.output.is_symlink(), 'report path must be unused and absolute')
            args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        print(json.dumps(result if args.action in ('index','sign-review','verify-review') else {'status': result['status'], 'version': result['version']}, sort_keys=True))
        return 0
    except (Blocked, OSError, subprocess.SubprocessError, urllib.error.URLError,
            TypeError, KeyError) as exc:
        print('0.52.2 NATIVE ACCEPTANCE BLOCKED: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
