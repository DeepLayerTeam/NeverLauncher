#!/usr/bin/env python3
"""Verify actual final Guard release on a *native* OS/CPU and emit a hash-bound receipt.

This tool is deliberately separate from the independent reviewer signature.
It refuses cross-compiled/non-native targets and never bypasses OS signature
validation. All trust anchors are external to the release package.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
from delivery_verify_0462 import verify_bundle, read_archive, EXPECTED
from staged_accept_0462 import run_verify

VERSION = '0.51.0'
SUPPORTED = ('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64')


def run(argv, *, env=None, timeout=180):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, env=env)
    if result.returncode != 0:
        raise ValueError(f'native command {argv[0]} failed: {(result.stderr + result.stdout)[-900:]}')
    return result.stdout + result.stderr


def assert_host(target):
    osname, arch = target.split('-')
    actual = platform.system()
    if actual != {'windows': 'Windows', 'linux': 'Linux', 'darwin': 'Darwin'}[osname]:
        raise ValueError('native signing requires the exact target operating system')
    machine = platform.machine().lower()
    if machine not in {'x64': ('amd64', 'x86_64', 'x64'), 'arm64': ('arm64', 'aarch64')}[arch]:
        raise ValueError('native signing requires exact hardware architecture, not emulation')
    return actual, arch


def validate_os(target: str, archive: Path, *, signer: str) -> str:
    osname, _ = target.split('-')
    members = read_archive(archive)
    if osname == 'linux':
        # На платформе нет механизма подписи кода ОС. Закреплённая подпись выпуска Ed25519
        # отдельно проверяется производственным CLI, не на этом этапе ОС.
        if not re.fullmatch(r'[A-Za-z0-9 ._:@-]{3,128}', signer):
            raise ValueError('pinned publisher identity required')
        return 'production-cli-release-trust'
    if osname == 'windows':
        if not re.fullmatch(r'[A-Fa-f0-9]{40}', signer):
            raise ValueError('pinned Authenticode SHA-1 certificate thumbprint required')
        for name in EXPECTED['windows']:
            if name not in members:
                raise ValueError('missing native Windows executable ' + name)
        with tempfile.TemporaryDirectory(prefix='nl-guard-win-sign-') as temp:
            # Нативные API читают реально извлечённый PE-файл, а не метаданные ZIP.
            for name in EXPECTED['windows']:
                exe = Path(temp) / name
                exe.write_bytes(members[name])
                script = ("$s=Get-AuthenticodeSignature -LiteralPath $env:NL_GA_BINARY; "
                          "if ($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate "
                          "-or $s.SignerCertificate.Thumbprint -ne $env:NL_GA_SIGNER "
                          "-or $null -eq $s.TimeStamperCertificate) { exit 13 }")
                env = {**os.environ, 'NL_GA_BINARY': str(exe), 'NL_GA_SIGNER': signer.upper()}
                run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script], env=env)
        return 'authenticode-chain-timestamp'
    if not re.fullmatch(r'[A-Z0-9]{10}', signer):
        raise ValueError('pinned Apple Developer Team ID required')
    for command in ('ditto', 'codesign', 'xcrun', 'spctl'):
        if shutil.which(command) is None:
            raise ValueError('missing native macOS signature validation tool: ' + command)
    with tempfile.TemporaryDirectory(prefix='nl-guard-mac-sign-') as temp:
        # read_archive отклоняет символьные ссылки и обход путей до извлечения.
        run(['ditto', '-xk', str(archive), temp])
        app = Path(temp) / 'Launcher.app'
        if not app.is_dir():
            raise ValueError('real signed Launcher.app missing')
        run(['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)])
        actual_signer = run(['codesign', '-dv', '--verbose=4', str(app)])
        if 'TeamIdentifier=' + signer not in actual_signer:
            raise ValueError('signed app has different Apple Developer Team ID')
        run(['spctl', '--assess', '--type', 'execute', '--verbose=2', str(app)])
        run(['xcrun', 'stapler', 'validate', str(app)])
    return 'codesign-gatekeeper-notarized'


def verify(target: str, bundle: Path, commit: str, signer: str, operator: str, execution: str,
           cli: Path, public_key: Path, trust_policy: Path, operator_key: Path) -> dict:
    if target not in SUPPORTED or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('invalid target or source commit')
    for value in (signer, operator, execution):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@ -]{2,127}', value):
            raise ValueError('real signer/operator/execution identity required')
    native, arch = assert_host(target)
    release = verify_bundle(bundle, release_manifest=True)
    if release['version'] != VERSION:
        raise ValueError('final package is not version 0.51.0')
    # Криптографическая проверка распространяемого выпуска использует внешние доверенные корни
    # и СКОМПИЛИРОВАННЫЙ CLI выпуска до нативной проверки подписи ОС.
    run_verify(cli, bundle, public_key, trust_policy, operator_key)
    row = release['targets'][target]
    verifier = validate_os(target, bundle / row['file'], signer=signer)
    manifest = bundle / 'RELEASE_MANIFEST.json'
    return {'schema': 'neverlauncher.guard.native-signed/0510',
            'version': VERSION, 'commit': commit, 'target': target,
            'status': 'native-verified', 'packageSha256': row['sha256'],
            'releaseManifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
            'nativeOS': native, 'nativeArch': arch, 'verifier': verifier,
            'publisherSigner': signer, 'operator': operator, 'executionId': execution}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', choices=SUPPORTED, required=True)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--expected-signer', required=True)
    p.add_argument('--operator', required=True)
    p.add_argument('--execution-id', required=True)
    p.add_argument('--release-cli', type=Path, required=True)
    p.add_argument('--release-public-key', type=Path, required=True)
    p.add_argument('--trust-policy', type=Path, required=True)
    p.add_argument('--operations-public-key', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(argv)
    a.output.unlink(missing_ok=True)
    try:
        data = verify(a.target, a.bundle, a.commit, a.expected_signer,
                      a.operator, a.execution_id, a.release_cli, a.release_public_key,
                      a.trust_policy, a.operations_public_key)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        print(a.target + ': real native signature verified; independent approval still required')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print('GUARD 0.51.0 native signing BLOCKED: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
