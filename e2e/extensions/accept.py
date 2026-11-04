#!/usr/bin/env python3
"""Run executable extension acceptance and signed-package attacks on the current OS.

Results describe observed local execution only. A missing binary, OS mismatch,
Java mismatch, failed subprocess or absent signature check makes the job fail.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ("java-host", "examples/extensions/java-host/test-runner.py",
     "examples/extensions/java-host/build/package/backend/java-host.jar"),
    ("java-runtime", "examples/extensions/java-runtime/test-runner.py",
     "examples/extensions/java-runtime/build/package/backend/lib/java-runtime.jar"),
    ("java-lifecycle", "examples/extensions/java-lifecycle/test-runner.py",
     "examples/extensions/java-lifecycle/build/package/backend/lib/java-lifecycle.jar"),
    ("gravit-port", "examples/extensions/gravit-compat/test-runner.py",
     "examples/extensions/gravit-compat/build/package/backend/gravit-port.jar"),
)
STAGES = (
    "examples/extensions/java-host/build/package",
    "examples/extensions/gravit-compat/build/package",
)


def run(args, *, success=True, timeout=110):
    proc = subprocess.run([str(x) for x in args], cwd=ROOT, text=True,
                          capture_output=True, timeout=timeout, check=False)
    if (proc.returncode == 0) != success:
        raise RuntimeError(f"command {' '.join(str(x) for x in args)}: "
                           f"exit {proc.returncode}, expected success={success}\n"
                           f"stdout={proc.stdout[-2500:]}\nstderr={proc.stderr[-2500:]}")
    return proc


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def actual_platform():
    system = {'Linux': 'linux', 'Windows': 'windows', 'Darwin': 'macos'}.get(platform.system())
    machine = platform.machine().lower()
    arch = ('arm64' if machine in ('aarch64', 'arm64') else
            'x64' if machine in ('amd64', 'x86_64') else None)
    if not system or not arch:
        raise RuntimeError(f"unsupported actual host: {platform.platform()}")
    return f'{system}-{arch}'


def check_java_arch(expected):
    proc = run(['java', '-XshowSettings:properties', '-version'])
    match = re.search(r'^\s*os\.arch\s*=\s*([^\s]+)', proc.stderr, re.MULTILINE)
    if not match:
        raise RuntimeError('Java runtime did not publish os.arch')
    arch = match.group(1).lower()
    actual = ('arm64' if arch in ('aarch64', 'arm64') else
              'x64' if arch in ('amd64', 'x86_64') else None)
    if actual != expected.split('-')[1]:
        raise RuntimeError(f"Java architecture mismatch: JVM={arch}, target={expected}")
    return proc.stderr.strip().splitlines()[-1]


def negative_signatures(cli, stage, tmpdir, name):
    private = tmpdir / f'{name}-private.pem'
    public = tmpdir / f'{name}-public.pem'
    wrong_private = tmpdir / f'{name}-wrong.pem'
    wrong_public = tmpdir / f'{name}-wrong.pub'
    package = tmpdir / f'{name}.nlext'
    corrupted = tmpdir / f'{name}-tampered.nlext'
    for key, pub in ((private, public), (wrong_private, wrong_public)):
        run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', key])
        run(['openssl', 'pkey', '-in', key, '-pubout', '-out', pub])
    run([cli, 'extension', 'pack', stage, '--output', package, '--private-key', private])
    run([cli, 'extension', 'verify', package, '--public-key', public])
    run([cli, 'extension', 'verify', package, '--public-key', wrong_public], success=False)
    with zipfile.ZipFile(package, 'r') as source, zipfile.ZipFile(corrupted, 'w') as output:
        changed = False
        for item in source.infolist():
            payload = source.read(item.filename)
            if item.filename.endswith('.jar'):
                payload += b'\x00injected-after-signing'
                changed = True
            output.writestr(item, payload)
        if not changed:
            raise RuntimeError(f"{name}: signed package has no JAR payload to tamper")
    run([cli, 'extension', 'verify', corrupted, '--public-key', public], success=False)
    return {'sha256': sha(package), 'wrongKeyDenied': True, 'tamperDenied': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, choices=[
        'linux-x64', 'linux-arm64', 'windows-x64', 'windows-arm64', 'macos-x64', 'macos-arm64'])
    parser.add_argument('--cli', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    report = {'version': (ROOT / 'VERSION').read_text().strip(),
              'target': args.target, 'status': 'failed',
              'sourceCommit': os.getenv('GITHUB_SHA') or None,
              'runId': os.getenv('GITHUB_RUN_ID') or None,
              'runAttempt': os.getenv('GITHUB_RUN_ATTEMPT') or None, 'checks': {}}
    try:
        if not re.fullmatch(r'\d+\.\d+\.\d+', report['version']) or tuple(map(int, report['version'].split('.'))) < (0, 42, 12):
            raise RuntimeError(f"unsupported source version: {report['version']}")
        if actual_platform() != args.target:
            raise RuntimeError(f"host architecture/OS mismatch: {actual_platform()} != {args.target}")
        report['javaRuntime'] = check_java_arch(args.target)
        run([sys.executable, 'scripts/version/manage.py', 'check'])
        cli = args.cli.resolve(strict=True)
        if not cli.is_file():
            raise RuntimeError('CLI is not a regular file')
        report['cliSha256'] = sha(cli)
        # Inspect the 19 real module source/test references with the built CLI,
        # preserving their partial/blocked status rather than inventing parity.
        with tempfile.TemporaryDirectory(prefix='nl-gravit-audit-') as audit_dir:
            audit_file = Path(audit_dir) / 'audit.json'
            run([cli, 'module-parity', 'audit', '--root', ROOT,
                 '--baseline', '0.42.11', '--report', audit_file])
            audit = json.loads(audit_file.read_text())
            rows = audit.get('results', [])
            if (audit.get('productVersion') != report['version'] or
                    audit.get('fullyCertified') is not False or len(rows) != 19 or
                    audit.get('auditStatus') != 'evidence-present-not-certified' or
                    any(row.get('status') not in ('partial', 'blocked') or
                        row.get('sourceValidated') is not True for row in rows)):
                raise RuntimeError('Gravit CLI audit failed to validate 19 explicit module outcomes')
            report['gravitMatrixAudit'] = {
                'status': 'source-verified-not-equivalent', 'modules': 19,
                'sha256': sha(ROOT / 'compatibility/gravit/module-parity-04211.json')}
        for key, script, jar in CASES:
            executable = ROOT / jar
            if not executable.is_file():
                raise RuntimeError(f"build missing executable fixture: {jar}")
            completed = run([sys.executable, ROOT / script])
            if 'PASS:' not in completed.stdout:
                raise RuntimeError(f"test runner {script} returned without PASS")
            report['checks'][key] = {'runtime': 'pass', 'jarSha256': sha(executable)}
            print(f'{key}: {completed.stdout.strip().splitlines()[-1]}', flush=True)
        with tempfile.TemporaryDirectory(prefix='nl-ext-04212-') as folder:
            for name, stage in zip(('java-host', 'gravit-port'), STAGES):
                report['checks'][name]['signing'] = negative_signatures(
                    cli, ROOT / stage, Path(folder), name)
        report['status'] = 'pass'
    except Exception as error:
        report['failure'] = str(error)
        print(f'Extension acceptance failed closed: {error}', file=sys.stderr, flush=True)
        returncode = 1
    else:
        print(f"PASS: real extension E2E, signed packages and negative cases on {args.target}")
        returncode = 0
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return returncode


if __name__ == '__main__':
    sys.exit(main())
