#!/usr/bin/env python3
"""Release baseline guard for actual tool input files in the 0.47.0 tree.

This is deliberately a *source-input* guard, not a false claim that native
compilers, network packages or output binaries were independently verified.
CI can run `verify` before AND after each build; an input change fails closed
unless a deliberate reviewed rebaseline occurs in source control.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT/'reproducibility'/'baseline-0.47.0.json'
SOURCES = (
    'VERSION', 'schemas/openapi.yaml',
    'scripts/release/inputs_guard_0461.py',
    'scripts/release/zip-dir.py',
    'scripts/release/source-package.py',
    'scripts/release/canonical_zip_0461.py',
    'scripts/release/build-release.sh',
    'scripts/release/delivery_verify_0462.py',
    'scripts/release/staged_accept_0462.py',
    'scripts/release/check_payload_0461.py',
    'scripts/release/publish_0370.py',
    'scripts/operations/operations_ga_0460.py',
    'cli/cmd/launcher/release_commands.go',
    'reproducibility/primary-payload-0.47.0.json',
    'scripts/build/bridge-plugins.sh',
    'sdk/api/go/client.go', 'sdk/api/go/stream_0463_test.go',
    'sdk/api/typescript/client.ts',
    'scripts/smoke/offline/repository-policy.py',
    'scripts/smoke/offline/device-trust-e2e-matrix-0129.py',
    'scripts/smoke/offline/session-device-risk-0126.py',
    'scripts/smoke/offline/notarized-macos-x64-arm64-0154.py',
    'scripts/smoke/offline/serverbridge-forge-neoforge-0147.py',
    'scripts/smoke/offline/guard-windows-adversarial-ci-01811.py',
    'scripts/ci/required_jobs_0363.py',
    'scripts/release/test_gate_retention_0463.py',
    'scripts/release/reproducible_0470.py',
    'scripts/release/test_reproducible_0470.py',
    'scripts/release/unsigned_package_0470.py',
    'scripts/release/native_verify_0470.py',
    'scripts/release/test_native_verify_0470.py',
    'scripts/release/test_unsigned_package_0470.py',
    'scripts/release/check_go_repro_0470.py',
    'scripts/release/build-windows-desktop.ps1',
    'scripts/release/build-linux-production.sh',
    'scripts/release/build-macos-production.sh',
    'scripts/version/manage.py',
    'deploy/production/docker-compose.yml',
    'deploy/production/nginx.conf',
    'deploy/production/env.production.example',
    'cli/cmd/launcher/templates/production/docker-compose.yml',
    'cli/cmd/launcher/templates/production/nginx.conf',
    'cli/cmd/launcher/templates/production/env.production.example',
)
SUFFIXES = ('go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'package.json',
            'package-lock.json', 'npm-shrinkwrap.json', 'gradle.lockfile',
            'gradle-wrapper.properties', 'gradle-wrapper.jar', 'libs.versions.toml')


def inputs() -> list[str]:
    result = set(SOURCES)
    for path in ROOT.rglob('*'):
        if any(x in {'node_modules', 'target', 'dist', 'build', '.git', '.gradle', '__pycache__'}
               for x in path.relative_to(ROOT).parts):
            continue
        if path.is_symlink():
            # External dependencies may not be smuggled into versioned inputs.
            if path.name in SUFFIXES:
                raise ValueError('symlink in release inputs: '+str(path))
            continue
        if path.is_file() and path.name in SUFFIXES:
            result.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT/'.github/workflows').glob('*.yml'):
        if path.is_symlink(): raise ValueError('symlink in workflow: '+str(path))
        result.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT/'plugins').rglob('*.gradle.kts'):
        if path.is_symlink(): raise ValueError('symlink in Gradle build: '+str(path))
        result.add(path.relative_to(ROOT).as_posix())
    for path in ('settings.gradle.kts','build.gradle.kts','gradle.properties'):
        if (ROOT/path).exists(): result.add(path)
    return sorted(result)


def record() -> dict:
    files = {}
    for rel in inputs():
        path = ROOT/rel
        if not path.is_file() or path.is_symlink(): raise ValueError('missing required input: '+rel)
        raw = path.read_bytes()
        files[rel] = {'sha256':hashlib.sha256(raw).hexdigest(), 'size':len(raw)}
    return {'schema':'neverlauncher.input-baseline.v1', 'release':(ROOT/'VERSION').read_text().strip(),
            'files': files}


def verify(snapshot: dict, current: dict) -> None:
    if snapshot.get('schema') != 'neverlauncher.input-baseline.v1' or snapshot.get('release') != '0.47.0':
        raise ValueError('unrecognized input baseline or release')
    if current != snapshot:
        old = snapshot.get('files', {})
        new = current['files']
        changed = sorted(set(old)^set(new) | {k for k in old.keys() & new.keys() if old[k] != new[k]})
        raise ValueError('release input drift (including lockfiles): '+', '.join(changed[:20]))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('verify','freeze'))
    args=parser.parse_args()
    try:
        snapshot=record()
        if args.mode=='freeze':
            if snapshot['release'] != '0.47.0': raise ValueError('wrong release')
            BASELINE.write_text(json.dumps(snapshot, indent=2, sort_keys=True)+'\n',encoding='utf8')
            print(f'frozen {len(snapshot["files"])} real source inputs')
        else:
            verify(json.loads(BASELINE.read_text(encoding='utf8')),snapshot)
            print(f'PASS: {len(snapshot["files"])} pinned source inputs unchanged')
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print('INPUT BASELINE BLOCKED: '+str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
