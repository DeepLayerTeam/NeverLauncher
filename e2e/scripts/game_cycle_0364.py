#!/usr/bin/env python3
"""Run genuine NeverLauncher client install/update/rollback against real Minecraft files.

The calling Minecraft E2E owns PostgreSQL, API, signed publishing, the JVM and
ServerBridge. This runner executes the production Go client commands on the
very same Mojang/loader tree and binds their results to exact bytes. No
simulated client, fake network join or pre-canned certification is accepted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.request import urlopen

HEX = re.compile(r'^[0-9a-f]{64}$')
SCHEMA = 'neverlauncher.game-cycle.0364/v1'
CHANGE_PATH = 'resources/neverlauncher-game-cycle-0364.txt'


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read(path: Path) -> dict:
    result = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(result, dict), f'expected JSON object: {path.name}')
    return result


def write(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def run(cli: Path, args: list[str], out: Path, expected: str) -> dict:
    require(cli.is_file(), 'production Go CLI binary missing')
    cmd = [str(cli), 'client', *args, '--output', str(out)]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=1800, check=False)
    require(result.returncode == 0 and out.is_file(),
            f'production client {args[0]} failed (exit {result.returncode}); {result.stderr.decode(errors="replace")[-3000:]}')
    obj = read(out)
    require(obj.get('status') == expected,
            f'production client {args[0]} returned {obj.get("status")!r}, expected {expected}')
    return obj


def file_manifest(pkg: dict, client_dir: Path) -> dict[str, str]:
    manifest = pkg.get('manifest', pkg)
    files = manifest.get('files')
    require(isinstance(files, list) and len(files) > 10, 'not a real Minecraft client package')
    known: dict[str, str] = {}
    root = client_dir.resolve()
    for entry in files:
        require(isinstance(entry, dict), 'invalid package file')
        rel, expected = entry.get('path'), entry.get('sha256')
        require(isinstance(rel, str) and rel and '\\' not in rel and not rel.startswith('/')
                and all(x not in ('', '.', '..') for x in rel.split('/')),
                'unsafe package path')
        require(isinstance(expected, str) and HEX.fullmatch(expected) is not None, 'invalid package digest')
        require(rel not in known, f'duplicate package file: {rel}')
        path = client_dir.joinpath(*rel.split('/'))
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root),
                f'package file missing or unsafe: {rel}')
        require(path.stat().st_size == entry.get('size') and sha(path) == expected,
                f'package bytes mismatch: {rel}')
        known[rel] = expected
    return known


def identity(root: Path, version: str) -> str:
    source_sha = os.environ.get('GITHUB_SHA', '').strip()
    require(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', source_sha) is not None, 'GITHUB_SHA required for genuine source identity')
    proc = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True, text=True, check=True)
    require(proc.stdout.strip() == source_sha, 'checkout HEAD differs from GITHUB_SHA')
    require((root / 'VERSION').read_text().strip() == version, 'product version differs from checkout')
    return source_sha


def prepare(args: argparse.Namespace) -> None:
    root, work, source, cli = args.root, args.work, args.source, args.cli
    source_sha = identity(root, args.version)
    old = read(args.package)
    original = old.get('manifest', {})
    require(old.get('manifestSettings') and original.get('version') == args.release,
            'initial package is not the genuine Minecraft factory output')
    require(original.get('projectId') == 'e2e-project' and original.get('profileId') == args.profile
            and original.get('channel') == 'stable', 'project/profile/channel mismatch')
    old_files = file_manifest(old, source)
    require(CHANGE_PATH not in old_files, 'update payload path is already owned by the baseline')
    require(not (source / CHANGE_PATH).exists(), 'update payload already exists in source')
    install_dir, store = work / 'cycle-client', work / 'cycle-store'
    require(not install_dir.exists() and not store.exists(), 'cycle run must use fresh install/storage')
    run(cli, ['package-upload', '--package', str(args.package), '--client-dir', str(source),
              '--storage-dir', str(store), '--prefix', f'clients/e2e-project/{args.profile}/stable/{args.release}'], work / 'cycle-upload-base.json', 'uploaded')
    installed = run(cli, ['install', '--package', str(args.package), '--client-dir', str(install_dir),
                          '--storage-dir', str(store)], work / 'cycle-install.json', 'applied-and-verified')
    run(cli, ['verify', '--package', str(args.package), '--client-dir', str(install_dir)],
        work / 'cycle-verify-base.json', 'valid')
    require(file_manifest(old, install_dir) == old_files, 'installed baseline differs from Minecraft source')

    # A real, versioned client resource changes between releases. The Minecraft
    # assets, libraries, natives, and loader remain the genuine Mojang material.
    updated_content = (f'NeverLauncher E2E release: {args.release}-update\n'
                       f'project=e2e-project\nprofile={args.profile}\nsourceCommit={source_sha}\n').encode()
    updated_resource = source / CHANGE_PATH
    updated_resource.parent.mkdir(parents=True, exist_ok=True)
    updated_resource.write_bytes(updated_content)
    updated_version = args.release + '-update'
    updated_path = work / 'cycle-package-update.json'
    run_args = [str(cli), 'client', 'package-build', '--client-dir', str(source), '--project', 'e2e-project',
                '--profile', args.profile, '--channel', 'stable', '--version', updated_version,
                '--output', str(updated_path)]
    built = subprocess.run(run_args, capture_output=True, text=True, timeout=1800, check=False)
    require(built.returncode == 0 and updated_path.is_file(), 'production package-build failed: ' + built.stderr[-2000:])
    updated = read(updated_path)
    updated['manifestSettings'] = old['manifestSettings']
    write(updated_path, updated)
    new_files = file_manifest(updated, source)
    require(len(new_files) == len(old_files) + 1 and
            all(new_files[k] == digest for k, digest in old_files.items()) and
            new_files.get(CHANGE_PATH) == sha(updated_resource),
            'update must contain exactly one changed, independently hashed resource')
    run(cli, ['package-upload', '--package', str(updated_path), '--client-dir', str(source),
              '--storage-dir', str(store), '--prefix', f'clients/e2e-project/{args.profile}/stable/{updated_version}'], work / 'cycle-upload-update.json', 'uploaded')
    updated_result = run(cli, ['update', '--package', str(updated_path), '--client-dir', str(install_dir),
                               '--storage-dir', str(store)], work / 'cycle-update.json', 'applied-and-verified')
    run(cli, ['verify', '--package', str(updated_path), '--client-dir', str(install_dir)],
        work / 'cycle-verify-update.json', 'valid')
    require(file_manifest(updated, install_dir) == new_files, 'update did not install exact files')
    require(read(install_dir / '.neverlauncher/client-state.json').get('version') == updated_version,
            'updater did not atomically advance installed version')
    snapshot = updated_result.get('rollbackSnapshot')
    require(isinstance(snapshot, str) and bool(snapshot) and snapshot != installed.get('rollbackSnapshot'),
            'transactional updater did not create a distinct rollback snapshot')
    write(work / 'game-cycle-0364-state.json', {
        'schemaVersion': SCHEMA, 'version': args.version, 'sourceCommit': source_sha,
        'baselineVersion': args.release, 'updateVersion': updated_version,
        'baselineManifestSha256': sha(args.package), 'updatePackageSha256': sha(updated_path),
        'changedResource': CHANGE_PATH, 'changedResourceSha256': new_files[CHANGE_PATH],
        'rollbackSnapshot': snapshot, 'clientCLIsha256': sha(cli),
        'baselineFiles': len(old_files), 'updateFiles': len(new_files),
        'updateFilesSha256': hashlib.sha256(json.dumps(new_files, sort_keys=True).encode()).hexdigest(),
        'status': 'updated-and-verified',
    })


def rollback(args: argparse.Namespace) -> None:
    work, cli = args.work, args.cli
    state = read(work / 'game-cycle-0364-state.json')
    require(state.get('schemaVersion') == SCHEMA and state.get('status') == 'updated-and-verified',
            'no completed real update to rollback')
    require(state.get('clientCLIsha256') == sha(cli), 'Go CLI changed since update')
    require(state.get('sourceCommit') == identity(args.root, args.version), 'source changed since update')
    base, new = read(args.package), read(work / 'cycle-package-update.json')
    client = work / 'cycle-client'
    require(file_manifest(new, client).get(CHANGE_PATH) == state['changedResourceSha256'],
            'updated client resource was tampered with')
    restored = run(cli, ['rollback', '--client-dir', str(client), '--target', state['rollbackSnapshot']],
                   work / 'cycle-rollback.json', 'rolled-back')
    require(restored.get('restoredSnapshot') == state['rollbackSnapshot'], 'wrong snapshot restored')
    run(cli, ['verify', '--package', str(args.package), '--client-dir', str(client)],
        work / 'cycle-verify-rollback.json', 'valid')
    require(not (client / CHANGE_PATH).exists(), 'update-only resource survived rollback')
    require(file_manifest(base, client) and
            read(client / '.neverlauncher/client-state.json').get('version') == state['baselineVersion'],
            'rollback failed to restore baseline state')
    state['status'] = 'rolled-back-and-verified'
    write(work / 'game-cycle-0364-state.json', state)


def finalize(args: argparse.Namespace) -> None:
    work = args.work
    state = read(work / 'game-cycle-0364-state.json')
    require(state.get('status') == 'rolled-back-and-verified' and
            state.get('sourceCommit') == identity(args.root, args.version),
            'rollback/source identity not verified')
    files = [
        'client-package.json', 'published-client-package.json', 'manifest.json',
        'runtime-launch-minecraft.json', 'cycle-package-update.json',
        'cycle-install.json', 'cycle-update.json', 'cycle-rollback.json',
        'cycle-verify-base.json', 'cycle-verify-update.json', 'cycle-verify-rollback.json',
        'cycle-published-update.json', 'cycle-manifest-update.json',
        'cycle-runtime-verify-update.json', 'cycle-runtime-launch-update.json',
        'cycle-runtime-launch-rollback.json',
        'cycle-join-update.log', 'cycle-join-rollback.log',
        'cycle-game-update.log', 'cycle-game-rollback.log',
        'cycle-join-update.json', 'cycle-join-rollback.json',
        'game-cycle-0364-state.json',
    ]
    digests = {}
    for rel in files:
        path = work / rel
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                'missing real gameplay evidence: ' + rel)
        digests[rel] = sha(path)
    initial_manifest, update_manifest = read(work/'manifest.json'), read(work/'cycle-manifest-update.json')
    require(initial_manifest.get('version') == state['baselineVersion'] and
            update_manifest.get('version') == state['updateVersion'] and
            initial_manifest.get('signature', {}).get('algorithm') == 'Ed25519' and
            update_manifest.get('signature', {}).get('algorithm') == 'Ed25519' and
            digests['manifest.json'] != digests['cycle-manifest-update.json'],
            'two distinct signed releases not proven')
    require(read(work/'cycle-runtime-verify-update.json').get('status') == 'ready',
            'NeverRuntime did not verify the update signature')
    for stage in ('update', 'rollback'):
        actual = read(work/f'cycle-runtime-launch-{stage}.json')
        require(actual.get('success') is True or actual.get('timedOut') is True,
                f'actual JVM launch not confirmed: {stage}')
        counters = read(work/f'cycle-join-{stage}.json')
        require(counters.get('allowedAfter', 0) > counters.get('allowedBefore', 0) and
                counters.get('joinedAfter', 0) > counters.get('joinedBefore', 0),
                'new live Minecraft join not observed: ' + stage)
        log = (work/f'cycle-join-{stage}.log').read_text(encoding='utf-8')
        require('neverlauncher.join.allowed username=' + args.player in log and
                args.player + ' joined the game' in log,
                'real Paper/ServerBridge join not observed: ' + stage)
    require(read(work/'cycle-verify-rollback.json').get('verify', {}).get('valid') is True,
            'restored baseline package not valid')
    binaries = {'javaExecutable': args.java, 'neverRuntime': args.runtime, 'paperServerBridge': args.bridge}
    for name, path in binaries.items():
        require(path is not None and path.is_file() and path.stat().st_size > 0,
                f'actual {name} binary missing')
    write(work/'game-cycle-0364-result.json', {
        'schemaVersion': SCHEMA, 'status': 'passed', 'version': args.version,
        'sourceCommit': state['sourceCommit'],
        'githubRunId': os.environ.get('GITHUB_RUN_ID', ''),
        'githubRunAttempt': os.environ.get('GITHUB_RUN_ATTEMPT', ''),
        'project': 'e2e-project', 'profile': args.profile,
        'baselineVersion': state['baselineVersion'], 'updateVersion': state['updateVersion'],
        'checks': {'postgresBackend': True, 'signedBaseline': True, 'signedUpdate': True,
                   'productionGoTransactionalUpdate': True, 'updateMinecraftJVMJoin': True,
                   'productionGoTransactionalRollback': True, 'rollbackMinecraftJVMJoin': True,
                   'serverBridgeJoin': True},
        'artifacts': dict(sorted(digests.items())),
        'clientCLIsha256': state['clientCLIsha256'],
        'executablesSha256': {name: sha(path) for name, path in binaries.items()},
        'changedResourceSha256': state['changedResourceSha256'],
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'rollback', 'finalize'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--cli', type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--release')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--player')
    parser.add_argument('--java', type=Path)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--bridge', type=Path)
    args = parser.parse_args()
    args.root = args.root.resolve()
    args.work = args.work.resolve()
    for action, required in {'prepare': ('source', 'package', 'cli', 'release'),
                             'rollback': ('package', 'cli'), 'finalize': ('player', 'java', 'runtime', 'bridge')}.items():
        if args.action == action:
            for attr in required:
                require(getattr(args, attr) is not None, f'{action}: --{attr} is required')
    {'prepare': prepare, 'rollback': rollback, 'finalize': finalize}[args.action](args)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print('[game-cycle-0364] BLOCKED:', exc, file=sys.stderr)
        sys.exit(2)
