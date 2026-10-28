#!/usr/bin/env python3
"""NeverLauncher 0.35.12: real Docker Compose backup, fresh-site DR and chaos checks.

Requires Docker Compose V2, a configured production Compose env file and Alpine.
Chaos injections are isolated-only; maintenance backups and fresh-site production
restores require two explicit approvals. It does not back up signing keys, credential stores or other secrets: restore them from a
separate approved secret manager, using the same keys as the source deployment.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / 'deploy/production/docker-compose.yml'
COMPOSE_FILES = [COMPOSE]
COMPOSE_PROFILES: list[str] = []
VOLUMES = ('neverlauncher_storage', 'neverlauncher_backups', 'neverlauncher_factory',
           'neverlauncher_coordinator', 'neverlauncher_redis')
STANDARD_VOLUMES = VOLUMES[:-1]


def required_volumes() -> tuple[str, ...]:
    return VOLUMES if 'network-ha' in COMPOSE_PROFILES else STANDARD_VOLUMES
CHUNK = 1024 * 1024
PROJECT_PATTERN = re.compile(r'^nl-dr-[a-z0-9][a-z0-9-]{0,35}$')
VALID_PROJECT = re.compile(r'^[a-z0-9][a-z0-9_-]{0,40}$')


class DrillError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def run(args: list[str], *, stdin=None, stdout=None, timeout=600, env=None) -> subprocess.CompletedProcess:
    # Do not print commands: Compose env and pg_dump invocations may contain secrets.
    result = subprocess.run(args, stdin=stdin, stdout=stdout if stdout is not None else subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
    if result.returncode:
        # Keep diagnostic bounded; never echo credentials/DSNs from tool output.
        raise DrillError(f'{args[0]} command failed (exit {result.returncode})')
    return result


def compose(project: str, env_file: Path, *args: str, stdout=None, stdin=None, timeout=600):
    return run(['docker', 'compose', '-p', project, '--env-file', str(env_file),
                *[entry for profile in COMPOSE_PROFILES for entry in ('--profile', profile)],
                *[entry for path in COMPOSE_FILES for entry in ('-f', str(path))], *args], stdin=stdin, stdout=stdout, timeout=timeout)


def volume_name(project: str, logical: str) -> str:
    if logical not in VOLUMES:
        raise DrillError('unknown volume')
    if not VALID_PROJECT.fullmatch(project):
        raise DrillError('invalid Compose project name')
    return project + '_' + logical


def authorize_project(project: str, confirmation: str, *, production: bool = False,
                      approved: bool = False, chaos_mode: bool = False) -> None:
    if not VALID_PROJECT.fullmatch(project):
        raise DrillError('invalid Compose project name')
    if confirmation != project:
        raise DrillError('refusing destructive operation: --confirm must exactly match --project')
    if PROJECT_PATTERN.fullmatch(project):
        return
    if chaos_mode or not (production and approved):
        raise DrillError('production project requires explicit production mode and maintenance approval')


def ensure_isolated(project: str, confirmation: str) -> None:
    authorize_project(project, confirmation, chaos_mode=True)


def docker_volume_exists(volume: str) -> bool:
    result = subprocess.run(['docker', 'volume', 'inspect', volume], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, timeout=30)
    return result.returncode == 0


def safe_tar(path: Path) -> tuple[int, int]:
    total, count = 0, 0
    seen: set[str] = set()
    with tarfile.open(path, 'r:gz') as archive:
        for entry in archive:
            # A DR archive may never plant symlinks, devices, hardlinks, or escape paths.
            name = PurePosixPath(entry.name)
            if entry.name.startswith('/') or '\\' in entry.name or '..' in name.parts or '\x00' in entry.name:
                raise DrillError('unsafe archive member path')
            if not (entry.isfile() or entry.isdir()):
                raise DrillError('unsafe archive member type')
            canonical = str(name)
            if canonical in seen and canonical != '.':
                raise DrillError('duplicate archive path')
            seen.add(canonical)
            if entry.isfile():
                count += 1
                total += entry.size
    return count, total


def stream_to_file(cmd: list[str], destination: Path, timeout: int = 1800) -> None:
    # Large archives/dumps stream directly to disk; no full in-memory buffering.
    with destination.open('xb') as out:
        run(cmd, stdout=out, timeout=timeout)
    if not destination.is_file() or destination.stat().st_size == 0:
        raise DrillError('empty snapshot output')


def docker_tar_backup(volume: str, output: Path) -> None:
    stream_to_file(['docker', 'run', '--rm', '--network', 'none', '--mount',
                    f'type=volume,src={volume},dst=/source,readonly',
                    'alpine:3.20', 'tar', '-czf', '-', '-C', '/source', '.'], output)
    safe_tar(output)


def tar_digests(path: Path) -> dict[str, dict]:
    """Stream every restored volume file and compare actual bytes, not tar headers."""
    safe_tar(path)
    result = {}
    with tarfile.open(path, 'r:gz') as archive:
        for entry in archive:
            if entry.isfile():
                digest = hashlib.sha256()
                contents = archive.extractfile(entry)
                if contents is None:
                    raise DrillError('invalid tar file entry')
                with contents:
                    for chunk in iter(lambda: contents.read(CHUNK), b''):
                        digest.update(chunk)
                result[str(PurePosixPath(entry.name))] = {
                    'sha256': digest.hexdigest(), 'size': entry.size}
    return result


def docker_tar_restore(volume: str, archive: Path) -> None:
    safe_tar(archive)
    # Only ever extract into a new, empty, isolated volume.
    cmd = ['docker', 'run', '--rm', '-i', '--network', 'none', '--mount',
           f'type=volume,src={volume},dst=/target', 'alpine:3.20',
           'tar', '-xzf', '-', '-C', '/target']
    with archive.open('rb') as source:
        run(cmd, stdin=source, timeout=1800)
    with tempfile.TemporaryDirectory(prefix='neverlauncher-volume-check-') as work:
        actual = Path(work) / 'readback.tar.gz'
        docker_tar_backup(volume, actual)
        if tar_digests(archive) != tar_digests(actual):
            raise DrillError('restored Docker volume data mismatch')


def compose_pg_dump(project: str, env_file: Path, dst: Path) -> None:
    prefix = ['docker', 'compose', '-p', project, '--env-file', str(env_file),
              *[entry for profile in COMPOSE_PROFILES for entry in ('--profile', profile)],
              *[entry for path in COMPOSE_FILES for entry in ('-f', str(path))]]
    stream_to_file(prefix + ['exec', '-T', 'postgres', 'sh', '-ec',
                   'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-acl'], dst)


def compose_pg_restore(project: str, env_file: Path, dump: Path) -> None:
    # --single-transaction makes failed database restores atomic within PG.
    with dump.open('rb') as source:
        compose(project, env_file, 'exec', '-T', 'postgres', 'sh', '-ec',
                'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --single-transaction --exit-on-error --no-owner --no-acl',
                stdin=source, timeout=1800)


def pg_validate(dump: Path) -> None:
    # Validate archive structure using the matching PostgreSQL client in Alpine.
    with dump.open('rb') as f:
        run(['docker', 'run', '--rm', '-i', '--network', 'none', 'postgres:16-alpine',
             'sh', '-ec', 'cat > /tmp/backup.dump && pg_restore --list /tmp/backup.dump >/dev/null'],
            stdin=f, timeout=1800)


def aws(*args: str, timeout: int = 1800) -> str:
    result = run(['aws', *args], timeout=timeout)
    return result.stdout.decode('utf-8', errors='replace')


def s3_options(endpoint: str | None) -> list[str]:
    if endpoint and not (endpoint.startswith('https://') or endpoint.startswith('http://127.0.0.1:') or endpoint.startswith('http://localhost:')):
        raise DrillError('S3 endpoint must be HTTPS or local loopback')
    return ['--endpoint-url', endpoint] if endpoint else []


def s3_download(bucket: str, root: Path, endpoint: str | None) -> None:
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,62}', bucket):
        raise DrillError('invalid S3 bucket')
    root.mkdir(parents=True, exist_ok=False)
    aws(*s3_options(endpoint), 's3', 'sync', 's3://' + bucket, str(root), '--only-show-errors')
    for path in root.rglob('*'):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise DrillError('S3 snapshot contains unsafe filesystem entry')


def s3_list_first(bucket: str, endpoint: str | None) -> bool:
    value = aws(*s3_options(endpoint), 's3api', 'list-objects-v2', '--bucket', bucket,
                '--max-keys', '1', '--query', 'KeyCount', '--output', 'text').strip()
    if value not in ('0', '1'):
        raise DrillError('unexpected S3 inventory response')
    return value == '1'


def s3_upload_fresh(bucket: str, root: Path, endpoint: str | None, expected: dict) -> None:
    if s3_list_first(bucket, endpoint):
        raise DrillError('S3 restore bucket is not empty')
    aws(*s3_options(endpoint), 's3', 'sync', str(root), 's3://' + bucket, '--only-show-errors')
    # The restore is not called verified until every uploaded byte is read back.
    with tempfile.TemporaryDirectory(prefix='neverlauncher-s3-verify-') as temp:
        second = Path(temp) / 'objects'
        s3_download(bucket, second, endpoint)
        files = {p.relative_to(second).as_posix(): {'size': p.stat().st_size,
                    'sha256': sha256_file(p)} for p in second.rglob('*') if p.is_file()}
        if files != expected:
            raise DrillError('S3 readback differs from verified source snapshot')


def snapshot(project: str, env_file: Path, dest: Path, confirm: str,
             s3_bucket: str | None = None, s3_endpoint: str | None = None,
             production: bool = False, approved: bool = False) -> dict:
    authorize_project(project, confirm, production=production, approved=approved)
    if dest.exists():
        raise DrillError('snapshot destination already exists; will not overwrite')
    if not env_file.is_file():
        raise DrillError('Compose environment file missing')
    started = time.monotonic()
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.dr-stage-', dir=dest.parent))
    stopped = []
    try:
        # Freeze writes before the logical dump and cold volume backup.
        for svc in (('nginx', 'admin', 'api', 'redis') if 'network-ha' in COMPOSE_PROFILES
                    else ('nginx', 'admin', 'api')):
            compose(project, env_file, 'stop', '-t', '30', svc)
            stopped.append(svc)
        compose_pg_dump(project, env_file, stage / 'database.dump')
        pg_validate(stage / 'database.dump')
        for item in required_volumes():
            name = volume_name(project, item)
            if not docker_volume_exists(name):
                raise DrillError(f'missing volume: {item}')
            docker_tar_backup(name, stage / (item + '.tar.gz'))
        s3_files = {}
        if s3_bucket:
            s3_root = stage / 's3-objects'
            s3_download(s3_bucket, s3_root, s3_endpoint)
            s3_files = {p.relative_to(s3_root).as_posix():
                        {'sha256': sha256_file(p), 'size': p.stat().st_size}
                        for p in s3_root.rglob('*') if p.is_file()}
        files = {p.name: {'sha256': sha256_file(p), 'size': p.stat().st_size}
                 for p in stage.iterdir() if p.is_file()}
        result = {'schema': 1, 'version': (ROOT / 'VERSION').read_text().strip(),
                  'sourceProject': project, 'createdUtc': datetime.now(timezone.utc).isoformat(),
                  'repository': 'postgres-logical', 'storage': 's3-objects' if s3_bucket else 'local-volume',
                  's3SourceBucket': s3_bucket, 's3Files': s3_files,
                  'volumes': list(required_volumes()),
                  'redis': 'cold-volume-snapshot' if 'network-ha' in COMPOSE_PROFILES else 'not-used', 'files': files,
                  'credentialPolicy': 'signing keys, passwords, TLS and KMS material must be restored separately',
                  'consistentWrites': 'API stopped; external database writers must be fenced'}
        (stage / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
        stage.rename(dest)
        result['durationSeconds'] = round(time.monotonic() - started, 3)
        return result
    finally:
        # Never leave isolated services down after a failed backup.
        try:
            for svc in reversed(stopped):
                compose(project, env_file, 'up', '-d', svc)
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def verify_snapshot(folder: Path) -> dict:
    data = json.loads((folder / 'manifest.json').read_text())
    if data.get('schema') != 1 or data.get('storage') not in ('local-volume', 's3-objects'):
        raise DrillError('unsupported snapshot schema/storage')
    volumes = data.get('volumes', [])
    if volumes not in (list(STANDARD_VOLUMES), list(VOLUMES)):
        raise DrillError('invalid volume inventory')
    expected = {'database.dump', *(v + '.tar.gz' for v in volumes)}
    if set(data.get('files', {})) != expected:
        raise DrillError('snapshot files mismatch')
    if data['storage'] == 's3-objects':
        s3_root = folder / 's3-objects'
        if not s3_root.is_dir() or s3_root.is_symlink():
            raise DrillError('S3 object snapshot missing')
        actual = {}
        for obj in s3_root.rglob('*'):
            if obj.is_symlink() or (not obj.is_file() and not obj.is_dir()):
                raise DrillError('unsafe S3 object')
            if obj.is_file():
                actual[obj.relative_to(s3_root).as_posix()] = {
                    'size': obj.stat().st_size, 'sha256': sha256_file(obj)}
        if actual != data.get('s3Files'):
            raise DrillError('S3 object snapshot checksum mismatch')
    for filename, meta in data['files'].items():
        path = folder / filename
        if not path.is_file() or path.is_symlink():
            raise DrillError('snapshot missing file')
        if path.stat().st_size != meta['size'] or sha256_file(path) != meta['sha256']:
            raise DrillError('snapshot SHA-256 verification failed')
        if filename.endswith('.tar.gz'):
            safe_tar(path)
    return data


def restore_fresh(project: str, env_file: Path, folder: Path, confirm: str,
                  ready_url: str | None = None, target_s3_bucket: str | None = None,
                  s3_endpoint: str | None = None, production: bool = False, approved: bool = False) -> dict:
    authorize_project(project, confirm, production=production, approved=approved)
    manifest = verify_snapshot(folder)
    if project == manifest['sourceProject']:
        raise DrillError('restore must target a different DR project')
    if not env_file.is_file():
        raise DrillError('Compose environment file missing')
    if manifest['volumes'] != list(required_volumes()):
        raise DrillError('restore mode does not match snapshot volume topology')
    if manifest['storage'] == 's3-objects':
        if not target_s3_bucket or target_s3_bucket == manifest['s3SourceBucket']:
            raise DrillError('restore requires a distinct --target-s3-bucket')
        if s3_list_first(target_s3_bucket, s3_endpoint):
            raise DrillError('S3 target bucket is not empty')
    for item in manifest['volumes']:
        if docker_volume_exists(volume_name(project, item)):
            raise DrillError('target already has state: fresh project required; refusing to overwrite')
    started = time.monotonic()
    # A failed restore does not boot the API with partial data.
    compose(project, env_file, 'create')
    for item in manifest['volumes']:
        name = volume_name(project, item)
        if not docker_volume_exists(name):
            raise DrillError('compose did not create required volume')
        docker_tar_restore(name, folder / (item + '.tar.gz'))
    compose(project, env_file, 'up', '-d', 'postgres')
    for attempt in range(45):
        try:
            compose(project, env_file, 'exec', '-T', 'postgres', 'sh', '-ec',
                    'exec pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"', timeout=10)
            break
        except DrillError:
            time.sleep(1)
    else:
        raise DrillError('PostgreSQL did not become healthy')
    try:
        compose_pg_restore(project, env_file, folder / 'database.dump')
    except Exception:
        # Leave API stopped; manual inspection mandatory.
        raise
    if manifest['storage'] == 's3-objects':
        s3_upload_fresh(target_s3_bucket, folder / 's3-objects', s3_endpoint, manifest['s3Files'])
    for svc in (('redis', 'api', 'admin', 'nginx') if 'network-ha' in COMPOSE_PROFILES
                else ('api', 'admin', 'nginx')):
        compose(project, env_file, 'up', '-d', svc)
    outcome = {'status': 'restored-and-started', 'source': manifest['sourceProject'],
               'target': project, 'rtoSeconds': round(time.monotonic() - started, 3),
               'dataChecks': 'snapshot SHA-256, archive member safety, pg_restore transaction',
               'credentials': 'provided externally via target environment',
               'applicationVerified': False}
    if ready_url:
        await_readiness(ready_url, expected=True, limit=120)
        outcome['applicationVerified'] = True
    return outcome


def ready(url: str) -> bool:
    try:
        with urlopen(url, timeout=4) as response:
            if response.status != 200:
                return False
            value = json.load(response)
            return value.get('status') == 'ready'
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return False


def await_readiness(url: str, expected: bool, limit=90) -> float:
    start = time.monotonic()
    while time.monotonic() - start <= limit:
        if ready(url) == expected:
            return round(time.monotonic() - start, 3)
        time.sleep(1)
    raise DrillError(f'/ready did not reach expected state after {limit}s')


def chaos(project: str, env_file: Path, url: str, confirm: str, network_ha: bool) -> dict:
    ensure_isolated(project, confirm)
    if not (url.startswith('http://127.0.0.1:') or url.startswith('http://localhost:')) or not url.endswith('/ready'):
        raise DrillError('chaos readiness URL must be loopback /ready')
    await_readiness(url, expected=True, limit=30)
    outcomes = []
    for svc in (('postgres', 'redis') if network_ha else ('postgres',)):
        down_start = time.monotonic()
        try:
            compose(project, env_file, 'stop', '-t', '5', svc)
            # Loss of DB must fail closed; Redis is mandatory in network-ha.
            down_sec = await_readiness(url, expected=False, limit=35)
        finally:
            compose(project, env_file, 'up', '-d', svc)
        up_sec = await_readiness(url, expected=True, limit=120)
        outcomes.append({'service': svc, 'failClosedSeconds': down_sec,
                         'recoverySeconds': up_sec, 'totalSeconds': round(time.monotonic()-down_start, 3)})
    try:
        compose(project, env_file, 'kill', 'api')
        compose(project, env_file, 'stop', '-t', '1', 'api')
        await_readiness(url, expected=False, limit=25)
    finally:
        compose(project, env_file, 'up', '-d', 'api')
    outcomes.append({'service': 'api', 'recoverySeconds': await_readiness(url, expected=True, limit=120)})
    return {'status': 'measured', 'project': project, 'mode': 'network-ha' if network_ha else 'standard',
            'events': outcomes, 'haDisclaimer': 'single-node recovery and readiness; does not establish backend HA'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['backup', 'verify', 'restore-fresh', 'chaos'])
    parser.add_argument('--project', help='isolated docker compose project, nl-dr-*')
    parser.add_argument('--confirm', help='exact project name required for mutation')
    parser.add_argument('--env-file', type=Path)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--ready-url')
    parser.add_argument('--network-ha', action='store_true')
    parser.add_argument('--s3-source-bucket')
    parser.add_argument('--target-s3-bucket')
    parser.add_argument('--s3-endpoint')
    parser.add_argument('--production-source', action='store_true',
                        help='allow backup on explicitly approved maintenance-window source')
    parser.add_argument('--production-target', action='store_true',
                        help='allow restore to explicitly approved fresh target; does not overwrite')
    parser.add_argument('--maintenance-approved', action='store_true',
                        help='explicit operator acknowledgement: all writers fenced, downtime approved')
    args = parser.parse_args()
    if args.network_ha:
        COMPOSE_FILES.append(ROOT / 'deploy/production/docker-compose.network-ha.yml')
        COMPOSE_PROFILES.append('network-ha')
    try:
        if args.network_ha and args.action == 'backup' and not args.s3_source_bucket:
            raise DrillError('network-ha backup requires --s3-source-bucket')
        if args.action == 'verify':
            report = {'status': 'verified', 'manifest': verify_snapshot(args.snapshot)}
        else:
            if not args.project or not args.env_file:
                raise DrillError('project and env-file required')
            if args.action == 'backup':
                report = snapshot(args.project, args.env_file, args.snapshot, args.confirm or '',
                                  args.s3_source_bucket, args.s3_endpoint,
                                  args.production_source, args.maintenance_approved)
            elif args.action == 'restore-fresh':
                report = restore_fresh(args.project, args.env_file, args.snapshot,
                                       args.confirm or '', args.ready_url,
                                       args.target_s3_bucket, args.s3_endpoint,
                                       args.production_target, args.maintenance_approved)
            else:
                if not args.ready_url:
                    raise DrillError('--ready-url required')
                report = chaos(args.project, args.env_file, args.ready_url,
                               args.confirm or '', args.network_ha)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except (DrillError, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
        print(json.dumps({'status': 'failed', 'reason': str(exc)[:160]}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
