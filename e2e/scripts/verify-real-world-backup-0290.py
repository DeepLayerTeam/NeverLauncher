#!/usr/bin/env python3
"""Exercise actual Paper world backup/restore after an actual Minecraft join.

Runs on the disposable Docker Compose E2E network, NOT a production host.
Intentionally refuses a missing playerdata file, unsuccessful server exit,
missing plugin configuration, bad hashes, and overwriting restored data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def execute(argv, *, output=True, timeout=180):
    result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout if output else None


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def check_files(root):
    level_name = 'world'
    properties = root / 'server.properties'
    if not properties.is_file():
        raise RuntimeError('real Paper server.properties was not copied')
    for line in properties.read_text(errors='replace').splitlines():
        if line.startswith('level-name='):
            level_name = line.partition('=')[2].strip()
    world = root / level_name
    if not (world / 'level.dat').is_file():
        raise RuntimeError('real Paper level.dat missing after graceful shutdown')
    players = sorted((world / 'playerdata').glob('*.dat'))
    if not players:
        raise RuntimeError('no persisted real Minecraft player UUID data after client join')
    plugin_root = root / 'plugins'
    plugins = sorted(p for p in plugin_root.rglob('*') if p.is_file() and p.suffix.lower() in ('.yml', '.yaml', '.json', '.properties', '.db'))
    if not plugins:
        raise RuntimeError('no real Minecraft plugin configuration/data files were persisted')
    chosen = [world / 'level.dat', *players, *plugins]
    return {p.relative_to(root).as_posix(): digest(p) for p in chosen}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', required=True, type=Path)
    parser.add_argument('--compose-file', required=True, type=Path)
    parser.add_argument('--env-file', required=True, type=Path)
    parser.add_argument('--override-file', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', default='')
    args = parser.parse_args()
    if not args.cli.is_file():
        parser.error('compiled NeverLauncher CLI not found')
    compose = ['docker', 'compose', '--env-file', str(args.env_file), '-f', str(args.compose_file), '-f', str(args.override_file)]
    paper = execute([*compose, 'ps', '-q', 'paper']).strip()
    if not paper:
        raise RuntimeError('real Paper container unavailable')
    # A Docker SIGTERM is NOT a proven Minecraft save. Issue real authenticated
    # Minecraft console commands over the unexposed internal E2E RCON channel.
    flush = execute([*compose, 'exec', '-T', 'paper', 'rcon-cli', 'save-all', 'flush'], timeout=45)
    if not flush.strip():
        raise RuntimeError('Paper did not acknowledge save-all flush')
    execute([*compose, 'exec', '-T', 'paper', 'rcon-cli', 'stop'], timeout=45)
    deadline = time.monotonic() + 95
    while True:
        state = json.loads(execute(['docker', 'inspect', '--format', '{{json .State}}', paper]))
        if not state.get('Running'):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Paper did not exit after Minecraft console stop')
        time.sleep(1)
    if state.get('OOMKilled') or state.get('ExitCode') != 0:
        raise RuntimeError(f'Paper shutdown did not complete cleanly: exit={state.get("ExitCode")} OOM={state.get("OOMKilled")}')
    with tempfile.TemporaryDirectory(prefix='nl-real-world-0290-') as temp:
        root = Path(temp) / 'paper-real'
        store = Path(temp) / 'world-backups'
        restored = Path(temp) / 'restored'
        root.mkdir(mode=0o700)
        # Docker cp from the *actual* stopped E2E Paper container; this is not
        # a fake Java process or an invented inventory fixture.
        execute([*compose, 'cp', 'paper:/data/.', str(root)], timeout=180)
        source = check_files(root)
        base = [str(args.cli), 'server-bridge', 'host', 'world-backup']
        extra = ['--server-root', str(root), '--backup-root', str(store)]
        created = json.loads(execute([*base, 'create', *extra, '--consistency', 'stopped'], timeout=180))
        backup_id = created['manifest']['id']
        if created['manifest']['consistency'] != 'stopped':
            raise RuntimeError('backup claims a different consistency policy')
        execute([*base, 'verify', *extra, '--id', backup_id], timeout=180)
        execute([*base, 'restore', *extra, '--id', backup_id, '--confirm', backup_id,
                 '--destination', str(restored)], timeout=180)
        actual = check_files(restored)
        if actual != source:
            raise RuntimeError('restored real world/playerdata/plugin data differs from source')
        # Overwriting a completed restore must fail, not silently succeed.
        second = subprocess.run([*base, 'restore', *extra, '--id', backup_id, '--confirm', backup_id,
                                 '--destination', str(restored)], capture_output=True, text=True, timeout=60)
        if second.returncode == 0:
            raise RuntimeError('restore unexpectedly overwrote an existing destination')
        # Return the *same* real Paper server to service and require a fresh
        # Docker health transition; a successful offline restore alone does not
        # demonstrate that the running network can recover after maintenance.
        execute([*compose, 'up', '-d', 'paper'], timeout=180)
        restarted = execute([*compose, 'ps', '-q', 'paper']).strip()
        if not restarted:
            raise RuntimeError('Paper container disappeared during recovery')
        for _ in range(120):
            state = json.loads(execute(['docker', 'inspect', '--format', '{{json .State}}', restarted]))
            if state.get('Running') and state.get('Health', {}).get('Status') == 'healthy':
                break
            if not state.get('Running'):
                raise RuntimeError('Paper failed to restart after world backup')
            time.sleep(2)
        else:
            raise RuntimeError('Paper did not return to healthy state after world backup')
        report = {
            'schemaVersion': 'neverlauncher.server-control.real-world-restore.v1',
            'version': args.version,
            'sourceCommit': args.source_commit,
            'source': 'docker-compose-real-paper-after-minecraft-client-join',
            'status': 'passed', 'actualMinecraftWorld': True,
            'gracefulPaperExit': True, 'minecraftSaveFlushAcknowledged': True, 'worldBackupVerified': True,
            'isolatedRestoreVerified': True, 'overwriteRejected': True,
            'returnedToHealthyService': True,
            'worldFileSha256': source[next(k for k in source if k.endswith('/level.dat'))],
            'playerDataFiles': sum('/playerdata/' in k for k in source),
            'pluginDataFiles': sum(k.startswith('plugins/') for k in source),
            'filesVerified': len(source),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'[0290] real Paper backup -> verify -> isolated restore verified {len(source)} files')


if __name__ == '__main__':
    main()
