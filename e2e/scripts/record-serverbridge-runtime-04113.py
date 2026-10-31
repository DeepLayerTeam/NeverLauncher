#!/usr/bin/env python3
"""Record evidence from *running* Docker JVM and actual authenticated game probes.

Not a simulator: invoking this program without Docker, a live JVM, real probe output,
and ServerBridge's log markers fails closed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path

PROBE = re.compile(r"\bprobe host=\S+ port=(\d+) username=([^ ]+) ")
SHA = re.compile(r"[0-9a-f]{64}\Z")


def run(*argv: str) -> str:
    result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30)
    return result.stdout.strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(service: str, node: str, port: int, player: str, runtime: Path, cid: str,
           version: str, require_real_join: bool = False, artifact: Path | None = None,
           source_commit: str = "") -> dict:
    if artifact is None or not artifact.is_file() or artifact.is_symlink() or artifact.stat().st_size == 0:
        raise ValueError(f'{service}: the exact built plugin JAR is required')
    # A runtime test must bind to the actual plugin bytes, not a file name or
    # a declaration in the generated build manifest.
    jar_digest = digest(artifact)
    if version == '0.42.0' and not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', source_commit):
        raise ValueError('0.42.0 requires an exact source commit for live certification')
    # Independent observation: do not infer process presence from HTTP heartbeat.
    inspect = json.loads(run('docker', 'inspect', '--type', 'container', cid))
    if len(inspect) != 1:
        raise ValueError('Docker must identify exactly one runtime container')
    entry = inspect[0]
    state = entry.get('State') or {}
    health = state.get('Health') or {}
    if not (state.get('Running') is True and health.get('Status') == 'healthy'
            and int(state.get('Pid') or 0) > 1):
        raise ValueError(f'{service}: container is not healthy and running')
    image = entry.get('Image')
    if not isinstance(image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError(f'{service}: missing immutable Docker image identity')
    top = run('docker', 'top', cid, '-eo', 'pid,comm')
    java_pids = []
    for row in top.splitlines()[1:]:
        fields = row.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1] in ('java', 'java.exe'):
            java_pids.append(int(fields[0]))
    if len(java_pids) != 1:
        raise ValueError(f'{service}: expected one live Java process, got {java_pids}')
    # java -version writes to stderr; retain only the major version, no private args.
    proc = subprocess.run(['docker', 'exec', cid, 'java', '-version'],
                          capture_output=True, text=True, timeout=30, check=True)
    first_line = (proc.stderr or proc.stdout).splitlines()[0]
    match = re.search(r'\bversion "(\d+)', first_line)
    if not match or int(match.group(1)) < 21:
        raise ValueError(f'{service}: wrong JVM: {first_line}')
    logs = runtime / f'live-{service}-04113.log'
    log_proc = subprocess.run(['docker', 'logs', cid], check=True, capture_output=True, text=True, timeout=30)
    logs.write_text(log_proc.stdout + log_proc.stderr, encoding='utf-8')
    log_data = logs.read_text(encoding='utf-8')
    if not re.search(r'NeverLauncher .* Bridge .*heartbeat=true', log_data, re.I):
        raise ValueError(f'{service}: no real ServerBridge heartbeat in JVM log')
    allow = f'neverlauncher.join.allowed username={player}'
    deny = f'neverlauncher.join.denied username={player}'
    if allow not in log_data or deny not in log_data or log_data.index(deny) <= log_data.index(allow):
        raise ValueError(f'{service}: missing ordered allow/revocation deny from platform')
    probes = {}
    for outcome in ('allow', 'deny'):
        name = (('runtime-launch-minecraft.json' if outcome == 'allow' else 'probe-paper-deny.txt')
                if require_real_join else f'probe-{node}-{outcome}.txt')
        probe_path = runtime / name
        data = probe_path.read_text(encoding='utf-8')
        if require_real_join and outcome == 'allow':
            launch = json.loads(data)
            if launch.get('success') is not True and launch.get('timedOut') is not True:
                raise ValueError('real client JVM did not launch')
        else:
            match = PROBE.search(data)
            if not match or int(match.group(1)) != port or match.group(2) != player:
                raise ValueError(f'{service}: {outcome} network probe does not match the runtime')
        probes[outcome] = {'path': probe_path.name, 'sha256': digest(probe_path)}
    if require_real_join:
        if f'{player} joined the game' not in log_data:
            raise ValueError(f'{service}: no actual player join in game log')
    return {
        'schemaVersion': '1.0', 'productVersion': version, 'service': service,
        'nodeId': node, 'minecraftPort': port, 'bridgeJarSha256': jar_digest,
        'sourceCommit': source_commit,
        'observedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
        'runtime': {'containerId': entry['Id'], 'imageId': image,
                    'hostJavaPid': java_pids[0], 'javaMajor': int(re.search(r'\bversion "(\d+)', first_line).group(1)),
                    'startedAt': state.get('StartedAt'), 'health': 'healthy'},
        'observations': {'signedBridgeHeartbeat': True, 'allowAfterNetworkProbe': True,
                         'denyAfterRevocation': True, 'actualClientJoin': bool(require_real_join)},
        'probes': probes, 'log': {'path': logs.name, 'sha256': digest(logs)},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--service', required=True)
    parser.add_argument('--node', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--player', required=True)
    parser.add_argument('--container', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--require-real-join', action='store_true')
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--source-commit', default='')
    args = parser.parse_args()
    try:
        proof = record(args.service, args.node, args.port, args.player, args.runtime,
                       args.container, args.version, args.require_real_join, args.artifact, args.source_commit)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
        parser.exit(1, f'[live] cannot certify {args.service}: {exc}\n')
    target = args.runtime / f'live-{args.service}-04113.json'
    # Atomic, avoid exposing partial certifications on crash.
    tmp = target.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    tmp.replace(target)
    print(f'[live] observed JVM + authenticated login/revocation: {args.service}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
