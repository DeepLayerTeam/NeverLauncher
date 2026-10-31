#!/usr/bin/env python3
"""Final, fail-closed acceptance for the *built* 0.42.0 ServerBridge network.

This is an executable release boundary, not a producer of certifications.
It inspects the exact copied release JARs, independently recorded real
Minecraft/JVM/Proxy evidence, real Paper world restore and player/rollback
flows. A successful unit test, signed manifest or build alone cannot pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from serverbridge.live_matrix_04113 import certify  # noqa: E402

HEX = re.compile(r'^[a-f0-9]{64}$')
COMMIT = re.compile(r'^[a-f0-9]{40}$|^[a-f0-9]{64}$')
TARGETS = ('velocity', 'bungeecord', 'waterfall', 'bukkit', 'spigot', 'paper',
           'purpur', 'folia', 'fabric', 'quilt', 'forge', 'neoforge', 'sponge', 'vanilla')


class ReleaseBlocked(Exception):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ReleaseBlocked(why)


def read_json(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 16 * 1024 * 1024,
            f'missing, linked or oversized evidence: {path}')
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            require(k not in obj, f'duplicate JSON field {k}: {path.name}')
            obj[k] = v
        return obj
    value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)
    require(type(value) is dict, f'expected JSON object: {path.name}')
    return value


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify_final_jars(root: Path, release: Path, version: str) -> dict:
    # Compare three independent bytes/claims: Gradle-built JAR, the shipped JAR
    # in the final release folder, and the frozen build manifest.
    manifest = read_json(release / 'BRIDGE_PLUGIN_MANIFEST.json')
    require(manifest.get('toolVersion') == version, 'bridge manifest version mismatch')
    rows = manifest.get('artifacts')
    require(type(rows) is list and len(rows) == len(TARGETS), 'incomplete bridge artifact cohort')
    require([row.get('id') for row in rows if type(row) is dict] == list(TARGETS),
            'unexpected, duplicated or reordered release bridge target')
    results = {}
    seen = set()
    for target, row in zip(TARGETS, rows):
        filename = f'neverlauncher-{target}-bridge-{version}.jar'
        require(row.get('file') == filename and HEX.fullmatch(str(row.get('sha256'))) is not None,
                f'{target}: wrong manifest name or digest')
        original = root / 'artifacts/plugins' / filename
        shipped = release / filename
        for item in (original, shipped):
            require(item.is_file() and not item.is_symlink() and item.stat().st_size >= 1024,
                    f'{target}: missing/suspicious final Java artifact: {item}')
        original_hash = digest(original)
        shipped_hash = digest(shipped)
        require(original_hash == shipped_hash == row['sha256'],
                f'{target}: final release JAR differs from actual certified build')
        require(shipped_hash not in seen, f'{target}: duplicate byte-identical runtime JAR')
        seen.add(shipped_hash)
        results[target] = shipped_hash
    for name in ('BRIDGE_RELEASE_ALLOWLIST.json', 'SERVERBRIDGE3_CERTIFICATION.json'):
        require((release / name).is_file() and not (release / name).is_symlink(),
                f'missing release security artifact: {name}')
    return results


def verify_faults(runtime: Path, version: str, commit: str) -> None:
    from scripts.ga.record_network_faults_0420 import REQUIRED, validate
    proof = read_json(runtime / 'network-faults-0420.json')
    require(proof.get('version') == version and proof.get('sourceCommit') == commit and
            proof.get('status') == 'passed' and proof.get('raceDetector') is True,
            'live host/JVM/race fault report does not match exact release')
    require(proof.get('logFile') == 'network-faults-0420.go-test.jsonl',
            'wrong host fault log')
    log = runtime / proof['logFile']
    fresh = validate(log, commit, version)
    require(proof == fresh and set(proof['tests']) == set(REQUIRED),
            'host fault report differs from actual test JSON events')


def verify_e2e_files(runtime: Path, version: str, commit: str) -> None:
    result = read_json(runtime / 'result.json')
    require(result.get('version') == version and result.get('mode') == 'full' and
            result.get('status') == 'passed', 'full real Minecraft E2E not passed')
    checks = result.get('checks') or {}
    require(all(checks.get(k) is True for k in ('actualClient', 'paperJoin', 'sessionRevokeDeny',
                                                'realWorldBackupRestore', 'realGameUpdateRollback',
                                                'liveServerBridgeCore')),
            'missing complete client/join/revoke/world-restore/update-rollback proof')
    evidence_names = result.get('evidence')
    require(type(evidence_names) is list and len(evidence_names) == len(set(evidence_names)),
            'duplicate or malformed runtime evidence index')
    required = ('world-backup-0290.json', 'game-cycle-0364-result.json',
                'live-matrix-core-04113.json')
    require(all(name in evidence_names for name in required), 'missing runtime evidence in index')
    for name in required:
        read_json(runtime / name)
    # The previous independently maintained verifiers inspect actual gameplay
    # counters, file digests, one-time tickets, player identity, and restore.
    checks_to_run = (
        ('scripts/ga/verify_server_control_0290.py',
         ['--e2e-dir', str(runtime), '--version', version, '--source-commit', commit]),
        ('scripts/ga/verify_game_cycle_0364.py',
         ['--e2e-dir', str(runtime), '--version', version, '--source-commit', commit]),
        ('scripts/ga/verify_player_cycle_0398.py',
         ['--e2e-dir', str(runtime), '--version', version, '--source-commit', commit]),
    )
    for script, arguments in checks_to_run:
        try:
            proc = subprocess.run([sys.executable, str(ROOT / script), *arguments],
                                  capture_output=True, text=True, timeout=60, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ReleaseBlocked(f'{script}: evidence verification timed out') from exc
        require(proc.returncode == 0, f'{script}: rejected real E2E evidence: {proc.stderr[-1000:]}')


def accept(root: Path, release: Path, runtime: Path, commit: str) -> dict:
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    from scripts.ga.record_network_faults_0420 import network_gate_version
    require(network_gate_version(version), 'network gate requires version >= 0.42.0')
    require(COMMIT.fullmatch(commit) is not None, 'real source commit SHA required')
    hashes = verify_final_jars(root, release, version)
    matrix = certify(root, runtime, 'all')
    require(matrix.get('status') == 'passed' and matrix.get('passedCount') == len(TARGETS),
            'real JVM/Minecraft/Proxy matrix incomplete: ' + ', '.join(
                f'{name}={matrix.get("cases", {}).get(name, {}).get("reason", "no live proof")}'
                for name in TARGETS if matrix.get('cases', {}).get(name, {}).get('status') != 'passed'))
    for name in TARGETS:
        proof_path = runtime / f'live-{name}-04113.json'
        proof = read_json(proof_path)
        require(proof.get('sourceCommit') == commit, f'{name}: live JVM evidence from different source commit')
        require(matrix['cases'][name].get('bridgeJarSha256') == hashes[name],
                f'{name}: live proof not bound to final JAR bytes')
    verify_faults(runtime, version, commit)
    verify_e2e_files(runtime, version, commit)
    return {'schemaVersion': 'neverlauncher.server-network.acceptance.0420/v1',
            'version': version, 'sourceCommit': commit, 'status': 'passed',
            'runtime': 'real-minecraft-jvm-proxy', 'targetCount': len(TARGETS),
            'checks': {'allTargetsRealJvm': True, 'allReleaseJarDigestsMatch': True,
                       'actualMinecraftClientJoin': True, 'sessionRevocation': True,
                       'worldBackupRestore': True, 'gameUpdateRollback': True,
                       'playerAuthorizationNegativeCases': True,
                       'realJvmHostFaultsAndRaceDetector': True},
            'bridgeJarsSha256': hashes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        outcome = accept(args.root, args.release, args.runtime, args.source_commit)
    except (ReleaseBlocked, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f'NETWORK PRODUCTION RELEASE BLOCKED: {exc}', file=sys.stderr)
        return 2
    serialized = json.dumps(outcome, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.out.with_suffix(args.out.suffix + '.tmp')
        temporary.write_text(serialized, encoding='utf-8')
        temporary.replace(args.out)
    print(serialized)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
