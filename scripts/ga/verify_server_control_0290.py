#!/usr/bin/env python3
"""Fail-closed validation of CI-produced real Minecraft and Paper restore evidence.

The authoritative execution is e2e/scripts/run-minecraft-e2e.sh. This verifier
cannot manufacture evidence or replace a real E2E run: it examines the files
left by that job, rejects skipped/substituted reports and mismatched commits.
"""
import argparse
import json
from pathlib import Path
import re
import sys

DIGEST = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')


def strict_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError(f'missing, symlinked or oversized evidence: {path.name}')
    def unique(pairs):
        value = {}
        for k, v in pairs:
            if k in value:
                raise ValueError(f'duplicate evidence key {k}')
            value[k] = v
        return value
    data = json.loads(path.read_text('utf-8'), object_pairs_hook=unique)
    if not isinstance(data, dict):
        raise ValueError(f'not a JSON object: {path.name}')
    return data


def verify(root: Path, version: str, commit: str):
    result = strict_json(root / 'result.json')
    proof = strict_json(root / 'world-backup-0290.json')
    if result.get('version') != version or result.get('status') != 'passed' or result.get('mode') != 'full':
        raise ValueError('full actual-client Minecraft E2E result missing')
    mc = result.get('minecraft', {})
    if not isinstance(mc, dict) or mc.get('client') != 'actual-mojang-client' or mc.get('paperJoin') != 'passed':
        raise ValueError('real Minecraft client Paper join not evidenced')
    checks = result.get('checks', {})
    required = ('signedManifest', 'cleanSync', 'actualClient', 'paperJoin',
                'sessionRevokeDeny', 'bukkitFamilyRuntime', 'proxyFamilyRuntime')
    if not isinstance(checks, dict) or any(checks.get(k) is not True for k in required):
        raise ValueError('real login, replay or routing checks missing')
    if proof.get('schemaVersion') != 'neverlauncher.server-control.real-world-restore.v1' or proof.get('version') != version or proof.get('status') != 'passed':
        raise ValueError('real Paper world restore report not present for release')
    if proof.get('source') != 'docker-compose-real-paper-after-minecraft-client-join':
        raise ValueError('restored source is not the real Minecraft Paper container')
    for name in ('actualMinecraftWorld', 'gracefulPaperExit', 'minecraftSaveFlushAcknowledged', 'worldBackupVerified',
                 'isolatedRestoreVerified', 'overwriteRejected', 'returnedToHealthyService'):
        if proof.get(name) is not True:
            raise ValueError(f'world backup runtime check failed: {name}')
    for name in ('playerDataFiles', 'pluginDataFiles', 'filesVerified'):
        if type(proof.get(name)) is not int or proof[name] <= 0:
            raise ValueError(f'world backup contains no actual {name}')
    if not DIGEST.fullmatch(str(proof.get('worldFileSha256', ''))):
        raise ValueError('no preserved real world digest')
    if commit:
        if not COMMIT.fullmatch(commit) or proof.get('sourceCommit') != commit:
            raise ValueError('Paper world restore proof belongs to a different commit')
    # Validate independent outputs, not just an asserted boolean in result.json.
    join = strict_json(root / 'join-paper-real-client-fresh.json')
    if join.get('data', {}).get('oneTime') is not True or join.get('data', {}).get('ticketVersion') != 2:
        raise ValueError('real Minecraft client did not receive a one-time join ticket')
    denied = strict_json(root / 'validate-paper-e2e-p3-deny.json')
    if denied.get('data', {}).get('allowed') is not False:
        raise ValueError('ServerBridge replay was not rejected')
    if 'world-backup-0290.json' in result.get('evidence', []) and checks.get('realWorldBackupRestore') is not True:
        raise ValueError('inconsistent backup evidence index')
    handoff = strict_json(root / 'handoff-velocity-paper.json')
    if handoff.get('data', {}).get('oneTime') is not True or handoff.get('data', {}).get('status') != 'handoff-created':
        raise ValueError('real proxy-to-backend one-time handoff not evidenced')
    return {'version': version, 'sourceCommit': commit, 'status': 'verified',
            'realPlayerDataFiles': proof['playerDataFiles'], 'realPluginDataFiles': proof['pluginDataFiles']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--e2e-dir', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.e2e_dir, args.version, args.source_commit), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f'[0290] Production GA evidence denied: {error}', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
