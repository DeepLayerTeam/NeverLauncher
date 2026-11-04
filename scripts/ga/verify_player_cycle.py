#!/usr/bin/env python3
"""Require a genuine Minecraft JVM join/update/rollback and live negative ServerBridge responses.

This verifier consumes the exact outputs of run-minecraft-e2e.sh, rather than
creating success evidence. It is a LOCAL/Yggdrasil player gate; the independently
signed Microsoft online-mode certification remains a separate required gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from verify_game_cycle_0364 import verify as verify_game_cycle

CASES = {
    'uuid-mismatch': ('uuid', 'serverbridge_player_uuid_mismatch'),
    'invalid-uuid': ('uuid', 'serverbridge_player_uuid_invalid'),
    'project-mismatch': ('projectId', 'project_mismatch'),
    'profile-mismatch': ('profileId', 'profile_mismatch'),
    'channel-mismatch': ('channel', 'channel_mismatch'),
    'server-mismatch': ('serverId', 'serverbridge_node_server_id_mismatch'),
    'unissued-player': ('username', 'launcher_session_or_handoff_missing_or_expired'),
}
HEX32 = re.compile(r'[a-f0-9]{32}\Z')
HEX40 = re.compile(r'[a-f0-9]{40}\Z')
HEX64 = re.compile(r'[a-f0-9]{64}\Z')


def require(condition: bool, description: str) -> None:
    if not condition:
        raise ValueError(description)


def read_json(root: Path, name: str) -> dict:
    path = root / name
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 2_000_000,
            f'missing/unsafe actual HTTP evidence: {name}')
    def strict(pairs):
        doc = {}
        for k, v in pairs:
            require(k not in doc, f'duplicate JSON field: {name}:{k}')
            doc[k] = v
        return doc
    doc = json.loads(path.read_text('utf-8'), object_pairs_hook=strict)
    require(type(doc) is dict, f'non-object HTTP evidence: {name}')
    return doc


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_uuid(raw: object) -> str:
    require(type(raw) is str, 'missing Minecraft UUID')
    if len(raw) == 36:
        require(all(raw[i] == '-' for i in (8,13,18,23)), 'malformed Minecraft UUID')
        raw = raw.replace('-', '')
    raw = raw.lower()
    require(HEX32.fullmatch(raw) is not None, 'invalid Minecraft UUID')
    return raw


def verify(root: Path, version: str, source: str, run_id: str = '', run_attempt: str = '') -> dict:
    require(root.is_dir() and not root.is_symlink(), 'missing real E2E directory')
    require(HEX40.fullmatch(source) is not None or HEX64.fullmatch(source) is not None,
            'missing exact source commit')
    base = verify_game_cycle(root, version, source, run_id, run_attempt)
    parent = read_json(root, 'result.json')
    require(parent.get('mode') == 'full' and parent.get('minecraft', {}).get('client') == 'actual-mojang-client' and
            parent.get('minecraft', {}).get('paperJoin') == 'passed' and
            parent.get('checks', {}).get('sessionRevokeDeny') is True,
            'real player join/revocation missing')
    issued = read_json(root, 'join-paper-real-client.json')
    fresh = read_json(root, 'join-paper-real-client-fresh.json')
    require(issued.get('data', {}).get('oneTime') is True and
            fresh.get('data', {}).get('oneTime') is True and
            issued['data'].get('ticketId') != fresh['data'].get('ticketId'),
            'live launch did not receive separate one-time ticket')
    join = issued['data'].get('join', {})
    expected = {'username': join.get('username'), 'projectId': join.get('projectId'),
                'profileId': join.get('profileId'), 'channel': join.get('channel'),
                'serverId': join.get('serverId')}
    uuid = canonical_uuid(join.get('uuid'))
    require(expected == {'username': join['username'], 'projectId': 'e2e-project',
            'profileId': parent['minecraft']['profileId'], 'channel': 'stable',
            'serverId': 'paper-e2e-p3'} and expected['username'], 'unexpected player/server fixture')
    proof = {}
    for case, (changed, reason) in CASES.items():
        name_req = f'player-0398-request-{case}.json'
        name_resp = f'player-0398-response-{case}.json'
        request = read_json(root, name_req)
        response = read_json(root, name_resp)
        status_file = root / f'player-0398-http-{case}.txt'
        require(status_file.is_file() and not status_file.is_symlink() and
                status_file.read_text('ascii') == '403\n',
                f'live negative HTTP status was not 403: {case}')
        require(request.get('protocolVersion') == 2 and
                all(request.get(k) == v for k, v in expected.items() if k != changed),
                f'unexpected signed request fixture: {case}')
        require(all(request.get(k) != expected.get(k) for k in [changed] if changed != 'uuid') and
                (canonical_uuid(request.get('uuid')) != uuid if changed == 'uuid' and case == 'uuid-mismatch' else True),
                f'negative case did not change expected field: {case}')
        if changed != 'uuid':
            require(canonical_uuid(request.get('uuid')) == uuid, f'wrong UUID in negative case {case}')
        if case == 'invalid-uuid':
            require(request.get('uuid') == 'not-a-minecraft-uuid', 'invalid UUID fixture missing')
        require(request.get('pluginVersion') == version and
                HEX64.fullmatch(str(request.get('pluginSha256', ''))) is not None,
                f'wrong actual bridge binary version/digest: {case}')
        payload = response.get('data')
        require(type(payload) is dict and payload.get('allowed') is False and
                payload.get('reason') == reason and not payload.get('player') and
                payload.get('serverId') == request['serverId'] and
                payload.get('username') == request['username'],
                f'{case} not rejected with exact server-side reason')
        proof[case] = {name_req: sha(root / name_req), name_resp: sha(root / name_resp),
                       status_file.name: sha(status_file)}
    allowed = read_json(root, 'validate-paper-e2e-p3-allow.json').get('data', {})
    denied = read_json(root, 'validate-paper-e2e-p3-deny.json').get('data', {})
    require(allowed.get('allowed') is True and
            canonical_uuid(allowed.get('player', {}).get('uuid')) == uuid and
            allowed.get('player', {}).get('username') == expected['username'] and
            denied.get('allowed') is False and
            denied.get('reason') in ('launcher_session_or_handoff_missing_or_expired',
                                     'launcher_session_missing_or_expired'),
            'real ticket was consumed by a negative test, replay succeeded or player UUID changed')
    # Genuine JVM game join and rollback are independently checked by 0.36.4
    # using counters, logs, signed manifests, binary hashes and source identity.
    require(type(base['artifactsVerified']) is int and base['artifactsVerified'] >= 20 and
            base['realJoinsAfterUpdateAndRollback'] is True, 'game cycle not verified')
    return {'status': 'verified', 'scope': 'real-local-Minecraft-player-negative-and-positive-0398',
            'version': version, 'sourceCommit': source, 'negativeCasesVerified': len(CASES),
            'expectedPlayerUUID': uuid, 'runtimeArtifactsVerified': base['artifactsVerified'],
            'evidenceSha256': proof, 'officialProviderLiveE2E': 'not-covered-by-local-runner'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--e2e-dir', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--run-id', default='')
    parser.add_argument('--run-attempt', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.e2e_dir, args.version, args.source_commit,
                                args.run_id, args.run_attempt), sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as err:
        print(f'[player-0398] BLOCKED: {err}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
