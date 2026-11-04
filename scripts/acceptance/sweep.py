#!/usr/bin/env python3
"""Final-byte acceptance sweep. Replays real evidence, never converts CI to GA.

`minecraft` executes all 280 deep per-target verifiers on raw runner output.
`full` additionally replays six final native installs, six actual native GUI
runs, independent signed six-target rebuilds, 5 one-hour gameplay soaks, and
an hour of real HTTPS load. Separate independent GA authorization is required.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/acceptance'))
sys.path.insert(0, str(ROOT / 'scripts/release'))
sys.path.insert(0, str(ROOT / 'scripts/ga'))
import inventory_0521 as inventory
import native_packages_0522 as native
import independent_current_05211 as reproducible
import verify_six_native_game_0440 as native_game

SHA = re.compile(r'[a-f0-9]{64}\Z')
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')
SOAK_TARGETS = {
 'vanilla-26.3-linux-x64': 'vanilla',
 'fabric-26.3-linux-x64': 'fabric',
 'quilt-26.3-linux-x64': 'quilt',
 'forge-26.3-linux-x64': 'forge',
 'neoforge-26.2-linux-x64': 'neoforge',
}

class Blocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Blocked(why)

def read_json(path: Path, limit=16*1024*1024):
    inventory.safe_file(path, limit)
    return inventory.read_json(path)

def verify_minecraft(root, commit, run_id, attempt):
    report = inventory.inventory(root, commit, run_id, attempt, strict=True)
    entries = [row for row in report['targets'] if row['id'].startswith('minecraft/') and row['required']]
    require(len(entries) == 280 and all(e['status'] == 'observed' for e in entries),
            '280 real Minecraft targets not all observed')
    return {'status': '280_REAL_CI_OBSERVATIONS_NOT_GA', 'targets': len(entries),
            'catalogSha256': report['catalogSha256']['minecraft'],
            'sha256': hashlib.sha256(inventory.canonical(report)).hexdigest()}

def signed_soak(root: Path, pubkey: Path, pin: str, commit: str, run_id: str, attempt: int, kind: str):
    summary = read_json(root / 'soak.json', 8*1024*1024)
    sig = inventory.safe_file(root / 'soak.sig', 128).read_bytes()
    require(len(sig) == 64 and SHA.fullmatch(pin or '') is not None, 'signed soak receipt and pin required')
    key = inventory.public_key(pubkey, pin)
    try:
        key.verify(sig, ('neverlauncher.soak.real.' + inventory.VERSION + '\x00').encode() + inventory.canonical(summary))
    except InvalidSignature as exc:
        raise Blocked('independent soak attestation signature invalid') from exc
    return raw_soak(root, commit, run_id, attempt, kind)

def raw_soak(root: Path, commit: str, run_id: str, attempt: int, kind: str):
    summary = read_json(root / 'soak.json', 8*1024*1024)
    require(summary.get('schema') == 'neverlauncher.real-soak/' + inventory.VERSION and
            summary.get('status') == 'OBSERVED_NOT_GA' and
            summary.get('version') == inventory.VERSION == '0.53.0' and
            summary.get('commit') == commit and summary.get('runId') == run_id and
            summary.get('attempt') == attempt and summary.get('mode') == kind and
            type(summary.get('seconds')) in (float,int) and summary['seconds'] >= 3600,
            'soak scope, identity or duration invalid')
    if kind == 'game':
        target_id = summary.get('target')
        require(target_id in SOAK_TARGETS, 'game soak not for required five loader anchors')
        targets = {t['id']:t for t in inventory.catalogs()['minecraft']['rows'] if t['required']}
        sessions = summary.get('sessions')
        require(type(sessions) is list and 8 <= len(sessions) <= 200, 'real sessions missing')
        actual = sorted(p.name for p in root.glob('session-*'))
        require(actual == [f'session-{i+1:03d}' for i in range(len(sessions))],
                'gameplay soak execution evidence missing or duplicated')
        duration = 0
        for i, (sample, receipt) in enumerate(zip(actual,sessions),1):
            require(receipt.get('session') == i and type(receipt.get('seconds')) in (int,float)
                    and receipt['seconds'] > 0, 'session identity/time invalid')
            duration += receipt['seconds']
            sample_dir = root / sample
            log = inventory.safe_file(sample_dir / 'runner.log',32*1024*1024)
            require(inventory.digest(log) == receipt.get('runnerLogSha256'), 'soak runner log changed')
            path = sample_dir / 'compatibility-result/compatibility-result.json'
            raw = read_json(path)
            verified = inventory.verify_compatibility(targets[target_id], (path,raw), commit, run_id, attempt)
            require(verified['resultSha256'] == receipt.get('resultSha256') and
                    verified['files'].get('matching-server.log') == receipt.get('serverLogSha256'),
                    'soak session evidence not from live joined game')
        require(duration >= 0.5 * summary['seconds'], 'insufficient time spent in actual sessions')
        return {'targetId': target_id,'sessions':len(sessions),'seconds':summary['seconds'],
                'receiptSha256': inventory.digest(root/'soak.json')}
    # Повторно воспроизводите сырые измерения вместо принятия независимо подписанного, но
    # основанного только на заявлении p95/status. По 20 байт на реальный TLS-запрос.
    ledger = inventory.safe_file(root/'requests.bin', 210*1024*1024)
    require(inventory.digest(ledger) == summary.get('requestsSha256'),
            'changed or missing HTTPS request ledger')
    require(ledger.stat().st_size % 20 == 0 and
            ledger.stat().st_size // 20 == summary.get('requests'),
            'incomplete or truncated HTTPS request measurements')
    times, durations, total_bytes = [], [], 0
    with ledger.open('rb') as stream:
        while part := stream.read(20):
            require(len(part) == 20, 'truncated request sample')
            when, elapsed, size = struct.unpack('!QdI', part)
            require(0 < elapsed <= 30000 and 0 < size <= 256*1024 and
                    (not times or times[-1] <= when), 'nonmonotonic or invalid TLS timing sample')
            times.append(when); durations.append(elapsed); total_bytes += size
    require(len(times) >= 10000 and times[-1]-times[0] >= 3590*10**9,
            'observed request timestamps do not span a real hour')
    import math
    p95 = sorted(durations)[math.ceil(.95*len(durations))-1]
    require(round(p95,3) == summary.get('p95Ms') and
            total_bytes == summary.get('responseBytes'),
            'independent recomputation disagrees with reported latency/volume')
    require(type(summary.get('requests')) is int and summary['requests'] >= 10000 and
            summary.get('failed') == 0 and summary.get('concurrency',0) >= 1 and
            type(summary.get('p95Ms')) in (int,float) and 0 <= summary['p95Ms'] <= 1500,
            'HTTPS soak failed minimum load budget')
    return {'requests': summary['requests'], 'p95Ms': summary['p95Ms'],
            'seconds':summary['seconds'],'receiptSha256':inventory.digest(root/'soak.json')}

def verify_repro(a):
    ka,kb = a.repro_a_key, a.repro_b_key
    require(ka.read_bytes()!=kb.read_bytes(), 'independent builders must have distinct keys')
    reproducible.pinned_key(ka,a.repro_a_pin)
    reproducible.pinned_key(kb,a.repro_b_pin)
    doc_a = reproducible.signed_json(a.repro_a_report,a.repro_a_sig,ka)
    doc_b = reproducible.signed_json(a.repro_b_report,a.repro_b_sig,kb)
    report = reproducible.compare(doc_a,doc_b,a.repro_a_dir,a.repro_b_dir,
                                  a.commit,a.repro_run_id,a.repro_attempt)
    return {'sha256':hashlib.sha256(inventory.canonical(report)).hexdigest(),
            'targets': {name:row['sha256'] for name,row in report['targets'].items()},
            'builders':report['builders']}

def verify_full(a):
    require(COMMIT.fullmatch(a.commit or '') is not None and inventory.VERSION == '0.53.0',
            'current exact source commit and 0.53.0 required')
    report = {'schema':'neverlauncher.full-compatibility-sweep/' + inventory.VERSION,
              'version':inventory.VERSION,'commit':a.commit,'status':'BLOCKED'}
    report['minecraft'] = verify_minecraft(a.compat_results,a.commit,a.compat_run_id,a.compat_attempt)
    native_args = SimpleNamespace(results=a.native_results,source_index=a.source_index,
       manifest_sha256=a.index_sha,version=inventory.VERSION,commit=a.commit,project=a.project,
       run_id=a.native_run_id,attempt=str(a.native_attempt),public_key=a.native_key,
       public_key_sha256=a.native_key_pin,receipt=a.native_review,reviewer=a.native_reviewer)
    native.verify_review(native_args)  # Signature + replay all 6 installation logs.
    report['nativePackages'] = native.aggregate(native_args)
    report['nativeGame'] = native_game.verify(a.native_game_results,a.package_id,
          inventory.VERSION,a.commit,a.native_game_run_id)
    report['reproducibility'] = verify_repro(a)
    require(a.game_soaks.is_dir() and not a.game_soaks.is_symlink(),
            'actual independently reviewed game soak directory missing')
    directory_names = {entry.name for entry in a.game_soaks.iterdir()}
    require(directory_names == set(SOAK_TARGETS) or
            directory_names == set(SOAK_TARGETS) | {'https'},
            'all five unique loader soak folders and no unexpected entries required')
    for name in sorted(SOAK_TARGETS):
        folder = a.game_soaks / name
        require(folder.is_dir() and not folder.is_symlink(), 'unsafe game soak directory')
        row = signed_soak(folder,a.soak_key,a.soak_key_pin,a.commit,a.soak_run_id,
                          a.soak_attempt,'game')
        require(row['targetId'] == name, 'mislabelled loader soak directory')
        report.setdefault('gameSoaks',[]).append(row)
    report['httpSoak'] = signed_soak(a.http_soak,a.soak_key,a.soak_key_pin,
                                    a.commit,a.soak_run_id,a.soak_attempt,'https')
    report['status'] = 'OBSERVED_NOT_INDEPENDENT_GA'
    return report

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='mode',required=True)
    for mode in ('minecraft','full'):
        s = sub.add_parser(mode)
        s.add_argument('--commit', required=True)
        s.add_argument('--compat-results', required=True, type=Path)
        s.add_argument('--compat-run-id', required=True)
        s.add_argument('--compat-attempt', required=True, type=int)
        s.add_argument('--output', required=True, type=Path)
        if mode == 'full':
            for name in ('native-results','source-index','native-review','native-key',
                         'native-game-results','repro-a-report','repro-b-report','repro-a-sig',
                         'repro-b-sig','repro-a-key','repro-b-key','repro-a-dir','repro-b-dir',
                         'game-soaks','http-soak','soak-key'):
                s.add_argument('--'+name, required=True, type=Path)
            for name in ('index-sha','project','native-run-id','native-key-pin',
                         'native-reviewer','native-game-run-id','package-id',
                         'repro-run-id','repro-a-pin','repro-b-pin','soak-run-id','soak-key-pin'):
                s.add_argument('--'+name, required=True)
            for name in ('native-attempt','repro-attempt','soak-attempt'):
                s.add_argument('--'+name,type=int,required=True)
    a = p.parse_args()
    try:
        require(COMMIT.fullmatch(a.commit or '') is not None and RUN.fullmatch(a.compat_run_id or '') is not None,
                'valid exact CI source/run required')
        if a.mode == 'full':
            doc = verify_full(a)
        else:
            doc = {'schema':'neverlauncher.full-compatibility-sweep/' + inventory.VERSION,
                   'version':inventory.VERSION,'commit':a.commit,
                   'status':'280_REAL_CI_OBSERVATIONS_NOT_GA',
                   'minecraft':verify_minecraft(a.compat_results,a.commit,a.compat_run_id,a.compat_attempt)}
        require(a.output.is_absolute() and not a.output.exists(), 'new absolute report filename required')
        inventory.write_exclusive(a.output,(json.dumps(doc,sort_keys=True,indent=2)+'\n').encode())
        print('PASS: real observations replayed; independent final GA remains BLOCKED')
        return 0
    except (Blocked, inventory.Blocked, native.Blocked, reproducible.Blocked, OSError,
            ValueError, TypeError, KeyError, InvalidSignature) as exc:
        print('FULL COMPATIBILITY SWEEP BLOCKED: '+str(exc),file=sys.stderr)
        return 3

if __name__ == '__main__':
    raise SystemExit(main())
