#!/usr/bin/env python3
"""Run actual Guard regressions; verify signed server observations and real game witnesses.

No synthetic certification: absent software, live players, real Minecraft artifacts,
reviewed incidents, or measured game frames are BLOCKED, never counted as PASS.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
HEX = re.compile(r'^[0-9a-f]{64}$')
BOOT = re.compile(r'^[0-9a-f]{32}$')
SAFE = re.compile(r'^[a-z][a-z0-9_:-]{0,95}$')
SUITES = (
    ('loader-transformations', 'scripts/tests/guard_loader_0504.py', 6),
    ('runtime-integrity', 'scripts/tests/guard_runtime_integrity_0505.py', 7),
    ('continuous-watchdog', 'scripts/tests/continuous_game_protection_0506.py', 2),
    ('linux-process-protection', 'scripts/tests/linux_runtime_guard_0508.py', 4),
)


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    with path.open('rb') as handle:
        sha = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            sha.update(chunk)
        return sha.hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(obj, dict), f'expected object in {path.name}')
    return obj


def write_report(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_bytes(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False).encode('utf-8') + b'\n')
    os.replace(tmp, path)


def mac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def read_secret(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), 'shadow key must be a regular non-symlink file')
    if os.name != 'nt':
        require(path.stat().st_mode & 0o077 == 0, 'shadow key has unsafe permissions')
    key = bytes.fromhex(path.read_text(encoding='ascii').strip())
    require(len(key) == 32, 'shadow key must contain 32 random bytes')
    return key


def verify_shadow_file(path: Path, key: bytes) -> list[dict]:
    require(path.is_file() and not path.is_symlink(), 'shadow journal is not a regular file')
    require(path.stat().st_size <= 128 * 1024 * 1024, 'shadow journal exceeds per-file limit')
    previous, boot, last_ts = '', None, 0
    events: list[dict] = []
    with path.open('rb') as stream:
        for line_number, line in enumerate(stream, 1):
            require(line.endswith(b'\n') and len(line) <= 2048, f'{path.name}:{line_number}: truncated/oversized event')
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError) as exc:
                raise EvidenceError(f'{path.name}:{line_number}: invalid JSON') from exc
            require(isinstance(record, dict), 'shadow record is not an object')
            fields = {'schema', 'version', 'bootId', 'sequence', 'prevMac', 'timestampMs', 'sessionKey', 'nodeKey', 'outcome', 'reason', 'durationUs', 'mac'}
            require(set(record) == fields, f'{path.name}:{line_number}: unsupported fields')
            signature = record.pop('mac')
            require(isinstance(signature, str) and bool(HEX.fullmatch(signature)), 'invalid shadow MAC encoding')
            expected = mac(key, canonical(record))
            require(hmac.compare_digest(expected, signature), f'{path.name}:{line_number}: failed MAC')
            require(record['schema'] == 'neverlauncher.guard-shadow/v1' and record['version'] == VERSION, 'shadow schema/version mismatch')
            require(isinstance(record['bootId'], str) and BOOT.fullmatch(record['bootId']), 'bad boot ID')
            require(boot is None or boot == record['bootId'], 'mixed boot ID')
            boot = record['bootId']
            require(type(record['sequence']) is int and record['sequence'] == line_number, 'missing/replayed shadow sequence')
            require(record['prevMac'] == previous, 'broken shadow record chain')
            require(type(record['timestampMs']) is int and 1_500_000_000_000 < record['timestampMs'] <= int(time.time() * 1000) + 300_000 and record['timestampMs'] >= last_ts, 'invalid/nonmonotonic observation time')
            last_ts = record['timestampMs']
            for name in ('sessionKey', 'nodeKey'):
                require(isinstance(record[name], str) and bool(HEX.fullmatch(record[name])), f'invalid {name}')
            require(record['outcome'] in ('allowed', 'revoked'), 'unsupported shadow outcome')
            require(isinstance(record['reason'], str) and bool(SAFE.fullmatch(record['reason'])), 'sensitive/invalid reason')
            require((record['reason'] == 'none') == (record['outcome'] == 'allowed'), 'invalid outcome/reason pair')
            require(type(record['durationUs']) is int and 0 <= record['durationUs'] <= 600_000_000, 'invalid checking duration')
            record['mac'] = signature
            record['sourceFileSha256'] = None
            events.append(record)
            previous = signature
    require(bool(events), f'{path.name}: empty shadow journal')
    return events


def percentile(values: list[float], q: float) -> float:
    require(bool(values) and 0 <= q <= 1, 'no values or invalid quantile')
    s = sorted(values)
    pos = (len(s) - 1) * q
    lower = math.floor(pos)
    return s[lower] + (s[min(lower + 1, len(s) - 1)] - s[lower]) * (pos - lower)


def analyze_shadow(folder: Path, key_path: Path, reviews_path: Path | None = None) -> dict:
    key = read_secret(key_path)
    paths = sorted(folder.glob('guard-shadow-*.jsonl'))
    require(bool(paths), 'no live ServerBridge shadow journals supplied')
    events, files, boot_seen = [], [], set()
    for path in paths:
        found = verify_shadow_file(path, key)
        boot_id = found[0]['bootId']
        require(boot_id not in boot_seen, 'duplicate boot journal (replay)')
        boot_seen.add(boot_id)
        files.append({'name': path.name, 'sha256': file_hash(path), 'events': len(found)})
        events.extend(found)
    unique_macs = {v['mac'] for v in events}
    require(len(unique_macs) == len(events), 'replayed event MAC')
    sessions: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        sessions[event['sessionKey']].append(event)
    observed_ms = 0
    revoked_events: list[dict] = []
    durations = []
    for history in sessions.values():
        history.sort(key=lambda row: (row['timestampMs'], row['bootId'], row['sequence']))
        previous = None
        for item in history:
            durations.append(item['durationUs'] / 1000.0)
            if previous and previous['outcome'] == 'allowed' and item['outcome'] == 'allowed':
                delta = item['timestampMs'] - previous['timestampMs']
                if 0 <= delta <= 30_000:
                    # Conservative lower bound: only gaps covered by two
                    # independent successful checks on an active SQL session.
                    observed_ms += delta
            if item['outcome'] == 'revoked':
                revoked_events.append(item)
            previous = item
    reviews: dict[str, str] = {}
    if reviews_path is not None:
        require(reviews_path.is_absolute() and reviews_path.is_file() and not reviews_path.is_symlink()
                and reviews_path.stat().st_nlink == 1 and
                0 < reviews_path.stat().st_size <= 8 * 1024 * 1024 and
                not any(p.is_symlink() for p in reviews_path.parents),
                'review journal must be a bounded, nonlinked original file')
        def no_duplicate_json_fields(pairs):
            obj = {}
            for key, value in pairs:
                require(key not in obj, 'duplicate incident review JSON field')
                obj[key] = value
            return obj
        with reviews_path.open('rb') as f:
            for index, line in enumerate(f, 1):
                require(line.endswith(b'\n') and len(line) <= 2048,
                        f'review {index}: truncated/oversized incident record')
                try:
                    row = json.loads(line, object_pairs_hook=no_duplicate_json_fields)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise EvidenceError(f'review {index}: invalid incident JSON') from exc
                require(isinstance(row, dict) and set(row) == {'eventMac', 'verdict', 'reviewerId'}, f'review {index}: invalid fields')
                evidence = row['eventMac']
                require(isinstance(evidence, str) and bool(HEX.fullmatch(evidence)) and evidence in unique_macs, f'review {index}: unknown event')
                require(row['verdict'] in ('false_positive', 'true_positive', 'inconclusive'), f'review {index}: invalid verdict')
                require(isinstance(row['reviewerId'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{1,63}', row['reviewerId']) is not None,
                        f'review {index}: invalid reviewer')
                require(evidence not in reviews, f'review {index}: duplicate review')
                reviews[evidence] = row['verdict']
    invalid_reviews = [v for v in reviews if v not in {e['mac'] for e in revoked_events}]
    require(not invalid_reviews, 'review must target an actual revoked event')
    counts = {v: sum(1 for e in revoked_events if reviews.get(e['mac']) == v) for v in ('false_positive', 'true_positive', 'inconclusive')}
    missing = len(revoked_events) - sum(counts.values())
    hours = round(observed_ms / 3_600_000, 6)
    # The pilot gate requires independent confirmation of player-hours and an
    # external operator's actual review, not self-reported journal timestamps.
    return {
        'schema': 'neverlauncher.guard-shadow-analysis/v1', 'version': VERSION,
        'status': 'BLOCKED' if hours < 10_000 or missing or counts['inconclusive'] or counts['false_positive'] else 'EVIDENCE_REVIEW_REQUIRED',
        'observedGuardActiveHoursLowerBound': hours,
        'playerHoursCertified': False,
        'requiredLegitimatePlayerHours': 10_000,
        'totalEvents': len(events), 'uniquePseudonymousSessions': len(sessions),
        'revokedEvents': len(revoked_events), 'unreviewedRevocations': missing,
        'reviewed': counts,
        'serverCheckP95Ms': round(percentile(durations, .95), 3),
        'files': files,
        'notes': 'Observations from authenticated server heartbeats; not fresh client memory attestation. Manual incident review and independent real-player-hours evidence remain mandatory.',
    }


def load_frame_capture(folder: Path) -> tuple[dict, list[float], dict]:
    details = read_json(folder / 'capture.json')
    for field in ('os', 'arch', 'cpu', 'gpu', 'minecraftVersion', 'loader', 'scene', 'buildSha256', 'sourceTool'):
        require(isinstance(details.get(field), str) and details[field].strip(), f'missing capture {field}')
    require(HEX.fullmatch(details['buildSha256']) is not None, 'invalid build SHA-256')
    require(details['sourceTool'] in ('PresentMon', 'MangoHud', 'CapFrameX', 'RenderDoc', 'MinecraftFrameProfiler'), 'frame measurements require known actual frame capture tool')
    csvfile = folder / 'frames.csv'
    require(csvfile.is_file() and not csvfile.is_symlink() and csvfile.stat().st_size <= 64 * 1024 * 1024, 'missing/bad frames CSV')
    values = []
    with csvfile.open(newline='', encoding='utf-8-sig') as handle:
        rows = csv.DictReader(handle)
        require(rows.fieldnames is not None and 'frameTimeMs' in rows.fieldnames, 'frames.csv must contain frameTimeMs measured data')
        for row in rows:
            try: value = float(row['frameTimeMs'])
            except (ValueError, TypeError) as exc: raise EvidenceError('invalid frame time') from exc
            require(math.isfinite(value) and 0.05 <= value <= 5000.0, 'invalid recorded frame time')
            values.append(value)
            require(len(values) <= 2_000_000, 'too many frames')
    require(len(values) >= 600, 'at least 600 measured frames required per capture')
    return details, values, {'metadataSha256': file_hash(folder / 'capture.json'), 'framesSha256': file_hash(csvfile), 'frames': len(values)}


def compare_performance(base: Path, protected: Path) -> dict:
    a, av, ah = load_frame_capture(base)
    b, bv, bh = load_frame_capture(protected)
    require(a == b, 'A/B requires exactly matched OS/CPU/GPU/build/scene/loader/tool metadata')
    p0, p1 = percentile(av, .95), percentile(bv, .95)
    change = (p1 / p0 - 1) * 100
    return {
        'schema': 'neverlauncher.guard-frame-performance/v1', 'version': VERSION,
        'status': 'PASS_MEASURED' if change <= 3.0 else 'FAIL_BUDGET',
        'baselineP95FrameMs': round(p0, 4), 'guardP95FrameMs': round(p1, 4),
        'guardP95RegressionPercent': round(change, 3), 'initialBudgetPercent': 3.0,
        'baseline': ah, 'protected': bh,
        'environment': a,
        'notes': 'Only these two external frame capture files were measured; not a cross-hardware performance certification.',
    }


def verify_game(work: Path, server_log: Path, username: str) -> dict:
    result = read_json(work / 'result.json')
    require(result.get('status') == 'passed' and result.get('version') == VERSION, 'real Minecraft E2E result missing or version mismatch')
    game = result.get('minecraft', {})
    checks = result.get('checks', {})
    require(isinstance(game, dict) and game.get('client') == 'actual-mojang-client' and game.get('paperJoin') == 'passed', 'not actual Mojang client / server join')
    for check in ('packageVerified', 'signedManifest', 'actualClient', 'paperJoin', 'sessionRevokeDeny'):
        require(checks.get(check) is True, f'Minecraft E2E check failed: {check}')
    require(game.get('loader') in ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge'), 'invalid loader')
    if game['loader'] != 'vanilla':
        require(checks.get('loaderNativeClientJoin') is True, 'modded client did not join real loader server')
    require((work / 'runtime-launch-minecraft.json').is_file(), 'missing real E2E evidence: runtime-launch-minecraft.json')
    launch = read_json(work / 'runtime-launch-minecraft.json')
    require(launch.get('success') is True or launch.get('timedOut') is True, 'actual game process did not execute')
    evidence = result.get('evidence')
    require(isinstance(evidence, list) and evidence and len(evidence) == len(set(evidence)), 'no unique Minecraft E2E evidence references')
    hashed = {}
    root = work.resolve()
    for name in evidence:
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,120}', name), 'unsafe evidence filename')
        target = work / name
        require(target.is_file() and not target.is_symlink() and target.resolve().parent == root and target.stat().st_size > 0, f'missing real E2E evidence: {name}')
        hashed[name] = file_hash(target)
    require(server_log.is_file() and not server_log.is_symlink() and re.fullmatch(r'[A-Za-z0-9_]{3,16}', username) is not None, 'server log and valid Minecraft player identity required')
    # Match both the authenticated server permission and the actual Minecraft
    # join message in the same captured server log, not a fake client main.
    with server_log.open('r', encoding='utf-8', errors='replace') as log:
        seen_allow, seen_join = False, False
        for line in log:
            seen_allow |= re.search(r'launcher\.join\.allowed username=' + re.escape(username) + r'(?![A-Za-z0-9_])', line) is not None
            seen_join |= re.search(r'(?<![A-Za-z0-9_])' + re.escape(username) + r' joined the game(?![A-Za-z0-9_])', line) is not None
    require(seen_allow and seen_join, 'server never recorded both authenticated admission and real player join')
    return {
        'schema': 'neverlauncher.guard-real-game-evidence/v1', 'version': VERSION,
        'status': 'EVIDENCE_VERIFIED_NOT_INDEPENDENT',
        'loader': game['loader'], 'minecraftVersion': game.get('version'),
        'gameResultSha256': file_hash(work / 'result.json'),
        'serverLogSha256': file_hash(server_log), 'evidenceSha256': hashed,
        'notes': 'Verified actual run artifacts and Paper join log, not independent proof of genuine gameplay duration or all Guard sensors.',
    }


def run_jvm_suites(output: Path, only: set[str] | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    suites = []
    for name, rel, minimum in SUITES:
        if only is not None and name not in only:
            continue
        if name == 'linux-process-protection' and not sys.platform.startswith('linux'):
            suites.append({'name': name, 'status': 'UNSUPPORTED', 'reason': 'requires native Linux JVM'})
            continue
        script = ROOT / rel
        if not script.is_file():
            suites.append({'name': name, 'status': 'BLOCKED', 'reason': 'real executable suite missing'})
            continue
        started = time.monotonic()
        try:
            proc = subprocess.run([sys.executable, str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=260, check=False)
            output_bytes = proc.stdout
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            output_bytes = exc.stdout or b''
            exit_code = 124
        text = output_bytes.decode('utf-8', errors='replace')
        # The log may contain library paths but not user credentials; keep
        # raw evidence locally with strict mode; release reports only hashes.
        log = output / (name + '.log')
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(output_bytes)
        found = re.findall(r'Ran (\d+) tests? in [0-9.]+s', text)
        count = int(found[-1]) if found else 0
        passed = exit_code == 0 and count >= minimum and re.search(r'(?m)^OK\s*$', text) is not None and not re.search(r'\bskipped=\d+\b', text)
        suites.append({'name': name, 'status': 'PASS' if passed else 'FAIL',
                       'exitCode': exit_code, 'testsRun': count, 'minimumTests': minimum,
                       'durationSeconds': round(time.monotonic() - started, 2),
                       'logSha256': digest(output_bytes), 'logFile': log.name})
    status = 'PASS_JVM_REGRESSIONS_ONLY' if suites and all(v['status'] == 'PASS' for v in suites) else 'BLOCKED'
    return {'schema': 'neverlauncher.guard-adversarial-jvm/v1', 'version': VERSION,
            'status': status, 'suites': suites,
            'notes': 'Real Java subprocess fixtures; not official Minecraft or user shadow-pilot certification.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('run-jvm', help='execute actual Java Agent negative and compatibility tests')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--only', choices=[row[0] for row in SUITES], action='append')
    p = sub.add_parser('analyze-shadow', help='verify server-authenticated HMAC shadow journal, count actual observations')
    p.add_argument('--journal-dir', type=Path, required=True)
    p.add_argument('--key-file', type=Path, required=True)
    p.add_argument('--reviews', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('compare-frame-times', help='compare two actual instrumented game-frame captures')
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--guard', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('verify-game', help='validate existing real Minecraft E2E result and Paper join log')
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--paper-log', type=Path, required=True)
    p.add_argument('--username', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'run-jvm': report = run_jvm_suites(args.output.parent / 'logs', set(args.only) if args.only else None)
        elif args.command == 'analyze-shadow': report = analyze_shadow(args.journal_dir, args.key_file, args.reviews)
        elif args.command == 'compare-frame-times': report = compare_performance(args.baseline, args.guard)
        else: report = verify_game(args.work, args.paper_log, args.username)
        write_report(args.output, report)
        print(json.dumps({'status': report['status'], 'report': str(args.output)}, ensure_ascii=False))
        return 0 if report['status'].startswith('PASS') or report['status'] in ('EVIDENCE_VERIFIED_NOT_INDEPENDENT', 'EVIDENCE_REVIEW_REQUIRED') else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'Guard 0.50.12 BLOCKED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
