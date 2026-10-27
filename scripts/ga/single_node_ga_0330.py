#!/usr/bin/env python3
"""Verify independently signed *real* 0.33.0 single-node GA evidence.

There is intentionally no 'certify by declaration' or 'generate passing evidence'
mode. An independent operator must sign the literal bytes of a report from
an actual installed SQLite-only HTTP deployment. Never sign a build if that
report or its exact-commit RC results are unavailable.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = '0.33.0'
SUITES = {
    'auth-replay-mfa-and-minecraft': 8,
    'jobs-lease-fencing-and-outbox': 5,
    'sqlite-real-crash-and-backup': 4,
    'single-node-coordinator': 5,
    'postgres-transfer-invariants': 1,
    'actual-postgres-redis-and-s3': 4,
    'http-security-and-minecraft': 4,
    'measured-load-safety': 3,
}
# These must be observed against an actually installed and exercised instance.
# A PostgreSQL backend with a SQLite *coordinator* is not a SQLite-only backend.
CHECKS = (
    'signed_installer_and_release_bom',
    'fresh_install_and_owner_bootstrap',
    'admin_login_and_permissions',
    'minecraft_uuid_login_and_join',
    'one_time_ticket_and_replay_after_restart',
    'mfa_and_token_revocation',
    'sqlite_durable_jobs_outbox_and_fencing',
    'sqlite_wal_crash_and_restore',
    'upgrade_backup_restore_and_rollback',
    'second_backend_denied_same_storage',
    'negative_security_and_signature_tests',
    'bounded_capacity_measurement',
    'operator_runbook_smoke',
)
SHA = re.compile(r'^[0-9a-f]{64}$')
TESTED_ARTIFACTS = (
    'neverlauncher-api-linux-x64',
    'neverlauncher-cli-linux-x64',
    'neverlauncher-linux-x64-0.33.0.tar.gz',
)
COMMIT = re.compile(r'^[0-9a-f]{40}(?:[0-9a-f]{24})?$')
MAX_FILE = 2 * 1024 * 1024


class Blocked(ValueError):
    pass


def strict_json(raw: bytes) -> dict:
    def no_duplicate(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Blocked('duplicate JSON key: ' + key)
            result[key] = value
        return result
    data = json.loads(raw, object_pairs_hook=no_duplicate)
    if not isinstance(data, dict):
        raise Blocked('expected JSON object')
    return data


def bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
        raise Blocked(f'missing, linked or oversized evidence: {path.name}')
    return path.read_bytes()


def public_key(raw: bytes) -> Ed25519PublicKey:
    if raw.lstrip().startswith(b'-----BEGIN'):
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise Blocked('the independent key must be Ed25519')
        return key
    value = raw.strip().decode('ascii')
    try:
        key_raw = bytes.fromhex(value)
    except ValueError:
        key_raw = base64.b64decode(value, validate=True)
    if len(key_raw) != 32:
        raise Blocked('independent Ed25519 public key must be 32 bytes')
    return Ed25519PublicKey.from_public_bytes(key_raw)


def validate_rc(rc: dict, commit: str):
    if rc.get('format') != 'neverlauncher-03216-rc-test-evidence-v1' or rc.get('version') != VERSION or rc.get('commit') != commit:
        raise Blocked('RC evidence version/format/commit mismatch')
    if not re.search(r'go1\.(?:2[7-9]|[3-9]\d)\.', str(rc.get('toolchain', ''))):
        raise Blocked('RC must have used Go 1.27+')
    suites = rc.get('suites')
    if not isinstance(suites, list) or len(suites) != len(SUITES):
        raise Blocked('incomplete RC suite set')
    seen = set()
    for suite in suites:
        if not isinstance(suite, dict):
            raise Blocked('invalid RC suite')
        name = suite.get('suite')
        if name not in SUITES or name in seen:
            raise Blocked('duplicate or unknown RC suite')
        seen.add(name)
        tests = suite.get('passed')
        if not isinstance(tests, list) or len(tests) != SUITES[name] or len(set(tests)) != len(tests) or suite.get('count') != SUITES[name]:
            raise Blocked('RC tests incomplete or duplicated: ' + name)
    if seen != set(SUITES):
        raise Blocked('missing required RC suites')


def validate_attestation(report: dict, commit: str, rc_hash: str):
    if report.get('schema') != 'neverlauncher-single-node-ga-attestation-v1' or report.get('version') != VERSION or report.get('source_commit') != commit:
        raise Blocked('GA attestation version/commit mismatch')
    if report.get('rc_receipt_sha256') != rc_hash:
        raise Blocked('GA attestation is not bound to RC test receipt')
    env = report.get('environment')
    if not isinstance(env, dict) or not all((
        env.get('backend_repository') == 'sqlite',
        env.get('coordinator') == 'sqlite',
        env.get('journal_mode') == 'wal',
        env.get('backend_processes') == 1,
        env.get('database_on_local_supported_filesystem') is True,
        env.get('postgres_required') is False,
        env.get('redis_required') is False,
        env.get('durable_data_after_restart') is True,
    )):
        raise Blocked('SQLite-only production deployment has NOT been proven')
    checks = report.get('checks')
    if not isinstance(checks, dict) or set(checks) != set(CHECKS) or any(checks[c] != 'pass' for c in CHECKS):
        raise Blocked('GA acceptance scenarios missing or failed')
    if report.get('operator') is None or not isinstance(report['operator'], str) or len(report['operator'].strip()) < 3:
        raise Blocked('independent operator identity required')
    tested = report.get('tested_artifacts')
    if not isinstance(tested, dict) or set(tested) != set(TESTED_ARTIFACTS) or any(
            not isinstance(tested[f], str) or not SHA.fullmatch(tested[f]) for f in TESTED_ARTIFACTS):
        raise Blocked('independently tested executable/package bytes must be pinned by SHA-256')


def verify(evidence_dir: Path, pinned_public_key: Path, commit: str) -> dict:
    if not COMMIT.fullmatch(commit):
        raise Blocked('expected full exact source commit')
    report_raw = bounded(evidence_dir / 'SINGLE_NODE_GA_ATTESTATION.json')
    sig_raw = bounded(evidence_dir / 'SINGLE_NODE_GA_ATTESTATION.sig').strip()
    rc_raw = bounded(evidence_dir / 'SINGLE_NODE_GA_RC.json')
    pub_raw = bounded(pinned_public_key)
    key = public_key(pub_raw)
    try:
        signature = base64.b64decode(sig_raw, validate=True)
        if len(signature) != 64:
            raise Blocked('invalid detached Ed25519 signature length')
        key.verify(signature, report_raw)
    except Exception as err:
        # Do not expose claims from unverified attacker-controlled evidence.
        raise Blocked('independent GA attestation signature invalid') from err
    rc_sha = hashlib.sha256(rc_raw).hexdigest()
    validate_rc(strict_json(rc_raw), commit)
    validate_attestation(strict_json(report_raw), commit, rc_sha)
    return {
        'schema': 'neverlauncher-single-node-ga-verification-v1',
        'version': VERSION,
        'source_commit': commit,
        'status': 'independently-attested',
        'rc_receipt_sha256': rc_sha,
        'attestation_sha256': hashlib.sha256(report_raw).hexdigest(),
        'attestation_signature_sha256': hashlib.sha256(sig_raw).hexdigest(),
        'verification_key_fingerprint': hashlib.sha256(key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).hexdigest(),
        'checks': len(CHECKS),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.evidence_dir, args.public_key, args.commit)
        if args.output.exists() or args.output.is_symlink():
            raise Blocked('refusing to overwrite an existing certification file')
        with args.output.open('x', encoding='utf-8') as f:
            json.dump(result, f, sort_keys=True, indent=2)
            f.write('\n')
        args.output.chmod(0o644)
    except (Blocked, OSError, ValueError, TypeError) as err:
        print(f'SINGLE-NODE GA BLOCKED: {err}', file=sys.stderr)
        return 2
    print('Independent signed GA evidence verified; release still requires BOM and release signing.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
