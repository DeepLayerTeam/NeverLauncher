#!/usr/bin/env python3
"""Зафиксировать и независимо повторить точные неподписанные нативные пакеты 0.52.12.

Сборочный узел должен создать шесть *настоящих* пакетов ОС/CPU штатными нативными скриптами.
Сгенерированные манифесты, фиктивные исполняемые файлы или локальные фикстуры не удовлетворяют
инспектору архива. Каждый сборочный узел подписывает независимо. Сравнение повторно открывает все 12
архивов и проверяет содержимое и подписи. Это НЕ сертифицирует нативные подписи ОС или финальные
установщики — за них отвечает 0.52.2.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from reproducible_0470 import (TARGETS, contract, atomic_json, visit_archive, require_path,
    sha256_file, signed_json)

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r'[a-f0-9]{40}\Z')
ID = re.compile(r'[a-zA-Z0-9_.:-]{3,128}\Z')
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
SCHEMA = 'neverlauncher.unsigned-build-current/' + VERSION
LOCKS = ('services/api/go.mod', 'services/api/go.sum', 'apps/desktop/package-lock.json',
         'apps/desktop/src-tauri/Cargo.toml', 'runtime/runtime/Cargo.toml',
         'scripts/release/unsigned_package_0470.py')

class Blocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Blocked(why)

def source_sha() -> str:
    result = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True)
    return result.stdout.strip()

def inputs() -> dict:
    output = {}
    for name in LOCKS:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink(), 'missing locked build input: ' + name)
        output[name] = sha256_file(path)
    return output

def expected_archives():
    return dict(contract()['targets'])

def scan(directory: Path):
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(),
            'absolute, non-symlinked actual payload directory required')
    expected = expected_archives()
    seen = {p.name for p in directory.iterdir()}
    require(seen == set(expected.values()), 'six exact unsigned archives required, no extra files')
    output = {}
    for target, name in sorted(expected.items()):
        path = require_path(directory, name)
        platform, arch = target.split('-', 1)
        members = visit_archive(path, platform, arch)
        output[target] = {'file': name, 'size': path.stat().st_size,
                          'sha256': sha256_file(path), 'members': members}
    require(set(output) == TARGETS, 'six target coverage incomplete')
    return output

def capture(directory: Path, builder: str, runner: str, commit: str, run_id: str, attempt: int):
    require(VERSION == '0.53.0', 'release version 0.53.0 required')
    require(SHA.fullmatch(commit) and source_sha() == commit, 'checkout/source commit mismatch')
    require(all(ID.fullmatch(x or '') for x in (builder, runner, run_id)) and
            type(attempt) is int and attempt > 0, 'invalid independent builder identity')
    return {'schema': SCHEMA, 'version': VERSION, 'commit': commit,
            'builder': builder, 'runner': runner, 'runId': run_id, 'attempt': attempt,
            'inputs': inputs(), 'targets': scan(directory)}

def pinned_key(path: Path, pin: str):
    require(re.fullmatch('[a-f0-9]{64}', pin or ''), 'independently pinned builder key required')
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'unsafe builder key path')
    raw = path.read_bytes()
    require(len(raw) <= 8192, 'builder key too large')
    key = serialization.load_pem_public_key(raw)
    require(isinstance(key, Ed25519PublicKey), 'Ed25519 builder key required')
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(hashlib.sha256(der).hexdigest() == pin, 'builder public key pin mismatch')
    return key

def compare(a: dict, b: dict, dir_a: Path, dir_b: Path, commit: str, run_id: str, attempt: int):
    require(a.get('schema') == b.get('schema') == SCHEMA, 'unsupported independent-build schema')
    require(a.get('version') == b.get('version') == VERSION == '0.53.0' and
            a.get('commit') == b.get('commit') == commit and
            a.get('runId') == b.get('runId') == run_id and
            a.get('attempt') == b.get('attempt') == attempt,
            'source, version or CI run differs')
    require(source_sha() == commit and SHA.fullmatch(commit) is not None, 'checkout not exact source')
    require(a.get('inputs') == b.get('inputs') == inputs(), 'build inputs changed')
    require(a.get('builder') != b.get('builder') and a.get('runner') != b.get('runner') and
            all(ID.fullmatch(x or '') for x in (a.get('builder'), b.get('builder'), a.get('runner'), b.get('runner'))),
            'independent builder/runner identities required')
    require(a.get('targets') == scan(dir_a) and b.get('targets') == scan(dir_b),
            'signed reports disagree with actual archive bytes')
    require(a['targets'] == b['targets'] and set(a['targets']) == TARGETS,
            'two independent builds differ in unsigned byte payloads')
    return {'schema': 'neverlauncher.reproducibility-current-comparison/' + VERSION,
            'version': VERSION, 'commit': commit, 'runId': run_id, 'attempt': attempt,
            'status': 'SIX_UNSIGNED_TARGETS_BYTE_IDENTICAL_NOT_GA',
            'inputs': a['inputs'], 'builders': [
                {'name': a['builder'], 'runner': a['runner']},
                {'name': b['builder'], 'runner': b['runner']}],
            'targets': {key: {'sha256': row['sha256'], 'size': row['size'], 'members': len(row['members'])}
                        for key, row in sorted(a['targets'].items())}}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    cap = sub.add_parser('capture')
    cap.add_argument('--bundle', required=True, type=Path)
    cap.add_argument('--builder', required=True)
    cap.add_argument('--runner', required=True)
    cap.add_argument('--commit', required=True)
    cap.add_argument('--run-id', required=True)
    cap.add_argument('--attempt', required=True, type=int)
    cap.add_argument('--out', required=True, type=Path)
    cmp = sub.add_parser('compare')
    for side in ('a','b'):
        for name in ('report','sig','key','dir','key-sha256'):
            cmp.add_argument('--'+side+'-'+name, required=True)
    cmp.add_argument('--commit', required=True)
    cmp.add_argument('--run-id', required=True)
    cmp.add_argument('--attempt', required=True, type=int)
    cmp.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    try:
        if a.cmd == 'capture':
            doc = capture(a.bundle.resolve(), a.builder, a.runner, a.commit, a.run_id, a.attempt)
        else:
            left, right = Path(a.a_key).resolve(), Path(a.b_key).resolve()
            require(left.read_bytes() != right.read_bytes(), 'different independent trust anchors required')
            pinned_key(left, a.a_key_sha256); pinned_key(right, a.b_key_sha256)
            r1 = signed_json(Path(a.a_report).resolve(), Path(a.a_sig).resolve(), left)
            r2 = signed_json(Path(a.b_report).resolve(), Path(a.b_sig).resolve(), right)
            doc = compare(r1, r2, Path(a.a_dir).resolve(), Path(a.b_dir).resolve(),
                          a.commit, a.run_id, a.attempt)
        require(not a.out.exists(), 'refusing to overwrite comparison/receipt')
        atomic_json(a.out, doc)
        print('PASS: exact unsigned payloads independently checked; final native GA NOT established')
        return 0
    except (Blocked, OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        print('INDEPENDENT BUILD BLOCKED: ' + str(exc), file=sys.stderr)
        return 3

if __name__ == '__main__':
    raise SystemExit(main())
