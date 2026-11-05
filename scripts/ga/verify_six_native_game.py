#!/usr/bin/env python3
"""Требовать шесть независимых нативных наблюдений Minecraft в производственном CI.

Используются исходные наблюдения настоящих GUI-исполнителей Windows, Linux и macOS. Это НЕ
независимые подписанные оператором сертификаты GA; второе разрешение по-прежнему обязательно в
verified_targets.py. Шлюз не позволит считать зелёную матрицу доказательством, если нативный
исполнитель не загрузил полную запись положительного и атакующего запусков.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'e2e/scripts'))
from run_native_validation_03410 import verify_game_observations_04314
sys.path.insert(0, str(ROOT / 'scripts/release'))

TARGETS = {
    'windows-x64': ('windows', 'amd64'),
    'windows-arm64': ('windows', 'arm64'),
    'linux-x64': ('linux', 'amd64'),
    'linux-arm64': ('linux', 'arm64'),
    'darwin-x64': ('macos', 'amd64'),
    'darwin-arm64': ('macos', 'arm64'),
}
SHA = re.compile(r'[0-9a-f]{64}\Z')
PACKAGE = re.compile(r'[A-Za-z0-9._:-]{1,128}\Z')
EVIDENCE = (
    'host-capabilities.json', 'staged-execution.json', 'gameplay-smoke.json',
    'adversarial-gameplay-04314.json',
)


def _read(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 2 * 1024 * 1024:
        raise ValueError('missing or unsafe native game evidence: ' + str(path))
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate evidence field: ' + key)
            obj[key] = value
        return obj
    doc = json.loads(path.read_bytes(), object_pairs_hook=unique)
    if not isinstance(doc, dict):
        raise ValueError('native game evidence must be a JSON object')
    return doc


def verify(root: Path, package_id: str, version: str, commit: str, run_id: str) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise ValueError('native game artifact directory absent or unsafe')
    if not PACKAGE.fullmatch(package_id):
        raise ValueError('invalid immutable staged package identity')
    from release_policy import parsed
    number, prerelease = parsed(version)
    if number < (0, 44, 0) or prerelease is not None:
        raise ValueError('0.44.0+ stable release required for six native GUI acceptance')
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or not re.fullmatch(r'[1-9][0-9]*', run_id):
        raise ValueError('native acceptance requires source SHA and CI execution identity')
    names = {f.name for f in root.iterdir()}
    expected = {f'v10-native-{os}-{arch}-gui-{run_id}' for os, arch in TARGETS.values()}
    if names != expected:
        raise ValueError('six native GUI artifact directories required: missing=' + str(sorted(expected - names)) + ' extra=' + str(sorted(names - expected)))
    outputs = []
    for target in TARGETS:
        osname, arch = TARGETS[target]
        directory = root / f'v10-native-{osname}-{arch}-gui-{run_id}'
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError('unsafe native GUI output folder: ' + target)
        verify_game_observations_04314(directory, osname, arch)
        staged = _read(directory / 'staged-execution.json')
        if staged.get('packageId') != package_id:
            raise ValueError(target + ': observation refers to another staged package')
        for name in ('manifestSha256', 'artifactSha256'):
            if not isinstance(staged.get(name), str) or not SHA.fullmatch(staged[name]):
                raise ValueError(target + ': missing exact executable/manifest hash ' + name)
        output = {'target': target, 'packageId': package_id, 'manifestSha256': staged['manifestSha256'],
                  'artifactSha256': staged['artifactSha256']}
        for name in EVIDENCE:
            path = directory / name
            _read(path)
            output[name + 'Sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        outputs.append(output)
    return {'schemaVersion': 'launcher.native-game.aggregate.0440.v1',
            'status': 'observed-not-independently-certified', 'version': version,
            'sourceCommit': commit, 'ciRunId': run_id, 'packageId': package_id,
            'targets': outputs}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--package-id', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.artifacts, args.package_id, args.version, args.commit, args.run_id)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        args.output.unlink(missing_ok=True)
        print('native six-platform game acceptance BLOCKED: ' + str(exc), file=sys.stderr)
        return 3
    print('six native positive and adversarial game observations checked; independent GA still required')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
