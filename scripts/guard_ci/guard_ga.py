#!/usr/bin/env python3
"""Шлюз Guard GA 0.51.0 с блокировкой при неопределённости на ФИНАЛЬНЫХ байтах подписанного установщика.

Шлюз потребляет независимые артефакты реальных запусков на платформе. Он никогда не придумывает
результаты тестов, подписи, игровые часы или одобрение выпуска. Рецензент обязан подписать точное
дерево свидетельств внешним закреплённым ключом.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
sys.path.insert(0, str(ROOT / 'scripts/ga'))
from delivery_verify_0462 import verify_bundle
from verify_six_native_game_0440 import verify as verify_native_game
from adversarial_pilot_05012 import analyze_shadow, compare_performance, verify_game, file_hash

VERSION = '0.51.0'
SCHEMA = 'neverlauncher.guard.ga0510.independent.v1'
DOMAIN = b'neverlauncher.guard.ga0510.independent.v1\x00'
TARGETS = ('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64')
LOADERS = ('vanilla', 'fabric', 'quilt', 'forge', 'neoforge')
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}\Z')
MAX_SMALL = 4 * 1024 * 1024


class Blocked(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Blocked(reason)


def json_unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key: ' + key)
        value[key] = item
    return value


def regular(path: Path, limit: int = MAX_SMALL) -> bytes:
    require(path.is_file() and not path.is_symlink(), 'Отсутствует подтверждение или его файл не является обычным: ' + str(path))
    size = path.stat().st_size
    require(0 < size <= limit, 'Подтверждение пустое или слишком велико: ' + str(path))
    return path.read_bytes()


def doc(path: Path) -> dict:
    try:
        obj = json.loads(regular(path), object_pairs_hook=json_unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Blocked('invalid JSON: ' + str(path)) from exc
    require(type(obj) is dict, 'JSON подтверждения должен содержать объект: ' + str(path))
    return obj


def evidence_inventory(root: Path) -> dict[str, str]:
    require(root.is_dir() and not root.is_symlink(), 'Требуется существующий каталог подтверждений')
    output = {}
    folded = set()
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            require(not (Path(base) / name).is_symlink(), 'Каталог подтверждений является символической ссылкой')
        for name in files:
            path = Path(base) / name
            require(not path.is_symlink() and path.is_file(), 'Файл подтверждения является ссылкой или специальным файлом')
            relative = path.relative_to(root).as_posix()
            require(len(relative) <= 240 and re.fullmatch(r'[A-Za-z0-9_./-]+', relative) is not None
                    and '..' not in Path(relative).parts, 'unsafe evidence member: ' + relative)
            require(relative.casefold() not in folded, 'Неоднозначное имя файла подтверждения с учётом регистра: ' + relative)
            folded.add(relative.casefold())
            require(path.stat().st_size > 0, 'Пустое подтверждение: ' + relative)
            output[relative] = file_hash(path)
            require(len(output) <= 50_000, 'Превышен лимит дерева подтверждений')
    require(bool(output), 'Пустое дерево подтверждений')
    return output


def approval(root: Path, approval_file: Path, signature_file: Path, key_file: Path,
             commit: str, publisher: str, *, now=None) -> dict:
    require(bool(COMMIT.fullmatch(commit)), 'Необходимо указать точный коммит исходников')
    require(bool(IDENTITY.fullmatch(publisher)), 'publisher identity required')
    key = regular(key_file, 32)
    sig = regular(signature_file, 64)
    require(len(key) == 32 and len(sig) == 64, 'raw Ed25519 public key and detached signature required')
    data = regular(approval_file, 512 * 1024)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, DOMAIN + data)
    except (ValueError, InvalidSignature) as exc:
        raise Blocked('Некорректная независимая подпись подтверждения Ed25519') from exc
    manifest = doc(approval_file)
    require(set(manifest) == {'schema', 'version', 'commit', 'reviewer', 'publisher', 'issuedAt', 'files'},
            'approval fields must be exact')
    require(manifest['schema'] == SCHEMA and manifest['version'] == VERSION
            and manifest['commit'] == commit and manifest['publisher'] == publisher,
            'approval is not for this exact release')
    require(type(manifest['reviewer']) is str and bool(IDENTITY.fullmatch(manifest['reviewer']))
            and manifest['reviewer'] != publisher, 'independent reviewer cannot be release publisher')
    try:
        timestamp = datetime.fromisoformat(manifest['issuedAt'].replace('Z', '+00:00'))
    except (AttributeError, TypeError, ValueError) as exc:
        raise Blocked('Некорректная временная метка проверяющего') from exc
    now = now or datetime.now(timezone.utc)
    require(timestamp.tzinfo is not None and now - timedelta(hours=72) <= timestamp <= now + timedelta(minutes=1),
            'review is stale or future-dated')
    files = manifest['files']
    actual = evidence_inventory(root)
    require(type(files) is dict and files == actual, 'Независимое подтверждение не охватывает все байты свидетельств')
    return {'reviewer': manifest['reviewer'], 'approvalSha256': hashlib.sha256(data).hexdigest(),
            'reviewerKeySha256': hashlib.sha256(key).hexdigest(), 'filesBound': len(actual)}


def verified_native(root: Path, commit: str, delivered: dict) -> dict:
    results = {}
    seen_runs = set()
    for target in TARGETS:
        r = doc(root / 'native-signed' / (target + '.json'))
        require(set(r) == {'schema', 'version', 'commit', 'target', 'status', 'packageSha256',
                           'releaseManifestSha256', 'nativeOS', 'nativeArch', 'verifier',
                           'publisherSigner', 'operator', 'executionId'},
                target + ': invalid native certificate structure')
        osname, arch = target.split('-')
        expected_os = {'windows': 'Windows', 'linux': 'Linux', 'darwin': 'Darwin'}[osname]
        expected_verifier = {'windows': 'authenticode-chain-timestamp',
                             'linux': 'production-cli-release-trust',
                             'darwin': 'codesign-gatekeeper-notarized'}[osname]
        require(r['schema'] == 'neverlauncher.guard.native-signed/0510' and r['version'] == VERSION
                and r['commit'] == commit and r['target'] == target and r['status'] == 'native-verified'
                and r['nativeOS'] == expected_os and r['nativeArch'] == arch
                and r['verifier'] == expected_verifier,
                target + ': native signing never passed on correct OS/CPU')
        require(r['packageSha256'] == delivered['targets'][target]['sha256'],
                target + ': native signer did not check final package')
        require(r['releaseManifestSha256'] == file_hash(root / 'signed' / 'RELEASE_MANIFEST.json'),
                target + ': signing receipt refers to another release manifest')
        for field in ('publisherSigner', 'operator', 'executionId'):
            require(type(r[field]) is str and bool(IDENTITY.fullmatch(r[field])),
                    target + ': invalid ' + field)
        require((target, r['executionId']) not in seen_runs, 'Повторно использован идентификатор нативного выполнения')
        seen_runs.add((target, r['executionId']))
        results[target] = r
    return results


def verified_jvm(root: Path) -> dict:
    summary = {}
    for target in TARGETS:
        folder = root / 'adversarial' / target
        report = doc(folder / 'result.json')
        suites = report.get('suites')
        minimum = {'loader-transformations', 'continuous-watchdog'}
        if target.startswith('linux-'):
            minimum |= {'runtime-integrity', 'linux-process-protection'}
        require(report.get('schema') == 'neverlauncher.guard-adversarial-jvm/v1'
                and report.get('version') == VERSION and report.get('status') == 'PASS_JVM_REGRESSIONS_ONLY'
                and type(suites) is list and {s.get('name') for s in suites if isinstance(s, dict)} == minimum,
                target + ': missing successful actual JVM tests')
        for item in suites:
            require(item.get('status') == 'PASS' and type(item.get('exitCode')) is int and item['exitCode'] == 0
                    and type(item.get('testsRun')) is int and type(item.get('minimumTests')) is int
                    and item['testsRun'] >= item['minimumTests'] > 0,
                    target + ': JVM adversarial suite did not pass')
            name = item.get('logFile')
            require(type(name) is str and re.fullmatch(r'[a-z0-9-]+\.log', name) is not None,
                    target + ': unsafe JVM log path')
            require(item.get('logSha256') == file_hash(folder / 'logs' / name),
                    target + ': JVM log was altered or absent')
        summary[target] = len(suites)
    return summary


def verified_frame_times(root: Path, delivered: dict) -> dict:
    results = {}
    for target in TARGETS:
        base = root / 'performance' / target
        details = compare_performance(base / 'baseline', base / 'guard')
        meta = details['environment']
        osname, arch = target.split('-')
        require(meta['os'] == {'darwin': 'macos'}.get(osname, osname)
                and meta['arch'] in ({'x64': ('x64', 'amd64', 'x86_64'),
                                     'arm64': ('arm64', 'aarch64')}[arch]),
                target + ': performance run is from different host architecture')
        require(meta.get('packageSha256') == delivered['targets'][target]['sha256'],
                target + ': performance capture is not bound to final signed package')
        require(details['status'] == 'PASS_MEASURED', target + ': p95 времени кадра превышает допустимый предел')
        results[target] = details['guardP95RegressionPercent']
    return results


def verified_minecraft(root: Path, delivered: dict, commit: str) -> dict:
    completed = 0
    for target in TARGETS:
        for loader in LOADERS:
            work = root / 'real-game' / target / loader
            run = doc(work / 'run-identity.json')
            require(set(run) == {'target', 'version', 'loader', 'packageSha256', 'username', 'commit'}
                    and run['target'] == target and run['version'] == VERSION
                    and run['loader'] == loader and run['packageSha256'] == delivered['targets'][target]['sha256']
                    and run['commit'] == commit,
                    f'{target}/{loader}: real game not linked to final package')
            result = verify_game(work, work / 'paper.log', run['username'])
            require(result['loader'] == loader, f'{target}/{loader}: different Minecraft loader ran')
            completed += 1
    return {'realNativeMinecraftJoins': completed}


def gate(root: Path, approve_file: Path, approve_sig: Path, trusted_key: Path,
         commit: str, publisher: str, native_package_id: str, ci_run: str,
         shadow_key: Path, *, publishing_bundle: Path | None = None, now=None) -> dict:
    require((ROOT / 'VERSION').read_text(encoding='utf-8').strip() == VERSION,
            'source VERSION must equal 0.51.0')
    require(root.is_dir() and not root.is_symlink(), 'Отсутствует корень подтверждений')
    require(not shadow_key.resolve().is_relative_to(root.resolve()),
            'private shadow journal verification key must remain outside evidence')
    require(not trusted_key.resolve().is_relative_to(root.resolve()),
            'independent reviewer trust anchor must remain outside evidence')
    # Проверяйте независимую подпись ДО трактовки доказательств, контролируемых злоумышленником.
    independent = approval(root, approve_file, approve_sig, trusted_key, commit, publisher, now=now)
    require(re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', native_package_id) is not None
            and re.fullmatch(r'[1-9][0-9]*', ci_run) is not None,
            'immutable native run identity required')
    release = verify_bundle(root / 'signed', release_manifest=True)
    require(release.get('version') == VERSION and release.get('releaseManifestMatchesAssets') is True
            and set(release.get('targets', {})) == set(TARGETS),
            'final signed six-target distribution not verified')
    if publishing_bundle is not None:
        require(evidence_inventory(root / 'signed') == evidence_inventory(publishing_bundle),
                'publication candidate differs from independently reviewed final signed bytes')
    native = verified_native(root, commit, release)
    game = verify_native_game(root / 'native-game', native_package_id, VERSION, commit, ci_run)
    require(len(game['targets']) == 6, 'Отсутствуют отчёты реального игрового запуска')
    for row in game['targets']:
        target = row['target']
        require(row['artifactSha256'] == release['targets'][target]['sha256'],
                target + ': native game did not run final signed package')
    jvm = verified_jvm(root)
    performance = verified_frame_times(root, release)
    games = verified_minecraft(root, release, commit)
    pilot = analyze_shadow(root / 'shadow', shadow_key, root / 'shadow-reviews.jsonl')
    require(pilot['status'] == 'EVIDENCE_REVIEW_REQUIRED' and pilot['observedGuardActiveHoursLowerBound'] >= 10000
            and pilot['unreviewedRevocations'] == 0
            and pilot['reviewed']['false_positive'] == 0 and pilot['reviewed']['inconclusive'] == 0,
            '10,000 legitimate shadow player-hours and reviewed zero-false-positive incidents required')
    # Эти серверные наблюдения не доказывают, что каждый час принадлежит настоящему
    # человеку. Другой независимый проверяющий подтверждает подлинность по источникам
    # ВНЕ этого низкопривилегированного журнала.
    certified = doc(root / 'shadow-certification.json')
    require(certified.get('schema') == 'neverlauncher.guard.shadow-certified/0510'
            and certified.get('status') == 'independently-reviewed'
            and certified.get('version') == VERSION
            and certified.get('reviewer') == independent['reviewer']
            and type(certified.get('legitimatePlayerHours')) in (int, float)
            and certified['legitimatePlayerHours'] >= 10000
            and certified['legitimatePlayerHours'] <= pilot['observedGuardActiveHoursLowerBound']
            and certified.get('journalFiles') == pilot['files'],
            'independently verified legitimate player-hours must match the observed journal')
    require(all(value['operator'] != independent['reviewer'] for value in native.values()),
            'final reviewer cannot be a native test operator')
    return {'schema': 'neverlauncher.guard.ga0510.verification.v1',
            'version': VERSION, 'commit': commit, 'status': 'independent-guard-acceptance-verified',
            'approvedBy': independent['reviewer'], 'approvalSha256': independent['approvalSha256'],
            'releaseManifestSha256': file_hash(root / 'signed' / 'RELEASE_MANIFEST.json'),
            'signedPackages': {target: release['targets'][target]['sha256'] for target in TARGETS},
            'nativeSigningVerified': len(native), 'nativeGameVerified': len(game['targets']),
            'jvmSuitesVerified': jvm, 'gameJoinsVerified': games['realNativeMinecraftJoins'],
            'frameP95RegressionPercent': performance,
            'shadowPlayerHours': pilot['observedGuardActiveHoursLowerBound'],
            'reviewedRevocations': pilot['revokedEvents'], 'filesIndependentlyBound': independent['filesBound']}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence-root', required=True, type=Path)
    p.add_argument('--approval', required=True, type=Path)
    p.add_argument('--signature', required=True, type=Path)
    p.add_argument('--trusted-reviewer-key', required=True, type=Path)
    p.add_argument('--commit', required=True)
    p.add_argument('--release-operator', required=True)
    p.add_argument('--native-package-id', required=True)
    p.add_argument('--native-ci-run', required=True)
    p.add_argument('--shadow-key', required=True, type=Path)
    p.add_argument('--publishing-bundle', type=Path, help="Каталог реального выпуска, который планируется опубликовать")
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args(argv)
    if args.output.resolve().is_relative_to(args.evidence_root.resolve()):
        print('GUARD 0.51.0: производственная приёмка заблокирована — квитанция не может изменять дерево подписанных свидетельств', file=sys.stderr)
        return 2
    args.output.unlink(missing_ok=True)
    try:
        result = gate(args.evidence_root, args.approval, args.signature,
                      args.trusted_reviewer_key, args.commit, args.release_operator,
                      args.native_package_id, args.native_ci_run, args.shadow_key,
                      publishing_bundle=args.publishing_bundle)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': result['status'], 'output': str(args.output)}))
        return 0
    except (Blocked, ValueError, KeyError, OSError, TypeError, RuntimeError, json.JSONDecodeError) as exc:
        print('GUARD 0.51.0 PRODUCTION GA BLOCKED: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
