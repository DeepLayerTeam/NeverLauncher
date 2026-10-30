#!/usr/bin/env python3
"""Independently signed, exact-byte per-target GA authorization for all GA releases.

Invoked after staging REAL installers and BEFORE the existing release signer.
An RC test receipt, unsigned CI artifact, or asserted status alone cannot authorize
GA. Operator signature must bind actual package and executable hashes and nine
independent live acceptance records per shipped platform/architecture.
For 0.40.0+ the signed approval additionally binds six complete player-journey
checks (both identity modes, component graph, textures and recovery) to the
exact packaged client, not just the source-compiled desktop executable.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import policy

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = policy('0.36.0').signing_domain  # exported for historical 0.36.0 readers
TARGETS = ('windows-x64','windows-arm64','linux-x64','linux-arm64','darwin-x64','darwin-arm64')
CHECKS = ('nativeInstall','desktopLaunch','minecraftLaunch','serverJoin',
          'releaseRollback','security','performance','operations','osSignature')
PLAYER_CHECKS_0400 = ('componentPresetInstall', 'skinCapeGameRender',
    'localYggdrasilJoin', 'officialOnlineModeJoin',
    'identityNegativeAndReplay', 'playerUpdateRollback')
PLAYER_OBSERVATIONS_0400 = {
    'componentPresetInstall': ('dependenciesResolved', 'conflictsDenied', 'presetInstalled'),
    'skinCapeGameRender': ('skinRendered', 'capeRendered', 'modelVerified'),
    'localYggdrasilJoin': ('sessionJoinVerified', 'serverUUIDMatches', 'serverAccepted'),
    'officialOnlineModeJoin': ('microsoftIdentityVerified', 'onlineModeVerified', 'serverUUIDMatches', 'serverAccepted'),
    'identityNegativeAndReplay': ('wrongUUIDDenied', 'foreignProjectDenied', 'replayedTicketDenied', 'crossRealmDenied'),
    'playerUpdateRollback': ('updateJVMJoin', 'rollbackJVMJoin', 'userFilesPreserved'),
}


def checks_for(version: str) -> tuple[str, ...]:
    # Exact-byte, platform-specific player acceptance is a new stable-release
    # requirement; historical signed formats remain verifiable unchanged.
    from release_policy import parsed
    number, _ = parsed(version)
    return CHECKS + PLAYER_CHECKS_0400 if number >= (0, 40, 0) else CHECKS


def verify_player_trace(trace: dict, check: str, item: dict, target: str,
                        evidence: Path) -> None:
    # An operator approval over a build executable alone cannot prove that
    # the actual shipped installer completed the player cycle. Require the
    # same real installed package and one correlated execution for every part.
    require(set(trace) == {'schemaVersion','version','commit','target','kind',
            'status','actualExecution','simulated','artifactSha256','executionId',
            'packageSha256','playerCycleId','evidenceSha256'},
            target+': incomplete final-package player trace '+check)
    require(trace['packageSha256'] == item['packageSha256'] and
            isinstance(trace['playerCycleId'],str) and
            re.fullmatch(r'[a-zA-Z0-9._:-]{16,128}', trace['playerCycleId']) is not None and
            isinstance(trace['evidenceSha256'],str) and
            SHA.fullmatch(trace['evidenceSha256']) is not None,
            target+': player test does not bind a real final-package run: '+check)
    # The signed trace must reference independently stored live operator output,
    # not merely assert success. Hash the raw evidence and process log bytes;
    # no in-memory/generated release manifests are accepted as execution logs.
    folder = evidence/'targets'/target/'player-0400'
    require(folder.is_dir() and not folder.is_symlink(),
            target+': actual player execution evidence directory missing')
    report_path = folder/(check+'.json')
    report = read_json(report_path)
    require(sha(report_path) == trace['evidenceSha256'],
            target+': signed player evidence digest mismatch: '+check)
    require(set(report) == {'schemaVersion','version','commit','target','kind',
                           'status','playerCycleId','binarySha256','packageSha256',
                           'observed','runtimeLogSha256'},
            target+': malformed actual player report: '+check)
    for key, wanted in (('schemaVersion','neverlauncher.player.final.0400.v1'),
                        ('version',trace['version']), ('commit',trace['commit']),
                        ('target',target), ('kind',check), ('status','passed'),
                        ('playerCycleId',trace['playerCycleId']),
                        ('binarySha256',item['binarySha256']),
                        ('packageSha256',item['packageSha256'])):
        require(report.get(key) == wanted, target+': mismatched real execution field '+key+': '+check)
    required = PLAYER_OBSERVATIONS_0400[check]
    observed = report['observed']
    require(type(observed) is dict and set(observed) == set(required) and
            all(observed[name] is True for name in required),
            target+': actual player result absent or negative: '+check)
    log_path = folder/(check+'.log')
    require(log_path.is_file() and not log_path.is_symlink() and
            0 < log_path.stat().st_size <= 32*1024*1024 and
            isinstance(report['runtimeLogSha256'],str) and
            SHA.fullmatch(report['runtimeLogSha256']) is not None and
            sha(log_path) == report['runtimeLogSha256'],
            target+': missing, corrupted or unsigned actual runtime log: '+check)

SHA = re.compile(r'[a-f0-9]{64}\Z')
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
LIMIT = 1024 * 1024

class Blocked(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def read_file(path: Path, max_size=LIMIT) -> bytes:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= max_size,
            'missing, symlinked, empty or oversized file: '+str(path))
    return path.read_bytes()


def object_pairs(pairs):
    result={}
    for key, value in pairs:
        if key in result:
            raise Blocked('duplicate JSON field: '+key)
        result[key]=value
    return result


def read_json(path: Path):
    value=json.loads(read_file(path), object_pairs_hook=object_pairs)
    require(isinstance(value,dict), 'JSON root must be an object')
    return value


def sha(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda:file.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()


def utc(value):
    require(isinstance(value,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',value),
            'timestamp must be UTC second precision')
    return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def paths(version, target):
    osname,arch=target.split('-')
    binaries={'windows':f'neverlauncher-desktop-windows-{arch}.exe',
              'linux':f'neverlauncher-desktop-linux-{arch}',
              'darwin':f'neverlauncher-desktop-macos-{arch}'}
    packages={'windows':f'neverlauncher-desktop-{version}-windows-{arch}.zip',
              'linux':f'neverlauncher-linux-{arch}-{version}.tar.gz',
              'darwin':f'neverlauncher-desktop-{version}-macos-{arch}.zip'}
    return binaries[osname],packages[osname]


def approval_data(evidence: Path, public_key: Path, version: str, commit: str, *, now=None):
    """Cryptographic preflight prior to staging; full byte-check occurs after build."""
    cfg=policy(version)
    require(cfg.ga_mode in ('legacy-ga036','signed-ga-v2') and COMMIT.fullmatch(commit) is not None,
            'stable GA policy and exact 40-character Git SHA required')
    key_raw=read_file(public_key,4096).strip()
    # Explicit raw Ed25519 key hex, never a private key or GitHub CI self-signer.
    require(re.fullmatch(rb'[0-9a-fA-F]{64}',key_raw) is not None,
            'trusted independently pinned operator key must contain 32 public bytes (hex)')
    raw=read_file(evidence/'approval.json')
    signature_hex=read_file(evidence/'approval.sig',256).strip()
    require(re.fullmatch(rb'[a-fA-F0-9]{128}',signature_hex) is not None,
            'missing canonical 64-byte Ed25519 approval signature')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_raw.decode())).verify(
            bytes.fromhex(signature_hex.decode()),cfg.signing_domain+raw)
    except InvalidSignature as exc:
        raise Blocked('operator signature invalid') from exc
    data=json.loads(raw,object_pairs_hook=object_pairs)
    require(isinstance(data,dict) and set(data)=={
        'schemaVersion','version','commit','issuedAtUtc','expiresAtUtc','targets'},
        'approval fields incomplete or unexpected')
    require(data['schemaVersion']==cfg.approval_schema and
            data['version']==version and data['commit']==commit,
            'approval is not for this release and exact commit')
    timestamp=now or datetime.now(timezone.utc)
    require(utc(data['issuedAtUtc'])<=timestamp<=utc(data['expiresAtUtc']) and
            (utc(data['expiresAtUtc'])-utc(data['issuedAtUtc'])).total_seconds()<=7*86400,
            'GA approval expired, future-dated, or valid too long')
    return data, raw, key_raw


def verify(bundle:Path, evidence:Path, public_key:Path, version:str, commit:str, *, now=None):
    cfg=policy(version)
    data, raw, key_raw=approval_data(evidence, public_key, version, commit, now=now)
    targets=data['targets']
    require(isinstance(targets,list) and len(targets)==6 and
            {row.get('target') for row in targets if isinstance(row,dict)}==set(TARGETS),
            'all six release targets must have independent approval; partial GA bundle prohibited')
    # Don't silently ship a seventh platform or a wrong architecture alias.
    require(bundle.is_dir() and not bundle.is_symlink(), 'real release staging directory required')
    # A release with an unlisted platform package is not an approved subset.
    permitted={name for target in TARGETS for name in paths(version,target)}
    # Backward-compatible composite packages also shipped by build-release.sh;
    # their corresponding x64/ARM64 payloads still require exact-byte approval.
    permitted.update({f'neverlauncher-desktop-{version}-windows-amd64.zip',
                      f'neverlauncher-desktop-{version}-macos-universal.zip'})
    for artifact in bundle.iterdir():
        name=artifact.name
        if (name.startswith('neverlauncher-desktop-windows-') or
            name.startswith('neverlauncher-desktop-linux-') or
            name.startswith('neverlauncher-desktop-macos-') or
            name.startswith('neverlauncher-linux-') or
            name.startswith(f'neverlauncher-desktop-{version}-windows-') or
            name.startswith(f'neverlauncher-desktop-{version}-macos-')):
            # Other shared/legacy platform outputs remain subject to the existing
            # release CLI; only matching architecture packages may enter GA.
            if name not in permitted and (name.endswith('.zip') or name.endswith('.tar.gz') or
                                          name.endswith('-riscv64') or name.endswith('-riscv64.exe')):
                raise Blocked('unapproved additional target artifact: '+name)
    records=[]
    for target in sorted(TARGETS):
        item=next(row for row in targets if row['target']==target)
        require(set(item)=={'target','status','binarySha256','packageSha256','checks'} and
                item['status']=='certified' and isinstance(item['checks'],dict) and
                set(item['checks'])==set(checks_for(version)),target+': incomplete GA target')
        binary_name, package_name=paths(version,target)
        binary=bundle/binary_name
        package=bundle/package_name
        for path in (binary,package):
            require(path.is_file() and not path.is_symlink() and path.stat().st_size>0,
                    target+': no real packaged executable or installer')
        for field,path in (('binarySha256',binary),('packageSha256',package)):
            require(SHA.fullmatch(item[field]) is not None and sha(path)==item[field],
                    target+': signed approval does not match exact shipping bytes: '+field)
        cycle_ids = set()
        for check in checks_for(version):
            meta=item['checks'][check]
            require(isinstance(meta,dict) and set(meta)=={'sha256'} and
                    isinstance(meta['sha256'],str) and SHA.fullmatch(meta['sha256']) is not None,
                    target+': missing independently approved '+check)
            trace_path=evidence/'targets'/target/(check+'.json')
            require(trace_path.resolve().is_relative_to(evidence.resolve()) and
                    not trace_path.parent.is_symlink(),target+': unsafe trace directory')
            trace=read_json(trace_path)
            require(sha(trace_path)==meta['sha256'],target+': changed trace '+check)
            if check in PLAYER_CHECKS_0400 and check in checks_for(version):
                verify_player_trace(trace,check,item,target,evidence)
                cycle_ids.add(trace['playerCycleId'])
            else:
                require(set(trace)=={'schemaVersion','version','commit','target','kind','status',
                                     'actualExecution','simulated','artifactSha256','executionId'},
                        target+': invalid trace fields '+check)
            require(trace['schemaVersion']==cfg.execution_schema and
                    trace['version']==version and trace['commit']==commit and
                    trace['target']==target and trace['kind']==check and
                    trace['status']=='passed' and trace['actualExecution'] is True and
                    trace['simulated'] is False and trace['artifactSha256']==item['binarySha256'] and
                    isinstance(trace['executionId'],str) and
                    re.fullmatch(r'[a-zA-Z0-9._:-]{8,128}',trace['executionId']),
                    target+': test does not attest actual approved binary: '+check)
        if PLAYER_CHECKS_0400[0] in checks_for(version):
            require(len(cycle_ids)==1, target+': unrelated player runs cannot be combined into a pass')
        records.append({'target':target,'binary':binary_name,'binarySha256':item['binarySha256'],
                        'package':package_name,'packageSha256':item['packageSha256'],
                        'checksPassed':len(checks_for(version))})
    return {'schemaVersion':cfg.receipt_schema,
            'version':version,'commit':commit,'status':'approved-for-release-signing',
            'approvalSha256':hashlib.sha256(raw).hexdigest(),
            'operatorPublicKeySha256':hashlib.sha256(bytes.fromhex(key_raw.decode())).hexdigest(),
            'targets':records}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--trusted-key',type=Path,required=True)
    parser.add_argument('--commit',required=True)
    parser.add_argument('--version',required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--preflight',action='store_true',help='verify signed identity before expensive build; NOT GA approval')
    args=parser.parse_args()
    if args.output:
        args.output.unlink(missing_ok=True)
    try:
        if args.preflight:
            approval_data(args.evidence,args.trusted_key,args.version,args.commit)
            print(f'{args.version}: signed operator identity preflight accepted; exact bytes NOT YET checked')
            return 0
        require(args.output is not None, 'required --output for exact-byte verification')
        require(args.bundle is not None, 'required --bundle for exact-byte verification')
        receipt=verify(args.bundle,args.evidence,args.trusted_key,args.version,args.commit)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    except (Blocked,OSError,ValueError,TypeError,KeyError,InvalidSignature) as exc:
        print(f'{args.version} GA BLOCKED: '+str(exc),file=sys.stderr)
        return 3
    print(f'{args.version}: all six exact-byte targets independently signed and approved')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
