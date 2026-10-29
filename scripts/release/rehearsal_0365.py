#!/usr/bin/env python3
"""Verify final six-platform packages against independently signed GA approval.

`certify` executes BEFORE release manifest signing. `dry-run` copies the signed
release to an isolated publication directory and invokes the real CLI publish
validator on the copied files; neither action uploads or promotes a release.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ga'))
from verified_targets import Blocked, TARGETS, paths, sha, verify, require
from release_policy import requires_rehearsal

SCHEMA = 'neverlauncher.release.rehearsal.v1'
SHA = re.compile('[a-f0-9]{64}\\Z')
MAX_ENTRIES = 25000
MAX_UNCOMPRESSED = 4 * 1024**3


def architecture(content: bytes, target: str) -> None:
    system, arch = target.split('-')
    if system == 'windows':
        require(len(content) >= 0x40 and content[:2] == b'MZ', 'not a Windows executable')
        offset = struct.unpack_from('<I', content, 0x3c)[0]
        require(offset >= 0x40 and offset + 24 <= len(content) and
                content[offset:offset+4] == b'PE\0\0', 'bad PE header')
        actual = struct.unpack_from('<H', content, offset+4)[0]
        require(actual == {'x64': 0x8664, 'arm64': 0xaa64}[arch], 'wrong PE architecture')
        # IMAGE_DIRECTORY_ENTRY_SECURITY contains the Authenticode certificate table.
        # Its presence is NOT a chain-of-trust verification: the native Windows
        # signer/OS checks this and signs its result in the independent GA traces.
        opt = offset + 24
        magic = struct.unpack_from('<H', content, opt)[0]
        require(magic == 0x20b and opt + 144 <= len(content), 'PE32+ required')
        cert_offset, cert_size = struct.unpack_from('<II', content, opt + 112 + 4*8)
        require(cert_offset > 0 and cert_size >= 8 and cert_offset + cert_size <= len(content),
                'missing Authenticode certificate table')
    elif system == 'linux':
        require(len(content) >= 20 and content[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian required')
        require(struct.unpack_from('<H', content, 18)[0] == {'x64':62, 'arm64':183}[arch],
                'wrong ELF architecture')
    else:
        require(len(content) >= 32 and content[:4] == b'\xcf\xfa\xed\xfe', 'Mach-O 64-bit required')
        require(struct.unpack_from('<I', content, 4)[0] == {'x64':0x01000007,'arm64':0x0100000c}[arch],
                'wrong Mach-O architecture')
        ncmds = struct.unpack_from('<I', content, 16)[0]
        size = struct.unpack_from('<I', content, 20)[0]
        require(0 < ncmds <= 200 and 32+size <= len(content), 'bad Mach-O commands')
        cursor = 32
        signed = False
        for _ in range(ncmds):
            require(cursor+8 <= 32+size, 'bad Mach-O command size')
            cmd, length = struct.unpack_from('<II',content,cursor)
            require(length >= 8 and cursor+length <= 32+size, 'truncated Mach-O command')
            if cmd == 0x1d:
                require(length >= 16, 'truncated code-signing command')
                off, length_sig = struct.unpack_from('<II',content,cursor+8)
                require(off > 0 and length_sig > 0 and off+length_sig <= len(content),
                        'invalid Mach-O code signature')
                signed = True
            cursor += length
        require(signed, 'macOS code signature absent')


def safe_members(members: dict[str, bytes]) -> None:
    require(len(members) <= MAX_ENTRIES and sum(map(len, members.values())) <= MAX_UNCOMPRESSED,
            'archive size/entry limit')
    seen = set()
    for name in members:
        path = PurePosixPath(name)
        require(name not in seen and not name.startswith('/') and '\\' not in name and
                all(x not in ('', '.', '..') for x in name.split('/')) and
                not path.is_absolute(), 'duplicate or unsafe archive member: '+name)
        seen.add(name)


def unpack(path: Path) -> dict[str, bytes]:
    result = {}
    total = 0
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            for meta in archive.infolist():
                if meta.is_dir():
                    continue
                mode = (meta.external_attr >> 16) & 0o170000
                require(mode != 0o120000 and not meta.flag_bits & 1, 'archive symlink/encrypted entry')
                require(meta.filename not in result and meta.file_size <= MAX_UNCOMPRESSED,
                        'archive duplicate or oversized member')
                total += meta.file_size
                require(total <= MAX_UNCOMPRESSED and len(result) < MAX_ENTRIES, 'archive expansion limit')
                result[meta.filename] = archive.read(meta)
    else:
        require(path.name.endswith('.tar.gz'), 'unsupported installer format')
        with tarfile.open(path, mode='r:gz') as archive:
            for meta in archive:
                if meta.isdir():
                    continue
                require(meta.isfile() and meta.name not in result, 'unsafe TAR member')
                total += meta.size
                require(total <= MAX_UNCOMPRESSED and len(result) < MAX_ENTRIES, 'TAR expansion limit')
                reader = archive.extractfile(meta)
                require(reader is not None, 'unreadable TAR member')
                result[meta.name] = reader.read()
    safe_members(result)
    return result


def exact_package(bundle: Path, version: str, target: str) -> dict:
    system, arch = target.split('-')
    binary_name, package_name = paths(version,target)
    binary = bundle/binary_name
    package = bundle/package_name
    architecture(binary.read_bytes(),target)
    members = unpack(package)
    if system == 'windows':
        manifest_name = f'WINDOWS_PACKAGE_MANIFEST_{arch.upper()}.json'
        inner = 'WINDOWS_PACKAGE_MANIFEST.json'
        member = 'neverlauncher-desktop.exe'
    elif system == 'linux':
        manifest_name = f'LINUX_PACKAGE_MANIFEST_{arch.upper()}.json'
        inner = 'neverlauncher/LINUX_PACKAGE_MANIFEST.json'
        member = 'neverlauncher/neverlauncher-desktop'
    else:
        manifest_name = f'MACOS_PACKAGE_MANIFEST_{arch.upper()}.json'
        inner = 'NeverLauncher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json'
        member = 'NeverLauncher.app/Contents/MacOS/neverlauncher-desktop'
    require(inner in members and member in members, target+': missing packaged desktop/manifest')
    # On macOS the .app's embedded manifest is sealed by codesign before the
    # final notarized bytes are copied back to the root manifest. Therefore
    # compare its identity but use the finalized top-level hash manifest to
    # verify the exact ZIP payload, never demand equal pre-/post-sign hashes.
    if system == 'darwin':
        embedded = json.loads(members[inner],object_pairs_hook=_no_dupes)
        require(embedded.get('productVersion') == version and
                embedded.get('architecture') == arch, target+': embedded macOS manifest identity mismatch')
        manifest = json.loads((bundle/manifest_name).read_bytes(),object_pairs_hook=_no_dupes)
    else:
        require(sha(bundle/manifest_name) == hashlib.sha256(members[inner]).hexdigest(),
                target+': embedded package manifest differs from signed source')
        manifest = json.loads(members[inner],object_pairs_hook=_no_dupes)
    require(manifest.get('productVersion') == version and
            manifest.get('architecture') == arch and isinstance(manifest.get('artifacts'),list),
            target+': package manifest version/architecture mismatch')
    require(hashlib.sha256(members[member]).hexdigest() == sha(binary),
            target+': packaged executable differs from approved binary')
    seen = set()
    for row in manifest['artifacts']:
        name = row.get('packagePath') if system == 'linux' else (row.get('bundlePath') if system == 'darwin' else row.get('name'))
        require(isinstance(name,str) and name in members and name not in seen and
                isinstance(row.get('sha256'),str) and SHA.fullmatch(row['sha256']) is not None and
                row.get('size') == len(members[name]) and
                hashlib.sha256(members[name]).hexdigest() == row['sha256'],
                target+': missing/altered package component: '+str(name))
        seen.add(name)
        if row.get('component') == 'desktop-launcher':
            require(name == member, target+': unexpected desktop component mapping')
        if row.get('component') in ('desktop-launcher','runtime','guard','cli'):
            architecture(members[name],target)
        if system == 'windows':
            require(row.get('authenticodeStatus') == 'Valid' and
                    row.get('timestamped') is True and row.get('signtoolVerified') is True and
                    re.fullmatch(r'[a-fA-F0-9]{40}', str(row.get('signerThumbprint',''))) is not None,
                    target+': native Authenticode signing evidence missing')
        if system == 'darwin':
            require(row.get('codeSigned') is True and row.get('hardenedRuntime') is True and
                    re.fullmatch('[A-Z0-9]{10}',str(row.get('teamId',''))) is not None,
                    target+': native code-signing evidence missing')
    require(member in seen and len(seen) >= 4, target+': incomplete production package')
    if system in ('linux','windows'):
        require(('neverlauncher/COMPONENT_SET_SIGNATURE.json' if system=='linux' else 'COMPONENT_SET_SIGNATURE.json') in members,
                target+': missing component set signature')
    return {'target':target,'binary':binary_name,'binarySha256':sha(binary),
            'package':package_name,'packageSha256':sha(package),'packageMembers':len(members)}


def _no_dupes(pairs):
    obj = {}
    for key,value in pairs:
        require(key not in obj, 'duplicate JSON field '+key)
        obj[key] = value
    return obj


def current_run() -> tuple[str, str]:
    run_id = os.environ.get('NEVERLAUNCHER_RELEASE_RUN_ID') or os.environ.get('GITHUB_RUN_ID','')
    attempt = os.environ.get('NEVERLAUNCHER_RELEASE_RUN_ATTEMPT') or os.environ.get('GITHUB_RUN_ATTEMPT','')
    require(re.fullmatch(r'[1-9][0-9]{0,29}',run_id) is not None and
            re.fullmatch(r'[1-9][0-9]{0,9}',attempt) is not None,
            'production rehearsal requires the exact CI run ID and attempt')
    return run_id, attempt


def certify(bundle:Path,evidence:Path,key:Path,version:str,commit:str) -> dict:
    run_id, run_attempt = current_run()
    receipt = verify(bundle,evidence,key,version,commit)
    require(requires_rehearsal(version), 'rehearsal requires 0.36.5 or newer')
    allowed = {name for target in TARGETS for name in paths(version,target)}
    allowed.update({f'neverlauncher-desktop-{version}-windows-amd64.zip',
                    f'neverlauncher-desktop-{version}-macos-universal.zip',
                    'neverlauncher-desktop-windows-amd64.exe',
                    'neverlauncher-desktop-linux-amd64',
                    'neverlauncher-desktop-macos-universal'})
    for entry in bundle.iterdir():
        name = entry.name
        target_shaped = (name.startswith(('neverlauncher-desktop-windows-',
                                         'neverlauncher-desktop-linux-',
                                         'neverlauncher-desktop-macos-')) or
                         name.startswith((f'neverlauncher-desktop-{version}-windows-',
                                          f'neverlauncher-desktop-{version}-macos-',
                                          f'neverlauncher-desktop-{version}-linux-',
                                          'neverlauncher-linux-')))
        if target_shaped and name not in allowed:
            raise Blocked('unapproved extra platform target: '+name)
    rows = [exact_package(bundle,version,target) for target in sorted(TARGETS)]
    require([(r['target'],r['binarySha256'],r['packageSha256']) for r in rows] ==
            [(r['target'],r['binarySha256'],r['packageSha256']) for r in receipt['targets']],
            'rehearsal records are not the signed GA target set')
    return {'schemaVersion':SCHEMA,'version':version,'commit':commit,
            'runId':run_id,'runAttempt':run_attempt,
            'status':'package-and-ga-verified', 'gaApprovalSha256':receipt['approvalSha256'],
            'targets':rows}


def dry_run(bundle:Path,cli:Path,public_key:Path,trust_policy:Path,trust_state:Path,
            evidence:Path,key:Path,version:str,commit:str,stage:Path) -> dict:
    require(stage.resolve() != bundle.resolve() and not stage.exists(),
            'dry-run staging must be a fresh distinct directory')
    receipt = certify(bundle,evidence,key,version,commit)
    report = json.loads((bundle/'RELEASE_REHEARSAL_0365.json').read_bytes(),object_pairs_hook=_no_dupes)
    require(report == receipt, 'signed release rehearsal receipt is stale or mismatched')
    sums = (bundle/'SHA256SUMS').read_text(encoding='utf-8')
    expected = {}
    for line in sums.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        require(len(fields)==2 and SHA.fullmatch(fields[0]) is not None and
                fields[1] not in expected and '/' not in fields[1] and '\\' not in fields[1],
                'invalid SHA256SUMS entry')
        expected[fields[1]]=fields[0]
    files = [p for p in bundle.iterdir() if p.is_file() and not p.is_symlink()]
    require(set(expected) == {p.name for p in files} - {'SHA256SUMS','SHA256SUMS.sig'},
            'missing/unsigned/extra final release file')
    # Never use a shared/production trust-state as writable dry-run state.
    independent_trust_state = stage.parent/(stage.name+'-trust-state.json')
    if trust_state.is_file():
        shutil.copy2(trust_state, independent_trust_state)
    stage.mkdir(parents=True)
    try:
        for source in files:
            target=stage/source.name
            with source.open('rb') as read, target.open('xb') as write:
                shutil.copyfileobj(read,write,1024*1024)
            require(sha(target)==sha(source),'dry-run transport changed bytes '+source.name)
            if source.name in expected:
                require(sha(target)==expected[source.name], 'SHA256SUMS mismatch '+source.name)
        copied_cli = stage/cli.name
        require(copied_cli.is_file(), 'publication dry-run is missing its release CLI')
        copied_cli.chmod(cli.stat().st_mode & 0o777)
        argv=[str(copied_cli.resolve()), 'release','publish-check', str(stage),
              '--public-key',str(public_key.resolve()),'--trust-state',str(independent_trust_state.resolve()),
              '--trust-policy',str(trust_policy.resolve())]
        finished=subprocess.run(argv,capture_output=True,text=True,timeout=240)
        require(finished.returncode==0, 'staged release publish-check refused: '+
                (finished.stderr or finished.stdout)[-900:])
        return {'schemaVersion':'neverlauncher.release.publication-dry-run.v1',
                'version':version,'commit':commit,'status':'passed',
                'runId':receipt['runId'],'runAttempt':receipt['runAttempt'],
                'published':False,'filesCopied':len(files),
                'sha256sumsSha256':sha(stage/'SHA256SUMS'),
                'gaApprovalSha256':receipt['gaApprovalSha256']}
    finally:
        shutil.rmtree(stage,ignore_errors=True)
        independent_trust_state.unlink(missing_ok=True)


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('certify','dry-run'))
    for field in ('bundle','evidence','trusted-key','version','commit','output'):
        p.add_argument('--'+field,required=True)
    for field in ('cli','public-key','trust-policy','trust-state','stage'):
        p.add_argument('--'+field)
    a=p.parse_args()
    output=Path(a.output)
    output.unlink(missing_ok=True)
    try:
        base=dict(bundle=Path(a.bundle),evidence=Path(a.evidence),key=Path(a.trusted_key),
                  version=a.version,commit=a.commit)
        if a.action=='certify':
            result=certify(**base)
        else:
            require(all((a.cli,a.public_key,a.trust_policy,a.trust_state,a.stage)),
                    'dry-run requires cli, public key, trust policy, trust state and staging directory')
            result=dry_run(base['bundle'],Path(a.cli),Path(a.public_key),Path(a.trust_policy),
                           Path(a.trust_state),base['evidence'],base['key'],base['version'],
                           base['commit'],Path(a.stage))
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(a.action+': '+result['status'])
        return 0
    except (Blocked,OSError,ValueError,TypeError,KeyError,IndexError,struct.error,
            zipfile.BadZipFile,tarfile.TarError,subprocess.TimeoutExpired) as exc:
        print('release rehearsal BLOCKED: '+str(exc),file=sys.stderr)
        return 3

if __name__=='__main__':
    raise SystemExit(main())
