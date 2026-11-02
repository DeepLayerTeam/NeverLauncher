#!/usr/bin/env python3
"""Run native OS checks on final staged signed packages, not JSON declarations.

Invoke separately on supported Windows/macOS/Linux native operator machines.
This only reports the actual checks completed. A third independent operator
must audit the unsigned->signed transformation and sign its approval separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

from delivery_verify_0462 import EXPECTED, read_archive, verify_target
from reproducible_0470 import (
    TARGETS, contract, visit_archive, require_path, sha256_file, atomic_json,
)


def call(argv: list[str]) -> None:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    if completed.returncode:
        raise ValueError(f'native validator failed ({argv[0]}): {completed.stderr[-700:]} {completed.stdout[-700:]}')


def normalize_pe(unsigned: bytes, signed: bytes) -> None:
    """Verify signtool only appended WIN_CERTIFICATE and touched PE metadata.

    The timestamped signature naturally changes each time, so compare the
    unmodified executable pages and allow only the checksum, certificate
    directory and the trailing aligned WIN_CERTIFICATE table to differ.
    """
    if len(unsigned)<512 or len(signed)<len(unsigned):
        raise ValueError('truncated PE signing transformation')
    def offsets(payload):
        if payload[:2]!=b'MZ':raise ValueError('invalid PE DOS header')
        off=struct.unpack_from('<I',payload,0x3c)[0]
        if off+160>len(payload) or payload[off:off+4]!=b'PE\0\0':
            raise ValueError('invalid PE signing header')
        return off+24+64,off+24+112+4*8
    ck_a,sec_a=offsets(unsigned);ck_b,sec_b=offsets(signed)
    if (ck_a,sec_a)!=(ck_b,sec_b):raise ValueError('PE layout changed during signing')
    u=bytearray(unsigned);s=bytearray(signed)
    original_dir=struct.unpack_from('<II',u,sec_a)
    cert_off,cert_size=struct.unpack_from('<II',s,sec_b)
    if original_dir!=(0,0) or cert_off<len(u) or cert_off>len(u)+7 or cert_size<8 or cert_off+cert_size>len(s):
        raise ValueError('PE signing certificate placement/bounds invalid')
    for arr in (u,s):
        arr[ck_a:ck_a+4]=b'\0'*4
        arr[sec_a:sec_a+8]=b'\0'*8
    if u!=s[:len(u)] or any(s[len(u):cert_off]):
        raise ValueError('signer altered executable bytes outside Authenticode metadata')
    # Any post-certificate data needs separate declaration/verification.
    if cert_off+cert_size!=len(s):
        raise ValueError('unsigned trailing data after Authenticode certificate')


def native_report(target: str, unsigned: Path, signed_root: Path, *, release_cli: Path,
                  public_key: Path, trust_policy: Path, trust_state: Path) -> dict:
    if target not in TARGETS:
        raise ValueError('target not in release contract')
    plat,arch=target.split('-',1)
    expected_os={'windows':'Windows','darwin':'Darwin','linux':'Linux'}[plat]
    if platform.system()!=expected_os:
        raise ValueError(f'{target} requires native {expected_os} verifier')
    file=contract()['targets'][target]
    unsigned_file=require_path(unsigned,file)
    visit_archive(unsigned_file,plat,arch)
    actual=verify_target(signed_root,target,file,'0.47.0')
    # Existing compiled release CLI checks exact manifest, signed Ed25519 and
    # operator trust policy. Native checks do not replace that trust gate.
    call([str(release_cli),'release','verify',str(signed_root),
          '--public-key',str(public_key),'--trust-state',str(trust_state),
          '--trust-policy',str(trust_policy)])
    binary_names=[('launcher/' if plat=='linux' else 'Launcher.app/' if plat=='darwin' else '')+x
                  for x in EXPECTED[plat]]
    unsigned_files=read_archive(unsigned_file)
    signed_files=read_archive(signed_root/file)
    actual_check=''
    if plat=='linux':
        for name in binary_names:
            if unsigned_files[name]!=signed_files[name]:
                raise ValueError('Linux package changed executable bytes after unsigned capture: '+name)
        actual_check='release-ed25519-and-digest-verified'
    elif plat=='windows':
        signtool=shutil.which('signtool.exe')
        powershell=shutil.which('pwsh.exe') or shutil.which('powershell.exe')
        if not signtool or not powershell:
            raise ValueError('native Windows signing validators unavailable')
        with tempfile.TemporaryDirectory(prefix='launcher-authenticode-') as t:
            for name in binary_names:
                normalize_pe(unsigned_files[name],signed_files[name])
                path=Path(t)/name
                path.write_bytes(signed_files[name])
                call([signtool,'verify','/pa','/all','/v',str(path)])
                # Validate Windows-trusted chain, not a certificate-table flag.
                powershell_script=(
                    'param([string]$File) '
                    '$s=Get-AuthenticodeSignature -FilePath $File; '
                    'if($s.Status -ne "Valid" -or $null -eq $s.SignerCertificate '
                    '-or $null -eq $s.TimeStamperCertificate){exit 2}'
                )
                call([powershell,'-NoProfile','-NonInteractive','-Command',powershell_script,'-File',str(path)])
        actual_check='authenticode-chain-and-timestamp-verified'
    else:
        codesign=shutil.which('codesign');ditto=shutil.which('ditto')
        stapler=shutil.which('xcrun')
        gatekeeper=Path('/usr/sbin/spctl')
        if not codesign or not ditto or not stapler or not gatekeeper.is_file():
            raise ValueError('macOS native Gatekeeper/notary validators unavailable')
        with tempfile.TemporaryDirectory(prefix='launcher-codesign-') as t:
            app=Path(t)/'Launcher.app'
            # Check member safety before native extraction; ditto is required
            # to retain the resource metadata needed by codesign.
            read_archive(signed_root/file)
            call([ditto,'-xk',str(signed_root/file),t])
            if not app.is_dir():
                raise ValueError('macOS package has no extracted Launcher.app')
            call([codesign,'--verify','--deep','--strict','--verbose=2',str(app)])
            call([str(gatekeeper),'--assess','--type','execute','--verbose=2',str(app)])
            call([stapler,'stapler','validate',str(app)])
        # codesign modifies Mach-O executable load commands/linkedit; the
        # independent signing operator must audit the transformation too.
        actual_check='codesign-gatekeeper-and-notarization-verified'
    return {'schema':'neverlauncher.native-verification.v1','version':'0.47.0',
            'target':target,'unsignedSha256':sha256_file(unsigned_file),
            'signedSha256':actual['sha256'], 'nativeCheck':actual_check,
            'releaseManifestSha256':sha256_file(signed_root/'RELEASE_MANIFEST.json'),
            'nativeOS':platform.system(),'status':'native-verified-transform-audit-separate'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',choices=sorted(TARGETS),required=True)
    p.add_argument('--unsigned-dir',type=Path,required=True)
    p.add_argument('--signed-dir',type=Path,required=True)
    p.add_argument('--release-cli',type=Path,required=True)
    p.add_argument('--public-key',type=Path,required=True)
    p.add_argument('--trust-policy',type=Path,required=True)
    p.add_argument('--trust-state',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    try:
        report=native_report(args.target,args.unsigned_dir,args.signed_dir,release_cli=args.release_cli,
                             public_key=args.public_key,trust_policy=args.trust_policy,trust_state=args.trust_state)
        atomic_json(args.out,report)
    except (ValueError,OSError,subprocess.TimeoutExpired,KeyError,zipfile.BadZipFile) as exc:
        print('NATIVE SIGNING BLOCKED: '+str(exc),file=sys.stderr)
        return 2
    print(f'PASS: OS-native signing verified for actual {args.target} package; independent transform audit remains required')
    return 0

if __name__=='__main__':raise SystemExit(main())
