#!/usr/bin/env python3
"""Выполнять нативные проверки ОС для финальных подготовленных подписанных пакетов, а не JSON-деклараций.

Запускать отдельно на поддерживаемых нативных машинах оператора Windows/macOS/Linux. Отчёт содержит
только реально выполненные проверки. Третий независимый оператор должен проверить переход от
неподписанных к подписанным байтам и отдельно подписать одобрение.
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
    TARGETS, RELEASE_VERSION, contract, visit_archive, require_path, sha256_file, atomic_json,
)


def call(argv: list[str]) -> None:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    if completed.returncode:
        raise ValueError(f'Нативный валидатор завершился ошибкой ({argv[0]}): {completed.stderr[-700:]} {completed.stdout[-700:]}')


def normalize_pe(unsigned: bytes, signed: bytes) -> None:
    """Проверить, что signtool лишь добавил WIN_CERTIFICATE и изменил метаданные PE.

    Временная метка подписи закономерно меняется, поэтому нужно сравнивать неизменённые страницы
    исполняемого файла, допуская отличия только в контрольной сумме, каталоге сертификатов и
    конечной выровненной таблице WIN_CERTIFICATE.
    """
    if len(unsigned)<512 or len(signed)<len(unsigned):
        raise ValueError('Преобразование PE при подписании обрезано')
    def offsets(payload):
        if payload[:2]!=b'MZ':raise ValueError('Недопустимый заголовок PE DOS')
        off=struct.unpack_from('<I',payload,0x3c)[0]
        if off+160>len(payload) or payload[off:off+4]!=b'PE\0\0':
            raise ValueError('Недопустимый заголовок подписи PE')
        return off+24+64,off+24+112+4*8
    ck_a,sec_a=offsets(unsigned);ck_b,sec_b=offsets(signed)
    if (ck_a,sec_a)!=(ck_b,sec_b):raise ValueError('Разметка PE изменилась при подписании')
    u=bytearray(unsigned);s=bytearray(signed)
    original_dir=struct.unpack_from('<II',u,sec_a)
    cert_off,cert_size=struct.unpack_from('<II',s,sec_b)
    if original_dir!=(0,0) or cert_off<len(u) or cert_off>len(u)+7 or cert_size<8 or cert_off+cert_size>len(s):
        raise ValueError('Недопустимое расположение сертификата подписи PE или его границы')
    for arr in (u,s):
        arr[ck_a:ck_a+4]=b'\0'*4
        arr[sec_a:sec_a+8]=b'\0'*8
    if u!=s[:len(u)] or any(s[len(u):cert_off]):
        raise ValueError('Подписант изменил байты исполняемого файла вне метаданных Authenticode')
    # Любые данные после сертификата требуют отдельного объявления и проверки.
    if cert_off+cert_size!=len(s):
        raise ValueError('Неподписанные дополнительные данные после сертификата Authenticode')


def native_report(target: str, unsigned: Path, signed_root: Path, *, release_cli: Path,
                  public_key: Path, trust_policy: Path, trust_state: Path) -> dict:
    if target not in TARGETS:
        raise ValueError('Целевая платформа отсутствует в контракте выпуска')
    plat,arch=target.split('-',1)
    expected_os={'windows':'Windows','darwin':'Darwin','linux':'Linux'}[plat]
    if platform.system()!=expected_os:
        raise ValueError(f'Для платформы {target} требуется нативный верификатор {expected_os}')
    file=contract()['targets'][target]
    unsigned_file=require_path(unsigned,file)
    visit_archive(unsigned_file,plat,arch)
    actual=verify_target(signed_root,target,file,RELEASE_VERSION)
    # Существующий скомпилированный CLI выпуска проверяет точный манифест, подпись
    # Ed25519 и политику доверия оператора. Нативные проверки не заменяют этот
    # барьер доверия.
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
                raise ValueError('Исполняемые байты пакета Linux изменились после фиксации неподписанного содержимого: '+name)
        actual_check='release-ed25519-and-digest-verified'
    elif plat=='windows':
        signtool=shutil.which('signtool.exe')
        powershell=shutil.which('pwsh.exe') or shutil.which('powershell.exe')
        if not signtool or not powershell:
            raise ValueError('Нативные средства проверки подписи Windows недоступны')
        with tempfile.TemporaryDirectory(prefix='launcher-authenticode-') as t:
            for name in binary_names:
                normalize_pe(unsigned_files[name],signed_files[name])
                path=Path(t)/name
                path.write_bytes(signed_files[name])
                call([signtool,'verify','/pa','/all','/v',str(path)])
                # Проверяйте доверенную Windows цепочку, а не флаг наличия таблицы
                # сертификатов.
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
            raise ValueError('Нативные проверки Gatekeeper/нотаризации macOS недоступны')
        with tempfile.TemporaryDirectory(prefix='launcher-codesign-') as t:
            app=Path(t)/'Launcher.app'
            # Проверяйте безопасность элементов перед нативной распаковкой; ditto
            # обязателен для сохранения метаданных ресурсов, необходимых codesign.
            read_archive(signed_root/file)
            call([ditto,'-xk',str(signed_root/file),t])
            if not app.is_dir():
                raise ValueError('В пакете macOS отсутствует извлечённый Launcher.app')
            call([codesign,'--verify','--deep','--strict','--verbose=2',str(app)])
            call([str(gatekeeper),'--assess','--type','execute','--verbose=2',str(app)])
            call([stapler,'stapler','validate',str(app)])
        # codesign изменяет команды загрузки и linkedit исполняемого Mach-O;
        # независимый оператор подписи должен проверить и это преобразование.
        actual_check='codesign-gatekeeper-and-notarization-verified'
    return {'schema':'neverlauncher.native-verification.v1','version':RELEASE_VERSION,
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
        print('ПРОВЕРКА НАТИВНОЙ ПОДПИСИ ЗАБЛОКИРОВАНА: '+str(exc),file=sys.stderr)
        return 2
    print(f'PASS: нативная подпись ОС проверена для фактического пакета {args.target}; независимый аудит преобразований по-прежнему требуется')
    return 0

if __name__=='__main__':raise SystemExit(main())
