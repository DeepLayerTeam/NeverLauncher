#!/usr/bin/env python3
"""Проверить настоящие бинарные файлы поставки для шести целей и манифесты их пакетов.

Это дополнительный шлюз целостности бинарных файлов, *не* замена проверкам ОС Authenticode/codesign,
независимому одобрению оператора или E2E-тестам.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import zipfile

from check_payload_0461 import inventory, inspect, secure_name

EXPECTED = {
    'windows': ('launcher-desktop.exe','guard.exe','runtime.exe','guard-sensor.dll','launcher-cli.exe'),
    'linux': ('launcher-cli','launcher-api','launcher-desktop','guard','runtime'),
    'darwin': ('Contents/MacOS/launcher-desktop','Contents/Helpers/guard',
               'Contents/Helpers/runtime','Contents/Helpers/launcher-cli'),
}
ARCH = {'x64': {'elf':62, 'pe':0x8664, 'macho':0x01000007},
        'arm64': {'elf':183, 'pe':0xaa64, 'macho':0x0100000c}}
MAX_MEMBER = 1024 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exe_arch(data: bytes, platform: str, arch: str) -> None:
    if len(data) < 64:
        raise ValueError('Исполняемый файл обрезан')
    if platform == 'linux':
        if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1 or struct.unpack_from('<H',data,18)[0] != ARCH[arch]['elf']:
            raise ValueError('invalid ELF64 target architecture')
    elif platform == 'windows':
        if data[:2] != b'MZ':raise ValueError('invalid PE DOS header')
        off=struct.unpack_from('<I',data,0x3c)[0]
        if off > len(data)-24 or data[off:off+4] != b'PE\0\0' or struct.unpack_from('<H',data,off+4)[0] != ARCH[arch]['pe']:
            raise ValueError('invalid PE target architecture')
        optional=off+24
        if len(data) < optional+120 or struct.unpack_from('<H',data,optional)[0] != 0x20b:
            raise ValueError('missing PE32+ optional header')
        # Каталог данных PE номер 4 содержит сертификат Authenticode, но не
        # доказательство доверия ему.
        cert_off,cert_size=struct.unpack_from('<II',data,optional+112+4*8)
        if cert_off <= 0 or cert_size < 8 or cert_off+cert_size > len(data):
            raise ValueError('no Authenticode certificate table')
    else:
        if data[:4] != b'\xcf\xfa\xed\xfe' or struct.unpack_from('<I',data,4)[0] != ARCH[arch]['macho']:
            raise ValueError('invalid thin Mach-O target architecture')
        ncmds,sz=struct.unpack_from('<II',data,16)
        if not (0 < ncmds < 2048 and 0 < sz <= len(data)-32):
            raise ValueError('malformed Mach-O load commands')
        offset=32; code_signed=False
        for _ in range(ncmds):
            if offset+8 > 32+sz:raise ValueError('Обрезана команда загрузки Mach-O')
            cmd,length=struct.unpack_from('<II',data,offset)
            if length < 8 or offset+length > 32+sz:raise ValueError('malformed Mach-O load command size')
            if cmd == 0x1d:
                if length < 16:raise ValueError('truncated LC_CODE_SIGNATURE')
                start, size=struct.unpack_from('<II',data,offset+8)
                if size <= 0 or start <= 0 or start+size > len(data):raise ValueError('invalid Mach-O signature bounds')
                code_signed=True
            offset+=length
        if not code_signed:raise ValueError('Mach-O lacks LC_CODE_SIGNATURE')


def read_archive(path: Path) -> dict[str, bytes]:
    result={}
    count=0
    if path.suffix=='.zip':
        with zipfile.ZipFile(path) as z:
            for item in z.infolist():
                secure_name(item.filename)
                mode=(item.external_attr>>16)&0o170000
                if mode not in (0,stat.S_IFREG,stat.S_IFDIR):raise ValueError('archive link/special file not supported')
                if item.is_dir():continue
                if item.file_size > MAX_MEMBER:raise ValueError('oversize archive entry')
                if item.filename in result:raise ValueError('Повторяющийся элемент архива')
                with z.open(item) as f:
                    value=f.read(MAX_MEMBER+1)
                if len(value)>MAX_MEMBER:raise ValueError('expanded ZIP entry exceeds size limit')
                result[item.filename]=value
                count+=1
    else:
        with tarfile.open(path,'r:gz') as t:
            for item in t:
                secure_name(item.name)
                if item.isdir():continue
                if not item.isfile():raise ValueError('archive link/special file not supported')
                if item.size>MAX_MEMBER:raise ValueError('oversize TAR entry')
                if item.name in result:raise ValueError('Повторяющийся элемент архива')
                stream=t.extractfile(item)
                if stream is None: raise ValueError('unreadable TAR entry')
                with stream as f:value=f.read(MAX_MEMBER+1)
                if len(value)>MAX_MEMBER:raise ValueError('expanded TAR entry exceeds size limit')
                result[item.name]=value
                count+=1
    if not count:raise ValueError('empty archive')
    return result


def verify_target(bundle: Path, target: str, name: str, version: str) -> dict:
    platform,arch=target.split('-',1)
    path=bundle/name
    sha,size=inspect(path)
    files=read_archive(path)
    prefix = 'launcher/' if platform=='linux' else 'Launcher.app/' if platform=='darwin' else ''
    for binary in EXPECTED[platform]:
        key=prefix+binary
        if key not in files:raise ValueError(f'{name}: missing executable {key}')
        exe_arch(files[key],platform,arch)
    if platform=='windows':
        manifest_name='WINDOWS_PACKAGE_MANIFEST.json'
        manifest_key=manifest_name
    elif platform=='linux':
        manifest_name='LINUX_PACKAGE_MANIFEST.json'
        manifest_key='launcher/'+manifest_name
    else:
        manifest_name=f'MACOS_PACKAGE_MANIFEST_{arch.upper()}.json'
        manifest_key=None
    if manifest_key:
        if manifest_key not in files:raise ValueError(f'{name}: embedded package manifest missing')
        manifest=json.loads(files[manifest_key])
        rows=manifest.get('artifacts')
        if not isinstance(rows,list) or len(rows)<len(EXPECTED[platform]):
            raise ValueError(f'{name}: incomplete package artifact records')
        if manifest.get('productVersion')!=version:
            raise ValueError(f'{name}: wrong embedded version')
        if platform=='windows':
            if manifest.get('architecture')!=arch or manifest.get('authenticodeRequired') is not True or manifest.get('signingMode')!='authenticode-rfc3161':
                raise ValueError(f'{name}: not Windows signed production delivery')
        else:
            if manifest.get('architecture')!=arch: raise ValueError(f'{name}: wrong target architecture')
        visited=set()
        for row in rows:
            key=(row.get('packagePath') if platform=='linux' else row.get('name'))
            if not isinstance(key,str) or key not in files or key in visited:
                raise ValueError(f'{name}: invalid/duplicated manifest component {key}')
            visited.add(key)
            data=files[key]
            if (row.get('sha256')!=digest(data) or row.get('size')!=len(data)):
                raise ValueError(f'{name}: wrong component hash/size {key}')
    else:
        # Финальное подписанное приложение macOS содержит запечатанные ресурсы, а
        # корневой манифест окончательно оформлен после codesign/notarization.
        # Проверяйте его по точным исполняемым байтам в архиве.
        root=bundle/manifest_name
        if not root.is_file() or root.is_symlink():raise ValueError(f'{name}: missing finalized macOS package manifest')
        manifest=json.loads(root.read_bytes())
        if manifest.get('productVersion')!=version or manifest.get('architecture')!=arch or manifest.get('hashBindingMode')!='final-artifact-sha256':
            raise ValueError(f'{name}: wrong macOS finalized package manifest')
        rows=manifest.get('artifacts')
        if not isinstance(rows,list) or len(rows)!=len(EXPECTED['darwin']):raise ValueError(f'{name}: incomplete macOS package manifest')
        visited=set()
        for row in rows:
            key=row.get('bundlePath')
            if not isinstance(key,str) or key not in files or key in visited:
                raise ValueError(f'{name}: missing/duplicate macOS manifest binary {key}')
            visited.add(key)
            data=files[key]
            if row.get('sha256')!=digest(data) or row.get('size')!=len(data):
                raise ValueError(f'{name}: macOS final package executable mismatch {key}')
    return {'file':name,'sha256':sha,'bytes':size,'executablesVerified':len(EXPECTED[platform]),
            'packageManifest':manifest_name,'packageManifestVerified':True}


def verify_bundle(bundle: Path, release_manifest: bool=False) -> dict:
    initial=inventory(bundle)
    version=initial['version']
    targets={target:verify_target(bundle,target,row['file'],version) for target,row in initial['targets'].items()}
    report={'schema':'neverlauncher.delivery-verified.v1','version':version,
            'status':'binary-integrity-verified-signatures-and-E2E-separate','targets':targets}
    if release_manifest:
        raw=json.loads((bundle/'RELEASE_MANIFEST.json').read_text())
        if raw.get('version')!=version:raise ValueError('RELEASE_MANIFEST version mismatch')
        entries=raw.get('artifacts')
        if not isinstance(entries,list):raise ValueError('RELEASE_MANIFEST lacks artifacts')
        byname={r['name']:r for r in entries if isinstance(r,dict) and isinstance(r.get('name'),str)}
        if len(byname)!=len(entries):raise ValueError('duplicate release manifest artifact names')
        for target,row in targets.items():
            entry=byname.get(row['file'])
            if not entry or entry.get('status')!='present' or entry.get('required') is not True or entry.get('sha256','').lower()!=row['sha256'] or entry.get('size',entry.get('bytes'))!=row['bytes']:
                raise ValueError(f'{target}: actual package missing/mismatched in RELEASE_MANIFEST')
        # Проверенный реестр шести пакетов является обязательной частью выпуска и сам
        # должен описывать те же измеренные финальные байты.
        ledger_path=bundle/'DELIVERY_VERIFIED_0462.json'
        if not ledger_path.is_file() or ledger_path.is_symlink():
            raise ValueError('missing delivery integrity inventory')
        ledger=json.loads(ledger_path.read_text(encoding='utf-8'))
        if (ledger.get('schema')!='neverlauncher.delivery-verified.v1'
                or ledger.get('version')!=version
                or ledger.get('targets')!=targets):
            raise ValueError('stale/forged delivery integrity inventory')
        entry=byname.get(ledger_path.name)
        if not entry or entry.get('required') is not True or entry.get('status')!='present' or entry.get('sha256')!=digest(ledger_path.read_bytes()):
            raise ValueError('unbound delivery integrity inventory')
        report['releaseManifestMatchesAssets']=True
    return report


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--release-manifest',action='store_true')
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    try:
        report=verify_bundle(a.bundle,a.release_manifest)
        raw=json.dumps(report,sort_keys=True,indent=2)+'\n'
        if a.out:
            a.out.write_text(raw,encoding='utf-8')
        else:print(raw)
        return 0
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError,zipfile.BadZipFile,tarfile.TarError) as exc:
        print(f'DELIVERY BLOCKED: {exc}',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
