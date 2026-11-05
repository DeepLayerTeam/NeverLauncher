#!/usr/bin/env python3
"""Проверка воспроизводимой поставки NeverLauncher: реальные байты архивов, а не заявления.

capture: независимо изучать *настоящие* неподписанные артефакты (шесть целей и каждый элемент).
compare: независимо аутентифицировать и повторно прочитать артефакты двух сборочных узлов; нулевое
расхождение.
link: требовать внешне подписанную нативную приёмку ОС для точных финальных подписанных установщиков
и их связи с успешно сопоставленными неподписанными байтами.

Ни сбор свидетельств, ни наличие подписи Ed25519 не доказывают корректность подписи ОС или запуска
Minecraft. Нативный подписывающий компонент/оператор должен выполнить проверки и подписать одобрение
точных байтов; отсутствие свидетельств всегда означает отказ.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import zipfile
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from delivery_verify_0462 import ARCH, EXPECTED, verify_bundle
from check_payload_0461 import secure_name

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / 'reproducibility/primary-payload.json'
BASELINE_PATH = ROOT / 'reproducibility/baseline.json'
RELEASE_VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
HEX = re.compile(r'^[a-f0-9]{40,64}$')
MAX_TOTAL_BYTES = 3 * 1024**3
MAX_FILE_BYTES = 1024**3
MAX_MEMBERS = 50000
TARGETS = frozenset(('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'))


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Объект не является обычным файлом: {path}')
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        for part in iter(lambda: fh.read(1024*1024), b''):
            digest.update(part)
    return digest.hexdigest()


def canonical(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':'))+'\n').encode('utf8')


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    try:
        with tmp.open('xb') as fh:
            fh.write(canonical(data))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def load_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16*1024*1024:
        raise ValueError(f'JSON отсутствует или не является доверенным: {path}')
    obj = json.loads(path.read_bytes())
    if not isinstance(obj, dict):
        raise ValueError('Корневой элемент JSON должен быть объектом')
    return obj


def contract() -> dict:
    data = load_json(CONTRACT_PATH)
    if data.get('schema') != 'neverlauncher.primary-payload.v1' or data.get('version') != RELEASE_VERSION:
        raise ValueError('Некорректный контракт основного набора файлов')
    if data.get('targets', {}).keys() != TARGETS:
        raise ValueError('Неполный контракт набора файлов для шести платформ')
    for target, filename in data['targets'].items():
        if not isinstance(filename, str) or filename != Path(filename).name or '/' in filename or '\\' in filename:
            raise ValueError(f'Небезопасное имя целевого файла: {target}')
    return data


def require_path(root: Path, name: str) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Каталог артефактов отсутствует или небезопасен')
    path = root / name
    if path.is_symlink() or not path.is_file() or path.stat().st_size < 128:
        raise ValueError(f'Артефакт отсутствует или не предназначен для промышленной эксплуатации: {name}')
    return path


def inspect_exe(head: bytes, platform: str, architecture: str) -> None:
    """Проверять заголовки недоверенных неподписанных исполняемых файлов без системных инструментов сборки ОС."""
    if len(head) < 256:
        raise ValueError('Исполняемый файл обрезан')
    if platform == 'linux':
        if head[:4] != b'\x7fELF' or head[4:6] != b'\x02\x01' or struct.unpack_from('<H', head, 18)[0] != ARCH[architecture]['elf']:
            raise ValueError('Не совпадает архитектура неподписанного ELF64')
    elif platform == 'windows':
        if head[:2] != b'MZ':
            raise ValueError('В неподписанном PE отсутствует заголовок DOS')
        offset = struct.unpack_from('<I', head, 0x3c)[0]
        if offset > len(head) - 160 or head[offset:offset+4] != b'PE\0\0':
            raise ValueError('invalid PE header')
        if struct.unpack_from('<H', head, offset+4)[0] != ARCH[architecture]['pe'] or struct.unpack_from('<H',head,offset+24)[0] != 0x20b:
            raise ValueError('Не совпадает архитектура неподписанного PE64')
        cert_off, cert_size = struct.unpack_from('<II',head,offset+24+112+4*8)
        if cert_off or cert_size:
            raise ValueError('В неподписанном PE неожиданно присутствует каталог сертификатов')
    else:
        if head[:4] != b'\xcf\xfa\xed\xfe' or struct.unpack_from('<I',head,4)[0] != ARCH[architecture]['macho']:
            raise ValueError('Не совпадает архитектура неподписанного Mach-O')
        ncmds, cmd_size = struct.unpack_from('<II',head,16)
        if not (0 < ncmds < 2048 and 0 < cmd_size <= len(head)-32):
            raise ValueError('Некорректные команды загрузки Mach-O')
        off = 32
        for _ in range(ncmds):
            if off+8 > 32+cmd_size:
                raise ValueError('Обрезана команда загрузки Mach-O')
            cmd, length = struct.unpack_from('<II',head,off)
            if length < 8 or off+length > 32+cmd_size:
                raise ValueError('Некорректная команда загрузки Mach-O')
            if cmd == 0x1d:
                raise ValueError('Неподписанный Mach-O содержит цифровую подпись кода')
            off += length


def visit_archive(path: Path, platform: str, architecture: str) -> dict:
    """Хешировать каждый элемент архива; отклонять ссылки, дубликаты и распаковку без ограничения объёма."""
    names = set()
    entries = {}
    total = 0
    expected = {('launcher/' if platform == 'linux' else 'Launcher.app/' if platform == 'darwin' else '') + key for key in EXPECTED[platform]}

    def visit(name: str, size: int, mode: int, src) -> None:
        nonlocal total
        secure_name(name)
        if name in names:
            raise ValueError('Повторяющийся элемент архива: ' + name)
        names.add(name)
        if len(names) > MAX_MEMBERS or size < 0 or size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
            raise ValueError('Превышен лимит распаковки архива')
        total += size
        digest = hashlib.sha256()
        size_read = 0
        head = bytearray()
        while True:
            piece = src.read(1024*1024)
            if not piece:
                break
            if len(head) < 65536:
                head.extend(piece[:65536-len(head)])
            size_read += len(piece)
            if size_read > size:
                raise ValueError('Размер элемента архива больше заявленного')
            digest.update(piece)
        if size_read != size:
            raise ValueError('Неполный элемент архива')
        if name in expected:
            inspect_exe(bytes(head), platform, architecture)
            if platform == 'linux' and not (mode & 0o111):
                raise ValueError('У ELF отсутствует разрешение на выполнение: ' + name)
        entries[name] = {'sha256':digest.hexdigest(),'size':size_read,'mode':mode & 0o777}

    if path.name.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                secure_name(item.filename)
                kind = (item.external_attr >> 16) & 0o170000
                if kind not in (0, stat.S_IFDIR, stat.S_IFREG):
                    raise ValueError('В архиве запрещены ссылки и специальные устройства: '+item.filename)
                if item.is_dir():
                    continue
                with archive.open(item) as handle:
                    visit(item.filename, item.file_size, (item.external_attr >> 16) & 0o777, handle)
    elif path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'r:gz') as archive:
            for item in archive:
                secure_name(item.name)
                if item.isdir():
                    continue
                if not item.isfile():
                    raise ValueError('В архиве запрещены ссылки и специальные устройства: '+item.name)
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError('Отсутствует поток данных архива')
                with stream:
                    visit(item.name, item.size, item.mode, stream)
    else:
        raise ValueError('Неизвестный формат неподписанного архива')
    if not expected.issubset(entries):
        raise ValueError('Отсутствуют неподписанные исполняемые файлы: ' + ', '.join(sorted(expected - entries)))
    return dict(sorted(entries.items()))


def inspect_builder(bundle: Path) -> dict:
    output = {}
    for target, file in sorted(contract()['targets'].items()):
        path = require_path(bundle, file)
        platform, arch = target.split('-',1)
        output[target] = {'file':file,'sha256':sha256_file(path),'size':path.stat().st_size,
                          'members':visit_archive(path,platform,arch)}
    return output


def capture(bundle: Path, *, builder: str, runner: str, commit: str) -> dict:
    if not HEX.fullmatch(commit):
        raise ValueError('Некорректный полный идентификатор исходного коммита')
    if not builder.strip() or not runner.strip() or len(builder)>128 or len(runner)>128:
        raise ValueError('Идентификатор сборщика отсутствует или небезопасен')
    if not BASELINE_PATH.is_file():
        raise ValueError('Отсутствует закреплённый базовый набор входных данных')
    baseline = load_json(BASELINE_PATH)
    if baseline.get('release') != RELEASE_VERSION:
        raise ValueError('Неожиданная версия базового набора')
    from inputs_guard_0461 import record, verify
    verify(baseline, record())
    return {'schema':'neverlauncher.unsigned-build.v1','version':RELEASE_VERSION,
            'commit':commit,'builder':builder,'runner':runner,
            'inputBaselineSha256':sha256_file(BASELINE_PATH),
            'contractSha256':sha256_file(CONTRACT_PATH),
            'targets':inspect_builder(bundle)}


def private_key(path: Path) -> Ed25519PrivateKey:
    result = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(result, Ed25519PrivateKey):
        raise ValueError('Ключ аттестации должен использовать Ed25519')
    return result


def public_key(path: Path) -> Ed25519PublicKey:
    result = load_pem_public_key(path.read_bytes())
    if not isinstance(result, Ed25519PublicKey):
        raise ValueError('Корневой ключ доверия аттестации должен использовать Ed25519')
    return result


def signed_json(path: Path, signature: Path, trusted_key: Path) -> dict:
    raw=path.read_bytes()
    obj=load_json(path)
    # Требуйте каноническую сериализацию во избежание различий между JSON-парсерами.
    if raw != canonical(obj):
        raise ValueError('Подписанный JSON не соответствует каноническому формату: '+str(path))
    if signature.is_symlink() or not signature.is_file() or signature.stat().st_size != 64:
        raise ValueError('Отсутствует или некорректна подпись доказательных данных Ed25519')
    try:
        public_key(trusted_key).verify(signature.read_bytes(), raw)
    except InvalidSignature as exc:
        raise ValueError('Некорректная независимая подпись доказательных данных') from exc
    return obj


def compare(a: dict, b: dict, a_dir: Path, b_dir: Path) -> dict:
    if a.get('schema')!='neverlauncher.unsigned-build.v1' or b.get('schema')!='neverlauncher.unsigned-build.v1':
        raise ValueError('Неподдерживаемые доказательные данные неподписанной сборки')
    for k in ('version','commit','inputBaselineSha256','contractSha256'):
        if a.get(k) != b.get(k):
            raise ValueError(f'Независимые входные данные различаются: {k}')
    if a['version'] != RELEASE_VERSION or not HEX.fullmatch(a['commit']):
        raise ValueError('Некорректный идентификатор источника релиза')
    if a['inputBaselineSha256'] != sha256_file(BASELINE_PATH) or a['contractSha256'] != sha256_file(CONTRACT_PATH):
        raise ValueError('Базовые входные данные или заявленный набор файлов изменились')
    if (not a.get('builder') or not b.get('builder') or a['builder']==b['builder']
            or not a.get('runner') or not b.get('runner') or a['runner']==b['runner']):
        raise ValueError('Требуются независимые сборщики и исполнители проверок')
    if a.get('targets')!=inspect_builder(a_dir) or b.get('targets')!=inspect_builder(b_dir):
        raise ValueError('Подписанный отчёт сборщика не соответствует фактическим файлам')
    if a['targets'] != b['targets'] or set(a['targets'])!=TARGETS:
        raise ValueError('Неподписанные сборки не совпадают побайтово для всех шести платформ')
    return {'schema':'neverlauncher.reproducibility-compared.v1', 'version':RELEASE_VERSION,
            'commit':a['commit'],'inputBaselineSha256':a['inputBaselineSha256'],
            'contractSha256':a['contractSha256'], 'builders':[{'builder':a['builder'],'runner':a['runner']},
                                                             {'builder':b['builder'],'runner':b['runner']}],
            'targets':{k:{'file':v['file'],'sha256':v['sha256'],'size':v['size'],
                           'members':len(v['members'])} for k,v in sorted(a['targets'].items())},
            'status':'six-unsigned-targets-byte-identical'}


def link(comparison: dict, approval: dict, signed_bundle: Path, *, a_key: Path, b_key: Path, approval_key: Path, native_reports_dir: Path) -> dict:
    if comparison.get('schema')!='neverlauncher.reproducibility-compared.v1' or comparison.get('version')!=RELEASE_VERSION or set(comparison.get('targets',{}))!=TARGETS:
        raise ValueError('Отсутствует полное независимое сравнение')
    if approval.get('schema')!='neverlauncher.native-signing-approval.v1' or approval.get('version')!=RELEASE_VERSION:
        raise ValueError('Некорректное разрешение на штатное подписание для ОС')
    if approval.get('commit') != comparison['commit'] or approval.get('comparisonSha256') != hashlib.sha256(canonical(comparison)).hexdigest():
        raise ValueError('Разрешение на подпись не относится к сравненному неподписанному содержимому')
    if not approval.get('operator') or approval.get('operator') in (x['builder'] for x in comparison['builders']):
        raise ValueError('Требуется независимый оператор подписания')
    identities={key.read_bytes() for key in (a_key,b_key,approval_key)}
    if len(identities)!=3:
        raise ValueError('У двух независимых сборщиков и оператора подписания должны быть разные доверенные ключи')
    expected=approval.get('targets')
    if not isinstance(expected,dict) or set(expected)!=TARGETS:
        raise ValueError('Разрешение штатного подписания должно охватывать все шесть фактически подписанных платформ')
    # Существующий промышленный верификатор проверяет настоящие заголовки
    # исполняемых файлов, встроенные манифесты пакетов и точные SHA-256 выпущенных
    # подписанных пакетов.
    signed=verify_bundle(signed_bundle, release_manifest=True)
    if approval.get('releaseSignatureVerified') is not True or approval.get('releaseManifestSha256')!=sha256_file(signed_bundle/'RELEASE_MANIFEST.json'):
        raise ValueError('Не подтверждена привязка финальной подписи релиза')
    for target in sorted(TARGETS):
        row=expected[target]
        kind=target.split('-')[0]
        if not isinstance(row,dict) or row.get('unsignedSha256')!=comparison['targets'][target]['sha256']:
            raise ValueError('Непривязанный набор неподписанных файлов: '+target)
        if row.get('signedSha256')!=signed['targets'][target]['sha256']:
            raise ValueError('Непривязанный финальный подписанный пакет: '+target)
        if kind=='windows' and row.get('nativeCheck')!='authenticode-chain-and-timestamp-verified':
            raise ValueError('Отсутствует штатная проверка подписи Windows: '+target)
        if kind=='darwin' and row.get('nativeCheck')!='codesign-gatekeeper-and-notarization-verified':
            raise ValueError('Отсутствует штатная проверка подписи macOS: '+target)
        if kind=='linux' and row.get('nativeCheck')!='release-ed25519-and-digest-verified':
            raise ValueError('Отсутствует проверка подписи релиза Linux: '+target)
        # Нативная квитанция создаётся реальным выполнением проверок ОС для точного
        # окончательного пакета, а не утверждением строки в JSON одобрения.
        native_path=native_reports_dir/(target+'.json')
        native=signed_json(native_path,native_reports_dir/(target+'.sig'),approval_key)
        if (row.get('nativeReceiptSha256')!=sha256_file(native_path)
                or native.get('schema')!='neverlauncher.native-verification.v1'
                or native.get('version')!=RELEASE_VERSION or native.get('target')!=target
                or native.get('nativeCheck')!=row['nativeCheck']
                or native.get('unsignedSha256')!=row['unsignedSha256']
                or native.get('signedSha256')!=row['signedSha256']
                or native.get('releaseManifestSha256')!=approval.get('releaseManifestSha256')
                or native.get('status')!='native-verified-transform-audit-separate'):
            raise ValueError('Квитанция штатной проверки ОС не охватывает подписанную платформу: '+target)
        if row.get('boundPayload') is not True:
            raise ValueError('Оператор не одобрил преобразование неподписанной сборки в финальный пакет: '+target)
    return {'schema':'neverlauncher.reproducibility-linked.v1','version':RELEASE_VERSION,
            'commit':comparison['commit'],'comparisonSha256':approval['comparisonSha256'],
            'nativeApprovalSha256':hashlib.sha256(canonical(approval)).hexdigest(),
            'releaseManifestSha256':approval['releaseManifestSha256'],
            'targets':{k:{'unsignedSha256':comparison['targets'][k]['sha256'],
                          'signedSha256':signed['targets'][k]['sha256']} for k in sorted(TARGETS)},
            'status':'native-attested-exact-byte-signing-link'}


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    cap=sub.add_parser('capture')
    for f in ('bundle','builder','runner','commit','out'):
        cap.add_argument('--'+f,required=True)
    sign=sub.add_parser('sign')
    sign.add_argument('--report',type=Path,required=True);sign.add_argument('--private-key',type=Path,required=True);sign.add_argument('--out',type=Path,required=True)
    cmp=sub.add_parser('compare')
    for f in ('a-report','a-sig','a-key','a-dir','b-report','b-sig','b-key','b-dir','out'):
        cmp.add_argument('--'+f,required=True)
    fin=sub.add_parser('link')
    for f in ('comparison','approval','approval-sig','approval-key','a-key','b-key','signed-dir','native-reports-dir','out'):
        fin.add_argument('--'+f,required=True)
    args=p.parse_args()
    try:
        if args.cmd=='capture':
            report=capture(Path(args.bundle),builder=args.builder,runner=args.runner,commit=args.commit)
            atomic_json(Path(args.out),report)
        elif args.cmd=='sign':
            report=load_json(args.report)
            raw=args.report.read_bytes()
            if raw!=canonical(report):
                raise ValueError('Подписание неканонического отчёта запрещено')
            if args.report.resolve()==args.out.resolve():
                raise ValueError('Файл подписи не должен перезаписывать отчёт')
            args.out.write_bytes(private_key(args.private_key).sign(raw))
        elif args.cmd=='compare':
            a_key=Path(args.a_key);b_key=Path(args.b_key)
            if a_key.read_bytes()==b_key.read_bytes():
                raise ValueError('Оба сборщика используют один и тот же ключ подписи доказательных данных')
            a=signed_json(Path(args.a_report),Path(args.a_sig),a_key)
            b=signed_json(Path(args.b_report),Path(args.b_sig),b_key)
            result=compare(a,b,Path(args.a_dir),Path(args.b_dir))
            atomic_json(Path(args.out),result)
        else:
            c=load_json(Path(args.comparison))
            apr=signed_json(Path(args.approval),Path(args.approval_sig),Path(args.approval_key))
            result=link(c,apr,Path(args.signed_dir),a_key=Path(args.a_key),b_key=Path(args.b_key),approval_key=Path(args.approval_key),native_reports_dir=Path(args.native_reports_dir))
            atomic_json(Path(args.out),result)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError,zipfile.BadZipFile,tarfile.TarError,InvalidSignature) as exc:
        print('Проверка воспроизводимости заблокирована: '+str(exc),file=sys.stderr)
        return 2
    print(f'PASS: проверка воспроизводимости {args.cmd} завершена; свидетельства ещё должны пройти следующий выпускной контроль')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
