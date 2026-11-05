#!/usr/bin/env python3
"""Упаковать точные неподписанные *собранные* бинарные файлы перед подписанием платформой.

Вызывается настоящими скриптами нативной упаковки после проверки сборки/архитектуры и до
Authenticode/codesign. Не создаёт фиктивные исполняемые файлы или ключи. Одинаковые входные файлы,
пути и режимы дают побайтово идентичный пакет на разных сборочных узлах. Все выпущенные пакеты
дополнительно проверяет reproducible_0470.
"""
from __future__ import annotations
import argparse
import gzip
import io
from pathlib import Path
import sys
import tarfile
import hashlib
import re

from canonical_zip_0461 import write_zip, safe_member, safe_file
from reproducible_0470 import inspect_exe, contract, visit_archive


def make_package(platform: str, arch: str, out_dir: Path, mapping: dict[str,Path]) -> Path:
    target=f'{platform}-{arch}' if platform!='macos' else f'darwin-{arch}'
    if target not in contract()['targets']:
        raise ValueError('Неподдерживаемая целевая платформа')
    if not mapping:
        raise ValueError('Неподписанное содержимое пусто')
    # Используйте точные имена файлов из текущего проверенного контракта выпуска.
    version=(Path(__file__).resolve().parents[2]/'VERSION').read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version):
        raise ValueError('Небезопасное обозначение версии продукта')
    current_contract=contract()
    if current_contract['version'] != version:
        raise ValueError('Версия выпуска не соответствует контракту неподписанного содержимого')
    expected=current_contract['targets'][target]
    paths=set()
    for arc,path in mapping.items():
        safe_member(arc)
        if arc in paths:
            raise ValueError('Повторяющийся элемент')
        paths.add(arc)
        if not path.is_file() or path.is_symlink() or path.stat().st_size==0:
            raise ValueError('Скомпилированный исходный файл отсутствует или небезопасен: '+str(path))
        # Проверяйте все настоящие элементы на наличие символьных ссылок в
        # промежуточных компонентах пути.
        current=path.absolute()
        for parent in (current,*current.parents):
            if parent.is_symlink():
                raise ValueError('Символическая ссылка в пути неподписанных входных файлов: '+str(parent))
    expected_binaries={'windows':('launcher-desktop.exe','guard.exe','runtime.exe','guard-sensor.dll','launcher-cli.exe'),
                       'linux':('launcher/launcher-cli','launcher/launcher-api','launcher/launcher-desktop','launcher/guard','launcher/runtime'),
                       'darwin':('Launcher.app/Contents/MacOS/launcher-desktop','Launcher.app/Contents/Helpers/guard','Launcher.app/Contents/Helpers/runtime','Launcher.app/Contents/Helpers/launcher-cli')}
    if not set(expected_binaries['darwin' if platform=='macos' else platform]).issubset(mapping):
        raise ValueError('Отсутствует один или несколько скомпилированных нативных компонентов')
    # Для нативных платформ имена архивов намеренно соответствуют ОКОНЧАТЕЛЬНОМУ
    # пакету; неподписанные пакеты должны храниться в другом неизменяемом корне
    # staging.
    out_dir.mkdir(parents=True,exist_ok=True)
    out=out_dir/expected
    if out.exists():
        raise ValueError('Отказ перезаписывать неизменяемый неподписанный артефакт: '+str(out))
    # Проверяйте все настоящие бинарники, а не только выбранный основной
    # исполняемый файл.
    for name in expected_binaries['darwin' if platform=='macos' else platform]:
        with mapping[name].open('rb') as fh:
            inspect_exe(fh.read(65536), 'darwin' if platform=='macos' else platform, arch)
    if platform in ('windows','macos'):
        # canonical_zip ожидает общий корень. Нельзя внедрять связанные исходники как
        # пути элементов архива: скопируйте их байты в закрытый промежуточный
        # каталог.
        import tempfile
        with tempfile.TemporaryDirectory(prefix='launcher-unsigned-') as tmp:
            root=Path(tmp)
            for name,path in mapping.items():
                dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes(path.read_bytes())
                dest.chmod(0o755 if name in expected_binaries['darwin' if platform=='macos' else platform] else 0o644)
            write_zip(root,out,[(name,name) for name in mapping])
    else:
        import os
        with out.open('xb') as target_file:
            with gzip.GzipFile(filename='',fileobj=target_file,mode='wb',mtime=0,compresslevel=9) as gz:
                with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as archive:
                    for name,path in sorted(mapping.items()):
                        info=tarfile.TarInfo(name)
                        info.uid=info.gid=0;info.uname=info.gname=''
                        info.mtime=0;info.mode=0o755 if name in expected_binaries['linux'] else 0o644
                        info.size=path.stat().st_size
                        with path.open('rb') as fh:
                            archive.addfile(info,fh)
    visit_archive(out,'darwin' if platform=='macos' else platform,arch)
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform',choices=('windows','linux','macos'),required=True)
    p.add_argument('--arch',choices=('x64','arm64'),required=True)
    p.add_argument('--out-dir',type=Path,required=True)
    p.add_argument('--file',action='append',required=True,help="archive/member/path=/absolute/compiled/file")
    args=p.parse_args()
    try:
        mapping={}
        for item in args.file:
            if '=' not in item:
                raise ValueError('Некорректное сопоставление --file')
            member,source=item.split('=',1)
            if member in mapping:
                raise ValueError('Повторяющееся сопоставление --file')
            mapping[member]=Path(source)
        out=make_package(args.platform,args.arch,args.out_dir,mapping)
        print(f'UNSIGNED PAYLOAD {out} sha256={hashlib.sha256(out.read_bytes()).hexdigest()}')
    except (OSError,ValueError,tarfile.TarError) as exc:
        print('Создание неподписанного пакета заблокировано: '+str(exc),file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':raise SystemExit(main())
