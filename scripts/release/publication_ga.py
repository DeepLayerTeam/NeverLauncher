#!/usr/bin/env python3
"""Защита производственной публикации 1.0.0.

Проверять точную подпись независимого валидатора 18 групп и сопоставлять все шесть подписанных
установщиков И с отдельно закреплённым индексом дистрибуции, И с реально публикуемыми файлами. Сам
факт завершения CI-workflow не принимается.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
from cryptography.exceptions import InvalidSignature

import full_real_acceptance as ga

class Blocked(ValueError):pass

def need(ok, why):
    if not ok:raise Blocked(why)

def verify(approval:Path, signature:Path, verifier_public:Path, verifier_pin:str,
           packages:Path, index:Path, index_pin:str, bundle:Path,
           source_commit:str, project:str):
    need(ga.VERSION=='1.0.0' and ga.rehearsal.COMMIT.fullmatch(source_commit),
         'Для защищённой публикации версии 1.0.0 необходим точный SHA исходного кода')
    report=ga.verify_signed(approval,signature,verifier_public,verifier_pin,ga.FINAL_DOMAIN)
    need(set(report)=={'schema','version','commit','project','sourceTree',
         'sourceIndexSha256','finalPackages','qaSha256','fullSweepSha256','e2eGroups','status'} and
         report['schema']==ga.FINAL_SCHEMA and report['version']==ga.VERSION and
         report['commit']==source_commit and report['project']==project and
         report['status']=='PASS' and report['sourceIndexSha256']==index_pin and
         report['e2eGroups']==list(ga.GROUPS) and
         ga.rehearsal.COMMIT.fullmatch(report.get('sourceTree','')) and
         all(ga.rehearsal.SHA.fullmatch(report.get(x,'')) for x in ('qaSha256','fullSweepSha256')),
         'Отсутствует действительное независимо подписанное решение о полной пользовательской приёмке')
    raw=ga.rehearsal.safe(index,ga.rehearsal.native.MAX_INDEX).read_bytes()
    need(hashlib.sha256(raw).hexdigest()==index_pin, 'Байты независимо проверенного индекса исходников изменились')
    original=ga.rehearsal.package_set(packages,index,index_pin,source_commit,project)
    need(original==report['finalPackages'] and len(original)==8,
         'Фактический финальный подписанный установщик отличается от проверенного в GA')
    # Отдельный подписанный пакет выпуска — ещё не одобренный установщик. Не
    # публикуйте незаметно другие исполняемые пакеты только потому, что у них
    # одинаковые исходники. В подписанный пакет должны войти точно шесть
    # артефактов с окончательными байтами.
    need(bundle.is_absolute() and bundle.is_dir() and not bundle.is_symlink(),
         'Отсутствует реальный подписанный комплект публикации')
    present={p.name for p in bundle.iterdir() if p.is_file() and not p.is_symlink()}
    need(set(original).issubset(present),
         'Фактический комплект публикации не содержит утверждённых финальных пакетов')
    for name,row in original.items():
        file=ga.rehearsal.safe(bundle/name,ga.rehearsal.native.MAX_PACKAGE)
        need(file.stat().st_size==row['size'] and ga.rehearsal.sha(file)==row['sha256'],
             'Попытка заменить утверждённый подписанный пакет при публикации '+name)
    # Существующий публикующий процесс проверяет, что эти файлы покрываются
    # SHA256SUMS, RELEASE_MANIFEST и подписью корня выпуска; эта защита
    # дополнительная.
    return {'version':ga.VERSION,'commit':source_commit,'status':'PASS',
            'authorizedPackages':len(original),
            'gaApprovalSha256':ga.rehearsal.sha(approval)}

# The public release must carry the *actual* independently approved OS installers,
# not merely their names in an approval or a CI job result. The receipt below is
# generated only after all eight source files (six installers, two Linux signatures)
# have been reread and hashed. It is included in the release-root signature.
RECEIPT = 'SUPPORTED_PLATFORM_GA_1000.json'
RECEIPT_SCHEMA = 'launcher.supported-platform-ga/1.0.0'


def receipt(authorized: dict, approved: dict, *, commit: str, project: str,
            index_pin: str) -> dict:
    return {
        'schema': RECEIPT_SCHEMA,
        'version': ga.VERSION,
        'commit': commit,
        'project': project,
        'sourceIndexSha256': index_pin,
        'independentApprovalSha256': approved['gaApprovalSha256'],
        'status': 'independently-approved-exact-native-packages',
        'packages': authorized,
        'supportedTargets': [
            f'{p}-{arch}' for p in ('windows', 'linux', 'macos') for arch in ('x64', 'arm64')
        ],
    }


def serialize_receipt(doc: dict) -> bytes:
    import json
    return (json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def stage(*, approval: Path, signature: Path, verifier_public: Path,
          verifier_pin: str, packages: Path, index: Path, index_pin: str,
          bundle: Path, source_commit: str, project: str) -> dict:
    """Copy approved packages into the *unsigned* release directory, fail closed.

    Never mutate an existing final installer, and never accept artifacts with
    different bytes. A separate post-signing validation rechecks the same files.
    This is deliberately not a mechanism for creating GA approval.
    """
    import os
    import shutil

    need(ga.VERSION == '1.0.0', 'Подготовка поддерживаемой GA-поставки предназначена для версии 1.0.0')
    packages, index, bundle = packages.absolute(), index.absolute(), bundle.absolute()
    need(packages != bundle and bundle.is_dir() and not bundle.is_symlink(),
         'Недоступен отдельный каталог ещё не подписанного выпуска')
    approved = verify(approval, signature, verifier_public, verifier_pin,
                      packages, index, index_pin, packages, source_commit, project)
    authorized = ga.rehearsal.package_set(packages, index, index_pin, source_commit, project)
    destination = bundle / RECEIPT
    need(not destination.exists() and not destination.is_symlink(),
         'Подтверждение поддерживаемых платформ уже существует; перезапись запрещена')
    need(all(not (bundle / name).exists() and not (bundle / name).is_symlink()
             for name in authorized), 'В каталоге выпуска уже имеются финальные пакеты; перезапись запрещена')
    staged: list[Path] = []
    try:
        for name, row in sorted(authorized.items()):
            source = ga.rehearsal.safe(packages / name, ga.rehearsal.native.MAX_PACKAGE)
            final = bundle / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(final, flags, 0o644)
            staged.append(final)
            with os.fdopen(fd, 'wb') as target, source.open('rb') as inp:
                shutil.copyfileobj(inp, target, 1024 * 1024)
                target.flush()
                os.fsync(target.fileno())
            need(final.stat().st_size == row['size'] and ga.rehearsal.sha(final) == row['sha256'],
                 'Финальный пакет изменился при импорте: ' + name)
        report = receipt(authorized, approved, commit=source_commit,
                         project=project, index_pin=index_pin)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o644)
        staged.append(destination)
        with os.fdopen(fd, 'wb') as out:
            out.write(serialize_receipt(report))
            out.flush()
            os.fsync(out.fileno())
        # Also verifies the copy, not merely the source files.
        verify(approval, signature, verifier_public, verifier_pin,
               packages, index, index_pin, bundle, source_commit, project)
        return report
    except BaseException:
        for created in reversed(staged):
            created.unlink(missing_ok=True)
        raise


def verify_staged_receipt(bundle: Path, approved: dict, authorized: dict,
                          source_commit: str, project: str, index_pin: str) -> None:
    path = bundle / RECEIPT
    need(path.is_file() and not path.is_symlink() and
         0 < path.stat().st_size <= (64 << 10),
         'Отсутствует проверяемое свидетельство поддерживаемой поставки 1.0.0')
    expected = serialize_receipt(receipt(authorized, approved, commit=source_commit,
                                         project=project, index_pin=index_pin))
    need(path.read_bytes() == expected,
         'Публичный отчёт о поддерживаемых платформах отличается от проверенных байтов')


def main() -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Проверенная передача реальных GA-установщиков в подписываемый релиз')
    parser.add_argument('operation', choices=('stage', 'verify'))
    for field in ('approval', 'signature', 'verifier-public', 'verifier-pin',
                  'packages', 'index', 'index-pin', 'bundle', 'source-commit', 'project'):
        parser.add_argument('--' + field, required=True)
    opts = parser.parse_args()
    paths = {key: Path(getattr(opts, key)) for key in
             ('approval', 'signature', 'verifier_public', 'packages', 'index', 'bundle')}
    args = dict(approval=paths['approval'], signature=paths['signature'],
                verifier_public=paths['verifier_public'], verifier_pin=opts.verifier_pin,
                packages=paths['packages'], index=paths['index'], index_pin=opts.index_pin,
                bundle=paths['bundle'], source_commit=opts.source_commit, project=opts.project)
    try:
        if opts.operation == 'stage':
            stage(**args)
        else:
            approved = verify(*[args[k] for k in ('approval', 'signature', 'verifier_public',
                         'verifier_pin', 'packages', 'index', 'index_pin', 'bundle',
                         'source_commit', 'project')])
            authorized = ga.rehearsal.package_set(args['packages'], args['index'],
                         args['index_pin'], args['source_commit'], args['project'])
            verify_staged_receipt(args['bundle'], approved, authorized,
                                  args['source_commit'], args['project'], args['index_pin'])
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('SUPPORTED PLATFORM GA заблокирована: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
