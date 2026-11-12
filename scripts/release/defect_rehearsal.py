#!/usr/bin/env python3
"""Зафиксировать и независимо репетировать точный кандидат выпуска 0.52.12.

Никакого успеха только по манифесту/квитанции: каждая репетиция повторно открывает БАЙТЫ шести
финальных подписанных пакетов, выполняет регрессии исходников и проверяет все исходные свидетельства
0.52.12 по совместимости, нативным запускам, воспроизводимости и длительным прогонам штатными живыми
валидаторами. Отдельно подписанный экспорт трекера дефектов определяет закрытие P0/P1. Отсутствие
настоящих внешних запусков БЛОКИРУЕТ репетицию и не превращается в GA из-за присутствия скрипта.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/acceptance'))
sys.path.insert(0, str(ROOT / 'scripts/release'))
import inventory_0521 as inventory
import native_packages_0522 as native
import sweep_05211 as sweep

VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
SCHEMA = 'launcher.candidate-freeze/' + VERSION
REPORT = 'launcher.independent-rehearsal/' + VERSION
ISSUES = 'launcher.defect-closure-export/' + VERSION
FREEZE_DOMAIN = ('launcher.candidate-freeze.'+VERSION+'\x00').encode()
ISSUE_DOMAIN = ('launcher.defect-closure.'+VERSION+'\x00').encode()
REHEARSAL_DOMAIN = ('launcher.independent-rehearsal.'+VERSION+'\x00').encode()
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')

# Фиксированные промышленные точки входа регрессии: экспорт задач не может
# подменить настоящие тесты произвольными командами оболочки или путями из
# своего JSON.
REGRESSIONS = (
 'scripts.release.test_independent_current_05211',
 'scripts.acceptance.test_sweep_05211',
 'scripts.acceptance.test_soak_05211',
 'scripts.release.test_reproducible_0470',
 'scripts.release.test_unsigned_package_0470',
 'scripts.acceptance.test_inventory_0521',
 'scripts.acceptance.test_native_packages_0522',
 'scripts.acceptance.test_owner_admin_real_0523',
 'scripts.acceptance.test_guard_device_bridge_real_0529',
 'scripts.operations.test_physical_ha_dr_05210',
 'scripts.release.test_defect_rehearsal_05212',
 'scripts.release.test_full_real_acceptance_0530',
 'scripts.release.test_publication_ga_0530',
 'scripts.acceptance.test_sdk_live_0530',
)

class Blocked(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Blocked(why)

def safe(path: Path, maximum: int):
    # Не разрешайте путь до проверки: разрешение скрыло бы подмену символьной ссылкой.
    require(path.is_absolute() and not path.is_symlink() and path.is_file(),
            'Исходное свидетельство отсутствует или небезопасно: ' + str(path))
    require(not any(parent.is_symlink() for parent in path.parents),
            'Каталог свидетельств содержит символьную ссылку: ' + str(path))
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= maximum,
            'Свидетельство имеет жёсткую ссылку, пусто или слишком велико: ' + str(path))
    return path

def sha(path: Path) -> str:
    safe(path, 4*1024*1024*1024)
    return native.file_hash(path)

def read(path: Path, limit=8*1024*1024):
    raw = safe(path, limit).read_bytes()
    require(len(raw) <= limit, 'JSON превышает допустимый размер')
    doc = native.parse_json(raw)
    require(type(doc) is dict, 'Документ JSON должен содержать объект')
    return doc

def git(*args):
    p = subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True,
                       text=True, timeout=30, check=True)
    return p.stdout.strip()

def source_identity(expected: str):
    require(VERSION == '0.53.0' and COMMIT.fullmatch(expected or '') is not None,
            'Требуются точная версия 0.53.0 и утверждённый коммит из 40 шестнадцатеричных символов')
    require(git('rev-parse', 'HEAD') == expected, 'Коммит проверяемой рабочей копии изменился')
    require(git('status','--porcelain','--untracked-files=all') == '',
            'В рабочей копии есть незакоммиченные изменения или неотслеживаемые исходные файлы')
    tree = git('rev-parse','HEAD^{tree}')
    require(COMMIT.fullmatch(tree) is not None, 'Некорректное дерево исходников Git')
    return tree

def package_set(directory: Path, index_file: Path, index_pin: str, commit: str, project: str):
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
            and not any(p.is_symlink() for p in directory.parents), 'Небезопасный каталог финальных пакетов')
    require(SHA.fullmatch(index_pin or '') is not None, 'Требуется закреплённая по независимому каналу сумма SHA индекса исходников')
    index = safe(index_file, native.MAX_INDEX).read_bytes()
    records = native.read_index(index, index_pin, VERSION, commit, project)
    expected = {entry['filename'] for entry in records.values()}
    for item in records.values():
        if 'signatureUrl' in item:
            # Имя отделённого Linux-файла .asc следует имени окончательного артефакта
            # пакета.
            expected.add(item['filename'] + '.asc')
    require({p.name for p in directory.iterdir()} == expected,
            'Требуются ровно шесть финальных пакетов и их отдельные подписи Linux')
    files = {}
    for row in records.values():
        path = directory / row['filename']
        require(sha(path) == row['sha256'] and path.stat().st_size == row['size'],
                'содержимое итогового пакета отличается от независимого закреплённого индекса поставки')
        files[path.name] = {'sha256': row['sha256'], 'size': row['size']}
        if 'signatureUrl' in row:
            path = directory / (row['filename']+'.asc')
            require(sha(path) == row['signatureSha256'] and
                    path.stat().st_size == row['signatureSize'],
                    'Отдельная подпись финального пакета Linux не соответствует закреплённому индексу')
            files[path.name] = {'sha256': row['signatureSha256'], 'size': row['signatureSize']}
    return dict(sorted(files.items()))

def freeze(commit, project, packages, index, index_sha):
    tree = source_identity(commit)
    files = package_set(packages, index, index_sha, commit, project)
    return {'schema': SCHEMA, 'version': VERSION, 'commit': commit,
            'sourceTree': tree, 'project': project, 'sourceIndexSha256': index_sha,
            'finalPackages': files, 'status': 'CANDIDATE_FROZEN_NOT_GA'}

def private_key(path: Path):
    p = safe(path, 8192)
    require(not p.is_relative_to(ROOT), 'Закрытый ключ должен храниться вне рабочей копии')
    require(p.stat().st_mode & 0o077 == 0, 'Закрытый ключ должен иметь права 0600')
    key = serialization.load_pem_private_key(p.read_bytes(),password=None)
    require(isinstance(key, Ed25519PrivateKey), 'Требуется закрытый ключ Ed25519')
    return key

def verify_signature(doc, sig_path, public_path, pin, domain):
    key = inventory.public_key(public_path, pin)
    sig = safe(sig_path, 128).read_bytes()
    require(len(sig) == 64, 'Некорректная длина независимой подписи')
    try:
        key.verify(sig, domain + inventory.canonical(doc))
    except InvalidSignature as e:
        raise Blocked('Подпись некорректна или отчёт изменён') from e
    return key

def sealed_freeze(path, sig, key, pin, commit, project, packages, index, index_sha):
    doc = read(path)
    verify_signature(doc,sig,key,pin,FREEZE_DOMAIN)
    require(doc == freeze(commit,project,packages,index,index_sha),
            'Зафиксированное состояние не соответствует текущему дереву Git и точным данным финальных пакетов')
    return doc

def closed_defects(path, sig, key, pin, commit):
    doc = read(path)
    verify_signature(doc,sig,key,pin,ISSUE_DOMAIN)
    require(set(doc) == {'schema','version','commit','scope','issues'} and
            doc['schema'] == ISSUES and doc['version'] == VERSION and
            doc['commit'] == commit and doc['scope'] == 'all-open-release-defects',
            'Выгрузка дефектов не соответствует точному снимку задач всего выпуска')
    entries=doc['issues']
    require(type(entries) is list and len(entries) <= 10000,
            'Выгрузка дефектов некорректна или слишком велика')
    names=set()
    for issue in entries:
        require(type(issue) is dict and set(issue)=={'id','severity','status','regression'},
                'В задаче отсутствуют обязательные поля')
        ident=issue['id']
        require(type(ident) is str and re.fullmatch(r'[A-Z][A-Z0-9]+-[1-9][0-9]*',ident)
                and ident not in names, 'Некорректный или повторяющийся идентификатор задачи')
        names.add(ident)
        require(issue['severity'] in ('P0','P1','P2','P3') and
                issue['status'] in ('closed','open') and
                type(issue['regression']) is str, 'Некорректная серьёзность или статус задачи')
        if issue['severity'] in ('P0','P1'):
            require(issue['status'] == 'closed' and issue['regression'] in REGRESSIONS,
                    'Блокирующий дефект не закрыт обязательной реальной регрессионной проверкой')
    return {'issueCount':len(entries),'criticalClosed':sum(
        x['severity'] in ('P0','P1') for x in entries),'sha256':sha(path)}

def run_regressions(log_dir: Path, *, replay=False):
    require(log_dir.is_absolute() and log_dir.is_dir() and not log_dir.is_symlink()
            and not any(p.is_symlink() for p in log_dir.parents),
            'Требуется закрытый каталог свидетельств регрессионных проверок')
    commands = [([sys.executable,'scripts/version/manage.py','check'],'version-check'),
                ([sys.executable,'-m','unittest','-q',*REGRESSIONS],'mandatory-python-regressions')]
    env=os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join([str(ROOT/'scripts/release'),
                                          str(ROOT/'scripts/acceptance'),
                                          str(ROOT/'scripts/operations'),
                                          env.get('PYTHONPATH','')])
    output=[]
    for command,name in commands:
        proc=subprocess.run(command,cwd=ROOT,env=env,timeout=900,capture_output=True,
                            stdin=subprocess.DEVNULL)
        data=proc.stdout+proc.stderr
        require(proc.returncode == 0 and data and len(data)<=16*1024*1024,
                name+' завершился ошибкой, превысил время ожидания или не создал доступный журнал')
        require(b'FAILED' not in data and b' (skipped=' not in data and
                b'... skipped ' not in data,
                name+' содержит пропущенные или неудачные обязательные тесты')
        actual_count = None
        if name=='mandatory-python-regressions':
            found=re.search(rb'Ran ([1-9][0-9]*) tests? in [0-9.]+s',data)
            require(found is not None, 'Отсутствует доступный для проверки итоговый отчёт unittest')
            actual_count=int(found.group(1))
        path=log_dir/(name+'.log')
        if not replay:
            require(not path.exists() and not path.is_symlink(),
                    'Журнал регрессионной проверки уже существует')
            inventory.write_exclusive(path,data)
        original=safe(path,16*1024*1024).read_bytes()
        if replay:
            require(b'FAILED' not in original and b' (skipped=' not in original,
                    'Подписанный исходный журнал регрессионной проверки содержит ошибки или пропуски')
            require(actual_count is None or re.search(rb'Ran '+str(actual_count).encode()+
                    rb' tests? in [0-9.]+s',original) is not None,
                    'При повторном запуске изменился перечень обязательных тестов')
        output.append({'name':name,'exit':proc.returncode,
                       'logSha256':hashlib.sha256(original).hexdigest(),
                       'logBytes':len(original),'tests':actual_count})
    return output

FULL_PATHS = ('compat_results','native_results','source_index','native_review','native_key',
              'native_game_results','repro_a_report','repro_b_report','repro_a_sig',
              'repro_b_sig','repro_a_key','repro_b_key','repro_a_dir','repro_b_dir',
              'game_soaks','http_soak','soak_key')
FULL_STRINGS = ('index_sha','project','native_run_id','native_key_pin','native_reviewer',
                'native_game_run_id','package_id','repro_run_id','repro_a_pin',
                'repro_b_pin','soak_run_id','soak_key_pin','compat_run_id')
FULL_INTS = ('compat_attempt','native_attempt','repro_attempt','soak_attempt')

def full_args(config_path: Path, commit: str):
    doc=read(config_path,128*1024)
    require(set(doc)==set(FULL_PATHS+FULL_STRINGS+FULL_INTS) and
            all(type(doc[k]) is str and doc[k].startswith('/') for k in FULL_PATHS) and
            all(type(doc[k]) is str and doc[k] for k in FULL_STRINGS) and
            all(type(doc[k]) is int and doc[k]>0 for k in FULL_INTS),
            'В конфигурации полного прогона отсутствуют строгие независимые пути исходных входных данных')
    values={k:Path(doc[k]) for k in FULL_PATHS}
    values.update({k:doc[k] for k in FULL_STRINGS+FULL_INTS})
    values['commit']=commit
    return SimpleNamespace(**values)

def rehearse(freeze_path,freeze_sig,release_key,release_pin,commit,project,packages,
             index,index_sha,issues,issues_sig,issues_key,issues_pin,config,logs,*,replay=False):
    frozen=sealed_freeze(freeze_path,freeze_sig,release_key,release_pin,
                         commit,project,packages,index,index_sha)
    defects=closed_defects(issues,issues_sig,issues_key,issues_pin,commit)
    require(release_pin != issues_pin, 'Полномочия выпуска и проверки замечаний должны принадлежать разным сторонам')
    regression=run_regressions(logs,replay=replay)
    args=full_args(config,commit)
    require(args.project == project and args.index_sha == index_sha and
            sha(args.source_index) == index_sha,
            'Полный прогон использует другой финальный индекс исходников дистрибутива')
    # Независимо повторите ИСХОДНЫЙ полный набор 280+шесть+длительные
    # испытания+воспроизводимость дважды, а не копируйте JSON со status=PASS от
    # сборщика.
    first=sweep.verify_full(args)
    require(first.get('status')=='OBSERVED_NOT_INDEPENDENT_GA',
            'Полный прогон не проверил все исходные результаты реальных испытаний')
    second=sweep.verify_full(args)
    require(inventory.canonical(first)==inventory.canonical(second),
            'Между независимыми повторными прогонами свидетельства недетерминированы или изменены')
    require(freeze(commit,project,packages,index,index_sha)==frozen,
            'Во время прогона изменились исходники кандидата или данные загруженного финального пакета')
    return {'schema':REPORT,'version':VERSION,'commit':commit,'sourceTree':frozen['sourceTree'],
            'freezeSha256':sha(freeze_path),'issues':defects,'regressions':regression,
            'fullSweepSha256':hashlib.sha256(inventory.canonical(first)).hexdigest(),
            'sourceIndexSha256':index_sha,'finalPackages':frozen['finalPackages'],
            'status':'REHEARSED_NOT_GA'}

def save(path: Path, doc):
    require(path.is_absolute() and not path.exists() and not path.is_symlink(),
            'Требуется новый абсолютный путь к отчёту')
    inventory.write_exclusive(path,inventory.canonical(doc)+b'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    for name in ('freeze','rehearse','verify'):
        s=sub.add_parser(name)
        for arg in ('commit','project','index-sha'):
            s.add_argument('--'+arg,required=True)
        for arg in ('packages','index','freeze','freeze-sig','release-key',
                    'issues','issues-sig','issues-key','config','review-key',
                    'rehearsal','rehearsal-sig','logs'):
            if name=='freeze' and arg not in ('packages','index'): continue
            if name!='freeze' and arg in ('rehearsal','rehearsal-sig') and name=='rehearse': continue
            s.add_argument('--'+arg,required=True,type=Path)
        if name=='freeze':
            s.add_argument('--release-private-key',required=True,type=Path)
            s.add_argument('--output',required=True,type=Path)
            s.add_argument('--signature',required=True,type=Path)
        else:
            for arg in ('release-pin','issues-pin','review-pin'):
                s.add_argument('--'+arg,required=True)
            if name=='rehearse':
                s.add_argument('--review-private-key',required=True,type=Path)
                s.add_argument('--output',required=True,type=Path)
                s.add_argument('--signature',required=True,type=Path)
    a=p.parse_args()
    try:
        if a.cmd=='freeze':
            doc=freeze(a.commit,a.project,a.packages,a.index,a.index_sha)
            key=private_key(a.release_private_key)
            require(a.output!=a.signature,'Пути результата и подписи должны различаться')
            save(a.output,doc)
            inventory.write_exclusive(a.signature,key.sign(FREEZE_DOMAIN+inventory.canonical(doc)))
        else:
            require(a.release_pin != a.review_pin and a.issues_pin != a.review_pin,
                    'Проверяющий должен быть независимым от подписантов выпуска и задач')
            doc=rehearse(a.freeze,a.freeze_sig,a.release_key,a.release_pin,a.commit,
                         a.project,a.packages,a.index,a.index_sha,a.issues,a.issues_sig,
                         a.issues_key,a.issues_pin,a.config,a.logs,replay=(a.cmd=='verify'))
            if a.cmd=='rehearse':
                key=private_key(a.review_private_key)
                pub=inventory.public_key(a.review_key,a.review_pin)
                require(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
                        ==pub.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),
                        'Ключ независимого проверяющего не совпадает')
                require(a.output!=a.signature,'Пути результата и подписи должны различаться')
                save(a.output,doc)
                inventory.write_exclusive(a.signature,key.sign(REHEARSAL_DOMAIN+inventory.canonical(doc)))
            else:
                signed=read(a.rehearsal)
                verify_signature(signed,a.rehearsal_sig,a.review_key,a.review_pin,REHEARSAL_DOMAIN)
                require(doc==signed,'Исходные свидетельства или регрессии отличаются от независимо подписанной репетиции')
        print('ПРОЙДЕНО: точные байты и исходные свидетельства реальной среды независимо перепроверены; GA НЕ предоставлена')
        return 0
    except (Blocked,inventory.Blocked,native.Blocked,sweep.Blocked, OSError,ValueError,
            KeyError,TypeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        print('Репетиционная проверка заблокирована: '+str(exc),file=sys.stderr)
        return 3

if __name__=='__main__':
    raise SystemExit(main())
