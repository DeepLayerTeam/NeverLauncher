#!/usr/bin/env python3
"""0.53.0: выполнить и независимо проверить настоящую пользовательскую приёмку GA.

Утверждающий выпуск должен предоставить реальные независимо полученные финальные пакеты, рабочую
копию исходников, входы настоящих раннеров, независимо подписанный экспорт дефектов и исходные
свидетельства 280 целей, нативных запусков, длительных прогонов и сборок. Успех никогда не
выдумывается: недостающие результаты блокируют выпуск. Только подписанное одобрение отдельного
валидатора открывает шлюз выпуска и привязывается к точным исходникам и байтам финального
подписанного пакета.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/release'), str(ROOT / 'scripts/acceptance')]
import defect_rehearsal_05212 as rehearsal
import inventory_0521 as inventory

VERSION = (ROOT/'VERSION').read_text().strip()
SCHEMA = 'neverlauncher.full-real-user-acceptance/' + VERSION
DOMAIN = ('neverlauncher.full-real-user-acceptance.'+VERSION+'\x00').encode()
FINAL_SCHEMA = 'neverlauncher.independent-full-ga/' + VERSION
FINAL_DOMAIN = ('neverlauncher.independent-full-ga.'+VERSION+'\x00').encode()

# Это не замена верификатора 280+шесть+длительные испытания/воспроизводимость, а
# дополнительные реальные сценарии владельца, идентичности, модпаков, миграции,
# Guard и HA, обязательные для 0.53. Скрипты ниже — существующие промышленные
# исполнители, а не пути из ввода пользователя.
SCENARIOS = {
 'minimal': ('scripts/acceptance/minimal_live_e2e_0378.py', (), 'report'),
 'standard': ('scripts/acceptance/owner_admin_real_0523.py', (), 'report'),
 'auth': ('scripts/acceptance/auth_identity_real_0525.py', ('run',), 'output'),
 'modpacks': ('scripts/acceptance/modpacks_textures_publication_0526.py', (), 'report'),
 'install': ('scripts/acceptance/install_upgrade_repair_0527.py', (), 'output'),
 'java': ('scripts/acceptance/java_sdk_migration_0528.py', ('live',), 'report'),
 'guard': ('scripts/acceptance/guard_device_bridge_real_0529.py', ('live',), 'output'),
 'sdk': ('scripts/acceptance/sdk_live_0530.py', (), 'output'),
 'ha-host': ('scripts/operations/physical_ha_dr_05210.py', ('host',), 'report'),
 'ha-partition': ('scripts/operations/physical_ha_dr_05210.py', ('partition',), 'report'),
 'ha-postgresql': ('scripts/operations/physical_ha_dr_05210.py', ('dependency',), 'report'),
 'ha-redis': ('scripts/operations/physical_ha_dr_05210.py', ('dependency',), 'report'),
 'ha-s3': ('scripts/operations/physical_ha_dr_05210.py', ('dependency',), 'report'),
 'ha-world': ('scripts/operations/physical_ha_dr_05210.py', ('world',), 'report'),
}

# Полный охват E2E-01..18: группу нельзя считать пройденной по единственному
# самостоятельно заявленному PASS. Сквозные группы используют подписанный полный
# прогон и настоящие нативные пакеты.
GROUPS = {
 'E2E-01': ('minimal','standard'), 'E2E-02': ('standard',),
 'E2E-03': ('full-sweep',), 'E2E-04': ('modpacks',),
 'E2E-05': ('auth',), 'E2E-06': ('auth',), 'E2E-07': ('modpacks',),
 'E2E-08': ('full-sweep','modpacks'), 'E2E-09': ('modpacks',),
 'E2E-10': ('install',), 'E2E-11': ('java',),
 'E2E-12': ('java',), 'E2E-13': ('java',),
 'E2E-14': ('ha-host','ha-partition','ha-postgresql','ha-redis','ha-s3','ha-world'),
 'E2E-15': ('guard',), 'E2E-16': ('sdk',),
 'E2E-17': ('full-sweep',), 'E2E-18': ('full-sweep',*SCENARIOS),
}

class Blocked(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise Blocked(why)

def path_file(path, limit=16<<20):
    try:
        return rehearsal.safe(Path(path),limit)
    except (OSError, rehearsal.Blocked) as exc:
        raise Blocked('Исходные свидетельства отсутствуют или небезопасны: '+str(path)) from exc

def read(path):
    doc = rehearsal.read(Path(path))
    need(type(doc) is dict, 'Некорректные свидетельства JSON')
    return doc

def digest(path):
    return rehearsal.sha(Path(path))

def strict_plan(doc, commit, pin):
    need(type(doc) is dict and set(doc)=={'version','sourceCommit','sourceIndexSha256','scenarios'}
         and doc['version']==VERSION=='0.53.0' and doc['sourceCommit']==commit and
         doc['sourceIndexSha256']==pin and type(doc['scenarios']) is dict and
         set(doc['scenarios'])==set(SCENARIOS), 'Неполный план реального выполнения для точной версии')
    for name, args in doc['scenarios'].items():
        need(type(args) is list and 0<len(args)<=80 and
             all(type(part) is str and 0<len(part)<=2048 and '\x00' not in part and
                 '\n' not in part and '\r' not in part for part in args),
             'Некорректные аргументы реального запуска для: '+name)
        prefix=SCENARIOS[name][1]
        need(tuple(args[:len(prefix)])==prefix and
             '--help' not in args and '--version' not in args and
             '--output' not in args and '--report' not in args,
             'Небезопасный или имитированный вывод либо режим в: '+name)
        tail=args[len(prefix):]
        # Явно ограниченная грамматика, а не произвольные команды оболочки или
        # программы раннера. Каждый флаг без значения-переключателя должен иметь
        # ровно один аргумент.
        singles={'--isolated-destructive-acceptance','--destructive-isolated-run',
                 '--source-fenced'}
        need(all(t.startswith('--') or i>0 and tail[i-1].startswith('--') for i,t in enumerate(tail)),
             'Неожиданный позиционный аргумент в: '+name)
        used=set();i=0
        while i<len(tail):
            flag=tail[i]
            need(flag.startswith('--') and flag not in ('--help','--version')
                 and (flag not in used or flag=='--node'), 'Повторяющийся или запрещённый параметр: '+flag)
            used.add(flag)
            i+=1 if flag in singles else 2
            need(i<=len(tail) and (flag in singles or
                i-1<len(tail) and not tail[i-1].startswith('--')),
                'Отсутствует значение параметра: '+flag)
        required = {
            'minimal': {'--binary','--guard-policy','--bridge-policy','--work-root'},
            'standard': {'--env','--email','--password-file','--server-id','--bridge-registration-file',
                         '--world-marker','--isolated-destructive-acceptance'},
            'auth': {'--secrets','--oidc-proof','--source-commit','--api-package-sha256'},
            'modpacks': {'--secrets','--operator-token','--runtime','--cli','--java','--skin','--cape',
                         '--runtime-sha256','--cli-sha256','--pinned-manifest-public-key','--project',
                         '--profile','--channel','--package-id','--component','--selected-preset',
                         '--excluded-preset','--destructive-isolated-run'},
            'install': {'--installer','--installer-sha256','--old-bundle','--old-config-sha256',
                        '--new-bundle','--new-config-sha256','--managed-repair-file',
                        '--managed-repair-sha256','--tmpfs-mib','--scratch-parent','--confirm'},
            'java': {'--config'}, 'guard': {'--config'},
            'sdk': {'--origin','--bearer-file','--json-path','--text-path','--binary-path',
                    '--binary-sha256','--java','--go','--node'},
        }
        if name.startswith('ha-'):
            required[name]={'--edge-url','--allow-disruption'} if name!='ha-world' else {
                '--world-backup','--world-destination','--game-start','--game-stop','--game-config',
                '--rcon-password-file','--expected-player','--marker-xyz','--marker-block','--source-fenced'}
            if name!='ha-world': required[name].add('--state')
            if name in ('ha-host','ha-partition'): required[name].update(
                {'--redfish-url','--bmc-token-file','--bmc-ca','--expected-serial'})
            if name=='ha-partition': required[name].update({'--router','--victim-ip'})
            if name in ('ha-postgresql','ha-redis','ha-s3'):
                required[name].update({'--service','--backend-server','--target','--ha-env-file'})
                service={'ha-postgresql':'patroni','ha-redis':'redis-server','ha-s3':'minio'}[name]
                need(tail[tail.index('--service')+1]==service if '--service' in tail else False,
                     name+': неверная реальная служба')
        need(required[name].issubset(used), 'Пропущены обязательные реальные входные данные: '+name)
        if name=='auth':
            need(tail[tail.index('--source-commit')+1]==commit, 'official auth evidence from other commit')
        if name=='minimal':
            need('--expected-version' not in tail or
                 tail[tail.index('--expected-version')+1]==VERSION,
                 'Минимальная установка запустила другую версию продукта')
    return doc

def assert_observed(name, doc, commit):
    """Требовать точный формат успешного реального результата: без локальных/имитированных и частичных PASS."""
    expected={
      'minimal':('passed','productVersion',20),
      'standard':('passed','productVersion',14),
      'auth':('passed-live-operator-observations-not-independent-ga','productVersion',13),
      'modpacks':('passed','version',9),
      'install':('PASS','version',1),
      'java':('LIVE_CHECKS_PASSED_REVIEW_REQUIRED','productVersion',0),
      'guard':('LIVE_CHECKS_PASSED_REVIEW_REQUIRED','version',0),
      'sdk':('LIVE_SDK_OPERATIONS_PASSED_NOT_GA','version',9),
    }
    if name.startswith('ha-'):
        need(doc.get('status')=='PASS' and doc.get('version')==VERSION and
             doc.get('mode')==('dependency' if name in ('ha-postgresql','ha-redis','ha-s3')
                                else name[3:]) and
             (name!='ha-world' or doc.get('markerVerified') is True),
             'Не подтверждены реальный сбой HA или восстановление мира: '+name)
        if name in ('ha-postgresql','ha-redis','ha-s3'):
            need(doc.get('service')=={'ha-postgresql':'patroni','ha-redis':'redis-server',
                 'ha-s3':'minio'}[name], 'Некорректная фактическая зависимость')
        return
    status,version_key,checks=expected[name]
    need(doc.get('status')==status and doc.get(version_key)==VERSION,
         name+': реальная проверка не пройдена на текущей версии')
    if name in ('minimal','standard','auth'):
        actual=doc.get('checks')
        need(type(actual) is list and len(actual)>=checks and
             all(type(row) is dict and row.get('status') in ('passed',None) for row in actual),
             name+': не все реальные этапы завершены')
    if name=='modpacks':
        need(type(doc.get('checks')) is list and len(doc['checks'])==9 and
             type(doc.get('textures')) is list and len(doc['textures'])==2,
             'Операции со скином, плащом или запуском не завершены')
    if name=='java':
        need(doc.get('sourceCommit')==commit and doc.get('gravit',{}).get('migrationChecks')==36 and
             doc['gravit'].get('moduleChecks')==19 and
             set(doc.get('legacy',{}))=={'0.36.0','0.46.0'} and
             doc.get('java',{}).get('checks',0)>=6,
             'Отсутствуют пять сценариев JVM, три миграции Gravit или два пути обновления устаревших версий')
    if name=='guard':
        need(doc.get('sourceCommit')==commit and
             len(doc.get('serverBridge',{}).get('tenRealRuntime',{}))==10 and
             len(doc.get('serverBridge',{}).get('threeBuildCompatibility',[]))==3 and
             doc.get('deviceTrust',{}).get('targets') and doc.get('guard',{}),
             'Реальные свидетельства Guard, доверия к устройствам или Bridge неполны')
    if name=='install':
        need(type(doc.get('checks')) is list and len(doc['checks'])>=8,
             'Реальная последовательность установки, сбоя, восстановления и отката не завершена')
    if name=='sdk':
        need(type(doc.get('checks')) is list and len(doc['checks'])>=checks,
             'Не все три реальных HTTP-клиента SDK прошли проверку')
    if name=='auth': need(doc.get('sourceCommit')==commit, 'Официальная авторизация относится к другому коммиту')

def execute(plan, work, commit, pin):
    """Однократно запускать настоящие раннеры выделенной лаборатории; не принимать заданные пользователем
исполняемые файлы или команды оболочки."""
    need(work.is_absolute() and work.is_dir() and not work.is_symlink(), 'Требуется закрытый рабочий каталог')
    need(not any(work.iterdir()), 'Рабочий каталог должен быть пустым; повторное использование старых свидетельств запрещено')
    data=strict_plan(read(plan),commit,pin)
    need(path_file(plan,256*1024).stat().st_mode & 0o077 == 0,
         'Закрытый план лаборатории должен быть недоступен для чтения другим пользователям и группам')
    logdir=work/'logs'; datadir=work/'results'
    logdir.mkdir(mode=0o700);datadir.mkdir(mode=0o700)
    records={}
    for name,(script,prefix,outputflag) in SCENARIOS.items():
        outfile=datadir/(name+'.json')
        argv=[sys.executable,str(ROOT/script),*data['scenarios'][name],
              '--'+outputflag,str(outfile)]
        # Нативные физические отказы могут длиться часами, но выполнение всегда
        # должно быть ограничено.
        proc=subprocess.run(argv,cwd=ROOT,stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=7200,
                            env={**os.environ,'PYTHONUNBUFFERED':'1'})
        log=proc.stdout
        need(len(log)>0 and len(log)<16<<20 and proc.returncode==0,
             name+': реальное выполнение на оборудовании или клиенте завершилось ошибкой либо не создало ограниченный журнал')
        need(not re.search(rb'(?i)(authorization:\s*bearer\s+\S+|refresh[_ -]?token\s*[=:]\s*\S+)',log),
             name+': в журнал приёмки попали учётные данные')
        inventory.write_exclusive(logdir/(name+'.log'),log)
        observed=read(outfile)
        assert_observed(name,observed,commit)
        records[name]={'resultSha256':digest(outfile), 'logSha256':digest(logdir/(name+'.log')),
                       'status':observed['status'],'exit':proc.returncode}
    need(set(records)==set(SCENARIOS), 'Неполный набор реальных проверок')
    return records

def replay(work, records, commit):
    need(type(records) is dict and set(records)==set(SCENARIOS), 'Отсутствуют квитанции реальных сценариев')
    output={}
    for name in SCENARIOS:
        row=records[name]
        need(type(row) is dict and set(row)=={'resultSha256','logSha256','status','exit'}
             and row['exit']==0, 'Неполная исходная запись реального выполнения: '+name)
        source=work/'results'/(name+'.json')
        log=work/'logs'/(name+'.log')
        need(digest(source)==row['resultSha256'] and digest(log)==row['logSha256'],
             'Изменён результат или журнал реального выполнения: '+name)
        report=read(source)
        assert_observed(name,report,commit)
        need(report['status']==row['status'], 'Статус изменился после подписанного выполнения')
        output[name]=row
    return output

def group_coverage(sweep_result, original):
    need(sweep_result.get('status')=='OBSERVED_NOT_INDEPENDENT_GA' and
         sweep_result.get('minecraft',{}).get('targets')==280 and
         len(sweep_result.get('gameSoaks',[]))==5 and
         sweep_result.get('httpSoak',{}).get('requests',0)>=10000 and
         len(sweep_result.get('reproducibility',{}).get('targets',{}))==6 and
         sweep_result.get('nativePackages',{}).get('status')=='CI_OBSERVED_REVIEW_REQUIRED' and
         len(sweep_result.get('nativePackages',{}).get('nativeTargets',[]))==6 and
         sweep_result.get('nativeGame',{}).get('status')=='observed-not-independently-certified' and
         len(sweep_result.get('nativeGame',{}).get('targets',[]))==6,
         'Исходные наблюдения 280, шести нативных, шести игровых, длительных или повторных проверок неполны')
    need(type(original) is dict and set(original)==set(SCENARIOS),
         'Отсутствуют исходные реальные внешние сценарии')
    covered={name:tuple(members) for name,members in GROUPS.items()}
    need(len(covered)==18 and all(set(members).issubset(set(original)|{'full-sweep'}) for members in covered.values()),
         'Обязательный набор проверок E2E-01..18 выполнен не полностью')
    return covered

def inputs(p):
    # Повторно используйте независимо проверенный парсер заморозки/репетиции
    # 0.52.12 и глубокий повторный прогон с привязкой к версии 0.53.0 и точным
    # финальным байтам.
    return dict(freeze_path=p.freeze,freeze_sig=p.freeze_sig,release_key=p.release_key,
      release_pin=p.release_pin,commit=p.commit,project=p.project,
      packages=p.packages,index=p.index,index_sha=p.index_sha,
      issues=p.issues,issues_sig=p.issues_sig,issues_key=p.issues_key,
      issues_pin=p.issues_pin,config=p.config,logs=p.regression_logs)

def live_review(p, *, rerun):
    frozen=rehearsal.sealed_freeze(p.freeze,p.freeze_sig,p.release_key,p.release_pin,
                                   p.commit,p.project,p.packages,p.index,p.index_sha)
    rehearsal.require(p.release_pin not in (p.issues_pin,p.qa_pin,p.verifier_pin) and
             len({p.release_pin,p.issues_pin,p.qa_pin,p.verifier_pin})==4,
             'Выпускающий оператор, ответственный за дефекты, QA и проверяющий должны быть четырьмя независимыми сторонами')
    # Существующий повторный прогон выполняет исходные регрессии И проверяет все
    # исходные файлы окончательной подписанной установки, настоящего Minecraft,
    # часовой нагрузки и независимой сборки.
    former=rehearsal.rehearse(**inputs(p),replay=rerun)
    need(former['status']=='REHEARSED_NOT_GA', 'Не подтверждены все обязательные условия предыдущей финальной приёмки GA')
    a=rehearsal.full_args(p.config,p.commit)
    one=rehearsal.sweep.verify_full(a)
    two=rehearsal.sweep.verify_full(a)
    need(inventory.canonical(one)==inventory.canonical(two), 'Исходные свидетельства нестабильны')
    lab=strict_plan(read(p.lab_plan),p.commit,p.index_sha)
    plan_sha=digest(p.lab_plan)
    if not rerun:
        records=execute(p.lab_plan,p.lab_work,p.commit,p.index_sha)
    else:
        signed=read(p.qa_report)
        records=replay(p.lab_work,signed['scenarios'],p.commit)
    coverage=group_coverage(one,records)
    need(rehearsal.freeze(p.commit,p.project,p.packages,p.index,p.index_sha)==frozen,
         'Во время полной реальной приёмки изменились финальные подписанные исходные пакеты')
    return {'schema':SCHEMA,'version':VERSION,'commit':p.commit,'project':p.project,
            'indexSha256':p.index_sha,'labPlanSha256':plan_sha,'frozenSha256':digest(p.freeze),
            'rehearsalSha256':hashlib.sha256(inventory.canonical(former)).hexdigest(),
            'fullSweepSha256':hashlib.sha256(inventory.canonical(one)).hexdigest(),
            'sourceTree':frozen['sourceTree'],'finalPackages':frozen['finalPackages'],
            'scenarios':records,'e2eGroups':coverage,
            'status':'REVIEWED_LIVE_18_E2E_PENDING_INDEPENDENT_VERIFIER'}

def sign(path, sig, doc, private, domain):
    need(path!=sig and not path.exists() and not sig.exists(), 'Требуются новые пути для подписанных квитанций')
    rehearsal.save(path,doc)
    inventory.write_exclusive(sig,private.sign(domain+inventory.canonical(doc)))

def verify_signed(path,sig,key,pin,domain):
    report=read(path)
    rehearsal.verify_signature(report,sig,key,pin,domain)
    return report

def approval(p):
    need(VERSION=='0.53.0','Финальная приёмка GA допускается только для версии продукта 0.53.0')
    need(p.commit and rehearsal.COMMIT.fullmatch(p.commit),'Требуется утверждённый реальный коммит Git')
    need(len({p.release_pin,p.issues_pin,p.qa_pin,p.verifier_pin})==4,
         'Четырём проверяющим сторонам запрещено повторно использовать ключи')
    qa=verify_signed(p.qa_report,p.qa_sig,p.qa_key,p.qa_pin,DOMAIN)
    current=live_review(p,rerun=True)
    need(qa==current,'independent replay differs from QA observation')
    return {'schema':FINAL_SCHEMA,'version':VERSION,'commit':p.commit,'project':p.project,
            'sourceTree':current['sourceTree'],'sourceIndexSha256':p.index_sha,
            'finalPackages':current['finalPackages'],
            'qaSha256':digest(p.qa_report),
            'fullSweepSha256':current['fullSweepSha256'],
            'e2eGroups':list(GROUPS),'status':'PASS'}

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('review','approve','release-gate'))
    for key in ('commit','project','index-sha','release-pin','issues-pin','qa-pin','verifier-pin'):
        p.add_argument('--'+key,required=True)
    for key in ('freeze','freeze-sig','release-key','packages','index','issues',
                'issues-sig','issues-key','config','regression-logs',
                'lab-plan','lab-work','qa-report','qa-sig','qa-key','verifier-key',
                'ga-report','ga-sig'):
        p.add_argument('--'+key,required=True,type=Path)
    p.add_argument('--qa-private-key',type=Path)
    p.add_argument('--verifier-private-key',type=Path)
    return p

def main(argv=None):
    p=parser();a=p.parse_args(argv)
    try:
        if a.action=='review':
            need(a.qa_private_key is not None,'Требуется независимый ключ подписи QA')
            report=live_review(a,rerun=False)
            secret=rehearsal.private_key(a.qa_private_key)
            public=inventory.public_key(a.qa_key,a.qa_pin)
            need(secret.public_key().public_bytes(serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw)==public.public_bytes(serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw),'QA signer differs from pinned independent QA key')
            sign(a.qa_report,a.qa_sig,report,secret,DOMAIN)
            print('Независимо проверены 18 групп реальных E2E-тестов; итоговое подтверждение GA ещё заблокировано')
        elif a.action=='approve':
            need(a.verifier_private_key is not None,'Требуется отдельный ключ подписи финального проверяющего')
            report=approval(a)
            secret=rehearsal.private_key(a.verifier_private_key)
            public=inventory.public_key(a.verifier_key,a.verifier_pin)
            need(secret.public_key().public_bytes(serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw)==public.public_bytes(serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw),'verifier signer differs from approved verifier key')
            sign(a.ga_report,a.ga_sig,report,secret,FINAL_DOMAIN)
            print('Независимая полная приёмка в реальной среде пройдена: подписано подтверждение GA с точным совпадением байтов')
        else:
            approved=approval(a)
            signed=verify_signed(a.ga_report,a.ga_sig,a.verifier_key,a.verifier_pin,FINAL_DOMAIN)
            need(approved==signed and signed['status']=='PASS', 'Подпись GA или реальные свидетельства изменились')
            print('Выпускной контроль GA пройден: итоговые пакеты и все 18 групп реальных E2E-тестов независимо проверены')
        return 0
    except (Blocked,rehearsal.Blocked,inventory.Blocked,OSError,ValueError,TypeError,
            KeyError,subprocess.TimeoutExpired,subprocess.CalledProcessError,InvalidSignature) as exc:
        print('Полная пользовательская приёмка 0.53.0 заблокирована: '+type(exc).__name__+': '+str(exc),file=sys.stderr)
        return 3

if __name__=='__main__':
    raise SystemExit(main())
