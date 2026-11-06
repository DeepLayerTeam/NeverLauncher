#!/usr/bin/env python3
"""Независимый нативный исполнитель V10: свежий каталог задания, ограниченное исполнение, экспорт без секретов.

Это НАБЛЮДАТЕЛЬНЫЙ раннер. Он не подписывает и не загружает ValidationEvidence. Свидетельства
доверенного выполнения подписывает только независимый хост аттестации.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import hashlib
import re
from process_group_03410 import group_flags, kill_tree
from runtime_capabilities_03410 import host_identity

def requires_adversarial_acceptance(version: str) -> bool:
    match = re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?', version)
    if not match:
        raise ValueError('Некорректная версия продукта для нативной проверки')
    return tuple(map(int, match.groups())) >= (0, 43, 14)


PUBLIC_REPORTS=('host-capabilities.json','staged-execution.json','verified.json',
                'startup-readiness.json','server-readiness.json','gameplay-smoke.json',
                'adversarial-gameplay-04314.json', 'update-recovery.json')


def export_reports(work, destination):
    destination=Path(destination).resolve()
    destination.mkdir(parents=True,exist_ok=True)
    for name in PUBLIC_REPORTS:
        source=Path(work)/name
        if source.is_file() and not source.is_symlink() and source.stat().st_size<=2*1024*1024:
            # Экспортируйте только очищенный JSON из разрешённого списка, никогда — данные аутентификации,
            # гранты рабочих процессов, сырые журналы JVM, сеансы или приватные идентификаторы тестов.
            try:
                data=json.loads(source.read_text(encoding='utf-8'))
                if not isinstance(data,dict):continue
                if name=='staged-execution.json':
                    data={k:v for k,v in data.items() if k in
                          ('schemaVersion','runId','packageId','manifestSha256','artifactSha256',
                           'startedAt','finishedAt','stages')}
                    data['stages']={k:{'status':v.get('status'),
                        'detail':str(v.get('detail',''))[:240] if v.get('status')=='blocked'
                        and any(word in str(v.get('detail','')).lower() for word in
                                ('renderer','display','gui','headless','java','capability'))
                        else '[redacted]'} for k,v in data.get('stages',{}).items()}
                if name=='adversarial-gameplay-04314.json':
                    # Экспортируйте из одноразового рабочего процесса только ограниченные булевы
                    # результаты и дайджесты, никогда — сырой вывод команд или токены.
                    data={k:v for k,v in data.items() if k in
                          ('schemaVersion', 'manifestTamper', 'installedFileTamper')}
                    manifest=data.get('manifestTamper')
                    installed=data.get('installedFileTamper')
                    if (set(data)!={'schemaVersion','manifestTamper','installedFileTamper'} or
                        not isinstance(manifest,dict) or not isinstance(installed,dict) or
                        set(manifest)!={'status','baselineVerified','alteredManifestSha256'} or
                        set(installed)!={'status','filePath','baselineSha256','restoredFileSha256','restoredVerificationSha256'} or
                        not isinstance(installed.get('filePath'),str) or
                        '/' not in installed['filePath'] or len(installed['filePath'])>256 or
                        not all(isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)
                                for x in (manifest.get('alteredManifestSha256'), installed.get('baselineSha256'),
                                          installed.get('restoredFileSha256'), installed.get('restoredVerificationSha256')))):
                        continue
                    # Сохраняйте точные исходные байты, чтобы хеш в gameplay-smoke.json
                    # по-прежнему привязывал отрицательное наблюдение после очистки.
                    (destination/name).write_bytes(source.read_bytes())
                    continue
                if name=='host-capabilities.json':
                    data={k:v for k,v in data.items() if k not in ('host','user','environment')}
                # Не экспортируйте потенциально чувствительные данные аутентификации провайдера из
                # общей диагностики: централизованное удаление секретов выполняется V12.
                if name not in ('host-capabilities.json','staged-execution.json','verified.json',
                                'startup-readiness.json','server-readiness.json','gameplay-smoke.json',
                                'adversarial-gameplay-04314.json', 'update-recovery.json'):
                    continue
                (destination/name).write_text(json.dumps(data,indent=2),encoding='utf-8')
            except (OSError,ValueError,TypeError):
                continue


def verify_game_observations_04314(destination, expected_os, expected_arch):
    """Блокировать при неполных положительных/отрицательных нативных наблюдениях.

    Эти неподписанные наблюдения исполнителя НЕ являются учётными данными GA. Они нужны, чтобы
    отклонять пропущенные или не совпадающие нативные задания до независимой аттестации.
    """
    target=Path(destination)
    def read(name):
        path=target/name
        if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 2*1024*1024:
            raise ValueError("Отсутствуют данные наблюдения за нативной игрой: " + name)
        data=json.loads(path.read_bytes())
        if not isinstance(data,dict):
            raise ValueError("Некорректные данные наблюдения за нативной игрой: " + name)
        return data
    host=read('host-capabilities.json')
    if host.get('os') != expected_os or host.get('arch') != expected_arch or host.get('status') != 'ready':
        raise ValueError('Обнаружено несоответствие идентификатора или возможностей нативного хоста')
    staged=read('staged-execution.json')
    stages=staged.get('stages')
    mandatory=('manifest-files', 'materialization', 'startup', 'loader-readiness',
               'authentication','server-readiness','matching-server','gameplay-smoke','update-recovery')
    if not isinstance(stages,dict) or any(not isinstance(stages.get(s),dict) or stages[s].get('status')!='passed' for s in mandatory):
        raise ValueError('Отсутствуют успешные этапы реального игрового запуска')
    game=read('gameplay-smoke.json')
    negative=read('adversarial-gameplay-04314.json')
    proof=game.get('adversarialGameplay04314')
    raw=(target/'adversarial-gameplay-04314.json').read_bytes()
    if (not isinstance(proof,dict) or proof.get('status')!='passed' or
        proof.get('evidenceSha256')!=hashlib.sha256(raw).hexdigest() or
        proof.get('manifestTamperDenied') is not True or
        proof.get('installedFileTamperDeniedAndRestored') is not True or
        negative.get('schemaVersion')!='launcher.adversarial-gameplay.04314.v1' or
        negative.get('manifestTamper',{}).get('status')!='denied' or
        negative.get('installedFileTamper',{}).get('status')!='denied-and-restored' or
        negative.get('installedFileTamper',{}).get('baselineSha256') !=
        negative.get('installedFileTamper',{}).get('restoredFileSha256')):
        raise ValueError('Реальные отрицательные игровые проверки отсутствуют или не совпадают с ожидаемыми')
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('headless','gui'),required=True)
    parser.add_argument('--report-dir',required=True)
    parser.add_argument('--deadline-seconds',type=int,default=7200)
    parser.add_argument('--expected-os',choices=('windows','linux','macos'))
    parser.add_argument('--expected-arch',choices=('amd64','arm64'))
    parser.add_argument('--expected-version',default='')
    args,remainder=parser.parse_known_args()
    if bool(args.expected_os)!=bool(args.expected_arch):
        parser.error('ОС и архитектуру нативной платформы необходимо указывать вместе')
    if args.expected_version and requires_adversarial_acceptance(args.expected_version) and not args.expected_os:
        parser.error('Для нативной приёмки версии 0.43.14+ требуется явно указать ОС и архитектуру')
    if args.expected_os:
        ident=host_identity()
        if ident.get('os')!=args.expected_os or ident.get('arch')!=args.expected_arch or not ident.get('supported'):
            parser.error('ОС или архитектура физического исполнителя не соответствует запрошенной платформе')
    if args.expected_version:
        remainder += ['--expected-version', args.expected_version]
    if not 120<=args.deadline_seconds<=14400:
        parser.error('Ограничение времени должно составлять 120–14400 секунд')
    if remainder and remainder[0]=='--':remainder=remainder[1:]
    if not remainder or not {'--package-id','--backend','--cli','--runtime','--java','--pinned-public-key'} <= set(remainder):
        parser.error('Параметры поэтапного запуска должны включать пакет, Backend, CLI, Runtime, Java и ключ манифеста')
    if '--output' in remainder or '--execution-mode' in remainder:
        parser.error('Рабочий процесс самостоятельно определяет каталог вывода и режим выполнения')
    if Path(args.report_dir).exists() and any(Path(args.report_dir).iterdir()):
        parser.error('Каталог отчётов должен быть пустым')
    old_umask=os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='nl-validation-v10-') as root:
            work=Path(root)/'execution'
            invocation=[sys.executable,str(Path(__file__).parent/'run-staged-package-0342.py'),
                        *remainder,'--execution-mode',args.mode,'--output',str(work)]
            # Рабочий процесс наследует только окружение текущего задания. На общих хостах запускайте
            # его под отдельной учётной записью ОС или в VM без производственных секретов.
            proc=subprocess.Popen(invocation,stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**group_flags())
            try:
                rc=proc.wait(timeout=args.deadline_seconds)
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                proc.wait(timeout=20)
                rc=3
            finally:
                if proc.poll() is None:
                    kill_tree(proc)
                    proc.wait(timeout=20)
            export_reports(work,args.report_dir)
            if args.mode=='headless':
                report=Path(args.report_dir)/'staged-execution.json'
                if report.exists():
                    stages=json.loads(report.read_text())['stages']
                    if (stages.get('manifest-files',{}).get('status')=='passed' and
                        stages.get('materialization',{}).get('status')=='passed'):
                        print('Подготовка без графического интерфейса подтверждена; игровой процесс НЕ ПРОВЕРЕН (не PASS)')
                        return 3
            if rc:
                print('Нативное окружение не сертифицировано; см. статусы этапов в обезличенном отчёте',file=sys.stderr)
                return 3
            if args.expected_version and requires_adversarial_acceptance(args.expected_version):
                try:
                    verify_game_observations_04314(args.report_dir, args.expected_os, args.expected_arch)
                except (ValueError, OSError, TypeError, KeyError) as exc:
                    print('Нативная проверка игрового процесса заблокирована: ' + str(exc),file=sys.stderr)
                    return 3
            print('Наблюдательные проверки нативного окружения завершены; результат не является подписанным свидетельством')
            return 0
    finally:
        os.umask(old_umask)

if __name__=='__main__':
    sys.exit(main())
