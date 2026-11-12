#!/usr/bin/env python3
"""Исполнитель настоящей приёмки Guard/Device Trust/ServerBridge 0.52.9.

Локальный режим запускает *производственные* Java и Guard JVM-процессы. Живой режим использует
ИСХОДНЫЕ закрытые журналы нативных компонентов/протокола/JVM и активно проверяет работающий Vanilla
sidecar, одновременно повторно проверяя десять других Docker JVM. Успех требует дальнейшего внешнего
рассмотрения и никогда не разрешает публиковать GA.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / 'VERSION').read_text().strip()
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
RUN = re.compile(r'[1-9][0-9]*\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
NATIVE = ('linux-x64','linux-arm64','windows-x64','windows-arm64','darwin-x64','darwin-arm64')

class Blocked(ValueError):
    pass

def require(condition, error):
    if not condition:
        raise Blocked(error)

def module(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    require(spec is not None and spec.loader is not None, 'Отсутствует реализация проверки: ' + relative)
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    return target

def secure_file(path, limit=8<<20):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Файл доказательств отсутствует или небезопасен: '+str(path))
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit,
            'Доказательство содержит жёсткую ссылку, пусто или превышает допустимый размер: ' + str(path))
    require(not any(parent.is_symlink() for parent in path.parents), 'Родительский каталог доказательств является символической ссылкой')
    return path

def read_json(path):
    def reject_duplicates(pairs):
        data = {}
        for key,value in pairs:
            require(key not in data, 'Повторяющийся ключ JSON доказательства: '+key)
            data[key] = value
        return data
    data = json.loads(secure_file(path).read_bytes(), object_pairs_hook=reject_duplicates,
                      parse_constant=lambda x: (_ for _ in ()).throw(Blocked('JSON доказательства содержит нечисловое значение')))
    require(type(data) is dict, 'Корневой элемент доказательств должен быть объектом JSON')
    return data

def sha(path):
    digest=hashlib.sha256()
    with secure_file(path, 2<<30).open('rb') as stream:
        for piece in iter(lambda: stream.read(1<<20), b''):
            digest.update(piece)
    return digest.hexdigest()

def run_command(argv, timeout=600):
    completed = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False)
    require(completed.returncode == 0 and len(completed.stdout) < 16<<20,
            'Проверка исполняемого файла не пройдена: ' + Path(argv[0]).name)
    return hashlib.sha256(completed.stdout).hexdigest()

def inspect_device(root, commit, run_id):
    device = module('scripts/device_trust/matrix.py', 'device_matrix_0529')
    targets = device.load_targets(ROOT / 'device-trust/targets.json')['targets']
    require(sum(x['required'] for x in targets) == 7, 'Изменён обязательный объём проверок доверия к устройству')
    found, errors = device.discover_results(root)
    require(not errors and set(found) == {t['id'] for t in targets},
            'Неполные, повторяющиеся или небезопасные результаты нативной проверки доверия к устройству')
    result = {}
    for target in targets:
        path, doc = found[target['id']]
        require(not path.is_symlink(), 'Результат проверки доверия к устройству является символической ссылкой')
        failures = device.verify_result(target, doc, result_path=path, commit=commit, run_id=run_id)
        require(not failures, target['id'] + ': '+ '; '.join(failures))
        # Матрица проверяет хеши; здесь также отклоняются жёсткие ссылки и символьные
        # ссылки в предках, которые другой процесс мог бы подменить.
        for name in doc['evidence']['files']:
            secure_file(path.parent / name, 2<<30)
        result[target['id']] = sha(path)
    return result

def inspect_guard_ci(root, commit, run_id, repository):
    guard = module('scripts/guard_ci/matrix.py', 'guard_matrix_0529')
    targets = guard.load_targets(ROOT / 'guard-ci/targets.json')['targets']
    require(len(targets) == 3 and all(t['required'] for t in targets), 'Набор целей Guard неполон')
    found, errors = guard.discover_results(root)
    require(not errors and set(found) == {t['id'] for t in targets}, 'Нативные результаты Guard отсутствуют или повторяются')
    out = {}
    for target in targets:
        path, data = found[target['id']]
        require(not path.is_symlink(), 'Результат Guard является символической ссылкой')
        failures = guard.verify_result(target, data, commit=commit, run_id=run_id, repository=repository)
        require(not failures, target['id'] + ': ' + '; '.join(failures))
        # Произвольный JSON со статусом «passed» и придуманными хешами пакетов НЕ является нативным
        # доказательством. Повторно хешируйте каждый исходный скомпилированный пакет и бинарный файл.
        for item in data['artifacts'].values():
            actual = secure_file(path.parent / item['name'], 2<<30)
            require(actual.stat().st_size == item['size'] and sha(actual) == item['sha256'],
                    target['id'] + ': исходный пакет или исполняемый файл Guard изменён либо отсутствует')
        out[target['id']] = sha(path)
    return out

def inspect_jvm(root):
    tests = module('scripts/guard_ci/adversarial_pilot.py', 'adversarial_0529')
    expected = {'loader-transformations','continuous-watchdog'}
    results = {}
    for native in NATIVE:
        run = read_json(root / native / 'result.json')
        suites = run.get('suites')
        names = set(expected)
        if native.startswith('linux-'):
            names |= {'runtime-integrity', 'linux-process-protection'}
        require(run.get('schema') == 'launcher.guard-adversarial-jvm/v1' and
                run.get('version') == VERSION and run.get('status') == 'PASS_JVM_REGRESSIONS_ONLY' and
                type(suites) is list and {x['name'] for x in suites} == names,
                native + ': отсутствуют реальные сценарии JVM Guard')
        for suite in suites:
            name = suite['name']
            require(suite.get('status') == 'PASS' and suite.get('exitCode') == 0 and
                    type(suite.get('testsRun')) is int and suite['testsRun'] >= suite.get('minimumTests',10**9) > 0,
                    native + '/' + name + ': тесты не пройдены')
            log = root / native / 'logs' / (name + '.log')
            require(suite.get('logFile') == log.name and suite.get('logSha256') == sha(log),
                    native + '/' + name + ': исходный вывод JVM отсутствует или изменён')
            output = secure_file(log, 32<<20).read_text(errors='replace')
            require(re.search(r'(?m)^OK\s*$', output) and
                    re.search(r'Ran \d+ tests? in [0-9.]+s', output),
                    native + '/' + name + ': нет успешного реального запуска unittest')
        results[native] = sha(root / native / 'result.json')
    return results

def inspect_serverbridge(runtime):
    live = module('serverbridge/live_matrix.py', 'serverbridge_live_0529')
    # Для всех 10 целей повторно проверьте идентичность процесса Docker, Bridge JAR, нативный журнал,
    # сетевые разрешение и запрет, а также реальное подключение Paper-клиента.
    targets = read_json(ROOT / 'serverbridge/targets.json')['targets']
    require(len(targets) == 14 and len({t['id'] for t in targets}) == 14, 'Изменён набор из 14 адаптеров')
    base = read_json(runtime / 'result.json')
    require(base.get('version') == VERSION and base.get('status') == 'passed' and
            base.get('mode') == 'full', 'Отсутствует полный реальный запуск Docker/Minecraft')
    outcome = {}
    for target in targets:
        if target['id'] not in live.CORE:
            continue
        proof = live.verify_runtime(target['id'], target, runtime, VERSION, 'E2EPlayer', ROOT)
        require(proof['status'] == 'passed', target['id'] + ': работа реального серверного окружения заблокирована')
        node_id, _ = live.CORE[target['id']]
        for kind in ('allow', 'deny'):
            name = ('runtime-launch-minecraft.json' if kind == 'allow' else 'probe-paper-deny.txt') if target['id'] == 'paper' else f'probe-{node_id}-{kind}.txt'
            secure_file(runtime / name, 32<<20)
        secure_file(runtime / f"live-{target['id']}-04113.log", 128<<20)
        outcome[target['id']] = sha(runtime / f"live-{target['id']}-04113.json")
    require(len(outcome) == 10, 'Отсутствуют 10 реальных адаптеров JVM/proxy')
    return outcome

def run_live(cfg):
    require(type(cfg) is dict and set(cfg) == {
        'sourceCommit','runId','repository','deviceResults','guardResults','guardJvmResults',
        'guardShadowDir','guardShadowKeyFile','guardIncidentReviews','frameBaseline','frameGuard',
        'gameRuntime','gameServerLog','player','serverbridgeRuntime','vanilla'},
        'В конфигурации реального запуска должны быть указаны все зависимости приёмки')
    commit, run_id, repo = cfg['sourceCommit'], cfg['runId'], cfg['repository']
    require(type(commit) is str and COMMIT.fullmatch(commit) and
            type(run_id) is str and RUN.fullmatch(run_id) and
            type(repo) is str and re.fullmatch(r'[A-Za-z0-9._/-]{3,150}', repo),
            'Реальный запуск должен быть привязан к точному коммиту, запуску CI и репозиторию')
    all_paths = {k: Path(cfg[k]) for k in ('deviceResults','guardResults','guardJvmResults','guardShadowDir',
                  'guardShadowKeyFile','guardIncidentReviews','frameBaseline','frameGuard','gameRuntime',
                  'gameServerLog','serverbridgeRuntime')}
    require(all(p.is_absolute() for p in all_paths.values()), 'Требуются абсолютные внешние пути к доказательствам')
    # Закрытый MAC-ключ отдельного сервера никогда не экспортируется в этот приёмочный отчёт.
    pilot = module('scripts/guard_ci/adversarial_pilot.py', 'shadow_0529')
    shadow = pilot.analyze_shadow(all_paths['guardShadowDir'], all_paths['guardShadowKeyFile'],
                                  all_paths['guardIncidentReviews'])
    require(shadow['status'] == 'EVIDENCE_REVIEW_REQUIRED' and
            shadow['unreviewedRevocations'] == 0 and
            not shadow['reviewed']['false_positive'] and not shadow['reviewed']['inconclusive'],
            'Проверка часов пилотной эксплуатации Guard или ложных срабатываний заблокирована')
    frames = pilot.compare_performance(all_paths['frameBaseline'], all_paths['frameGuard'])
    require(frames['status'] == 'PASS_MEASURED', 'Недопустимое ухудшение времени обработки кадров из-за Guard')
    game = pilot.verify_game(all_paths['gameRuntime'], all_paths['gameServerLog'], cfg['player'])
    require(game['status'] == 'EVIDENCE_VERIFIED_NOT_INDEPENDENT', 'Отсутствует реальный аутентифицированный вход в Minecraft')
    native = inspect_guard_ci(all_paths['guardResults'], commit, run_id, repo)
    devices = inspect_device(all_paths['deviceResults'], commit, run_id)
    jvm = inspect_jvm(all_paths['guardJvmResults'])
    # Вызывайте существующий производственный верификатор JAR, а не тестовую заглушку.
    release = run_command([sys.executable, str(ROOT / 'serverbridge/certify_release.py'),
                           '--artifacts', str(ROOT / 'artifacts/plugins')], timeout=180)
    bridge = inspect_serverbridge(all_paths['serverbridgeRuntime'])
    vanilla = module('scripts/acceptance/vanilla_sidecar_live.py', 'vanilla_0529')
    vanilla_result = vanilla.verify(cfg['vanilla'])
    # Три сборочные цели совместимости должны реально присутствовать в наборе производственных
    # JAR выпуска, а не получать статус Runtime лишь по сборочному тесту.
    return {'schema': 'launcher.guard-device-bridge-live/0.52.9', 'version': VERSION,
            'sourceCommit': commit, 'runId':run_id, 'repository':repo,
            'status':'LIVE_CHECKS_PASSED_REVIEW_REQUIRED', 'independentGA':False,
            'guard':{'nativeCi':native,'sixJvm':jvm,'shadow':shadow,'performance':frames,'game':game},
            'deviceTrust':{'targets':devices, 'nativeSecureStorageHardwareCertification':False},
            'serverBridge':{'tenRealRuntime':bridge,'threeBuildCompatibility':
                ['bukkit','quilt','sponge'], 'vanillaSidecar':vanilla_result,
                'productionJarVerificationOutputSha256':release},
            'reviewRequired':'Независимая проверка окончательных подписанных нативных пакетов, пилотных наблюдений, аппаратного защищённого хранилища и реальных сторонних сред выполнения',
            'completedAt':datetime.now(timezone.utc).isoformat()}

def run_local(output, only=None):
    import shutil
    require(shutil.which('java') is not None and shutil.which('javac') is not None,
            'Для тестов адаптеров Java необходим настоящий JDK')
    bridge = run_command(['bash',str(ROOT/'e2e/scripts/run-serverbridge-adapter-capabilities.sh')], timeout=120)
    guard = module('scripts/guard_ci/adversarial_pilot.py', 'adversarial_local_0529')
    result = guard.run_jvm_suites(output.parent / 'jvm-logs', only)
    require(result['status'] == 'PASS_JVM_REGRESSIONS_ONLY',
            'Реальные нативные регрессионные тесты JVM Guard не пройдены')
    complete = len(result['suites']) == 4 and all(x['status'] == 'PASS' for x in result['suites'])
    return {'schema':'launcher.guard-device-bridge-local/0.52.9', 'version':VERSION,
            'status':'LOCAL_REAL_JVM_REGRESSIONS_ONLY' if complete else 'LOCAL_PARTIAL_JVM_REGRESSIONS_NOT_GA', 'javaAdapterStdoutSha256':bridge,
            'guardJvm':result, 'independentGA':False}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('local','live'))
    parser.add_argument('--config',type=Path)
    parser.add_argument('--only-suite',action='append', choices=['loader-transformations','runtime-integrity','continuous-watchdog','linux-process-protection'])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        require(tuple(map(int, VERSION.split('.')[:3])) >= (0,52,9), 'Для Guard/Bridge требуется версия 0.52.9 или новее')
        require(args.mode == 'local' or args.config is not None, 'Требуется внешняя конфигурация реального запуска')
        report=run_local(args.output, set(args.only_suite) if args.only_suite else None) if args.mode=='local' else run_live(read_json(args.config))
        require(not args.output.exists() and args.output.is_absolute(), 'Требуется новый абсолютный путь вывода')
        args.output.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(json.dumps(report,ensure_ascii=False,indent=2).encode()+b'\n')
            stream.flush();os.fsync(stream.fileno())
        print(report['status'])
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired) as exc:
        print('Проверка Guard/Bridge 0.52.9 заблокирована: '+str(exc),file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
