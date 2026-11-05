#!/usr/bin/env python3
"""Проверка нативных свидетельств приёмки 0.48.0 с блокировкой при неопределённости.

Квитанция об успехе никогда не создаётся. Входные данные берутся из независимо выполненного
нативного обновления, настоящего браузера Admin, SQL/Backend/ServerBridge и JVM-раннеров.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_VERSION = '0.48.0'
VERSIONS = {'0.45.14'} | {f'0.46.{n}' for n in range(4)} | {f'0.47.{n}' for n in range(9)}

class EvidenceError(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise EvidenceError(why)

def read(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 2*1024*1024, f'missing/unsafe receipt: {path}')
    obj = json.loads(path.read_text('utf-8'))
    require(isinstance(obj, dict), f'receipt is not an object: {path}')
    return obj

def files(root, entries):
    require(isinstance(entries, list) and entries and len(entries) == len(set(entries)), 'Список файлов свидетельств отсутствует или содержит повторы')
    for name in entries:
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9._/-]{1,160}', name), 'Небезопасное имя файла свидетельства')
        require(all(p not in ('', '.', '..') for p in name.split('/')), 'В имени свидетельства обнаружен выход за пределы каталога')
        f = root / name
        require(f.resolve().is_relative_to(root.resolve()) and f.is_file() and not f.is_symlink() and f.stat().st_size > 0, f'missing actual evidence: {name}')

def minecraft(root, version=EXPECTED_VERSION, *, matching=False, mc=None):
    value = read(root / 'result.json')
    require(value.get('status') == 'passed' and value.get('version') == version, 'Проверка игры для целевого выпуска не пройдена')
    game = value.get('minecraft') or {}
    require(game.get('client') == 'actual-mojang-client', 'Использование имитации игрового клиента запрещено')
    if mc is not None:
        require(game.get('version') == mc, 'Версия Minecraft не соответствует записи в матрице')
    checks = value.get('checks') or {}
    required = ('materialized','packageVerified','runtimeResolved','javaMatched','actualClient','matchingServer','serverVersionMatched','serverHealthy','clientJoinedServer') if matching else (
        'packageVerified','signedManifest','cleanSync','actualClient','paperJoin',
        'sessionRevokeDeny','realGameUpdateRollback','realWorldBackupRestore',
        'fabricServerBridge','forgeNeoForgeServerBridge')
    require(all(checks.get(k) is True for k in required), 'Проверки игры, Runtime или ServerBridge отсутствуют либо завершились неуспешно')
    if matching:
        proof = read(root / 'matching-server.json')
        require(proof.get('status') == 'passed' and proof.get('clientJoinedServer') is True and proof.get('actualClient') is True, 'Не подтверждено реальное подключение к подходящему серверу')
        require(game.get('serverVersion') == game.get('version'), 'Версии Minecraft на сервере и клиенте различаются')
    else:
        require(value.get('mode') == 'full' and game.get('paperJoin') == 'passed', 'Нет подтверждения полной подписанной сборки с реальным подключением к Paper')
        require((value.get('health') or {}).get('paper') == 'healthy', 'Сервер Paper не перешёл в исправное состояние')
        game_cycle = read(root / 'game-cycle-0364-result.json')
        require(game_cycle.get('status') == 'passed' and all(game_cycle.get('checks',{}).get(k) is True for k in (
          'productionGoTransactionalUpdate','updateMinecraftJVMJoin','productionGoTransactionalRollback','rollbackMinecraftJVMJoin')),
          'Не подтверждены обновление и откат рабочего клиента с подключением JVM')
        bridge = read(root / 'live-matrix-core-04113.json')
        require(bridge.get('status') in ('core-passed-not-full-matrix', 'passed') and bridge.get('passedCount') == 10, 'Матрица реальных проверок ServerBridge Core на 10 целевых окружениях не пройдена')
    files(root, value.get('evidence'))
    return value

def owner(path, version, commit):
    from importlib.util import spec_from_file_location, module_from_spec
    # Повторно используйте исходную независимо реализованную проверку из настоящего браузерного E2E.
    source = ROOT / 'e2e/scripts/owner-cycle-0390-browser.py'
    spec = spec_from_file_location('owner_cycle_0390', source)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    data = read(path)
    module.verify_receipt(data, version=version, commit=commit)
    return data

def legacy(path, version):
    data = read(path)
    require(data.get('status') == 'passed' and data.get('targetVersion') == version and data.get('type') == 'native-legacy-upgrade', 'Нативное обновление не сертифицировано')
    rows = data.get('results')
    require(isinstance(rows, list) and len(rows) == len(VERSIONS) and {x.get('version') for x in rows} == VERSIONS, 'Не все старые версии охвачены проверками')
    require(all(x.get('nativeVerified') is True and x.get('userDataVerified') is True
                and isinstance(x.get('beforeFiles'), int) and x['beforeFiles'] >= 2
                and isinstance(x.get('originalSha256'), str) and re.fullmatch('[a-f0-9]{64}', x['originalSha256'])
                and isinstance(x.get('oldExecutableSha256'), str) and re.fullmatch('[a-f0-9]{64}', x['oldExecutableSha256'])
                and isinstance(x.get('newExecutableSha256'), str) and re.fullmatch('[a-f0-9]{64}', x['newExecutableSha256'])
                for x in rows), 'Отсутствует обновлённый нативный исполняемый файл или проверка пользовательских данных')
    return data

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('type', choices=('full-game','matching-game','owner','legacy'))
    p.add_argument('--path', required=True, type=Path)
    p.add_argument('--version', default=EXPECTED_VERSION)
    p.add_argument('--commit', default='')
    p.add_argument('--minecraft-version')
    a = p.parse_args(argv)
    try:
        require(a.version == (ROOT / 'VERSION').read_text().strip(), 'Версия не совпадает с каноническим файлом VERSION')
        if a.type == 'full-game':
            minecraft(a.path, a.version, mc=a.minecraft_version)
        elif a.type == 'matching-game':
            minecraft(a.path, a.version, matching=True, mc=a.minecraft_version)
        elif a.type == 'owner':
            require(bool(re.fullmatch(r'[0-9a-f]{40}', a.commit)), 'Необходимо указать точный коммит исходников')
            owner(a.path, a.version, a.commit)
        else:
            legacy(a.path, a.version)
        print(f'0.48.0: фактические свидетельства проверены — {a.type}')
        return 0
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as e:
        print(f'0.48.0: свидетельства отклонены — {e}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
