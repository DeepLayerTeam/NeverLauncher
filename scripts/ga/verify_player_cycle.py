#!/usr/bin/env python3
"""Требовать настоящий вход JVM Minecraft, обновление/откат и живые отрицательные ответы ServerBridge.

Валидатор использует точные результаты run-minecraft-e2e.sh, а не создаёт свидетельства успеха. Это
локальный/Yggdrasil шлюз игрока; независимая подписанная сертификация Microsoft online-mode остаётся
отдельным обязательным шлюзом.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from verify_game_cycle import verify as verify_game_cycle

CASES = {
    'uuid-mismatch': ('uuid', 'serverbridge_player_uuid_mismatch'),
    'invalid-uuid': ('uuid', 'serverbridge_player_uuid_invalid'),
    'project-mismatch': ('projectId', 'project_mismatch'),
    'profile-mismatch': ('profileId', 'profile_mismatch'),
    'channel-mismatch': ('channel', 'channel_mismatch'),
    'server-mismatch': ('serverId', 'serverbridge_node_server_id_mismatch'),
    'unissued-player': ('username', 'launcher_session_or_handoff_missing_or_expired'),
}
HEX32 = re.compile(r'[a-f0-9]{32}\Z')
HEX40 = re.compile(r'[a-f0-9]{40}\Z')
HEX64 = re.compile(r'[a-f0-9]{64}\Z')


def require(condition: bool, description: str) -> None:
    if not condition:
        raise ValueError(description)


def read_json(root: Path, name: str) -> dict:
    path = root / name
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 2_000_000,
            f'Отсутствует фактическое HTTP-свидетельство или его использование небезопасно: {name}')
    def strict(pairs):
        doc = {}
        for k, v in pairs:
            require(k not in doc, f'Повторяющееся поле JSON: {name}:{k}')
            doc[k] = v
        return doc
    doc = json.loads(path.read_text('utf-8'), object_pairs_hook=strict)
    require(type(doc) is dict, f'HTTP-свидетельство не является объектом: {name}')
    return doc


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_uuid(raw: object) -> str:
    require(type(raw) is str, 'Отсутствует UUID Minecraft')
    if len(raw) == 36:
        require(all(raw[i] == '-' for i in (8,13,18,23)), 'Некорректный UUID Minecraft')
        raw = raw.replace('-', '')
    raw = raw.lower()
    require(HEX32.fullmatch(raw) is not None, 'Некорректный UUID Minecraft')
    return raw


def verify(root: Path, version: str, source: str, run_id: str = '', run_attempt: str = '') -> dict:
    require(root.is_dir() and not root.is_symlink(), 'Не найден каталог реальных E2E-проверок')
    require(HEX40.fullmatch(source) is not None or HEX64.fullmatch(source) is not None,
            'Отсутствует точная фиксация исходного кода')
    base = verify_game_cycle(root, version, source, run_id, run_attempt)
    parent = read_json(root, 'result.json')
    require(parent.get('mode') == 'full' and parent.get('minecraft', {}).get('client') == 'actual-mojang-client' and
            parent.get('minecraft', {}).get('paperJoin') == 'passed' and
            parent.get('checks', {}).get('sessionRevokeDeny') is True,
            'Не подтверждены реальное подключение игрока и отзыв доступа')
    issued = read_json(root, 'join-paper-real-client.json')
    fresh = read_json(root, 'join-paper-real-client-fresh.json')
    require(issued.get('data', {}).get('oneTime') is True and
            fresh.get('data', {}).get('oneTime') is True and
            issued['data'].get('ticketId') != fresh['data'].get('ticketId'),
            'Реальный запуск не получил отдельный одноразовый билет')
    join = issued['data'].get('join', {})
    expected = {'username': join.get('username'), 'projectId': join.get('projectId'),
                'profileId': join.get('profileId'), 'channel': join.get('channel'),
                'serverId': join.get('serverId')}
    uuid = canonical_uuid(join.get('uuid'))
    require(expected == {'username': join['username'], 'projectId': 'e2e-project',
            'profileId': parent['minecraft']['profileId'], 'channel': 'stable',
            'serverId': 'paper-e2e-p3'} and expected['username'], 'Неожиданные тестовые данные игрока или сервера')
    proof = {}
    for case, (changed, reason) in CASES.items():
        name_req = f'player-0398-request-{case}.json'
        name_resp = f'player-0398-response-{case}.json'
        request = read_json(root, name_req)
        response = read_json(root, name_resp)
        status_file = root / f'player-0398-http-{case}.txt'
        require(status_file.is_file() and not status_file.is_symlink() and
                status_file.read_text('ascii') == '403\n',
                f'Отрицательный HTTP-сценарий вернул статус, отличный от 403: {case}')
        require(request.get('protocolVersion') == 2 and
                all(request.get(k) == v for k, v in expected.items() if k != changed),
                f'Неожиданные тестовые данные подписанного запроса: {case}')
        require(all(request.get(k) != expected.get(k) for k in [changed] if changed != 'uuid') and
                (canonical_uuid(request.get('uuid')) != uuid if changed == 'uuid' and case == 'uuid-mismatch' else True),
                f'Отрицательный сценарий не изменил ожидаемое поле: {case}')
        if changed != 'uuid':
            require(canonical_uuid(request.get('uuid')) == uuid, f'Неверный UUID в отрицательном сценарии {case}')
        if case == 'invalid-uuid':
            require(request.get('uuid') == 'not-a-minecraft-uuid', 'Отсутствует тестовый набор с некорректным UUID')
        require(request.get('pluginVersion') == version and
                HEX64.fullmatch(str(request.get('pluginSha256', ''))) is not None,
                f'Неверная версия или хеш фактического исполняемого файла Bridge: {case}')
        payload = response.get('data')
        require(type(payload) is dict and payload.get('allowed') is False and
                payload.get('reason') == reason and not payload.get('player') and
                payload.get('serverId') == request['serverId'] and
                payload.get('username') == request['username'],
                f'{case} Сервер не отклонил запрос с точной причиной отказа')
        proof[case] = {name_req: sha(root / name_req), name_resp: sha(root / name_resp),
                       status_file.name: sha(status_file)}
    allowed = read_json(root, 'validate-paper-e2e-p3-allow.json').get('data', {})
    denied = read_json(root, 'validate-paper-e2e-p3-deny.json').get('data', {})
    require(allowed.get('allowed') is True and
            canonical_uuid(allowed.get('player', {}).get('uuid')) == uuid and
            allowed.get('player', {}).get('username') == expected['username'] and
            denied.get('allowed') is False and
            denied.get('reason') in ('launcher_session_or_handoff_missing_or_expired',
                                     'launcher_session_missing_or_expired'),
            'Реальный билет использован отрицательным тестом, повтор запроса удался или UUID игрока изменился')
    # Настоящие подключение JVM к игре и откат независимо проверяются 0.36.4 по счётчикам, журналам,
    # подписанным манифестам, хешам бинарных файлов и идентичности исходников.
    require(type(base['artifactsVerified']) is int and base['artifactsVerified'] >= 20 and
            base['realJoinsAfterUpdateAndRollback'] is True, 'Игровой цикл не подтверждён')
    return {'status': 'verified', 'scope': 'real-local-Minecraft-player-negative-and-positive-0398',
            'version': version, 'sourceCommit': source, 'negativeCasesVerified': len(CASES),
            'expectedPlayerUUID': uuid, 'runtimeArtifactsVerified': base['artifactsVerified'],
            'evidenceSha256': proof, 'officialProviderLiveE2E': 'not-covered-by-local-runner'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--e2e-dir', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--run-id', default='')
    parser.add_argument('--run-attempt', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.e2e_dir, args.version, args.source_commit,
                                args.run_id, args.run_attempt), sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as err:
        print(f'[player-0398] ЗАБЛОКИРОВАНО: {err}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
