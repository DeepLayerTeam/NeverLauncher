#!/usr/bin/env python3
"""Adapt verified real live-join evidence to the historical matching-server schema."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from live_join import file_sha256, read_json, require, run_binding, SHA


def report(runtime: Path, minecraft: str, java_major: int, target: str) -> dict:
    live = read_json(runtime / 'live-join.json')
    install_path = runtime / 'matching-server-install.json'
    install = read_json(install_path)
    cert = runtime / 'vanilla-certification.json'
    require(live.get('schema') == 'launcher.compatibility-live-join/0.52.4'
            and live.get('status') == 'passed' and live.get('targetId') == target
            and all(live.get(k) == v for k, v in run_binding().items())
            and live.get('minecraftVersion') == minecraft and live.get('loader') == 'vanilla'
            and live.get('javaMajor') == java_major
            and all(live.get(k) is True for k in ('playerJoined', 'playerOnlineViaRcon', 'worldTicksAdvanced')),
            'Серверное подтверждение реального подключения отсутствует или не соответствует цели')
    require(install.get('status') == 'installed-and-verified' and install.get('minecraftVersion') == minecraft
            and install.get('javaMajorVersion') == java_major
            and SHA.fullmatch(str(install.get('sha256', ''))) is not None
            and install['sha256'] == live.get('serverArtifactSha256'),
            'Подтверждение установки сервера Mojang не совпадает')
    for field, name in (('serverLogSha256', 'matching-server.log'),
                        ('clientCertificationSha256', cert.name),
                        ('witnessSha256', 'live-server-witness.json'),
                        ('serverStoppedSha256', 'live-server-stopped.json')):
        require(live.get(field) == file_sha256(runtime / name), 'Изменилось свидетельство: ' + name)
    matching = {
        'schemaVersion': '1.0', 'status': 'passed', 'minecraftVersion': minecraft,
        'clientVersion': minecraft, 'serverVersion': minecraft, 'javaMajor': java_major,
        'serverHost': '127.0.0.1', 'serverPort': live['serverPort'],
        'serverProcessAlive': True,  # alive through the witness, then stopped cleanly
        'serverVersionMatched': True, 'clientJoinedServer': True, 'actualClient': True,
        'clientConnectPort': live.get('clientConnectPort', live['serverPort']), 'serverLog': 'matching-server.log',
        'serverArtifactEvidence': 'vanilla-server-install.json',
        'liveJoinSha256': file_sha256(runtime / 'live-join.json'),
    }
    result = read_json(runtime / 'result.json')
    require(result.get('status') == 'passed' and result.get('targetId') == target,
            'Результат фактического клиента отсутствует')
    shutil.copyfile(install_path, runtime / 'vanilla-server-install.json')
    (runtime / 'matching-server.json').write_text(json.dumps(matching, indent=2) + '\n', encoding='utf-8')
    result['checks'].update({k: True for k in ('matchingServer', 'serverVersionMatched', 'serverHealthy', 'clientJoinedServer', 'liveMultiplayerJoin')})
    result['minecraft'].update(server='actual-mojang-server', serverVersion=minecraft, matchingServer='passed')
    result['evidence'] = list(dict.fromkeys(result['evidence'] + ['vanilla-server-install.json', 'matching-server.json', 'matching-server.log', 'live-join.json', 'live-server-witness.json', 'live-server-ready.json', 'live-server-stopped.json', 'live-server-execution.log']))
    (runtime / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return matching


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--minecraft', required=True)
    parser.add_argument('--java-major', type=int, required=True)
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    report(args.runtime, args.minecraft, args.java_major, args.target)
