#!/usr/bin/env python3
"""Зафиксировать проверенный реальный E2E Minecraft, *уже выполненный* на нативном хосте.

Нельзя получить успешный результат из пустых main-классов или поддельного статуса лаунчера. До
выдачи точной корреляции с финальным пакетом проверяются настоящий клиент Mojang, загрузчик,
разрешения ServerBridge и свидетельства входа на Paper.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/release'))
from check_payload_0461 import inventory
from adversarial_pilot_05012 import verify_game
from guard_ga_0510 import Blocked, VERSION, TARGETS, LOADERS, COMMIT, require


def capture(work: Path, paper: Path, username: str, target: str, loader: str, commit: str,
            package: Path, release_bundle: Path) -> dict:
    require(target in TARGETS and loader in LOADERS and bool(COMMIT.fullmatch(commit)),
            'Требуются точная целевая нативная платформа, загрузчик и коммит исходников')
    host_os = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system())
    host_arch = {'x86_64': 'x64', 'AMD64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    require(f'{host_os}-{host_arch}' == target, 'Запись E2E Minecraft необходимо выполнять на целевой платформе')
    release = inventory(release_bundle)
    require(release['version'] == VERSION, 'Неверная версия итогового пакета выпуска')
    row = release['targets'][target]
    require(package.resolve() == (release_bundle / row['file']).resolve() and package.is_file()
            and not package.is_symlink(), 'Это не точный финальный подписанный установщик')
    from adversarial_pilot_05012 import file_hash
    require(file_hash(package) == row['sha256'], 'Готовый установщик изменён после проверки')
    game = verify_game(work, paper, username)
    require(game['loader'] == loader, 'Фактический загрузчик Minecraft отличается от запрошенного')
    require(paper.resolve() == (work / 'paper.log').resolve(),
            'Журнал подключения Paper необходимо сохранить вместе с точными игровыми свидетельствами')
    result = {'target': target, 'version': VERSION, 'loader': loader,
              'packageSha256': row['sha256'], 'username': username, 'commit': commit}
    output = work / 'run-identity.json'
    require(not output.exists(), 'Не перезаписывайте ранее сохранённый запуск игры')
    handle = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, 'w', encoding='utf-8') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--game-work', type=Path, required=True)
    p.add_argument('--paper-log', type=Path, required=True)
    p.add_argument('--username', required=True)
    p.add_argument('--target', choices=TARGETS, required=True)
    p.add_argument('--loader', choices=LOADERS, required=True)
    p.add_argument('--commit', required=True)
    p.add_argument('--installer', type=Path, required=True)
    p.add_argument('--release-bundle', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        result = capture(a.game_work, a.paper_log, a.username, a.target,
                         a.loader, a.commit, a.installer, a.release_bundle)
        print(json.dumps({'status': 'verified-real-game-captured', **result}))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Запись реальной игровой сессии Guard 0.51.0 заблокирована: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
