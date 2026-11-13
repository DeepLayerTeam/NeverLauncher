#!/usr/bin/env python3
"""Собрать настоящий неподписанный пакет Java-разработчика из опубликованных Maven JAR SDK.

Результат подходит для `nl extension pack --private-key ...`; скрипт намеренно не утверждает наличие
доверенной подписи и не устанавливает пакет.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.java.developer_e2e import (verified_repo, executable_from_public_sdk)


def build(repository: Path, destination: Path) -> Path:
    base = ROOT / 'examples/extensions/java-developer-04812'
    manifest = json.loads((base/'launcher-extension.json').read_text())
    allowed = {'backend/workspace.jar', 'cli/workspace.jar', 'admin/index.html', 'desktop/index.html'}
    if {t['entrypoint'] for t in manifest['targets']} != allowed:
        raise ValueError('В манифесте примера обнаружены неожиданные целевые платформы')
    if destination.exists() and (destination.is_symlink() or any(destination.iterdir())):
        raise ValueError('Выходной каталог должен быть новым или пустым')
    jars = verified_repo(repository.resolve())
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='java-dev-build-04812-') as tmp:
        backend = destination/'backend/workspace.jar'
        backend.parent.mkdir(parents=True)
        executable_from_public_sdk(jars['launcher-java-sdk-core'], base/'src/main/java/example/developer/DeveloperExtension.java', backend, Path(tmp))
    cli = destination/'cli/workspace.jar'
    cli.parent.mkdir(parents=True)
    shutil.copyfile(backend, cli)
    for kind in ('admin', 'desktop'):
        path = destination/kind
        path.mkdir(parents=True)
        shutil.copyfile(base/kind/'index.html', path/'index.html')
    shutil.copyfile(base/'launcher-extension.json', destination/'launcher-extension.json')
    return backend


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sdk-repo', type=Path, default=ROOT/'dist/java-sdk/maven')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        build(args.sdk_repo, args.output.resolve())
        print(f'ПРОЙДЕНО: реальный неподписанный пакет расширения Java готов к подписанию: {args.output}')
    except (OSError, RuntimeError, ValueError) as e:
        sys.exit(f'ОШИБКА: {e}')
