#!/usr/bin/env python3
"""Скомпилировать ТРИ независимых расширения из опубликованных бинарных артефактов Java SDK.

Запускаются настоящие JVM-интеграционные подпроцессы (Admin/Desktop/CLI, content SPI, versioned
library SPI). Не заявляется сертификация установленных подписанных пакетов, PostgreSQL, Go RBAC или
нативной песочницы. Каталоги классов SDK из дерева исходников никогда не попадают в classpath javac.
Сеть не нужна.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.java.developer_e2e_04812 import verified_repo, run
from scripts.ga.java_sdk_ga_0310 import deterministic_jar
from scripts.java.package_dependencies_0482 import bundle

FIXTURES = ROOT / 'examples/extensions'


def binary_jar(core: Path, sources: list[Path], main: str, dest: Path,
               work: Path, additional_classpath: list[Path] | None = None) -> None:
    """Без скрытого classpath или фонового build/classes; только байты внешнего SDK."""
    classes = work / 'compiled'
    classes.mkdir(parents=True)
    cp = os.pathsep.join([str(core), *map(str, additional_classpath or [])])
    run('javac', '--release', '17', '-encoding', 'UTF-8', '-cp', cp,
        '-d', str(classes), *map(str, sources))
    with zipfile.ZipFile(core) as jar:
        payload = [(name, jar.read(name)) for name in jar.namelist()
                   if name.endswith('.class') or name.startswith('META-INF/services/')]
    payload.extend((source.relative_to(classes).as_posix(), source.read_bytes())
                   for source in sorted(classes.rglob('*.class')))
    if len(set(name for name, _ in payload)) != len(payload):
        raise ValueError('Расширение переопределяет опубликованные классы SDK')
    manifest = (f'Manifest-Version: 1.0\r\nMain-Class: ru.launcher.sdk.host.JavaExtensionHost\r\n'
                f'Launcher-Extension-Class: {main}\r\n\r\n').encode()
    deterministic_jar(dest, payload + [('META-INF/MANIFEST.MF', manifest)])


def verify_one(case: str, jar: Path, evidence: dict) -> None:
    with zipfile.ZipFile(jar) as data:
        assert data.testzip() is None, 'Повреждённый JAR-файл'
        assert 'ru/launcher/sdk/host/JavaExtensionHost.class' in data.namelist()
    run(sys.executable, str(FIXTURES / case / 'test-runner.py'), cwd=ROOT, timeout=70)
    evidence[case] = {'jarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
                      'status': 'passed', 'runtime': 'Реальный дочерний процесс Java, имитация Host'}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sdk-repo', type=Path, required=True)
    ap.add_argument('--report', type=Path)
    args = ap.parse_args()
    sdk = verified_repo(args.sdk_repo.resolve())
    core = sdk['launcher-java-sdk-core']
    evidence = {}
    with tempfile.TemporaryDirectory(prefix='never-deep-java-0490-') as td:
        work = Path(td)
        # Стенды проверяют реальное исполнение java -jar с обратными вызовами,
        # heartbeat, CLI, загрузкой пакета и жизненным циклом. Созданные JAR
        # записываются только в игнорируемые каталоги example/build.
        ui = FIXTURES / 'java-ui'
        jar = ui / 'build/package/backend/workspace.jar'
        jar.parent.mkdir(parents=True, exist_ok=True)
        binary_jar(core, [ui/'src/example/ui/WorkspaceExtension.java'],
                   'example.ui.WorkspaceExtension', jar, work/'ui')
        cli = ui / 'build/package/cli/workspace.jar'
        cli.parent.mkdir(parents=True, exist_ok=True)
        cli.write_bytes(jar.read_bytes())
        verify_one('java-ui', jar, evidence)

        content = FIXTURES / 'java-content-spi'
        jar = content / 'build/package/backend/content-spi.jar'
        jar.parent.mkdir(parents=True, exist_ok=True)
        binary_jar(core, [content/'src/example/content/ContentExtension.java'],
                   'example.content.ContentExtension', jar, work/'content')
        cli = content / 'build/package/cli/content-spi.jar'
        cli.parent.mkdir(parents=True, exist_ok=True)
        cli.write_bytes(jar.read_bytes())
        verify_one('java-content-spi', jar, evidence)

        spi = FIXTURES / 'java-spi'
        libclasses = work/'libclasses'
        libclasses.mkdir()
        run('javac', '--release', '17', '-encoding', 'UTF-8', '-d', str(libclasses),
            str(spi/'src/example/terms/Terms.java'))
        terms = work/'terms.jar'
        deterministic_jar(terms, [(p.relative_to(libclasses).as_posix(), p.read_bytes())
                                  for p in libclasses.rglob('*.class')])
        host = work/'host.jar'
        binary_jar(core, sorted((spi/'src/example/spi').glob('*.java')),
                   'example.spi.GreetingExtension', host, work/'spi', [terms])
        jar = spi/'build/package/backend/java-spi.jar'
        bundle(host, jar, [f'org.example:spi-terms@1.0.0@>=1.0.0 <2.0.0@{terms}'])
        cli = spi/'build/package/cli/java-spi.jar'
        cli.parent.mkdir(parents=True, exist_ok=True)
        cli.write_bytes(jar.read_bytes())
        verify_one('java-spi', jar, evidence)

    report = {
        'version': (ROOT/'VERSION').read_text().strip(),
        'status': 'local-subprocess-pass',
        'sdk': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name,path in sdk.items()},
        'extensions': evidence,
        'notCertified': ['Установка подписанного пакета .nlext в производственной конфигурации', 'Реальная авторизация и отзыв разрешений через брокер Go',
                         'Обновление и откат PostgreSQL', 'OS sandbox', 'Minecraft E2E',
                         'cross-platform Java 17/21 and independent CI'],
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print('ПРОЙДЕНО: три независимых расширения опубликованного SDK запущены в реальных подпроцессах JVM (хост имитируется)')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AssertionError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        sys.exit('ОШИБКА: 0.49.0 — независимая интеграция с подпроцессом Java: '+str(e))
