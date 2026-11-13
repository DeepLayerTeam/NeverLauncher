#!/usr/bin/env python3
"""Проверить *опубликованный* Java SDK Launcher через настоящий подпроцесс JVM Host.

Утилита НИКОГДА не компилирует потребителей на классах дерева src и не подписывает пакет. Доверие и
установка контролируются существующими CLI/Backend.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import zipfile
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / 'VERSION').read_text().strip()
MODULES = ('launcher-java-sdk-core', 'launcher-gravit-compat', 'launcher-api-sdk')
NS = {'m': 'http://maven.apache.org/POM/4.0.0'}


def run(*args: str, cwd: Path = ROOT, timeout: int = 75) -> None:
    subprocess.run(args, cwd=cwd, check=True, timeout=timeout)


def artifact_dir(repo: Path, module: str) -> Path:
    return repo / 'ru' / 'launcher' / module / VERSION


def verified_repo(repo: Path) -> dict[str, Path]:
    jars: dict[str, Path] = {}
    for module in MODULES:
        folder = artifact_dir(repo, module)
        stem = f'{module}-{VERSION}'
        for suffix in ('.jar', '-sources.jar', '-javadoc.jar', '.pom'):
            path = folder / (stem + suffix)
            if path.is_symlink() or not path.is_file():
                raise ValueError(f'Публикуемый артефакт отсутствует или небезопасен: {path}')
            content = path.read_bytes()
            for algo in ('sha256', 'sha512'):
                checksum = path.with_name(path.name + '.' + algo)
                if checksum.is_symlink() or not checksum.is_file() or checksum.read_text().strip() != getattr(hashlib, algo)(content).hexdigest():
                    raise ValueError(f'{algo}: несоответствие — {path.name}')
        pom = ET.parse(folder / f'{stem}.pom').getroot()
        val = lambda key: pom.findtext('m:' + key, namespaces=NS)
        if val('groupId') != 'ru.launcher' or val('artifactId') != module or val('version') != VERSION:
            raise ValueError(f'Некорректные координаты Maven для {module}')
        dependencies = {(x.findtext('m:artifactId', namespaces=NS), x.findtext('m:version', namespaces=NS))
                        for x in pom.findall('m:dependencies/m:dependency', namespaces=NS)}
        if module != 'launcher-java-sdk-core' and ('launcher-java-sdk-core', VERSION) not in dependencies:
            raise ValueError(f'Отсутствует основная зависимость для {module}')
        jar = folder / f'{stem}.jar'
        with zipfile.ZipFile(jar) as binary:
            members = binary.namelist()
            if len(members) != len(set(members)) or not any(m.endswith('.class') for m in members):
                raise ValueError(f'Некорректные или пустые классы в {jar}')
            for name in members:
                if name.startswith('/') or '..' in name.split('/') or '\\' in name:
                    raise ValueError(f'небезопасная запись в {jar}: {name}')
                if name.endswith('.class'):
                    header = binary.read(name)[:8]
                    if len(header) < 8 or header[:4] != b'\xca\xfe\xba\xbe' or int.from_bytes(header[6:8], 'big') > 61:
                        raise ValueError(f'Несовместимо с Java 17: {module}/{name}')
        jars[module] = jar
    return jars


def executable_from_public_sdk(core_jar: Path, extension_source: Path, output: Path, work: Path) -> None:
    classes = work / 'extension-classes'
    classes.mkdir()
    javac = str(Path(os.environ['JAVA_HOME']) / 'bin' / 'javac') if os.environ.get('JAVA_HOME') else 'javac'
    run(javac, '--release', '17', '-encoding', 'UTF-8', '-classpath', str(core_jar),
        '-d', str(classes), str(extension_source))
    with zipfile.ZipFile(core_jar) as core:
        payload = [(name, core.read(name)) for name in core.namelist()
                   if name.endswith('.class') or name.startswith('META-INF/services/')]
    for java_class in sorted(classes.rglob('*.class')):
        payload.append((java_class.relative_to(classes).as_posix(), java_class.read_bytes()))
    if len({name for name, _ in payload}) != len(payload):
        raise RuntimeError('Дублирующийся класс расширения перекрывает опубликованный Java SDK')
    sys.path.insert(0, str(ROOT))
    from scripts.ga.java_sdk_ga import deterministic_jar
    manifest = (b'Manifest-Version: 1.0\r\nMain-Class: ru.launcher.sdk.host.JavaExtensionHost\r\n'
                b'Launcher-Extension-Class: example.developer.DeveloperExtension\r\n\r\n')
    deterministic_jar(output, payload + [('META-INF/MANIFEST.MF', manifest)])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-repo', type=Path, default=ROOT / 'dist/java-sdk/maven')
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args()
    repo = args.sdk_repo.resolve()
    jars = verified_repo(repo)
    with tempfile.TemporaryDirectory(prefix='nl-java-e2e-04812-') as tmp:
        work = Path(tmp)
        fixture = ROOT / 'examples/extensions/java-developer-04812'
        sys.path.insert(0, str(ROOT))
        from scripts.java.build_developer_package import build
        package = work / 'package'
        jar = build(repo, package)
        with zipfile.ZipFile(jar) as built:
            if built.read('META-INF/MANIFEST.MF').find(b'JavaExtensionHost') == -1:
                raise AssertionError('Отсутствует настоящий главный класс Host')
            if not built.getinfo('example/developer/DeveloperExtension.class'):
                raise AssertionError('Отсутствует байт-код расширения')
        if (package/'cli/workspace.jar').read_bytes() != jar.read_bytes():
            raise AssertionError('CLI и Backend JAR должны использовать одинаковое подписанное содержимое')
        if not (package/'admin/index.html').is_file() or not (package/'desktop/index.html').is_file():
            raise AssertionError('Отсутствуют необходимые ресурсы интерфейса')
        run(sys.executable, str(ROOT/'examples/extensions/java-ui/test-runner.py'),
            str(jar), str(fixture/'launcher-extension.json'), timeout=65)
    report = {
        'version': VERSION, 'os': platform.system(), 'jdk': subprocess.check_output(['java', '-version'], stderr=subprocess.STDOUT, text=True).splitlines()[0],
        'modules': {module: hashlib.sha256(path.read_bytes()).hexdigest() for module, path in jars.items()},
        'checks': ['published jar/pom/sources/javadoc digests', 'Совместимость байткода классов с Java 17',
                   'Публичный граф зависимостей Maven', 'Внешний потребитель компилятора javac', 'Реальный дочерний процесс JVM Host',
                   'authenticated Admin/Desktop RPC', 'settings storage/validation',
                   'Отклонены неподписанное действие и недействительный токен', 'CLI command', 'graceful shutdown'],
        'passed': True,
        'note': 'Локальный аутентифицированный симулятор JVM; не подтверждает подписанную рабочую установку или нативную песочницу ОС',
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print('ПРОЙДЕНО: независимая проверка публичного SDK 0.48.12 на Java 17, хоста, удалённых вызовов панели администратора и настольного приложения, CLI и негативных сценариев безопасности')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, AssertionError, subprocess.CalledProcessError, subprocess.TimeoutExpired, zipfile.BadZipFile) as err:
        print(f'ОШИБКА: независимая сквозная проверка разработчика Java: {err}', file=sys.stderr)
        sys.exit(1)
