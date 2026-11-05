#!/usr/bin/env python3
"""Приёмка выполненных кроссплатформенных проверок выпуска Launcher с блокировкой при неопределённости.

Свидетельства создаются run_integration_0310.py и собираются из CI-заданий. Успех не доказывает
полный паритет M01–M19 или настоящего Minecraft.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
from run_integration_0310 import CASES

COMMON = {
    "java-sdk",
    "jvm-host-e2e",
    "gravit-e2e",
    "trusted-agent-e2e",
    "devtools-e2e",
    "discord-ipc",
    "devtools-security",
    "sentry-backend",
    "asset-integrity",
    "sentry-release",
    "module-parity",
    "java-publication",
    "java-signed-fixtures",
}
REQUIRED = {
    "linux": COMMON
    | {"java-supervisor-go", "lan-security", "java-lifecycle-e2e", "java-runtime-e2e"},
    "darwin": COMMON | {"lan-security", "java-lifecycle-e2e", "java-runtime-e2e"},
    "windows": COMMON,
}
HASH = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")


def review(paths: list[Path], revision: str) -> dict:
    if not REVISION.fullmatch(revision):
        raise ValueError("Ожидается 40-символьный SHA коммита Git")
    found = {}
    digests = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Некорректное значение: файл подтверждающих данных: {path}")
        if path.stat().st_size > 512_000:
            raise ValueError(f"Слишком большой файл подтверждающих данных: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        platform = raw.get("platform")
        if platform not in REQUIRED or platform in found:
            raise ValueError(f"Неизвестное значение: «or duplicate platform»: {platform}")
        if (
            raw.get("schemaVersion") != "1.0"
            or raw.get("release") != "0.31.0"
            or raw.get("revision") != revision
        ):
            raise ValueError(f"Некорректная схема, релиз или рабочая копия в {path}")
        if raw.get("passed") is not True or raw.get("fullyCertified") is not False:
            raise ValueError(f"Неуспешный сценарий или неподтверждённое заявление о полной совместимости в {path}")
        results = raw.get("results")
        if (
            not isinstance(results, list)
            or {x.get("case") for x in results if isinstance(x, dict)}
            != REQUIRED[platform]
            or len(results) != len(REQUIRED[platform])
        ):
            raise ValueError(f"Обязательные сквозные тесты на {platform} выполнены не полностью")
        for case in results:
            expected_commands = CASES[case["case"]]
            if (
                case.get("status") != "passed"
                or not isinstance(case.get("steps"), list)
                or len(case["steps"]) != len(expected_commands)
            ):
                raise ValueError(
                    f"Тест E2E {case.get('case')} на {platform} завершился ошибкой или был пропущен"
                )
            for step, expected in zip(case["steps"], expected_commands):
                command = step.get("command")
                if not isinstance(command, list) or len(command) != len(expected):
                    raise ValueError(f"Неожиданное значение: «E2E command shape for» {case['case']}")
                for actual, required in zip(command, expected):
                    if required in ("{cli}", "{root}", "{parity}", "{maven}"):
                        if (
                            not isinstance(actual, str)
                            or not actual
                            or not __import__("pathlib").Path(actual).is_absolute()
                        ):
                            raise ValueError(
                                "Команда E2E содержит не абсолютный путь к этапу"
                            )
                    elif required == __import__("sys").executable:
                        if (
                            not __import__("pathlib")
                            .Path(str(actual))
                            .name.lower()
                            .startswith("python")
                        ):
                            raise ValueError("Несовпадение: «E2E Python interpreter»")
                    elif actual != required:
                        raise ValueError(f"Неожиданное значение: «E2E command for» {case['case']}")
                if (
                    step.get("status") != "passed"
                    or step.get("exitCode") != 0
                    or not HASH.fullmatch(str(step.get("outputSha256", "")))
                ):
                    raise ValueError(
                        f"Некорректные или неуспешные данные выполнения дочернего процесса: {case['case']}"
                    )
        found[platform] = len(results)
        # Утверждение подписывает точные байты доказательств, а не только число успешных тестов.
        digests[platform] = hashlib.sha256(path.read_bytes()).hexdigest()
    if set(found) != set(REQUIRED):
        raise ValueError(
            f"Отсутствуют обязательные операционные системы: {sorted(set(REQUIRED) - set(found))}"
        )
    return {
        "release": "0.31.0",
        "revision": revision,
        "crossPlatformIntegrationGatesPassed": True,
        "upstreamGravitParityCertified": False,
        "realMinecraftLoaderCertificationIncluded": False,
        "caseCounts": found,
        "evidenceSha256": digests,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="Каталог с отчётами трёх ОС",
    )
    p.add_argument("--revision", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    # Не переходите по символьным ссылкам внутри собираемого дерева доказательств.
    if args.evidence.is_symlink():
        p.error("Каталог подтверждающих данных не должен быть символической ссылкой")
    paths = sorted(args.evidence.rglob("integration-0310.json"))
    try:
        result = review(paths, args.revision)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        "Межплатформенные интеграционные проверки версии 0.31.0 пройдены (это не подтверждает функциональную равнозначность исходному проекту)"
    )


if __name__ == "__main__":
    main()
