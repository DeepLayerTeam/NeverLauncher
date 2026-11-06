#!/usr/bin/env python3
"""Независимо подписанное разрешение GA по точным байтам для каждой цели всех GA-выпусков.

Вызывается ПОСЛЕ подготовки НАСТОЯЩИХ установщиков и ДО штатного подписанта выпуска. Квитанция RC,
неподписанный CI-артефакт или заявленный статус сами по себе не разрешают GA. Подпись оператора
должна связывать настоящие хеши пакета и исполняемого файла, а также девять независимых реальных
приёмочных записей на каждую поставляемую платформу/архитектуру. Начиная с 0.40.0 одобрение
дополнительно привязывает шесть полных пользовательских сценариев (оба режима идентификации, граф
компонентов, текстуры и восстановление) к точному упакованному клиенту, а не только к собранному из
исходников Desktop.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import policy
from security_capabilities_0431 import checks as security_checks, verify_all as verify_security

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = policy("0.36.0").signing_domain  # экспортируется для прежних считывателей версии 0.36.0
TARGETS = (
    "windows-x64",
    "windows-arm64",
    "linux-x64",
    "linux-arm64",
    "darwin-x64",
    "darwin-arm64",
)
CHECKS = (
    "nativeInstall",
    "desktopLaunch",
    "minecraftLaunch",
    "serverJoin",
    "releaseRollback",
    "security",
    "performance",
    "operations",
    "osSignature",
)
PLAYER_CHECKS_0400 = (
    "componentPresetInstall",
    "skinCapeGameRender",
    "localYggdrasilJoin",
    "officialOnlineModeJoin",
    "identityNegativeAndReplay",
    "playerUpdateRollback",
)
PLAYER_OBSERVATIONS_0400 = {
    "componentPresetInstall": (
        "dependenciesResolved",
        "conflictsDenied",
        "presetInstalled",
    ),
    "skinCapeGameRender": ("skinRendered", "capeRendered", "modelVerified"),
    "localYggdrasilJoin": (
        "sessionJoinVerified",
        "serverUUIDMatches",
        "serverAccepted",
    ),
    "officialOnlineModeJoin": (
        "microsoftIdentityVerified",
        "onlineModeVerified",
        "serverUUIDMatches",
        "serverAccepted",
    ),
    "identityNegativeAndReplay": (
        "wrongUUIDDenied",
        "foreignProjectDenied",
        "replayedTicketDenied",
        "crossRealmDenied",
    ),
    "playerUpdateRollback": ("updateJVMJoin", "rollbackJVMJoin", "userFilesPreserved"),
}


def checks_for(version: str) -> tuple[str, ...]:
    # Приёмка игрока по точным байтам и платформам — новое требование стабильного выпуска;
    # исторические подписанные форматы остаются проверяемыми без изменений.
    from release_policy import parsed

    number, _ = parsed(version)
    baseline = CHECKS + PLAYER_CHECKS_0400 if number >= (0, 40, 0) else CHECKS
    return baseline + security_checks(version)


def verify_player_trace(
    trace: dict, check: str, item: dict, target: str, evidence: Path
) -> None:
    # Одобрение оператора только для собранного исполняемого файла не доказывает прохождение
    # игроком цикла в поставленном установщике. Для каждого этапа требуйте один и тот же
    # реально установленный пакет и связанную запись исполнения.
    require(
        set(trace)
        == {
            "schemaVersion",
            "version",
            "commit",
            "target",
            "kind",
            "status",
            "actualExecution",
            "simulated",
            "artifactSha256",
            "executionId",
            "packageSha256",
            "playerCycleId",
            "evidenceSha256",
        },
        target + ": неполный журнал игрока для финального пакета " + check,
    )
    require(
        trace["packageSha256"] == item["packageSha256"]
        and isinstance(trace["playerCycleId"], str)
        and re.fullmatch(r"[a-zA-Z0-9._:-]{16,128}", trace["playerCycleId"]) is not None
        and isinstance(trace["evidenceSha256"], str)
        and SHA.fullmatch(trace["evidenceSha256"]) is not None,
        target + ": Проверка игрового клиента не связана с реальным запуском итогового пакета: " + check,
    )
    # Подписанная трассировка должна ссылаться на независимо сохранённый живой вывод оператора, а не
    # просто заявлять успех. Хешируйте сырые доказательства и журналы процессов; манифесты выпуска,
    # созданные в памяти, не считаются журналами исполнения.
    folder = evidence / "targets" / target / "player-0400"
    require(
        folder.is_dir() and not folder.is_symlink(),
        target + ": Отсутствует каталог свидетельств реального запуска игрового клиента",
    )
    report_path = folder / (check + ".json")
    report = read_json(report_path)
    require(
        sha(report_path) == trace["evidenceSha256"],
        target + ": Контрольная сумма подписанного свидетельства работы клиента не совпадает: " + check,
    )
    require(
        set(report)
        == {
            "schemaVersion",
            "version",
            "commit",
            "target",
            "kind",
            "status",
            "playerCycleId",
            "binarySha256",
            "packageSha256",
            "observed",
            "runtimeLogSha256",
        },
        target + ": Неверный формат отчёта о реальном запуске клиента: " + check,
    )
    for key, wanted in (
        ("schemaVersion", "launcher.player.final.0400.v1"),
        ("version", trace["version"]),
        ("commit", trace["commit"]),
        ("target", target),
        ("kind", check),
        ("status", "passed"),
        ("playerCycleId", trace["playerCycleId"]),
        ("binarySha256", item["binarySha256"]),
        ("packageSha256", item["packageSha256"]),
    ):
        require(
            report.get(key) == wanted,
            target + ": Несоответствие поля реального выполнения " + key + ": " + check,
        )
    required = PLAYER_OBSERVATIONS_0400[check]
    observed = report["observed"]
    require(
        type(observed) is dict
        and set(observed) == set(required)
        and all(observed[name] is True for name in required),
        target + ": Результат реального запуска клиента отсутствует или отрицателен: " + check,
    )
    log_path = folder / (check + ".log")
    require(
        log_path.is_file()
        and not log_path.is_symlink()
        and 0 < log_path.stat().st_size <= 32 * 1024 * 1024
        and isinstance(report["runtimeLogSha256"], str)
        and SHA.fullmatch(report["runtimeLogSha256"]) is not None
        and sha(log_path) == report["runtimeLogSha256"],
        target + ": Журнал реального выполнения отсутствует, повреждён или не подписан: " + check,
    )


SHA = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
LIMIT = 1024 * 1024


class Blocked(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def read_file(path: Path, max_size=LIMIT) -> bytes:
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < path.stat().st_size <= max_size,
        "Файл отсутствует, является символической ссылкой, пуст или слишком велик: " + str(path),
    )
    return path.read_bytes()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Blocked("Обнаружен дубликат: «поле JSON:»" + key)
        result[key] = value
    return result


def read_json(path: Path):
    value = json.loads(read_file(path), object_pairs_hook=object_pairs)
    require(isinstance(value, dict), "Корневое значение JSON должно быть объектом")
    return value


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def utc(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
        "Метка времени должна быть в UTC с точностью до секунды",
    )
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def paths(version, target):
    osname, arch = target.split("-")
    binaries = {
        "windows": f"launcher-desktop-windows-{arch}.exe",
        "linux": f"launcher-desktop-linux-{arch}",
        "darwin": f"launcher-desktop-macos-{arch}",
    }
    packages = {
        "windows": f"launcher-desktop-{version}-windows-{arch}.zip",
        "linux": f"launcher-linux-{arch}-{version}.tar.gz",
        "darwin": f"launcher-desktop-{version}-macos-{arch}.zip",
    }
    return binaries[osname], packages[osname]


def approval_data(
    evidence: Path, public_key: Path, version: str, commit: str, *, now=None
):
    """Криптографическая предварительная проверка до подготовки пакета; полная проверка байтов — после сборки."""
    cfg = policy(version)
    require(
        cfg.ga_mode in ("legacy-ga036", "signed-ga-v2")
        and COMMIT.fullmatch(commit) is not None,
        "Требуются неизменная политика финального выпуска и точный 40-символьный SHA Git",
    )
    key_raw = read_file(public_key, 4096).strip()
    # Явный открытый ключ Ed25519 в шестнадцатеричном формате, никогда не приватный ключ и не самоподписант GitHub CI.
    require(
        re.fullmatch(rb"[0-9a-fA-F]{64}", key_raw) is not None,
        "Доверенный независимо закреплённый ключ оператора должен содержать 32 байта открытого ключа (hex)",
    )
    raw = read_file(evidence / "approval.json")
    signature_hex = read_file(evidence / "approval.sig", 256).strip()
    require(
        re.fullmatch(rb"[a-fA-F0-9]{128}", signature_hex) is not None,
        "Отсутствует каноническая 64-байтная подпись подтверждения Ed25519",
    )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_raw.decode())).verify(
            bytes.fromhex(signature_hex.decode()), cfg.signing_domain + raw
        )
    except InvalidSignature as exc:
        raise Blocked("Некорректное значение: «подпись оператора»") from exc
    data = json.loads(raw, object_pairs_hook=object_pairs)
    require(
        isinstance(data, dict)
        and set(data)
        == {
            "schemaVersion",
            "version",
            "commit",
            "issuedAtUtc",
            "expiresAtUtc",
            "targets",
        },
        "Поля подтверждения неполны или содержат неожиданные значения",
    )
    require(
        data["schemaVersion"] == cfg.approval_schema
        and data["version"] == version
        and data["commit"] == commit,
        "Подтверждение относится к другому выпуску или коммиту",
    )
    timestamp = now or datetime.now(timezone.utc)
    require(
        utc(data["issuedAtUtc"]) <= timestamp <= utc(data["expiresAtUtc"])
        and (utc(data["expiresAtUtc"]) - utc(data["issuedAtUtc"])).total_seconds()
        <= 7 * 86400,
        "Подтверждение финального выпуска истекло, датировано будущим или имеет слишком долгий срок действия",
    )
    return data, raw, key_raw


def verify(
    bundle: Path,
    evidence: Path,
    public_key: Path,
    version: str,
    commit: str,
    *,
    now=None,
    run_id=None,
    run_attempt=None,
):
    cfg = policy(version)
    data, raw, key_raw = approval_data(evidence, public_key, version, commit, now=now)
    # Полная GA требует всех подписанных живых доказательств безопасности текущего запуска,
    # а не одной подписи деклараций или ранее одобренных целей.
    verify_security(evidence, data, now=now, run_id=run_id, run_attempt=run_attempt)
    targets = data["targets"]
    require(
        isinstance(targets, list)
        and len(targets) == 6
        and {row.get("target") for row in targets if isinstance(row, dict)}
        == set(TARGETS),
        "Все шесть целевых платформ выпуска должны иметь независимое подтверждение; неполный комплект финального выпуска запрещён",
    )
    # Не отправляйте незаметно седьмую платформу или неверный псевдоним архитектуры.
    require(
        bundle.is_dir() and not bundle.is_symlink(),
        "Требуется реальный каталог подготовки выпуска",
    )
    # Выпуск с неуказанным платформенным пакетом не является одобренным подмножеством.
    permitted = {name for target in TARGETS for name in paths(version, target)}
    # Совместимые составные пакеты также поставляет build-release.sh; соответствующие
    # файлы x64/ARM64 по-прежнему требуют одобрения точных байтов.
    permitted.update(
        {
            f"launcher-desktop-{version}-windows-amd64.zip",
            f"launcher-desktop-{version}-macos-universal.zip",
        }
    )
    for artifact in bundle.iterdir():
        name = artifact.name
        if (
            name.startswith("launcher-desktop-windows-")
            or name.startswith("launcher-desktop-linux-")
            or name.startswith("launcher-desktop-macos-")
            or name.startswith("launcher-linux-")
            or name.startswith(f"launcher-desktop-{version}-windows-")
            or name.startswith(f"launcher-desktop-{version}-macos-")
        ):
            # Прочие общие и устаревшие платформенные результаты остаются под контролем прежнего CLI
            # выпуска; в GA допускаются только пакеты соответствующей архитектуры.
            if name not in permitted and (
                name.endswith(".zip")
                or name.endswith(".tar.gz")
                or name.endswith("-riscv64")
                or name.endswith("-riscv64.exe")
            ):
                raise Blocked("Обнаружен неутверждённый дополнительный артефакт целевой платформы: " + name)
    records = []
    for target in sorted(TARGETS):
        item = next(row for row in targets if row["target"] == target)
        require(
            set(item) == {"target", "status", "binarySha256", "packageSha256", "checks"}
            and item["status"] == "certified"
            and isinstance(item["checks"], dict)
            and set(item["checks"]) == set(checks_for(version)),
            target + ": Неполная целевая платформа финального выпуска",
        )
        binary_name, package_name = paths(version, target)
        binary = bundle / binary_name
        package = bundle / package_name
        for path in (binary, package):
            require(
                path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                target + ": Отсутствует реальный упакованный исполняемый файл или установщик",
            )
        for field, path in (("binarySha256", binary), ("packageSha256", package)):
            require(
                SHA.fullmatch(item[field]) is not None and sha(path) == item[field],
                target
                + ": Подписанное подтверждение не соответствует точному содержимому поставки: "
                + field,
            )
        cycle_ids = set()
        for check in checks_for(version):
            meta = item["checks"][check]
            require(
                isinstance(meta, dict)
                and set(meta) == {"sha256"}
                and isinstance(meta["sha256"], str)
                and SHA.fullmatch(meta["sha256"]) is not None,
                target + ": Отсутствует независимо подтверждённый " + check,
            )
            trace_path = evidence / "targets" / target / (check + ".json")
            require(
                trace_path.resolve().is_relative_to(evidence.resolve())
                and not trace_path.parent.is_symlink(),
                target + ": Небезопасный каталог трассировки",
            )
            trace = read_json(trace_path)
            require(
                sha(trace_path) == meta["sha256"], target + ": журнал событий изменился " + check
            )
            if check in security_checks(version):
                # Уже проверено на предварительном этапе подписанного одобрения, включая сырые события
                # исполнения и идентичность финального пакета в рамках запуска.
                pass
            elif check in PLAYER_CHECKS_0400 and check in checks_for(version):
                verify_player_trace(trace, check, item, target, evidence)
                cycle_ids.add(trace["playerCycleId"])
            elif check not in security_checks(version):
                require(
                    set(trace)
                    == {
                        "schemaVersion",
                        "version",
                        "commit",
                        "target",
                        "kind",
                        "status",
                        "actualExecution",
                        "simulated",
                        "artifactSha256",
                        "executionId",
                    },
                    target + ": Недопустимые поля трассировки " + check,
                )
            if check in security_checks(version):
                continue
            require(
                trace["schemaVersion"] == cfg.execution_schema
                and trace["version"] == version
                and trace["commit"] == commit
                and trace["target"] == target
                and trace["kind"] == check
                and trace["status"] == "passed"
                and trace["actualExecution"] is True
                and trace["simulated"] is False
                and trace["artifactSha256"] == item["binarySha256"]
                and isinstance(trace["executionId"], str)
                and re.fullmatch(r"[a-zA-Z0-9._:-]{8,128}", trace["executionId"]),
                target + ": Проверка не подтверждает фактически одобренный исполняемый файл: " + check,
            )
        if PLAYER_CHECKS_0400[0] in checks_for(version):
            require(
                len(cycle_ids) == 1,
                target + ": Нельзя объединять несвязанные запуски клиента для получения положительного результата",
            )
        records.append(
            {
                "target": target,
                "binary": binary_name,
                "binarySha256": item["binarySha256"],
                "package": package_name,
                "packageSha256": item["packageSha256"],
                "checksPassed": len(checks_for(version)),
                **({"securityCapabilitiesVerified": list(security_checks(version))}
                   if security_checks(version) else {}),
            }
        )
    return {
        "schemaVersion": cfg.receipt_schema,
        "version": version,
        "commit": commit,
        "status": "approved-for-release-signing",
        "approvalSha256": hashlib.sha256(raw).hexdigest(),
        "operatorPublicKeySha256": hashlib.sha256(
            bytes.fromhex(key_raw.decode())
        ).hexdigest(),
        "targets": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Проверить подписанную идентичность до затратной сборки; НЕ одобрение GA",
    )
    args = parser.parse_args()
    if args.output:
        args.output.unlink(missing_ok=True)
    try:
        if args.preflight:
            approval, _, _ = approval_data(args.evidence, args.trusted_key, args.version, args.commit)
            verify_security(args.evidence, approval)
            print(
                f"{args.version}: Предварительная проверка подписанной личности оператора пройдена; точное совпадение байтов ЕЩЁ НЕ проверено"
            )
            return 0
        require(
            args.output is not None, "Для проверки точного совпадения байтов необходим параметр --output"
        )
        require(
            args.bundle is not None, "Для проверки точного совпадения байтов необходим параметр --bundle"
        )
        receipt = verify(
            args.bundle, args.evidence, args.trusted_key, args.version, args.commit
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    except (Blocked, OSError, ValueError, TypeError, KeyError, InvalidSignature) as exc:
        print(f"{args.version} Финальный выпуск ЗАБЛОКИРОВАН: " + str(exc), file=sys.stderr)
        return 3
    print(
        f"{args.version}: Все шесть платформ с точным совпадением байтов независимо подписаны и подтверждены"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
