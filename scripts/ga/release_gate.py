#!/usr/bin/env python3
"""Проверить *подписанные* свидетельства GA для шести платформ и описанные ими точные артефакты.

Принятую аттестацию может создать только разрешённый ключ подписи CI выпуска. Валидатор не создаёт
аттестации и не называет неподписанные пакеты GA. Свидетельства намеренно внешние к исходникам и
привязаны к одному точному SHA.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN = b"Launcher-GA-0.24.0-attestation-v1\n"
COMPONENT_GA_DOMAIN = b"Launcher-GA-0.25.0-optional-components-v1\n"
COMPONENT_GA_SCHEMA = "launcher.ga.optional-components.v1"
COMPONENT_GA_CHECKS = {
    "signed-catalog",
    "dependency-conflicts",
    "condition-boundaries",
    "signed-actions",
    "ownership-rollback",
    "selection-migration",
    "gravit-import",
    "native-adversarial",
    "fault-injection",
    "guard-live",
    "serverbridge-replay",
    "minecraft-real-launch",
}
TARGETS = {(p, a) for p in ("windows", "linux", "darwin") for a in ("amd64", "arm64")}
COMMON_CHECKS = {
    "os-signature",
    "installer-clean-machine",
    "managed-java-real",
    "minecraft-real-launch",
    "recovery-rollback",
    "powerloss-recovery",
    "runtime-certification",
    "baseline-benchmark",
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GITSHA = re.compile(r"^[a-f0-9]{40}$")


def strict_json(raw: bytes) -> dict:
    def reject_duplicates(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"Обнаружен дубликат: поле JSON: {key}")
            obj[key] = value
        return obj

    doc = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(doc, dict):
        raise ValueError("Для подтверждающие данные требуется: объект JSON")
    return doc


def load_attested_file(
    folder: Path, name: str, digest: str, *, binary: bool = False
) -> bytes:
    """Подходят только обычные файлы непосредственно в целевом каталоге."""
    if not name or Path(name).name != name or name in {".", ".."}:
        raise ValueError(f"Небезопасное значение: путь к артефакту: {name!r}")
    if not SHA256.fullmatch(digest):
        raise ValueError(f"Некорректное значение: «SHA-256 for» {name}")
    path = folder / name
    if folder.is_symlink() or path.is_symlink() or not path.is_file():
        raise ValueError(f"Отсутствует: «or symlinked file»: {path}")
    hasher = hashlib.sha256()
    raw = bytearray()
    total = 0
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            total += len(chunk)
            if total > 4 * 1024**3:
                raise ValueError(f"Артефакт превышает предельный размер 4 ГиБ: {name}")
            hasher.update(chunk)
            # Хешируйте бинарные установщики потоково. JSON-доказательства должны оставаться
            # небольшими; не держите многогигабайтные входы в памяти.
            if not binary:
                if len(raw) + len(chunk) > 8 * 1024 * 1024:
                    raise ValueError(f"Превышен допустимый размер: «evidence JSON»: {name}")
                raw.extend(chunk)
    if hasher.hexdigest() != digest:
        raise ValueError(f"Несовпадение: «content digest»: {name}")
    return bytes(raw)


def check_report(
    data: bytes, *, commit: str, version: str, subject: str, target: str = ""
) -> None:
    report = strict_json(data)
    if (
        report.get("commit") != commit
        or report.get("productVersion") != version
        or report.get("status") != "passed"
    ):
        raise ValueError(f"{subject}: отчёт реального выполнения неполный или содержит несовпадения")
    if report.get("simulated") or report.get("mocked"):
        raise ValueError(f"{subject}: симуляция или имитация выполнения не подтверждает готовность GA")
    if subject == "osSignature":
        if report.get("signatureVerified") is not True or not report.get(
            "trustedSigner"
        ):
            raise ValueError("Не проверены подпись операционной системы и закреплённый издатель")
    elif subject == "cleanMachine":
        if (
            report.get("schemaVersion") != "launcher.ga.clean-machine.v1"
            or not SHA256.fullmatch(report.get("javaSha256", ""))
            or not SHA256.fullmatch(report.get("logSha256", ""))
            or not report.get("minecraftVersion")
        ):
            raise ValueError("Отсутствуют реальные подтверждающие данные Minecraft и управляемой Java")
    elif subject == "certification":
        if (
            not report.get("gitTreeClean")
            or not report.get("suites")
            or report.get("unmetGates")
        ):
            raise ValueError("Полные наборы сертификационных тестов отсутствуют или не завершены")
        if any(s.get("status") != "passed" for s in report["suites"]):
            raise ValueError("Набор сертификационных тестов завершился ошибкой или был пропущен")
    elif subject in ("nativeRun", "minecraftRun", "guardRun", "bridgeRun"):
        if report.get("target") != target or report.get("actualExecution") is not True:
            raise ValueError(f"{subject}: отсутствует реальное выполнение или привязка к платформе")
        if subject == "nativeRun":
            if (
                report.get("signedManifestVersion") != "3.0"
                or report.get("catalogSchema") != "5.0"
                or not isinstance(report.get("httpRequests"), int)
                or report["httpRequests"] <= 0
            ):
                raise ValueError(
                    "Нативный Runtime компонентов не выполнил проверенную установку по HTTP"
                )
        elif subject == "minecraftRun":
            if report.get("actualClient") is not True or report.get("loader") not in (
                "vanilla",
                "fabric",
                "quilt",
                "forge",
                "neoforge",
            ):
                raise ValueError("Запуск Minecraft JVM не подтверждён")
        elif subject == "guardRun":
            if (
                report.get("kind") != "guard-live-attestation"
                or report.get("actualIntegration") is not True
            ):
                raise ValueError("Интеграция Guard в реальном окружении не подтверждена")
        else:
            if (
                report.get("kind") != "serverbridge-real-join-replay"
                or report.get("actualIntegration") is not True
            ):
                raise ValueError(
                    "Реальные тесты подключения и повторного воспроизведения ServerBridge не прошли проверку"
                )
    elif subject == "components":
        if (
            version != "0.25.0"
            or report.get("schemaVersion") != "launcher.components.certification.v1"
        ):
            raise ValueError("Неподдерживаемая схема сертификации необязательных компонентов")
        if report.get("target") != target or report.get("gitTreeClean") is not True:
            raise ValueError("Цель и источник сертификации необязательных компонентов не совпадают")
        if (
            report.get("signedManifestVersion") != "3.0"
            or report.get("catalogSchema") != "5.0"
        ):
            raise ValueError(
                "Для сертификации дополнительных компонентов отсутствует подписанный каталог v3/v5"
            )
        if (
            report.get("actualMinecraftClient") is not True
            or report.get("actualGuardIntegration") is not True
            or report.get("actualBridgeIntegration") is not True
        ):
            raise ValueError("Отсутствуют реальные подтверждающие данные Minecraft, Guard и Bridge")
        checks = report.get("checks")
        if not isinstance(checks, dict) or any(
            checks.get(c) != "passed" for c in COMPONENT_GA_CHECKS
        ):
            raise ValueError(
                "В сертификации дополнительных компонентов есть пропущенные или неуспешные проверки"
            )
        if not SHA256.fullmatch(report.get("nativeEvidenceSha256", "")):
            raise ValueError("Отсутствует дайджест подтверждения нативного выполнения")
        for section in ("minecraftEvidence", "guardEvidence", "bridgeEvidence"):
            reference = report.get(section)
            if (
                not isinstance(reference, dict)
                or not SHA256.fullmatch(reference.get("sha256", ""))
                or reference.get("target") != target
            ):
                raise ValueError(f"Дополнительные компоненты {section} не привязаны к целевой платформе")
    elif subject == "benchmark":
        if (
            not isinstance(report.get("runs"), list)
            or len(report["runs"]) < 6
            or report.get("speedup", 0) <= 1
        ):
            raise ValueError("Отсутствуют базовое измерение производительности или значение ускорения")
        if not SHA256.fullmatch(
            report.get("baselineExecutableSha256", "")
        ) or not SHA256.fullmatch(report.get("candidateExecutableSha256", "")):
            raise ValueError("Отсутствует: «real compiled baseline/candidate hashes»")
        if {r.get("implementation") for r in report["runs"]} != {
            "baseline",
            "candidate",
        }:
            raise ValueError("Нет сравнения производительности базовой и кандидатной версий")


def verify_target(folder: Path, key: Ed25519PublicKey, commit: str, version: str):
    data = folder / "attestation.json"
    sig = folder / "attestation.sig"
    if data.is_symlink() or sig.is_symlink():
        raise ValueError("Подтверждение через символическую ссылку не принимается")
    raw = data.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("Превышен допустимый размер: «signed GA attestation»")
    signature = bytes.fromhex(sig.read_text("ascii").strip())
    key.verify(
        signature, (COMPONENT_GA_DOMAIN if version == "0.25.0" else DOMAIN) + raw
    )
    doc = strict_json(raw)
    pair = (doc.get("platform"), doc.get("architecture"))
    if pair not in TARGETS or folder.name != "-".join(pair):
        raise ValueError(f"Неожиданное значение: «platform/architecture» {pair}")
    schema = (
        COMPONENT_GA_SCHEMA if version == "0.25.0" else "launcher.ga.attestation.v1"
    )
    if doc.get("schemaVersion") != schema or doc.get("status") != "passed":
        raise ValueError("Не поддерживается: «or incomplete signed attestation»")
    if doc.get("commit") != commit or doc.get("productVersion") != version:
        raise ValueError("Несовпадение: «attestation commit/version»")
    if doc.get("gitTreeClean") is not True:
        raise ValueError("Релиз должен собираться из чистого дерева исходников")
    checks = doc.get("checks")
    expected = COMMON_CHECKS | (
        {"windows-executable-lock"} if pair[0] == "windows" else set()
    )
    if version == "0.25.0":
        expected |= {
            "component-graph",
            "signed-actions",
            "migration",
            "serverbridge-plan-evidence",
            "minecraft-component-launch",
        }
    if not isinstance(checks, dict) or any(checks.get(c) != "passed" for c in expected):
        raise ValueError(
            f"Обязательные проверки доказательств отсутствуют или завершились ошибкой: {sorted(expected)}"
        )
    objects = doc.get("objects", {})
    required_objects = {
        "installer",
        "osSignature",
        "cleanMachine",
        "certification",
        "benchmark",
    }
    if version == "0.25.0":
        required_objects.update(
            {"components", "nativeRun", "minecraftRun", "guardRun", "bridgeRun"}
        )
    if not isinstance(objects, dict) or set(objects) != required_objects:
        raise ValueError(
            f"Требуется ровно {len(required_objects)} прикреплённых объектов артефактов и доказательств"
        )
    proofs = {}
    for name, obj in objects.items():
        if not isinstance(obj, dict):
            raise ValueError(f"Некорректный объект {name}")
        content = load_attested_file(
            folder, obj.get("file"), obj.get("sha256"), binary=name == "installer"
        )
        if name != "installer":
            check_report(
                content,
                commit=commit,
                version=version,
                subject=name,
                target=f"{pair[0]}-{pair[1]}",
            )
            proofs[name] = strict_json(content)
    installer_sha = objects["installer"]["sha256"]
    if version == "0.25.0":
        components = proofs["components"]
        # Отчёт компонента должен относиться к ЭТОМУ точному установщику, а не к
        # прежней проверенной сборке той же версии или коммита.
        if components.get("installerSha256") != installer_sha:
            raise ValueError("Сертификация компонентов относится к другому установщику")
        if components["nativeEvidenceSha256"] != objects["nativeRun"]["sha256"]:
            raise ValueError("«native run digest» не совпадает с «authenticated evidence»")
        for section, object_name in (
            ("minecraftEvidence", "minecraftRun"),
            ("guardEvidence", "guardRun"),
            ("bridgeEvidence", "bridgeRun"),
        ):
            if components[section]["sha256"] != objects[object_name]["sha256"]:
                raise ValueError(f"{section}: не совпадает контрольная сумма аутентифицированных данных")
    if (
        proofs["osSignature"].get("artifactSha256") != installer_sha
        or proofs["cleanMachine"].get("installerSha256") != installer_sha
    ):
        raise ValueError(
            "Подпись или доказательства чистой установки относятся к другому установщику"
        )
    for name in ("osSignature", "cleanMachine"):
        if (
            proofs[name].get("platform")
            != {"windows": "Windows", "linux": "Linux", "darwin": "Darwin"}[pair[0]]
        ):
            raise ValueError(f"{name}: платформа не совпадает")
    return pair, {
        "attestationSha256": hashlib.sha256(raw).hexdigest(),
        "installerSha256": objects["installer"]["sha256"],
        "platform": pair[0],
        "architecture": pair[1],
        "status": "passed",
    }


def verify_all(root: Path, public_key_hex: str, commit: str, version="0.24.0") -> dict:
    if not GITSHA.fullmatch(commit):
        raise ValueError("Необходимо указать точный 40-байтовый идентификатор коммита Git")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", public_key_hex):
        raise ValueError("trusted attestation key: требуется «32 raw bytes in hex»")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    results = []
    for platform, arch in sorted(TARGETS):
        folder = root / f"{platform}-{arch}"
        pair, result = verify_target(folder, key, commit, version)
        assert pair == (platform, arch)
        results.append(result)
    return {
        "schemaVersion": "launcher.ga.release.v1",
        "productVersion": version,
        "commit": commit,
        "status": "passed",
        "artifacts": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attestations", type=Path, required=True)
    p.add_argument("--trusted-attestation-public-key", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", default="0.24.0", choices=("0.24.0", "0.25.0"))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        result = verify_all(
            args.attestations,
            args.trusted_attestation_public_key,
            args.commit,
            version=args.version,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        InvalidSignature,
        json.JSONDecodeError,
    ) as exc:
        result = {
            "productVersion": args.version,
            "commit": args.commit,
            "status": "incomplete",
            "reason": str(exc),
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Проверка готовности GA-релиза: {result['status']}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
