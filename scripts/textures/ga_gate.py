#!/usr/bin/env python3
"""Валидатор независимо подписанных свидетельств GA Launcher 0.26.0 с блокировкой при неопределённости.

Утилита НИКОГДА не генерирует и не подписывает аттестации выпуска. Успешные модульные тесты,
самодекларированный JSON или удачный имитированный вход не сертифицируют выпуск.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

VERSION = "0.26.0"
SCHEMA = "launcher.textures.ga.v1"
DOMAIN = b"Launcher-Textures-GA-0.26.0-v1\n"
TARGETS = {
    f"{os}-{arch}"
    for os in ("linux", "windows", "darwin")
    for arch in ("amd64", "arm64")
}
REQUIRED_REPORTS = {
    "gameplay": (
        "clientStarted",
        "remoteObserverSawSkin",
        "classic",
        "slim",
        "cape",
        "cacheInvalidation",
    ),
    "official": (
        "microsoftOwned",
        "officialProfileVerified",
        "localIdentityIsolated",
        "skinUploadReset",
        "ownedCapeOnly",
    ),
    "backend": (
        "postgresql17",
        "realS3",
        "snapshotRestored",
        "gcRace",
        "gravitMigration",
        "signedTextures",
        "ssrfBlocked",
        "foreignUUIDBlocked",
    ),
    "desktop": (
        "nativeAppStarted",
        "skin2D",
        "skin3D",
        "cape3D",
        "progressCancel",
        "permissionFailures",
    ),
    "installer": (
        "builtFromSource",
        "osSignatureVerified",
        "cleanMachineInstall",
        "rollbackTested",
    ),
}
LOADER_SET = {"vanilla", "fabric", "neoforge"}
SHA = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")


class GateError(ValueError):
    pass


def strict_json(data: bytes) -> dict:
    def no_duplicate(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise GateError(f"Обнаружен дубликат: ключ JSON: {k}")
            out[k] = v
        return out

    value = json.loads(data, object_pairs_hook=no_duplicate)
    if type(value) is not dict:
        raise GateError("Отчёт не является объектом")
    return value


def read_file(
    base: Path,
    name: str,
    *,
    limit: int,
    expected: str | None = None,
    retain: bool = True,
) -> bytes:
    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or Path(name).name != name
    ):
        raise GateError("Небезопасное значение: «имя файла свидетельства»")
    if base.is_symlink():
        raise GateError("Каталог подтверждений является символической ссылкой")
    path = base / name
    if path.is_symlink() or not path.is_file():
        raise GateError(f"Файл доказательных данных отсутствует или небезопасен: {path}")
    if path.stat().st_size > limit:
        raise GateError(f"Слишком большой файл подтверждающих данных: {path}")
    hasher = hashlib.sha256()
    output = bytearray()
    size = 0
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            size += len(block)
            if size > limit:
                raise GateError(f"Слишком большой файл подтверждающих данных: {path}")
            hasher.update(block)
            if retain:
                output.extend(block)
    if expected is not None and (
        not SHA.fullmatch(expected) or hasher.hexdigest() != expected
    ):
        raise GateError(f"Несовпадение: «контрольная сумма SHA-256 свидетельства»: {path}")
    return bytes(output)


def check_report(report: dict, name: str, target: str, commit: str) -> None:
    if (
        report.get("schemaVersion") != f"launcher.textures.ga.{name}.v1"
        or report.get("productVersion") != VERSION
        or report.get("commit") != commit
        or report.get("target") != target
        or report.get("status") != "passed"
        or report.get("actualExecution") is not True
        or report.get("simulated") is not False
        or report.get("mocked") is not False
    ):
        raise GateError(f"{target}/{name}: отчёт не соответствует фактическому выполнению")
    for check in REQUIRED_REPORTS[name]:
        if report.get(check) is not True:
            raise GateError(f"{target}/{name}: проверка {check} не подтверждена")
    if name == "gameplay":
        loaders = report.get("loaders")
        if not isinstance(loaders, list) or not LOADER_SET.issubset(
            set(str(v) for v in loaders)
        ):
            raise GateError(
                f"{target}/gameplay: отсутствуют обязательные реальные загрузчики Minecraft"
            )
    if name == "installer" and not report.get("trustedOSSigner"):
        raise GateError(f"{target}/installer: отсутствует доверенный сертификат подписи ОС")


def verify_target(
    folder: Path, target: str, key: Ed25519PublicKey, commit: str
) -> dict:
    raw = read_file(folder, "attestation.json", limit=1024 * 1024)
    signature_hex = (
        read_file(folder, "attestation.sig", limit=256).decode("ascii").strip()
    )
    if not re.fullmatch(r"[0-9a-f]{128}", signature_hex):
        raise GateError(f"{target}: некорректная кодировка подписи Ed25519")
    try:
        key.verify(bytes.fromhex(signature_hex), DOMAIN + raw)
    except InvalidSignature as exc:
        raise GateError(f"{target}: недоверенное или изменённое подписанное подтверждение") from exc
    data = strict_json(raw)
    if (
        data.get("schemaVersion") != SCHEMA
        or data.get("productVersion") != VERSION
        or data.get("commit") != commit
        or data.get("target") != target
        or data.get("status") != "passed"
        or data.get("actualExecution") is not True
        or data.get("sourceTreeClean") is not True
    ):
        raise GateError(f"{target}: идентификатор или статус релиза не совпадает")
    try:
        recorded = datetime.fromisoformat(data["recordedAt"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError) as exc:
        raise GateError(f"{target}: отсутствует временная метка recordedAt") from exc
    age = (
        (datetime.now(timezone.utc) - recorded).total_seconds()
        if recorded.tzinfo
        else -1
    )
    if age < -300 or age > 60 * 60 * 24 * 90:
        raise GateError(f"{target}: подтверждение устарело или датировано будущим")
    reports = data.get("reports")
    if not isinstance(reports, dict) or set(reports) != set(REQUIRED_REPORTS):
        raise GateError(f"{target}: отсутствует обязательный отчёт с подтверждениями")
    for name, info in reports.items():
        if not isinstance(info, dict) or set(info) != {"file", "sha256"}:
            raise GateError(f"{target}/{name}: некорректное описание отчёта")
        report = strict_json(
            read_file(
                folder, info["file"], expected=info["sha256"], limit=2 * 1024 * 1024
            )
        )
        check_report(report, name, target, commit)
    # Настоящий установщик выпуска обязан существовать, быть привязанным дайджестом
    # к подписанной аттестации и иметь отдельно проверенные доказательства нативной
    # подписи ОС.
    installer = data.get("releaseArtifact")
    if not isinstance(installer, dict) or set(installer) != {"file", "sha256"}:
        raise GateError(f"{target}: отсутствует установщик релиза")
    read_file(
        folder,
        installer["file"],
        expected=installer["sha256"],
        limit=4 * 1024 * 1024 * 1024,
        retain=False,
    )
    return {
        "target": target,
        "installerSha256": installer["sha256"],
        "reports": sorted(reports),
    }


def verify(evidence: Path, commit: str, trusted_public_key: str) -> dict:
    if not COMMIT.fullmatch(commit):
        raise GateError("Коммит Git должен содержать 40 шестнадцатеричных символов в нижнем регистре")
    if not re.fullmatch("[a-f0-9]{64}", trusted_public_key):
        raise GateError("trusted independent Ed25519 public key: требуется «32 байта в шестнадцатеричном формате»")
    if evidence.is_symlink() or not evidence.is_dir():
        raise GateError("Каталог подтверждающих данных отсутствует или небезопасен")
    found = {p.name for p in evidence.iterdir()}
    if found != TARGETS:
        raise GateError(
            f"Для GA требуется ровно шесть независимых целей; отсутствуют={sorted(TARGETS - found)}, лишние={sorted(found - TARGETS)}"
        )
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key))
    checked = [
        verify_target(evidence / target, target, key, commit)
        for target in sorted(TARGETS)
    ]
    return {
        "schemaVersion": "launcher.textures.ga.verdict.v1",
        "status": "passed",
        "productVersion": VERSION,
        "commit": commit,
        "targets": checked,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description="Проверить внешние подписанные свидетельства GA текстур из реальной среды"
    )
    p.add_argument("--evidence", required=True, type=Path)
    p.add_argument("--commit", required=True)
    p.add_argument("--trusted-public-key", required=True)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    try:
        result = verify(args.evidence, args.commit, args.trusted_public_key)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print("Приняты независимые подписанные подтверждения GA для всех шести платформ")
        return 0
    except (GateError, ValueError, OSError, json.JSONDecodeError, UnicodeError) as exc:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                {
                    "schemaVersion": "launcher.textures.ga.verdict.v1",
                    "status": "incomplete",
                    "productVersion": VERSION,
                    "reason": str(exc),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"0.26.0: GA НЕ СЕРТИФИЦИРОВАНА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
