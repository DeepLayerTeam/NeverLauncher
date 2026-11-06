#!/usr/bin/env python3
"""Проверить финальные пакеты для шести платформ по независимо подписанному одобрению GA.

`certify` выполняется ДО подписи манифеста выпуска. `dry-run` копирует подписанный выпуск в
изолированный каталог публикации и запускает настоящий CLI-валидатор публикации на копии. Ни одно
действие не загружает и не продвигает выпуск.
"""

from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ga"))
from verified_targets import Blocked, TARGETS, paths, sha, verify, require
from release_policy import requires_rehearsal

SCHEMA = "launcher.release.rehearsal.v1"
SHA = re.compile("[a-f0-9]{64}\\Z")
MAX_ENTRIES = 25000
MAX_UNCOMPRESSED = 4 * 1024**3


def architecture(content: bytes, target: str) -> None:
    system, arch = target.split("-")
    if system == "windows":
        require(
            len(content) >= 0x40 and content[:2] == b"MZ", "Файл не является исполняемым файлом Windows"
        )
        offset = struct.unpack_from("<I", content, 0x3C)[0]
        require(
            offset >= 0x40
            and offset + 24 <= len(content)
            and content[offset : offset + 4] == b"PE\0\0",
            "bad PE header",
        )
        actual = struct.unpack_from("<H", content, offset + 4)[0]
        require(
            actual == {"x64": 0x8664, "arm64": 0xAA64}[arch], "Неверная архитектура PE-файла"
        )
        # IMAGE_DIRECTORY_ENTRY_SECURITY содержит таблицу сертификатов Authenticode. Само
        # её наличие НЕ подтверждает цепочку доверия: нативная проверка подписи Windows/ОС
        # делает это и подписывает результат в независимых трассах GA.
        opt = offset + 24
        magic = struct.unpack_from("<H", content, opt)[0]
        require(magic == 0x20B and opt + 144 <= len(content), "PE32+ required")
        cert_offset, cert_size = struct.unpack_from("<II", content, opt + 112 + 4 * 8)
        require(
            cert_offset > 0
            and cert_size >= 8
            and cert_offset + cert_size <= len(content),
            "Отсутствует таблица сертификатов Authenticode",
        )
    elif system == "linux":
        require(
            len(content) >= 20 and content[:6] == b"\x7fELF\x02\x01",
            "Требуется ELF64 с порядком байтов little endian",
        )
        require(
            struct.unpack_from("<H", content, 18)[0] == {"x64": 62, "arm64": 183}[arch],
            "Неверная архитектура ELF",
        )
    else:
        require(
            len(content) >= 32 and content[:4] == b"\xcf\xfa\xed\xfe",
            "Требуется 64-разрядный Mach-O",
        )
        require(
            struct.unpack_from("<I", content, 4)[0]
            == {"x64": 0x01000007, "arm64": 0x0100000C}[arch],
            "Неверная архитектура Mach-O",
        )
        ncmds = struct.unpack_from("<I", content, 16)[0]
        size = struct.unpack_from("<I", content, 20)[0]
        require(0 < ncmds <= 200 and 32 + size <= len(content), "Недопустимые команды Mach-O")
        cursor = 32
        signed = False
        for _ in range(ncmds):
            require(cursor + 8 <= 32 + size, "Недопустимый размер команды Mach-O")
            cmd, length = struct.unpack_from("<II", content, cursor)
            require(
                length >= 8 and cursor + length <= 32 + size, "Усечённая команда Mach-O"
            )
            if cmd == 0x1D:
                require(length >= 16, "Неполная команда подписи кода")
                off, length_sig = struct.unpack_from("<II", content, cursor + 8)
                require(
                    off > 0 and length_sig > 0 and off + length_sig <= len(content),
                    "Некорректная подпись кода Mach-O",
                )
                signed = True
            cursor += length
        require(signed, "Отсутствует подпись кода macOS")


def safe_members(members: dict[str, bytes]) -> None:
    require(
        len(members) <= MAX_ENTRIES
        and sum(map(len, members.values())) <= MAX_UNCOMPRESSED,
        "Превышено ограничение размера архива или количества элементов",
    )
    seen = set()
    for name in members:
        path = PurePosixPath(name)
        require(
            name not in seen
            and not name.startswith("/")
            and "\\" not in name
            and all(x not in ("", ".", "..") for x in name.split("/"))
            and not path.is_absolute(),
            "Повторяющийся или небезопасный элемент архива: " + name,
        )
        seen.add(name)


def unpack(path: Path) -> dict[str, bytes]:
    result = {}
    total = 0
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for meta in archive.infolist():
                if meta.is_dir():
                    continue
                mode = (meta.external_attr >> 16) & 0o170000
                require(
                    mode != 0o120000 and not meta.flag_bits & 1,
                    "В архиве обнаружена символьная ссылка или зашифрованный элемент",
                )
                require(
                    meta.filename not in result and meta.file_size <= MAX_UNCOMPRESSED,
                    "В архиве обнаружен повторяющийся или слишком большой элемент",
                )
                total += meta.file_size
                require(
                    total <= MAX_UNCOMPRESSED and len(result) < MAX_ENTRIES,
                    "Превышено ограничение распаковки архива",
                )
                result[meta.filename] = archive.read(meta)
    else:
        require(path.name.endswith(".tar.gz"), "Неподдерживаемый формат установщика")
        with tarfile.open(path, mode="r:gz") as archive:
            for meta in archive:
                if meta.isdir():
                    continue
                require(meta.isfile() and meta.name not in result, "Небезопасный элемент архива TAR")
                total += meta.size
                require(
                    total <= MAX_UNCOMPRESSED and len(result) < MAX_ENTRIES,
                    "Превышено ограничение распаковки TAR",
                )
                reader = archive.extractfile(meta)
                require(reader is not None, "Невозможно прочитать элемент архива TAR")
                result[meta.name] = reader.read()
    safe_members(result)
    return result


def verify_update_payload_0410(
    members: dict[str, bytes], manifest: dict, system: str, arch: str, version: str
) -> None:
    """Проверить, что *поставляемый* обновляющий компонент может использовать именно этот установщик.

    Успешно подписанный установщик с устаревшим манифестом обновлений нельзя безопасно исправить или
    откатить. Внешняя подпись GA связывает пакет; эта проверка независимо сверяет внутренний граф
    байтов установки/обновления.
    """
    prefix = {"windows": "", "linux": "launcher/", "darwin": "Launcher.app/"}[system]
    manifest_member = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_UPDATE_MANIFEST.json"
    )
    require(
        manifest_member in members,
        "Отсутствует установленный манифест обновления компонентов: " + manifest_member,
    )
    update_bytes = members[manifest_member]
    update = json.loads(update_bytes, object_pairs_hook=_no_dupes)
    require(
        isinstance(update, dict)
        and update.get("schemaVersion") == "1.0"
        and update.get("product") == "Launcher"
        and update.get("productVersion") == version
        and update.get("architecture") == arch
        and update.get("platform") == {"darwin": "macos"}.get(system, system),
        "Идентификатор манифеста обновления установленного компонента не совпадает",
    )
    require(
        update.get("layout")
        == ("macos-app-bundle" if system == "darwin" else "adjacent-files"),
        "Структура манифеста обновления установленного компонента не соответствует ожидаемой",
    )
    expected_roles = {
        "desktop": "desktop-launcher",
        "guard": "guard",
        "runtime": "runtime",
    }
    if system == "windows":
        expected_roles["sensor"] = "sensor"
    expected_support = {"updater": "cli"}
    if system != "darwin":
        expected_support["package-manifest"] = "package-manifest"

    package_rows = {}
    for row in manifest["artifacts"]:
        require(isinstance(row, dict), "Недопустимая запись артефакта установщика")
        source = (
            row.get("packagePath")
            if system == "linux"
            else row.get("bundlePath")
            if system == "darwin"
            else row.get("name")
        )
        require(
            isinstance(source, str) and source not in package_rows,
            "Повторяющийся или некорректный путь артефакта установщика",
        )
        package_rows[source] = row

    def check_rows(rows: object, expected: dict[str, str], label: str) -> None:
        require(
            isinstance(rows, list) and len(rows) == len(expected),
            "Отсутствует или неожиданно присутствует установленный компонент: " + label,
        )
        roles = set()
        for entry in rows:
            require(isinstance(entry, dict), "Недопустимая запись установленного компонента")
            role = entry.get("component")
            require(
                isinstance(role, str) and role in expected and role not in roles,
                "Повторяющийся или неожиданный установленный компонент: " + str(role),
            )
            roles.add(role)
            src = entry.get("sourcePath")
            dest = entry.get("targetPath")
            require(
                isinstance(src, str)
                and src
                and src == dest
                and not src.startswith("/")
                and "\\" not in src
                and all(part not in ("", ".", "..") for part in src.split("/")),
                "Небезопасный путь установленного обновления для " + role,
            )
            actual_member = prefix + src
            require(
                actual_member in members
                and isinstance(entry.get("sha256"), str)
                and SHA.fullmatch(entry["sha256"]) is not None
                and type(entry.get("size")) is int
                and entry["size"] > 0
                and entry.get("executable") is (role != "package-manifest")
                and len(members[actual_member]) == entry["size"]
                and hashlib.sha256(members[actual_member]).hexdigest()
                == entry["sha256"],
                "installed update component bytes differ: " + role,
            )
            if role == "package-manifest":
                expected_path = ("launcher/" if system == "linux" else "") + (
                    "LINUX_PACKAGE_MANIFEST.json"
                    if system == "linux"
                    else "WINDOWS_PACKAGE_MANIFEST.json"
                )
                require(
                    actual_member == expected_path,
                    "Путь манифеста пакета обновления компонента не совпадает",
                )
            else:
                matching = [
                    row
                    for path, row in package_rows.items()
                    if path == actual_member and row.get("component") == expected[role]
                ]
                require(
                    len(matching) == 1
                    and matching[0].get("sha256") == entry["sha256"]
                    and matching[0].get("size") == entry["size"],
                    "Сопоставление компонентов установщика и обновляющего модуля различается: " + role,
                )

    check_rows(update.get("components"), expected_roles, "components")
    check_rows(update.get("supportFiles"), expected_support, "support files")
    # Подписи проверяются закреплённой политикой доверия обновлятора, а не
    # открытыми ключами, переданными внутри пакета. Сопутствующий файл должен
    # связывать именно устанавливаемые байты; проверка согласованности хеша сама по
    # себе не заменяет независимую проверку подписи.
    signature_path = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_SET_SIGNATURE.json"
    )
    require(signature_path in members, "Отсутствует подпись набора установленных компонентов")
    signature = json.loads(members[signature_path], object_pairs_hook=_no_dupes)
    require(
        isinstance(signature, dict)
        and signature.get("schemaVersion") == "1.0"
        and signature.get("algorithm") == "ed25519"
        and signature.get("manifestSha256") == hashlib.sha256(update_bytes).hexdigest()
        and isinstance(signature.get("signature"), str)
        and re.fullmatch("[a-f0-9]{128}", signature["signature"]) is not None,
        "Подпись набора компонентов не привязана к установленному манифесту обновления",
    )
    v2_path = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_SET_SIGNATURE_V2.json"
    )
    require(v2_path in members, "Отсутствует делегированная подпись набора установленных компонентов")
    v2 = json.loads(members[v2_path], object_pairs_hook=_no_dupes)
    require(
        isinstance(v2, dict)
        and v2.get("schemaVersion") == "2.0"
        and v2.get("algorithm") == "ed25519"
        and v2.get("manifestSha256") == hashlib.sha256(update_bytes).hexdigest()
        and isinstance(v2.get("signature"), str)
        and re.fullmatch("[a-f0-9]{128}", v2["signature"]) is not None,
        "Делегированная подпись компонента не привязана к установленному манифесту обновления",
    )
    trust_policy = (
        prefix
        + ("Contents/Resources/" if system == "darwin" else "")
        + "COMPONENT_TRUST_POLICY.json"
    )
    require(
        trust_policy in members and 0 < len(members[trust_policy]) <= 128 * 1024,
        "Отсутствует установленная политика доверия к делегированным компонентам",
    )
    # Проверяйте обе подписи Ed25519 по корневым ключам доверия, предоставленным
    # отдельно оператором выпуска. Никогда не берите открытый ключ доверия из ZIP.
    component_root = os.environ.get(
        "LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY", ""
    ).strip()
    delegation_root = os.environ.get(
        "LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY", ""
    ).strip()
    require(
        re.fullmatch("[0-9a-fA-F]{64}", component_root) is not None
        and re.fullmatch("[0-9a-fA-F]{64}", delegation_root) is not None,
        "Отсутствуют доверенные открытые ключи компонентов выпуска",
    )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(component_root)).verify(
            bytes.fromhex(signature["signature"]), update_bytes
        )
        envelope = json.loads(members[trust_policy], object_pairs_hook=_no_dupes)
        require(
            isinstance(envelope, dict) and envelope.get("schemaVersion") == "1.0",
            "Некорректная оболочка политики доверия к компонентам с корневой подписью",
        )
        payload = base64.b64decode(envelope["payload"], validate=True)
        require(
            0 < len(payload) <= 128 * 1024
            and re.fullmatch("[0-9a-fA-F]{128}", envelope.get("rootSignature", ""))
            is not None,
            "Некорректное содержимое или подпись политики доверия к компонентам",
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(delegation_root)).verify(
            bytes.fromhex(envelope["rootSignature"]),
            b"Launcher-Trust-Policy-v1\n" + payload,
        )
        delegated_policy = json.loads(payload, object_pairs_hook=_no_dupes)
        require(
            isinstance(delegated_policy, dict)
            and delegated_policy.get("schemaVersion") == "1.0"
            and delegated_policy.get("domain") == "launcher.trust.v1"
            and type(delegated_policy.get("epoch")) is int
            and delegated_policy["epoch"] > 0
            and v2.get("trustEpoch") == delegated_policy["epoch"]
            and v2.get("policySha256") == hashlib.sha256(payload).hexdigest(),
            "Не совпадают эпоха или идентификатор политики доверия к компонентам",
        )

        def date(value: str) -> datetime:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )

        current = datetime.now(timezone.utc)
        require(
            date(delegated_policy["issuedAt"])
            <= current
            < date(delegated_policy["expiresAt"]),
            "Срок действия политики доверия к компонентам истёк или ещё не начался",
        )
        require(
            date(v2["signedAt"]) <= current
            and date(delegated_policy["issuedAt"])
            <= date(v2["signedAt"])
            < date(delegated_policy["expiresAt"]),
            "Делегированная подпись компонента выходит за срок действия политики",
        )
        matching = [
            key
            for key in delegated_policy.get("keys", [])
            if isinstance(key, dict)
            and key.get("id") == v2.get("keyId")
            and key.get("role") == "component"
            and key.get("status") == "active"
            and date(key["notBefore"]) <= date(v2["signedAt"])
            and isinstance(key.get("publicKey"), str)
            and re.fullmatch("[a-fA-F0-9]{64}", key["publicKey"]) is not None
        ]
        require(
            len(matching) == 1,
            "Отсутствует активный делегированный ключ компонента с независимым доверием",
        )
        context = (
            "Launcher-Component-v2\n"
            + v2["keyId"]
            + "\n"
            + str(v2["trustEpoch"])
            + "\n"
            + v2["policySha256"]
            + "\n"
            + v2["manifestSha256"]
            + "\n"
            + v2["signedAt"]
            + "\n"
        ).encode()
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(matching[0]["publicKey"])
        ).verify(bytes.fromhex(v2["signature"]), context + update_bytes)
    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
        base64.binascii.Error,
    ) as exc:
        raise Blocked(
            "Криптографическая проверка доверия установленного набора компонентов не пройдена"
        ) from exc


def exact_package(bundle: Path, version: str, target: str) -> dict:
    system, arch = target.split("-")
    binary_name, package_name = paths(version, target)
    binary = bundle / binary_name
    package = bundle / package_name
    architecture(binary.read_bytes(), target)
    members = unpack(package)
    if system == "windows":
        manifest_name = f"WINDOWS_PACKAGE_MANIFEST_{arch.upper()}.json"
        inner = "WINDOWS_PACKAGE_MANIFEST.json"
        member = "launcher-desktop.exe"
    elif system == "linux":
        manifest_name = f"LINUX_PACKAGE_MANIFEST_{arch.upper()}.json"
        inner = "launcher/LINUX_PACKAGE_MANIFEST.json"
        member = "launcher/launcher-desktop"
    else:
        manifest_name = f"MACOS_PACKAGE_MANIFEST_{arch.upper()}.json"
        inner = "Launcher.app/Contents/Resources/MACOS_PACKAGE_MANIFEST.json"
        member = "Launcher.app/Contents/MacOS/launcher-desktop"
    require(
        inner in members and member in members,
        target + ": отсутствует упакованный Desktop или манифест",
    )
    # На macOS встроенный манифест .app запечатывается codesign до копирования
    # окончательных нотариально заверенных байтов обратно в корневой манифест.
    # Поэтому сравнивайте идентичность, но точный ZIP проверяйте по окончательному
    # верхнеуровневому хеш-манифесту, не требуя совпадения хешей до и после
    # подписи.
    if system == "darwin":
        embedded = json.loads(members[inner], object_pairs_hook=_no_dupes)
        require(
            embedded.get("productVersion") == version
            and embedded.get("architecture") == arch,
            target + ": идентификатор встроенного манифеста macOS не совпадает",
        )
        manifest = json.loads(
            (bundle / manifest_name).read_bytes(), object_pairs_hook=_no_dupes
        )
    else:
        require(
            sha(bundle / manifest_name) == hashlib.sha256(members[inner]).hexdigest(),
            target + ": встроенный манифест пакета отличается от подписанного источника",
        )
        manifest = json.loads(members[inner], object_pairs_hook=_no_dupes)
    require(
        manifest.get("productVersion") == version
        and manifest.get("architecture") == arch
        and isinstance(manifest.get("artifacts"), list),
        target + ": версия или архитектура манифеста пакета не совпадает",
    )
    require(
        hashlib.sha256(members[member]).hexdigest() == sha(binary),
        target + ": исполняемый файл в пакете отличается от утверждённого бинарного файла",
    )
    seen = set()
    for row in manifest["artifacts"]:
        name = (
            row.get("packagePath")
            if system == "linux"
            else (row.get("bundlePath") if system == "darwin" else row.get("name"))
        )
        require(
            isinstance(name, str)
            and name in members
            and name not in seen
            and isinstance(row.get("sha256"), str)
            and SHA.fullmatch(row["sha256"]) is not None
            and row.get("size") == len(members[name])
            and hashlib.sha256(members[name]).hexdigest() == row["sha256"],
            target + ": отсутствующий или изменённый компонент пакета: " + str(name),
        )
        seen.add(name)
        if row.get("component") == "desktop-launcher":
            require(name == member, target + ": неожиданное сопоставление компонентов Desktop")
        if row.get("component") in ("desktop-launcher", "runtime", "guard", "cli"):
            architecture(members[name], target)
        if system == "windows":
            require(
                row.get("authenticodeStatus") == "Valid"
                and row.get("timestamped") is True
                and row.get("signtoolVerified") is True
                and re.fullmatch(
                    r"[a-fA-F0-9]{40}", str(row.get("signerThumbprint", ""))
                )
                is not None,
                target + ": отсутствует свидетельство нативной подписи Authenticode",
            )
        if system == "darwin":
            require(
                row.get("codeSigned") is True
                and row.get("hardenedRuntime") is True
                and re.fullmatch("[A-Z0-9]{10}", str(row.get("teamId", "")))
                is not None,
                target + ": отсутствует свидетельство нативной подписи кода",
            )
    require(
        member in seen and len(seen) >= 4, target + ": неполный рабочий пакет"
    )
    if tuple(int(v) for v in version.split(".")[:3]) >= (0, 41, 0):
        verify_update_payload_0410(members, manifest, system, arch, version)
    if system in ("linux", "windows"):
        require(
            (
                "launcher/COMPONENT_SET_SIGNATURE.json"
                if system == "linux"
                else "COMPONENT_SET_SIGNATURE.json"
            )
            in members,
            target + ": отсутствует подпись набора компонентов",
        )
    return {
        "target": target,
        "binary": binary_name,
        "binarySha256": sha(binary),
        "package": package_name,
        "packageSha256": sha(package),
        "packageMembers": len(members),
    }


def _no_dupes(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "Повторяющееся поле JSON: " + key)
        obj[key] = value
    return obj


def current_run() -> tuple[str, str]:
    run_id = os.environ.get("LAUNCHER_RELEASE_RUN_ID") or os.environ.get(
        "GITHUB_RUN_ID", ""
    )
    attempt = os.environ.get("LAUNCHER_RELEASE_RUN_ATTEMPT") or os.environ.get(
        "GITHUB_RUN_ATTEMPT", ""
    )
    require(
        re.fullmatch(r"[1-9][0-9]{0,29}", run_id) is not None
        and re.fullmatch(r"[1-9][0-9]{0,9}", attempt) is not None,
        "Для приёмочного прогона требуются точные идентификатор запуска CI и номер попытки",
    )
    return run_id, attempt


def certify(bundle: Path, evidence: Path, key: Path, version: str, commit: str) -> dict:
    run_id, run_attempt = current_run()
    receipt = verify(bundle, evidence, key, version, commit)
    require(requires_rehearsal(version), "Для репетиции требуется версия не ниже 0.36.5")
    allowed = {name for target in TARGETS for name in paths(version, target)}
    allowed.update(
        {
            f"launcher-desktop-{version}-windows-amd64.zip",
            f"launcher-desktop-{version}-macos-universal.zip",
            "launcher-desktop-windows-amd64.exe",
            "launcher-desktop-linux-amd64",
            "launcher-desktop-macos-universal",
        }
    )
    for entry in bundle.iterdir():
        name = entry.name
        target_shaped = name.startswith(
            (
                "launcher-desktop-windows-",
                "launcher-desktop-linux-",
                "launcher-desktop-macos-",
            )
        ) or name.startswith(
            (
                f"launcher-desktop-{version}-windows-",
                f"launcher-desktop-{version}-macos-",
                f"launcher-desktop-{version}-linux-",
                "launcher-linux-",
            )
        )
        if target_shaped and name not in allowed:
            raise Blocked("Дополнительная платформа не утверждена: " + name)
    rows = [exact_package(bundle, version, target) for target in sorted(TARGETS)]
    require(
        [(r["target"], r["binarySha256"], r["packageSha256"]) for r in rows]
        == [
            (r["target"], r["binarySha256"], r["packageSha256"])
            for r in receipt["targets"]
        ],
        "Записи приёмочного прогона не соответствуют подписанному набору целей GA",
    )
    return {
        "schemaVersion": SCHEMA,
        "version": version,
        "commit": commit,
        "runId": run_id,
        "runAttempt": run_attempt,
        "status": "package-and-ga-verified",
        "gaApprovalSha256": receipt["approvalSha256"],
        "targets": rows,
    }


def dry_run(
    bundle: Path,
    cli: Path,
    public_key: Path,
    trust_policy: Path,
    trust_state: Path,
    evidence: Path,
    key: Path,
    version: str,
    commit: str,
    stage: Path,
) -> dict:
    require(
        stage.resolve() != bundle.resolve() and not stage.exists(),
        "Для пробной подготовки требуется новый отдельный каталог",
    )
    receipt = certify(bundle, evidence, key, version, commit)
    report = json.loads(
        (bundle / "RELEASE_REHEARSAL_0365.json").read_bytes(),
        object_pairs_hook=_no_dupes,
    )
    require(
        report == receipt, "Квитанция пробного выпуска с подписью устарела или не соответствует сборке"
    )
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    expected = {}
    for line in sums.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        require(
            len(fields) == 2
            and SHA.fullmatch(fields[0]) is not None
            and fields[1] not in expected
            and "/" not in fields[1]
            and "\\" not in fields[1],
            "Некорректная запись SHA256SUMS",
        )
        expected[fields[1]] = fields[0]
    files = [p for p in bundle.iterdir() if p.is_file() and not p.is_symlink()]
    require(
        set(expected) == {p.name for p in files} - {"SHA256SUMS", "SHA256SUMS.sig"},
        "В финальном выпуске отсутствует файл, обнаружен неподписанный или лишний файл",
    )
    # Никогда не используйте общее или промышленное состояние доверия как
    # записываемое состояние пробного прогона.
    independent_trust_state = stage.parent / (stage.name + "-trust-state.json")
    if trust_state.is_file():
        shutil.copy2(trust_state, independent_trust_state)
    stage.mkdir(parents=True)
    try:
        for source in files:
            target = stage / source.name
            with source.open("rb") as read, target.open("xb") as write:
                shutil.copyfileobj(read, write, 1024 * 1024)
            require(
                sha(target) == sha(source),
                "Пробная передача изменила данные: " + source.name,
            )
            if source.name in expected:
                require(
                    sha(target) == expected[source.name],
                    "SHA256SUMS mismatch " + source.name,
                )
        copied_cli = stage / cli.name
        require(copied_cli.is_file(), "В пробной публикации отсутствует CLI выпуска")
        copied_cli.chmod(cli.stat().st_mode & 0o777)
        argv = [
            str(copied_cli.resolve()),
            "release",
            "publish-check",
            str(stage),
            "--public-key",
            str(public_key.resolve()),
            "--trust-state",
            str(independent_trust_state.resolve()),
            "--trust-policy",
            str(trust_policy.resolve()),
        ]
        finished = subprocess.run(argv, capture_output=True, text=True, timeout=240)
        require(
            finished.returncode == 0,
            "Проверка публикации подготовленного выпуска отклонена: "
            + (finished.stderr or finished.stdout)[-900:],
        )
        return {
            "schemaVersion": "launcher.release.publication-dry-run.v1",
            "version": version,
            "commit": commit,
            "status": "passed",
            "runId": receipt["runId"],
            "runAttempt": receipt["runAttempt"],
            "published": False,
            "filesCopied": len(files),
            "sha256sumsSha256": sha(stage / "SHA256SUMS"),
            "gaApprovalSha256": receipt["gaApprovalSha256"],
        }
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        independent_trust_state.unlink(missing_ok=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("certify", "dry-run"))
    for field in ("bundle", "evidence", "trusted-key", "version", "commit", "output"):
        p.add_argument("--" + field, required=True)
    for field in ("cli", "public-key", "trust-policy", "trust-state", "stage"):
        p.add_argument("--" + field)
    a = p.parse_args()
    output = Path(a.output)
    output.unlink(missing_ok=True)
    try:
        base = dict(
            bundle=Path(a.bundle),
            evidence=Path(a.evidence),
            key=Path(a.trusted_key),
            version=a.version,
            commit=a.commit,
        )
        if a.action == "certify":
            result = certify(**base)
        else:
            require(
                all((a.cli, a.public_key, a.trust_policy, a.trust_state, a.stage)),
                "Для пробного запуска требуются CLI, открытый ключ, политика доверия, состояние доверия и каталог подготовки",
            )
            result = dry_run(
                base["bundle"],
                Path(a.cli),
                Path(a.public_key),
                Path(a.trust_policy),
                Path(a.trust_state),
                base["evidence"],
                base["key"],
                base["version"],
                base["commit"],
                Path(a.stage),
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(a.action + ": " + result["status"])
        return 0
    except (
        Blocked,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        struct.error,
        zipfile.BadZipFile,
        tarfile.TarError,
        subprocess.TimeoutExpired,
    ) as exc:
        print("Репетиция релиза ЗАБЛОКИРОВАНА: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
