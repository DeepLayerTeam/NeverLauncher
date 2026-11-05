#!/usr/bin/env python3
"""Автономная корневая подпись для делегирования ключей между компонентами.

Корневой seed должен поступать из защищённой среды выпуска. Он никогда не поставляется клиентам и не
включается в фирменный пакет.
"""

import argparse
import base64
import json
import os
import tempfile
import re
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PREFIX = b"Launcher-Trust-Policy-v1\n"


def _no_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Обнаружен дубликат: «key in trust policy»")
        result[key] = value
    return result


def _read_policy(path: Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("trust policy source: требуется обычный файл без символических ссылок")
    with path.open("rb") as stream:
        payload = stream.read(96 * 1024 + 1)
    if len(payload) > 96 * 1024:
        raise ValueError("Превышен допустимый размер: «policy payload»")
    value = json.loads(payload, object_pairs_hook=_no_duplicate_keys)
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != "1.0"
        or value.get("domain") != "launcher.trust.v1"
        or type(value.get("epoch")) is not int
        or not 1 <= value["epoch"] < 2**64
    ):
        raise ValueError("Некорректное значение: «trust policy version/domain/epoch»")
    # Сертификат с истёкшим или перевёрнутым интервалом действия никогда нельзя
    # подписывать автономным корнем и затем случайно продвигать как действующий.
    def parse_time(field):
        raw = value.get(field)
        if not isinstance(raw, str) or len(raw) != 20:
            raise ValueError("Отсутствует: «trust policy certificate validity»")
        try:
            return datetime.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        except ValueError as err:
            raise ValueError("Некорректный срок действия сертификата политики доверия") from err
    issued = parse_time("issuedAt")
    expires = parse_time("expiresAt")
    if issued >= expires:
        raise ValueError("Начало срока действия политики доверия позже его окончания")
    if not isinstance(value.get("keys"), list) or not value["keys"]:
        raise ValueError("Политика доверия: требуется «delegated keys»")
    seen = set()
    for key in value["keys"]:
        if not isinstance(key, dict) or not isinstance(key.get("id"), str) or not key["id"]:
            raise ValueError("Некорректное значение: делегированный ключ")
        if key["id"] in seen:
            raise ValueError("Обнаружен дубликат: «delegated key ID»")
        seen.add(key["id"])
        if key.get("status") not in ("active", "revoked"):
            raise ValueError("Некорректное значение: статус делегированного ключа")
        if not isinstance(key.get("role"), str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", key["role"]):
            raise ValueError("Некорректное значение: «delegated key role»")
        public = key.get("publicKey")
        if not isinstance(public, str) or len(public) != 64:
            raise ValueError("Некорректное значение: «delegated key fingerprint»")
        try:
            bytes.fromhex(public)
        except ValueError as err:
            raise ValueError("Некорректное значение: делегированный открытый ключ") from err
    return payload


def sign_policy(
    payload_path: Path, output_path: Path, seed_hex: str, expected_root: str
) -> None:
    payload = _read_policy(payload_path)
    if output_path.is_symlink() or output_path.is_dir():
        raise ValueError("Замена политики доверия, которая является символической ссылкой или каталогом, отклонена")
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError("Исходное значение корневого ключа должно содержать 32 байта")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    actual = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    if actual != expected_root.strip().lower():
        raise ValueError("«root signing key» не совпадает с «provisioned client anchor»")
    signature = private.sign(PREFIX + payload)
    envelope = {
        "schemaVersion": "1.0",
        "payload": base64.b64encode(payload).decode(),
        "rootSignature": signature.hex(),
    }
    output = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()
    # До публикации байтов выполните настоящую криптографическую проверку.
    private.public_key().verify(bytes.fromhex(envelope["rootSignature"]), PREFIX + payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        fd, name = tempfile.mkstemp(prefix=".trust-policy-", dir=output_path.parent)
        temp = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as writer:
            writer.write(output)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temp, output_path)
        temp = None
        # Убедитесь, что переименованная запись каталога надёжно сохранена в POSIX.
        if os.name == "posix":
            directory_fd = os.open(output_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--root-key-hex",
        required=True,
        help="Предварительно предоставленный корневой ОТКРЫТЫЙ ключ, никогда не из загруженных метаданных",
    )
    args = parser.parse_args()
    seed = os.environ.get("LAUNCHER_TRUST_ROOT_ED25519_SEED", "")
    if not seed:
        raise SystemExit("Требуется: «offline LAUNCHER_TRUST_ROOT_ED25519_SEED»")
    sign_policy(args.payload, args.output, seed, args.root_key_hex)


if __name__ == "__main__":
    main()
