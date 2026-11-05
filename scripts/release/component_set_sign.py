#!/usr/bin/env python3
"""Собрать аутентифицированный набор протокольных компонентов 0.23.10 и отдельную подпись.

Seed подписи выпуска никогда не записывается на диск. Открытый ключ проверки отдельно закрепляется в
бинарном файле обновляющего компонента при доверенной сборке.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def required(version: str) -> bool:
    major, minor, patch = (int(s) for s in version.split(".")[:3])
    return (major, minor, patch) >= (0, 23, 10)


def signed_set(
    manifest: dict, *, development: bool = False
) -> tuple[bytes, bytes | None]:
    if not required(manifest["productVersion"]):
        return (
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
        ).encode(), None
    if required("0.23.11") and tuple(
        int(v) for v in manifest["productVersion"].split(".")[:3]
    ) >= (0, 23, 11):
        generation = manifest.get("securityGeneration")
        if generation is None and os.environ.get(
            "LAUNCHER_COMPONENT_SECURITY_GENERATION", ""
        ):
            value = os.environ["LAUNCHER_COMPONENT_SECURITY_GENERATION"].strip()
            if not value.isascii() or not value.isdigit():
                raise ValueError("component security generation: требуется «decimal»")
            generation = int(value)
            manifest["securityGeneration"] = generation
        if type(generation) is not int or generation <= 0 or generation > 2**64 - 1:
            raise ValueError(
                "securityGeneration должен быть явно заданным положительным значением uint64"
            )
    platform = manifest["platform"]
    components = {x["component"] for x in manifest["components"]}
    if components != (
        {"desktop", "guard", "runtime", "sensor"}
        if platform == "windows"
        else {"desktop", "guard", "runtime"}
    ):
        raise ValueError("Неожиданное значение: «component role set»")
    helpers = [
        x for x in manifest.get("supportFiles", []) if x["component"] == "updater"
    ]
    if len(helpers) != 1 or not helpers[0]["executable"]:
        raise ValueError("Отсутствует: «component update helper»")
    rows = [
        {
            "component": "desktop",
            "provides": {"guard-ipc": 4},
            "requires": [
                {"component": "guard", "protocol": "guard-ipc", "minimum": 4},
                {"component": "runtime", "protocol": "guard-ipc", "minimum": 4},
                {"component": "updater", "protocol": "component-update", "minimum": 2},
            ],
        },
        {
            "component": "guard",
            "provides": {"guard-ipc": 4},
            "requires": [
                {"component": "runtime", "protocol": "guard-ipc", "minimum": 4},
            ],
        },
        {
            "component": "runtime",
            "provides": {"guard-ipc": 4},
            "requires": [
                {"component": "guard", "protocol": "guard-ipc", "minimum": 4},
            ],
        },
        {
            "component": "updater",
            "provides": {"component-update": 2},
            "requires": [
                {"component": "desktop", "protocol": "guard-ipc", "minimum": 4},
            ],
        },
    ]
    if platform == "windows":
        rows[1]["requires"].append(
            {"component": "sensor", "protocol": "sensor-ipc", "minimum": 3}
        )
        rows.append({"component": "sensor", "provides": {"sensor-ipc": 3}})
    # Сохраните 1.0 для обновления со старого внешнего обновлятора 0.23.9, уже
    # закреплённого по SHA-256 пакета. Новые обновляторы обеспечивают проверку
    # подписи сопутствующего набора компонентов и матрицы протоколов.
    manifest["schemaVersion"] = "1.0"
    manifest["componentSet"] = {"schemaVersion": "1.0", "protocols": rows}
    raw = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    seed = os.environ.get("LAUNCHER_COMPONENT_SET_ED25519_SEED", "").strip()
    if not seed:
        if development:
            return raw, None
        raise RuntimeError(
            "Для производственного обновления компонентов требуется LAUNCHER_COMPONENT_SET_ED25519_SEED"
        )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed_bytes = bytes.fromhex(seed)
    if len(seed_bytes) != 32:
        raise ValueError("Ed25519 seed: требуется «exactly 32 bytes in hexadecimal»")
    key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    expected_pub = (
        os.environ.get("LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY", "").strip().lower()
    )
    actual_pub = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        .hex()
    )
    if not expected_pub or expected_pub != actual_pub:
        raise RuntimeError(
            "Ключ подписи набора компонентов не соответствует встроенному открытому корню доверия"
        )
    signature = key.sign(raw)
    envelope = {
        "schemaVersion": "1.0",
        "algorithm": "ed25519",
        "manifestSha256": hashlib.sha256(raw).hexdigest(),
        "signature": signature.hex(),
    }
    signed = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()
    return raw, signed


def sign_delegated_set(manifest_bytes: bytes, now=None):
    """Подписать точный манифест, совместимый с v1, отдельным делегированным ключом.

    Всё доверие исходит от предварительно предоставленного корня выпуска, а не от пакета.
    """
    import base64
    import datetime
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    now = now or datetime.datetime.now(datetime.timezone.utc)
    root_hex = os.environ.get("LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY", "").strip()
    policy_file = os.environ.get("LAUNCHER_COMPONENT_TRUST_POLICY_FILE", "").strip()
    seed = os.environ.get("LAUNCHER_COMPONENT_DELEGATED_ED25519_SEED", "").strip()
    key_id = os.environ.get("LAUNCHER_COMPONENT_DELEGATED_KEY_ID", "").strip()
    if not all((root_hex, policy_file, seed, key_id)):
        raise RuntimeError(
            "Для промышленного подписания 0.23.12 необходимы автономный корень доверия, подписанная политика, делегированный ключ и идентификатор ключа"
        )
    root = Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_hex))
    policy_raw = Path(policy_file).read_bytes()
    if len(policy_raw) > 128 * 1024:
        raise ValueError("Превышен допустимый размер: политика доверия")
    envelope = json.loads(policy_raw)
    if envelope.get("schemaVersion") != "1.0":
        raise ValueError("Некорректное значение: конверт политики доверия")
    payload = base64.b64decode(envelope["payload"], validate=True)
    root.verify(
        bytes.fromhex(envelope["rootSignature"]),
        b"Launcher-Trust-Policy-v1\n" + payload,
    )
    policy = json.loads(payload)
    if (
        policy.get("schemaVersion") != "1.0"
        or policy.get("domain") != "launcher.trust.v1"
        or policy.get("epoch", 0) < 1
    ):
        raise ValueError("Некорректное значение: «delegated policy»")

    def timestamp(s):
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )

    if not timestamp(policy["issuedAt"]) <= now < timestamp(policy["expiresAt"]):
        raise ValueError("Политика доверия просрочена или датирована будущим")
    signing = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    pub = (
        signing.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    authorized = any(
        k.get("id") == key_id
        and k.get("role") == "component"
        and k.get("status") == "active"
        and k.get("publicKey", "").lower() == pub
        and timestamp(k["notBefore"]) <= now
        for k in policy["keys"]
    )
    if not authorized:
        raise ValueError("Ключ компонента не активен в политике доверия, подписанной корневым ключом")
    signature = {
        "schemaVersion": "2.0",
        "algorithm": "ed25519",
        "keyId": key_id,
        "trustEpoch": policy["epoch"],
        "policySha256": hashlib.sha256(payload).hexdigest(),
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "signedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature": "",
    }
    context = (
        "Launcher-Component-v2\n"
        + key_id
        + "\n"
        + str(policy["epoch"])
        + "\n"
        + signature["policySha256"]
        + "\n"
        + signature["manifestSha256"]
        + "\n"
        + signature["signedAt"]
        + "\n"
    ).encode()
    signature["signature"] = signing.sign(context + manifest_bytes).hex()
    return json.dumps(signature, sort_keys=True, indent=2).encode() + b"\n", policy_raw


def sign_file(manifest_path: Path, *, development: bool = False) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw, envelope = signed_set(manifest, development=development)
    manifest_path.write_bytes(raw)
    sig_path = manifest_path.with_name("COMPONENT_SET_SIGNATURE.json")
    if envelope is not None:
        sig_path.write_bytes(envelope)
    else:
        sig_path.unlink(missing_ok=True)
    v2_path = manifest_path.with_name("COMPONENT_SET_SIGNATURE_V2.json")
    policy_path = manifest_path.with_name("COMPONENT_TRUST_POLICY.json")
    version = manifest.get("productVersion", "0.0.0").split(".")
    require_v2 = len(version) >= 3 and tuple(map(int, version[:3])) >= (0, 23, 12)
    if require_v2 and not development:
        v2, root_signed = sign_delegated_set(raw)
        v2_path.write_bytes(v2)
        policy_path.write_bytes(root_signed)
    else:
        v2_path.unlink(missing_ok=True)
        policy_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--development", action="store_true")
    args = parser.parse_args()
    sign_file(args.manifest, development=args.development)


if __name__ == "__main__":
    main()
