#!/usr/bin/env python3
"""Подписать финальный манифест Linux-пакета Guard существующим ключом выпуска компонентов.

Префикс домена не позволяет переиспользовать подпись манифеста набора компонентов как действительную
подпись пакета Guard (или наоборот).
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

DOMAIN = b"NeverLauncher Linux Guard package manifest v1\0"


def sign_manifest(raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = os.environ.get("LAUNCHER_COMPONENT_SET_ED25519_SEED", "").strip()
    public = os.environ.get("LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY", "").strip()
    if len(seed) != 64 or len(public) != 64:
        raise ValueError("Манифест производственной сборки Guard для Linux: требуется «закреплённый закрытый ключ подписи Ed25519 и публичный ключ»")
    try:
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        expected = bytes.fromhex(public)
    except (ValueError, TypeError) as exc:
        raise ValueError("Некорректное значение: «кодировка ключа подписи манифеста Linux Guard»") from exc
    actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if actual != expected:
        raise ValueError("Публичный ключ Linux Guard не соответствует закрытому ключу подписи")
    return (key.sign(DOMAIN + raw).hex() + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    sidecar = args.manifest.with_name(args.manifest.name + ".ed25519")
    sidecar.write_bytes(sign_manifest(raw))
    sidecar.chmod(0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
