#!/usr/bin/env python3
"""Автономный авторизованный этап утверждения безопасности (НЕ запускается тестовым CI).

Закрытый ключ Ed25519 PKCS#8 остаётся на подконтрольной утверждающему стороне рабочей станции. CI
никогда не генерирует, не хранит, не коммитит и не выводит закрытый ключ.
"""

import argparse
import getpass
import os
from pathlib import Path
import stat
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import ga_verify as ga


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--private-key-file", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--source-sha256", required=True)
    args = p.parse_args()
    if args.evidence.is_symlink() or args.private_key_file.is_symlink():
        raise SystemExit("Символические ссылки на подтверждения или закрытый ключ запрещены")
    key_stat = args.private_key_file.stat()
    if not stat.S_ISREG(key_stat.st_mode) or (
        os.name == "posix" and key_stat.st_mode & 0o077
    ):
        raise SystemExit("Закрытый ключ должен храниться в обычном файле, доступном только владельцу (0600)")
    password = os.environ.get("LAUNCHER_GA_SIGNING_KEY_PASSPHRASE")
    if password is None:
        password = getpass.getpass(
            "Пароль закрытого ключа (оставьте пустым для незашифрованного PKCS#8): "
        )
    private = serialization.load_pem_private_key(
        args.private_key_file.read_bytes(),
        password=password.encode() if password else None,
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise SystemExit("Принимаются только ключи подписи Ed25519")
    raw = args.evidence.read_bytes()
    # Подписывайте точно одобренные байты. Не меняйте форматирование после
    # подписи.
    sig_path = Path(str(args.evidence) + ".sig")
    if sig_path.exists() or sig_path.is_symlink():
        raise SystemExit("Подпись уже существует; после повторной проверки удалите её явно")
    signature = private.sign(ga.DOMAIN + raw)
    try:
        with sig_path.open("x", encoding="ascii") as f:
            f.write(signature.hex() + "\n")
        if os.name == "posix":
            os.chmod(sig_path, 0o600)
        pub = (
            private.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )
        ga.verify_evidence(
            args.evidence,
            ga.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)),
            commit=args.commit,
            source_sha=args.source_sha256,
            now=ga.dt.datetime.now(ga.dt.timezone.utc),
        )
    except BaseException:
        sig_path.unlink(missing_ok=True)
        raise
    print(
        f"Подписанное подтверждение одобрено: {args.evidence.name} (.sig); отпечаток ключа сохранён у подтверждающего лица"
    )


if __name__ == "__main__":
    main()
