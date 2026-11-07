#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import subprocess
import tempfile
from pathlib import Path


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def run_bytes(*args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"Команда завершилась ошибкой ({' '.join(args)}): {proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout


def read_der_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("Обрезанное поле длины DER")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise ValueError("Недопустимая длина DER")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def der_ecdsa_to_p1363(signature: bytes, width: int = 32) -> bytes:
    pos = 0
    if len(signature) < 2 or signature[pos] != 0x30:
        raise ValueError("Подпись ECDSA не является последовательностью DER")
    pos += 1
    seq_len, pos = read_der_length(signature, pos)
    if pos + seq_len != len(signature):
        raise ValueError("Недопустимая длина последовательности DER")
    values: list[bytes] = []
    for _ in range(2):
        if pos >= len(signature) or signature[pos] != 0x02:
            raise ValueError("В подписи ECDSA отсутствует целое число")
        pos += 1
        int_len, pos = read_der_length(signature, pos)
        if int_len == 0 or pos + int_len > len(signature):
            raise ValueError("Недопустимая длина целого числа ECDSA")
        value = signature[pos : pos + int_len]
        pos += int_len
        while len(value) > 1 and value[0] == 0:
            value = value[1:]
        if len(value) > width:
            raise ValueError("Целое число ECDSA превышает ширину кривой")
        values.append(value.rjust(width, b"\0"))
    if pos != len(signature):
        raise ValueError("Лишние данные после подписи ECDSA")
    return values[0] + values[1]


def public_key(algorithm: str, key: Path) -> str:
    der = run_bytes("openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER")
    if algorithm == "ed25519":
        if len(der) < 32:
            raise SystemExit("Слишком короткое значение Ed25519 SPKI")
        raw = der[-32:]
        if len(raw) != 32:
            raise SystemExit("Некорректный исходный открытый ключ Ed25519")
        return b64url(raw)
    if algorithm == "p256":
        if len(der) < 65:
            raise SystemExit("Слишком короткое значение P-256 SPKI")
        raw = der[-65:]
        if len(raw) != 65 or raw[0] != 0x04:
            raise SystemExit("Некорректный несжатый открытый ключ P-256")
        return b64url(raw)
    raise SystemExit(f"Неподдерживаемый алгоритм: {algorithm}")


def sign(algorithm: str, key: Path, payload: Path) -> str:
    if algorithm == "ed25519":
        raw = run_bytes(
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(key),
            "-in",
            str(payload),
        )
        if len(raw) != 64:
            raise SystemExit(f"Недопустимая длина подписи Ed25519: {len(raw)}")
        return b64url(raw)
    if algorithm == "p256":
        with tempfile.NamedTemporaryFile(
            prefix="nl-dt-", suffix=".der", delete=False
        ) as tmp:
            tmp_path = Path(tmp.name)
        try:
            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(key),
                    "-out",
                    str(tmp_path),
                    str(payload),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            return b64url(der_ecdsa_to_p1363(tmp_path.read_bytes()))
        finally:
            tmp_path.unlink(missing_ok=True)
    raise SystemExit(f"Неподдерживаемый алгоритм: {algorithm}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Криптографический помощник Device Trust E2E Launcher"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("public")
    p.add_argument("--algorithm", choices=["ed25519", "p256"], required=True)
    p.add_argument("--key", type=Path, required=True)
    p = sub.add_parser("sign")
    p.add_argument("--algorithm", choices=["ed25519", "p256"], required=True)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "public":
        print(public_key(args.algorithm, args.key))
    else:
        print(sign(args.algorithm, args.key, args.payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
