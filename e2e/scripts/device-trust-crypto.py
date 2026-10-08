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
    proc = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({' '.join(args)}): {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def read_der_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated DER length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise ValueError("invalid DER length")
    return int.from_bytes(data[pos:pos + count], "big"), pos + count


def der_ecdsa_to_p1363(signature: bytes, width: int = 32) -> bytes:
    pos = 0
    if len(signature) < 2 or signature[pos] != 0x30:
        raise ValueError("ECDSA signature is not a DER sequence")
    pos += 1
    seq_len, pos = read_der_length(signature, pos)
    if pos + seq_len != len(signature):
        raise ValueError("invalid DER sequence length")
    values: list[bytes] = []
    for _ in range(2):
        if pos >= len(signature) or signature[pos] != 0x02:
            raise ValueError("ECDSA signature integer is missing")
        pos += 1
        int_len, pos = read_der_length(signature, pos)
        if int_len == 0 or pos + int_len > len(signature):
            raise ValueError("invalid ECDSA integer length")
        value = signature[pos:pos + int_len]
        pos += int_len
        while len(value) > 1 and value[0] == 0:
            value = value[1:]
        if len(value) > width:
            raise ValueError("ECDSA integer exceeds curve width")
        values.append(value.rjust(width, b"\0"))
    if pos != len(signature):
        raise ValueError("trailing ECDSA signature data")
    return values[0] + values[1]


def public_key(algorithm: str, key: Path) -> str:
    der = run_bytes("openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER")
    if algorithm == "ed25519":
        if len(der) < 32:
            raise SystemExit("Ed25519 SPKI is too short")
        raw = der[-32:]
        if len(raw) != 32:
            raise SystemExit("invalid Ed25519 raw public key")
        return b64url(raw)
    if algorithm == "p256":
        if len(der) < 65:
            raise SystemExit("P-256 SPKI is too short")
        raw = der[-65:]
        if len(raw) != 65 or raw[0] != 0x04:
            raise SystemExit("invalid P-256 uncompressed public key")
        return b64url(raw)
    raise SystemExit(f"unsupported algorithm: {algorithm}")


def sign(algorithm: str, key: Path, payload: Path) -> str:
    if algorithm == "ed25519":
        raw = run_bytes("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(payload))
        if len(raw) != 64:
            raise SystemExit(f"unexpected Ed25519 signature length: {len(raw)}")
        return b64url(raw)
    if algorithm == "p256":
        with tempfile.NamedTemporaryFile(prefix="nl-dt-", suffix=".der", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(tmp_path), str(payload)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            return b64url(der_ecdsa_to_p1363(tmp_path.read_bytes()))
        finally:
            tmp_path.unlink(missing_ok=True)
    raise SystemExit(f"unsupported algorithm: {algorithm}")


def main() -> int:
    parser = argparse.ArgumentParser(description="NeverLauncher Device Trust E2E crypto helper")
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
