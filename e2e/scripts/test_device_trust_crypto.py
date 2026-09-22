#!/usr/bin/env python3
from __future__ import annotations

import base64
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "e2e/scripts/device-trust-crypto.py"


def run(*args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return proc.stdout


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def der_int(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + bytes([len(value)]) + value


def p1363_to_der(raw: bytes) -> bytes:
    if len(raw) != 64:
        raise ValueError("P-256 P1363 signature must be 64 bytes")
    body = der_int(raw[:32]) + der_int(raw[32:])
    if len(body) >= 128:
        raise ValueError("unexpected P-256 DER body length")
    return b"\x30" + bytes([len(body)]) + body


@unittest.skipUnless(subprocess.run(["sh", "-c", "command -v openssl >/dev/null"], check=False).returncode == 0, "OpenSSL is required")
class DeviceTrustCryptoTests(unittest.TestCase):
    def test_ed25519_public_and_signature_are_backend_wire_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            key, pub, msg, sig = tmp / "key.pem", tmp / "pub.pem", tmp / "msg", tmp / "sig"
            run("openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key))
            run("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub))
            msg.write_bytes(b"NeverLauncher Device Trust crypto test\n")
            wire_pub = run("python3", str(HELPER), "public", "--algorithm", "ed25519", "--key", str(key)).decode().strip()
            self.assertEqual(len(b64decode(wire_pub)), 32)
            wire_sig = run("python3", str(HELPER), "sign", "--algorithm", "ed25519", "--key", str(key), "--payload", str(msg)).decode().strip()
            sig.write_bytes(b64decode(wire_sig))
            self.assertEqual(sig.stat().st_size, 64)
            subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(pub), "-in", str(msg), "-sigfile", str(sig)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_p256_public_and_p1363_signature_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            key, pub, msg, sig = tmp / "key.pem", tmp / "pub.pem", tmp / "msg", tmp / "sig.der"
            run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key))
            run("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub))
            msg.write_bytes(b"NeverLauncher Device Attestation crypto test\n")
            wire_pub = run("python3", str(HELPER), "public", "--algorithm", "p256", "--key", str(key)).decode().strip()
            raw_pub = b64decode(wire_pub)
            self.assertEqual(len(raw_pub), 65)
            self.assertEqual(raw_pub[0], 0x04)
            wire_sig = run("python3", str(HELPER), "sign", "--algorithm", "p256", "--key", str(key), "--payload", str(msg)).decode().strip()
            raw_sig = b64decode(wire_sig)
            self.assertEqual(len(raw_sig), 64)
            sig.write_bytes(p1363_to_der(raw_sig))
            subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(msg)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


if __name__ == "__main__":
    unittest.main()
