#!/usr/bin/env python3
"""Minimal deterministic-shape WebAuthn test authenticator for NeverLauncher E2E.

This is test-only code. It generates a P-256 credential, emits a standards-shaped
none-attestation registration response, and signs assertion ceremonies with the
private key kept under the E2E runtime directory.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", value)


def cbor_int(value: int) -> bytes:
    if value >= 0:
        return cbor_head(0, value)
    return cbor_head(1, -1 - value)


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return cbor_head(3, len(encoded)) + encoded


def cbor_map(items: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray(cbor_head(5, len(items)))
    for key, value in items:
        out.extend(key)
        out.extend(value)
    return bytes(out)


def json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def run(*args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr.decode(errors='replace')}")
    return proc.stdout


def generate_p256_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(path))
    os.chmod(path, 0o600)


def p256_coordinates(key_path: Path) -> tuple[bytes, bytes]:
    der = run("openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER")
    # SubjectPublicKeyInfo for an uncompressed P-256 key ends with 0x04 || X || Y.
    if len(der) < 65 or der[-65] != 0x04:
        raise SystemExit("unexpected P-256 SubjectPublicKeyInfo encoding")
    point = der[-65:]
    return point[1:33], point[33:65]


def client_data(kind: str, challenge: str, origin: str) -> bytes:
    # The challenge is already base64url as supplied by WebAuthn options.
    b64u_decode(challenge)  # strict-enough validation for malformed input.
    return json_bytes({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False})


def registration_auth_data(rp_id: str, credential_id: bytes, key_path: Path) -> bytes:
    x, y = p256_coordinates(key_path)
    cose = cbor_map([
        (cbor_int(1), cbor_int(2)),       # kty = EC2
        (cbor_int(3), cbor_int(-7)),      # alg = ES256
        (cbor_int(-1), cbor_int(1)),      # crv = P-256
        (cbor_int(-2), cbor_bytes(x)),
        (cbor_int(-3), cbor_bytes(y)),
    ])
    return (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([0x45])                   # UP | UV | AT
        + struct.pack(">I", 0)
        + bytes(16)                       # AAGUID intentionally zero for CI authenticator
        + struct.pack(">H", len(credential_id))
        + credential_id
        + cose
    )


def assertion_auth_data(rp_id: str, sign_count: int) -> bytes:
    if sign_count < 0 or sign_count > 0xFFFFFFFF:
        raise SystemExit("sign count must fit uint32")
    return hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([0x05]) + struct.pack(">I", sign_count)


def command_register(args: argparse.Namespace) -> None:
    state_path = Path(args.state)
    key_path = Path(args.key)
    if state_path.exists() or key_path.exists():
        raise SystemExit("refusing to overwrite existing WebAuthn test credential")
    generate_p256_key(key_path)
    credential_id = os.urandom(32)
    user_handle = b64u_decode(args.user_handle)
    client = client_data("webauthn.create", args.challenge, args.origin)
    auth_data = registration_auth_data(args.rp_id, credential_id, key_path)
    attestation = cbor_map([
        (cbor_text("fmt"), cbor_text("none")),
        (cbor_text("attStmt"), cbor_map([])),
        (cbor_text("authData"), cbor_bytes(auth_data)),
    ])
    state = {
        "schemaVersion": "1.0",
        "rpId": args.rp_id,
        "origin": args.origin,
        "credentialId": b64u(credential_id),
        "userHandle": b64u(user_handle),
        "keyPath": str(key_path),
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.chmod(state_path, 0o600)
    response = {
        "transactionToken": args.transaction_token,
        "friendlyName": args.friendly_name,
        "credential": {
            "id": b64u(credential_id),
            "rawId": b64u(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client),
                "attestationObject": b64u(attestation),
                "transports": ["internal"],
            },
        },
    }
    print(json.dumps(response, separators=(",", ":")))


def command_assert(args: argparse.Namespace) -> None:
    state = json.loads(Path(args.state).read_text(encoding="utf-8"))
    key_path = Path(state["keyPath"])
    if not key_path.is_file():
        raise SystemExit("WebAuthn private key is unavailable")
    client = client_data("webauthn.get", args.challenge, state["origin"])
    auth_data = assertion_auth_data(state["rpId"], args.sign_count)
    signed = auth_data + hashlib.sha256(client).digest()
    with tempfile.NamedTemporaryFile(prefix="neverlauncher-webauthn-", delete=False) as tmp:
        tmp.write(signed)
        payload_path = Path(tmp.name)
    try:
        signature = run("openssl", "dgst", "-sha256", "-sign", str(key_path), str(payload_path))
    finally:
        payload_path.unlink(missing_ok=True)
    credential_id = state["credentialId"]
    response = {
        "transactionToken": args.transaction_token,
        "credential": {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client),
                "authenticatorData": b64u(auth_data),
                "signature": b64u(signature),
                "userHandle": state["userHandle"],
            },
        },
    }
    print(json.dumps(response, separators=(",", ":")))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register")
    reg.add_argument("--transaction-token", required=True)
    reg.add_argument("--challenge", required=True)
    reg.add_argument("--rp-id", required=True)
    reg.add_argument("--origin", required=True)
    reg.add_argument("--user-handle", required=True)
    reg.add_argument("--state", required=True)
    reg.add_argument("--key", required=True)
    reg.add_argument("--friendly-name", default="NeverLauncher Device Trust E2E passkey")
    reg.set_defaults(func=command_register)

    assertion = sub.add_parser("assert")
    assertion.add_argument("--transaction-token", required=True)
    assertion.add_argument("--challenge", required=True)
    assertion.add_argument("--state", required=True)
    assertion.add_argument("--sign-count", type=int, default=1)
    assertion.set_defaults(func=command_assert)
    return p


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
