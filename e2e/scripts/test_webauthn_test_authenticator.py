#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "e2e/scripts/webauthn-test-authenticator.py"


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class WebAuthnTestAuthenticator(unittest.TestCase):
    def test_registration_and_signed_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            challenge = base64.urlsafe_b64encode(b"registration-challenge-32-byte!!").rstrip(b"=").decode()
            user_handle = base64.urlsafe_b64encode(b"user-handle-32-byte-test-value!!").rstrip(b"=").decode()
            register = subprocess.run([
                "python3", str(HELPER), "register", "--transaction-token", "tx-register",
                "--challenge", challenge, "--rp-id", "127.0.0.1", "--origin", "http://127.0.0.1:18081",
                "--user-handle", user_handle, "--state", str(td / "state.json"), "--key", str(td / "key.pem"),
            ], check=True, text=True, capture_output=True)
            body = json.loads(register.stdout)
            self.assertEqual(body["transactionToken"], "tx-register")
            self.assertEqual(body["credential"]["id"], body["credential"]["rawId"])
            self.assertGreater(len(b64d(body["credential"]["response"]["attestationObject"])), 100)

            assert_challenge = base64.urlsafe_b64encode(b"assertion-challenge-32-byte-value!").rstrip(b"=").decode()
            assertion = subprocess.run([
                "python3", str(HELPER), "assert", "--transaction-token", "tx-assert", "--challenge", assert_challenge,
                "--state", str(td / "state.json"), "--sign-count", "1",
            ], check=True, text=True, capture_output=True)
            assertion_body = json.loads(assertion.stdout)
            response = assertion_body["credential"]["response"]
            auth_data = b64d(response["authenticatorData"])
            client = b64d(response["clientDataJSON"])
            signature = b64d(response["signature"])
            self.assertEqual(auth_data[32], 0x05)
            self.assertEqual(int.from_bytes(auth_data[33:37], "big"), 1)
            signed = auth_data + hashlib.sha256(client).digest()
            payload = td / "signed.bin"
            sig = td / "sig.der"
            pub = td / "pub.pem"
            payload.write_bytes(signed)
            sig.write_bytes(signature)
            subprocess.run(["openssl", "pkey", "-in", str(td / "key.pem"), "-pubout", "-out", str(pub)], check=True, capture_output=True)
            verify = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(payload)], text=True, capture_output=True)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertIn("Verified OK", verify.stdout)


if __name__ == "__main__":
    unittest.main()
