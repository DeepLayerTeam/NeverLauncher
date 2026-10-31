#!/usr/bin/env python3
"""Executable negative tests for the production Linux Guard manifest signature."""
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from guard_manifest_sign_0437 import DOMAIN, sign_manifest


class GuardManifestSignatureTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        key = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.pub = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.env = patch.dict(os.environ, {
            "LAUNCHER_COMPONENT_SET_ED25519_SEED": self.seed.hex(),
            "LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY": self.pub,
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_real_signature_and_tampered_manifest(self):
        payload = b'{"productVersion":"0.43.7","artifacts":[]}'
        signature = sign_manifest(payload)
        self.assertEqual(len(signature), 129)
        self.assertTrue(signature.endswith(b"\n"))
        key = Ed25519PrivateKey.from_private_bytes(self.seed).public_key()
        key.verify(bytes.fromhex(signature.decode().strip()), DOMAIN + payload)
        with self.assertRaises(InvalidSignature):
            key.verify(bytes.fromhex(signature.decode().strip()), DOMAIN + payload + b" ")
        with self.assertRaises(InvalidSignature):
            key.verify(bytes.fromhex(signature.decode().strip()), payload)

    def test_mismatched_public_key_fails_closed(self):
        with patch.dict(os.environ, {"LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY": "ff" * 32}):
            with self.assertRaises(ValueError):
                sign_manifest(b"valid")

    def test_missing_signing_seed_fails_closed(self):
        with patch.dict(os.environ, {"LAUNCHER_COMPONENT_SET_ED25519_SEED": ""}):
            with self.assertRaises(ValueError):
                sign_manifest(b"valid")


class LinuxPackageIntegrationTests(GuardManifestSignatureTests):
    def test_exact_generated_tar_contains_signed_manifest(self):
        import importlib.util
        import io
        import json
        import struct
        import sys
        import tarfile
        import tempfile
        from pathlib import Path

        module_path = Path(__file__).with_name("linux-package.py")
        spec = importlib.util.spec_from_file_location("never_linux_package_0437", module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for pattern, _ in module.COMPONENTS.values():
                file = out / pattern.format(arch="x64")
                elf = bytearray(64)
                elf[:4] = b"\x7fELF"
                elf[4:6] = b"\x02\x01"
                struct.pack_into("<HH", elf, 16, 2, 62)
                file.write_bytes(elf)
            from unittest.mock import patch
            with patch.object(module, "signed_set", side_effect=lambda d:(json.dumps(d).encode(),b"component-test-sig")), \
                 patch.object(module, "sign_delegated_set", return_value=(b"delegated-test-sig",b"delegated-test-policy")):
                module.write_package(out,"0.43.7","x64")
            package=out / "launcher-linux-x64-0.43.7.tar.gz"
            with tarfile.open(package,"r:gz") as archive:
                manifest=archive.extractfile("launcher/LINUX_PACKAGE_MANIFEST.json").read()
                signature=archive.extractfile("launcher/LINUX_PACKAGE_MANIFEST.json.ed25519").read()
                update=json.loads(archive.extractfile("launcher/COMPONENT_UPDATE_MANIFEST.json").read())
                assert any(row["component"]=="guard-manifest-signature" for row in update["supportFiles"])
                key=Ed25519PrivateKey.from_private_bytes(self.seed).public_key()
                key.verify(bytes.fromhex(signature.decode().strip()),DOMAIN+manifest)


if __name__ == "__main__":
    unittest.main()
