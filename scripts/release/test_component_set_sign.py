#!/usr/bin/env python3
"""Executable signing/compatibility tests using a throwaway Ed25519 key."""
from __future__ import annotations

import copy
import os
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from component_set_sign import signed_set


class ComponentSetSigningTest(unittest.TestCase):
    def setUp(self):
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.prev = (os.environ.get("NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED"), os.environ.get("NEVERLAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY"))
        os.environ["NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED"] = seed.hex()
        os.environ["NEVERLAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY"] = public.hex()
        self.public = private.public_key()

    def tearDown(self):
        for name, value in zip(("NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED", "NEVERLAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY"), self.prev):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def fixture(self, platform="linux"):
        roles = ["desktop", "guard", "runtime"] + (["sensor"] if platform == "windows" else [])
        return {
            "schemaVersion": "1.0", "product": "NeverLauncher", "productVersion": "0.23.10",
            "platform": platform,
            "components": [{"component": role} for role in roles],
            "supportFiles": [{"component": "updater", "executable": True}],
        }

    def test_signature_and_protocol_roles(self):
        for platform in ("linux", "windows", "macos"):
            data, sig = signed_set(self.fixture(platform))
            import json
            envelope = json.loads(sig)
            assert envelope["algorithm"] == "ed25519"
            self.public.verify(bytes.fromhex(envelope["signature"]), data)
            parsed = json.loads(data)
            self.assertEqual(parsed["schemaVersion"], "1.0")  # 0.23.9 upgrade compatibility
            self.assertEqual({p["component"] for p in parsed["componentSet"]["protocols"]},
                             {"desktop", "guard", "runtime", "updater"} | ({"sensor"} if platform == "windows" else set()))
            with self.assertRaises(Exception):
                self.public.verify(bytes.fromhex(envelope["signature"]), data + b" ")

    def test_missing_key_fails_closed(self):
        os.environ.pop("NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED")
        with self.assertRaises(RuntimeError):
            signed_set(self.fixture())
        unsigned, detached = signed_set(self.fixture(), development=True)
        self.assertIsNone(detached)
        self.assertIn(b'"componentSet"', unsigned)

    def test_wrong_public_key_rejected(self):
        os.environ["NEVERLAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY"] = "00" * 32
        with self.assertRaises(RuntimeError):
            signed_set(self.fixture())

    def test_security_generation_bound_to_02311_signature(self):
        value = self.fixture()
        value["productVersion"] = "0.23.11"
        with self.assertRaises(ValueError):
            signed_set(value)
        os.environ["NEVERLAUNCHER_COMPONENT_SECURITY_GENERATION"] = "14"
        self.addCleanup(os.environ.pop,"NEVERLAUNCHER_COMPONENT_SECURITY_GENERATION",None)
        raw, signature = signed_set(value)
        import json
        self.assertEqual(json.loads(raw)["securityGeneration"], 14)
        self.public.verify(bytes.fromhex(json.loads(signature)["signature"]), raw)
        value["securityGeneration"] = 0
        with self.assertRaises(ValueError):
            signed_set(value)

    def test_missing_updater_rejected(self):
        value = self.fixture()
        value["supportFiles"] = []
        with self.assertRaises(ValueError):
            signed_set(value)


if __name__ == "__main__":
    unittest.main()
