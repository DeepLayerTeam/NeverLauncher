import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from component_set_sign import sign_delegated_set

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "sign_trust_policy_02312", ROOT / "sign-trust-policy.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def keys():
    root = Ed25519PrivateKey.generate()
    delegated = Ed25519PrivateKey.generate()

    def seed(k):
        return k.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()

    def pub(k):
        return (
            k.public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            .hex()
        )

    return root, delegated, seed, pub


class TrustPolicyTests02312(unittest.TestCase):
    def test_v2_component_is_bound_to_root_epoch_key_and_exact_manifest(self):
        root, delegated, seed, pub = keys()
        now = datetime.datetime.now(datetime.timezone.utc)
        policy = {
            "schemaVersion": "1.0",
            "domain": "launcher.trust.v1",
            "epoch": 19,
            "issuedAt": (now - datetime.timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "expiresAt": (now + datetime.timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "keys": [
                {
                    "id": "components-2026",
                    "role": "component",
                    "publicKey": pub(delegated),
                    "status": "active",
                    "notBefore": (now - datetime.timedelta(hours=1)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "policy.json").write_text(json.dumps(policy))
            module.sign_policy(
                t / "policy.json", t / "signed-policy.json", seed(root), pub(root)
            )
            raw = b'{"securityGeneration":15,"productVersion":"0.23.12"}'
            env = {
                "LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY": pub(root),
                "LAUNCHER_COMPONENT_TRUST_POLICY_FILE": str(t / "signed-policy.json"),
                "LAUNCHER_COMPONENT_DELEGATED_ED25519_SEED": seed(delegated),
                "LAUNCHER_COMPONENT_DELEGATED_KEY_ID": "components-2026",
            }
            with patch.dict(os.environ, env):
                signed, policy_bytes = sign_delegated_set(raw)
                sig = json.loads(signed)
                self.assertEqual(sig["trustEpoch"], 19)
                self.assertEqual(
                    sig["policySha256"],
                    hashlib.sha256((t / "policy.json").read_bytes()).hexdigest(),
                )
                context = (
                    "Launcher-Component-v2\n"
                    + sig["keyId"]
                    + "\n"
                    + str(sig["trustEpoch"])
                    + "\n"
                    + sig["policySha256"]
                    + "\n"
                    + sig["manifestSha256"]
                    + "\n"
                    + sig["signedAt"]
                    + "\n"
                ).encode()
                delegated.public_key().verify(
                    bytes.fromhex(sig["signature"]), context + raw
                )
                with self.assertRaises(Exception):
                    delegated.public_key().verify(
                        bytes.fromhex(sig["signature"]), context + raw + b" "
                    )
                forged = json.loads(policy_bytes)
                forged["rootSignature"] = "00" * 64
                (t / "signed-policy.json").write_text(json.dumps(forged))
                with self.assertRaises(Exception):
                    sign_delegated_set(raw)
                (t / "signed-policy.json").write_bytes(policy_bytes)
                policy["keys"][0]["status"] = "revoked"
                (t / "policy.json").write_text(json.dumps(policy))
                module.sign_policy(
                    t / "policy.json", t / "signed-policy.json", seed(root), pub(root)
                )
                with self.assertRaises(Exception):
                    sign_delegated_set(raw)

    def test_signing_rejects_unprovisioned_root(self):
        root, _, seed, pub = keys()
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "payload").write_text("{}")
            with self.assertRaises(Exception):
                module.sign_policy(t / "payload", t / "out", seed(root), "ab" * 32)


if __name__ == "__main__":
    unittest.main()
