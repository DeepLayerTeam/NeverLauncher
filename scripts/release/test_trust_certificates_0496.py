import datetime
import hashlib
import importlib.util
import json
import os
from unittest.mock import patch
from component_set_sign import sign_delegated_set
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('trust_certificates_0496', BASE / 'trust_certificates_0496.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CertificateLifecycle0496(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.root = Ed25519PrivateKey.generate()
        self.seed = self.root.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
        self.public = self.root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.original = self.dir / 'policy.json'
        self.signed = self.dir / 'signed.json'
        self.key = self.dir / 'delegated.key'
        issued = {
            'schemaVersion': '1.0', 'domain': 'launcher.trust.v1', 'epoch': 1,
            'issuedAt': '2026-11-01T00:00:00Z', 'expiresAt': '2027-11-01T00:00:00Z',
            'keys': [{'id': 'original', 'role': 'component', 'status': 'active', 'publicKey': self.public}],
        }
        self.original.write_text(json.dumps(issued))
        mod.root_signing.sign_policy(self.original, self.signed, self.seed, self.public)

    def digest(self):
        return hashlib.sha256(self.signed.read_bytes()).hexdigest()

    def test_issue_and_revoke_real_delegated_key(self):
        first = mod.rotate(signed_policy=self.signed, expected_sha256=self.digest(), output=self.signed,
                           root_public=self.public, root_seed=self.seed, operation='issue', key_id='new-key', private_key_output=self.key)
        self.assertEqual(first['epoch'], 2)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.key.read_text().strip()), 64)
        self.assertNotIn(self.key.read_text().strip(), self.signed.read_text())
        signed_env = {
            'LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY': self.public,
            'LAUNCHER_COMPONENT_TRUST_POLICY_FILE': str(self.signed),
            'LAUNCHER_COMPONENT_DELEGATED_ED25519_SEED': self.key.read_text().strip(),
            'LAUNCHER_COMPONENT_DELEGATED_KEY_ID': 'new-key',
        }
        with patch.dict(os.environ, signed_env):
            real_signature, _ = sign_delegated_set(b'{"productVersion":"0.49.6"}')
            self.assertEqual(json.loads(real_signature)['trustEpoch'], 2)
        with self.assertRaises(mod.CertificateError):
            mod.rotate(signed_policy=self.signed, expected_sha256='0'*64, output=self.signed,
                       root_public=self.public, root_seed=self.seed, operation='revoke', key_id='new-key')
        second = mod.rotate(signed_policy=self.signed, expected_sha256=self.digest(), output=self.signed,
                            root_public=self.public, root_seed=self.seed, operation='revoke', key_id='new-key')
        self.assertEqual(second['epoch'], 3)
        policy = mod.current_policy(self.signed, self.digest(), self.public)
        self.assertEqual(next(k for k in policy['keys'] if k['id'] == 'new-key')['status'], 'revoked')
        with patch.dict(os.environ, signed_env):
            with self.assertRaises(ValueError):
                sign_delegated_set(b'{"productVersion":"0.49.6"}')

    def test_forged_policy_and_duplicate_key_rejected(self):
        raw = bytearray(self.signed.read_bytes())
        raw[-4] ^= 1
        self.signed.write_bytes(raw)
        with self.assertRaises(Exception):
            mod.rotate(signed_policy=self.signed, expected_sha256=self.digest(), output=self.signed,
                       root_public=self.public, root_seed=self.seed, operation='issue', key_id='another', private_key_output=self.key)
        self.assertFalse(self.key.exists())


if __name__ == '__main__':
    unittest.main()
