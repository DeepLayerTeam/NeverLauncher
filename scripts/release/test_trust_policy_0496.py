import datetime
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

spec = importlib.util.spec_from_file_location('sign_policy_0496', Path(__file__).with_name('sign-trust-policy.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TrustPolicyRotation0496(unittest.TestCase):
    def setUp(self):
        self.root = Ed25519PrivateKey.generate()
        self.delegated = Ed25519PrivateKey.generate()
        self.seed = self.root.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
        self.public = self.root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'policy.json'
        self.out = Path(self.temp.name) / 'signed.json'
        self.policy = {
            'schemaVersion': '1.0', 'domain': 'launcher.trust.v1', 'epoch': 8,
            'issuedAt': '2026-11-01T00:00:00Z', 'expiresAt': '2026-12-01T00:00:00Z',
            'keys': [{'id': 'delegated-1', 'role': 'component',
                      'publicKey': self.delegated.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
                      'status': 'active'}],
        }

    def sign(self):
        self.path.write_text(json.dumps(self.policy))
        mod.sign_policy(self.path, self.out, self.seed, self.public)
        signed = json.loads(self.out.read_text())
        return signed

    def test_rotate_epoch_and_revoke_delegation(self):
        before = self.sign()
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o600)
        self.root.public_key().verify(bytes.fromhex(before['rootSignature']), mod.PREFIX + self.path.read_bytes())
        original = self.out.read_bytes()
        self.policy['epoch'] = 9
        self.policy['keys'][0]['status'] = 'revoked'
        after = self.sign()
        self.assertNotEqual(self.out.read_bytes(), original)
        self.assertNotEqual(after['rootSignature'], before['rootSignature'])
        self.root.public_key().verify(bytes.fromhex(after['rootSignature']), mod.PREFIX + self.path.read_bytes())

    def test_invalid_policy_never_replaces_previous_signature(self):
        self.sign()
        original = self.out.read_bytes()
        for mutation in ('inverted', 'duplicate-key', 'bad-hash', 'invalid-epoch'):
            p = json.loads(json.dumps(self.policy))
            if mutation == 'inverted':
                p['expiresAt'] = '2026-10-01T00:00:00Z'
            elif mutation == 'duplicate-key':
                p['keys'].append(p['keys'][0])
            elif mutation == 'bad-hash':
                p['keys'][0]['publicKey'] = 'zz'*32
            else:
                p['epoch'] = True
            self.path.write_text(json.dumps(p))
            with self.assertRaises(ValueError):
                mod.sign_policy(self.path, self.out, self.seed, self.public)
            self.assertEqual(self.out.read_bytes(), original)

    def test_duplicate_json_and_symlink_are_rejected(self):
        self.path.write_text(json.dumps(self.policy)[:-1] + ',"epoch":123}')
        with self.assertRaises(ValueError):
            mod.sign_policy(self.path, self.out, self.seed, self.public)
        self.path.unlink()
        source = Path(self.temp.name) / 'original.json'
        source.write_text(json.dumps(self.policy))
        self.path.symlink_to(source)
        with self.assertRaises(ValueError):
            mod.sign_policy(self.path, self.out, self.seed, self.public)
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
