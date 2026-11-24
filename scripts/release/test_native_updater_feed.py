import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_updater_feed import build_feed, verify_signature, release_notes


def b64(raw):
    return base64.b64encode(raw).decode()


class NativeUpdaterFeed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'launcher.zip'
        self.key = Ed25519PrivateKey.generate()
        self.key_id = b'12345678'
        self.public = b64(('untrusted comment: public key\n' + b64(b'Ed' + self.key_id + self.key.public_key().public_bytes_raw())).encode())
        self.package()
        self.sign('1.1.1')

    def package(self, version='1.1.1', mode='authenticode-rfc3161'):
        with zipfile.ZipFile(self.path, 'w') as z:
            z.writestr('COMPONENT_UPDATE_MANIFEST.json', json.dumps({'product': 'Launcher', 'productVersion': version, 'platform': 'windows', 'architecture': 'x64', 'trustMode': mode, 'components': [{'component': x} for x in ['desktop', 'guard', 'runtime', 'sensor']], 'supportFiles': [{'component': 'updater'}]}))

    def sign(self, version):
        comment = f'timestamp:1\tfile:launcher.zip\tversion:{version}'
        sig = self.key.sign(hashlib.blake2b(self.path.read_bytes()).digest())
        text = '\n'.join(['untrusted comment: signature', b64(b'ED' + self.key_id + sig), 'trusted comment: ' + comment, b64(self.key.sign(sig + comment.encode()))])
        self.signature = b64(text.encode())
        Path(str(self.path) + '.sig').write_text(self.signature)

    def feed(self, url='https://release.example/v1.1.1'):
        return build_feed('1.1.1', url, [self.path], self.public)

    def test_valid_signature_and_feed(self):
        self.assertEqual(self.feed()['platforms']['windows-x86_64']['signature'], self.signature)

    def test_version_scoped_release_notes(self):
        changelog = '# History\n## 1.1.10 — Other\nWrong\n## 1.1.1 — Release\n- Correct\n## 1.1.0 — Old\nOld'
        notes = release_notes('1.1.1', changelog)
        self.assertEqual(notes, '- Correct')
        feed = build_feed('1.1.1', 'https://release.example', [self.path], self.public, notes=notes)
        self.assertEqual(feed['notes'], notes)
        for bad in ('', '## 1.1.1\n', changelog + '\n## 1.1.1\nDuplicate', '## 1.1.1\n' + 'x'*16001):
            with self.assertRaises(ValueError): release_notes('1.1.1', bad)
        with self.assertRaises(ValueError): build_feed('1.1.1', 'https://release.example', [self.path], self.public, notes=' ')

    def test_tampered_bytes(self):
        with self.path.open('ab') as f:
            f.write(b'tamper')
        with self.assertRaises(InvalidSignature): self.feed()

    def test_relabelled_release(self):
        self.sign('1.0.0')
        with self.assertRaises(ValueError): self.feed()

    def test_tampered_trusted_comment(self):
        altered = b64(base64.b64decode(self.signature).replace(b'version:1.1.1', b'version:1.2.0'))
        with self.assertRaises(InvalidSignature): verify_signature(self.path, altered, self.public, '1.2.0')

    def test_wrong_key(self):
        wrong = b64(('untrusted comment: public key\n' + b64(b'Ed' + self.key_id + Ed25519PrivateKey.generate().public_key().public_bytes_raw())).encode())
        with self.assertRaises(InvalidSignature): verify_signature(self.path, self.signature, wrong, '1.1.1')

    def test_unsafe_feed_url(self):
        with self.assertRaises(ValueError): self.feed('http://release.example')

    def test_development_package(self):
        self.package(mode='unsigned-development'); self.sign('1.1.1')
        with self.assertRaises(ValueError): self.feed()

    def test_duplicate_target(self):
        with self.assertRaises(ValueError): build_feed('1.1.1', 'https://release.example', [self.path, self.path], self.public)

if __name__ == '__main__': unittest.main()
