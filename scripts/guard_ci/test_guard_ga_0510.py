#!/usr/bin/env python3
"""Non-production fixtures for the *real* Guard 0.51.0 release gate.

All positive test receipts here are isolated unit fixtures; no test fixture may
be reused as a real independent acceptance or production certificate.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import guard_ga_0510 as gate
import native_signed_0510 as native
import capture_game_0510 as capture
import reviewer_sign_0510 as signhelper
from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption

SHA = 'a' * 64
COMMIT = 'b' * 40


class GuardGATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'evidence'
        self.root.mkdir()
        (self.root / 'sample.txt').write_text('real byte-bound fixture only', encoding='utf-8')
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.base / 'reviewer.pub'
        self.pub.write_bytes(self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.manifest = self.base / 'review.json'
        self.sig = self.base / 'review.sig'
        self.now = datetime.now(timezone.utc)

    def seal(self, *, reviewer='reviewer-2', publisher='publisher-1', issued=None):
        data = {'schema': gate.SCHEMA, 'version': gate.VERSION, 'commit': COMMIT,
                'reviewer': reviewer, 'publisher': publisher,
                'issuedAt': (issued or self.now).isoformat(),
                'files': gate.evidence_inventory(self.root)}
        raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        self.manifest.write_bytes(raw)
        self.sig.write_bytes(self.priv.sign(gate.DOMAIN + raw))

    def review(self):
        return gate.approval(self.root, self.manifest, self.sig,
                             self.pub, COMMIT, 'publisher-1', now=self.now)

    def test_signature_binds_all_original_bytes(self):
        self.seal()
        self.assertEqual(1, self.review()['filesBound'])
        (self.root / 'sample.txt').write_text('modified fixture', encoding='utf-8')
        with self.assertRaisesRegex(gate.Blocked, 'every exact evidence byte'):
            self.review()

    def test_signature_cannot_be_reused_across_versions(self):
        self.seal()
        data = json.loads(self.manifest.read_text())
        data['version'] = '0.50.12'
        raw = json.dumps(data).encode()
        self.manifest.write_bytes(raw)
        self.sig.write_bytes(self.priv.sign(gate.DOMAIN + raw))
        with self.assertRaisesRegex(gate.Blocked, 'exact release'):
            self.review()

    def test_invalid_signature_rejected(self):
        self.seal()
        self.sig.write_bytes(b'0' * 64)
        with self.assertRaisesRegex(gate.Blocked, 'signature invalid'):
            self.review()

    def test_reviewer_must_not_be_publisher(self):
        self.seal(reviewer='publisher-1')
        with self.assertRaisesRegex(gate.Blocked, 'reviewer cannot'):
            self.review()

    def test_stale_review_rejected(self):
        self.seal(issued=self.now - timedelta(hours=96))
        with self.assertRaisesRegex(gate.Blocked, 'stale'):
            self.review()

    def test_symlink_evidence_rejected(self):
        (self.root / 'link').symlink_to(self.root / 'sample.txt')
        with self.assertRaisesRegex(gate.Blocked, 'symlink'):
            gate.evidence_inventory(self.root)

    def test_case_collision_rejected(self):
        (self.root / 'SAMPLE.TXT').write_text('duplicate path differing in case')
        with self.assertRaisesRegex(gate.Blocked, 'case-ambiguous'):
            gate.evidence_inventory(self.root)

    def test_duplicate_json_keys_rejected(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"status":"PASS","status":"FAIL"}')
        with self.assertRaisesRegex(gate.Blocked, 'duplicate JSON key'):
            gate.doc(path)

    def test_missing_native_report_rejected(self):
        signed = {'targets': {t: {'sha256': SHA} for t in gate.TARGETS}}
        with self.assertRaisesRegex(gate.Blocked, 'missing/non-regular'):
            gate.verified_native(self.root, COMMIT, signed)

    def test_native_wrong_package_rejected(self):
        d = self.root / 'native-signed'
        d.mkdir()
        (self.root / 'signed').mkdir()
        (self.root / 'signed' / 'RELEASE_MANIFEST.json').write_text('manifest')
        report = {'schema': 'neverlauncher.guard.native-signed/0510', 'version': gate.VERSION,
                  'commit': COMMIT, 'target': 'windows-x64', 'status': 'native-verified',
                  'packageSha256': 'c'*64, 'releaseManifestSha256': gate.file_hash(self.root / 'signed' / 'RELEASE_MANIFEST.json'),
                  'nativeOS': 'Windows', 'nativeArch': 'x64', 'verifier': 'authenticode-chain-timestamp',
                  'publisherSigner': 'publisher-1', 'operator': 'native-operator', 'executionId': 'native-run-1'}
        (d / 'windows-x64.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(gate.Blocked, 'final package'):
            gate.verified_native(self.root, COMMIT, {'targets': {t:{'sha256':SHA} for t in gate.TARGETS}})

    def test_incomplete_adversarial_game_rejected(self):
        with self.assertRaisesRegex(gate.Blocked, 'missing/non-regular'):
            gate.verified_jvm(self.root)

    def test_missing_real_game_rejected(self):
        with self.assertRaisesRegex(gate.Blocked, 'missing/non-regular'):
            gate.verified_minecraft(self.root, {'targets':{t: {'sha256':SHA} for t in gate.TARGETS}}, COMMIT)

    def test_non_native_signing_rejected(self):
        target = 'darwin-x64' if os.name != 'darwin' else 'windows-x64'
        with self.assertRaisesRegex(ValueError, 'native signing'):
            native.assert_host(target)

    def test_no_final_delivery_means_no_ga(self):
        self.seal()
        with self.assertRaises(Exception):
            gate.gate(self.root, self.manifest, self.sig, self.pub, COMMIT, 'publisher-1',
                      'immutable-stage', '12345', self.base / 'shadow-key', now=self.now)

    def test_reviewer_signs_exact_real_files_only_from_external_private_key(self):
        pem = self.base / 'reviewer.pem'
        pem.write_bytes(self.priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        os.chmod(pem, 0o600)
        signed = signhelper.sign(self.root, pem, 'reviewer-2', 'publisher-1',
                                 COMMIT, self.manifest, self.sig)
        self.assertEqual('signed-pending-independent-gate', signed['status'])
        self.assertEqual(1, self.review()['filesBound'])
        with self.assertRaisesRegex(gate.Blocked, 'never overwrite'):
            signhelper.sign(self.root, pem, 'reviewer-2', 'publisher-1',
                            COMMIT, self.manifest, self.sig)

    def test_game_capture_requires_native_real_join_and_exact_package(self):
        root = self.base / 'bundle'
        root.mkdir()
        file = root / 'game-installer.zip'
        file.write_bytes(b'actual package bytes test fixture')
        work = self.root / 'game'
        work.mkdir()
        paper = work / 'paper.log'
        paper.write_text('real log required in production; unit fixture only')
        declared = {'version': gate.VERSION,
                    'targets':{'linux-x64': {'file':file.name,'sha256':gate.file_hash(file)}}}
        with mock.patch.object(capture, 'inventory', return_value=declared), \
             mock.patch.object(capture, 'verify_game', return_value={'loader':'fabric'}), \
             mock.patch.object(capture.platform, 'system', return_value='Linux'), \
             mock.patch.object(capture.platform, 'machine', return_value='x86_64'):
            data = capture.capture(work,paper,'GameUser','linux-x64','fabric',COMMIT,file,root)
        self.assertEqual(COMMIT,data['commit'])
        self.assertEqual('fabric',gate.doc(work/'run-identity.json')['loader'])
        with self.assertRaisesRegex(gate.Blocked,'do not overwrite'):
            with mock.patch.object(capture,'inventory', return_value=declared), \
                 mock.patch.object(capture,'verify_game', return_value={'loader':'fabric'}):
                capture.capture(work,paper,'GameUser','linux-x64','fabric',COMMIT,file,root)

    def test_game_capture_blocks_foreign_installer(self):
        from unittest.mock import patch
        work = self.root / 'g'
        work.mkdir()
        paper = work / 'paper.log'
        paper.write_text('test')
        bundle = self.base / 'bundle'
        bundle.mkdir()
        f = bundle / 'package.zip'
        f.write_bytes(b'test')
        with patch.object(capture, 'inventory', return_value={'version':gate.VERSION,
             'targets':{'linux-x64':{'file':'other-package.zip','sha256':gate.file_hash(f)}}}), \
             patch.object(capture.platform,'system',return_value='Linux'), \
             patch.object(capture.platform,'machine',return_value='x86_64'):
            with self.assertRaisesRegex(gate.Blocked,'not the exact final'):
                capture.capture(work,paper,'GameUser','linux-x64','fabric',COMMIT,f,bundle)

    def test_approval_not_stored_inside_evidence(self):
        self.seal()
        shutil.copy2(self.manifest, self.root / 'review.json')
        with self.assertRaisesRegex(gate.Blocked, 'every exact evidence byte'):
            self.review()


if __name__ == '__main__':
    unittest.main()
