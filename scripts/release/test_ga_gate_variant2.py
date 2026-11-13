"""Тесты независимого подтверждения с отделённой подписью (доставка и действующий Backend имитируются локально)."""
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import ga_gate_variant2 as gate


def write(path, value):
    if isinstance(value, dict):
        value = json.dumps(value, sort_keys=True).encode()
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class TestGAReleaseApproval(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        # Historical gate: exercise the original version without changing the checkout.
        source = self.root.parent / (self.root.name + "-source")
        source.mkdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(source))
        (source / "VERSION").write_text(gate.VERSION + "\n")
        patcher = patch.object(gate, "ROOT", source)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.signed = self.root / 'signed'
        self.signed.mkdir(mode=0o700)
        write(self.signed / 'RELEASE_MANIFEST.json', b'{"version":"0.50.0"}')
        self.report = {'format': gate.ga.FORMAT, 'status': 'LIVE_CHECKS_PASSED_REVIEW_REQUIRED',
                       'productionGA': False, 'migrationChecks': 36, 'moduleCheckCount': 19,
                       'completedAt': datetime.now(timezone.utc).isoformat(),
                       'commitSha': '1' * 40, 'targetReleaseSha256': '2' * 64,
                       'references': [{'referenceClass': cls, 'projectId': cls, 'runId': cls + '-run'}
                                      for cls in gate.ga.CLASSES],
                       'moduleChecks': [{'moduleId': module} for module in gate.ga.MODULE_IDS]}
        write(self.root / 'acceptance-0500.json', self.report)
        for module in gate.ga.MODULE_IDS:
            write(self.root / (module + '.evidence'), ('actual witness ' + module).encode())
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pubfile = write(self.root.parent / 'reviewer-public.key', public)
        self.approval = self.root.parent / 'review.json'
        self.sig = self.root.parent / 'signature.bin'
        self.approval_doc = {'schema': gate.APPROVAL_SCHEMA, 'version': gate.VERSION,
                             'reviewer': 'independent-operator', 'commitSha': self.report['commitSha'],
                             'targetReleaseSha256': self.report['targetReleaseSha256'], 'files': {}}
        self.config = {'references': {cls: {'certificate': str(write(self.root.parent / (cls + '.cert'),
                                                 {'reviewedBy': 'migration-operator'}))}
                                      for cls in gate.ga.CLASSES}}
        self.sign()

    def sign(self):
        self.approval_doc['files'] = {p.relative_to(self.root).as_posix(): sha(p.read_bytes())
                                      for p in self.root.rglob('*') if p.is_file()}
        raw = json.dumps(self.approval_doc, sort_keys=True).encode()
        write(self.approval, raw)
        write(self.sig, self.private.sign(gate.DOMAIN + raw))

    def test_independent_approval_and_second_live_backend_read(self):
        with patch.object(gate, 'verify_bundle', return_value={
            'releaseManifestMatchesAssets': True, 'version': '0.50.0'}), \
             patch.object(gate.ga, 'live_certificate_verification') as live:
            accepted = gate.promote(self.config, self.root, self.approval, self.sig, self.pubfile)
        self.assertTrue(accepted['independentlyApproved'])
        self.assertEqual(accepted['realModuleChecks'], 19)
        live.assert_called_once()

    def test_tampered_module_evidence_blocked(self):
        write(self.root / 'M17.evidence', b'changed')
        with self.assertRaisesRegex(gate.Blocked, 'Подписанный файл доказательства отсутствует или изменён'):
            gate.verify_approval(self.root, self.approval, self.sig, self.pubfile, self.report)

    def test_missing_module_not_accepted(self):
        (self.root / 'M19.evidence').unlink()
        with self.assertRaisesRegex(gate.Blocked, 'Независимая подпись не охватывает все проверки модулей'):
            gate.verify_approval(self.root, self.approval, self.sig, self.pubfile, self.report)

    def test_forged_reviewer_signature_blocked(self):
        write(self.sig, b'0' * 64)
        with self.assertRaisesRegex(gate.Blocked, 'Некорректная подпись независимой проверки'):
            gate.verify_approval(self.root, self.approval, self.sig, self.pubfile, self.report)

    def test_original_operator_not_independent(self):
        self.approval_doc['reviewer'] = 'migration-operator'
        self.sign()
        with patch.object(gate, 'verify_bundle', return_value={
            'releaseManifestMatchesAssets': True, 'version': '0.50.0'}):
            with self.assertRaisesRegex(gate.Blocked, 'Независимый утверждающий не должен быть оператором исходной миграции'):
                gate.promote(self.config, self.root, self.approval, self.sig, self.pubfile)

    def test_fake_delivery_never_promoted(self):
        with patch.object(gate, 'verify_bundle', return_value={
            'releaseManifestMatchesAssets': False, 'version': '0.50.0'}):
            with self.assertRaisesRegex(gate.Blocked, 'Подписанные артефакты поставки 0.50.0 не прошли'):
                gate.promote(self.config, self.root, self.approval, self.sig, self.pubfile)

    def test_stale_real_approval_cannot_be_promoted(self):
        self.report['completedAt'] = (datetime.now(timezone.utc) - timedelta(hours=80)).isoformat()
        write(self.root / 'acceptance-0500.json', self.report)
        self.sign()
        with self.assertRaisesRegex(gate.Blocked, 'устарели'):
            gate.promote(self.config, self.root, self.approval, self.sig, self.pubfile)

    def test_revoked_backend_after_approval_fails(self):
        with patch.object(gate, 'verify_bundle', return_value={
            'releaseManifestMatchesAssets': True, 'version': '0.50.0'}), \
             patch.object(gate.ga, 'live_certificate_verification', side_effect=gate.ga.Blocked('revoked')):
            with self.assertRaisesRegex(gate.ga.Blocked, 'revoked'):
                gate.promote(self.config, self.root, self.approval, self.sig, self.pubfile)


if __name__ == '__main__':
    unittest.main()
