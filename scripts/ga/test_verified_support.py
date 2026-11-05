"""Заявления о подписанной поддержке должны выводиться из полной GA-проверки точных байтов."""
from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_full_evidence_04315 as fixture
from test_verified_targets_0360 import COMMIT, NOW
from verified_targets import verify
from verified_support_0440 import document, serialize, check_file, BOUNDS


class SignedSupportIntegrationTests(unittest.TestCase):
    def setUp(self):
        with patch.object(fixture, 'VER', '0.44.0'):
            f = fixture.CompleteExecutionEvidenceTests('test_archive_replays_real_signature_and_all_six_final_bytes')
            f.setUp()
        self.addCleanup(f.doCleanups)
        self.fixture = f
        self.report = None
        self.path = Path(f.base.parent.tmp.name) / 'GA_VERIFIED_SUPPORT_0440.json'

    def full_receipt(self):
        f = self.fixture
        return verify(f.bundle, f.evidence, f.key, '0.44.0', COMMIT, now=NOW)

    def test_full_independent_ga_populates_exact_six_platform_claims(self):
        receipt = self.full_receipt()
        doc = document(receipt)
        self.assertEqual({x['target'] for x in doc['targets']}, {
            'windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64',
            'darwin-x64', 'darwin-arm64'})
        self.assertEqual(doc['approvalSha256'], receipt['approvalSha256'])
        self.assertGreater(len(doc['targets'][0]['security']), 6)
        self.assertEqual(doc['supportBoundaries'], list(BOUNDS))
        self.path.write_bytes(serialize(doc))
        check_file(self.path, receipt)

    def test_edited_support_claim_rejected_even_if_json_valid(self):
        receipt = self.full_receipt()
        value = document(receipt)
        value['targets'][0]['security'].append({'capability': 'unverified', 'scope': 'client', 'verification': 'invented'})
        self.path.write_bytes(serialize(value))
        with self.assertRaisesRegex(ValueError, 'differ'): check_file(self.path, receipt)

    def test_support_report_does_not_replace_evidence(self):
        receipt = self.full_receipt()
        self.path.write_bytes(serialize(document(receipt)))
        (self.fixture.evidence / 'targets/linux-arm64/security-0431/securityNativeRevocation.jsonl').unlink()
        with self.assertRaises(ValueError): self.full_receipt()

    def test_signed_receipt_must_contain_all_capabilities(self):
        receipt = self.full_receipt()
        receipt['targets'][0]['securityCapabilitiesVerified'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete independently verified'): document(receipt)

    def test_missing_report_refused(self):
        with self.assertRaisesRegex(ValueError, 'missing'): check_file(self.path, self.full_receipt())


if __name__ == '__main__':
    unittest.main()
