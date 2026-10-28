import copy
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

MODULE = Path(__file__).with_name('runtime_acceptance_0350.py')
spec = importlib.util.spec_from_file_location('runtime_acceptance_0350', MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = 'a' * 40
MATRIX = 'b' * 64
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def fixture():
    targets = ['linux-java17-default', 'windows-java21-mods']
    package = {'packageId': 'release-0350', 'version': '0.35.0', 'channel': 'stable', 'status': 'integrity-passed'}
    cov = {'required': 2, 'verified': 2, 'matrixSha256': MATRIX,
           'sourceSha': SHA, 'stablePublishEligible': True,
           'targetCoverage': {x: True for x in targets}, 'targetBlockers': {}}
    policy = {'source': 'production-runtime-gate-0.34.11', 'requiredLevel': 'trusted-runtime',
              'sourceSha': SHA, 'publishEligible': True, 'matrixSha256': MATRIX,
              'requiredTargets': 2, 'verifiedTargets': 2, 'targetCoverage': cov['targetCoverage'].copy(), 'targetBlockers': {}}
    validations = {'integrity': {'result': 'passed'}, 'effectivePolicy': policy}
    expiry = (NOW + timedelta(hours=1)).isoformat()
    evidence = [{'runId': 'run-' + str(i), 'targetId': t, 'status': 'signature-and-execution-verified', 'expiresAt': expiry}
                for i, t in enumerate(targets)]
    runs = [{'runId': 'run-' + str(i), 'stages': {stage: {'status': 'passed'} for stage in mod.STAGES}}
            for i, t in enumerate(targets)]
    report = {'packageId': 'release-0350', 'manualCertificationAllowed': False, 'coverage': cov,
              'runs': runs, 'evidence': evidence}
    return package, validations, report


class AcceptanceTests(unittest.TestCase):
    def check(self, inputs):
        return mod.assess(*inputs, 'release-0350', '0.35.0', SHA, now=NOW)

    def test_real_coverage_fixture(self):
        self.assertEqual(self.check(fixture())['verifiedTargets'], 2)

    def deny(self, operation):
        values = fixture()
        operation(*values)
        with self.assertRaises(mod.Blocked):
            self.check(values)

    def test_integrity_only(self):
        self.deny(lambda p, v, r: v['effectivePolicy'].update(publishEligible=False))

    def test_wrong_version(self):
        self.deny(lambda p, v, r: p.update(version='0.34.12'))

    def test_wrong_channel(self):
        self.deny(lambda p, v, r: p.update(channel='dev'))

    def test_source_mismatch(self):
        self.deny(lambda p, v, r: r['coverage'].update(sourceSha='c' * 40))

    def test_missing_one_target(self):
        self.deny(lambda p, v, r: r['evidence'].pop())

    def test_inconclusive_target(self):
        self.deny(lambda p, v, r: r['runs'][0]['stages']['gameplay-smoke'].update(status='inconclusive'))

    def test_only_tcp_join(self):
        self.deny(lambda p, v, r: r['runs'][0]['stages']['gameplay-smoke'].update(status='failed'))

    def test_stale_certificate(self):
        self.deny(lambda p, v, r: r['evidence'][0].update(expiresAt=(NOW+timedelta(minutes=5)).isoformat()))

    def test_forged_evidence(self):
        self.deny(lambda p, v, r: r['evidence'][0].update(status='invalid'))

    def test_replay(self):
        self.deny(lambda p, v, r: r['evidence'][1].update(runId=r['evidence'][0]['runId']))

    def test_matrix_race(self):
        self.deny(lambda p, v, r: r['coverage'].update(matrixSha256='f'*64))

    def test_operator_flag(self):
        self.deny(lambda p, v, r: r.update(manualCertificationAllowed=True))

    def test_no_required_targets(self):
        self.deny(lambda p, v, r: v['effectivePolicy'].update(requiredTargets=0, verifiedTargets=0))

    def test_missing_stage(self):
        self.deny(lambda p, v, r: r['runs'][1]['stages'].pop('authentication'))

    def test_backend_error(self):
        self.deny(lambda p, v, r: v.update(effectivePolicy={}))

    def test_report_ineligible(self):
        self.deny(lambda p, v, r: r['coverage'].update(stablePublishEligible=False))

    def test_worker_trust_invalid(self):
        self.deny(lambda p, v, r: r['coverage']['targetBlockers'].update({'worker':'untrusted'}))


if __name__ == '__main__':
    unittest.main()
