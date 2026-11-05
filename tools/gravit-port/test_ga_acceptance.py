"""Local integration regressions. The fake checker/probes do NOT certify GA."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ga_acceptance_0500 as ga


def sh(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    if isinstance(data, dict):
        data = json.dumps(data).encode()
    path.write_bytes(data)
    path.chmod(0o600)
    return path


class TestLiveAcceptance0500(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rehearsal = self.root / 'rehearsal'
        self.rehearsal.mkdir(mode=0o700)
        self.output = self.root / 'private'
        self.output.mkdir(mode=0o700)
        self.refs = {}
        self.cases = []
        self.old = 'a' * 64
        self.new = 'b' * 64
        self.target = 'c' * 64
        for cls in ga.CLASSES:
            base = self.rehearsal / cls
            base.mkdir(mode=0o700)
            original = save(base / 'source.zip', ('real original bytes of ' + cls).encode())
            run = 'run-' + cls
            project = 'project-' + cls
            plan = save(base / 'plan.json', {
                'referenceClass': cls, 'runId': run, 'projectId': project,
                'sourceArchive': str(original)})
            cert = save(base / 'certificate.json', {
                'referenceClass': cls, 'runId': run, 'projectId': project,
                'sourceSha256': ga.sha(original), 'commitSha': '1' * 40,
                'targetReleaseSha256': self.target})
            evidence = base / 'ga-evidence'
            evidence.mkdir(mode=0o700)
            self.refs[cls] = {'plan': str(plan), 'certificate': str(cert), 'evidenceDir': str(evidence)}
            case = {'referenceClass': cls, 'runId': run, 'projectId': project,
                    'sourceSha256': ga.sha(original), 'installedBeforeSha256': self.old,
                    'installedAfterSha256': self.new, 'updatePackageSha256': 'd' * 64}
            for step, digest in (('pre-update-live', self.old), ('post-update-live', self.new)):
                report = {'data': {'runId': run,
                                   'ready': step == 'pre-update-live',
                                   'blockers': [] if step == 'pre-update-live' else ['non-authoritative-local-only'],
                                   'liveSession': {'clientSha256': digest, 'joinedAt': '2026-11-02T19:59:00Z',
                                                   'playerUuid': '12345678-1234-1234-1234-123456789abc'},
                                   'probes': [{'name': n, 'passed': True, 'evidenceSha256': 'e' * 64}
                                              for n in ga.rehearsal.PROBES]}}
                file = save(base / (step + '.json'), report)
                case[('preUpdateWitnessSha256' if step == 'pre-update-live' else 'postUpdateWitnessSha256')] = ga.sha(file)
            save(base / 'signed-update.json', {'status': 'committed', 'packageSha256': case['updatePackageSha256']})
            self.cases.append(case)
        self.cohort_file = save(self.rehearsal / 'cohort-04910.json', {
            'format': ga.rehearsal.FORMAT, 'status': 'isolated-stage-pass-not-production-GA',
            'productionGA': False, 'cases': self.cases})
        self.module_checks = {}
        for index, module in enumerate(ga.MODULE_IDS):
            cls = ga.CLASSES[index % len(ga.CLASSES)]
            case = next(c for c in self.cases if c['referenceClass'] == cls)
            executable = self.root / ('check-' + module)
            evidence = self.root / ('output-' + module)
            fixture = {'moduleId': module, 'projectId': case['projectId'], 'runId': case['runId'],
                       'sourceSha256': case['sourceSha256'], 'passed': True,
                       'observations': ['request accepted', 'observable state changed'],
                       'evidenceFile': str(evidence), 'evidenceSha256': sh(b'actual stdout and logs')}
            program = ('#!/usr/bin/env python3\nimport json, os\nfrom pathlib import Path\n'
                       'Path(' + repr(str(evidence)) + ').write_bytes(b"actual stdout and logs")\n'
                       'print(json.dumps(' + repr(fixture) + '))\n')
            save(executable, program.encode()).chmod(0o700)
            self.module_checks[module] = {'referenceClass': cls, 'executable': str(executable),
                                          'executableSha256': ga.sha(executable), 'args': [], 'timeoutSeconds': 8}
        checker = save(self.root / 'checker', b'#!/bin/sh\nexit 0\n')
        checker.chmod(0o700)
        key = save(self.root / 'trusted.pem', b'not a real public key: mocked checker')
        self.cfg = {'format': ga.FORMAT, 'checker': str(checker), 'checkerSha256': ga.sha(checker),
                    'trustedPublicKey': str(key), 'rehearsalRoot': str(self.rehearsal),
                    'rehearsalReport': str(self.cohort_file), 'references': self.refs,
                    'modules': self.module_checks}

    def test_real_subprocesses_and_private_retained_evidence(self):
        with patch.object(ga, 'live_certificate_verification') as verify:
            report = ga.run(self.cfg, self.output)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(report['moduleCheckCount'], 19)
        self.assertFalse(report['productionGA'])
        self.assertEqual(report['status'], 'LIVE_CHECKS_PASSED_REVIEW_REQUIRED')
        self.assertEqual(len(list(self.output.glob('M*.evidence'))), 19)
        self.assertTrue((self.output / 'acceptance-0500.json').is_file())
        with self.assertRaises(ga.Blocked):
            ga.run(self.cfg, self.output)  # no overwritten evidence

    def test_missing_module_blocks_before_live_verification(self):
        self.module_checks.pop('M17')
        with patch.object(ga, 'live_certificate_verification') as verify:
            with self.assertRaisesRegex(ga.Blocked, '19 real'):
                ga.run(self.cfg, self.output)
            self.assertEqual(verify.call_count, 1)

    def test_tampered_minecraft_join_blocks(self):
        save(self.rehearsal / 'proxy-network' / 'post-update-live.json', {'data': {'runId': 'changed'}})
        with patch.object(ga, 'live_certificate_verification') as verify:
            with self.assertRaisesRegex(ga.Blocked, 'witness changed'):
                ga.run(self.cfg, self.output)
            verify.assert_not_called()

    def test_changed_source_archive_blocks(self):
        save(self.rehearsal / 'fileauth-single' / 'source.zip', b'updated Gravit source')
        with self.assertRaisesRegex(ga.Blocked, 'original Gravit source changed'):
            ga.check_migration(self.cfg, ga.doc(self.cohort_file))

    def test_different_client_after_update_blocks(self):
        self.cases[0]['installedAfterSha256'] = self.old
        save(self.cohort_file, {'format': ga.rehearsal.FORMAT, 'status': 'isolated-stage-pass-not-production-GA',
                                'productionGA': False, 'cases': self.cases})
        with self.assertRaisesRegex(ga.Blocked, 'not updated'):
            ga.check_migration(self.cfg, ga.doc(self.cohort_file))

    def test_module_evidence_must_be_current(self):
        self.module_checks['M01']['executableSha256'] = 'f' * 64
        with self.assertRaisesRegex(ga.Blocked, 'pinned file'):
            ga.check_modules(self.cfg, self.refs, self.output)

    def test_second_live_check_revoked_blocks_final_report(self):
        calls = 0
        def live(*_):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ga.Blocked('route revoked during module checks')
        with patch.object(ga, 'live_certificate_verification', side_effect=live):
            with self.assertRaisesRegex(ga.Blocked, 'route revoked'):
                ga.run(self.cfg, self.output)
        self.assertFalse((self.output / 'acceptance-0500.json').exists())

    def test_secret_environment_is_removed_from_module_probes(self):
        with patch.dict('os.environ', {'LAUNCHER_MIGRATION_GA_TOKEN':'sensitive', 'POSTGRES_DSN':'postgres://secret',
                                       'AWS_SECRET_ACCESS_KEY':'some-key', 'PATH':'/usr/bin'}):
            env = ga.clean_env()
        self.assertNotIn('LAUNCHER_MIGRATION_GA_TOKEN', env)
        self.assertNotIn('POSTGRES_DSN', env)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
        self.assertEqual(env['PATH'], '/usr/bin')

    def test_symlinked_evidence_rejected(self):
        original = self.rehearsal / 'fileauth-single' / 'source.zip'
        symlink = self.root / 'linked.zip'
        symlink.symlink_to(original)
        with self.assertRaisesRegex(ga.Blocked, 'unsafe checked file'):
            ga.sha(symlink)


if __name__ == '__main__':
    unittest.main()
