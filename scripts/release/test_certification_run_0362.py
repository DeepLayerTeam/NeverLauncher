#!/usr/bin/env python3
"""Negative/positive regression tests for fresh 0.36.2+ certifications."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from certification_run import identity, verify, CertificationBlocked
from check_protected_run import check as check_external
from verify_current_certifications import check_admin, check_profiles, ADMIN_CHECKS, PROFILES

SHA = 'a'*40
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)
ENV = {'GITHUB_SHA': SHA, 'GITHUB_REPOSITORY': 'DeepLayerTeam/NeverLauncher',
       'GITHUB_RUN_ID': '567', 'GITHUB_RUN_ATTEMPT': '2'}


class IdentityTests(unittest.TestCase):
    def sample(self):
        return {'certificationRun': identity('0.36.2', SHA, ENV, now=NOW)}

    def test_fresh_current_run_passes(self):
        verify(self.sample(), '0.36.2', SHA, ENV, now=NOW)

    def test_old_version_format_is_preserved(self):
        verify({}, '0.36.0', SHA, {}, now=NOW)
        verify({}, '0.36.1', SHA, {}, now=NOW)

    def test_previous_attempt_previous_run_wrong_sha_or_version_rejected(self):
        for field, value in [('runId','566'), ('runAttempt',1), ('commit','b'*40),
                             ('version','0.36.1'), ('repository','other/never')]:
            with self.subTest(field=field):
                sample = self.sample()
                sample['certificationRun'][field] = value
                with self.assertRaises(CertificationBlocked):
                    verify(sample,'0.36.2', SHA, ENV, now=NOW)

    def test_missing_or_expired_or_future_report_rejected(self):
        with self.assertRaises(CertificationBlocked):
            verify({},'0.36.2', SHA, ENV, now=NOW)
        for stamp in (NOW-timedelta(hours=7), NOW+timedelta(seconds=1)):
            sample = self.sample()
            sample['certificationRun']['generatedAt'] = stamp.isoformat().replace('+00:00', 'Z')
            with self.assertRaises(CertificationBlocked):
                verify(sample, '0.36.2', SHA, ENV, now=NOW)

    def test_no_ci_run_or_wrong_sha_rejected(self):
        for field in ('GITHUB_SHA','GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):
            with self.subTest(field=field), self.assertRaises(CertificationBlocked):
                identity('0.36.2', SHA, {k:v for k,v in ENV.items() if k != field}, now=NOW)


class ProtectedRunTests(unittest.TestCase):
    def sample(self):
        return dict(head_sha=SHA,status='completed',conclusion='success',event='workflow_dispatch',
                    path='DeepLayerTeam/NeverLauncher/.github/workflows/client-factory-ga-0280.yml',
                    id=654, run_attempt=2, run_started_at=NOW.isoformat().replace('+00:00', 'Z'))

    def test_external_latest_passes(self):
        check_external(self.sample(),'0.36.2',SHA,'client-factory-ga-0280.yml',now=NOW)

    def test_expired_wrong_commit_failed_and_wrong_workflow_denied(self):
        for field, value in [('head_sha','b'*40), ('conclusion','failure'),
                             ('run_started_at',(NOW-timedelta(hours=25)).isoformat().replace('+00:00','Z')),
                             ('path','other.yml'), ('run_attempt',0)]:
            item = self.sample(); item[field] = value
            with self.subTest(field=field),self.assertRaises(ValueError):
                check_external(item,'0.36.2', SHA,'client-factory-ga-0280.yml',now=NOW)


class ActiveGATests(unittest.TestCase):
    def sample_admin(self):
        return {'status':'passed','productVersion':'0.36.2','commit':SHA,
                'checks':sorted(ADMIN_CHECKS), 'adminBundle':{'index.html':'b'*64,'assets/main.js':'c'*64},
                'openapiSha256':'d'*64, **self.sample_identity()}

    def sample_identity(self):
        return {'certificationRun':identity('0.36.2',SHA,ENV,now=NOW)}

    def sample_profiles(self):
        return {'status':'passed','productVersion':'0.36.2','commit':SHA,
                'suites':[{'id':key,'status':'passed','tests':sorted(values),
                           'command':['go','test','-json','-race','-count=1','-timeout=7m','./pkg']}
                          for key,values in PROFILES.items()], **self.sample_identity()}

    def test_complete_reports_pass(self):
        from unittest.mock import patch
        with patch('certification_run.os.environ',ENV), patch('certification_run.datetime', wraps=datetime) as dt:
            dt.now.return_value=NOW
            check_admin(self.sample_admin(),'0.36.2',SHA)
            check_profiles(self.sample_profiles(),'0.36.2',SHA)

    def test_skipped_and_replayed_active_reports_blocked(self):
        from unittest.mock import patch
        with patch('certification_run.os.environ',ENV), patch('certification_run.datetime', wraps=datetime) as dt:
            dt.now.return_value=NOW
            for item in ('admin','profiles'):
                a = self.sample_admin() if item == 'admin' else self.sample_profiles()
                if item == 'admin':
                    a['checks'].remove('live-playwright-rbac-two-tabs-recovery')
                else:
                    a['suites'][0]['tests'].pop()
                with self.assertRaises(CertificationBlocked):
                    (check_admin if item == 'admin' else check_profiles)(a, '0.36.2', SHA)
                a = self.sample_admin() if item == 'admin' else self.sample_profiles()
                a['certificationRun']['runAttempt']=1
                with self.assertRaises(CertificationBlocked):
                    (check_admin if item == 'admin' else check_profiles)(a,'0.36.2',SHA)

if __name__ == '__main__': unittest.main()
