"""Offline negative cases for the live Docker evidence collector.

Mocked Docker responses are ONLY used to test fail-closed behavior; they must
never be submitted as runtime certificates.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).with_name('record-serverbridge-runtime-04113.py')
spec = importlib.util.spec_from_file_location('record_serverbridge_runtime_04113', SOURCE)
rec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rec)


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        for suffix in ('allow', 'deny'):
            (self.runtime / f'probe-velocity-e2e-p3-{suffix}.txt').write_text(
                'probe host=127.0.0.1 port=25570 username=E2EPlayer responseBytes=0 terminal=reset')
        self.recorded = []

    def docker(self, argv, **kwargs):
        self.recorded.append(argv)
        if argv[1] == 'inspect':
            payload = [{'State': {'Running': True, 'Pid': 123, 'Health': {'Status': 'healthy'},
                                  'StartedAt': '2026-10-31T01:00:00Z'},
                        'Image': 'sha256:' + 'b'*64, 'Id': 'a'*64}]
            return mock.Mock(stdout=json.dumps(payload), stderr='', returncode=0)
        if argv[1] == 'top':
            return mock.Mock(stdout='PID COMMAND\n555 java\n', stderr='', returncode=0)
        if argv[1] == 'exec':
            return mock.Mock(stdout='', stderr='openjdk version "21.0.12"\n', returncode=0)
        if argv[1] == 'logs':
            return mock.Mock(stdout='', stderr='NeverLauncher Velocity Bridge heartbeat=true\n'
                             'neverlauncher.join.allowed username=E2EPlayer\n'
                             'neverlauncher.join.denied username=E2EPlayer\n', returncode=0)
        raise AssertionError(argv)

    def test_live_docker_invoked_and_evidence_hashed(self):
        with mock.patch.object(rec.subprocess, 'run', side_effect=self.docker):
            proof = rec.record('velocity', 'velocity-e2e-p3', 25570, 'E2EPlayer',
                               self.runtime, 'a'*64, '0.41.13')
        self.assertEqual(proof['runtime']['hostJavaPid'], 555)
        self.assertEqual(proof['runtime']['javaMajor'], 21)
        self.assertEqual(len(self.recorded), 4)
        self.assertEqual(proof['observations']['denyAfterRevocation'], True)

    def test_missing_docker_java_process_is_a_failure(self):
        def no_java(argv, **kwargs):
            value = self.docker(argv, **kwargs)
            if argv[1] == 'top':
                value.stdout = 'PID COMMAND\n555 sh\n'
            return value
        with mock.patch.object(rec.subprocess, 'run', side_effect=no_java):
            with self.assertRaisesRegex(ValueError, 'one live Java process'):
                rec.record('velocity', 'velocity-e2e-p3', 25570, 'E2EPlayer',
                           self.runtime, 'a'*64, '0.41.13')

    def test_unhealthy_container_rejected(self):
        def unhealthy(argv, **kwargs):
            value = self.docker(argv, **kwargs)
            if argv[1] == 'inspect':
                data = json.loads(value.stdout)
                data[0]['State']['Health']['Status'] = 'unhealthy'
                value.stdout = json.dumps(data)
            return value
        with mock.patch.object(rec.subprocess, 'run', side_effect=unhealthy):
            with self.assertRaisesRegex(ValueError, 'not healthy'):
                rec.record('velocity', 'velocity-e2e-p3', 25570, 'E2EPlayer',
                           self.runtime, 'a'*64, '0.41.13')

    def test_missing_revocation_evidence_rejected(self):
        def missing_deny(argv, **kwargs):
            value = self.docker(argv, **kwargs)
            if argv[1] == 'logs':
                value.stderr = 'NeverLauncher Velocity Bridge heartbeat=true\nneverlauncher.join.allowed username=E2EPlayer\n'
            return value
        with mock.patch.object(rec.subprocess, 'run', side_effect=missing_deny):
            with self.assertRaisesRegex(ValueError, 'missing ordered allow/revocation deny'):
                rec.record('velocity', 'velocity-e2e-p3', 25570, 'E2EPlayer',
                           self.runtime, 'a'*64, '0.41.13')


if __name__ == '__main__':
    unittest.main()
