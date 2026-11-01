"""Regression: 0.45.5 must not back up or reactivate HA with live workers."""
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import dr_03512 as dr


class MultiNodeRecovery0455(unittest.TestCase):
    def test_backup_refuses_live_worker_even_if_original_api_is_down(self):
        states = {'postgres': 'running', 'api': 'exited', 'api-b': 'exited',
                  'worker-a': 'running', 'worker-b': 'exited', 'nginx': 'exited', 'redis': 'exited'}
        with patch.object(dr, 'COMPOSE_PROFILES', ['network-ha']), patch.object(dr, 'compose_states', return_value=states):
            with self.assertRaisesRegex(dr.DrillError, 'worker-a'):
                dr.assert_quiescent('nl-dr-ha0455', Path('/tmp/test.env'))

    def test_backup_refuses_second_api_live(self):
        states = {'postgres': 'running', 'api': 'exited', 'api-b': 'running',
                  'worker-a': 'exited', 'worker-b': 'exited', 'nginx': 'exited', 'redis': 'exited'}
        with patch.object(dr, 'COMPOSE_PROFILES', ['network-ha']), patch.object(dr, 'compose_states', return_value=states):
            with self.assertRaisesRegex(dr.DrillError, 'api-b'):
                dr.assert_quiescent('nl-dr-ha0455', Path('/tmp/test.env'))

    def test_role_based_restore_verification_includes_future_versions(self):
        self.assertFalse(dr.has_split_ha_roles_0455('0.45.4'))
        self.assertTrue(dr.has_split_ha_roles_0455('0.45.5'))
        self.assertTrue(dr.has_split_ha_roles_0455('0.46.0'))
        self.assertFalse(dr.has_split_ha_roles_0455('not-a-version'))

    def test_restored_worker_requires_actual_successful_readiness(self):
        result = subprocess.CompletedProcess([], 0, stdout=b'{"status":"ready","repository":"postgres","storage":"s3"}', stderr=b'')
        with patch.object(dr, 'compose', return_value=result) as call:
            dr.check_restored_worker_0455('nl-dr-ha0455', Path('/tmp/target.env'), 'worker-b', timeout=2)
            self.assertIn('worker-b', call.call_args.args)
        with self.assertRaisesRegex(dr.DrillError, 'invalid'):
            dr.check_restored_worker_0455('nl-dr-ha0455', Path('/tmp/target.env'), 'api')


if __name__ == '__main__':
    unittest.main()
