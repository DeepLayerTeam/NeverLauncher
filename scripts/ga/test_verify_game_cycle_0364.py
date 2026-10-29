#!/usr/bin/env python3
"""Negative verifier tests: missing/stale/tampered evidence never means PASS."""
import json
from pathlib import Path
import tempfile
import unittest

from verify_game_cycle_0364 import verify

COMMIT = 'a' * 40

class GameCycleVerifierFailClosed(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'result.json').write_text(json.dumps({
            'status': 'passed', 'version': '0.36.4', 'mode': 'full',
            'checks': {'realGameUpdateRollback': True}, 'evidence': ['game-cycle-0364-result.json']}))
        self.proof = {'schemaVersion': 'neverlauncher.game-cycle.0364/v1',
                      'status': 'passed', 'version': '0.36.4', 'sourceCommit': COMMIT,
                      'githubRunId': '1234', 'githubRunAttempt': '1',
                      'checks': {k: True for k in (
                          'postgresBackend', 'signedBaseline', 'signedUpdate',
                          'productionGoTransactionalUpdate', 'updateMinecraftJVMJoin',
                          'productionGoTransactionalRollback', 'rollbackMinecraftJVMJoin', 'serverBridgeJoin')},
                      'executablesSha256': {'javaExecutable': 'a'*64,
                                           'neverRuntime': 'b'*64, 'paperServerBridge': 'c'*64},
                      'clientCLIsha256': 'd'*64, 'changedResourceSha256': 'e'*64,
                      'artifacts': {}}
        self.save()

    def save(self):
        (self.root/'game-cycle-0364-result.json').write_text(json.dumps(self.proof))

    def test_missing_actual_files_is_blocked(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            verify(self.root, '0.36.4', COMMIT)

    def test_wrong_source_sha_is_blocked(self):
        with self.assertRaisesRegex(ValueError, 'wrong version, source SHA'):
            verify(self.root, '0.36.4', 'b'*40)

    def test_wrong_attempt_is_blocked(self):
        with self.assertRaisesRegex(ValueError, 'stale run/attempt'):
            verify(self.root, '0.36.4', COMMIT, '1234', '2')

    def test_skipped_stage_is_blocked(self):
        self.proof['checks']['rollbackMinecraftJVMJoin'] = False
        self.save()
        with self.assertRaisesRegex(ValueError, 'unverified'):
            verify(self.root, '0.36.4', COMMIT)

    def test_symlinked_report_is_blocked(self):
        (self.root/'result.json').unlink()
        (self.root/'result.json').symlink_to('game-cycle-0364-result.json')
        with self.assertRaisesRegex(ValueError, 'invalid/missing'):
            verify(self.root, '0.36.4', COMMIT)


if __name__ == '__main__': unittest.main()
