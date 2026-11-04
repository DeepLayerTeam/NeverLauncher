"""Regression tests for fail-closed 0.22.0 live Bridge acceptance rules.

Mocks are restricted to this unit test; the GA runner executes the unmocked
script separately against the real staging API and Minecraft ServerBridge.
"""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).with_name('admin-ga-0220-serverbridge.py')
spec = importlib.util.spec_from_file_location('ga0220_bridge', SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeGAAcceptanceTests(unittest.TestCase):
    def test_queued_or_dispatched_must_not_pass_as_ack(self):
        responses = iter([{'command': {'id': 'ctl-1', 'status': 'pending'}},
                          {'command': {'id': 'ctl-1', 'status': 'leased'}},
                          {'command': {'id': 'ctl-1', 'status': 'succeeded', 'completedAt': '2026-10-18T12:00:00Z'}}])
        with patch.object(bridge, 'request', side_effect=lambda *args, **kwargs: next(responses)), patch.object(bridge.time, 'sleep'):
            result = bridge.await_ack('https://example.invalid', '/control', 'token', 'ctl-1', bridge.time.monotonic() + 30)
            self.assertEqual(result['status'], 'succeeded')

    def test_success_without_confirmed_ack_timestamp_fails(self):
        with patch.object(bridge, 'request', return_value={'command': {'id': 'ctl-1', 'status': 'succeeded'}}):
            with self.assertRaisesRegex(RuntimeError, 'lacks completedAt'):
                bridge.await_ack('https://example.invalid', '/control', 'token', 'ctl-1', bridge.time.monotonic() + 10)

    def test_expired_and_unsupported_are_terminal_failures(self):
        for status in ['failed', 'unsupported', 'expired', 'indeterminate']:
            with self.subTest(status=status), patch.object(bridge, 'request', return_value={'command': {'id': 'ctl-1', 'status': status}}):
                with self.assertRaises(RuntimeError):
                    bridge.await_ack('https://example.invalid', '/control', 'token', 'ctl-1', bridge.time.monotonic() + 10)

    def test_duplicate_command_id_fails(self):
        first = {'command': {'id': 'ctl-1', 'serverId': 'server-1'}}
        duplicated = {'command': {'id': 'ctl-2', 'serverId': 'server-1'}, 'idempotentReplay': False}
        with patch.object(bridge, 'request', side_effect=[first, duplicated]):
            with self.assertRaisesRegex(RuntimeError, 'Duplicate ServerBridge'):
                bridge.execute('https://example.invalid', 'server-1', 'token', 'server.save', {})

    def test_drain_requires_explicit_disposable_server_confirmation(self):
        env = {'E2E_API_URL': 'https://example.invalid', 'E2E_OPERATOR_TOKEN': 'token',
               'E2E_PROJECT_ID': 'project', 'E2E_SERVERBRIDGE_NODE_ID': 'server-1',
               'E2E_DESTRUCTIVE_STAGING_ACK': 'no'}
        with patch.dict(bridge.os.environ, env):
            with self.assertRaisesRegex(RuntimeError, 'Refusing drain'):
                bridge.main()


if __name__ == '__main__':
    unittest.main()
