"""Строгие регрессионные тесты независимой приёмки GA (без фиктивной HA-сертификации)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import independent_ha_ga_0520 as ga
import rolling_update_0520 as rolling


def receipt(path, doc):
    path.write_text(json.dumps(doc, sort_keys=True))
    path.chmod(0o600)
    return path


class HAGATest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.nodes = {'a': 'user@node-a.example', 'b': 'user@node-b.example'}

    def test_new_controller_is_exact_rolling_pair_with_distinct_private_journals(self):
        self.assertEqual(rolling.SOURCE, '0.51.10')
        self.assertEqual(rolling.TARGET, '0.52.0')
        self.assertEqual(rolling.PAIR, {'0.51.10', '0.52.0'})
        self.assertTrue(rolling.STAGE.endswith('0520'))
        self.assertNotEqual(rolling.STATE, '.rolling-state-0517.json')
        self.assertNotEqual(rolling.LOCK, '.rolling-lock-0517')

    def test_real_subprocess_transport_accepts_silent_rolling_and_rejects_failures(self):
        from subprocess import CompletedProcess
        command = ga.COMMANDS['rolling']
        with patch.object(ga.subprocess, 'run', return_value=CompletedProcess([], 0, b'', b'')) as sp:
            self.assertIsNone(ga.execute(command, ['local-plan'], 10, json_output=False))
            self.assertEqual(sp.call_args.args[0][:2], [ga.sys.executable, str(command)])
        with patch.object(ga.subprocess, 'run', return_value=CompletedProcess([], 1, b'error', b'secret')):
            with self.assertRaises(ga.Blocked):
                ga.execute(command, [], 10, json_output=False)
        with patch.object(ga.subprocess, 'run', return_value=CompletedProcess([], 0, b'fake-pass', b'')):
            with self.assertRaises(ga.Blocked):
                ga.execute(command, [], 10, json_output=False)

    def test_receipt_is_private_exclusive_and_fsynced(self):
        path = self.root / 'ga.json'
        ga.write_receipt(path, {'schema': ga.SCHEMA, 'status': 'OBSERVED'})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(ga.Blocked):
            ga.write_receipt(path, {'status': 'PASS'})
        self.root.chmod(0o755)
        with self.assertRaises(ga.Blocked):
            ga.write_receipt(self.root / 'unsafe.json', {'status': 'OBSERVED'})

    def test_json_evidence_rejects_duplicate_keys_symlinks_and_permissive_files(self):
        file = self.root / 'bad.json'
        file.write_text('{"a":1,"a":2}')
        file.chmod(0o600)
        with self.assertRaises(ga.Blocked):
            ga.read_json(file, private=True)
        file.write_text('{"a":1}')
        file.chmod(0o644)
        with self.assertRaises(ga.Blocked):
            ga.read_json(file, private=True)
        file.chmod(0o600)
        link = self.root / 'link.json'
        link.symlink_to(file)
        with self.assertRaises(ga.Blocked):
            ga.read_json(link, private=True)

    def test_rejects_publisher_self_acceptance_and_unverified_root(self):
        with patch('independent_ha_ga_0520.pwd.getpwuid') as pw, \
             patch('independent_ha_ga_0520.os.getuid', return_value=111), \
             patch('independent_ha_ga_0520.os.geteuid', return_value=111), \
             patch.object(ga.multi.inventory, 'machine_identity', return_value='machine:other'):
            pw.return_value.pw_name = 'operator'
            with self.assertRaises(ga.Blocked):
                ga.operator('operator')
            self.assertEqual(ga.operator('publisher'), ('operator', 'machine:other'))

    def sample_case(self, name, fault):
        return {'schema': ga.CHAOS_SCHEMA, 'status': 'PASS', 'fault': fault,
                'failedNode': name, 'recoveredAndVerified': True,
                'evidence': {'faultObserved': True, 'alertState': 'ACTIVE',
                             'ingressSamples': [{'ingressReady': True}]*8}}

    def suite(self):
        home = self.root / 'suite'
        home.mkdir(mode=0o700)
        cases = []
        for name in self.nodes:
            for fault in ('host-stop', 'network-partition'):
                path = receipt(home / f'01-{name}-{fault}.report.json', self.sample_case(name, fault))
                cases.append({'node': name, 'fault': fault, 'iteration': 1,
                              'reportFile': path.name, 'sha256': ga.hash_file(path),
                              'status': 'PASS', 'recovered': True})
        receipt(home / 'suite-report.json',
                {'schema': ga.CHAOS_SCHEMA, 'status': 'PASS', 'iterations': 1, 'cases': cases})
        return home

    def test_actual_chaos_case_bytes_and_recovery_required(self):
        home = self.suite()
        summary = ga.verify_suite(home, self.nodes, 1)
        self.assertEqual(summary['cases'], 4)
        path = home / '01-a-network-partition.report.json'
        result = json.loads(path.read_text())
        result['evidence']['faultObserved'] = False
        receipt(path, result)
        with self.assertRaises(ga.Blocked):
            ga.verify_suite(home, self.nodes, 1)
        summary = json.loads((home / 'suite-report.json').read_text())
        summary['cases'][0]['status'] = 'SKIPPED'
        receipt(home / 'suite-report.json', summary)
        with self.assertRaises(ga.Blocked):
            ga.verify_suite(home, self.nodes, 1)

    def test_orphan_recovery_journal_blocks_ga(self):
        home = self.suite()
        (home / '01-a-host-stop.state.json').write_text('incomplete')
        with self.assertRaises(ga.Blocked):
            ga.verify_suite(home, self.nodes, 1)

    def test_rolling_requires_actual_zero_failure_ingress_and_every_node(self):
        path = receipt(self.root / 'rolling.json', {
            'schema': ga.ROLL_SCHEMA, 'from': '0.51.10', 'to': ga.VERSION,
            'verified': True, 'finalVersions': {name: ga.VERSION for name in self.nodes},
            'steps': [{'nodeId': name, 'verified': True, 'edgeFailures': 0,
                       'edgeSamples': 10} for name in self.nodes]})
        self.assertEqual(ga.validate_rolling(path, self.nodes)['steps'], 2)
        doc = ga.read_json(path, private=True)
        doc['steps'][1]['edgeFailures'] = 1
        receipt(path, doc)
        with self.assertRaises(ga.Blocked):
            ga.validate_rolling(path, self.nodes)
        doc['steps'][1]['edgeFailures'] = 0
        doc['finalVersions']['b'] = '0.51.10'
        receipt(path, doc)
        with self.assertRaises(ga.Blocked):
            ga.validate_rolling(path, self.nodes)

    def recovery(self):
        home = self.root / 'recovery'; home.mkdir(mode=0o700)
        receipt(home / 'recovery-state-0519.json', {
            'schema': ga.DR_SCHEMA, 'phase': 'recovery-ready', 'runId': 'recovery-123',
            'nodes': self.nodes})
        receipt(home / 'recovery-result-0519.json', {
            'schema': ga.DR_SCHEMA, 'status': 'recovery-ready', 'runId': 'recovery-123',
            'nodesReady': 2, 'worlds': 1, 'rtoSeconds': 65.2,
            'sampledRpo': {'sampledAuditRpoSeconds': 4.5}})
        return home

    def test_recovery_requires_readback_evidence_rto_rpo_and_same_host_targets(self):
        home = self.recovery()
        result = ga.validate_recovery(home, 120, 10, self.nodes)
        self.assertEqual(result['rtoSeconds'], 65.2)
        with self.assertRaises(ga.Blocked):
            ga.validate_recovery(home, 60, 10, self.nodes)
        with self.assertRaises(ga.Blocked):
            ga.validate_recovery(home, 120, 4, self.nodes)
        with self.assertRaises(ga.Blocked):
            ga.validate_recovery(home, 120, 10, {'a': 'other@host', 'b': self.nodes['b']})
        doc = ga.read_json(home / 'recovery-result-0519.json', private=True)
        doc['sampledRpo'] = {'sampledAuditRpoSeconds': None}
        receipt(home / 'recovery-result-0519.json', doc)
        with self.assertRaises(ga.Blocked):
            ga.validate_recovery(home, 120, 10, self.nodes)

    def test_no_ga_from_staged_or_missing_receipts(self):
        paths = []
        for stage in ga.STAGES:
            data = {'schema': ga.SCHEMA, 'stage': stage, 'status': 'OBSERVED',
                    'version': ga.VERSION, 'commit': 'a'*40, 'publisher': 'publisher',
                    'operator': 'reviewer', 'observerMachine': 'machine:abcdef1234567890',
                    'liveCluster': None, 'details': {}}
            paths.append(receipt(self.root / (stage+'.json'), data))
        result, sha = ga.validate_stage_receipts(paths, commit='a'*40, publisher='publisher')
        self.assertEqual(set(result), set(ga.STAGES))
        self.assertEqual(len(sha), 4)
        with self.assertRaises(ga.Blocked):
            ga.validate_stage_receipts(paths[:-1], commit='a'*40, publisher='publisher')
        data = ga.read_json(paths[1], private=True)
        data['commit'] = 'b'*40
        receipt(paths[1], data)
        with self.assertRaises(ga.Blocked):
            ga.validate_stage_receipts(paths, commit='a'*40, publisher='publisher')

    def test_gate_cannot_return_ga_pass_from_pretend_signed_input(self):
        with patch.object(ga, 'validate_stage_receipts', return_value=({'rolling': {
            'liveCluster': {'nodes': {'a': 1}}, 'details': {'edgeFailures': 0}}, 'chaos': {
            'liveCluster': {'nodes': {'a': 1}}}, 'recovery': {
            'details': {'rtoSeconds': 1}}, 'bundle': {'details': {'version': ga.VERSION, 'releaseManifestSha256': 'a'*64}}}, {})), \
            patch.object(ga, 'final_bundle', return_value={'version': ga.VERSION, 'releaseManifestSha256': 'a'*64}):
            result = ga.gate(argparse.Namespace(commit='a'*40, receipt=[], publisher='p',
                                                bundle='', maximum_rto=100))
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertTrue(result['missingIndependentEvidence'])


if __name__ == '__main__':
    unittest.main()
