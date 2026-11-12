#!/usr/bin/env python3
"""Регрессионные сценарии подмены, повторного воспроизведения и подписей; фикстуры НИКОГДА не служат свидетельствами выпуска."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from argparse import Namespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/compatibility'))
sys.path.insert(0, str(ROOT / 'scripts/acceptance'))
import test_matrix as fixture_matrix
import inventory_0521 as inv

COMMIT = 'a' * 40
RUN_ID = '12345'


def write_json(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True) + '\n', encoding='utf-8')


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.results = self.root / 'results'
        self.results.mkdir()
        self.targets = json.loads((ROOT / 'compatibility/targets.json').read_text())['targets']
        self.fake = fixture_matrix.MatrixToolTests('test_aggregate_accepts_bound_multiversion_java_evidence')

    def make(self, target):
        """Искусственные данные предназначены только для проверки валидатора, НЕ для игрового запуска."""
        doc = copy.deepcopy(self.fake.passing_result(target, commit=COMMIT))
        doc['runId'] = RUN_ID
        doc['runAttempt'] = 1
        runtime = self.results / target['id'] / 'runtime'
        report = self.results / target['id'] / 'compatibility-result'
        runtime.mkdir(parents=True)
        report.mkdir()
        loader = target['loader']
        install = {'status': 'installed-and-verified', 'minecraftVersion': target['minecraft'],
                   'profileId': f'profile-{target["id"]}', 'mainClass': 'example.Minecraft',
                   'loader': loader}
        cert = {'status': 'passed', 'requiredJavaMajor': target['javaMajor'],
                'detectedJavaMajor': target['javaMajor'], 'timedOut': True,
                'classpathEntries': 10, 'minecraftVersion': target['minecraft'] if loader == 'vanilla' else install['profileId'],
                'mainClass': install['mainClass']}
        actual = {'status': 'passed', 'targetId': target['id']}
        if target['scope'] == 'integration':
            actual['mode'] = 'compatibility'
        # Синтетический серверный артефакт ТОЛЬКО ДЛЯ ОТРИЦАТЕЛЬНОГО ТЕСТА, никогда для приёмочного прогона.
        witness = {'schema': 'launcher.compatibility-join-witness/0.52.4',
                   'targetId': target['id'], 'serverPid': 54321,
                   'serverArtifactSha256': 'f' * 64,
                   'username': 'NL_Cert_Client', 'joinedFromServerLog': True,
                   'playerOnlineViaRcon': True, 'tickBefore': 5, 'tickAfter': 10}
        ready = {'targetId': target['id'], 'port': 25565, 'serverPid': 54321,
                 'serverArtifactSha256': 'f' * 64}
        stopped = {'schema': 'launcher.compatibility-server-stopped/0.52.4',
                   'stoppedAfterLiveWitness': True, 'serverPid': 54321,
                   'serverLogSha256': hashlib.sha256(b'[Server thread/INFO]: NL_Cert_Client joined the game\n').hexdigest()}
        stopped_file = runtime / 'live-server-stopped.json'
        for binding in (ready, witness, stopped):
            binding.update({'sourceCommit': COMMIT, 'ciRunId': RUN_ID, 'ciRunAttempt': 1})
        write_json(stopped_file, stopped)
        cert['matchingServer'] = '127.0.0.1'
        cert['matchingServerPort'] = 25565
        log_bytes = b'[Server thread/INFO]: NL_Cert_Client joined the game\n'
        log_path = runtime / 'matching-server.log'
        log_path.write_bytes(log_bytes)
        cert_file = runtime / f'{loader}-certification.json'
        write_json(cert_file, cert)
        witness_file = runtime / 'live-server-witness.json'
        write_json(witness_file, witness)
        live = {'schema': 'launcher.compatibility-live-join/0.52.4',
                'targetId': target['id'], 'status': 'passed',
                'minecraftVersion': target['minecraft'], 'loader': loader,
                'profileId': cert['minecraftVersion'], 'javaMajor': target['javaMajor'],
                'serverPort': 25565, 'serverArtifactSha256': 'f' * 64,
                'sourceCommit': COMMIT, 'ciRunId': RUN_ID, 'ciRunAttempt': 1,
                'serverLogSha256': hashlib.sha256(log_bytes).hexdigest(),
                'clientCertificationSha256': hashlib.sha256(cert_file.read_bytes()).hexdigest(),
                'witnessSha256': hashlib.sha256(witness_file.read_bytes()).hexdigest(),
                'serverStoppedSha256': hashlib.sha256(stopped_file.read_bytes()).hexdigest(),
                'playerJoined': True, 'playerOnlineViaRcon': True, 'worldTicksAdvanced': True}
        named = {'live-join.json': live, 'live-server-ready.json': ready,
                 'live-server-witness.json': witness, 'live-server-stopped.json': stopped, 'result.json': actual, f'{loader}-install.json': install,
                 f'{loader}-certification.json': cert,
                 'materialized-client-verify.json': {'status': 'valid', 'verify': {'valid': True}},
                 'runtime-launch-minecraft.json': {'success': True},
                 'matching-server.json': {'status': 'passed', 'clientJoinedServer': True}}
        log = ('[compat] actual client execution target=' + target['id'] + '\n'
               '[fixture] synthesized proof for negative security regression only\n').encode()
        (report / 'compatibility-execution.log').write_bytes(log)
        if 'compatibility-execution.log' not in doc['evidence']['files']:
            doc['evidence']['files'].append('compatibility-execution.log')
        doc['evidence']['sha256'] = {}
        for name in doc['evidence']['files']:
            if name == 'compatibility-execution.log':
                dest = report / name
            else:
                dest = report / name if name in {'java-runtime.json', 'platform-runtime.json'} else runtime / name
                if name in named:
                    write_json(dest, named[name])
                elif name != 'matching-server.log':
                    dest.write_text(target['id'] + ' ' + name + '\n', encoding='utf-8')
            doc['evidence']['sha256'][name] = hashlib.sha256(dest.read_bytes()).hexdigest()
        path = report / 'compatibility-result.json'
        write_json(path, doc)
        return path

    def run_inventory(self, strict=False):
        return inv.inventory(self.results, COMMIT, RUN_ID, 1, strict=strict)

    def one(self):
        return next(row for row in self.targets if row['required'] and row['loader'] == 'vanilla'
                    and not row.get('matchingServer') and row['scope'] == 'client')

    def test_catalogs_have_complete_explicit_required_counts(self):
        data = self.run_inventory()
        self.assertEqual(data['counts'], {'required': 322, 'observed': 0, 'blocked': 322, 'optional': 12})
        self.assertEqual(data['status'], 'BLOCKED')
        self.assertIn('user/E2E-18', {row['id'] for row in data['targets']})
        self.assertIn('serverbridge/velocity', {row['id'] for row in data['targets']})
        with self.assertRaisesRegex(inv.Blocked, 'incomplete Minecraft evidence'):
            self.run_inventory(strict=True)

    def test_valid_bound_raw_evidence_is_only_observed_not_ga(self):
        target = self.one()
        self.make(target)
        data = self.run_inventory()
        matching = [row for row in data['targets'] if row['id'] == 'minecraft/' + target['id']][0]
        self.assertEqual(matching['status'], 'observed')
        self.assertEqual(data['counts']['observed'], 1)
        self.assertEqual(data['status'], 'BLOCKED')

    def test_replayed_server_receipt_blocked_despite_rehashed_result(self):
        target = self.one()
        result = self.make(target)
        path = result.parent.parent / 'runtime/live-server-ready.json'
        doc = json.loads(path.read_text())
        doc['ciRunId'] = '98765'
        write_json(path, doc)
        result_doc = json.loads(result.read_text())
        result_doc['evidence']['sha256'][path.name] = inv.digest(path)
        write_json(result, result_doc)
        self.assertEqual(self.run_inventory()['counts']['observed'], 0)

    def test_mutated_dedicated_server_log_invalidates_observation(self):
        target = self.one()
        result = self.make(target)
        server_log = result.parent.parent / 'runtime/matching-server.log'
        server_log.write_bytes(server_log.read_bytes() + b'[forged extra event]\n')
        self.assertEqual(self.run_inventory()['counts']['observed'], 0)

    def test_forged_server_stopped_receipt_invalidates_observation(self):
        target = self.one()
        result = self.make(target)
        stopped = result.parent.parent / 'runtime/live-server-stopped.json'
        body = json.loads(stopped.read_text())
        body['stoppedAfterLiveWitness'] = False
        write_json(stopped, body)
        self.assertEqual(self.run_inventory()['counts']['observed'], 0)

    def test_log_tamper_invalidates_observation(self):
        target = self.one()
        path = self.make(target)
        (path.parent / 'compatibility-execution.log').write_text('FORGED PASS')
        self.assertEqual(self.run_inventory()['counts']['observed'], 0)

    def test_forged_result_pass_without_real_cert_is_blocked(self):
        target = self.one()
        path = self.make(target)
        file = path.parent.parent / 'runtime/vanilla-certification.json'
        doc = json.loads(file.read_text()); doc['timedOut'] = False; doc['success'] = False
        write_json(file, doc)
        result = json.loads(path.read_text()); result['evidence']['sha256'][file.name] = inv.digest(file)
        write_json(path, result)
        self.assertEqual(self.run_inventory()['counts']['observed'], 0)

    def test_replay_on_new_run_or_attempt_is_blocked(self):
        self.make(self.one())
        self.assertEqual(inv.inventory(self.results, COMMIT, '99999', 1)['counts']['observed'], 0)
        self.assertEqual(inv.inventory(self.results, COMMIT, RUN_ID, 2)['counts']['observed'], 0)

    def test_duplicate_observations_are_not_silently_selected(self):
        target = self.one()
        path = self.make(target)
        other = self.results / 'duplicate' / 'compatibility-result'
        other.mkdir(parents=True)
        (other / 'compatibility-result.json').write_bytes(path.read_bytes())
        with self.assertRaisesRegex(inv.Blocked, 'duplicate observed target'):
            self.run_inventory()

    def test_symlinked_report_refused(self):
        target = self.one()
        path = self.make(target)
        path.rename(path.with_suffix('.bak'))
        path.symlink_to(path.with_suffix('.bak'))
        with self.assertRaisesRegex(inv.Blocked, 'symlinked'):
            self.run_inventory()

    def test_duplicate_json_key_refused(self):
        target = self.one()
        path = self.make(target)
        path.write_text('{"targetId":"' + target['id'] + '","targetId":"' + target['id'] + '"}')
        with self.assertRaisesRegex(inv.Blocked, 'duplicate JSON'):
            self.run_inventory()

    def test_unexpected_optional_proof_rejected(self):
        other = next(row for row in self.targets if not row['required'])
        self.make(other)
        with self.assertRaisesRegex(inv.Blocked, 'unknown/optional'):
            self.run_inventory()

    def test_recomputed_hash_cannot_hide_fake_runtime_status(self):
        target = self.one()
        path = self.make(target)
        root = path.parent.parent / 'runtime'
        cert = root / 'vanilla-certification.json'
        doc = json.loads(cert.read_text()); doc['status'] = 'failed'
        write_json(cert, doc)
        receipt = json.loads(path.read_text())
        receipt['evidence']['sha256'][cert.name] = inv.digest(cert)
        write_json(path, receipt)
        observed = self.run_inventory()['targets'][0]
        self.assertEqual(observed['status'], 'blocked')
        self.assertIn('JVM/loader', observed['error'])

    def test_wrong_commit_and_unknown_target_evidence_are_rejected(self):
        target = self.one()
        self.make(target)
        self.assertEqual(inv.inventory(self.results, 'b' * 40, RUN_ID, 1)['counts']['observed'], 0)
        fake = self.results / 'extra' / 'compatibility-result'
        fake.mkdir(parents=True)
        write_json(fake / 'compatibility-result.json', {'targetId': 'fake-unknown-target'})
        with self.assertRaisesRegex(inv.Blocked, 'unknown/optional'):
            self.run_inventory()

    def test_exposed_bearer_secret_never_observed(self):
        target = self.one()
        path = self.make(target)
        log = path.parent / 'compatibility-execution.log'
        log.write_bytes(log.read_bytes() + b'Authorization: Bearer REDACTME\n')
        report = json.loads(path.read_text())
        report['evidence']['sha256'][log.name] = inv.digest(log)
        write_json(path, report)
        observed = self.run_inventory()['targets'][0]
        self.assertEqual(observed['status'], 'blocked')
        self.assertIn('credentials', observed['error'])

    def test_actual_ed25519_signature_and_replay_all_280_observations(self):
        for target in self.targets:
            if target['required']:
                self.make(target)
        self.assertEqual(self.run_inventory()['counts']['observed'], 280)
        self.assertEqual(inv.command_inventory(Namespace(results_root=self.results,
            commit=COMMIT, run_id=RUN_ID, attempt=1, gate='minecraft',
            output=self.root / 'ci-observations.json')), 0)
        self.assertEqual(inv.command_inventory(Namespace(results_root=self.results,
            commit=COMMIT, run_id=RUN_ID, attempt=1, gate='full',
            output=self.root / 'full-acceptance.json')), 3)
        key = Ed25519PrivateKey.generate()
        private = self.root / 'reviewer-private.pem'
        public = self.root / 'reviewer-public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                          serialization.PublicFormat.SubjectPublicKeyInfo))
        der = key.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
        pin = hashlib.sha256(der).hexdigest()
        args = Namespace(results_root=self.results, commit=COMMIT, run_id=RUN_ID, attempt=1,
                         reviewer='independent-reviewer', public_key=public,
                         public_key_sha256=pin, private_key=private,
                         output=self.root / 'signed-receipt.json')
        self.assertEqual(inv.command_sign(args), 0)
        args.receipt = args.output
        self.assertEqual(inv.command_verify(args), 0)
        bad_pin = args.public_key_sha256
        args.public_key_sha256 = '0' * 64
        with self.assertRaisesRegex(inv.Blocked, 'independent pin'):
            inv.command_verify(args)
        args.public_key_sha256 = bad_pin
        doc = json.loads(args.receipt.read_text())
        doc['payload']['observation']['targets'][0]['status'] = 'passed'
        write_json(args.receipt, doc)
        with self.assertRaisesRegex(inv.Blocked, 'signature verification failed'):
            inv.command_verify(args)
        # Восстановите настоящую квитанцию, затем измените только один сырой журнал и пересчитайте его
        # JSON SHA: подпись всё равно должна быть привязана к исходным байтам.
        args.receipt.unlink()
        self.assertEqual(inv.command_sign(args), 0)
        first = self.results / self.one()['id'] / 'compatibility-result'
        log = first / 'compatibility-execution.log'
        log.write_bytes(log.read_bytes() + b'edited\n')
        result_file = first / 'compatibility-result.json'
        result = json.loads(result_file.read_text())
        result['evidence']['sha256']['compatibility-execution.log'] = inv.digest(log)
        write_json(result_file, result)
        with self.assertRaisesRegex(inv.Blocked, 'signed evidence differs'):
            inv.command_verify(args)


if __name__ == '__main__':
    unittest.main()
