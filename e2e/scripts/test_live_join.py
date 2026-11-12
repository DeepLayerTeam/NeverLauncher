#!/usr/bin/env python3
"""Только отрицательные сценарии безопасности; это НЕ реальный запуск игры и НЕ приёмка GA."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))
import live_join_0524 as gate
from staged_matching_0344 import MatchingServer


def put(path, doc):
    path.write_text(json.dumps(doc, sort_keys=True) + '\n', encoding='utf-8')


class LiveJoinNegativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pins = self.root / 'pins.json'
        self.bundles = self.root / 'bundles'
        self.bundles.mkdir()
        self.zipped = self.bundles / 'server.zip'
        with zipfile.ZipFile(self.zipped, 'w') as archive:
            archive.writestr('server.jar', b'not-a-real-server-jar-negative-test')
        self.sha = gate.file_sha256(self.zipped)
        self.args = SimpleNamespace(target='fabric-1.20.1-linux-x64', minecraft='1.20.1',
                                    loader='fabric', loader_version='0.16.10',
                                    pins=str(self.pins), bundle_dir=str(self.bundles))
        self.entry = {'minecraft': '1.20.1', 'loader': 'fabric',
                      'loaderVersion': '0.16.10', 'file': 'server.zip', 'sha256': self.sha}
        self.persist_pins()

    def persist_pins(self):
        put(self.pins, {'schema': 'launcher.compatibility-server/0.52.4',
                        'targets': {self.args.target: self.entry}})

    def test_exact_server_bundle_pin_is_enforced(self):
        self.assertEqual(gate.load_pinned_bundle(self.args)[1], self.sha)
        self.entry['loaderVersion'] = 'latest'
        self.persist_pins()
        with self.assertRaisesRegex(RuntimeError, 'Версия загрузчика'):
            gate.load_pinned_bundle(self.args)

    def test_bundle_tampering_is_blocked(self):
        with self.zipped.open('ab') as handle:
            handle.write(b'tampered')
        with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
            gate.load_pinned_bundle(self.args)

    def test_directory_escape_blocked(self):
        self.entry['file'] = '../server.zip'
        self.persist_pins()
        with self.assertRaisesRegex(RuntimeError, 'закреплённое имя ZIP-файла'):
            gate.load_pinned_bundle(self.args)

    def test_missing_modded_distribution_is_blocked(self):
        self.args.pins = ''
        with self.assertRaisesRegex(RuntimeError, 'required'):
            gate.load_pinned_bundle(self.args)

    def test_unmodified_default_bridge_policy_unchanged(self):
        server = MatchingServer(self.root, 'java', 'cli', '1.20.1', 'fabric', '0.16.10')
        self.assertTrue(server.requires_bridge)
        gate_server = MatchingServer(self.root, 'java', 'cli', '1.20.1', 'fabric', '0.16.10', require_bridge=False)
        self.assertFalse(gate_server.requires_bridge)

    def construct_fake_negative_fixture(self):
        # Доказательство намеренно подделано для проверки отклонения
        # вмешательства. Оно не поставляется как успешный результат совместимости.
        runtime = self.root / 'runtime'
        runtime.mkdir()
        ready = {'schema': 'launcher.compatibility-server-ready/0.52.4',
                 'targetId': self.args.target, 'minecraftVersion': '1.20.1',
                 'loader': 'fabric', 'loaderVersion': '0.16.10',
                 'port': 3333, 'serverPid': 1457,
                 'serverArtifactSha256': self.sha}
        witness = {'schema': 'launcher.compatibility-join-witness/0.52.4',
                   'targetId': self.args.target, 'minecraftVersion': '1.20.1',
                   'loader': 'fabric', 'loaderVersion': '0.16.10',
                   'port': 3333, 'serverPid': 1457,
                   'serverArtifactSha256': self.sha, 'username': 'NL_Cert_Client',
                   'joinedFromServerLog': True, 'playerOnlineViaRcon': True,
                   'tickBefore': 7, 'tickAfter': 8}
        cert = {'status': 'passed', 'minecraftVersion': 'fabric-profile',
                'requiredJavaMajor': 17, 'detectedJavaMajor': 17,
                'matchingServer': '127.0.0.1', 'matchingServerPort': 3333,
                'success': True, 'classpathEntries': 8}
        put(runtime / 'live-server-ready.json', ready)
        put(runtime / 'live-server-witness.json', witness)
        stopped = {'schema': 'launcher.compatibility-server-stopped/0.52.4',
                   'stoppedAfterLiveWitness': True, 'targetId': self.args.target,
                   'minecraftVersion': '1.20.1', 'loader': 'fabric',
                   'loaderVersion': '0.16.10', 'serverPid': 1457,
                   'serverPort': 3333, 'serverArtifactSha256': self.sha,
                   'serverLogSha256': hashlib.sha256(b'NL_Cert_Client joined the game\n').hexdigest()}
        put(runtime / 'live-server-stopped.json', stopped)
        put(runtime / 'fabric-certification.json', cert)
        (runtime / 'matching-server.log').write_text('NL_Cert_Client joined the game\n')
        for name in ('live-server-ready.json', 'live-server-witness.json',
                     'live-server-stopped.json'):
            evidence_file = runtime / name
            value = gate.read_json(evidence_file)
            value.update(gate.run_binding())
            put(evidence_file, value)
        args = SimpleNamespace(runtime=str(runtime), target=self.args.target,
                               minecraft='1.20.1', loader='fabric',
                               loader_version='0.16.10', profile='fabric-profile', java_major=17)
        return runtime, args

    def test_negative_fixture_validation_binds_actual_file_bytes(self):
        runtime, args = self.construct_fake_negative_fixture()
        self.assertEqual(gate.verify(args), 0)  # изолированный тестовый набор для парсера, не настоящая игра
        result = gate.read_json(runtime / 'live-join.json')
        self.assertEqual(result['serverLogSha256'], gate.file_sha256(runtime / 'matching-server.log'))
        self.assertEqual(result['clientCertificationSha256'], gate.file_sha256(runtime / 'fabric-certification.json'))

    def test_false_online_witness_blocked(self):
        runtime, args = self.construct_fake_negative_fixture()
        witness = gate.read_json(runtime / 'live-server-witness.json')
        witness['playerOnlineViaRcon'] = False
        put(runtime / 'live-server-witness.json', witness)
        with self.assertRaisesRegex(RuntimeError, 'не подтвердили реальное подключение клиента'):
            gate.verify(args)

    def test_wrong_java_or_client_port_blocked(self):
        runtime, args = self.construct_fake_negative_fixture()
        args.java_major = 21
        with self.assertRaisesRegex(RuntimeError, 'JVM'):
            gate.verify(args)
        args.java_major = 17
        cert = gate.read_json(runtime / 'fabric-certification.json')
        cert['matchingServerPort'] = 5555
        put(runtime / 'fabric-certification.json', cert)
        with self.assertRaisesRegex(RuntimeError, 'не был направлен'):
            gate.verify(args)

    def test_replayed_ci_run_identity_blocked(self):
        runtime, args = self.construct_fake_negative_fixture()
        original = gate.read_json(runtime / 'live-server-ready.json')
        original['ciRunId'] = 'a-previous-CI-run'
        put(runtime / 'live-server-ready.json', original)
        with self.assertRaisesRegex(RuntimeError, 'повторно использовано'):
            gate.verify(args)

    def test_stale_world_ticks_blocked(self):
        runtime, args = self.construct_fake_negative_fixture()
        witness = gate.read_json(runtime / 'live-server-witness.json')
        witness['tickAfter'] = 7
        put(runtime / 'live-server-witness.json', witness)
        with self.assertRaisesRegex(RuntimeError, 'не изменилось'):
            gate.verify(args)


if __name__ == '__main__':
    unittest.main()
