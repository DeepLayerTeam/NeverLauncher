"""Регрессионные тесты исполняемых проверок обхода защиты, а не сертификация игры."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import staged_negative as negative
import run_native_validation as native


class GameAdversarialRegression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.client = self.root / 'client'
        self.client.mkdir()
        (self.client / 'mods').mkdir()
        self.target = self.client / 'mods' / 'required.jar'
        self.target.write_bytes(b'ACTUAL-RELEASE-CONTENT')
        self.digest = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text(json.dumps({'version': '0.43.14', 'signature': {'signature': 'unchanged'}}))
        self.package = self.root / 'package.json'
        self.package.write_text('{}')
        self.files = [{'path': 'mods/required.jar', 'required': True, 'sha256': self.digest}]

    def test_restoration_after_production_cli_denies_corrupt_file(self):
        def execution(argv, env, timeout=90):
            if argv[1] == 'verify' and argv[0] == 'runtime':
                return (1, b'rejected') if 'adversarial-manifest' in argv[3] else (0, b'{"status":"ready","signature":{"valid":true}}')
            if argv[1:3] == ['client', 'verify']:
                path = Path(argv[argv.index('--output') + 1])
                valid = hashlib.sha256(self.target.read_bytes()).hexdigest() == self.digest
                if valid:
                    path.write_text('{"status":"valid"}')
                    return (0, b'')
                return (1, b'rejected-corrupted-file')
            raise AssertionError('Неожиданная команда')
        with patch.object(negative, '_run', side_effect=execution):
            result = negative.execute('runtime', 'cli', self.manifest, 'pub', self.package,
                                      self.client, self.files, self.work, {})
        self.assertEqual(result['manifestTamper']['status'], 'denied')
        self.assertEqual(result['installedFileTamper']['status'], 'denied-and-restored')
        self.assertEqual(self.target.read_bytes(), b'ACTUAL-RELEASE-CONTENT')

    def test_corruption_accepted_blocks_and_restores(self):
        with patch.object(negative, '_run', return_value=(0, b'{}')):
            with self.assertRaisesRegex(RuntimeError, 'ошибочно приняла повреждённый установленный файл'):
                negative.reject_corrupted_client('cli', self.package, self.client,
                                                self.files, self.work, {})
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).hexdigest(), self.digest)

    def test_invalid_baseline_blocks_not_a_false_positive(self):
        with patch.object(negative, '_run', return_value=(1, b'failed')):
            with self.assertRaisesRegex(RuntimeError, 'Реальный Runtime не смог проверить неизменённый подписанный манифест'):
                negative.reject_tampered_manifest('runtime', self.manifest, 'pub', self.work, {})

    def test_version_mismatch_and_symlink_rejected(self):
        self.files[0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'отсутствует первоначальная побайтовая проверка'):
            negative.reject_corrupted_client('cli', self.package, self.client,
                                            self.files, self.work, {})
        self.target.unlink()
        another = self.root / 'elsewhere'
        another.write_bytes(b'junk')
        self.target.symlink_to(another)
        with self.assertRaisesRegex(RuntimeError, 'Не найден обязательный установленный обычный файл'):
            negative.reject_corrupted_client('cli', self.package, self.client,
                                            self.files, self.work, {})
        self.assertEqual(another.read_bytes(), b'junk')


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.joinpath('host-capabilities.json').write_text(json.dumps({
            'os':'linux','arch':'arm64','status':'ready'}))
        self.root.joinpath('staged-execution.json').write_text(json.dumps({
            'stages':{k:{'status':'passed'} for k in (
                'manifest-files','materialization','startup','loader-readiness',
                'authentication','server-readiness','matching-server','gameplay-smoke',
                'update-recovery')}
        }))
        self.negative = {
            'schemaVersion':'launcher.adversarial-gameplay.04314.v1',
            'manifestTamper': {'status':'denied','baselineVerified':True,'alteredManifestSha256':'a'*64},
            'installedFileTamper': {'status':'denied-and-restored','filePath':'mods/required.jar','baselineSha256':'b'*64,
                                   'restoredFileSha256':'b'*64,'restoredVerificationSha256':'c'*64},
        }
        self.write_negative()

    def write_negative(self):
        raw = json.dumps(self.negative, sort_keys=True, indent=2).encode()
        self.root.joinpath('adversarial-gameplay-04314.json').write_bytes(raw)
        self.root.joinpath('gameplay-smoke.json').write_text(json.dumps({
            'adversarialGameplay04314':{
                'status':'passed', 'evidenceSha256':hashlib.sha256(raw).hexdigest(),
                'manifestTamperDenied':True,
                'installedFileTamperDeniedAndRestored':True,
            }
        }))

    def test_full_native_observation(self):
        self.assertTrue(native.verify_game_observations_04314(self.root,'linux','arm64'))

    def test_wrong_arch_rejected(self):
        with self.assertRaisesRegex(ValueError, 'несоответствие идентификатора или возможностей нативного хоста'):
            native.verify_game_observations_04314(self.root,'linux','amd64')

    def test_changed_negative_file_rejected(self):
        self.negative['installedFileTamper']['status']='not-run'
        self.root.joinpath('adversarial-gameplay-04314.json').write_text(json.dumps(self.negative))
        with self.assertRaisesRegex(ValueError, 'Реальные отрицательные игровые проверки'):
            native.verify_game_observations_04314(self.root,'linux','arm64')

    def test_missing_game_stage_rejected(self):
        staged = json.loads(self.root.joinpath('staged-execution.json').read_text())
        staged['stages']['gameplay-smoke']['status']='blocked'
        self.root.joinpath('staged-execution.json').write_text(json.dumps(staged))
        with self.assertRaisesRegex(ValueError, 'Отсутствуют успешные этапы реального игрового запуска'):
            native.verify_game_observations_04314(self.root,'linux','arm64')

    def test_unrestored_file_rejected(self):
        self.negative['installedFileTamper']['restoredFileSha256']='d'*64
        self.write_negative()
        with self.assertRaisesRegex(ValueError, 'Реальные отрицательные игровые проверки'):
            native.verify_game_observations_04314(self.root,'linux','arm64')

if __name__ == '__main__':
    unittest.main()
