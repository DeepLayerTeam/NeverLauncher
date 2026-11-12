#!/usr/bin/env python3
"""Отрицательные тесты подлинности свидетельств; фикстуры никогда не признаются результатами пилотного запуска."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

FILE = Path(__file__).with_name('adversarial_pilot_05012.py')
spec = importlib.util.spec_from_file_location('pilot05012', FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class PilotEvidenceTests05012(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.logdir = self.root / 'shadow'
        self.logdir.mkdir(mode=0o700)
        os.chmod(self.logdir, 0o700)
        self.key = b'\xab' * 32
        self.keyfile = self.root / 'key'
        self.keyfile.write_text(self.key.hex() + '\n')
        os.chmod(self.keyfile, 0o600)
        self.boot = 'a' * 32
        self.path = self.logdir / f'guard-shadow-{self.boot}.jsonl'

    def append(self, seq, outcome='allowed', reason='none', timestamp=None, prev=''):
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        event = dict(schema='launcher.guard-shadow/v1', version=mod.VERSION,
                     bootId=self.boot, sequence=seq, prevMac=prev, timestampMs=timestamp,
                     sessionKey=mod.mac(self.key, b'guard-session:test-correlation'),
                     nodeKey=mod.mac(self.key, b'bridge-node:test-server'),
                     outcome=outcome, reason=reason, durationUs=1000)
        event['mac'] = mod.mac(self.key, mod.canonical(event))
        with self.path.open('a') as f:
            f.write(json.dumps(event, sort_keys=True, separators=(',', ':')) + '\n')
        return event

    def test_verified_server_observations_count_only_bounded_live_intervals(self):
        now = int(time.time() * 1000) - 100000
        e = self.append(1, timestamp=now)
        e = self.append(2, timestamp=now + 10_000, prev=e['mac'])
        e = self.append(3, timestamp=now + 60_000, prev=e['mac'])
        e = self.append(4, outcome='revoked', reason='guard_build_revoked', timestamp=now + 61_000, prev=e['mac'])
        report = mod.analyze_shadow(self.logdir, self.keyfile)
        self.assertEqual('BLOCKED', report['status'])
        self.assertEqual(1, report['revokedEvents'])
        self.assertEqual(1, report['unreviewedRevocations'])
        self.assertAlmostEqual(10/3600, report['observedGuardActiveHoursLowerBound'], places=5)
        self.assertFalse(report['playerHoursCertified'])
        self.assertNotIn('test-correlation', json.dumps(report))
        self.assertNotIn('test-server', json.dumps(report))

    def test_modified_signed_record_rejected(self):
        self.append(1)
        content = self.path.read_text().replace('"outcome":"allowed"', '"outcome":"revoked"')
        self.path.write_text(content)
        with self.assertRaisesRegex(mod.EvidenceError, 'проверка MAC не пройдена'):
            mod.analyze_shadow(self.logdir, self.keyfile)

    def test_broken_chain_rejected(self):
        self.append(1)
        self.append(2, prev='0' * 64)
        with self.assertRaisesRegex(mod.EvidenceError, 'Нарушена цепочка записей теневого режима'):
            mod.analyze_shadow(self.logdir, self.keyfile)

    def test_replayed_sequence_rejected(self):
        e = self.append(1)
        self.append(1, prev=e['mac'])
        with self.assertRaisesRegex(mod.EvidenceError, 'Последовательность теневого режима отсутствует или воспроизведена повторно'):
            mod.analyze_shadow(self.logdir, self.keyfile)

    def test_unknown_review_rejected(self):
        self.append(1, outcome='revoked', reason='guard_runtime_policy_revoked')
        review = self.root / 'review.jsonl'
        review.write_text(json.dumps(dict(eventMac='f'*64, verdict='false_positive', reviewerId='operator'))+'\n')
        with self.assertRaisesRegex(mod.EvidenceError, 'неизвестное событие'):
            mod.analyze_shadow(self.logdir, self.keyfile, review)

    def test_review_field_collision_and_link_are_rejected(self):
        event = self.append(1, outcome='revoked', reason='guard_build_revoked')
        review = self.root / 'review.jsonl'
        review.write_text('{"eventMac":"' + event['mac'] + '","verdict":"true_positive",'
                          '"verdict":"false_positive","reviewerId":"operator"}\n')
        with self.assertRaisesRegex(mod.EvidenceError, 'Повторяющееся поле JSON разбора инцидента'):
            mod.analyze_shadow(self.logdir, self.keyfile, review)
        review.write_text(json.dumps(dict(eventMac=event['mac'], verdict='true_positive', reviewerId='operator'))+'\n')
        link = self.root / 'link.jsonl'; link.symlink_to(review)
        with self.assertRaisesRegex(mod.EvidenceError, 'не символьной ссылкой'):
            mod.analyze_shadow(self.logdir, self.keyfile, link)

    def test_review_missing_newline_is_not_accepted(self):
        event = self.append(1, outcome='revoked', reason='guard_build_revoked')
        review = self.root / 'review.jsonl'
        review.write_text(json.dumps(dict(eventMac=event['mac'], verdict='true_positive', reviewerId='operator')))
        with self.assertRaisesRegex(mod.EvidenceError, 'усечённая'):
            mod.analyze_shadow(self.logdir, self.keyfile, review)

    def test_real_review_record_keeps_incident_blocked(self):
        event = self.append(1, outcome='revoked', reason='guard_runtime_policy_revoked')
        review = self.root / 'review.jsonl'
        review.write_text(json.dumps(dict(eventMac=event['mac'], verdict='false_positive', reviewerId='operator'))+'\n')
        result = mod.analyze_shadow(self.logdir, self.keyfile, review)
        self.assertEqual(1, result['reviewed']['false_positive'])
        self.assertEqual('BLOCKED', result['status'])

    def test_insecure_shadow_key_rejected(self):
        os.chmod(self.keyfile, 0o644)
        self.append(1)
        with self.assertRaisesRegex(mod.EvidenceError, 'Небезопасные права'):
            mod.analyze_shadow(self.logdir, self.keyfile)

    def test_a_b_frame_comparison_real_values_and_metadata(self):
        for which, value in [('base', 12.0), ('protected', 12.2)]:
            folder = self.root / which
            folder.mkdir()
            meta = {'os':'linux', 'arch':'x86_64', 'cpu':'AMD-CPU', 'gpu':'GPU',
                    'minecraftVersion':'1.21.1', 'loader':'fabric', 'scene':'test-scene',
                    'buildSha256':'f'*64, 'sourceTool':'MangoHud'}
            (folder/'capture.json').write_text(json.dumps(meta))
            (folder/'frames.csv').write_text('frameTimeMs\n' + (f'{value}\n' * 600))
        report = mod.compare_performance(self.root/'base', self.root/'protected')
        self.assertEqual('PASS_MEASURED', report['status'])
        self.assertGreater(report['guardP95RegressionPercent'], 1)
        path = self.root/'protected'/'capture.json'
        content = json.loads(path.read_text())
        content['scene'] = 'different'
        path.write_text(json.dumps(content))
        with self.assertRaisesRegex(mod.EvidenceError, 'метаданные'):
            mod.compare_performance(self.root/'base', self.root/'protected')

    def test_missing_game_evidence_is_not_minecraft_pass(self):
        work = self.root/'work'
        work.mkdir()
        (work/'result.json').write_text(json.dumps({'version':mod.VERSION, 'status':'passed',
            'minecraft':{'client':'actual-mojang-client','paperJoin':'passed','loader':'fabric'},
            'checks': {'packageVerified':True,'signedManifest':True,'actualClient':True,'paperJoin':True,'sessionRevokeDeny':True,'loaderNativeClientJoin':True},
            'evidence':['runtime-launch-minecraft.json']}))
        (work/'runtime-launch-minecraft.json').write_text(json.dumps({'success':True}))
        log = self.root / 'paper.log'
        log.write_text('launcher.join.allowed username=Steve\nSteve joined the game\n')
        evidence = mod.verify_game(work, log, 'Steve')
        self.assertEqual('EVIDENCE_VERIFIED_NOT_INDEPENDENT', evidence['status'])
        (work/'runtime-launch-minecraft.json').unlink()
        with self.assertRaisesRegex(mod.EvidenceError, 'Отсутствует реальное E2E-подтверждение'):
            mod.verify_game(work, log, 'Steve')

    def test_invalid_game_join_logs_are_rejected(self):
        work = self.root/'work';work.mkdir()
        (work/'result.json').write_text(json.dumps({'version':mod.VERSION, 'status':'passed',
            'minecraft':{'client':'actual-mojang-client','paperJoin':'passed','loader':'vanilla'},
            'checks': {'packageVerified':True,'signedManifest':True,'actualClient':True,'paperJoin':True,'sessionRevokeDeny':True},
            'evidence':['runtime-launch-minecraft.json']}))
        (work/'runtime-launch-minecraft.json').write_text(json.dumps({'success':True}))
        log = self.root/'paper.log';log.write_text('Steve joined the game\n')
        with self.assertRaisesRegex(mod.EvidenceError, 'авторизованный допуск'):
            mod.verify_game(work, log, 'Steve')


if __name__ == '__main__':
    unittest.main(verbosity=2)
