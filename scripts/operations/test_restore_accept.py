"""Приёмка восстановления на новом хосте: арифметика времени, строгие отказы и реальное подключение процедур восстановления."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import restore_accept_0456 as recover
import dr_03512 as dr


class Recovery0456(unittest.TestCase):
    def test_timestamp_requires_timezone(self):
        with self.assertRaises(dr.DrillError):
            recover.parse_utc('2026-11-01T00:00:00')
        with self.assertRaises(dr.DrillError):
            recover.parse_utc('not-a-time')
        self.assertEqual(recover.parse_utc('2026-11-01T01:00:00+01:00'),
                         datetime(2026, 11, 1, tzinfo=timezone.utc))

    def test_rpo_upper_bound_from_real_timestamp_not_constant(self):
        incident = datetime.now(timezone.utc) - timedelta(seconds=1)
        snapshot = (incident - timedelta(seconds=19)).isoformat()
        self.assertEqual(recover.exposure_seconds(snapshot, incident), 19)
        with self.assertRaises(dr.DrillError):
            recover.exposure_seconds((incident + timedelta(seconds=5)).isoformat(), incident)
        with self.assertRaises(dr.DrillError):
            recover.exposure_seconds(snapshot, datetime.now(timezone.utc) + timedelta(hours=2))

    def test_report_atomic_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / 'result.json'
            recover.write_report(report, {'status':'passed', 'rtoSecondsMeasured': 3.4})
            self.assertEqual(json.loads(report.read_text())['rtoSecondsMeasured'], 3.4)
            with self.assertRaises(dr.DrillError):
                recover.write_report(report, {'status': 'wrong'})

    def test_only_verified_network_ha_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = {'schema': 2, 'mode':'standard'}
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                 patch.object(dr, 'restore_fresh') as restore, self.assertRaisesRegex(dr.DrillError, 'Network-HA'):
                recover.run_restore('nl-dr-fresh', 'nl-dr-fresh', Path(folder)/'env', Path(folder),
                                    'https://127.0.0.1:18443/ready','nl-dr-target', None, {},
                                    datetime.now(timezone.utc), Path(folder)/'report', None, None)
            restore.assert_not_called()

    def test_refuse_wrong_version_before_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = {'schema': 3,'mode':'network-ha','version':'0.45.6'}
            with patch.object(dr, 'verify_snapshot', return_value=manifest), \
                 patch.object(dr, 'target_release', return_value='0.45.5'), \
                 patch.object(dr, 'restore_fresh') as restore, self.assertRaisesRegex(dr.DrillError, 'version'):
                recover.run_restore('nl-dr-fresh','nl-dr-fresh',Path(folder)/'env',Path(folder),
                                    'https://127.0.0.1:18443/ready','nl-dr-target',None,{},
                                    datetime.now(timezone.utc),Path(folder)/'report',None,None)
            restore.assert_not_called()

    def test_real_restore_invoked_and_report_measured(self):
        with tempfile.TemporaryDirectory() as folder:
            incident = datetime.now(timezone.utc) - timedelta(seconds=4)
            manifest = {'schema':3,'mode':'network-ha','version':'0.45.6',
                        'createdUtc':(incident-timedelta(seconds=27)).isoformat(),
                        'storage':'s3-objects'}
            outcome = {'applicationVerified':True, 'serverbridgeFenced':True,
                       'redisRestored':False,'restoredWorlds':['world1']}
            with patch.object(dr,'verify_snapshot',return_value=manifest), \
                 patch.object(dr,'target_release',return_value='0.45.6'), \
                 patch.object(dr,'restore_fresh',return_value=outcome) as restore:
                report = recover.run_restore('nl-dr-fresh','nl-dr-fresh',Path(folder)/'env', Path(folder),
                                             'https://127.0.0.1:18443/ready', 'nl-dr-target',None,
                                             {'world1':Path(folder)/'world1'}, incident,
                                             Path(folder)/'result.json',None,None)
            self.assertEqual(report['rpoSecondsUpperBoundFromSnapshotAge'],27)
            self.assertGreaterEqual(report['rtoSecondsMeasured'], 4)
            self.assertEqual(report['restoredWorlds'], ['world1'])
            self.assertEqual(restore.call_count,1)
            self.assertEqual(report['status'],'passed')

    def test_incomplete_restore_does_not_certify(self):
        with tempfile.TemporaryDirectory() as folder:
            incident=datetime.now(timezone.utc)-timedelta(seconds=2)
            manifest={'schema':3,'mode':'network-ha','version':'0.45.6',
                      'createdUtc':(incident-timedelta(seconds=10)).isoformat(),'storage':'s3-objects'}
            with patch.object(dr,'verify_snapshot',return_value=manifest), \
                 patch.object(dr,'target_release',return_value='0.45.6'), \
                 patch.object(dr,'restore_fresh',return_value={'applicationVerified':True,'serverbridgeFenced':False,'redisRestored':False}), \
                 self.assertRaisesRegex(dr.DrillError, 'incomplete'):
                recover.run_restore('nl-dr-fresh','nl-dr-fresh',Path(folder)/'env',Path(folder),
                                    'https://127.0.0.1:18443/ready','nl-dr-target',None,{},incident,
                                    Path(folder)/'result.json',None,None)
            self.assertFalse((Path(folder)/'result.json').exists())


if __name__ == '__main__':
    unittest.main()
