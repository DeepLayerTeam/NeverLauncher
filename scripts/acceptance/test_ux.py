#!/usr/bin/env python3
"""Negative tests for the 0.35.1 acceptance runner (not client certification)."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ux_0351',HERE/'ux_0351.py')
ux=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=ux
spec.loader.exec_module(ux)


class InventoryTests(unittest.TestCase):
    def test_real_54_items_and_12_ux_routes(self):
        journeys=ux.load_inventory()
        self.assertEqual([x['id'] for x in journeys],ux.IDS)
        self.assertEqual(set(ux.UX),{f'UX{i:02}' for i in range(1,13)})
        self.assertTrue(all(x['verification']=='not-run' for x in journeys))
        self.assertEqual([x for x in journeys if x['acceptanceScope']=='security-exclusion'][0]['id'],'M17')

    def test_path_is_not_allowed_to_escape_tree(self):
        for attack in ('scripts/../../etc/passwd','/tmp/other','scripts/../VERSION',
                       'scripts\\acceptance\\test.py','https://example.org/test.go'):
            with self.subTest(attack=attack), self.assertRaises(ux.AuditError):
                ux.referenced_file(attack)

    def test_all_refs_are_real_files_with_runnable_tests(self):
        for journey in ux.load_inventory():
            for ref in journey['testRefs']:
                self.assertTrue(ux.referenced_file(ref).is_file())
                if not ref.endswith('.sh'):
                    self.assertIsNotNone(ux.plan_test(ref))

    def test_catalog_is_not_a_verification_attestation(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)
            (fake/'VERSION').write_text('0.35.1\n')
            source=ux.ROOT/ux.CATALOG
            path=fake/ux.CATALOG
            path.parent.mkdir(parents=True)
            data=json.loads(source.read_text())
            data['journeys'][0]['verification']='verified'
            path.write_text(json.dumps(data))
            # If the catalog tries to promote itself into a certificate, validation
            # MUST reject it before any ref checks or tests are run.
            with patch.object(ux,'ROOT',fake),self.assertRaises(ux.AuditError):
                ux.load_inventory()

    def test_real_local_run_does_not_promote_to_target_verified(self):
        if not __import__('shutil').which('node'): self.skipTest('node unavailable')
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'result.json'
            self.assertEqual(ux.execute(ux.load_inventory(),['M04'],30,path),0)
            record=json.loads(path.read_text())
            self.assertFalse(record['targetVerified'])
            self.assertFalse(record['realMinecraftCertification'])
            self.assertFalse(record['results'][0]['userJourneyVerified'])
            self.assertEqual(record['results'][0]['status'],'local-regression-passed')
            self.assertFalse(any('output' in r for r in record['testRuns'].values()))
            if sys.platform != 'win32':
                self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_missing_tool_or_timeout_fails_closed(self):
        j=next(x for x in ux.load_inventory() if x['id']=='M04')
        with tempfile.TemporaryDirectory() as d:
            with patch.object(ux,'plan_test',return_value=(('x',),['tool-that-does-not-exist'],ux.ROOT)):
                code=ux.execute([j],['M04'],5,Path(d)/'blocked.json')
            self.assertEqual(code,1)
            report=json.loads((Path(d)/'blocked.json').read_text())
            self.assertEqual(report['results'][0]['status'],'blocked')
            self.assertFalse(report['targetVerified'])

    def test_unknown_ids_are_rejected(self):
        self.assertEqual(ux.main(['run','--ids','G99','--report','/tmp/unused-0351.json']),2)
        self.assertEqual(ux.main(['run','--ids','G01,G01','--report','/tmp/unused-0351.json']),2)
        self.assertEqual(ux.main(['run','--ids','G01']),2)


if __name__=='__main__':
    unittest.main()
