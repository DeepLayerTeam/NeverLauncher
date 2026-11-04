import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('repro_05211', HERE / 'independent_current_05211.py')
import sys
sys.path.insert(0, str(HERE))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class CurrentIndependentTests(unittest.TestCase):
    def test_current_release_archives_not_0470(self):
        self.assertEqual(len(r.expected_archives()),6)
        self.assertTrue(all('0.53.0' in value for value in r.expected_archives().values()))
        self.assertEqual(len(set(r.expected_archives().values())),6)
    def test_missing_build_blocks(self):
        with tempfile.TemporaryDirectory() as p:
            with self.assertRaises(r.Blocked):
                r.scan(Path(p))
    def test_unexpected_archive_blocks(self):
        with tempfile.TemporaryDirectory() as p:
            (Path(p)/'random.zip').write_bytes(b'not-real')
            with self.assertRaises(r.Blocked):
                r.scan(Path(p))
    def test_same_runner_and_builder_blocked(self):
        with mock.patch.object(r, 'source_sha',return_value='a'*40), mock.patch.object(r,'inputs',return_value={'go.mod':'a'}), mock.patch.object(r,'scan',return_value={'real':'byte'}):
            v={'schema':r.SCHEMA,'version':r.VERSION,'commit':'a'*40,'runId':'1234','attempt':1,
                'inputs':{'go.mod':'a'},'targets':{'real':'byte'},'builder':'build-a','runner':'host-a'}
            with self.assertRaises(r.Blocked):
                r.compare(v,v,Path('/tmp/a'),Path('/tmp/b'),'a'*40,'1234',1)
    def test_tampered_package_blocks_even_if_signed(self):
        with mock.patch.object(r, 'source_sha',return_value='a'*40), mock.patch.object(r,'inputs',return_value={'go.mod':'a'}), mock.patch.object(r,'scan',side_effect=[{'real':'different'}, {'real':'byte'}]):
            a={'schema':r.SCHEMA,'version':r.VERSION,'commit':'a'*40,'runId':'1234','attempt':1,
                'inputs':{'go.mod':'a'},'targets':{'real':'byte'},'builder':'build-a','runner':'host-a'}
            b={**a,'builder':'build-b','runner':'host-b'}
            with self.assertRaises(r.Blocked):
                r.compare(a,b,Path('/tmp/a'),Path('/tmp/b'),'a'*40,'1234',1)
    def test_input_lockfiles_bound(self):
        names=r.inputs()
        self.assertIn('services/api/go.mod',names)
        self.assertTrue(all(len(x)==64 for x in names.values()))

if __name__=='__main__':unittest.main()
