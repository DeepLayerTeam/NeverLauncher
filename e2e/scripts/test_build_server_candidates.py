import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from build_server_candidates import build, candidate_command


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.row = {'id': 'fabric-1.21-linux-x64', 'scope': 'client', 'os': 'linux', 'arch': 'x86_64', 'minecraft': '1.21', 'loader': 'fabric', 'loaderVersion': 'latest-stable'}
        self.spec = {'image': 'itzg/minecraft-server@sha256:'+'a'*64, 'loaderVersion': '0.20.1', 'serverEntry': 'server.jar'}

    def test_exact_loader_and_digest(self):
        cmd = candidate_command(self.row, self.spec, Path('/tmp/test'))
        self.assertIn('FABRIC_LOADER_VERSION=0.20.1', cmd)
        self.assertIn('SETUP_ONLY=TRUE', cmd)
        self.assertEqual(cmd[-1], self.spec['image'])
        for field, bad in [('image', 'itzg/minecraft-server:latest'), ('loaderVersion', 'latest-stable'), ('serverEntry', '../server.jar')]:
            with self.assertRaises(RuntimeError):
                candidate_command(self.row, {**self.spec, field: bad}, Path('/tmp/test'))

    def test_acquisition_and_packaging_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = root/'targets.json'; targets.write_text(json.dumps({'targets': [self.row]}))
            spec = root/'spec.json'; spec.write_text(json.dumps({self.row['id']: self.spec}))
            def installer(cmd, **kwargs):
                path = Path(next(x for x in cmd if x.startswith('type=bind,source=')).split('source=')[1].split(',target=')[0])
                with zipfile.ZipFile(path/'server.jar', 'w') as jar:
                    jar.writestr('fixture', 'not a real server; packaging unit test')
                (path/'server.properties').write_text('test only')
            out = root/'out'
            digest = build(targets, spec, out, run=installer)
            self.assertEqual(len(digest), 64)
            with zipfile.ZipFile(out/(self.row['id']+'.zip')) as archive:
                self.assertEqual(archive.namelist(), ['server.jar'])


if __name__ == '__main__':
    unittest.main()
