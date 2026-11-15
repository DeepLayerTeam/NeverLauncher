import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from prepare_server_bundle import prepare
from fetch_server_bundle import ASSET
from live_join import file_sha256

class PrepareServerBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = 'fabric-1.21-linux-x64'
        self.targets = self.root / 'targets.json'
        self.targets.write_text(json.dumps({'targets':[{'id':self.target,'scope':'client','os':'linux','minecraft':'1.21','loader':'fabric','loaderVersion':'latest-stable'}]}))
        self.source = self.root / 'source'; self.source.mkdir()
        # Format-only packaging fixture, not a runnable Minecraft server.
        with zipfile.ZipFile(self.source/'server.jar','w') as jar:
            jar.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\n')
        self.spec = self.root/'spec.json'
        self.row = {'directory':'source','loaderVersion':'0.16.14','serverEntry':'server.jar'}
    def run_prepare(self):
        self.spec.write_text(json.dumps({self.target:self.row}))
        return prepare(self.targets,self.spec,self.root/'out')
    def test_manifest_exact_hashes(self):
        digest = self.run_prepare(); out = self.root/'out'; manifest=out/ASSET
        self.assertEqual(digest,file_sha256(manifest))
        row=json.loads(manifest.read_text())['targets'][self.target]
        self.assertEqual(row['sha256'],file_sha256(out/row['file']))
        self.assertEqual(row['loaderVersion'],'0.16.14')
    def test_reject_latest(self):
        self.row['loaderVersion']='latest-stable'
        with self.assertRaisesRegex(RuntimeError,'Exact resolved'): self.run_prepare()
        self.assertFalse((self.root/'out').exists())
    def test_reject_live_data(self):
        (self.source/'server.properties').write_text('rcon.password=secret')
        with self.assertRaisesRegex(RuntimeError,'Live/private'): self.run_prepare()
        self.assertFalse((self.root/'out').exists())
    def test_reject_nonjar(self):
        (self.source/'server.jar').write_bytes(b'not a jar')
        with self.assertRaisesRegex(RuntimeError,'JAR'): self.run_prepare()

if __name__=='__main__': unittest.main()
