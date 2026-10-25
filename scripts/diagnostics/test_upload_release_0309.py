import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('upload_release_0309.py')
VERSION = SCRIPT.parents[2].joinpath('VERSION').read_text().strip()

class ReleaseUploadTests(unittest.TestCase):
    def test_upload_and_strip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); assets=root/'dist/assets';assets.mkdir(parents=True)
            (assets/'app-abc.js').write_text('console.log(1)')
            sm=assets/'app-abc.js.map';sm.write_text(json.dumps({'version':3,'sources':['x.ts'],'mappings':'AAAA'}))
            log=root/'commands'
            cli=root/'sentry-cli';cli.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SENTRY_TEST_LOG"\n');cli.chmod(0o755)
            env={**os.environ,'SENTRY_AUTH_TOKEN':'test-secret','SENTRY_ORG':'test-org','SENTRY_PROJECT':'test-project','SENTRY_TEST_LOG':str(log)}
            run=subprocess.run([sys.executable,str(SCRIPT),'--version',VERSION,'--commit','abcdef1234567890','--js-dist',str(assets.parent),'--cli',str(cli)],env=env,capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertFalse(sm.exists())
            commands=log.read_text()
            self.assertIn('sourcemaps upload',commands)
            self.assertIn('releases finalize',commands)
    def test_mapping_requires_matching_jar_uuid(self):
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            mapping=root/'mapping.txt';mapping.write_text('com.sample.Example -> a:\n')
            bundle=root/'jvm.jar'
            with zipfile.ZipFile(bundle,'w') as z:
                z.writestr('META-INF/sentry-debug-meta.properties','io.sentry.proguard.uuid=12345678-1234-1234-1234-123456789abc\n')
            env={**os.environ,'SENTRY_AUTH_TOKEN':'test','SENTRY_ORG':'test','SENTRY_PROJECT':'test'}
            result=subprocess.run([sys.executable,str(SCRIPT),'--version',VERSION,'--commit','abcdef1234567890','--jvm-mapping',str(mapping),'--jvm-jar',str(bundle),'--mapping-uuid','98765432-1234-1234-1234-123456789abc'],env=env,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'UUID does not match',result.stderr)

    def test_no_credential_no_file_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            assets=Path(temporary)/'assets';assets.mkdir();(assets/'app.js.map').write_text('{}')
            env={k:v for k,v in os.environ.items() if k not in ['SENTRY_AUTH_TOKEN','SENTRY_ORG','SENTRY_PROJECT']}
            run=subprocess.run([sys.executable,str(SCRIPT),'--version',VERSION,'--commit','abcdef1234567890','--js-dist',str(assets.parent)],env=env,capture_output=True)
            self.assertNotEqual(run.returncode,0)
            self.assertTrue((assets/'app.js.map').exists())

if __name__=='__main__':unittest.main()
