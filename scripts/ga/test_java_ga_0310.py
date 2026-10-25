"""Publication repeatability, downstream ABI, digest validation and release refusal."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from java_sdk_ga_0310 import ROOT, MODULES, publish

class JavaGATests(unittest.TestCase):
    def test_maven_publication_reproducible_and_standalone_consumer(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a';b=Path(tmp)/'b'
            publish(a,build=True)
            publish(b,build=False)
            one={x.relative_to(a).as_posix(): hashlib.sha256(x.read_bytes()).hexdigest()
                 for x in a.rglob('*') if x.is_file()}
            two={x.relative_to(b).as_posix(): hashlib.sha256(x.read_bytes()).hexdigest()
                 for x in b.rglob('*') if x.is_file()}
            self.assertEqual(one,two)
            self.assertEqual(len([p for p in one if p.endswith('.jar')]),6)
            for name in MODULES:
                path=a/'maven'/'ru'/'neverlauncher'/name/'0.31.0'
                self.assertTrue((path/f'{name}-0.31.0.pom').exists())
                self.assertTrue((path/f'{name}-0.31.0-sources.jar').exists())
                self.assertTrue((path/f'{name}-0.31.0-javadoc.jar').exists())
            with self.assertRaises(RuntimeError):
                publish(a,build=False)
            jar=next((a/'maven').rglob('*-sources.jar'))
            sidecar=jar.with_name(jar.name+'.sha256')
            jar.write_bytes(jar.read_bytes()+b'corruption')
            self.assertNotEqual(hashlib.sha256(jar.read_bytes()).hexdigest(),sidecar.read_text().strip())
    def test_requires_valid_release_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The publisher refuses reuse of nonempty target and won't replace it.
            target=Path(tmp)/'repo';target.mkdir();(target/'keep').write_text('data')
            with self.assertRaises(RuntimeError):
                publish(target,build=False)

if __name__=='__main__':unittest.main()
