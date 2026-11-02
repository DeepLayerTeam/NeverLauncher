from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).with_name('zip-dir.py')

class CanonicalReleaseZipTests(unittest.TestCase):
    def test_contents_identical_despite_path_mtime_and_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            hashes=[]
            for name, mtime in [('first', 1234500000), ('second', 1700000000)]:
                src=root/name;src.mkdir()
                (src/'a').mkdir()
                for filename, data in [('a/z', b'z'),('x',b'\x00\xff\xf8')]:
                    f=src/filename;f.write_bytes(data);os.utime(f, (mtime,mtime))
                out=root/(name+'.zip')
                subprocess.run([sys.executable,str(SCRIPT),str(src),str(out)],check=True,capture_output=True)
                hashes.append(out.read_bytes())
                with zipfile.ZipFile(out) as z:
                    self.assertEqual(z.namelist(),['a/z','x'])
                    self.assertEqual(z.read('x'),b'\x00\xff\xf8')
                    self.assertTrue(all(x.date_time == (1980,1,1,0,0,0) for x in z.infolist()))
            self.assertEqual(hashes[0],hashes[1])
    def test_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'src';src.mkdir()
            (src/'link').symlink_to('/etc/hosts')
            p=subprocess.run([sys.executable,str(SCRIPT),str(src),str(root/'archive.zip')],capture_output=True)
            self.assertNotEqual(p.returncode,0)
    def test_bad_source_date_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'src';src.mkdir();(src/'x').write_text('hello')
            p=subprocess.run([sys.executable,str(SCRIPT),str(src),str(root/'archive.zip')],
                             env={**os.environ,'SOURCE_DATE_EPOCH':'-1'},capture_output=True)
            self.assertNotEqual(p.returncode,0)
            self.assertFalse((root/'archive.zip').exists())

if __name__=='__main__': unittest.main()
