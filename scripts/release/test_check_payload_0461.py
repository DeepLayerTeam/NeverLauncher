from pathlib import Path
import tempfile
import unittest
import zipfile
import check_payload_0461 as payload

class PayloadChecks(unittest.TestCase):
    def test_missing_target_blocks_production_instead_of_issuing_fictional_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'missing/non-production'):
                payload.inventory(Path(tmp))
    def test_traversal_entry_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('../evil',b'x'*4096)
            with self.assertRaisesRegex(ValueError,'unsafe archive'):
                payload.inspect(path)
    def test_real_integrity_check_detects_corrupt_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('payload.bin',b'x'*8192)
            raw=bytearray(path.read_bytes());raw[50]^=1;path.write_bytes(raw)
            with self.assertRaises((zipfile.BadZipFile,ValueError)):
                payload.inspect(path)

if __name__=='__main__':unittest.main()
