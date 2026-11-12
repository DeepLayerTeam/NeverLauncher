from pathlib import Path
import tempfile
import unittest
import zipfile
import check_payload as payload

class PayloadChecks(unittest.TestCase):
    def test_missing_target_blocks_production_instead_of_issuing_fictional_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'Итоговый пакет отсутствует'):
                payload.inventory(Path(tmp))
    def test_tracked_contract_matches_current_version_and_six_names(self):
        import json
        release=(payload.ROOT/'VERSION').read_text(encoding='utf-8').strip()
        current=json.loads(payload.CONTRACT.read_text(encoding='utf-8'))
        self.assertEqual(current['version'],release)
        self.assertEqual(len(current['targets']),6)
        for target,filename in current['targets'].items():
            self.assertIn(release,filename)
            self.assertEqual(filename,Path(filename).name)
    def test_stale_contract_refuses_even_if_staging_exists(self):
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            wrong=Path(tmp)/'stale.json'
            current=json.loads(payload.CONTRACT.read_text(encoding='utf-8'))
            current['version']='0.47.0'
            wrong.write_text(json.dumps(current),encoding='utf-8')
            with patch.object(payload,'CONTRACT',wrong):
                with self.assertRaisesRegex(ValueError,'Версия выпуска не соответствует основному контракту'):
                    payload.inventory(Path(tmp))
    def test_traversal_entry_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('../evil',b'x'*4096)
            with self.assertRaisesRegex(ValueError,'Небезопасный элемент архива'):
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
