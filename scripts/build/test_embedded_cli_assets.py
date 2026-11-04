#!/usr/bin/env python3
"""Regression checks for the single-source embedded CLI bundle workflow."""
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE = Path(__file__).with_name('embedded_cli_assets.py')
spec = importlib.util.spec_from_file_location('embedded_cli_assets', MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EmbeddedCLIAssetsTests(unittest.TestCase):
    def test_current_checked_in_resources_exactly_match_canonical(self):
        module.verify_or_write(write=False)

    def test_deterministic_zip_contains_only_expected_files(self):
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory)
            for name in sorted(module.PRODUCTION_FILES):
                (src / name).write_bytes(('production:' + name).encode())
            original, count = module.bundle(src, 'production/', '*')
            second, _ = module.bundle(src, 'production/', '*')
            self.assertEqual(original, second)
            self.assertEqual(count, 3)
            with zipfile.ZipFile(__import__('io').BytesIO(original)) as archive:
                self.assertEqual(set(archive.namelist()), {
                    'production/' + name for name in module.PRODUCTION_FILES
                })
                for member in archive.infolist():
                    self.assertEqual(member.date_time, (1980, 1, 1, 0, 0, 0))

    def test_malformed_source_set_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory)
            (src / 'nginx.conf').write_text('server {}')
            with self.assertRaisesRegex(ValueError, 'template list drift'):
                module.bundle(src, 'production/', '*')
            with self.assertRaisesRegex(ValueError, 'unexpectedly incomplete'):
                module.bundle(src, 'sql/', '*.sql')


if __name__ == '__main__':
    unittest.main()
