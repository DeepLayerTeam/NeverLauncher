"""Fail-closed input and local native-process tests for the destructive runner."""
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest

MOD = Path(__file__).with_name('install_upgrade_repair_0527.py')
spec = importlib.util.spec_from_file_location('nl_acceptance_0527', MOD)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RealInstallerAcceptanceTest(unittest.TestCase):
    def test_safe_relative_path(self):
        self.assertEqual(m.valid_rel('launcher/game/runtime.jar').as_posix(), 'launcher/game/runtime.jar')
        for value in ('', '../etc/passwd', 'some/../../parent', '/etc/passwd', 'foo\\bar', 'foo\x00bar'):
            with self.subTest(value=value), self.assertRaises(m.AcceptanceError):
                m.valid_rel(value)

    def test_binary_hash_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp, 'signed')
            file.write_bytes(b'original signed bytes')
            original = m.sha256(file)
            m.pinned(file, original)
            file.write_bytes(b'changed package payload')
            with self.assertRaises(m.AcceptanceError):
                m.pinned(file, original)

    def test_pinned_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp, 'signed')
            file.write_bytes(b'original signed bytes')
            link = Path(tmp, 'link')
            try:
                link.symlink_to(file)
            except OSError:
                self.skipTest('symlink unavailable')
            with self.assertRaises(m.AcceptanceError):
                m.pinned(link, m.sha256(file))

    def test_native_nonzero_required_under_fault(self):
        with self.assertRaises(m.AcceptanceError):
            m.run(['python3','-c','pass'], expect_ok=False)
        good = m.run(['python3','-c','pass'], expect_ok=True)
        self.assertEqual(good['exitCode'], 0)

    def test_only_private_activation_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root/'.launcher-installer'
            base.mkdir()
            with self.assertRaises(m.AcceptanceError):
                m.active(root)
            (base/'active-1.json').write_text('{"generation":1,"release":"v1"}')
            self.assertEqual(m.active(root)['generation'], 1)


if __name__ == '__main__':
    unittest.main()
