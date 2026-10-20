"""Precondition regression tests. These fixtures do NOT launch Minecraft."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from clean_machine_e2e import real_clean_install,resolve_installed_runtime

class CleanInstallPreconditions(unittest.TestCase):
    def test_existing_install_cannot_be_certified_as_clean(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'installed';root.mkdir();(root/'existing').write_text('old')
            with self.assertRaisesRegex(RuntimeError,'EMPTY installation root'):
                real_clean_install(installer=Path(d)/'no-installer',root=root,
                    signed_manifest=Path(d)/'not-real',public_key='a'*64,
                    java_major=21,username='TestPlayer',benchmark_commit='a'*40)
    def test_no_fake_preinstalled_runtime_passes_activation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaisesRegex(RuntimeError,'no native NeverRuntime'):
                resolve_installed_runtime(root)
    def test_missing_signed_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'clean'
            with self.assertRaisesRegex(RuntimeError,'real signed Minecraft profile'):
                real_clean_install(installer=Path(d)/'no-installer',root=root,
                    signed_manifest=Path(d)/'not-real',public_key='a'*64,
                    java_major=21,username='TestPlayer',benchmark_commit='a'*40)
if __name__ == '__main__':unittest.main()
