#!/usr/bin/env python3
"""Отрицательные тесты внешнего верификатора Java-релиза без фиктивного Host."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import shutil
import os
import tempfile
import unittest

file = Path(__file__).with_name('developer_e2e_04812.py')
spec = importlib.util.spec_from_file_location('developer_04812', file)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class JavaArtifactHardeningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(os.environ.get('LAUNCHER_JAVA_SDK_REPO', mod.ROOT / 'dist/java-sdk/maven'))
        if not cls.repo.is_dir():
            raise RuntimeError('Опубликуйте артефакты SDK перед запуском этого набора тестов')

    def isolated(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        dest = Path(temp.name) / 'maven'
        shutil.copytree(self.repo, dest)
        return dest

    def test_original_repo(self):
        self.assertEqual(len(mod.verified_repo(self.repo)), 3)

    def test_tampered_core_jar_rejected(self):
        repo = self.isolated()
        jar = mod.artifact_dir(repo, 'launcher-java-sdk-core') / f'launcher-java-sdk-core-{mod.VERSION}.jar'
        jar.write_bytes(jar.read_bytes() + b'evil')
        with self.assertRaisesRegex(ValueError, 'sha256 mismatch'):
            mod.verified_repo(repo)

    def test_missing_sources_rejected(self):
        repo = self.isolated()
        source = mod.artifact_dir(repo, 'launcher-java-sdk-core') / f'launcher-java-sdk-core-{mod.VERSION}-sources.jar'
        source.unlink()
        with self.assertRaisesRegex(ValueError, 'missing/unsafe'):
            mod.verified_repo(repo)

    def test_corrupt_dependency_pom_rejected(self):
        repo = self.isolated()
        pom = mod.artifact_dir(repo, 'neverlauncher-api-sdk') / f'neverlauncher-api-sdk-{mod.VERSION}.pom'
        data = pom.read_bytes().replace(b'launcher-java-sdk-core', b'not-the-core-artifact')
        pom.write_bytes(data)
        import hashlib
        for algo in ('sha256', 'sha512'):
            (pom.parent / (pom.name + '.' + algo)).write_text(getattr(hashlib, algo)(data).hexdigest() + '\n')
        with self.assertRaisesRegex(ValueError, 'missing core dependency'):
            mod.verified_repo(repo)

    def test_modified_manifest_digest_rejected(self):
        repo = self.isolated()
        checksum = mod.artifact_dir(repo, 'launcher-gravit-compat') / f'launcher-gravit-compat-{mod.VERSION}.pom.sha512'
        checksum.write_text('0'*128 + '\n')
        with self.assertRaisesRegex(ValueError, 'sha512 mismatch'):
            mod.verified_repo(repo)

if __name__ == '__main__':
    unittest.main(verbosity=2)
