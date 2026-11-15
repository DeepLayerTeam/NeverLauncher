import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from fetch_server_bundle import ASSET, fetch


class FetchServerBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.target = 'fabric-1.21-linux-x64'
        with zipfile.ZipFile(self.source / 'server.zip', 'w') as archive:
            archive.writestr('server.jar', b'negative test fixture, not a runnable server')
        self.entry = dict(loader='fabric', minecraft='1.21', loaderVersion='0.16.14',
                          file='server.zip', sha256=self.digest(self.source / 'server.zip'))
        self.calls = []

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def pins(self):
        path = self.source / ASSET
        path.write_text(json.dumps(dict(schema='launcher.compatibility-server/0.52.4', targets={self.target: self.entry})), encoding='utf-8')
        return self.digest(path)

    def download(self, repo, tag, name, directory):
        self.calls.append(name)
        (directory / name).write_bytes((self.source / name).read_bytes())

    def run_fetch(self, digest):
        return fetch('DeepLayerTeam/NeverLauncher', 'ci-server-pins', digest, self.target,
                     self.root / 'output', downloader=self.download)

    def test_verified_download(self):
        pins, directory = self.run_fetch(self.pins())
        self.assertEqual(self.calls, [ASSET, 'server.zip'])
        self.assertEqual(self.digest(pins), self.digest(self.source / ASSET))
        self.assertEqual(self.digest(directory / 'server.zip'), self.entry['sha256'])

    def test_official_vanilla_without_entry_downloads_only_manifest(self):
        digest = self.pins()
        pins, directory = fetch('DeepLayerTeam/NeverLauncher', 'ci-server-pins', digest,
                                'vanilla-1.21-linux-x64', self.root / 'output', downloader=self.download)
        self.assertEqual(self.calls, [ASSET])
        self.assertEqual(self.digest(pins), digest)
        self.assertFalse((directory / 'server.zip').exists())

    def test_missing_modded_entry_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, 'No approved server bundle'):
            fetch('DeepLayerTeam/NeverLauncher', 'ci-server-pins', self.pins(),
                  'quilt-1.21-linux-x64', self.root / 'output', downloader=self.download)

    def test_unapproved_manifest_cannot_select_download(self):
        self.pins()
        with self.assertRaisesRegex(RuntimeError, 'manifest SHA-256'):
            self.run_fetch('a' * 64)
        self.assertEqual(self.calls, [ASSET])

    def test_tampered_zip_rejected(self):
        digest = self.pins()
        (self.source / 'server.zip').write_bytes(b'tampered')
        with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
            self.run_fetch(digest)

    def test_path_escape_rejected_before_download(self):
        self.entry['file'] = '../server.zip'
        with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            self.run_fetch(self.pins())
        self.assertEqual(self.calls, [ASSET])


if __name__ == '__main__':
    unittest.main()
