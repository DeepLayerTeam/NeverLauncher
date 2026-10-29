#!/usr/bin/env python3
"""Exercise production Go updater, not a mocked command or fake JVM report."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('game_cycle_0364', HERE / 'game_cycle_0364.py')
game = importlib.util.module_from_spec(spec)
spec.loader.exec_module(game)


class PackageInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'libraries').mkdir()
        self.entries = []
        for i in range(11):
            name = f'libraries/test{i}.jar'
            data = f'fixture-{i}'.encode()
            (self.root / name).write_bytes(data)
            self.entries.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})

    def test_valid_files_must_be_hashed(self):
        expected = game.file_manifest({'manifest': {'files': self.entries}}, self.root)
        self.assertEqual(len(expected), 11)
        (self.root / 'libraries/test4.jar').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'bytes mismatch'):
            game.file_manifest({'manifest': {'files': self.entries}}, self.root)

    def test_symlink_and_path_traversal_fail_closed(self):
        self.entries[0]['path'] = '../secret'
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            game.file_manifest({'manifest': {'files': self.entries}}, self.root)
        self.entries[0]['path'] = 'libraries/link.jar'
        (self.root / 'libraries/link.jar').symlink_to('test0.jar')
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            game.file_manifest({'manifest': {'files': self.entries}}, self.root)

    def test_duplicate_manifest_file_fails(self):
        self.entries[1] = dict(self.entries[0])
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            game.file_manifest({'manifest': {'files': self.entries}}, self.root)

    def test_different_git_sha_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'GITHUB_SHA'):
            previous = os.environ.pop('GITHUB_SHA', None)
            try:
                game.identity(self.root, '0.36.4')
            finally:
                if previous is not None:
                    os.environ['GITHUB_SHA'] = previous


class RealProductionUpdater(unittest.TestCase):
    def test_real_cli_install_update_rollback_exact_bytes(self):
        self.assertIsNotNone(shutil.which('go'), 'Go required, cannot skip lifecycle')
        self.assertIsNotNone(shutil.which('git'), 'Git required, cannot skip commit identity')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout, source = root / 'checkout', root / 'minecraft-source'
            checkout.mkdir(); source.mkdir()
            (checkout / 'VERSION').write_text('0.36.4\n')
            subprocess.run(['git', 'init', '-q', str(checkout)], check=True)
            subprocess.run(['git', '-C', str(checkout), 'add', 'VERSION'], check=True)
            subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=E2E Test',
                            '-c', 'user.email=ci@invalid.local', 'commit', '-qm', 'fixture'], check=True)
            commit = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
            for i in range(11):
                path = source / f'libraries/library{i}.jar'
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(('real-go-updater-fixture-%d' % i).encode())
            cli = root / 'nl'
            subprocess.run(['go', 'build', '-o', str(cli), './cmd/neverlauncher'],
                           cwd=ROOT/'cli', check=True, timeout=180)
            package = root / 'client-package.json'
            subprocess.run([str(cli), 'client', 'package-build', '--client-dir', str(source),
                            '--project', 'e2e-project', '--profile', 'vanilla', '--channel', 'stable',
                            '--version', '0.36.4-vanilla-1.21.1-e2e', '--output', str(package)],
                           check=True, timeout=30)
            doc = json.loads(package.read_text())
            doc['manifestSettings'] = {'minecraft': {'loader': 'vanilla', 'version': '1.21.1'},
                                       'runtime': {'launch': {'classpathStrategy': 'compatibility'}}}
            package.write_text(json.dumps(doc))
            env = dict(os.environ, GITHUB_SHA=commit)
            runner = HERE/'game_cycle_0364.py'
            common = ['--root', str(checkout), '--work', str(root), '--package', str(package),
                      '--cli', str(cli), '--version', '0.36.4', '--profile', 'vanilla']
            subprocess.run([sys.executable, str(runner), 'prepare', *common,
                            '--source', str(source), '--release', '0.36.4-vanilla-1.21.1-e2e'],
                           env=env, check=True, timeout=120)
            self.assertTrue((root/'cycle-client'/game.CHANGE_PATH).is_file())
            self.assertEqual(json.loads((root/'cycle-update.json').read_text())['status'], 'applied-and-verified')
            subprocess.run([sys.executable, str(runner), 'rollback', *common],
                           env=env, check=True, timeout=120)
            self.assertFalse((root/'cycle-client'/game.CHANGE_PATH).exists())
            self.assertEqual(json.loads((root/'cycle-verify-rollback.json').read_text())['status'], 'valid')
            # No actual Minecraft JVM or ServerBridge: must NOT generate a PASS certificate.
            final = subprocess.run([sys.executable, str(runner), 'finalize', '--root', str(checkout),
                                    '--work', str(root), '--version', '0.36.4', '--profile', 'vanilla',
                                    '--player', 'E2EPlayer', '--java', str(cli), '--runtime', str(cli),
                                    '--bridge', str(cli)], env=env, capture_output=True, text=True)
            self.assertNotEqual(final.returncode, 0)
            self.assertFalse((root/'game-cycle-0364-result.json').exists())


if __name__ == '__main__':
    unittest.main()
