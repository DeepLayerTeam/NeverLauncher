#!/usr/bin/env python3
"""Нативные регрессионные проверки безопасности 0.52.2; фикстуры НИКОГДА не означают нативную приёмку."""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('native_0522', Path(__file__).with_name('native_packages_0522.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
SHA = 'a' * 64
COMMIT = 'b' * 40
PROJECT = 'sample-project'
VERSION = '0.52.2'


def fixture_index():
    assets = []
    for osname, arch in sorted(m.TARGETS):
        name = m.expected_filename(VERSION, PROJECT, osname, arch)
        entry = {'platform': osname, 'architecture': arch, 'filename': name,
                 'url': 'https://example.com/' + name, 'sha256': SHA, 'size': 1000}
        if osname == 'linux':
            entry.update(signatureUrl=entry['url'] + '.asc', signatureSha256=SHA, signatureSize=512)
        assets.append(entry)
    return {'schema': m.SCHEMA, 'version': VERSION, 'commit': COMMIT, 'project': PROJECT, 'assets': assets}


def raw_index(index):
    return json.dumps(index, sort_keys=True).encode()


def valid_report(asset, osname, arch, runner, folder):
    must = {'native-signature', 'bootstrap-verification', 'provision', 'verify-installed', 'uninstall'}
    if osname == 'linux':
        must |= {'system-install', 'package-metadata'}
    if osname == 'macos':
        must |= {'system-install', 'notarization', 'gatekeeper-package', 'codesign-app',
                 'gatekeeper-app', 'app-signature-details'}
    checks = {}
    for key in must:
        raw = ('command=' + key + '\nexit=0\nduration-ms=123\n').encode()
        (folder / (key + '.log')).write_bytes(raw)
        checks[key] = {'sha256': m.digest(raw), 'size': len(raw)}
    doc = {'schema': m.RESULT_SCHEMA, 'status': 'PASS', 'version': VERSION, 'commit': COMMIT,
           'project': PROJECT, 'sourceIndexSha256': asset['indexSha'], 'runId': '12345',
           'attempt': '1', 'platform': osname, 'architecture': arch, 'runner': runner,
           'observedAt': '2026-11-03T17:00:00+00:00',
           'package': {k: asset[k] for k in ('filename', 'sha256', 'size')},
           'checks': checks, 'nativeSigned': True, 'actuallyProvisioned': True, 'independentGA': False}
    (folder / 'receipt.json').write_text(json.dumps(doc))
    return doc


class IndexValidation(unittest.TestCase):
    def setUp(self):
        self.doc = fixture_index()

    def check(self):
        raw = raw_index(self.doc)
        return m.read_index(raw, m.digest(raw), VERSION, COMMIT, PROJECT)

    def test_exact_six(self):
        self.assertEqual(set(self.check()), m.TARGETS)

    def test_wrong_external_digest(self):
        with self.assertRaises(m.Blocked):
            m.read_index(raw_index(self.doc), SHA, VERSION, COMMIT, PROJECT)

    def test_duplicate_or_missing_target(self):
        self.doc['assets'][1] = dict(self.doc['assets'][0])
        with self.assertRaises(m.Blocked): self.check()
        self.doc = fixture_index()
        self.doc['assets'].pop()
        with self.assertRaises(m.Blocked): self.check()

    def test_unsigned_linux_forbidden(self):
        item = next(x for x in self.doc['assets'] if x['platform'] == 'linux')
        item.pop('signatureUrl')
        with self.assertRaises(m.Blocked): self.check()

    def test_http_redirect_local_and_unsafe_urls_forbidden(self):
        for bad in ('http://example.com/release', 'https://127.0.0.1/foo',
                    'https://169.254.169.254/', 'https://user:secret@foo.com/x',
                    'https://localhost/a', 'file:///tmp/test', 'https://example.com:8080/foo'):
            self.doc['assets'][0]['url'] = bad
            with self.subTest(bad=bad), self.assertRaises((m.Blocked, ValueError)): self.check()

    def test_unexpected_filename_and_arch(self):
        self.doc['assets'][0]['filename'] += '.zip'
        with self.assertRaises(m.Blocked): self.check()
        self.doc = fixture_index()
        self.doc['assets'][0]['architecture'] = 'aarch64-emulated'
        with self.assertRaises(m.Blocked): self.check()

    def test_duplicate_json_keys(self):
        with self.assertRaises(m.Blocked): m.parse_json(b'{"ok":true,"ok":false}')
        with self.assertRaises(m.Blocked): m.parse_json(b'{"x":NaN}')

    def test_different_source_version_and_project_block(self):
        raw = raw_index(self.doc)
        for k, v in [('version', '0.52.1'), ('commit', '1' * 40), ('project', 'foreign')]:
            doc = dict(self.doc, **{k: v})
            data = raw_index(doc)
            with self.subTest(k=k), self.assertRaises(m.Blocked):
                m.read_index(data, m.digest(data), VERSION, COMMIT, PROJECT)

    def test_source_index_builder_reads_six_real_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            for row in self.doc['assets']:
                (path / row['filename']).write_bytes(b'pkg-data' * 20)
                if row['platform'] == 'linux':
                    (path / (row['filename'] + '.asc')).write_bytes(b'signature' * 20)
            args = type('Args', (), {'packages': path, 'base_url': 'https://example.com/releases/v0.52.2/',
                    'version': VERSION, 'commit': COMMIT, 'project': PROJECT, 'output': path/'sources.json'})()
            report = m.build_index(args)
            self.assertEqual(report['packages'], 6)
            self.assertEqual(m.digest(args.output.read_bytes()), report['indexSha256'])
            self.assertEqual(len(m.read_index(args.output.read_bytes(), report['indexSha256'], VERSION, COMMIT, PROJECT)), 6)


class FakeResponse(io.BytesIO):
    def __init__(self, raw, url):
        super().__init__(raw)
        self._url = url
    def geturl(self): return self._url


class FakeOpener:
    def __init__(self, raw, redirect=None): self.raw, self.redirect = raw, redirect
    def open(self, request, timeout): return FakeResponse(self.raw, self.redirect or request.full_url)


class FetchExecution(unittest.TestCase):
    def test_pinned_real_byte_stream(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'package.exe'
            raw = b'native-final-file' * 200
            result = m.fetch('https://example.com/artifact', path, m.digest(raw), len(raw), opener=FakeOpener(raw))
            self.assertEqual(result['sha256'], m.digest(raw))
            self.assertEqual(path.read_bytes(), raw)
            with self.assertRaises(m.Blocked):
                m.fetch('https://example.com/artifact', path, m.digest(raw), len(raw), opener=FakeOpener(raw))

    def test_wrong_hash_size_and_redirect_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            for i, (sha, size, dest) in enumerate([(SHA, 10, None), (m.digest(b'abc'), 5, None),
                                                     (m.digest(b'abc'), 3, 'http://evil.example/')]):
                path = Path(d)/str(i)
                with self.assertRaises(m.Blocked):
                    m.fetch('https://example.com/package', path, sha, size, opener=FakeOpener(b'abc', dest))
                self.assertFalse(path.exists())

    def test_execution_redacts_secret_and_keeps_hashed_log(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'native-signature.log'
            report = m.execute([os.sys.executable, '-c', 'print("Authorization: Bearer SECRETKEY\\nhttps://test.org/?token=SECRETKEY")'], 30, path)
            self.assertEqual(m.file_hash(path), report['sha256'])
            self.assertNotIn('SECRETKEY', path.read_text())
            self.assertIn('exit=0', path.read_text())
            self.assertFalse(path.with_suffix('.unredacted').exists())

    def test_failed_process_cannot_produce_success_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(m.Blocked):
                m.execute([os.sys.executable, '-c', 'raise SystemExit(11)'], 30, Path(d)/'command.log')

    def test_actual_host_vs_wrong_target(self):
        with mock.patch.object(m.platform, 'system', return_value='Linux'), mock.patch.object(m.platform, 'machine', return_value='x86_64'):
            self.assertEqual(m.host_target(), ('linux','x64'))
        with mock.patch.object(m.platform, 'system', return_value='Linux'), mock.patch.object(m.platform, 'machine', return_value='i686'):
            with self.assertRaises(m.Blocked): m.host_target()


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gpg') and shutil.which('gpgv'),
                     'Требуется установленная в Linux утилита GNU Privacy Guard')
class RealLinuxSignature(unittest.TestCase):
    def test_actual_detached_gpgv_signature_and_modified_package(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)/'gnupg'
            home.mkdir(mode=0o700)
            pkg = Path(d)/'native.deb'
            sig = Path(d)/'native.deb.asc'
            keyring = Path(d)/'release.gpg'
            pkg.write_bytes(b'actual archive bytes to authenticate' * 16)
            gpg = ['gpg', '--homedir', str(home), '--batch']
            subprocess.run(gpg + ['--pinentry-mode', 'loopback', '--passphrase', '',
                            '--quick-gen-key', 'NeverLauncher Fixture <test@example.invalid>',
                            'ed25519', 'sign', '1d'], check=True, capture_output=True, timeout=20)
            subprocess.run(gpg + ['--armor', '--output', str(sig), '--detach-sign', str(pkg)],
                           check=True, capture_output=True, timeout=20)
            with keyring.open('wb') as f:
                subprocess.run(gpg + ['--export'], stdout=f, check=True, timeout=20)
            valid = m.execute(['gpgv', '--keyring', str(keyring), '--status-fd', '1',
                               str(sig), str(pkg)], 20, Path(d)/'verified.log')
            self.assertEqual(valid['sha256'], m.file_hash(Path(d)/'verified.log'))
            self.assertIn('VALIDSIG', (Path(d)/'verified.log').read_text())
            pkg.write_bytes(b'altered')
            with self.assertRaises(m.Blocked):
                m.execute(['gpgv', '--keyring', str(keyring), '--status-fd', '1',
                           str(sig), str(pkg)], 20, Path(d)/'tampered.log')


class Aggregation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.doc = fixture_index()
        self.raw = raw_index(self.doc)
        self.sha = m.digest(self.raw)
        self.index = self.base/'sources.json'
        self.index.write_bytes(self.raw)
        self.results = self.base/'results'
        self.results.mkdir()
        for n, item in enumerate(self.doc['assets']):
            folder = self.results / str(n)
            folder.mkdir()
            valid_report({**item, 'indexSha': self.sha}, item['platform'], item['architecture'], f'native-host-{n}', folder)
        self.args = type('Args', (), dict(results=self.results, source_index=self.index,
                       manifest_sha256=self.sha, version=VERSION, commit=COMMIT, project=PROJECT,
                       run_id='12345', attempt='1'))()

    def tearDown(self): self.tmp.cleanup()

    def test_full_fixture_only_ci_observed_not_ga(self):
        report = m.aggregate(self.args)
        self.assertEqual(len(report['nativeTargets']), 6)
        self.assertEqual(report['status'], 'CI_OBSERVED_REVIEW_REQUIRED')
        self.assertFalse(report['independentGA'])

    def test_missing_target_blocks(self):
        import shutil
        shutil.rmtree(self.results/'0')
        with self.assertRaises(m.Blocked): m.aggregate(self.args)

    def test_tampered_log_blocks(self):
        p = self.results/'0'/'provision.log'
        p.write_bytes(p.read_bytes() + b'tampered')
        with self.assertRaises(m.Blocked): m.aggregate(self.args)

    def test_log_exit_code_forgery_blocks(self):
        p = self.results/'0'/'provision.log'
        p.write_bytes(p.read_bytes().replace(b'exit=0', b'exit=1'))
        receipt = self.results/'0'/'receipt.json'
        obj = json.loads(receipt.read_bytes())
        obj['checks']['provision'] = {'sha256': m.file_hash(p), 'size': p.stat().st_size}
        receipt.write_text(json.dumps(obj))
        with self.assertRaises(m.Blocked): m.aggregate(self.args)

    def test_foreign_attempt_and_commit_rejected(self):
        path = self.results/'0'/'receipt.json'
        obj = json.loads(path.read_bytes())
        for key, bad in [('attempt', '2'), ('runId', '9999'), ('commit', 'c'*40),
                         ('sourceIndexSha256', SHA), ('independentGA', True)]:
            new = dict(obj, **{key: bad})
            path.write_text(json.dumps(new))
            with self.subTest(key=key), self.assertRaises(m.Blocked): m.aggregate(self.args)
        path.write_text(json.dumps(obj))

    def test_duplicate_runner_and_target_rejected(self):
        p = self.results/'0'/'receipt.json'
        obj = json.loads(p.read_bytes())
        other = json.loads((self.results/'1'/'receipt.json').read_bytes())
        obj['runner'] = other['runner']
        p.write_text(json.dumps(obj))
        with self.assertRaises(m.Blocked): m.aggregate(self.args)

    def test_symlink_extra_and_missing_logs_rejected(self):
        p = self.results/'0'/'provision.log'
        raw = p.read_bytes();p.unlink()
        (self.base/'external.log').write_bytes(raw)
        p.symlink_to(self.base/'external.log')
        with self.assertRaises(m.Blocked): m.aggregate(self.args)
        p.unlink();p.write_bytes(raw)
        (self.results/'0'/'danger.log').write_text('injected')
        with self.assertRaises(m.Blocked): m.aggregate(self.args)

    def test_independent_ed25519_review_replays_all_six_logs(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.generate()
        private = self.base/'reviewer-private.pem'
        public = self.base/'reviewer-public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        public.write_bytes(key.public_key().public_bytes(
                           serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        fingerprint = m.digest(key.public_key().public_bytes(
                             serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.args.reviewer = 'independent-qa'
        self.args.private_key = private
        self.args.public_key = public
        self.args.public_key_sha256 = fingerprint
        self.args.output = self.base/'approval.json'
        self.args.receipt = self.args.output
        self.assertEqual(m.sign_review(self.args)['status'], 'CI_OBSERVED_SIGNED_REVIEW_NOT_GA')
        self.assertFalse(m.verify_review(self.args)['independentGA'])
        with self.assertRaises(m.Blocked): m.sign_review(self.args)  # exclusive output
        log = self.results/'0'/'native-signature.log'
        log.write_bytes(log.read_bytes() + b'altered after approval')
        with self.assertRaises(m.Blocked): m.verify_review(self.args)

    def test_review_rejects_foreign_key_and_signer(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.generate()
        self.args.public_key = self.base/'wrong-public.pem'
        self.args.public_key.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.args.public_key_sha256 = 'a' * 64
        with self.assertRaises(m.Blocked):
            m.trusted_review_key(self.args.public_key, self.args.public_key_sha256)

    def test_substituted_package_bytes_rejected(self):
        p = self.results/'0'/'receipt.json'
        doc = json.loads(p.read_bytes())
        doc['package']['sha256'] = 'c'*64
        p.write_text(json.dumps(doc))
        with self.assertRaises(m.Blocked): m.aggregate(self.args)


if __name__ == '__main__': unittest.main()
