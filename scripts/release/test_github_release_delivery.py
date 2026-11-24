import base64
import datetime
import platform as host_platform
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_trust_policy import keys
import github_release_delivery as delivery
from native_updater_feed import TARGETS, MODES

VERSION = '1.1.2'
REPO = 'example/NeverLauncher'
COMMIT = 'a' * 40


def b64(raw):
    return base64.b64encode(raw).decode()


class ReleaseDelivery(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.directory = self.root / 'assets'
        self.directory.mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.key_id = b'abcdefgh'
        self.public = b64(('untrusted comment: public key\n' + b64(b'Ed' + self.key_id + self.key.public_key().public_bytes_raw())).encode())
        self.packages, self.installers, self.asc = delivery.expected_names(VERSION)
        for platform, arch in TARGETS:
            self.package(platform, arch)
        for name in self.installers + self.asc:
            (self.directory / name).write_bytes(('fixture:'+name).encode())
        for name in self.packages + self.installers + self.asc:
            self.sign(name)

    def package(self, platform, arch, file=None):
        path = self.directory / (file or delivery.package_name(VERSION, platform, arch))
        roles = ['desktop','guard','runtime'] + (['sensor'] if platform == 'windows' else [])
        raw = json.dumps({'product': 'Launcher', 'productVersion': VERSION, 'platform': platform, 'architecture': arch,
                          'trustMode': MODES[platform], 'components': [{'component': x} for x in roles],
                          'supportFiles': [{'component': 'updater'}]}).encode()
        if path.name.endswith('.zip'):
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('COMPONENT_UPDATE_MANIFEST.json', raw)
        else:
            with tarfile.open(path, 'w:gz') as t:
                entry = tarfile.TarInfo('launcher/COMPONENT_UPDATE_MANIFEST.json')
                entry.size = len(raw)
                t.addfile(entry, io.BytesIO(raw))

    def sign(self, name, version=VERSION):
        path = self.directory / name
        comment = f'timestamp:1\tfile:{name}\tversion:{version}'
        signature = self.key.sign(hashlib.blake2b(path.read_bytes()).digest())
        text = '\n'.join(['untrusted comment: signature', b64(b'ED'+self.key_id+signature),
                          'trusted comment: '+comment, b64(self.key.sign(signature+comment.encode()))])
        (self.directory / (name+'.sig')).write_text(b64(text.encode()))

    def generate(self):
        return delivery.metadata(self.directory, VERSION, REPO, COMMIT, self.public, write=True)

    def verify(self):
        return delivery.metadata(self.directory, VERSION, REPO, COMMIT, self.public)

    def test_complete_feed_and_exact_inventory(self):
        names = self.generate()
        self.assertEqual(len(names), 31)
        self.assertEqual(names, self.verify())
        feed = json.loads((self.directory / 'latest.json').read_text())
        self.assertEqual(set(feed['platforms']), set(TARGETS.values()))
        self.assertIn('GitHub Actions', feed['notes'])
        for (p,a), key in TARGETS.items():
            self.assertEqual(feed['platforms'][key]['url'], f'https://github.com/{REPO}/releases/download/v{VERSION}/'+delivery.package_name(VERSION,p,a))
        receipt = json.loads((self.directory/'RELEASE_DELIVERY.json').read_text())
        self.assertEqual(receipt['sourceCommit'], COMMIT)
        self.assertEqual(len(receipt['assets']),28)

    def test_missing_installer(self):
        (self.directory / self.installers[0]).unlink()
        with self.assertRaises(ValueError): self.generate()

    def test_extra_asset(self):
        (self.directory / 'private.key').write_text('not permitted')
        with self.assertRaises(ValueError): self.generate()

    def test_tamper_update_package(self):
        with (self.directory/self.packages[0]).open('ab') as f: f.write(b'tamper')
        with self.assertRaises(InvalidSignature): self.generate()

    def test_tamper_installer(self):
        (self.directory/self.installers[0]).write_bytes(b'tamper')
        with self.assertRaises(InvalidSignature): self.generate()

    def test_tamper_gpg_sidecar(self):
        (self.directory/self.asc[0]).write_bytes(b'tamper')
        with self.assertRaises(InvalidSignature): self.generate()

    def test_wrong_signature_version(self):
        self.sign(self.installers[0], '1.1.1')
        with self.assertRaises(ValueError): self.generate()

    def test_swapped_signed_target(self):
        a,b = self.packages[:2]
        for suffix in ('','.sig'):
            path = self.directory / (a+suffix)
            other = self.directory / (b+suffix)
            temp = path.read_bytes()
            path.write_bytes(other.read_bytes())
            other.write_bytes(temp)
        with self.assertRaises(ValueError): self.generate()

    def test_swapped_signed_installer(self):
        a,b = self.installers[:2]
        for suffix in ('','.sig'):
            path = self.directory / (a+suffix)
            other = self.directory / (b+suffix)
            temp = path.read_bytes()
            path.write_bytes(other.read_bytes())
            other.write_bytes(temp)
        with self.assertRaisesRegex(ValueError, 'Signed filename'):
            self.generate()

    def test_metadata_manipulation(self):
        self.generate()
        (self.directory/'latest.json').write_text('{}')
        with self.assertRaises(ValueError): self.verify()

    def test_release_notes_tampering(self):
        self.generate()
        path = self.directory / 'latest.json'
        feed = json.loads(path.read_text())
        feed['notes'] = 'tampered'
        path.write_text(json.dumps(feed))
        with self.assertRaisesRegex(ValueError, 'metadata mismatch'): self.verify()

    def test_receipt_other_commit(self):
        self.generate()
        with self.assertRaises(ValueError): delivery.metadata(self.directory, VERSION, REPO, 'b'*40, self.public)

    def test_wrong_repository(self):
        self.generate()
        with self.assertRaises(ValueError): delivery.metadata(self.directory, VERSION, 'other/project', COMMIT, self.public)

    def test_collect_duplicate(self):
        duplicate = self.directory/'duplicate'
        duplicate.mkdir()
        shutil.copyfile(self.directory/self.packages[0], duplicate/self.packages[0])
        with self.assertRaises(ValueError): delivery.collect(self.directory,self.root/'out',VERSION)

    def test_release_order(self):
        row = {'tag_name':'v1.1.1','draft':False,'prerelease':False}
        delivery.check_release_order([row], VERSION)
        for tag in ('v1.1.2','v1.2.0','1.10.0'):
            with self.assertRaises(ValueError): delivery.check_release_order([dict(row,tag_name=tag)],VERSION)
        with self.assertRaises(ValueError): delivery.check_release_order([dict(row,tag_name='v'+VERSION,draft=True)],VERSION)
        delivery.check_release_order([dict(row,tag_name='v'+VERSION,draft=True)],VERSION,allow_draft=True)

    def test_remote_digest_and_state(self):
        names = self.generate()
        rows = [{'name':n,'state':'uploaded','size':(self.directory/n).stat().st_size,'digest':'sha256:'+delivery.digest(self.directory/n)} for n in names]
        delivery.check_remote_assets(rows,self.directory,names)
        for change in ({'digest':None},{'size':0},{'state':'starter'}):
            bad = [dict(rows[0],**change)] + rows[1:]
            with self.assertRaises(ValueError): delivery.check_remote_assets(bad,self.directory,names)
        with self.assertRaises(ValueError): delivery.check_remote_assets(rows[:-1],self.directory,names)

    def test_publish_draft_before_latest_and_digest_failure(self):
        names = self.generate()
        remote = [{'name':n,'state':'uploaded','size':(self.directory/n).stat().st_size,'digest':'sha256:'+delivery.digest(self.directory/n)} for n in names]
        draft = {'tag_name':'v'+VERSION,'draft':True,'prerelease':False,'id':42}
        def execute(broken):
            responses = [ {'visibility':'public'}, [[]], [], {'sha':COMMIT}, [[draft]],
                          [[dict(remote[0],digest='bad')]+remote[1:] if broken else remote] ]
            if not broken: responses += [{'sha':COMMIT}, [[draft]]]
            with patch.dict(os.environ,{'NL_UPDATER_PUBLIC_KEY':self.public,'GITHUB_REF':'refs/heads/main','GITHUB_SHA':COMMIT}), patch.object(delivery,'gh_json',side_effect=responses), patch.object(delivery,'run') as command:
                if broken:
                    with self.assertRaises(ValueError): delivery.publish(self.directory,VERSION,REPO,COMMIT)
                else:
                    delivery.publish(self.directory,VERSION,REPO,COMMIT)
                calls = [c.args for c in command.call_args_list]
                create = next(c for c in calls if c[:3]==('gh','release','create'))
                self.assertIn('--draft', create)
                self.assertEqual(create[create.index('--notes') + 1], json.loads((self.directory/'latest.json').read_text())['notes'])
                self.assertTrue(any(c[:3]==('gh','release','upload') for c in calls))
                edits = [c for c in calls if c[:3]==('gh','release','edit')]
                self.assertEqual(len(edits), 0 if broken else 1)
                if edits: self.assertIn('--latest',edits[0])
        execute(True)
        execute(False)

    def test_beta_metadata_isolated_from_stable_on_all_six_targets(self):
        names = delivery.metadata(self.directory, VERSION, REPO, COMMIT, self.public, write=True, channel='beta')
        self.assertEqual(len(names), 31)
        self.assertIn('latest-beta.json', names)
        self.assertNotIn('latest.json', names)
        self.assertEqual(json.loads((self.directory/'RELEASE_DELIVERY.json').read_text())['channel'], 'beta')
        self.assertEqual(set(json.loads((self.directory/'latest-beta.json').read_text())['platforms']), set(TARGETS.values()))
        self.assertEqual(names, delivery.metadata(self.directory, VERSION, REPO, COMMIT, self.public, channel='beta'))
        with self.assertRaises(ValueError): self.verify()
        other = Ed25519PrivateKey.generate()
        other_key = b64(('untrusted comment: other\n' + b64(b'Ed' + self.key_id + other.public_key().public_bytes_raw())).encode())
        with self.assertRaises(InvalidSignature): delivery.metadata(self.directory, VERSION, REPO, COMMIT, other_key, channel='beta')
        with patch.dict(os.environ, {'NL_UPDATER_PUBLIC_KEY': other_key, 'NL_UPDATER_BETA_PUBLIC_KEY': self.public}):
            self.assertEqual(delivery.channel_key('stable'), other_key)
            self.assertEqual(delivery.channel_key('beta'), self.public)
        renamed = b64(('untrusted comment: renamed\n' + b64(b'Ed'+b'87654321'+self.key.public_key().public_bytes_raw())).encode())
        with patch.dict(os.environ, {'NL_UPDATER_PUBLIC_KEY': self.public, 'NL_UPDATER_BETA_PUBLIC_KEY': renamed}):
            with self.assertRaisesRegex(ValueError, 'distinct'): delivery.channel_key('beta')
        with patch.dict(os.environ, {'NL_UPDATER_PUBLIC_KEY': self.public, 'NL_UPDATER_BETA_PUBLIC_KEY': ''}):
            with self.assertRaisesRegex(ValueError, 'required'): delivery.channel_key('beta')

    def test_beta_publication_never_changes_latest(self):
        names = delivery.metadata(self.directory, VERSION, REPO, COMMIT, self.public, write=True, channel='beta')
        remote = [{'name':n,'state':'uploaded','size':(self.directory/n).stat().st_size,'digest':'sha256:'+delivery.digest(self.directory/n)} for n in names]
        draft = {'tag_name':'v'+VERSION,'draft':True,'prerelease':True,'id':42}
        for prerelease in (True, False):
            row = dict(draft, prerelease=prerelease)
            responses = [{'visibility':'public'}, [[]], [], {'sha':COMMIT}, [[row]], [remote], {'sha':COMMIT}, [[row]]]
            with patch.dict(os.environ, {'GITHUB_REF':'refs/heads/main','GITHUB_SHA':COMMIT}), patch.object(delivery,'channel_key',return_value=self.public), patch.object(delivery,'gh_json',side_effect=responses), patch.object(delivery,'run') as command:
                if prerelease: delivery.publish(self.directory, VERSION, REPO, COMMIT, 'beta')
                else:
                    with self.assertRaises(ValueError): delivery.publish(self.directory, VERSION, REPO, COMMIT, 'beta')
                calls = [c.args for c in command.call_args_list]
                create = next(c for c in calls if c[:3] == ('gh','release','create'))
                self.assertIn('--prerelease', create)
                edits = [c for c in calls if c[:3] == ('gh','release','edit')]
                self.assertEqual(len(edits), int(prerelease))
                if edits:
                    self.assertIn('--latest=false', edits[0])
                    self.assertIn('--prerelease=true', edits[0])
                    self.assertNotIn('--latest', edits[0])

    def test_global_release_sequence_prevents_cross_channel_downgrade(self):
        row = {'tag_name':'v1.2.0','draft':False,'prerelease':True}
        for channel in ('stable','beta'):
            with self.assertRaises(ValueError): delivery.check_release_order([row], VERSION, channel=channel)
            delivery.check_release_order([row], '1.2.1', channel=channel)

    def test_public_delivery_verifies_all_six_downloads_and_rejects_tampering(self):
        names = delivery.metadata(self.directory, VERSION, REPO, COMMIT, self.public, write=True, channel='beta')
        assets = [{'name':n,'state':'uploaded','size':(self.directory/n).stat().st_size,'digest':'sha256:'+delivery.digest(self.directory/n)} for n in names]
        release = {'tag_name':'v'+VERSION,'draft':False,'prerelease':True,'assets':assets}
        downloaded = []
        def read(url, limit, *, missing_ok=False, hash_only=False):
            if '/tags/' in url: return json.dumps(release).encode()
            if url.endswith('/latest'): return json.dumps({'tag_name':'v1.1.1','prerelease':False}).encode()
            path = self.directory/url.rsplit('/',1)[1]
            if hash_only:
                downloaded.append(path.name)
                return path.stat().st_size, delivery.digest(path)
            return path.read_bytes()
        with patch.object(delivery, 'channel_key', return_value=self.public), patch.object(delivery, 'public_read', side_effect=read):
            delivery.verify_public(self.directory, VERSION, REPO, COMMIT, 'beta')
        self.assertEqual(set(downloaded), set(self.packages))
        def tamper(url, limit, **kwargs):
            value = read(url, limit, **kwargs)
            return (value[0], '0'*64) if kwargs.get('hash_only') else value
        with patch.object(delivery, 'channel_key', return_value=self.public), patch.object(delivery, 'public_read', side_effect=tamper):
            with self.assertRaisesRegex(ValueError, 'Public package bytes'): delivery.verify_public(self.directory, VERSION, REPO, COMMIT, 'beta')
        def leaked(url, limit, **kwargs):
            if url.endswith('/latest'): return json.dumps(release).encode()
            return read(url, limit, **kwargs)
        with patch.object(delivery, 'channel_key', return_value=self.public), patch.object(delivery, 'public_read', side_effect=leaked):
            with self.assertRaisesRegex(ValueError, 'leaked'): delivery.verify_public(self.directory, VERSION, REPO, COMMIT, 'beta')

    def test_msi_source_stable_component_identity(self):
        payload=self.root/'payload';payload.mkdir()
        (payload/'launcher-desktop.exe').write_bytes(b'desktop')
        (payload/'runtime.exe').write_bytes(b'runtime')
        ns={'w':'http://wixtoolset.org/schemas/v4/wxs'}
        p=self.root/'first.wxs';q=self.root/'second.wxs'
        delivery.wix_source(VERSION,'x64',payload,p)
        (payload/'aaa.exe').write_bytes(b'new')
        delivery.wix_source('1.1.3','x64',payload,q)
        def identities(path):
            tree=ET.parse(path)
            return {Path(x.find('w:File',ns).attrib['Source']).name:(x.attrib['Id'],x.attrib['Guid']) for x in tree.findall('.//w:Component',ns)}
        for name, identity in identities(p).items():
            self.assertEqual(identities(q)[name],identity)
        self.assertEqual(ET.parse(p).find('w:Package',ns).attrib['Scope'],'perMachine')

    def test_wrong_branch_blocked_before_remote(self):
        self.generate()
        with patch.dict(os.environ,{'NL_UPDATER_PUBLIC_KEY':self.public,'GITHUB_REF':'refs/heads/feature','GITHUB_SHA':COMMIT}),patch.object(delivery,'gh_json') as remote:
            with self.assertRaises(ValueError): delivery.publish(self.directory,VERSION,REPO,COMMIT)
            remote.assert_not_called()


class LinuxPackageIntegration(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and host_platform.system() == 'Linux' and shutil.which('dpkg-deb') and shutil.which('gpg') and host_platform.machine() in ('x86_64', 'aarch64'), 'Linux DEB/GPG tools required')
    def test_real_deb_and_gpg_from_signed_component_fixture(self):
        with tempfile.TemporaryDirectory(prefix='nl-deb-test-') as tmp:
            root = Path(tmp)
            bundle = root/'bundle'; bundle.mkdir()
            arch = 'x64' if host_platform.machine() == 'x86_64' else 'arm64'
            for binary in ('launcher-cli', 'launcher-api', 'launcher-desktop', 'guard', 'runtime'):
                shutil.copyfile('/bin/true', bundle/f'{binary}-linux-{arch}')
            root_key, delegated, seed, pub = keys()
            now = datetime.datetime.now(datetime.timezone.utc)
            def utc(t): return t.strftime('%Y-%m-%dT%H:%M:%SZ')
            policy = {'schemaVersion':'1.0','domain':'launcher.trust.v1','epoch':1,
                      'issuedAt':utc(now-datetime.timedelta(minutes=5)), 'expiresAt':utc(now+datetime.timedelta(days=1)),
                      'keys':[{'id':'fixture','role':'component','publicKey':pub(delegated),'status':'active','notBefore':utc(now-datetime.timedelta(minutes=5))}]}
            raw = json.dumps(policy).encode()
            policy_file = root/'policy.json'
            policy_file.write_text(json.dumps({'schemaVersion':'1.0','payload':b64(raw),'rootSignature':root_key.sign(b'Launcher-Trust-Policy-v1\n'+raw).hex()}))
            gnupg = root/'gnupg'; gnupg.mkdir(mode=0o700)
            env = {'GNUPGHOME':str(gnupg), 'LAUNCHER_COMPONENT_SET_ED25519_SEED':seed(delegated),
                   'LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY':pub(delegated), 'LAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY':pub(root_key),
                   'LAUNCHER_COMPONENT_TRUST_POLICY_FILE':str(policy_file),'LAUNCHER_COMPONENT_DELEGATED_ED25519_SEED':seed(delegated),
                   'LAUNCHER_COMPONENT_DELEGATED_KEY_ID':'fixture','LAUNCHER_COMPONENT_SECURITY_GENERATION':'2'}
            with patch.dict(os.environ, env):
                try:
                    subprocess.run(['gpg','--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','NeverLauncher CI fixture <fixture@example.invalid>','ed25519','sign','1d'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    output = subprocess.check_output(['gpg','--batch','--with-colons','--fingerprint'], text=True, stderr=subprocess.DEVNULL)
                    fingerprint = next(line.split(':')[9] for line in output.splitlines() if line.startswith('fpr:'))
                    with patch.dict(os.environ, {'NL_LINUX_GPG_FINGERPRINT':fingerprint}):
                        subprocess.run([os.sys.executable,str(Path(delivery.__file__).with_name('linux-package.py')),'--out',str(bundle),'--version',VERSION,'--architecture',arch],check=True,stdout=subprocess.DEVNULL)
                        delivery.native_installer(bundle, VERSION, 'linux', arch)
                    installer = bundle/delivery.installer_name(VERSION,'linux',arch)
                    self.assertEqual(subprocess.check_output(['dpkg-deb','--field',str(installer),'Version'],text=True).strip(),VERSION)
                    subprocess.run(['gpg','--batch','--verify',str(installer)+'.asc',str(installer)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                finally:
                    subprocess.run(['gpgconf','--kill','all'], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__': unittest.main()
