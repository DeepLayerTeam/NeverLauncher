#!/usr/bin/env python3
"""Real package-writer + byte-inspection tests for the 0.41 updater path.

Temporary synthetic executables check archive layout and hash linking; they
are never represented as native-signing or Minecraft-launch certificates.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import importlib.util
import tempfile
import zipfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
def load_script(filename, alias):
    spec = importlib.util.spec_from_file_location(alias, Path(__file__).resolve().parent / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module

linux = load_script('linux-package.py', 'linux_package_0410')
macos = load_script('macos-package.py', 'macos_package_0410')
import rehearsal_0365 as release
from component_set_sign import signed_set, sign_delegated_set

VERSION = '0.41.0'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fake_elf() -> bytes:
    result = bytearray(64)
    result[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', result, 16, 2, 62)
    return bytes(result)


def fake_pe() -> bytes:
    data = bytearray(384)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x84, 0x8664)
    struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<II', data, 0x98+112+32, 352, 16)
    return bytes(data)


def fake_macho() -> bytes:
    result = bytearray(80)
    result[:4] = b'\xcf\xfa\xed\xfe'
    struct.pack_into('<I', result, 4, 0x01000007)
    struct.pack_into('<II', result, 16, 1, 16)
    struct.pack_into('<IIII', result, 32, 0x1d, 16, 48, 24)
    return bytes(result)


class FinalUpdateDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        root_key = Ed25519PrivateKey.generate()
        component = Ed25519PrivateKey.generate()
        delegated = Ed25519PrivateKey.generate()
        def raw_priv(key):
            return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                     serialization.NoEncryption()).hex()
        def raw_pub(key):
            return key.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw).hex()
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end = (now + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        payload = json.dumps({'schemaVersion': '1.0', 'domain': 'neverlauncher.trust.v1',
                              'epoch': 4, 'issuedAt': start, 'expiresAt': end,
                              'keys': [{'id': 'component-test', 'role': 'component',
                                        'publicKey': raw_pub(delegated), 'status': 'active',
                                        'notBefore': start}]}, separators=(',', ':')).encode()
        policy_doc = {'schemaVersion': '1.0', 'payload': base64.b64encode(payload).decode(),
                      'rootSignature': root_key.sign(b'NeverLauncher-Trust-Policy-v1\n'+payload).hex()}
        policy_path = self.root / 'root-signed-policy.json'
        policy_path.write_text(json.dumps(policy_doc))
        env = {
            'NEVERLAUNCHER_COMPONENT_SECURITY_GENERATION': '1',
            'NEVERLAUNCHER_COMPONENT_SET_ED25519_SEED': raw_priv(component),
            'NEVERLAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY': raw_pub(component),
            'NEVERLAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY': raw_pub(root_key),
            'NEVERLAUNCHER_COMPONENT_TRUST_POLICY_FILE': str(policy_path),
            'NEVERLAUNCHER_COMPONENT_DELEGATED_ED25519_SEED': raw_priv(delegated),
            'NEVERLAUNCHER_COMPONENT_DELEGATED_KEY_ID': 'component-test',
        }
        mock_env = patch.dict(os.environ, env)
        mock_env.start()
        self.addCleanup(mock_env.stop)
        self.delegated = delegated
        self.component = component
        self.policy_payload = payload

    def verify_signed_manifest(self, members: dict[str, bytes], prefix: str) -> None:
        raw = members[prefix+'COMPONENT_UPDATE_MANIFEST.json']
        v1 = json.loads(members[prefix+'COMPONENT_SET_SIGNATURE.json'])
        self.component.public_key().verify(bytes.fromhex(v1['signature']), raw)
        v2 = json.loads(members[prefix+'COMPONENT_SET_SIGNATURE_V2.json'])
        self.assertEqual(v2['manifestSha256'], digest(raw))
        context = ('NeverLauncher-Component-v2\n'+v2['keyId']+'\n'+str(v2['trustEpoch'])+'\n'+
                   v2['policySha256']+'\n'+v2['manifestSha256']+'\n'+v2['signedAt']+'\n').encode()
        self.delegated.public_key().verify(bytes.fromhex(v2['signature']), context+raw)
        policy_doc = json.loads(members[prefix+'COMPONENT_TRUST_POLICY.json'])
        self.assertEqual(base64.b64decode(policy_doc['payload']), self.policy_payload)

    def test_linux_real_tar_writer_installs_updatable_components(self):
        for component, (pattern, _) in linux.COMPONENTS.items():
            (self.root / pattern.format(arch='x64')).write_bytes(fake_elf() + component.encode())
        linux.write_package(self.root, VERSION, 'x64')
        package = self.root / f'neverlauncher-linux-x64-{VERSION}.tar.gz'
        members = release.unpack(package)
        self.verify_signed_manifest(members, 'neverlauncher/')
        manifest = json.loads(members['neverlauncher/LINUX_PACKAGE_MANIFEST.json'])
        release.verify_update_payload_0410(members, manifest, 'linux', 'x64', VERSION)
        self.assertTrue((self.root/'LINUX_PACKAGE_MANIFEST_X64.json').is_file())
        report = release.exact_package(self.root, VERSION, 'linux-x64')
        self.assertEqual(report['target'], 'linux-x64')

        # An installer checksum alone can be updated by a compromised staging
        # step. The inner updater manifest must still reject altered payloads.
        mutated = dict(members)
        mutated['neverlauncher/neverruntime'] += b'corrupt'
        with self.assertRaises(release.Blocked):
            release.verify_update_payload_0410(mutated, manifest, 'linux', 'x64', VERSION)
        mutated = dict(members)
        update = json.loads(mutated['neverlauncher/COMPONENT_UPDATE_MANIFEST.json'])
        update['components'][0]['sourcePath'] = '../neverlauncher-desktop'
        mutated['neverlauncher/COMPONENT_UPDATE_MANIFEST.json'] = json.dumps(update).encode()
        with self.assertRaises(release.Blocked):
            release.verify_update_payload_0410(mutated, manifest, 'linux', 'x64', VERSION)
        mutated = dict(members)
        mutated.pop('neverlauncher/COMPONENT_SET_SIGNATURE_V2.json')
        with self.assertRaises(release.Blocked):
            release.verify_update_payload_0410(mutated, manifest, 'linux', 'x64', VERSION)
        # A forged signature with a correct manifest digest is still rejected
        # by the pinned delegated key and root-signed trust policy.
        mutated = dict(members)
        forged = json.loads(mutated['neverlauncher/COMPONENT_SET_SIGNATURE_V2.json'])
        forged['signature'] = 'a'*128
        mutated['neverlauncher/COMPONENT_SET_SIGNATURE_V2.json'] = json.dumps(forged).encode()
        with self.assertRaises(release.Blocked):
            release.verify_update_payload_0410(mutated, manifest, 'linux', 'x64', VERSION)
        with patch.dict(os.environ, {'NEVERLAUNCHER_COMPONENT_TRUST_ROOT_PUBLIC_KEY': ''}):
            with self.assertRaises(release.Blocked):
                release.verify_update_payload_0410(members, manifest, 'linux', 'x64', VERSION)

    def test_windows_final_signed_package_contents_are_updatable(self):
        roles = {'desktop': 'desktop-launcher', 'guard': 'guard',
                 'runtime': 'runtime', 'sensor': 'sensor', 'updater': 'cli'}
        names = {'desktop': 'neverlauncher-desktop.exe', 'guard': 'neverguard.exe',
                 'runtime': 'neverruntime.exe', 'sensor': 'neverguard-sensor.dll',
                 'updater': 'neverlauncher-cli.exe'}
        members = {names[role]: fake_pe()+role.encode() for role in roles}
        rows = []
        for role, code in roles.items():
            rows.append({'component': code, 'name': names[role],
                         'sha256': digest(members[names[role]]),
                         'size': len(members[names[role]]),
                         'authenticodeStatus': 'Valid', 'timestamped': True,
                         'signtoolVerified': True, 'signerThumbprint': 'a'*40})
        manifest = {'productVersion': VERSION, 'architecture': 'x64', 'artifacts': rows}
        manifest_bytes = json.dumps(manifest).encode()
        members['WINDOWS_PACKAGE_MANIFEST.json'] = manifest_bytes
        (self.root/'WINDOWS_PACKAGE_MANIFEST_X64.json').write_bytes(manifest_bytes)
        update_rows = []
        for role in ('desktop', 'guard', 'runtime', 'sensor'):
            path = names[role]
            update_rows.append({'component': role, 'sourcePath': path, 'targetPath': path,
                                'sha256': digest(members[path]), 'size': len(members[path]),
                                'executable': True})
        support = []
        for role, path in (('updater', names['updater']), ('package-manifest', 'WINDOWS_PACKAGE_MANIFEST.json')):
            support.append({'component': role, 'sourcePath': path, 'targetPath': path,
                            'sha256': digest(members[path]), 'size': len(members[path]),
                            'executable': role != 'package-manifest'})
        update = {'schemaVersion': '1.0', 'product': 'NeverLauncher',
                  'productVersion': VERSION, 'platform': 'windows', 'architecture': 'x64',
                  'layout': 'adjacent-files', 'components': update_rows, 'supportFiles': support}
        raw, v1 = signed_set(update)
        v2, policy_doc = sign_delegated_set(raw)
        members['COMPONENT_UPDATE_MANIFEST.json'] = raw
        members['COMPONENT_SET_SIGNATURE.json'] = v1
        members['COMPONENT_SET_SIGNATURE_V2.json'] = v2
        members['COMPONENT_TRUST_POLICY.json'] = policy_doc
        self.verify_signed_manifest(members, '')
        with zipfile.ZipFile(self.root/f'neverlauncher-desktop-{VERSION}-windows-x64.zip', 'w') as z:
            for name, data in members.items():
                z.writestr(name, data)
        (self.root/'neverlauncher-desktop-windows-x64.exe').write_bytes(members['neverlauncher-desktop.exe'])
        self.assertEqual(release.exact_package(self.root, VERSION, 'windows-x64')['target'],
                         'windows-x64')
        bad = dict(members)
        bad['COMPONENT_UPDATE_MANIFEST.json'] = b'{}'
        with zipfile.ZipFile(self.root/f'neverlauncher-desktop-{VERSION}-windows-x64.zip', 'w') as z:
            for name, data in bad.items():
                z.writestr(name, data)
        with self.assertRaises(release.Blocked):
            release.exact_package(self.root, VERSION, 'windows-x64')

    def test_macos_app_writer_embeds_delegated_component_trust(self):
        app = self.root / 'NeverLauncher.app'
        for component, (relative, _) in macos.COMPONENTS.items():
            target = app / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(fake_macho()+component.encode())
        args = SimpleNamespace(version=VERSION, arch='x64', team_id='AAAAAAAAAA',
                               trust_mode='developer-id-notarized', app=str(app),
                               out_dir=str(self.root/'dist'))
        macos.manifest_cmd(args)
        resource_prefix = 'NeverLauncher.app/Contents/Resources/'
        members = {str(file.relative_to(self.root)):file.read_bytes()
                   for file in app.rglob('*') if file.is_file()}
        self.verify_signed_manifest(members, resource_prefix)
        manifest = json.loads(members[resource_prefix+'MACOS_PACKAGE_MANIFEST.json'])
        release.verify_update_payload_0410(members, manifest, 'darwin', 'x64', VERSION)
        macos.finalize_cmd(args)
        package_name = f'neverlauncher-desktop-{VERSION}-macos-x64.zip'
        package_path = self.root/'dist'/package_name
        with zipfile.ZipFile(package_path, 'w') as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        self.assertEqual(release.exact_package(self.root/'dist', VERSION, 'darwin-x64')['target'],
                         'darwin-x64')
        # Detect post-signing drift between the sealed component update list
        # and the final signed main application executable.
        modified = dict(members)
        modified['NeverLauncher.app/Contents/MacOS/neverlauncher-desktop'] += b'codesign-drift'
        with self.assertRaises(release.Blocked):
            release.verify_update_payload_0410(modified, manifest, 'darwin', 'x64', VERSION)


if __name__ == '__main__':
    unittest.main()
