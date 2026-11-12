"""Отрицательные регрессионные тесты и проверки целостности; не заменяют действующую приёмку."""
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import modpacks_textures_publication as acceptance


class ModpackPublicationTests0526(unittest.TestCase):
    def test_https_exact_origin_only(self):
        for value in ('http://example.org', 'https://example.org/extra',
                      'https://user:pass@example.org', 'https://example.org/?key=x',
                      'https://example.org/#section', 'https://example.org:bad'):
            with self.subTest(value=value), self.assertRaises((acceptance.Blocked, ValueError)):
                acceptance.API(value)
        self.assertEqual(acceptance.API('https://example.org').origin, 'https://example.org')

    def test_duplicate_json_is_never_accepted(self):
        with self.assertRaises(acceptance.Blocked):
            acceptance.parse_json(b'{"status":"failed","status":"passed"}')

    def test_native_ready_requires_every_selected_file(self):
        acceptance.assert_native_ready({'status':'ready','files':[{'status':'ok'}]})
        for doc in ({'status':'invalid','files':[]},
                    {'status':'ready','files':[{'status':'optional-missing'}]},
                    {'status':'ready','files':[{'status':'missing'}]}):
            with self.subTest(doc=doc), self.assertRaises(acceptance.Blocked):
                acceptance.assert_native_ready(doc)

    def test_catalog_must_really_contain_mod_jar(self):
        cat = {'components':[{'id':'live-test','files':['mods/authentic.jar']}]}
        self.assertEqual(acceptance.selected_catalog_files(cat,'live-test'), ['mods/authentic.jar'])
        for files in ([], ['../escape.jar'], ['mods/../../escape.jar'], ['other/asset.png']):
            with self.subTest(files=files), self.assertRaises(acceptance.Blocked):
                acceptance.selected_catalog_files({'components':[{'id':'live-test','files':files}]},'live-test')

    def test_binary_hash_is_not_substituted_with_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            file=root/'mod.jar'
            file.write_bytes(b'original')
            original=acceptance.sha_file(file)
            file.write_bytes(b'changed')
            self.assertNotEqual(acceptance.sha_file(file),original)
            with self.assertRaises(acceptance.Blocked):
                acceptance.confirm_local_files({'files':[{'path':'mods/mod.jar','sha256':original}]},root,['mods/mod.jar'],True)

    def test_unselected_mod_is_not_allowed_to_materialize(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            target=root/'mods'/'extra.jar'
            target.parent.mkdir()
            target.write_bytes(b'extra')
            with self.assertRaises(acceptance.Blocked):
                acceptance.confirm_local_files({'files':[{'path':'mods/extra.jar','sha256':acceptance.sha_file(target)}]},
                                               root,['mods/extra.jar'],False)

    def test_unsafe_symlink_prohibited(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            f=root/'secret';f.write_bytes(b'secret')
            link=root/'link';link.symlink_to(f)
            with self.assertRaises(acceptance.Blocked): acceptance.sha_file(link)
            with self.assertRaises(acceptance.Blocked): acceptance.private_file(link)

    def test_secret_file_requires_exclusive_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Path(temp)/'token'
            f.write_bytes(b'token')
            f.chmod(0o644)
            with self.assertRaises(acceptance.Blocked): acceptance.private_file(f)
            f.chmod(0o600)
            self.assertEqual(acceptance.private_file(f),b'token')

    def test_private_receipt_atomic_and_no_fake_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'report.json'
            acceptance.atomic_private_json(path,{'status':'blocked','gaCertified':False})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(path.read_text())['status'],'blocked')
            attack=Path(temp)/'symlink.json';attack.symlink_to(path)
            with self.assertRaises(acceptance.Blocked): acceptance.atomic_private_json(attack,{'status':'passed'})

    def test_png_rejects_header_only_and_wrong_geometry(self):
        for data in (b'',b'not-a-png',b'\x89PNG\r\n\x1a\n'+b'\x00'*25):
            with self.subTest(data=data), self.assertRaises(acceptance.Blocked): acceptance.check_png(data,'skin')
        fake=b'\x89PNG\r\n\x1a\n'+b'\x00'*8+struct.pack('>II',64,64)+b'\x00'*9
        acceptance.check_png(fake,'skin')  # Предварительно проверяется только заголовок; Backend выполняет полное декодирование PNG.
        with self.assertRaises(acceptance.Blocked): acceptance.check_png(fake,'cape')

    def test_no_external_credentials_always_block(self):
        with tempfile.TemporaryDirectory() as temp:
            from argparse import Namespace
            fields={'report':Path(temp)/'report.json','destructive_isolated_run':False}
            for name in ('secrets','operator_token','runtime','cli','java','skin','cape'):
                fields[name]=Path(temp)/'missing'
            for name in ('runtime_sha256','cli_sha256','pinned_manifest_public_key','project','profile',
                         'channel','package_id','component','selected_preset','excluded_preset'):
                fields[name]='missing'
            fields.update(server_bundle=None,server_bundle_sha256='',server_entry='')
            code=acceptance.main(sum((['--'+key.replace('_','-'),str(value)] for key,value in fields.items()
                                       if key not in ('destructive_isolated_run','server_bundle','server_bundle_sha256','server_entry')),[]))
            self.assertEqual(code,1)
            doc=json.loads(fields['report'].read_text())
            self.assertEqual(doc['status'],'blocked')
            self.assertFalse(doc['gaCertified'])


if __name__ == '__main__':
    unittest.main()
