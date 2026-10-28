import json
from pathlib import Path
import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from diagnostics_03412 import redact, retain, prune

class DiagnosticPrivacyTests(unittest.TestCase):
    def test_privacy_digest_expiry_and_nofollow(self):
        raw=('Authorization: Bearer bearerabc\n--accessToken 123topsecret --username user@example.com\n'
             'profile=123e4567-e89b-12d3-a456-426614174000\n'
             'https://login/?access_token=uriSecret&code=mycode\n'
             '{"password":"jsonpassword","refresh_token":"refresh777"}\n')
        output=redact(raw)
        for secret in ('bearerabc','123topsecret','user@example.com','123e4567-e89b-12d3-a456-426614174000',
                       'uriSecret','mycode','jsonpassword','refresh777'):
            self.assertNotIn(secret,output)
        with tempfile.TemporaryDirectory() as base:
            source=Path(base)/'worker.log';source.write_text(raw,encoding='utf-8')
            folder=Path(base)/'logs'
            run='a'*48
            saved=retain(source,folder,run,ttl_hours=1)
            content=(folder/(run+'.log')).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(),saved['sha256'])
            self.assertTrue((folder/(run+'.json')).exists())
            self.assertFalse(folder.stat().st_mode & 0o077)
            self.assertFalse((folder/(run+'.log')).stat().st_mode & 0o077)
            with self.assertRaises(FileExistsError):retain(source,folder,run,ttl_hours=1)
            prune(folder,datetime.now(timezone.utc)+timedelta(hours=2))
            self.assertFalse((folder/(run+'.log')).exists())
            self.assertFalse((folder/(run+'.json')).exists())
    def test_reject_insecure_spool(self):
        with tempfile.TemporaryDirectory() as base:
            worker=Path(base)/'worker';worker.write_text('nothing')
            folder=Path(base)/'world';folder.mkdir(mode=0o755)
            with self.assertRaisesRegex(ValueError,'owner-only'):
                retain(worker,folder,'b'*48)
            with self.assertRaisesRegex(ValueError,'invalid diagnostic run id'):
                retain(worker,Path(base)/'private','../../secret')

if __name__=='__main__':unittest.main()
