"""Строгие проверки отказов; локальные фикстуры никогда не представляют реальные GA-свидетельства SDK."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from scripts.acceptance import sdk_live_0530 as sdk

class SdkLiveTest(unittest.TestCase):
 def test_http_is_not_real_published_https(self):
    with tempfile.TemporaryDirectory() as folder:
     private=Path(folder)/'token';private.write_text('x'*32);private.chmod(0o600)
     args=self.args(private)
     args.origin='http://127.0.0.1:1234'
     with self.assertRaises(sdk.Blocked):sdk.probe(args)
 def test_missing_token_blocks(self):
    with tempfile.TemporaryDirectory() as folder:
     args=self.args(Path(folder)/'token')
     with self.assertRaises(sdk.Blocked):sdk.probe(args)
 def test_modified_unauthorized_query_blocks(self):
    with tempfile.TemporaryDirectory() as folder:
     token=Path(folder)/'token';token.write_text('x'*32);token.chmod(0o600)
     args=self.args(token);args.binary_path='/api/v1/file?skip=1'
     with self.assertRaises(sdk.Blocked):sdk.probe(args)
 def test_external_url_encoded_userinfo_blocks(self):
    with tempfile.TemporaryDirectory() as folder:
     args=self.args(Path(folder)/'token');args.origin='https://example.com@another.example'
     with self.assertRaises(sdk.Blocked):sdk.probe(args)
 def test_wrong_checksum_blocks_before_request(self):
    with tempfile.TemporaryDirectory() as folder:
     args=self.args(Path(folder)/'token');args.binary_sha256='not-a-hash'
     with self.assertRaises(sdk.Blocked):sdk.probe(args)
 @staticmethod
 def args(token):
    return SimpleNamespace(origin='https://api.example.org',json_path='/api/v1/auth/capabilities',
          text_path='/metrics',binary_path='/api/v1/test/bytes',binary_sha256='0'*64,
          bearer_file=token,java='/usr/bin/java',go='/usr/local/go/bin/go',node='/usr/bin/node')

if __name__=='__main__':unittest.main()
