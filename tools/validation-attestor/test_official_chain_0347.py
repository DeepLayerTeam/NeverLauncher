#!/usr/bin/env python3
"""Offline unit tests of host-only token handling, NOT a provider certification."""
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest
import official_chain_0347 as chain

CLIENT='12345678-1234-1234-1234-123456789abc'

class RealProviderBoundaryTests(unittest.TestCase):
    def test_microsoft_xbox_xsts_minecraft_chain_and_private_refresh_rotation(self):
        calls=[]
        def response(url,payload=None,bearer='',form=False):
            calls.append(url)
            if url==chain.MS:
                self.assertTrue(form)
                self.assertEqual(payload['grant_type'],'refresh_token')
                return {'access_token':'microsoft-only-test-token','refresh_token':'rotated-token-001'}
            if url==chain.XBL:return {'Token':'xbl-only-test-token','DisplayClaims':{'xui':[{'uhs':'test-user-hash'}]}}
            if url==chain.XSTS:return {'Token':'xsts-only-test-token','DisplayClaims':{'xui':[{'uhs':'test-user-hash'}]}}
            if url.endswith('login_with_xbox'):
                self.assertIn('XBL3.0 x=test-user-hash;',payload['identityToken'])
                return {'access_token':'minecraft-only-test-token','token_type':'Bearer','expires_in':3600}
            self.assertEqual(bearer,'minecraft-only-test-token')
            return {'name':'TestAccount','id':'1'*32}
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            token=d/'refresh.txt';token.write_text('initial-refresh-token');token.chmod(0o600)
            dest=d/'minecraft.json'
            with patch.object(chain,'request_live',side_effect=response):
                result=chain.issue_minecraft_credentials(CLIENT,token,dest)
            self.assertEqual(result['provider'],'real-microsoft-xbox-xsts-minecraft')
            self.assertEqual(token.read_text().strip(),'rotated-token-001')
            self.assertEqual(dest.stat().st_mode & 0o077,0)
            import json
            self.assertEqual(json.loads(dest.read_text())['userType'],'msa')
            self.assertNotIn('rotated-token',dest.read_text())
            self.assertEqual(calls,[chain.MS,chain.XBL,chain.XSTS,
                chain.MINECRAFT+'/authentication/login_with_xbox',chain.MINECRAFT+'/minecraft/profile'])

    def test_outage_never_generates_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);token=d/'refresh';token.write_text('initial-refresh-token');token.chmod(0o600)
            with patch.object(chain,'request_live',side_effect=chain.ExternalOutage('unavailable')):
                with self.assertRaises(chain.ExternalOutage):
                    chain.issue_minecraft_credentials(CLIENT,token,d/'credentials')
            self.assertFalse((d/'credentials').exists())

    def test_incorrect_minecraft_profile_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);token=d/'refresh';token.write_text('initial-refresh-token');token.chmod(0o600)
            def fake(url,payload=None,bearer='',form=False):
                if url==chain.MS:return {'access_token':'microsoft-only-test-token'}
                if url==chain.XBL:return {'Token':'xbl-only-test-token','DisplayClaims':{'xui':[{'uhs':'h'}]}}
                if url==chain.XSTS:return {'Token':'xsts-only-test-token','DisplayClaims':{'xui':[{'uhs':'h'}]}}
                if url.endswith('login_with_xbox'):
                    return {'access_token':'mc-only-test-token','token_type':'Bearer','expires_in':1000}
                return {'name':'Not a valid Java profile!','id':'0'*32}
            with patch.object(chain,'request_live',side_effect=fake):
                with self.assertRaises(chain.AccountRejected):
                    chain.issue_minecraft_credentials(CLIENT,token,d/'credentials')
            self.assertFalse((d/'credentials').exists())

if __name__=='__main__':unittest.main()
