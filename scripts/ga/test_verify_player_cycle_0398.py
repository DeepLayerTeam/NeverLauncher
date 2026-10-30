"""Verifier regressions use synthetic fixtures ONLY to test rejection logic;
these unit tests are not live-Minecraft evidence or player certification.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_player_cycle_0398 import CASES, verify

COMMIT = 'a' * 40
UUID = '0123456789abcdef0123456789abcdef'
BAD_UUID = '1123456789abcdef0123456789abcdef'
VERSION = '0.39.8'

class PlayerCycle0398Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.join = {'username':'Player0398', 'uuid':UUID, 'serverId':'paper-e2e-p3',
                     'projectId':'e2e-project','profileId':'vanilla','channel':'stable'}
        self.save('result.json',{'status':'passed','version':VERSION,'mode':'full',
             'minecraft':{'client':'actual-mojang-client','paperJoin':'passed','profileId':'vanilla'},
             'checks':{'sessionRevokeDeny':True}})
        self.save('join-paper-real-client.json',{'data':{'oneTime':True,'ticketId':'jt_1','join':self.join}})
        self.save('join-paper-real-client-fresh.json',{'data':{'oneTime':True,'ticketId':'jt_2'}})
        self.save('validate-paper-e2e-p3-allow.json',{'data':{'allowed':True,'player':{'uuid':UUID,'username':'Player0398'}}})
        self.save('validate-paper-e2e-p3-deny.json',{'data':{'allowed':False,'reason':'launcher_session_or_handoff_missing_or_expired'}})
        for case, (changed, reason) in CASES.items():
            request = {'protocolVersion':2,'pluginVersion':VERSION,'pluginSha256':'a'*64,**self.join}
            request[changed] = {
                'uuid-mismatch':BAD_UUID, 'invalid-uuid':'not-a-minecraft-uuid',
                'project-mismatch':'foreign-project', 'profile-mismatch':'wrong-profile',
                'channel-mismatch':'beta', 'server-mismatch':'velocity-e2e-p3',
                'unissued-player':'NotIssued0398'}[case]
            self.save(f'player-0398-request-{case}.json',request)
            self.save(f'player-0398-response-{case}.json',{'data':{'allowed':False,
                  'reason':reason,'serverId':request['serverId'],'username':request['username']}})
            (self.root/f'player-0398-http-{case}.txt').write_text('403\n','ascii')
        # Mock only the already independently tested 0.36.4 verifier. The real CLI
        # never uses this mock and refuses missing/invalid actual JVM evidence.
        patcher = patch('verify_player_cycle_0398.verify_game_cycle',
                    return_value={'artifactsVerified':23,'realJoinsAfterUpdateAndRollback':True})
        patcher.start()
        self.addCleanup(patcher.stop)

    def save(self,name,document):
        (self.root/name).write_text(json.dumps(document),'utf-8')

    def edit(self,name,fn):
        doc=json.loads((self.root/name).read_text('utf-8'))
        fn(doc)
        self.save(name,doc)

    def pass_test(self):
        return verify(self.root,VERSION,COMMIT)

    def test_complete_positive_and_negative_fixture(self):
        report=self.pass_test()
        self.assertEqual(report['negativeCasesVerified'],7)
        self.assertEqual(report['expectedPlayerUUID'],UUID)
        self.assertEqual(report['officialProviderLiveE2E'],'not-covered-by-local-runner')

    def test_all_cases_are_individually_required(self):
        for case in CASES:
            with self.subTest(case=case):
                p=self.root/f'player-0398-response-{case}.json'
                raw=p.read_bytes();p.unlink()
                with self.assertRaises(ValueError):self.pass_test()
                p.write_bytes(raw)

    def test_server_must_reject_the_negative_case(self):
        self.edit('player-0398-response-uuid-mismatch.json',lambda doc:doc['data'].update({'allowed':True,'reason':'session_valid'}))
        with self.assertRaisesRegex(ValueError,'uuid-mismatch'):self.pass_test()

    def test_actual_http_denial_status_is_required(self):
        (self.root/'player-0398-http-uuid-mismatch.txt').write_text('200\n','ascii')
        with self.assertRaisesRegex(ValueError,'status'):self.pass_test()

    def test_tampered_authorized_uuid_is_not_accepted(self):
        self.edit('join-paper-real-client.json',lambda d:d['data']['join'].update({'uuid':BAD_UUID}))
        with self.assertRaises(ValueError):self.pass_test()

    def test_denial_cannot_consume_ticket(self):
        self.edit('validate-paper-e2e-p3-allow.json',lambda d:d['data']['player'].update({'uuid':BAD_UUID}))
        with self.assertRaises(ValueError):self.pass_test()

    def test_reused_ticket_is_not_live_join(self):
        self.edit('join-paper-real-client-fresh.json',lambda d:d['data'].update({'ticketId':'jt_1'}))
        with self.assertRaises(ValueError):self.pass_test()

    def test_replay_must_be_denied(self):
        self.edit('validate-paper-e2e-p3-deny.json',lambda d:d['data'].update({'allowed':True}))
        with self.assertRaises(ValueError):self.pass_test()

    def test_renamed_project_is_not_evidence(self):
        self.edit('player-0398-request-project-mismatch.json',lambda d:d.update({'projectId':'e2e-project'}))
        with self.assertRaises(ValueError):self.pass_test()

    def test_wrong_commit_is_rejected(self):
        with self.assertRaises(ValueError):verify(self.root,VERSION,'not-a-commit')

    def test_no_game_cycle_cannot_be_certified(self):
        with patch('verify_player_cycle_0398.verify_game_cycle',side_effect=ValueError('missing JVM')):
            with self.assertRaisesRegex(ValueError,'missing JVM'):self.pass_test()

    def test_wrong_realm_and_client_are_not_accepted(self):
        self.edit('result.json',lambda d:d['minecraft'].update({'client':'protocol-probe'}))
        with self.assertRaises(ValueError):self.pass_test()

    def test_symlinked_http_evidence_is_rejected(self):
        src=self.root/'player-0398-request-channel-mismatch.json'
        contents=src.read_bytes();src.unlink()
        target=self.root/'outsider.json';target.write_bytes(contents)
        src.symlink_to(target)
        with self.assertRaises(ValueError):self.pass_test()

    def test_duplicate_json_field_is_rejected(self):
        p=self.root/'player-0398-response-channel-mismatch.json'
        p.write_text('{"data":{},"data":{}}','utf-8')
        with self.assertRaises(ValueError):self.pass_test()

if __name__=='__main__':unittest.main()
