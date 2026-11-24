import unittest
from unified_ai_smoke import validate_stream, verify_stage, verify_usage

RID = 'a' * 32
STREAM = f'event: start\ndata: {{"requestId":"{RID}"}}\n\nevent: delta\ndata: {{"delta":"OK"}}\n\nevent: done\ndata: {{"requestId":"{RID}","state":"completed","chargedMicroUsd":18}}\n\n'

class SmokeTests(unittest.TestCase):
    def test_completed_stream(self):
        self.assertEqual(validate_stream(STREAM), 18)
        self.assertEqual(validate_stream(STREAM.replace('\n', '\r\n')), 18)

    def test_stream_rejects_incomplete_or_inconsistent_result(self):
        for raw in (STREAM.split('event: done')[0], STREAM.replace('event: done', 'event: error'), STREAM.replace('"state":"completed"', '"state":"uncertain"'), STREAM.replace('"chargedMicroUsd":18', '"chargedMicroUsd":-1'), STREAM + STREAM, STREAM.replace('"delta":"OK"','"delta":""'), STREAM.replace('"state":"completed"', '"state":"completed","requestId":"b"')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                validate_stream(raw)

    def test_exact_stage_commit(self):
        status = {'version':'1.3.0','sourceCommit':'a'*40,'status':'ok'}
        verify_stage(status, '1.3.0', 'a'*40)
        for bad in ({**status,'version':'1.2.5'}, {**status,'sourceCommit':'b'*40}, {**status,'status':'unavailable'}, {'version':'1.3.0','status':'ok'}):
            with self.assertRaises(ValueError):
                verify_stage(bad, '1.3.0', 'a'*40)
        with self.assertRaises(ValueError):
            verify_stage(status, '1.3.0', 'unknown')

    def test_usage_requires_exact_settlement(self):
        before = {'requests':3,'chargedMicroUsd':100,'uncertainRequests':1}
        after = {'requests':4,'chargedMicroUsd':118,'uncertainRequests':1}
        verify_usage(before, after, 18)
        for bad in ({**after,'requests':5}, {**after,'chargedMicroUsd':117}, {**after,'uncertainRequests':2}):
            with self.assertRaises(ValueError):
                verify_usage(before, bad, 18)
