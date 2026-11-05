"""Реальные локальные тесты HTTP, bearer-аутентификации и устойчивых файлов; не подтверждают внешнюю доставку."""
import http.client
import json
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
import stat
import tempfile
import threading
import unittest

import alert_receiver_05210 as alert

class ReceiverTests(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.dir = Path(home.name)
        self.dir.chmod(0o700)
        self.webhook = b'accept-real-alertmanager-webhook-token-001'
        self.reader = b'accept-independent-reviewer-read-token-002'
        self.server = ThreadingHTTPServer(('127.0.0.1', 0),
            alert.make_handler(self.dir, 'NeverLauncherNodeUnavailable', self.webhook, self.reader))
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, token, data=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=5)
        try:
            conn.request(method, path, json.dumps(data).encode() if data is not None else None,
                {'Authorization':'Bearer ' + token.decode(), 'Content-Type':'application/json'})
            r = conn.getresponse()
            return r.status, json.loads(r.read())
        finally:
            conn.close()

    def firing(self):
        return {'status':'firing','alerts':[{'status':'firing','labels':{
            'alertname':'NeverLauncherNodeUnavailable'},
            'fingerprint':'1234abcd1234abcd',
            'startsAt':datetime.now(timezone.utc).isoformat()}]}

    def test_real_http_persists_independently_delivered_event(self):
        self.assertEqual(self.request('GET','/events/latest',self.reader)[0], 404)
        self.assertEqual(self.request('POST','/webhook',self.reader,self.firing())[0], 403)
        self.assertEqual(self.request('POST','/webhook',self.webhook,self.firing())[0], 200)
        status, report = self.request('GET','/events/latest',self.reader)
        self.assertEqual(status, 200)
        self.assertEqual(report['fingerprint'], '1234abcd1234abcd')
        self.assertEqual(report['schema'], alert.SCHEMA)
        self.assertEqual(stat.S_IMODE((self.dir / 'latest.json').stat().st_mode), 0o600)
        self.assertEqual(alert.latest(self.dir), report)

    def test_invalid_and_unrelated_alerts_never_replace_receipt(self):
        self.request('POST','/webhook',self.webhook,self.firing())
        original = alert.latest(self.dir)
        bad = self.firing(); bad['alerts'][0]['labels']['alertname'] = 'UnrelatedEvent'
        self.assertEqual(self.request('POST','/webhook',self.webhook,bad)[0],422)
        self.assertEqual(alert.latest(self.dir), original)
        self.assertEqual(self.request('GET','/events/latest',self.webhook)[0],403)

    def test_reject_duplicate_json_and_symlink_receipts(self):
        with self.assertRaises(alert.Error):
            alert.unique([('fingerprint',1),('fingerprint',2)])
        p = self.dir / 'latest.json'
        p.symlink_to('/etc/hosts')
        with self.assertRaises(alert.Error):
            alert.latest(self.dir)
        with self.assertRaises(alert.Error):
            alert.store(self.dir, {'status':'delivered'})

if __name__ == '__main__':
    unittest.main()
