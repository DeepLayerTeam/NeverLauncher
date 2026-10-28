#!/usr/bin/env python3
"""Test fail-closed API acceptance transport (mock only for NEGATIVE tests).

Real integration is run separately on a compiled Backend by CI.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import pathlib
import sys
import threading
import unittest

HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import owner_player_api_0351 as live

class Handler(BaseHTTPRequestHandler):
    status = 403
    body = b'{"error":"denied"}'
    def do_GET(self):
        self.send_response(type(self).status)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(type(self).body)
    def log_message(self,*args): pass

class LoopbackTransportNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.api=live.API(f'http://127.0.0.1:{cls.server.server_port}')
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def test_unexpected_403_fails_closed(self):
        Handler.status=403;Handler.body=b'{"error":"denied"}'
        with self.assertRaises(live.AuditError):
            self.api.request('GET','/api/v1/projects')

    def test_non_json_success_does_not_pass(self):
        Handler.status=200;Handler.body=b'<html>not JSON</html>'
        with self.assertRaises(live.AuditError):
            self.api.request('GET','/api/v1/projects')

    def test_size_limit_is_enforced(self):
        Handler.status=200;Handler.body=b'{' + (b' ' * (live.MAX_BODY+1)) + b'}'
        with self.assertRaises(live.AuditError):
            self.api.request('GET','/api/v1/projects')

    def test_arbitrary_urls_are_rejected(self):
        Handler.status=200;Handler.body=b'{}'
        for path in ('http://another-host/','//another-host/', '/internal/key'):
            with self.subTest(path=path),self.assertRaises(live.AuditError):
                self.api.request('GET',path)

if __name__=='__main__': unittest.main()
