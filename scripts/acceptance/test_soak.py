from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest
import shutil
import subprocess
import threading
import ssl
import os
import http.server
from unittest import mock
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
spec=importlib.util.spec_from_file_location('soak',Path(__file__).parent/'soak_05211.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class SoakTests(unittest.TestCase):
    def test_reject_plaintext_http_and_embedded_credentials(self):
        for url in ('http://localhost:8080/', 'https://user:pw@localhost/',
                    'https://localhost/#fragment', 'file:///etc/passwd'):
            with self.subTest(url=url), self.assertRaises(m.Blocked):m.check_https(url)
    def test_percentile_measures_tail(self):
        self.assertEqual(m.percentile(list(range(1,101)),.95),95)
        with self.assertRaises(m.Blocked):m.percentile([4],.95)
    def test_one_hour_lower_bound(self):
        fake=SimpleNamespace(commit='f'*40,run_id='123',attempt=1,min_seconds=30)
        with self.assertRaises(m.Blocked):m.check_identity(fake)
    def test_missing_java_fails_before_output(self):
        # Несуществующая цель не должна запускаться или сообщать об успехе.
        a=SimpleNamespace(commit='f'*40,run_id='123',attempt=1,min_seconds=3600,
                          min_sessions=8,max_sessions=100,target_id='no-such-target',output=Path('/tmp/nl-no-such'))
        with self.assertRaises(m.Blocked):m.game(a)
    def test_reject_unsafe_artifact_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'existing').mkdir()
            with self.assertRaises(m.Blocked):m.output_dir(root/'existing')
    @unittest.skipUnless(shutil.which('openssl'), 'requires openssl')
    def test_real_tls_health_request_and_real_http_failure(self):
        class Endpoint(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"status":"ready"}')
                else:
                    self.send_response(503)
                    self.end_headers()
                    self.wfile.write(b'backend not ready')
            def log_message(self, *args):
                pass
        with tempfile.TemporaryDirectory() as tmp:
            cert=Path(tmp)/'cert.pem';key=Path(tmp)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048',
                 '-keyout',str(key),'-out',str(cert),'-days','1','-nodes',
                 '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],
                 check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Endpoint)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert),str(key))
            server.socket=ctx.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                with mock.patch.dict(os.environ,{'SSL_CERT_FILE':str(cert)}):
                    latency,size=m.https_once(f'https://localhost:{server.server_port}/health',5)
                    self.assertGreater(latency,0)
                    self.assertEqual(size,len(b'{"status":"ready"}'))
                    with self.assertRaises(m.Blocked):
                        m.https_once(f'https://localhost:{server.server_port}/unhealthy',5)
            finally:
                server.shutdown();server.server_close();thread.join(timeout=3)

    def test_copy_replay_mismatch_blocks_even_with_python_optimized(self):
        # Здесь обязателен require(), а не assert, который исчезает при python -O.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/'e2e/compatibility-result';source.mkdir(parents=True)
            (source/'compatibility-result.json').write_text('{"evidence":{"files":[]}}')
            (root/'e2e/runtime').mkdir(parents=True)
            destination=root/'copied'
            with mock.patch.object(m,'ROOT',root), \
                 mock.patch.object(m.inventory,'verify_compatibility',
                                   side_effect=[{'resultSha256':'a'*64},
                                                {'resultSha256':'b'*64}]):
                with self.assertRaisesRegex(m.Blocked,'copied Minecraft session evidence'):
                    m.session_archive({'loader':'vanilla'},destination,
                        SimpleNamespace(commit='a'*40,run_id='42',attempt=1))

    def test_log_invalid_sha(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'log';p.write_bytes(b'actual real bytes')
            self.assertNotEqual(m.digest(p),'0'*64)

if __name__=='__main__':unittest.main()
