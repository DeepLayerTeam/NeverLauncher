import hashlib
import json
import sys
import http.server
import tempfile
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from importlib.machinery import SourceFileLoader

MODULE = SourceFileLoader('staged0342', str(Path(__file__).with_name('run-staged-package-0342.py'))).load_module()

class FakeHandler(http.server.BaseHTTPRequestHandler):
    payload = b'actual staged bytes'
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)
    def log_message(self, *args):
        pass

class StagedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'
        self.tmp = tempfile.TemporaryDirectory()
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()
    def test_download_exact(self):
        target = Path(self.tmp.name) / 'mods' / 'original.jar'
        payload = FakeHandler.payload
        MODULE.download_exact(self.base, '/api/v1/staged-runs/example/files/mod.jar', 'grant', target, len(payload), hashlib.sha256(payload).hexdigest())
        self.assertEqual(target.read_bytes(), payload)
    def test_corrupt_bytes_cannot_materialize(self):
        target = Path(self.tmp.name) / 'mods' / 'corrupt.jar'
        with self.assertRaisesRegex(ValueError, 'differs from signed snapshot'):
            MODULE.download_exact(self.base, '/api/v1/staged-runs/example/files/mod.jar', 'grant', target, len(FakeHandler.payload), '0'*64)
        self.assertFalse(target.exists())
    def test_native_neverruntime_stdout_is_persisted(self):
        output = Path(self.tmp.name) / 'launch.json'
        code = 'import json; print(json.dumps({"timed_out":True,"success":False,"exit_code":None}))'
        class Observer:
            root_pid = None
            def tick(self): pass
        observer = Observer()
        result = MODULE.run_runtime_observed([sys.executable, '-c', code], output, {}, 10, observer)
        self.assertIs(result['timed_out'], True)
        self.assertIsInstance(observer.root_pid, int)
        self.assertEqual(json.loads(output.read_text()), result)
        # The observation itself cannot certify startup or menu readiness.
        from staged_readiness_0343 import StartupObserver
        with patch.dict(__import__('os').environ, {'DISPLAY':''}):
            probe = StartupObserver(observer.root_pid, Path(self.tmp.name), Path(self.tmp.name)/'frames', 'vanilla', 0)
        self.assertNotEqual(probe.conclude(result)[0], 'passed')
    def test_missing_and_unsafe_paths(self):
        for name in ('../evil','/absolute','a\\b','a/../b'):
            with self.assertRaises(ValueError):
                MODULE.checked_path(name)
        with self.assertRaises(ValueError):
            MODULE.download_exact(self.base,'https://evil.example/a','grant',Path(self.tmp.name)/'p',1,'0'*64)

if __name__ == '__main__':
    unittest.main()
