"""Contract-free tests: real HTTP bytes, real local subprocess, fail-closed checks."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from benchmark_03511 import (MIB, ProcessMonitor, RepeatingRangeServer, benchmark_api,
                            describe, percentile, repeating_hash, run_native)


class Bench03511Tests(unittest.TestCase):
    def test_percentiles_use_samples_not_constants(self):
        self.assertEqual(percentile([3, 1, 5], .5), 3)
        self.assertEqual(percentile([1, 2, 3], .95), 2.9)
        self.assertEqual(describe([1, 2, 3])['count'], 3)

    def test_real_http_range_returns_correct_payload_and_wire_bytes(self):
        block = bytes(range(256)) * 4
        length = len(block) * 2 + 51
        with RepeatingRangeServer(block, length) as server:
            with urlopen(server.url) as response:
                body = response.read()
                self.assertEqual(response.status, 200)
            self.assertEqual(body, block * 2 + block[:51])
            with urlopen(Request(server.url, headers={'Range': 'bytes=1024-'})) as response:
                partial = response.read()
                self.assertEqual(response.status, 206)
                self.assertEqual(response.headers['Content-Range'], f'bytes 1024-{length-1}/{length}')
            self.assertEqual(partial, body[1024:])
            with self.assertRaises(HTTPError) as err:
                urlopen(Request(server.url, headers={'Range': f'bytes={length}-'}))
            self.assertEqual(err.exception.code, 416)
            self.assertEqual(server.transferred, length + len(partial))
            self.assertEqual(repeating_hash(block, length), hashlib.sha256(body).hexdigest())

    def test_run_native_collects_actual_cpu_and_memory(self):
        result, data = run_native([sys.executable, '-c',
            'import json,time; a=bytearray(2*1024*1024); time.sleep(.25); print(json.dumps({"status":"ready"}))'])
        self.assertEqual(data['status'], 'ready')
        self.assertGreater(result['elapsedMs'], 200)
        self.assertGreater(result['peakRssBytes'], 0)
        self.assertGreater(result['sampleCount'], 1)

    def test_api_get_on_actual_local_server_and_reject_unsafe_targets(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'{}')
        srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            report = benchmark_api(f'http://127.0.0.1:{srv.server_port}/ready',
                                   repetitions=3, requests_per_run=10, workers=2)
            self.assertEqual(len(report['runs']), 3)
            self.assertTrue(all(r['latencyMs']['p95'] > 0 for r in report['runs']))
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(timeout=2)
        for url in ['https://example.com/status', 'http://user:pass@127.0.0.1/status',
                    'http://localhost/ready?access_token=secret', 'file:///etc/passwd']:
            with self.assertRaises(ValueError):
                benchmark_api(url, repetitions=1, requests_per_run=1, workers=1)

    def test_no_measurement_can_be_published_without_real_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'report.json'
            proc = subprocess.run([sys.executable, str(Path(__file__).with_name('benchmark_03511.py')),
                '--runtime', str(Path(folder) / 'nonexistent'), '--signer', str(Path(folder) / 'missing'),
                '--output', str(output), '--download-mib', '8'], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(output.exists() and '"status": "measured"' in output.read_text())


if __name__ == '__main__':
    unittest.main()
