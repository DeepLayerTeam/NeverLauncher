#!/usr/bin/env python3
"""Integration regression for the strict resource readiness gate, no game network required."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

SCRIPT = Path(__file__).with_name('vanilla-1171-resource-ready-proxy.py')


class ResourceReadyProxyTests(unittest.TestCase):
    def test_never_forwards_before_atlas_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / 'logs'
            logs.mkdir()
            backend = socket.socket()
            backend.bind(('127.0.0.1', 0))
            backend.listen(1)
            backend.settimeout(10)
            bytes_received = []

            def echo_server():
                try:
                    with backend.accept()[0] as c:
                        c.settimeout(2)
                        data = c.recv(128)
                        bytes_received.append(data)
                        c.sendall(data)
                except OSError:
                    pass

            worker = threading.Thread(target=echo_server, daemon=True)
            worker.start()
            p = subprocess.Popen([sys.executable, str(SCRIPT), '--backend-port', str(backend.getsockname()[1]),
                                  '--logs', str(logs), '--port-file', str(root / 'port'), '--evidence', str(root / 'evidence.json'),
                                  '--timeout', '5'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 3
                while not (root / 'port').exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                port = int((root / 'port').read_text())
                with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                    client.settimeout(.15)
                    client.sendall(b'actual handshake bytes')
                    with self.assertRaises(socket.timeout):
                        client.recv(1)
                    self.assertFalse(bytes_received)
                    cert_log = logs / 'neverruntime-vanilla-certification-1.17.1-123.log'
                    cert_log.write_text('Reloading ResourceManager: Default\n')
                    with self.assertRaises(socket.timeout):
                        client.recv(1)
                    cert_log.write_text('Created: 1024x512x4 minecraft:textures/atlas/blocks.png-atlas\n')
                    client.settimeout(3)
                    self.assertEqual(client.recv(128), b'actual handshake bytes')
                self.assertEqual(bytes_received, [b'actual handshake bytes'])
                evidence = json.loads((root / 'evidence.json').read_text())
                self.assertEqual(evidence['status'], 'released')
                self.assertTrue(evidence['atlasReady'])
                self.assertTrue(evidence['backendConnected'])
            finally:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                backend.close()
                worker.join(timeout=1)


if __name__ == '__main__':
    unittest.main()
