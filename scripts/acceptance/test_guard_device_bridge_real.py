#!/usr/bin/env python3
"""Регрессионные тесты враждебных входных данных и формата обмена. Фикстуры НЕ являются действующей приёмкой."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

import guard_device_bridge_real_0529 as suite
import vanilla_sidecar_live_0529 as vanilla

class Acceptance0529(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_missing_required_live_paths_fail_closed(self):
        with self.assertRaises(suite.Blocked):
            suite.run_live({'sourceCommit':'a'*40, 'runId':'123'})

    def test_duplicate_json_field_is_not_overwritten(self):
        target=self.root/'evidence.json'
        target.write_text('{"status":"failed","status":"passed"}')
        with self.assertRaisesRegex(suite.Blocked, 'Повторяющийся ключ'):
            suite.read_json(target)

    def test_signed_input_is_not_allowed_from_symlinks_or_hardlinks(self):
        original=self.root/'test.json'
        original.write_text('{"status":"passed"}')
        self.assertEqual(suite.sha(original),hashlib.sha256(original.read_bytes()).hexdigest())
        link=self.root/'link.json';link.symlink_to(original)
        with self.assertRaises(suite.Blocked):suite.read_json(link)
        duplicate=self.root/'duplicate.json';os.link(original,duplicate)
        with self.assertRaises(suite.Blocked):suite.read_json(original)

    def test_no_guard_native_results_not_promoted(self):
        with self.assertRaises(suite.Blocked):
            suite.inspect_guard_ci(self.root,'a'*40,'120','DeepLayerTeam/Launcher')

    def test_no_device_native_results_not_promoted(self):
        with self.assertRaises(suite.Blocked):
            suite.inspect_device(self.root,'a'*40,'120')

    def test_no_serverbridge_runtime_not_promoted(self):
        with self.assertRaises(suite.Blocked):
            suite.inspect_serverbridge(self.root)

    def test_missing_vanilla_sidecar_not_promoted(self):
        with self.assertRaises(vanilla.Blocked):
            vanilla.verify({})

    def test_invalid_rcon_password_and_unbound_interface_rejected(self):
        with self.assertRaisesRegex(vanilla.Blocked, 'loopback'):
            vanilla.rcon('8.8.8.8', 25575, 'this is a password', 'list')
        with self.assertRaisesRegex(vanilla.Blocked, 'credential'):
            vanilla.rcon('127.0.0.1', 25575, 'secret', 'list')

    def test_actual_tcp_rcon_wire_protocol_rejects_wrong_auth_and_truncated_response(self):
        # Сокет настоящий; тестовый сервер намеренно не является Minecraft.
        listener=socket.socket()
        listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        def serve():
            client,_=listener.accept()
            with client:
                frame=vanilla.recv_exact(client,4)
                length=struct.unpack('<i',frame)[0]
                data=vanilla.recv_exact(client,length)
                req=struct.unpack('<i',data[:4])[0]
                # Возвращайте реальный отрицательный ответ аутентификации RCON.
                client.sendall(struct.pack('<iii',10,-1,2)+b'\0\0')
            listener.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        with self.assertRaisesRegex(vanilla.Blocked,'authentication'):
            vanilla.rcon('127.0.0.1',port,'sufficientlylongsecret','list')
        thread.join(timeout=3)

    def test_real_minecraft_status_reader_checks_actual_packet_fields(self):
        listener=socket.socket()
        listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        def serve():
            client,_=listener.accept()
            with client:
                client.settimeout(3)
                handshake_size=vanilla.read_varint(client)
                vanilla.recv_exact(client,handshake_size)
                # Пакет status query 0 следует после handshake.
                query_size=vanilla.read_varint(client)
                vanilla.recv_exact(client,query_size)
                payload=json.dumps({'version':{'name':'1.21.1','protocol':767},'players':{'max':20}}).encode()
                body=vanilla.varint(0)+vanilla.varint(len(payload))+payload
                client.sendall(vanilla.varint(len(body))+body)
            listener.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        report=vanilla.status('127.0.0.1',port,'1.21.1')
        self.assertEqual(report['minecraft'],'1.21.1')
        thread.join(timeout=3)

    def test_reject_wrong_sidecar_file_and_replaced_process(self):
        jar=self.root/'sidecar.jar';jar.write_bytes(b'fake')
        with self.assertRaises(vanilla.Blocked):
            vanilla.inspect_process(os.getpid(),jar,hashlib.sha256(jar.read_bytes()).hexdigest())

if __name__=='__main__':unittest.main(verbosity=2)
