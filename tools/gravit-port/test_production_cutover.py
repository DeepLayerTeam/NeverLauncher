"""Интеграционные тесты настоящего Unix-протокола HAProxy и CLI-передачи через подпроцессы.

Тестовые HAProxy и CLI являются имитациями; эти тесты не сертифицируют производственный Minecraft,
реальную транзакцию PostgreSQL или работающую установку прокси.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

spec = importlib.util.spec_from_file_location("cutover_04911", Path(__file__).with_name("production_cutover_04911.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

UUID = "12345678-1234-1234-1234-123456789abc"


def write_private(path, payload):
    path.write_bytes(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
    path.chmod(0o600)


class HAProxySocket:
    def __init__(self, path):
        self.path = str(path)
        self.stats = {
            ("auth-backend", "old-auth"): {"status": "UP", "scur": "1"},
            ("auth-backend", "new-auth"): {"status": "MAINT", "scur": "0"},
            ("game-backend", "old-game"): {"status": "UP", "scur": "1"},
            ("game-backend", "new-game"): {"status": "MAINT", "scur": "0"},
        }
        self.commands = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(12)
        self.listener.settimeout(0.25)
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                req = b""
                while not req.endswith(b"\n"):
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    req += chunk
                line = req.decode().strip()
                self.commands.append(line)
                if line == "show info":
                    response = "Pid: 4242\nVersion: 3.0\n"
                elif line == "show stat":
                    response = "# pxname,svname,status,scur,\n"
                    for (backend, server), entry in self.stats.items():
                        response += f"{backend},{server},{entry['status']},{entry['scur']},\n"
                elif line.startswith("set server "):
                    try:
                        _, _, qualified, _, state = line.split(" ")
                        backend, server = qualified.split("/")
                        entry = self.stats[(backend, server)]
                        entry["status"] = {"ready": "UP", "drain": "DRAIN", "maint": "MAINT"}[state]
                        if state == "drain":
                            entry["scur"] = "0"
                        response = "\n"
                    except Exception:
                        response = "Error: invalid server\n"
                else:
                    response = "Error: invalid command\n"
                conn.sendall(response.encode())

    def close(self):
        self.stop.set()
        self.listener.close()
        self.worker.join(timeout=2)


FAKE_CLI = '''#!/usr/bin/env python3
import json, os, sys
args = sys.argv
assert 'SECRET_SHOULD_NOT_BE_IN_ARGV' not in ' '.join(args)
assert os.getenv('LAUNCHER_TOKEN') == 'SECRET_SHOULD_NOT_BE_IN_ARGV'
command = args[3]
out = args[args.index('--output') + 1]
statefile = os.getenv('CUTOVER_TEST_STATE_FILE')
if command == 'cutover-list':
    try:
        with open(statefile) as f: active = f.read() == 'active'
    except FileNotFoundError: active = False
    doc = {'data': [{'runId':'run_12345678', 'profileId':'main', 'channel':'stable', 'stageId':'stage_12345678', 'releaseId':'release-abc', 'revision': 4 if active else 3, 'state':'active' if active else 'staged', 'activatedRevision': 9 if active else None, 'targetDigest': 'd'*64, 'baselineRevision': 8}]}
elif command == 'cutover-activate':
    with open(statefile, 'w') as f: f.write('active')
    doc = {'data': {'state': 'active'}}
elif command == 'rehearse-local':
    doc = {'data': {'ready': False, 'cutoverAllowed': False, 'liveSession': {'joinedAt':'2026-11-02T00:00:00Z','playerUuid':'12345678-1234-1234-1234-123456789abc','clientSha256':'a'*64}, 'probes': [{'name':n,'passed':True,'evidenceSha256':'b'*64} for n in ('launch','login','join','skins','loader','optional','admin')]}}
else: sys.exit(8)
with open(out,'x') as f: json.dump(doc,f)
'''


class CutoverTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.journal = self.root / "journal"
        self.journal.mkdir(mode=0o700)
        self.haproxy = HAProxySocket(self.root / "haproxy.sock")
        self.addCleanup(self.haproxy.close)
        self.launcher = self.root / "launcher"
        write_private(self.launcher, FAKE_CLI.encode())
        self.launcher.chmod(0o700)
        self.canary = self.root / "auth-request.json"
        write_private(self.canary, b'{"user":"cutover-test"}')
        self.live_config = self.root / "live-session.json"
        write_private(self.live_config, {"clientArgs": ["--server", "play.example.org:25565"]})
        self.statefile = self.root / "cli-state"
        self.config = {
            "format": mod.FORMAT, "runId": "run_12345678", "profileId": "main", "channel": "stable",
            "stageId": "stage_12345678", "releaseId": "release-abc", "expectedRevision": 3,
            "backend": "https://localhost:9443", "launcher": str(self.launcher),
            "launcherSha256": hashlib.sha256(self.launcher.read_bytes()).hexdigest(),
            "proxySocket": self.haproxy.path, "inventorySha256": "b"*64,
            "postSwitchStage": str(self.root), "gamePublicAddress": "play.example.org:25565", "sourceSnapshotSha256": "c"*64, "targetDigest": "d"*64, "baselineRevision": 8,
            "routes": {
                "auth": {"backend": "auth-backend", "source": "old-auth", "target": "new-auth"},
                "game": {"backend": "game-backend", "source": "old-game", "target": "new-game"}},
            "drainSeconds": 5,
            "authCanary": {"url":"https://localhost:9444/login", "frontendUrl":"https://play.example.org/auth/login", "method":"POST", "requestBodyFile": str(self.canary), "expectedPlayerUuid": UUID, "uuidJSONField": "uuid", "requestSha256": hashlib.sha256(self.canary.read_bytes()).hexdigest()}}
        self.config_file = self.root / "config.json"
        self.save_config()
        self.env = patch.dict(os.environ, {"LAUNCHER_TOKEN": "SECRET_SHOULD_NOT_BE_IN_ARGV", "CUTOVER_TEST_STATE_FILE": str(self.statefile)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def save_config(self):
        write_private(self.config_file, self.config)

    def prepare(self):
        self.assertEqual(mod.main(["prepare", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 0)

    def proof(self, *, stale=False):
        at = datetime.now(timezone.utc)
        if stale:
            from datetime import timedelta
            at -= timedelta(minutes=30)
        receipt = {"format": "never/gravit-source-stop/v1", "runId": "run_12345678", "profileId": "main",
                   "channel":"stable", "stageId":"stage_12345678", "unitState":"inactive", "unitFileState":"masked-runtime",
                   "snapshotSha256":"c"*64, "checkedAt":at.isoformat(), "stoppedAt":at.isoformat()}
        path = self.root / "fence.json"
        write_private(path, receipt)
        self.config["fenceReceipt"] = str(path)
        self.save_config()
        # Предварительная конфигурация неизменна между фазами. Укажите путь квитанции заранее.
        return path

    def test_real_socket_drains_auth_and_game_before_closing(self):
        self.prepare()
        state = mod.load_phase(self.journal, hashlib.sha256(self.config_file.read_bytes()).hexdigest())
        self.assertEqual(state["phase"], "traffic_fenced")
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")
        self.assertIn("set server auth-backend/old-auth state drain", self.haproxy.commands)
        self.assertIn("set server game-backend/old-game state maint", self.haproxy.commands)
        self.assertFalse(state["trafficOpen"])

    def test_two_phase_real_cli_subprocess_and_postjoin_success(self):
        # Путь квитанции должен быть включён ДО prepare; позднее байты менять нельзя.
        self.proof()
        self.prepare()
        with patch.object(mod, "auth_canary") as auth_check:
            self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 0)
            self.assertEqual(auth_check.call_count, 2)
        state = mod.load_phase(self.journal, hashlib.sha256(self.config_file.read_bytes()).hexdigest())
        self.assertTrue(state["backendRouteActive"] and state["trafficOpen"])
        self.assertEqual(state["phase"], "complete")
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "open")
        self.assertTrue(self.statefile.exists())

    def test_minecraft_join_failure_closes_both_new_servers_after_db_commit(self):
        self.proof()
        self.prepare()
        with patch.object(mod, "auth_canary"), patch.object(mod, "live_canary", side_effect=mod.Blocked("join failed")):
            self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")
        state = mod.load_phase(self.journal, hashlib.sha256(self.config_file.read_bytes()).hexdigest())
        self.assertEqual(state["phase"], "blocked")
        self.assertTrue(state["backendRouteActive"])
        self.assertFalse(state["trafficOpen"])
        self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)

    def test_stale_fence_and_config_changes_never_switch(self):
        self.proof(stale=True)
        self.prepare()
        self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.assertFalse(self.statefile.exists())
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")
        self.config["releaseId"] = "another-release"
        self.save_config()
        self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)

    def test_third_active_haproxy_server_blocks_prepare(self):
        self.haproxy.stats[("auth-backend", "shadow-auth")] = {"status":"UP", "scur":"0"}
        self.assertEqual(mod.main(["prepare", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.assertFalse((self.journal / "cutover-state.json").exists())

    def test_unverified_auth_canary_does_not_open_traffic(self):
        self.proof()
        self.prepare()
        with patch.object(mod, "auth_canary", side_effect=mod.Blocked("login failed")):
            self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.assertFalse(self.statefile.exists())
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")

    def test_public_auth_canary_failure_after_route_open_closes_ingress(self):
        self.proof()
        self.prepare()
        def check(_cfg, *, public=False):
            if public:
                raise mod.Blocked("front-door authentication failed")
        with patch.object(mod, "auth_canary", side_effect=check):
            self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")
        state = mod.load_phase(self.journal, hashlib.sha256(self.config_file.read_bytes()).hexdigest())
        self.assertEqual(state["phase"], "blocked")
        self.assertTrue(state["backendRouteActive"])
        self.assertFalse(state["trafficOpen"])

    def test_haproxy_restart_between_phases_blocks_activation(self):
        self.proof()
        self.prepare()
        original = mod.Proxy.instance
        with patch.object(mod.Proxy, "instance", return_value="9999"):
            self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.assertFalse(self.statefile.exists())
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")

    def test_changed_canary_payload_blocks_authorization(self):
        self.proof()
        self.prepare()
        write_private(self.canary, b'{"user":"different"}')
        self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.assertFalse(self.statefile.exists())
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")

    def test_missing_token_private_files_and_duplicate_backends_fail(self):
        with patch.dict(os.environ, {"LAUNCHER_TOKEN": ""}):
            self.assertEqual(mod.main(["prepare", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.config_file.chmod(0o644)
        self.assertEqual(mod.main(["prepare", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
        self.save_config()
        self.config["routes"]["game"]["backend"] = "auth-backend"
        self.save_config()
        self.assertEqual(mod.main(["prepare", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)

    def test_route_drift_before_activation(self):
        self.proof()
        self.prepare()
        self.statefile.write_text("active")
        with patch.object(mod, "auth_canary") as auth:
            self.assertEqual(mod.main(["activate", "--config", str(self.config_file), "--journal-dir", str(self.journal), "--confirm", "run_12345678"]), 2)
            auth.assert_not_called()
        mod.inspect_proxy(mod.Proxy(self.haproxy.path), self.config, "closed")


if __name__ == "__main__":
    unittest.main()
