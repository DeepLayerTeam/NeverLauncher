#!/usr/bin/env python3
"""Regression tests; synthetic messages must never certify actual gameplay."""

import hashlib
import io
import json
import socket
import struct
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from staged_matching_0344 import (
    MatchingServer,
    GameplayObserver,
    Rcon,
    safe_bundle_extract,
    verify_matching_server,
    player_online,
    parse_position,
    parse_gametime,
    changed_position,
)

VERSION = "1.21.1"
BOOT = '[Server thread/INFO]: Starting minecraft server version 1.21.1\n[Server thread/INFO]: Done (2.11s)! For help, type "help"\n'


class MatchingValidationTests(unittest.TestCase):
    def test_no_tcp_or_join_marker_can_prove_server(self):
        for message in [
            "",
            "joined the game",
            "Listening on 127.0.0.1:25565",
            'Starting minecraft server version 1.20.1\nDone (2.1s)! For help, type "help"',
        ]:
            with self.assertRaises(RuntimeError, msg=message):
                verify_matching_server(message, VERSION, "vanilla")

    def test_real_server_boot_loader_and_bridge_are_required(self):
        self.assertTrue(verify_matching_server(BOOT, VERSION, "vanilla"))
        with self.assertRaisesRegex(RuntimeError, "loader/version"):
            verify_matching_server(BOOT, VERSION, "fabric", "0.16.10", True)
        log = (
            BOOT
            + "[INFO] Fabric Loader 0.16.10\nLauncher Fabric Server Bridge 0.34.4 enabled\n"
        )
        self.assertTrue(
            verify_matching_server(log, VERSION, "fabric", "0.16.10", True, "0.34.4")
        )
        with self.assertRaisesRegex(RuntimeError, "ServerBridge"):
            verify_matching_server(
                BOOT + "[INFO] Fabric Loader 0.16.10\n",
                VERSION,
                "fabric",
                "0.16.10",
                True,
                "0.34.4",
            )
        with self.assertRaisesRegex(RuntimeError, "fatal"):
            verify_matching_server(
                log + "Exception in server tick loop",
                VERSION,
                "fabric",
                "0.16.10",
                True,
                "0.34.4",
            )

    def test_rcon_result_requires_enumerated_online_player_and_world(self):
        self.assertFalse(player_online("Client joined the game", "NL_Cert_Client"))
        self.assertFalse(
            player_online(
                "There are 0 of a max of 20 players online:", "NL_Cert_Client"
            )
        )
        self.assertTrue(
            player_online(
                "There are 1 of a max of 20 players online: NL_Cert_Client",
                "NL_Cert_Client",
            )
        )
        self.assertFalse(
            player_online(
                "There are 1 of a max of 20 players online: NL_Cert_Client_Other",
                "NL_Cert_Client",
            )
        )
        self.assertEqual(
            parse_position(
                "NL_Cert_Client has the following entity data: [7.5d, 64.0d, -8.125d]"
            ),
            (7.5, 64, -8.125),
        )
        self.assertEqual(parse_gametime("The time is 10440"), 10440)
        self.assertFalse(changed_position((0, 64, 0), (0, 64, 0)))
        self.assertTrue(changed_position((0, 64, 0), (0, 64, -2)))
        for message in ("Player joined the game", "The time is never"):
            with self.assertRaises(RuntimeError):
                parse_gametime(message)

    def test_pinned_distribution_and_zip_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            good = root / "server.zip"
            with zipfile.ZipFile(good, "w") as archive:
                archive.writestr("server.jar", b"exact jar bytes")
            target = root / "server"
            target.mkdir()
            safe_bundle_extract(good, target)
            self.assertEqual((target / "server.jar").read_bytes(), b"exact jar bytes")
            evil = root / "evil.zip"
            with zipfile.ZipFile(evil, "w") as archive:
                archive.writestr("../escape.jar", b"bad")
            with self.assertRaises(ValueError):
                safe_bundle_extract(evil, target)
            self.assertFalse((root / "escape.jar").exists())
            srv = MatchingServer(root, "java", "nl", VERSION, "fabric", "0.16.10")
            with self.assertRaisesRegex(RuntimeError, "pinned complete server bundle"):
                srv.prepare()

    def test_missing_binaries_and_pinned_server_hash_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bundle = root / "server.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("server.jar", b"example bytes")
            srv = MatchingServer(
                root, "java", "nl", VERSION, "vanilla", "", str(bundle), "0" * 64
            )
            with self.assertRaisesRegex(ValueError, "differs from pinned"):
                srv.prepare()

    def test_fake_join_with_no_player_position_or_client_action_not_pass(self):
        class FakeServer:
            minecraft = VERSION
            loader_version = ""
            bridge_version = ""
            requires_bridge = False
            artifact_sha = "0" * 64
            port = 25565
            process = type("Process", (), {"pid": 1, "poll": lambda _: None})()
            rcon = type(
                "RconFake",
                (),
                {
                    "query": lambda _, cmd: (
                        "There are 1 of a max of 20 players online: NL_Cert_Client"
                    )
                },
            )()

            def log_text(self):
                return BOOT + "NL_Cert_Client joined the game"

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "logs").mkdir()
            (p / "logs" / "latest.log").write_text("Connecting to server")
            observer = GameplayObserver(
                FakeServer(),
                p,
                sys.executable,
                "vanilla",
                "NL_Cert_Client",
                p / "output",
                "run-01",
                0,
            )
            observer.root_pid = 1
            observer.tick()
            self.assertNotEqual(observer.status, "passed")
            self.assertFalse(observer.action_sent)
            self.assertFalse(
                observer.evidence()["serverJoinAndOnline"]
                and observer.evidence()["clientInputSent"]
            )

    def test_actual_world_observation_requires_movement_and_ticks(self):
        class FakeRcon:
            def __init__(self, movement=True):
                self.move = movement
                self.positions = 0
                self.times = 0

            def query(self, query):
                if query == "list":
                    return "There are 1 of a max of 20 players online: NL_Cert_Client"
                if query.startswith("data get entity"):
                    self.positions += 1
                    x = 0 if self.positions == 1 or not self.move else 2
                    return f"NL_Cert_Client has the following entity data: [{x}.0d, 64.0d, 0.0d]"
                if query == "time query gametime":
                    self.times += 1
                    return f"The time is {1000 + self.times * 20}"
                raise ValueError(query)

        class FakeServer:
            minecraft = VERSION
            loader_version = ""
            bridge_version = ""
            requires_bridge = False
            artifact_sha = "0" * 64
            port = 25565
            process = type("Process", (), {"pid": 1, "poll": lambda _: None})()

            def __init__(self, movement):
                self.rcon = FakeRcon(movement)

            def log_text(self):
                return BOOT + "NL_Cert_Client joined the game"

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "logs").mkdir()
            (root / "logs" / "latest.log").write_text("Connecting to server 127.0.0.1")
            for moves in (True, False):
                observer = GameplayObserver(
                    FakeServer(moves),
                    root,
                    sys.executable,
                    "vanilla",
                    "NL_Cert_Client",
                    root / ("yes" if moves else "no"),
                    "run",
                    0,
                )
                observer.root_pid = 12

                def test_cmd(args, *rest):
                    return ""

                with (
                    patch(
                        "staged_matching_0344.find_window", return_value=("0x1234", 42)
                    ),
                    patch("staged_matching_0344.command", side_effect=test_cmd),
                    patch("staged_matching_0344.time.sleep", return_value=None),
                    patch.object(
                        GameplayObserver,
                        "screenshot",
                        side_effect=lambda wid, name: name,
                    ),
                ):
                    observer.tick()
                    observer.last_probe -= 4
                    observer.action_time -= 4
                    observer.tick()
                self.assertEqual(observer.status, "passed" if moves else "pending")
                self.assertTrue(observer.joined)
                self.assertTrue(observer.action_sent)
                self.assertEqual(observer.ticks_after > observer.ticks_before, True)
                self.assertEqual(observer.first_frame != observer.last_frame, True)

    def test_real_source_rcon_auth_and_query(self):
        with socket.socket() as listen:
            listen.bind(("127.0.0.1", 0))
            listen.listen(1)
            port = listen.getsockname()[1]
            err = []

            def run():
                try:
                    conn, _ = listen.accept()
                    with conn:

                        def pkt():
                            n = struct.unpack("<i", Rcon.recv_exact(conn, 4))[0]
                            return Rcon.recv_exact(conn, n)

                        auth = pkt()
                        self.assertIn(b"password", auth)
                        conn.sendall(
                            struct.pack("<i", 10) + struct.pack("<ii", 5, 0) + b"\0\0"
                        )
                        conn.sendall(
                            struct.pack("<i", 10) + struct.pack("<ii", 5, 2) + b"\0\0"
                        )
                        query = pkt()
                        self.assertIn(b"time query gametime", query)
                        body = struct.pack("<ii", 6, 0) + b"The time is 1234\0\0"
                        conn.sendall(struct.pack("<i", len(body)) + body)
                except Exception as exc:
                    err.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            self.assertEqual(
                parse_gametime(Rcon(port, "password").query("time query gametime")),
                1234,
            )
            thread.join(2)
            self.assertFalse(err)


if __name__ == "__main__":
    unittest.main()
