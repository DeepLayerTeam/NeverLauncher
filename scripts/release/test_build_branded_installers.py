#!/usr/bin/env python3
"""Smoke-тест действующей сборки Linux-пакета .deb с подписанной фикстурой."""

import base64
import hashlib
import json
import pathlib
import subprocess
import struct
import zlib
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = pathlib.Path(__file__).resolve().parents[2]


def art(data, suffix):
    return {
        "url": f"https://example.invalid/{suffix}",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def tiny_png():
    def chunk(kind, value):
        return struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))

class NativePackageTests(unittest.TestCase):
    def test_signed_linux_deb_builder(self):
        if sys.platform != "linux":
            self.skipTest("Debian package test requires Linux")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            pubkey = root / "root.hex"
            binpath = root / "prestarter"
            cfgpath = root / "signed.json"
            out = root / "dist"
            key = Ed25519PrivateKey.generate()
            pub = (
                key.public_key()
                .public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                .hex()
            )
            pubkey.write_text(pub)
            subprocess.run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-ldflags",
                    f"-X main.embeddedRootPublicKey={pub}",
                    "-o",
                    str(binpath),
                    "./cmd/prestarter",
                ],
                cwd=ROOT / "prestarter",
                check=True,
            )
            component = b"fake component"
            manifest = b"fake profile"
            java = b"fake java manifest"
            target = {
                "os": "linux",
                "arch": "amd64",
                "components": [
                    {"name": name, **art(component, name)}
                    for name in ("runtime", "desktop", "guard")
                ],
            }
            config = {
                "schemaVersion": "1.0",
                "projectId": "project",
                "profileId": "profile",
                "channel": "stable",
                "profilePublicKey": "aa" * 32,
                "manifest": art(manifest, "manifest"),
                "javaManifest": art(java, "java"),
                "targets": [target],
                "branding": {
                    "displayName": "Project Launcher",
                    "publisher": "Test Publisher",
                    "iconPng": base64.b64encode(tiny_png()).decode(),
                },
                "installerTargets": [
                    {
                        "os": "linux",
                        "arch": "amd64",
                        "prestarter": art(binpath.read_bytes(), "prestarter"),
                    }
                ],
            }
            payload = json.dumps(config, separators=(",", ":")).encode()
            envelope = {
                "schemaVersion": "1.0",
                "payload": base64.b64encode(payload).decode(),
                "signature": key.sign(payload).hex(),
            }
            cfgpath.write_text(json.dumps(envelope))
            script = ROOT / "scripts/release/build-branded-installers.py"
            cmd = [
                sys.executable,
                str(script),
                "--platform",
                "linux",
                "--arch",
                "amd64",
                "--project",
                "project",
                "--version",
                "0.23.9",
                "--config",
                str(cfgpath),
                "--prestarter",
                str(binpath),
                "--root-key-file",
                str(pubkey),
                "--output",
                str(out),
                "--unsigned-test",
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
            self.assertEqual(len(list(out.glob("*.deb"))), 1)
            deb = next(out.glob("*.deb"))
            subprocess.run(["dpkg-deb", "--contents", str(deb)], check=True, stdout=subprocess.PIPE)
            extracted = root / "unpacked"
            subprocess.run(["dpkg-deb", "-x", str(deb), str(extracted)], check=True)
            self.assertEqual((extracted / "usr/share/pixmaps/launcher-project.png").read_bytes(), tiny_png())
            desktop = (extracted / "usr/share/applications/launcher.desktop").read_text()
            self.assertIn("Name=Project Launcher", desktop)
            self.assertIn("Icon=launcher-project", desktop)
            bundle = extracted / "usr/lib/launcher/bundle"
            subprocess.run([str(bundle / "neverinstaller"), "verify", "--bundle", str(bundle)], check=True, stdout=subprocess.PIPE)
            # Подписанный, но недопустимый образ должен отклоняться также настоящим
            # Go-валидатором оформления, а не только проверкой подписи.
            invalid = json.loads(json.dumps(config))
            invalid["branding"]["iconPng"] = base64.b64encode(b"not png").decode()
            payload_bad = json.dumps(invalid, separators=(",", ":")).encode()
            cfgpath.write_text(json.dumps({"schemaVersion": "1.0", "payload": base64.b64encode(payload_bad).decode(), "signature": key.sign(payload_bad).hex()}))
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(p.returncode, 0, "signed invalid PNG was packaged")
            # Возобновите с корректной фикстурой для проверки подмены подписи.
            cfgpath.write_text(json.dumps(envelope))
            config["branding"]["displayName"] = "Tampered"
            payload = json.dumps(config, separators=(",", ":")).encode()
            envelope["payload"] = base64.b64encode(payload).decode()
            cfgpath.write_text(json.dumps(envelope))
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(p.returncode, 0, "tampered branded bundle was packaged")


if __name__ == "__main__":
    unittest.main()
