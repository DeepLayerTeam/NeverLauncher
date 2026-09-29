#!/usr/bin/env python3
"""Minimal Minecraft Java login probe used for bridge revoke/deny coverage.

The primary release gate launches the actual Mojang client. This probe is
kept only for fast protocol-level Velocity/Bukkit-family checks after session
revocation; it is not accepted as evidence of Minecraft client compatibility.
"""
from __future__ import annotations

import argparse
import socket
import struct
import uuid


def varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)


def mc_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return varint(len(raw)) + raw


def packet(payload: bytes) -> bytes:
    return varint(len(payload)) + payload


def offline_uuid(name: str) -> uuid.UUID:
    # Equivalent shape to Java's nameUUIDFromBytes for OfflinePlayer:<name>.
    import hashlib
    digest = bytearray(hashlib.md5(("OfflinePlayer:" + name).encode("utf-8")).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(digest))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--protocol", type=int, default=767, help="Minecraft 1.21.1 protocol")
    args = parser.parse_args()
    if not (3 <= len(args.username) <= 16) or not all(c.isalnum() or c == "_" for c in args.username):
        raise SystemExit("username must match Minecraft Java rules: 3-16 [A-Za-z0-9_]")

    handshake = (
        varint(0x00)
        + varint(args.protocol)
        + mc_string(args.host)
        + struct.pack(">H", args.port)
        + varint(2)
    )
    login_start = varint(0x00) + mc_string(args.username) + offline_uuid(args.username).bytes

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.settimeout(3)
        sock.sendall(packet(handshake))
        sock.sendall(packet(login_start))
        terminal = "response"
        try:
            response = sock.recv(4096)
            if not response:
                terminal = "eof"
        except socket.timeout:
            # The probe is only a login stimulus. The bridge decision is asserted
            # by the mandatory neverlauncher.join.allowed/denied log checks in
            # run-minecraft-e2e.sh, so a peer that keeps the socket open without
            # replying is a valid transport-level outcome here.
            response = b""
            terminal = "timeout"
        except ConnectionResetError:
            # Velocity/Bukkit-family runtimes may abort the intentionally
            # incomplete login exchange with TCP RST after consuming the login
            # stimulus. Treat only this post-send recv reset as terminal I/O;
            # connect/send failures remain fatal and the functional/security
            # result is still required from bridge allow/deny evidence.
            response = b""
            terminal = "reset"
    print(
        f"probe host={args.host} port={args.port} username={args.username} "
        f"responseBytes={len(response)} terminal={terminal}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
