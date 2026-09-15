#!/usr/bin/env python3
"""Minimal Minecraft Java login probe used for bridge revoke/deny coverage.

The primary release gate launches the actual Mojang client. This probe is
kept only for fast protocol-level Velocity/Paper/Purpur checks after session
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
        try:
            response = sock.recv(4096)
        except socket.timeout:
            response = b""
    print(f"probe host={args.host} port={args.port} username={args.username} responseBytes={len(response)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
