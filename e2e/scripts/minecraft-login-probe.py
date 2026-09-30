#!/usr/bin/env python3
"""Minimal Minecraft Java login probe used for bridge allow/revoke/deny coverage.

The primary release gate launches the actual Mojang client. This probe is
kept only for fast protocol-level bridge checks after session issuance or
revocation; it is not accepted as evidence of Minecraft client compatibility.

Forge runs its pre-world NeverLauncher gate in Minecraft's CONFIGURATION
phase. --enter-configuration performs the minimum protocol transition needed
to reach that phase while intentionally stopping before PLAY.
"""
from __future__ import annotations

import argparse
import socket
import struct
import time
import uuid
import zlib


LOGIN_DISCONNECT = 0x00
LOGIN_ENCRYPTION_REQUEST = 0x01
LOGIN_SUCCESS = 0x02
LOGIN_SET_COMPRESSION = 0x03
LOGIN_CUSTOM_QUERY = 0x04
LOGIN_COOKIE_REQUEST = 0x05

SERVERBOUND_LOGIN_CUSTOM_QUERY_ANSWER = 0x02
SERVERBOUND_LOGIN_ACKNOWLEDGED = 0x03
MAX_PACKET_LENGTH = 8 * 1024 * 1024


class ProtocolError(RuntimeError):
    pass


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


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    for index in range(5):
        pos = offset + index
        if pos >= len(data):
            raise ProtocolError("truncated VarInt")
        byte = data[pos]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, pos + 1
    raise ProtocolError("VarInt exceeds 5 bytes")


def read_varint(sock: socket.socket) -> int:
    value = 0
    for index in range(5):
        raw = sock.recv(1)
        if not raw:
            raise EOFError("peer closed while reading VarInt")
        byte = raw[0]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value
    raise ProtocolError("VarInt exceeds 5 bytes")


def read_exact(sock: socket.socket, length: int) -> bytes:
    if length < 0 or length > MAX_PACKET_LENGTH:
        raise ProtocolError(f"invalid packet length: {length}")
    out = bytearray()
    while len(out) < length:
        chunk = sock.recv(length - len(out))
        if not chunk:
            raise EOFError("peer closed while reading packet")
        out.extend(chunk)
    return bytes(out)


def mc_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return varint(len(raw)) + raw


def packet(payload: bytes) -> bytes:
    return varint(len(payload)) + payload


def framed_packet(payload: bytes, compression_threshold: int | None) -> bytes:
    if compression_threshold is None:
        return packet(payload)
    if compression_threshold < 0:
        raise ProtocolError(f"invalid compression threshold: {compression_threshold}")
    if len(payload) >= compression_threshold:
        compressed = zlib.compress(payload)
        body = varint(len(payload)) + compressed
    else:
        body = varint(0) + payload
    return packet(body)


def receive_packet(sock: socket.socket, compression_threshold: int | None) -> tuple[int, bytes, int]:
    frame_length = read_varint(sock)
    frame = read_exact(sock, frame_length)
    wire_bytes = len(varint(frame_length)) + frame_length

    if compression_threshold is None:
        payload = frame
    else:
        data_length, offset = decode_varint(frame)
        encoded = frame[offset:]
        if data_length == 0:
            payload = encoded
        else:
            if data_length < compression_threshold:
                raise ProtocolError(
                    f"compressed packet declared {data_length} bytes below threshold {compression_threshold}"
                )
            try:
                payload = zlib.decompress(encoded)
            except zlib.error as exc:
                raise ProtocolError(f"invalid compressed Minecraft packet: {exc}") from exc
            if len(payload) != data_length:
                raise ProtocolError(
                    f"decompressed packet length mismatch: expected {data_length}, got {len(payload)}"
                )

    packet_id, offset = decode_varint(payload)
    return packet_id, payload[offset:], wire_bytes


def send_protocol_packet(sock: socket.socket, payload: bytes, compression_threshold: int | None) -> None:
    sock.sendall(framed_packet(payload, compression_threshold))


def offline_uuid(name: str) -> uuid.UUID:
    # Equivalent shape to Java's nameUUIDFromBytes for OfflinePlayer:<name>.
    import hashlib
    digest = bytearray(hashlib.md5(("OfflinePlayer:" + name).encode("utf-8")).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(digest))


def enter_configuration(
    sock: socket.socket,
    login_timeout_seconds: float,
    allow_pre_configuration_disconnect: bool = False,
) -> tuple[int, int | None, int, str]:
    deadline = time.monotonic() + login_timeout_seconds
    compression_threshold: int | None = None
    packets_seen = 0
    wire_bytes = 0

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError("timed out before Login Finished")
        sock.settimeout(min(remaining, 2.0))
        try:
            packet_id, payload, received = receive_packet(sock, compression_threshold)
        except socket.timeout:
            continue
        except EOFError:
            if allow_pre_configuration_disconnect:
                return packets_seen, compression_threshold, wire_bytes, "login-eof"
            raise
        except ConnectionResetError:
            if allow_pre_configuration_disconnect:
                return packets_seen, compression_threshold, wire_bytes, "login-reset"
            raise
        packets_seen += 1
        wire_bytes += received

        if packet_id == LOGIN_DISCONNECT:
            if allow_pre_configuration_disconnect:
                return packets_seen, compression_threshold, wire_bytes, "login-disconnect"
            raise ProtocolError("server disconnected before CONFIGURATION")
        if packet_id == LOGIN_ENCRYPTION_REQUEST:
            raise ProtocolError("server requested online-mode encryption; E2E probe requires offline-mode runtime")
        if packet_id == LOGIN_SET_COMPRESSION:
            threshold, offset = decode_varint(payload)
            if offset != len(payload):
                raise ProtocolError("unexpected trailing bytes in Set Compression")
            compression_threshold = threshold
            continue
        if packet_id == LOGIN_CUSTOM_QUERY:
            transaction_id, _ = decode_varint(payload)
            # A null custom-query response identifies this as a vanilla client.
            # FriendlyByteBuf.writeNullable encodes null as a single false byte.
            response = varint(SERVERBOUND_LOGIN_CUSTOM_QUERY_ANSWER) + varint(transaction_id) + b"\x00"
            send_protocol_packet(sock, response, compression_threshold)
            continue
        if packet_id == LOGIN_COOKIE_REQUEST:
            # No E2E runtime currently requests cookies during login. Failing
            # closed here prevents silently claiming CONFIGURATION coverage if
            # the protocol gains a prerequisite that this probe does not honor.
            raise ProtocolError("server requested an unsupported login cookie")
        if packet_id == LOGIN_SUCCESS:
            acknowledgement = varint(SERVERBOUND_LOGIN_ACKNOWLEDGED)
            send_protocol_packet(sock, acknowledgement, compression_threshold)
            return packets_seen, compression_threshold, wire_bytes, "configuration"

        raise ProtocolError(f"unexpected login packet id 0x{packet_id:02x}")


def hold_configuration_socket(sock: socket.socket, seconds: float) -> tuple[str, int]:
    deadline = time.monotonic() + max(0.0, seconds)
    drained = 0
    while time.monotonic() < deadline:
        sock.settimeout(min(0.5, max(0.01, deadline - time.monotonic())))
        try:
            chunk = sock.recv(65536)
            if not chunk:
                return "configuration-eof", drained
            drained += len(chunk)
        except socket.timeout:
            continue
        except ConnectionResetError:
            return "configuration-reset", drained
    return "configuration-hold", drained


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--protocol", type=int, default=767, help="Minecraft 1.21.1 protocol")
    parser.add_argument(
        "--enter-configuration",
        action="store_true",
        help="complete LOGIN through Login Acknowledged and hold CONFIGURATION open",
    )
    parser.add_argument("--login-timeout-seconds", type=float, default=8.0)
    parser.add_argument("--configuration-hold-seconds", type=float, default=8.0)
    parser.add_argument(
        "--allow-pre-configuration-disconnect",
        action="store_true",
        help=(
            "treat LOGIN disconnect/EOF/reset before Login Acknowledged as a successful "
            "transport terminal; callers must still assert the NeverLauncher deny marker"
        ),
    )
    args = parser.parse_args()
    if not (3 <= len(args.username) <= 16) or not all(c.isalnum() or c == "_" for c in args.username):
        raise SystemExit("username must match Minecraft Java rules: 3-16 [A-Za-z0-9_]")
    if args.login_timeout_seconds <= 0:
        raise SystemExit("--login-timeout-seconds must be positive")
    if args.configuration_hold_seconds < 0:
        raise SystemExit("--configuration-hold-seconds cannot be negative")

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

        if args.enter_configuration:
            try:
                packets_seen, compression_threshold, login_wire_bytes, login_terminal = enter_configuration(
                    sock,
                    args.login_timeout_seconds,
                    args.allow_pre_configuration_disconnect,
                )
                if login_terminal == "configuration":
                    terminal, configuration_bytes = hold_configuration_socket(
                        sock, args.configuration_hold_seconds
                    )
                    login_acknowledged = True
                else:
                    terminal = login_terminal
                    configuration_bytes = 0
                    login_acknowledged = False
            except (EOFError, socket.timeout, ConnectionResetError, ProtocolError) as exc:
                raise SystemExit(f"configuration login probe failed: {exc}") from exc
            print(
                f"probe host={args.host} port={args.port} username={args.username} "
                f"mode=configuration loginAcknowledged={str(login_acknowledged).lower()} packetsSeen={packets_seen} "
                f"compressionThreshold={compression_threshold if compression_threshold is not None else 'disabled'} "
                f"loginWireBytes={login_wire_bytes} configurationBytes={configuration_bytes} terminal={terminal}"
            )
            return 0

        terminal = "response"
        try:
            response = sock.recv(4096)
            if not response:
                terminal = "eof"
        except socket.timeout:
            # The default probe is only a login stimulus. The bridge decision is
            # asserted by mandatory NeverLauncher allow/deny log checks.
            response = b""
            terminal = "timeout"
        except ConnectionResetError:
            # Proxy/Bukkit-family runtimes may abort the intentionally
            # incomplete login exchange with TCP RST after consuming the login
            # stimulus. Connect/send failures remain fatal.
            response = b""
            terminal = "reset"
    print(
        f"probe host={args.host} port={args.port} username={args.username} "
        f"responseBytes={len(response)} terminal={terminal}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
