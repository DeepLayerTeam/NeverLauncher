#!/usr/bin/env python3
"""Задержать рукопожатие мультиплеера 1.17.1, пока настоящий клиент не построит атлас блоков.

Это TCP-перенаправитель только для localhost с передачей байтов без изменений, а не имитация клиента
или обход сертификации. Сервер обязан зафиксировать настоящий вход игрока, Runtime — оставаться
работоспособным, а свидетельства — доказывать открытие шлюза.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import select
import socket
import sys
import tempfile
import time

ATLAS_READY = re.compile(
    rb"Created:\s*\d+x\d+x\d+\s+minecraft:textures/atlas/blocks\.png-atlas"
)
MAX_READ_BYTES = 256 * 1024


def write_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".resource-ready-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atlas_ready(logs: Path) -> bool:
    if not logs.is_dir() or logs.is_symlink():
        return False
    # Проверяйте только журналы, созданные под этим изолированным корнем сертификации.
    for path in logs.glob("runtime-vanilla-certification-1.17.1-*.log"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - MAX_READ_BYTES))
            if ATLAS_READY.search(stream.read(MAX_READ_BYTES)):
                return True
    return False


def serve(args: argparse.Namespace) -> None:
    if not (1 <= args.backend_port <= 65535) or not (0 <= args.listen_port <= 65535):
        raise ValueError("Недопустимый порт")
    evidence = {
        "schemaVersion": "1.0",
        "status": "failed",
        "backendHost": "127.0.0.1",
        "backendPort": args.backend_port,
        "listenHost": "127.0.0.1",
        "listenPort": 0,
        "resourceGate": "minecraft:textures/atlas/blocks.png-atlas",
        "atlasReady": False,
        "backendConnected": False,
    }

    def report() -> None:
        write_atomic(args.evidence, json.dumps(evidence, sort_keys=True) + "\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.listen_port))
        listener.listen(1)
        listener.settimeout(args.timeout)
        evidence["listenPort"] = listener.getsockname()[1]
        report()
        write_atomic(args.port_file, str(evidence["listenPort"]) + "\n")
        try:
            client, _ = listener.accept()
        except socket.timeout:
            evidence["reason"] = "Ни один настоящий клиент Minecraft не подключился"
            report()
            raise TimeoutError(evidence["reason"])
        with client:
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                if atlas_ready(args.logs):
                    evidence["atlasReady"] = True
                    break
                time.sleep(0.15)
            if not evidence["atlasReady"]:
                evidence["reason"] = (
                    "Атлас текстур блоков Minecraft не был подготовлен к установленному сроку"
                )
                report()
                raise TimeoutError(evidence["reason"])
            # Ни один игровой пакет не должен дойти до настоящего сервера Mojang, пока реальный
            # клиент не запишет проверенный маркер создания атласа.
            try:
                upstream = socket.create_connection(
                    ("127.0.0.1", args.backend_port), timeout=5
                )
            except OSError:
                evidence["reason"] = "Не удалось установить соединение с настоящим сервером для проверки совместимости"
                report()
                raise
            with upstream:
                evidence["backendConnected"] = True
                evidence["status"] = "released"
                report()
                client.settimeout(None)
                upstream.settimeout(None)
                sockets = (client, upstream)
                while True:
                    readable, _, _ = select.select(sockets, [], [], 3)
                    if not readable:
                        continue
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        destination = upstream if source is client else client
                        destination.sendall(data)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--listen-port", type=int, default=0)
    p.add_argument("--backend-port", type=int, required=True)
    p.add_argument("--logs", type=Path, required=True)
    p.add_argument("--port-file", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=45)
    args = p.parse_args()
    try:
        serve(args)
        return 0
    except (OSError, TimeoutError, ValueError) as exc:
        # Никаких сырых данных клиента, токенов, стеков исключений или путей.
        print(f"[Прокси проверки готовности ресурсов 1.17.1] {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
