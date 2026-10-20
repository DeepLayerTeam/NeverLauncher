#!/usr/bin/env python3
"""Deterministic loopback HTTP fault injector for real runtime / bootstrap tests.

Routes are deliberately restricted to pre-seeded in-memory objects. No remote
fetch, external listener, user supplied filesystem reads, or test-only bypass of
runtime verification. Each request is captured for transferable byte accounting.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
import time
from urllib.parse import urlsplit
from typing import Callable


@dataclass
class Object:
    data: bytes
    etag: str = '"fixture-v1"'
    delay: float = 0.0
    behavior: str = "ok"  # ok, truncate-once, bad-range, changed-once, 416-once,
                              # 429-once, 429-date-once, 503-once, poison
    hits: int = 0
    active: int = 0
    max_active: int = 0
    lock: Lock = field(default_factory=Lock, repr=False)


class FaultServer:
    def __init__(self, objects: dict[str, Object]):
        if not objects or any(not p.startswith("/") or ".." in p for p in objects):
            raise ValueError("objects must have safe absolute URL paths")
        self.objects = objects
        self.requests: list[dict] = []
        self.active_requests = 0
        self.max_active_requests = 0
        self.lock = Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                obj = outer.objects.get(path)
                if obj is None:
                    return self.send_body(404, b"not found")
                with obj.lock:
                    obj.hits += 1
                    ordinal = obj.hits
                    obj.active += 1
                    obj.max_active = max(obj.max_active, obj.active)
                with outer.lock:
                    outer.active_requests += 1
                    outer.max_active_requests = max(outer.max_active_requests, outer.active_requests)
                start = time.monotonic_ns()
                wire = 0
                code = 0
                try:
                    data, etag = obj.data, obj.etag
                    if obj.delay:
                        time.sleep(obj.delay)
                    fault = obj.behavior if ordinal == 1 else "ok"
                    if fault == "poison":
                        data = bytes((x ^ 0xFF) for x in data)
                    if fault in {"429-once", "429-date-once", "503-once"}:
                        code = 429 if fault.startswith("429") else 503
                        headers = {"Retry-After": "0" if fault == "429-once" else "Thu, 01 Jan 1970 00:00:00 GMT"}
                        self.send_body(code, b"", headers)
                        return
                    requested = self.headers.get("Range")
                    if fault == "416-once":
                        code = 416
                        self.send_body(416, b"", {"Content-Range": f"bytes */{len(data)}"})
                        return
                    offset = 0
                    if requested:
                        if not requested.startswith("bytes=") or not requested.endswith("-"):
                            code = 416
                            self.send_body(416, b"", {"Content-Range": f"bytes */{len(data)}"})
                            return
                        try:
                            offset = int(requested[6:-1])
                        except ValueError:
                            code = 416
                            self.send_body(416, b"")
                            return
                        if self.headers.get("If-Range") != etag and self.headers.get("If-Range"):
                            offset = 0  # validator changed; return a full 200
                        if offset >= len(data):
                            code = 416
                            self.send_body(416, b"", {"Content-Range": f"bytes */{len(data)}"})
                            return
                    headers = {"ETag": etag, "Accept-Ranges": "bytes"}
                    code = 206 if offset else 200
                    body = data[offset:]
                    if offset:
                        headers["Content-Range"] = f"bytes {offset}-{len(data)-1}/{len(data)}"
                    if fault == "bad-range":
                        code = 206
                        headers["Content-Range"] = f"bytes 1-{len(data)}/{len(data)+1}"
                    if fault == "changed-once":
                        headers["ETag"] = '"unexpected-object"'
                    self.send_response(code)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close" if fault == "truncate-once" else "keep-alive")
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    if fault == "truncate-once":
                        chunk = body[:max(1, len(body)//2)]
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        wire += len(chunk)
                        self.close_connection = True
                        self.connection.shutdown(1)
                    else:
                        self.wfile.write(body)
                        self.wfile.flush()
                        wire += len(body)
                except (BrokenPipeError, ConnectionError, OSError):
                    pass
                finally:
                    with obj.lock:
                        obj.active -= 1
                    with outer.lock:
                        outer.active_requests -= 1
                        outer.requests.append({"path": path, "status": code,
                          "range": self.headers.get("Range"), "ifRange": self.headers.get("If-Range"),
                          "wireBytes": wire, "durationNs": time.monotonic_ns()-start})

            def send_body(self, status, data, headers=None):
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if data:
                    self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread: Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def start(self):
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()

    def metrics(self) -> dict:
        with self.lock:
            requests = list(self.requests)
            peak = self.max_active_requests
        return {"requests": requests, "maxActiveOverall":peak, "transferredBytes": sum(x["wireBytes"] for x in requests),
                "maxActiveByObject": {k: v.max_active for k, v in self.objects.items()}}
