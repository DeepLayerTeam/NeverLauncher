#!/usr/bin/env python3
"""Publish a materialized Never client package through the canonical admin API.

The script is intentionally E2E-oriented: every local file is re-hashed before
upload, every backend response hash/size is compared with the package manifest,
and the release is published only after all artifacts and runtime settings have
been accepted by the Backend API.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import mimetypes
import os
from pathlib import Path
import secrets
import sys
from urllib.parse import quote, urlsplit


class APIClient:
    def __init__(self, base_url: str, token: str) -> None:
        parsed = urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("--api must be an absolute http(s) URL")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port
        self.base_path = parsed.path.rstrip("/")
        self.token = token
        self.conn: http.client.HTTPConnection | None = None

    def _connect(self) -> http.client.HTTPConnection:
        if self.conn is None:
            cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
            self.conn = cls(self.host, self.port, timeout=120)
        return self.conn

    def _request(self, method: str, path: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, bytes]:
        merged = {"Authorization": f"Bearer {self.token}", "User-Agent": "NeverLauncher-E2E/0.10.6", **headers}
        request_path = self.base_path + path
        for attempt in range(2):
            conn = self._connect()
            try:
                conn.request(method, request_path, body=body, headers=merged)
                response = conn.getresponse()
                payload = response.read()
                if response.getheader("Connection", "").lower() == "close":
                    self.conn = None
                return response.status, payload
            except (ConnectionError, OSError, http.client.HTTPException):
                try:
                    conn.close()
                except Exception:
                    pass
                self.conn = None
                if attempt:
                    raise
        raise RuntimeError("unreachable")

    def json(self, method: str, path: str, payload: object | None = None) -> object:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        status, raw = self._request(method, path, body, {"Content-Type": "application/json"})
        if status < 200 or status >= 300:
            raise RuntimeError(f"{method} {path} => HTTP {status}: {raw.decode(errors='replace')}")
        return json.loads(raw or b"{}")

    def upload(self, path: str, local_file: Path, expected_sha256: str, expected_size: int, executable: bool, target_os: list[str]) -> object:
        boundary = "----neverlauncher-e2e-" + secrets.token_hex(16)
        filename = local_file.name
        content = local_file.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual.lower() != expected_sha256.lower() or len(content) != expected_size:
            raise RuntimeError(f"local package file changed before upload: {path}")
        parts: list[bytes] = []

        def field(name: str, value: str) -> None:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())

        field("path", path)
        field("executable", "true" if executable else "false")
        for os_name in target_os:
            field("targetOs", os_name)
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename.replace(chr(34), '')}\"\r\nContent-Type: {mime}\r\n\r\n".encode()
            + content
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        if not self.project_id or not self.package_id:
            raise RuntimeError("upload target is not initialized")
        endpoint = f"/api/v1/admin/projects/{quote(self.project_id, safe='')}/versions/{quote(self.package_id, safe='')}/files"
        status, raw = self._request("POST", endpoint, body, {"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))})
        if status < 200 or status >= 300:
            raise RuntimeError(f"upload {path} => HTTP {status}: {raw.decode(errors='replace')}")
        parsed = json.loads(raw)
        file_info = parsed.get("data", {}).get("file", parsed)
        remote_sha = str(file_info.get("sha256", ""))
        remote_size = int(file_info.get("size", -1))
        if remote_sha.lower() != expected_sha256.lower() or remote_size != expected_size:
            raise RuntimeError(f"backend checksum mismatch after upload: {path}")
        return parsed

    project_id = ""
    package_id = ""


def safe_local(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or not relative or "\\" in relative:
        raise RuntimeError(f"unsafe package path: {relative!r}")
    resolved_root = root.resolve(strict=True)
    lexical = root
    for part in rel.parts:
        lexical = lexical / part
        if lexical.is_symlink():
            raise RuntimeError(f"symlink package path is forbidden: {relative!r}")
    candidate = (root / rel).resolve(strict=True)
    if candidate == resolved_root or resolved_root not in candidate.parents:
        raise RuntimeError(f"package path escapes client root or resolves to root: {relative!r}")
    if not candidate.is_file():
        raise RuntimeError(f"package path is not a regular file: {relative!r}")
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--client-dir", required=True, type=Path)
    parser.add_argument("--quick-play", default="")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    wrapper = json.loads(args.package.read_text())
    manifest = wrapper.get("manifest")
    settings = wrapper.get("manifestSettings")
    if not isinstance(manifest, dict) or not isinstance(settings, dict):
        raise RuntimeError("client package must contain manifest and manifestSettings")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("client package does not contain files")
    if args.quick_play:
        minecraft = settings.setdefault("minecraft", {})
        game_args = list(minecraft.get("gameArgs") or [])
        game_args += ["--quickPlayMultiplayer", args.quick_play]
        minecraft["gameArgs"] = game_args
    runtime = settings.setdefault("runtime", {})
    runtime.setdefault("memory", {"minimumMb": 512, "recommendedMb": 1024, "maximumMb": 1536})

    project = str(manifest["projectId"])
    profile = str(manifest["profileId"])
    channel = str(manifest["channel"])
    version = str(manifest["version"])
    client = APIClient(args.api, args.token)

    created = client.json("POST", f"/api/v1/admin/projects/{quote(project, safe='')}/versions", {
        "profileId": profile,
        "channel": channel,
        "version": version,
    })
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError(f"version create response does not contain id: {created!r}")
    version_id = str(created["id"])
    client.project_id = project
    client.package_id = version_id

    client.json("PUT", f"/api/v1/admin/projects/{quote(project, safe='')}/versions/{quote(version_id, safe='')}/manifest", settings)

    total = len(files)
    total_bytes = 0
    for index, item in enumerate(files, 1):
        if not isinstance(item, dict):
            raise RuntimeError("invalid file entry")
        relative = str(item["path"])
        expected_sha = str(item["sha256"])
        expected_size = int(item["size"])
        local_file = safe_local(args.client_dir, relative)
        if not local_file.is_file():
            raise RuntimeError(f"package file missing: {relative}")
        client.upload(relative, local_file, expected_sha, expected_size, bool(item.get("executable", False)), list(item.get("targetOs") or []))
        total_bytes += expected_size
        if index == 1 or index % 250 == 0 or index == total:
            print(f"[e2e-upload] {index}/{total} files, {total_bytes} bytes", file=sys.stderr, flush=True)

    published = client.json("POST", f"/api/v1/admin/projects/{quote(project, safe='')}/versions/{quote(version_id, safe='')}/publish")
    manifest_url = f"{args.api.rstrip('/')}/api/v1/projects/{quote(project, safe='')}/profiles/{quote(profile, safe='')}/manifest?channel={quote(channel, safe='')}"
    result = {
        "status": "published",
        "projectId": project,
        "profileId": profile,
        "channel": channel,
        "version": version,
        "versionId": version_id,
        "files": total,
        "bytes": total_bytes,
        "manifestUrl": manifest_url,
        "release": published,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
