#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

API = "https://api.adoptium.net/v3"
MAX_ARCHIVE = 1_500_000_000
MAX_JAVA_BINARY = 256 * 1024 * 1024
USER_AGENT = "NeverLauncher ManagedJRE/0.15.5"
TARGETS = (
    ("windows", "x64", "windows", "x64", "zip"),
    ("windows", "arm64", "windows", "aarch64", "zip"),
    ("linux", "x64", "linux", "x64", "tar.gz"),
    ("linux", "arm64", "linux", "aarch64", "tar.gz"),
    ("macos", "x64", "mac", "x64", "tar.gz"),
    ("macos", "arm64", "mac", "aarch64", "tar.gz"),
)


def die(message: str) -> None:
    raise RuntimeError(message)


def canonical_sha256(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        die(f"invalid SHA-256: {value!r}")
    return value


def https_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        die(f"HTTPS URL required: {value!r}")
    return value


def request_json(url: str) -> object:
    req = urllib.request.Request(https_url(url), headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as response:
        if response.status != 200:
            die(f"{url}: HTTP {response.status}")
        if urllib.parse.urlparse(response.geturl()).scheme != "https":
            die("Adoptium redirect downgraded from HTTPS")
        payload = response.read(16 * 1024 * 1024 + 1)
        if len(payload) > 16 * 1024 * 1024:
            die("Adoptium metadata response too large")
    return json.loads(payload)


def resolve_asset(major: int, vendor_os: str, vendor_arch: str) -> dict:
    query = urllib.parse.urlencode({
        "architecture": vendor_arch,
        "heap_size": "normal",
        "image_type": "jre",
        "jvm_impl": "hotspot",
        "os": vendor_os,
        "vendor": "eclipse",
    })
    url = f"{API}/assets/latest/{major}/hotspot?{query}"
    payload = request_json(url)
    if not isinstance(payload, list):
        die(f"Adoptium metadata for {vendor_os}/{vendor_arch} is not an array")
    for asset in payload:
        try:
            binary = asset["binary"]
            version = asset["version"]
            package = binary["package"]
            if (
                int(version["major"]) == major
                and binary["image_type"] == "jre"
                and binary["jvm_impl"] == "hotspot"
                and binary["os"] == vendor_os
                and binary["architecture"] == vendor_arch
            ):
                checksum = canonical_sha256(str(package["checksum"]))
                link = https_url(str(package["link"]))
                size = int(package["size"])
                if size <= 0 or size > MAX_ARCHIVE:
                    die(f"Adoptium archive size outside policy: {size}")
                return {
                    "releaseName": str(asset["release_name"]),
                    "semver": str(version.get("semver") or asset["release_name"]),
                    "sourceUrl": link,
                    "sourceSha256": checksum,
                    "sourceSize": size,
                    "sourceName": str(package.get("name") or ""),
                }
        except (KeyError, TypeError, ValueError):
            continue
    die(f"Adoptium did not return Temurin JRE {major} for {vendor_os}/{vendor_arch}")


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def download_exact(url: str, path: Path, expected_sha256: str, expected_size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        digest, size = sha256_file(path)
        if digest == expected_sha256 and size == expected_size:
            return
        path.unlink()
    part = path.with_name(path.name + f".part-{os.getpid()}")
    part.unlink(missing_ok=True)
    req = urllib.request.Request(https_url(url), headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"})
    digest = hashlib.sha256()
    written = 0
    try:
        with urllib.request.urlopen(req, timeout=15 * 60) as response, part.open("xb") as out:
            if urllib.parse.urlparse(response.geturl()).scheme != "https":
                die("JRE archive redirect downgraded from HTTPS")
            header_size = response.headers.get("Content-Length")
            if header_size is not None and int(header_size) != expected_size:
                die(f"Content-Length={header_size}, expected {expected_size}")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_size or written > MAX_ARCHIVE:
                    die("JRE download exceeded declared size")
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        got = digest.hexdigest()
        if written != expected_size or got != expected_sha256:
            die(f"JRE archive checksum/size mismatch: {got}/{written}, expected {expected_sha256}/{expected_size}")
        os.replace(part, path)
    finally:
        part.unlink(missing_ok=True)


def safe_archive_name(name: str) -> str:
    name = name.replace("\\", "/").rstrip("/")
    if not name:
        return ""
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        die(f"unsafe archive entry: {name}")
    return str(p)


def validate_binary(platform: str, arch: str, data: bytes) -> None:
    if platform == "windows":
        if len(data) < 0x40 or data[:2] != b"MZ":
            die("bin/java.exe is not PE")
        peoff = struct.unpack_from("<I", data, 0x3C)[0]
        if peoff + 6 > len(data) or data[peoff:peoff + 4] != b"PE\0\0":
            die("bin/java.exe has invalid PE header")
        machine = struct.unpack_from("<H", data, peoff + 4)[0]
        expected = 0x8664 if arch == "x64" else 0xAA64
        if machine != expected:
            die(f"bin/java.exe PE machine=0x{machine:04x}, expected 0x{expected:04x}")
        return
    if platform == "linux":
        if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            die("bin/java is not little-endian ELF64")
        machine = struct.unpack_from("<H", data, 18)[0]
        expected = 62 if arch == "x64" else 183
        if machine != expected:
            die(f"bin/java ELF machine={machine}, expected {expected}")
        return
    if platform == "macos":
        if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
            die("bin/java is not thin little-endian Mach-O64")
        cpu = struct.unpack_from("<I", data, 4)[0]
        expected = 0x01000007 if arch == "x64" else 0x0100000C
        if cpu != expected:
            die(f"bin/java Mach-O cputype=0x{cpu:08x}, expected 0x{expected:08x}")
        return
    die(f"unsupported platform {platform}")


def inspect_zip(path: Path, platform: str, arch: str) -> str:
    found: list[str] = []
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 100000:
            die("invalid JRE zip entry count")
        for info in infos:
            clean = safe_archive_name(info.filename)
            if not clean or info.is_dir():
                continue
            if clean.lower().endswith("/bin/java.exe"):
                if info.file_size <= 0 or info.file_size > MAX_JAVA_BINARY:
                    die("bin/java.exe size outside policy")
                data = archive.read(info)
                if len(data) != info.file_size:
                    die("bin/java.exe truncated in zip")
                validate_binary(platform, arch, data)
                found.append(clean)
    if len(found) != 1:
        die(f"expected exactly one bin/java.exe, found {len(found)}")
    return found[0]


def inspect_tar(path: Path, platform: str, arch: str) -> str:
    found: list[str] = []
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > 100000:
            die("invalid JRE tar entry count")
        for member in members:
            clean = safe_archive_name(member.name)
            if not clean:
                continue
            if member.issym():
                link = member.linkname.replace("\\", "/")
                if not link or PurePosixPath(link).is_absolute():
                    die(f"unsafe JRE symlink: {member.name} -> {member.linkname}")
                resolved = PurePosixPath(clean).parent.joinpath(link)
                depth = 0
                for part in resolved.parts:
                    if part == "..":
                        depth -= 1
                    elif part not in {"", "."}:
                        depth += 1
                    if depth < 0:
                        die(f"JRE symlink escapes archive root: {member.name}")
                continue
            if member.islnk():
                link = safe_archive_name(member.linkname)
                if not link:
                    die(f"unsafe JRE hardlink: {member.name} -> {member.linkname}")
                continue
            if not member.isfile():
                continue
            if clean.lower().endswith("/bin/java"):
                if member.size <= 0 or member.size > MAX_JAVA_BINARY:
                    die("bin/java size outside policy")
                extracted = archive.extractfile(member)
                if extracted is None:
                    die("cannot read bin/java")
                data = extracted.read(MAX_JAVA_BINARY + 1)
                if len(data) != member.size:
                    die("bin/java truncated in tar")
                validate_binary(platform, arch, data)
                found.append(clean)
    if len(found) != 1:
        die(f"expected exactly one bin/java, found {len(found)}")
    return found[0]


def write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def archive_name(version: str, major: int, platform: str, arch: str, fmt: str) -> str:
    ext = ".zip" if fmt == "zip" else ".tar.gz"
    return f"neverlauncher-jre-temurin{major}-{platform}-{arch}-{version}{ext}"


def build_distribution(out: Path, version: str, major: int) -> None:
    out.mkdir(parents=True, exist_ok=True)
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    targets = []
    for platform, arch, vendor_os, vendor_arch, fmt in TARGETS:
        print(f"[ManagedJRE] resolving Temurin {major} {platform}/{arch}", file=sys.stderr)
        asset = resolve_asset(major, vendor_os, vendor_arch)
        name = archive_name(version, major, platform, arch, fmt)
        path = out / name
        download_exact(asset["sourceUrl"], path, asset["sourceSha256"], asset["sourceSize"])
        java_entry = inspect_zip(path, platform, arch) if fmt == "zip" else inspect_tar(path, platform, arch)
        digest, size = sha256_file(path)
        if digest != asset["sourceSha256"] or size != asset["sourceSize"]:
            die(f"post-download mismatch for {name}")
        targets.append({
            "platform": platform,
            "architecture": arch,
            "distribution": "temurin",
            "majorVersion": major,
            "releaseName": asset["releaseName"],
            "semver": asset["semver"],
            "archive": name,
            "format": fmt,
            "sha256": digest,
            "size": size,
            "javaEntry": java_entry,
            "sourceUrl": asset["sourceUrl"],
            "sourceSha256": asset["sourceSha256"],
            "vendorOs": vendor_os,
            "vendorArch": vendor_arch,
        })
    targets.sort(key=lambda item: (item["platform"], item["architecture"]))
    manifest = {
        "schemaVersion": "1.0",
        "product": "NeverLauncher",
        "productVersion": version,
        "distribution": "temurin",
        "vendor": "Eclipse Adoptium",
        "majorVersion": major,
        "generatedAt": generated,
        "targets": targets,
    }
    manifest_path = out / "MANAGED_JRE_MANIFEST.json"
    write_json_atomic(manifest_path, manifest)
    manifest_sha, _ = sha256_file(manifest_path)
    evidence = {
        "schemaVersion": "1.0",
        "product": "NeverLauncher",
        "productVersion": version,
        "distribution": "temurin",
        "vendor": "Eclipse Adoptium",
        "integrityMode": "exact-vendor-archive-sha256",
        "manifest": manifest_path.name,
        "manifestSha256": manifest_sha,
        "generatedAt": generated,
        "targets": [
            {
                "platform": item["platform"],
                "architecture": item["architecture"],
                "archive": item["archive"],
                "sha256": item["sha256"],
                "size": item["size"],
                "sourceUrl": item["sourceUrl"],
                "sourceSha256": item["sourceSha256"],
            }
            for item in targets
        ],
    }
    write_json_atomic(out / "MANAGED_JRE_EVIDENCE.json", evidence)
    print(f"[ManagedJRE] distribution ready: {out}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build NeverLauncher Managed JRE Distribution from exact Eclipse Temurin vendor archives")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--major", type=int, default=21)
    args = parser.parse_args()
    if args.major != 21:
        parser.error("0.15.5 production distribution is pinned to Temurin 21")
    if not args.version.strip():
        parser.error("--version is empty")
    try:
        build_distribution(args.out.resolve(), args.version.strip(), args.major)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, urllib.error.URLError, RuntimeError) as exc:
        print(f"managed-jre-distribution: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
