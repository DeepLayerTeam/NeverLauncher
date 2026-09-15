#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import zipfile
from pathlib import Path

PATH_PATTERNS = [
    re.compile(r"(^|/)\.env$", re.I),
    re.compile(r"(^|/)(id_rsa|id_ed25519)$", re.I),
    re.compile(r"\.(key|p12|pfx|jks|keystore)$", re.I),
    re.compile(r"(^|/)(secrets?|credentials?)(/|$)", re.I),
]
CONTENT_PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
]
ENV_SECRET = re.compile(rb"(?mi)^(?:NEVERLAUNCHER_[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY)|POSTGRES_PASSWORD|REDIS_PASSWORD)\s*=\s*([^\r\n#]+)")
PLACEHOLDERS = {b"", b"change-me", b"replace-me", b"example", b"example-only", b"<required>", b"<secret>"}
PLACEHOLDER_PREFIXES = (b"change-me", b"change_me", b"replace-me", b"replace_me", b"${", b"$", b"<")


def suspicious_path(name: str) -> bool:
    if name.endswith(".example") or name.endswith(".example.pem") or name.endswith(".env.example"):
        return False
    return any(p.search(name) for p in PATH_PATTERNS)


def scan_content(name: str, data: bytes) -> list[str]:
    issues: list[str] = []
    for pat in CONTENT_PATTERNS:
        if pat.search(data):
            issues.append(f"{name}: обнаружен private key/access-key pattern")
    for match in ENV_SECRET.finditer(data):
        value = match.group(1).strip().strip(b"\"'").lower()
        if value not in PLACEHOLDERS and not value.startswith(PLACEHOLDER_PREFIXES) and b"example" not in value and b"replace" not in value:
            issues.append(f"{name}: обнаружено непустое secret/password/private-key значение")
    return issues


def scan_zip(path: Path) -> list[str]:
    issues: list[str] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if suspicious_path(name):
                issues.append(f"{name}: secret-like path запрещён в release archive")
            if info.file_size <= 2 * 1024 * 1024:
                issues.extend(scan_content(name, zf.read(info)))
    return issues


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("archive")
    ns = ap.parse_args()
    path = Path(ns.archive)
    issues = scan_zip(path)
    if issues:
        print("secret-scan: FAILED")
        for issue in issues:
            print(" -", issue)
        return 1
    print(f"secret-scan: OK ({path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
