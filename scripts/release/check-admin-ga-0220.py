#!/usr/bin/env python3
"""Fail-closed, executable GA source audit for Admin 0.22.0.

Checks immutable migration parity and actual SDK regeneration, not only references
in docs/manifests. The full certification runner performs builds and live E2E.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

from release_policy import legacy_admin_supported

ROOT = Path(__file__).resolve().parents[2]
SDK_GENERATED = (
    "sdk/backend/go/types_generated.go", "sdk/cli/go/types_generated.go",
    "sdk/admin/typescript/generated.ts", "sdk/desktop/typescript/generated.ts",
    "sdk/desktop/rust/src/generated.rs", "sdk/admin/typescript/openapi-generated.ts",
    "sdk/desktop/typescript/openapi-generated.ts", "sdk/backend/go/openapi_generated.go",
    "sdk/cli/go/openapi_generated.go", "sdk/api/openapi-operations-generated.json",
    "sdk/admin/typescript/api-types-generated.ts", "sdk/desktop/typescript/api-types-generated.ts",
    "sdk/admin/typescript/api-requests-generated.ts", "sdk/desktop/typescript/api-requests-generated.ts",
    "sdk/backend/go/api_types_generated.go", "sdk/cli/go/api_types_generated.go",
)


def run(*cmd: str) -> None:
    subprocess.run(cmd, check=True, cwd=ROOT)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not legacy_admin_supported(version):
        raise RuntimeError(f"Admin GA audit requires version >=0.22.0, got {version}")
    run(sys.executable, "scripts/version/manage.py", "check")
    run(sys.executable, "scripts/contracts/validate-openapi.py")
    run(sys.executable, "scripts/smoke/offline/repository-policy.py")

    api = ROOT / "services/api/internal/dbmigrate/sql"
    cli = ROOT / "cli/internal/dbmigrate/sql"
    a = {p.name: digest(p) for p in api.glob("*.sql")}
    b = {p.name: digest(p) for p in cli.glob("*.sql")}
    if not a or a != b:
        raise RuntimeError("Backend/CLI migration files or checksums differ")
    for migration in (
        "0053_release_workspace_0218.sql", "0054_serverbridge_operator_0219.sql",
        "0055_config_audit_02111.sql",
    ):
        if migration not in a:
            raise RuntimeError(f"required migration absent: {migration}")

    generated = {name: digest(ROOT / name) for name in SDK_GENERATED}
    run(sys.executable, "scripts/sdk/generate-types.py")
    drift = [name for name in SDK_GENERATED if digest(ROOT / name) != generated[name]]
    if drift:
        raise RuntimeError("SDK generation drift: " + ", ".join(drift))
    if not (ROOT / "docs/administration/ga-0220.md").is_file():
        raise RuntimeError("GA operations and rollback documentation missing")
    print(f"Admin GA source audit PASS: {version}, {len(a)} identical migrations, {len(generated)} reproducible SDK artifacts")


if __name__ == "__main__":
    try:
        audit()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Admin GA source audit FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
