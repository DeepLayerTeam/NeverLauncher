#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/guard_ci/matrix.py"
STAGE = ROOT / "scripts/guard_ci/stage_release.py"
TARGETS = ROOT / "guard-ci/targets.json"
VERSION = (ROOT / "VERSION").read_text().strip()
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = "139001"
REPOSITORY = "DeepLayerTeam/NeverLauncher"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def run(*args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT, text=True, capture_output=True)
    if ok and proc.returncode != 0:
        raise SystemExit(proc.stdout + proc.stderr)
    if not ok and proc.returncode == 0:
        raise SystemExit("expected command failure")
    return proc


def emit(root: Path, target: str, os_name: str, signing: str) -> Path:
    d = root / target
    package = d / {
        "linux": f"neverlauncher-desktop-{VERSION}-linux-amd64.zip",
        "windows": f"neverlauncher-desktop-{VERSION}-windows-amd64.zip",
        "macos": f"neverlauncher-desktop-{VERSION}-macos-universal.zip",
    }[os_name]
    launcher = d / {
        "linux": "neverlauncher-desktop-linux-amd64",
        "windows": "neverlauncher-desktop-windows-amd64.exe",
        "macos": "neverlauncher-desktop-macos-universal",
    }[os_name]
    guard = d / {
        "linux": "neverguard-linux-amd64",
        "windows": "neverguard-windows-amd64.exe",
        "macos": "neverguard-macos-universal",
    }[os_name]
    manifest = d / {"linux": "LINUX_PACKAGE_MANIFEST.json", "windows": "WINDOWS_PACKAGE_MANIFEST.json", "macos": "MACOS_PACKAGE_MANIFEST.json"}[os_name]
    allowlist = d / {"linux": "GUARD_RELEASE_ALLOWLIST_LINUX.json", "windows": "GUARD_RELEASE_ALLOWLIST_WINDOWS.json", "macos": "GUARD_RELEASE_ALLOWLIST_MACOS.json"}[os_name]
    write(package, f"package-{target}\n".encode())
    write(launcher, f"launcher-{target}\n".encode())
    write(guard, f"guard-{target}\n".encode())
    lh, gh = sha(launcher), sha(guard)
    if os_name == "linux":
        manifest_payload = {
            "schemaVersion": "1.0", "productVersion": VERSION, "platform": "linux-amd64", "neverGuardProtocolVersion": 4,
            "artifacts": [{"name": "neverlauncher-desktop", "size": launcher.stat().st_size, "sha256": lh}, {"name": "neverguard", "size": guard.stat().st_size, "sha256": gh}],
        }
    elif os_name == "windows":
        manifest_payload = {
            "schemaVersion": "1.0", "productVersion": VERSION, "platform": "windows-amd64", "neverGuardProtocolVersion": 4,
            "artifacts": [{"name": f"neverlauncher-desktop-{VERSION}-windows-amd64.exe", "size": launcher.stat().st_size, "sha256": lh}, {"name": "neverguard.exe", "size": guard.stat().st_size, "sha256": gh}],
        }
    else:
        manifest_payload = {
            "schemaVersion": "1.0", "productVersion": VERSION, "platform": "macos-universal", "neverGuardProtocolVersion": 4,
            "desktopSha256": lh, "desktopSize": launcher.stat().st_size, "guardSha256": gh, "guardSize": guard.stat().st_size,
        }
    manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    allowlist.write_text(json.dumps({VERSION: {"guardSha256": [gh], "launcherSha256": [lh], "requireAuthenticode": False}}), encoding="utf-8")
    result = d / "guard-ci-result.json"
    run("result", "--targets", str(TARGETS), "--target-id", target, "--package", str(package), "--launcher", str(launcher), "--guard", str(guard), "--manifest", str(manifest), "--allowlist", str(allowlist), "--signing-mode", signing, "--commit", COMMIT, "--run-id", RUN_ID, "--repository", REPOSITORY, "--output", str(result))
    return result


def main() -> int:
    run("validate", "--targets", str(TARGETS))
    with tempfile.TemporaryDirectory(prefix="neverlauncher-guard-ci-") as tmp:
        root = Path(tmp)
        emit(root, "guard-linux-amd64", "linux", "none-linux-integrity")
        emit(root, "guard-windows-amd64", "windows", "unsigned-development-ci")
        emit(root, "guard-macos-universal", "macos", "adhoc-ci")
        out = root / "aggregate"
        run("aggregate", "--targets", str(TARGETS), "--results-root", str(root), "--output-dir", str(out), "--commit", COMMIT, "--run-id", RUN_ID, "--repository", REPOSITORY)
        matrix = json.loads((out / "matrix.json").read_text())
        if matrix.get("status") != "passed" or len(matrix.get("targets", [])) != 3:
            raise SystemExit("valid cross-platform Guard matrix did not pass")

        staged = root / "staged"
        stage_proc = subprocess.run(
            [sys.executable, str(STAGE), "--matrix", str(out / "matrix.json"), "--artifacts-root", str(root), "--out", str(staged), "--expected-commit", COMMIT],
            cwd=ROOT, text=True, capture_output=True,
        )
        if stage_proc.returncode != 0:
            raise SystemExit(stage_proc.stdout + stage_proc.stderr)
        staged_files = [path for path in staged.iterdir() if path.is_file()]
        if len(staged_files) != 15:
            raise SystemExit(f"expected 15 staged Guard artifacts, got {len(staged_files)}")

        linux_package = root / "guard-linux-amd64" / f"neverlauncher-desktop-{VERSION}-linux-amd64.zip"
        linux_package.write_bytes(linux_package.read_bytes() + b"tamper")
        tampered_stage = subprocess.run(
            [sys.executable, str(STAGE), "--matrix", str(out / "matrix.json"), "--artifacts-root", str(root), "--out", str(root / "staged-tampered"), "--expected-commit", COMMIT],
            cwd=ROOT, text=True, capture_output=True,
        )
        if tampered_stage.returncode == 0:
            raise SystemExit("tampered certified artifact unexpectedly staged")

        # Restore the package before exercising metadata tampering.
        write(linux_package, b"package-guard-linux-amd64\n")
        bad_matrix = json.loads((out / "matrix.json").read_text(encoding="utf-8"))
        bad_matrix["targets"][0]["artifacts"]["launcher"]["name"] = "neverlauncher-cli-linux-amd64"
        bad_matrix_path = root / "matrix-bad-name.json"
        bad_matrix_path.write_text(json.dumps(bad_matrix), encoding="utf-8")
        unsafe_stage = subprocess.run(
            [sys.executable, str(STAGE), "--matrix", str(bad_matrix_path), "--artifacts-root", str(root), "--out", str(root / "staged-unsafe"), "--expected-commit", COMMIT],
            cwd=ROOT, text=True, capture_output=True,
        )
        if unsafe_stage.returncode == 0:
            raise SystemExit("non-canonical certified artifact name unexpectedly staged")

        bad = root / "guard-windows-amd64" / "guard-ci-result.json"
        payload = json.loads(bad.read_text())
        payload["checks"]["guardIntegrationTest"] = False
        bad.write_text(json.dumps(payload), encoding="utf-8")
        run("aggregate", "--targets", str(TARGETS), "--results-root", str(root), "--output-dir", str(root / "aggregate-bad"), "--commit", COMMIT, "--run-id", RUN_ID, "--repository", REPOSITORY, ok=False)
    print("Guard CI matrix tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
