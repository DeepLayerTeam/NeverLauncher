#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def triple(v: str) -> tuple[int, int, int]:
    core = v.split("-", 1)[0].split("+", 1)[0]
    return tuple(int(x) for x in core.split(".")[:3])  # type: ignore[return-value]


def require(text: str, needles: list[str], label: str) -> None:
    missing = [x for x in needles if x not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


if triple(VERSION) < (0, 15, 11):
    raise SystemExit(
        f"Production Release Candidate gate requires VERSION>=0.15.11, got {VERSION}"
    )

impl = (ROOT / "cli/cmd/launcher/production_release_candidate_01511.go").read_text(
    encoding="utf-8"
)
release = (ROOT / "cli/cmd/launcher/release_commands.go").read_text(encoding="utf-8")
build = (ROOT / "scripts/release/build-release.sh").read_text(encoding="utf-8")
tests = (
    ROOT / "cli/cmd/launcher/production_release_candidate_01511_test.go"
).read_text(encoding="utf-8")

require(
    impl,
    [
        "PRODUCTION_RELEASE_CANDIDATE.json",
        "production-release-candidate",
        "exact-source-commit-cohort",
        "productionReleaseCandidateCohortDigest01511",
        "verifyProductionReleaseCandidatePrerequisites01511",
        "verifyWindowsSigningEvidence0152",
        "verifyMacOSNotarizationEvidence0154",
        "verifyManagedJREDistribution0155",
        "verifyPublicProductionDeliveryMatrix0159",
        "PROVENANCE.json sourceCommit mismatch",
    ],
    "production candidate implementation",
)
require(
    release,
    [
        'case "candidate-verify":',
        "productionReleaseCandidateRequired01511",
        "writeProductionReleaseCandidate01511",
        "verifyProductionReleaseCandidate01511",
        "production-release-candidate-exact-source-cohort",
    ],
    "release integration",
)
require(
    build,
    [
        "PRODUCTION_RC_REQUIRED",
        "Production Release Candidate требует полный Compatibility + Device Trust + Guard CI certification cohort",
        'git -C "${ROOT_DIR}" diff --quiet HEAD --',
        "release candidate-verify",
        "PRODUCTION_RELEASE_CANDIDATE.json",
    ],
    "production build integration",
)
require(
    tests,
    [
        "TestProductionReleaseCandidate01511BindsExactCohort",
        "TestProductionReleaseCandidate01511RejectsInjectedFile",
        "TestSLSAProvenance01511CarriesExactSourceCommit",
        "TestNormalizeSourceCommit01511RejectsPlaceholders",
    ],
    "production candidate tests",
)

layout_resolver = ROOT / "scripts/release/resolve-artifact-payload.sh"
if not layout_resolver.is_file():
    raise SystemExit("production candidate artifact layout resolver is missing")
require(
    build,
    [
        "resolve-artifact-payload.sh",
        '"launcher-cli-windows-x64.exe" "Windows x64/ARM64 delivery"',
        '"launcher-cli-linux-x64" "Linux x64/ARM64 delivery"',
        '"launcher-cli-macos-x64" "macOS x64/ARM64 delivery"',
    ],
    "production artifact layout staging",
)


def bash_path(path: Path) -> str:
    value = str(path.resolve())
    if (
        sys.platform == "win32"
        and len(value) >= 3
        and value[1] == ":"
        and value[2] in ("\\", "/")
    ):
        return "/" + value[0].lower() + value[2:].replace("\\", "/")
    return value


def validate_native_layout(root: Path, marker: str) -> Path:
    """Windows-native equivalent of resolve-artifact-payload.sh.

    Git Bash /c/... paths from Python subprocesses can be interpreted by
    different bash installations (Git for Windows versus WSL). Validate the
    exact same release layout without depending on shell path translation.
    """
    if not root.is_dir() or root.is_symlink():
        raise ValueError("artifact root missing or symlink")
    releases = [p for p in root.iterdir() if p.name.startswith("release-")]
    flat = root / marker
    if flat.is_file() and not flat.is_symlink():
        if releases or any(p.is_symlink() for p in root.iterdir()):
            raise ValueError("mixed flat artifact or symlink")
        return root
    expected = root / f"release-{VERSION}"
    if len(releases) != 1 or releases[0] != expected:
        raise ValueError("expected exactly one versioned artifact payload")
    if not expected.is_dir() or expected.is_symlink():
        raise ValueError("artifact payload missing or symlink")
    nested = expected / marker
    if not nested.is_file() or nested.is_symlink():
        raise ValueError("artifact marker missing or symlink")
    if any(p.is_file() or p.is_symlink() for p in root.iterdir()):
        raise ValueError("unexpected top-level artifact or symlink")
    if any(p.is_symlink() for p in expected.iterdir()):
        raise ValueError("nested artifact payload contains symlink")
    return expected


def resolve_layout(root: Path, marker: str, *, expect_ok: bool) -> str:
    if sys.platform == "win32":
        try:
            resolved = validate_native_layout(root, marker)
        except ValueError as exc:
            if expect_ok:
                raise SystemExit(
                    f"artifact layout resolver unexpectedly failed: {exc}"
                ) from exc
            return ""
        if not expect_ok:
            raise SystemExit(
                f"artifact layout resolver unexpectedly accepted unsafe layout: {root}"
            )
        return bash_path(resolved)
    proc = subprocess.run(
        [
            "bash",
            bash_path(layout_resolver),
            bash_path(root),
            VERSION,
            marker,
            "RC layout regression",
        ],
        text=True,
        capture_output=True,
    )
    if expect_ok and proc.returncode != 0:
        raise SystemExit(
            f"artifact layout resolver unexpectedly failed: {proc.stderr.strip()}"
        )
    if not expect_ok and proc.returncode == 0:
        raise SystemExit(
            f"artifact layout resolver unexpectedly accepted unsafe layout: {root}"
        )
    return proc.stdout.strip()


with tempfile.TemporaryDirectory(prefix="nl-release-layout-") as td:
    base = Path(td)
    flat = base / "flat"
    flat.mkdir()
    (flat / "marker").write_bytes(b"ok")
    if resolve_layout(flat, "marker", expect_ok=True) != bash_path(flat):
        raise SystemExit("flat artifact payload resolved to unexpected directory")

    nested = base / "nested"
    expected = nested / f"release-{VERSION}"
    expected.mkdir(parents=True)
    (expected / "marker").write_bytes(b"ok")
    if resolve_layout(nested, "marker", expect_ok=True) != bash_path(expected):
        raise SystemExit("versioned artifact payload resolved to unexpected directory")

    wrong = base / "wrong"
    (wrong / "release-0.0.0").mkdir(parents=True)
    (wrong / "release-0.0.0" / "marker").write_bytes(b"bad")
    resolve_layout(wrong, "marker", expect_ok=False)

    mixed = base / "mixed"
    (mixed / f"release-{VERSION}").mkdir(parents=True)
    (mixed / "marker").write_bytes(b"flat")
    (mixed / f"release-{VERSION}" / "marker").write_bytes(b"nested")
    resolve_layout(mixed, "marker", expect_ok=False)

    multiple = base / "multiple"
    (multiple / f"release-{VERSION}").mkdir(parents=True)
    (multiple / "release-0.0.0").mkdir()
    (multiple / f"release-{VERSION}" / "marker").write_bytes(b"ok")
    resolve_layout(multiple, "marker", expect_ok=False)

    top_level_file = base / "top-level-file"
    (top_level_file / f"release-{VERSION}").mkdir(parents=True)
    (top_level_file / f"release-{VERSION}" / "marker").write_bytes(b"ok")
    (top_level_file / "unexpected.txt").write_text("bad", encoding="utf-8")
    resolve_layout(top_level_file, "marker", expect_ok=False)

    symlinked = base / "symlinked"
    (symlinked / f"release-{VERSION}").mkdir(parents=True)
    (symlinked / f"release-{VERSION}" / "marker").write_bytes(b"ok")
    (symlinked / f"release-{VERSION}" / "alias").symlink_to("marker")
    resolve_layout(symlinked, "marker", expect_ok=False)

subprocess.run(
    [
        "go",
        "test",
        "./cmd/launcher",
        "-run",
        "TestProductionReleaseCandidate|TestSLSAProvenance01511|TestNormalizeSourceCommit01511",
        "-count=1",
    ],
    cwd=ROOT / "cli",
    check=True,
)
print(f"Launcher {VERSION} Production release candidate 0.15.11 gate: OK")
