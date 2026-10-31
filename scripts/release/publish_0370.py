#!/usr/bin/env python3
"""Publish an already-signed Launcher GA bundle to GitHub Releases.

Fail closed before writing, stage as draft, round-trip download *every* release
asset, and only then switch the verified draft to public. GitHub publication
credentials are never used in the earlier build/GA jobs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile, BadZipFile

from release_policy import policy, parsed

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ga"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from verified_targets import TARGETS, checks_for, approval_data, paths, Blocked
from security_capabilities_0431 import checks as security_checks, verify_all as verify_security
from package_security_0431 import evidence_files as security_evidence_files
from required_jobs_0363 import declared_jobs

PRODUCTION_WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github/workflows/production-release-candidate.yml"
)

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
RECEIPT = "GA_VERIFIED_TARGETS.json"
REHEARSAL = "RELEASE_REHEARSAL_0365.json"
DRYRUN_SCHEMA = "launcher.release.publication-dry-run.v1"


def require(condition: bool, why: str) -> None:
    if not condition:
        raise Blocked(why)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def json_object(path: Path) -> dict:
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < path.stat().st_size <= 4 * 1024 * 1024,
        "missing/unsafe JSON evidence: " + str(path),
    )

    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "duplicate field: " + k)
            result[k] = v
        return result

    data = json.loads(path.read_bytes(), object_pairs_hook=unique)
    require(isinstance(data, dict), "evidence root is not JSON object")
    return data


def file_set(bundle: Path) -> dict[str, str]:
    require(
        bundle.is_dir() and not bundle.is_symlink(), "missing final release directory"
    )
    manifest = json_object(bundle / "RELEASE_MANIFEST.json")
    version = manifest.get("version")
    require(
        isinstance(version, str) and policy(version).ga_mode == "signed-ga-v2",
        "only current stable signed GA releases can be published",
    )
    require(
        tuple(parsed(version)[0]) >= (0, 37, 0), "publication requires version 0.37.0+"
    )
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    expected = {}
    for row in sums.splitlines():
        require(bool(row), "empty line in SHA256SUMS")
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)", row)
        require(match is not None, "malformed or unsafe SHA256SUMS entry")
        digest, name = match.groups()
        require(
            name not in expected and name not in ("SHA256SUMS", "SHA256SUMS.sig"),
            "duplicate/self-reference in SHA256SUMS",
        )
        expected[name] = digest
    require(len(expected) >= 20, "release has too few signed assets")
    present = set()
    for p in bundle.iterdir():
        require(
            p.is_file() and not p.is_symlink(),
            "release contains non-regular file: " + p.name,
        )
        present.add(p.name)
    require(
        present == set(expected) | {"SHA256SUMS", "SHA256SUMS.sig"},
        "unsigned extra or missing release asset",
    )
    for name, digest in expected.items():
        require(sha(bundle / name) == digest, "signed asset checksum mismatch: " + name)
    for extra in ("SHA256SUMS", "SHA256SUMS.sig"):
        require(
            (bundle / extra).stat().st_size > 0, "missing release signature/checksums"
        )
    expected["SHA256SUMS"] = sha(bundle / "SHA256SUMS")
    expected["SHA256SUMS.sig"] = sha(bundle / "SHA256SUMS.sig")
    return expected


def verify_ci(report: dict, version: str, commit: str, run_id: int, attempt: int):
    require(
        report.get("schemaVersion") == 1
        and report.get("status") == "passed"
        and report.get("gateJob") == "required-production-ci"
        and report.get("productVersion") == version
        and report.get("sourceCommit") == commit
        and report.get("runId") == run_id
        and report.get("runAttempt") == attempt
        and report.get("missingJobs") == []
        and report.get("unexpectedJobs") == []
        and report.get("nonSuccessJobs") == {},
        "production CI report is stale or incomplete",
    )
    jobs = report.get("jobResults")
    expected = declared_jobs(str(PRODUCTION_WORKFLOW)) - {
        "required-production-ci",
        "publish-release",
    }
    require(
        isinstance(jobs, dict)
        and set(jobs) == expected
        and all(value == "success" for value in jobs.values())
        and "release-bundle" in jobs
        and "base-ci" in jobs,
        "required production jobs missing, unexpected, skipped or failed",
    )


def verify_security_archive(
    bundle: Path, approval: dict, run_id: int, attempt: int, *, now=None
) -> None:
    """Recheck SHA256SUMS-protected raw observations before publication."""
    archive_path = bundle / "SECURITY_CAPABILITY_EVIDENCE_0431.zip"
    require(
        archive_path.is_file() and not archive_path.is_symlink()
        and 0 < archive_path.stat().st_size <= 256 * 1024 * 1024,
        "missing/unsafe signed security evidence archive",
    )
    with tempfile.TemporaryDirectory(prefix="nl-security-publish-") as folder:
        extracted = Path(folder)
        with ZipFile(archive_path, "r") as archive:
            expected_names = set(security_evidence_files())
            members = archive.infolist()
            require(
                len(members) == len(expected_names)
                and {item.filename for item in members} == expected_names
                and all(
                    not item.is_dir() and ((item.external_attr >> 16) & 0o170000) != 0o120000
                    and 0 < item.file_size <= 32 * 1024 * 1024
                    for item in members
                ),
                "security archive contains missing, extra, symlink or oversized evidence",
            )
            for member in members:
                # Filenames come exclusively from the fixed verifier list;
                # there are no arbitrary file paths or archive.extract().
                path = extracted / member.filename
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as stream:
                    data = stream.read(32 * 1024 * 1024 + 1)
                require(len(data) == member.file_size, "truncated security evidence")
                path.write_bytes(data)
        verify_security(
            extracted, approval, run_id=str(run_id), run_attempt=attempt, now=now
        )

def verify_ga(
    bundle: Path, public_key: Path, version: str, commit: str, run_id: int, attempt: int
) -> str:
    receipt = json_object(bundle / RECEIPT)
    rehearsal = json_object(bundle / REHEARSAL)
    require(
        receipt.get("schemaVersion") == policy(version).receipt_schema
        and receipt.get("status") == "approved-for-release-signing"
        and receipt.get("version") == version
        and receipt.get("commit") == commit,
        "GA receipt source/version mismatch",
    )
    require(
        rehearsal.get("schemaVersion") == "launcher.release.rehearsal.v1"
        and rehearsal.get("status") == "package-and-ga-verified"
        and rehearsal.get("version") == version
        and rehearsal.get("commit") == commit
        and rehearsal.get("runId") == str(run_id)
        and rehearsal.get("runAttempt") == str(attempt),
        "rehearsal from another CI run/attempt",
    )
    with tempfile.TemporaryDirectory(prefix="nl-ga-publish-") as folder:
        evidence = Path(folder)
        shutil.copyfile(bundle / "GA_TARGET_APPROVAL.json", evidence / "approval.json")
        shutil.copyfile(bundle / "GA_TARGET_APPROVAL.sig", evidence / "approval.sig")
        approval, raw, key = approval_data(evidence, public_key, version, commit)
    require(
        sha(bundle / "GA_TARGET_APPROVAL.json")
        == receipt.get("approvalSha256")
        == rehearsal.get("gaApprovalSha256"),
        "signed GA approval digest mismatch",
    )
    require(
        hashlib.sha256(bytes.fromhex(key.decode())).hexdigest()
        == receipt.get("operatorPublicKeySha256"),
        "GA receipt operator identity mismatch",
    )
    targets = approval.get("targets")
    require(
        isinstance(targets, list)
        and len(targets) == 6
        and all(isinstance(r, dict) for r in targets)
        and {r.get("target") for r in targets} == set(TARGETS),
        "GA signature does not authorize exactly six targets",
    )
    certified = receipt.get("targets")
    rehearsed = rehearsal.get("targets")
    require(
        isinstance(certified, list)
        and len(certified) == 6
        and all(isinstance(r, dict) for r in certified)
        and isinstance(rehearsed, list)
        and len(rehearsed) == 6
        and all(isinstance(r, dict) for r in rehearsed),
        "missing six target GA/rehearsal results",
    )
    require(
        {r.get("target") for r in rehearsed} == set(TARGETS)
        and {r.get("target") for r in certified} == set(TARGETS),
        "duplicate/missing target in GA and rehearsal receipts",
    )
    for target in TARGETS:
        signed_row = next(r for r in targets if r["target"] == target)
        certified_row = next(r for r in certified if r["target"] == target)
        rehearsed_row = next(r for r in rehearsed if r["target"] == target)
        binary, package = paths(version, target)
        require(
            signed_row.get("status") == "certified"
            and isinstance(signed_row.get("checks"), dict)
            and set(signed_row["checks"]) == set(checks_for(version))
            and certified_row.get("checksPassed") == len(checks_for(version))
            and (not security_checks(version)
                 or certified_row.get("securityCapabilitiesVerified") == list(security_checks(version)))
            and rehearsed_row.get("binary") == binary
            and rehearsed_row.get("package") == package,
            target + ": incomplete independent GA checks",
        )
        for field, file in [("binarySha256", binary), ("packageSha256", package)]:
            digest = sha(bundle / file)
            require(
                digest
                == signed_row.get(field)
                == certified_row.get(field)
                == rehearsed_row.get(field),
                target + ": published file not independently authorized: " + file,
            )
    if security_checks(version):
        verify_security_archive(bundle, approval, run_id, attempt)
    return receipt["approvalSha256"]


def run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command, text=True, capture_output=True, cwd=cwd, check=False
    )
    require(
        result.returncode == 0,
        "command failed: "
        + " ".join(command[:5])
        + " : "
        + (result.stderr or result.stdout)[-350:],
    )
    return result.stdout


def validate(
    *,
    bundle: Path,
    ci: Path,
    dryrun: Path,
    version: str,
    commit: str,
    run_id: int,
    attempt: int,
    ga_key: Path,
    release_key: Path,
    trust_policy: Path,
    cli: Path,
    trust_state: Path,
) -> dict:
    require(
        HEX40.fullmatch(commit) is not None and run_id > 0 and attempt > 0,
        "invalid source identity or CI run identity",
    )
    require(
        policy(version).ga_mode == "signed-ga-v2" and parsed(version)[0] >= (0, 37, 0),
        "missing current GA release policy",
    )
    manifest = json_object(bundle / "RELEASE_MANIFEST.json")
    require(
        manifest.get("version") == version and manifest.get("sourceCommit") == commit,
        "release manifest version/commit mismatch",
    )
    files = file_set(bundle)
    verify_ci(json_object(ci), version, commit, run_id, attempt)
    approval = verify_ga(bundle, ga_key, version, commit, run_id, attempt)
    dry = json_object(dryrun)
    require(
        dry.get("schemaVersion") == DRYRUN_SCHEMA
        and dry.get("status") == "passed"
        and dry.get("published") is False
        and dry.get("version") == version
        and dry.get("commit") == commit
        and dry.get("runId") == str(run_id)
        and dry.get("runAttempt") == str(attempt)
        and dry.get("filesCopied") == len(files)
        and dry.get("sha256sumsSha256") == files["SHA256SUMS"]
        and dry.get("gaApprovalSha256") == approval,
        "missing, stale or incomplete signed publication dry-run",
    )
    require(
        cli.is_file()
        and not cli.is_symlink()
        and cli.resolve().is_relative_to(bundle.resolve())
        and cli.name in files,
        "must verify with published release CLI",
    )
    cli.chmod(0o755)
    # Use isolated trust state: validating a candidate must not advance production trust.
    with tempfile.TemporaryDirectory(prefix="nl-0370-trust-") as tmp:
        state = Path(tmp) / "release-trust-state.json"
        if trust_state.is_file():
            shutil.copyfile(trust_state, state)
        run(
            [
                str(cli),
                "release",
                "publish-check",
                str(bundle),
                "--public-key",
                str(release_key),
                "--trust-policy",
                str(trust_policy),
                "--trust-state",
                str(state),
            ]
        )
    return {
        "schemaVersion": "launcher.release.publication.v1",
        "status": "verified",
        "version": version,
        "commit": commit,
        "runId": run_id,
        "runAttempt": attempt,
        "files": files,
        "gaApprovalSha256": approval,
    }


def github(repo: str, args: list[str]) -> str:
    return run(["gh", *args, "--repo", repo])


def publish(repo: str, verified: dict, bundle: Path) -> dict:
    require(REPOSITORY.fullmatch(repo) is not None, "invalid GitHub repository")
    require(
        os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
        "publication token not configured",
    )
    version = verified["version"]
    tag = "v" + version
    commit = verified["commit"]
    # Fail closed on any preexisting public release, draft, or tag: never overwrite.
    existing = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "tagName"],
        capture_output=True,
        text=True,
    )
    require(
        existing.returncode != 0
        and (
            "release not found" in existing.stderr.lower()
            or "http 404" in existing.stderr.lower()
            or "not found" in existing.stderr.lower()
        ),
        "release already exists or its absence cannot be verified",
    )
    ref = subprocess.run(
        ["gh", "api", f"repos/{repo}/git/ref/tags/{tag}"],
        capture_output=True,
        text=True,
    )
    require(
        ref.returncode != 0
        and ("http 404" in ref.stderr.lower() or "not found" in ref.stderr.lower()),
        "tag already exists or tag lookup failed",
    )
    files = verified["files"]
    args = [
        "gh",
        "release",
        "create",
        tag,
        "--repo",
        repo,
        "--target",
        commit,
        "--title",
        "Launcher " + version,
        "--draft",
        "--notes",
        "Verified six-platform release. GA exact-byte approvals and signed manifest are included.",
    ]
    run(args)
    try:
        # Upload all assets; do not promote a partial release.
        for name in sorted(files):
            run(["gh", "release", "upload", tag, str(bundle / name), "--repo", repo])
        with tempfile.TemporaryDirectory(prefix="nl-0370-roundtrip-") as tmp:
            remote = Path(tmp)
            run(
                ["gh", "release", "download", tag, "--repo", repo, "--dir", str(remote)]
            )
            require(
                {p.name for p in remote.iterdir()} == set(files),
                "published draft has missing or unexpected files",
            )
            for name, digest in files.items():
                require(
                    (remote / name).is_file()
                    and not (remote / name).is_symlink()
                    and sha(remote / name) == digest,
                    "remote GitHub asset bytes mismatch: " + name,
                )
        # Gate publication on a second complete server-side release inspection.
        metadata = json.loads(
            github(
                repo,
                [
                    "release",
                    "view",
                    tag,
                    "--json",
                    "tagName,isDraft,targetCommitish,assets",
                ],
            )
        )
        require(
            metadata.get("tagName") == tag
            and metadata.get("isDraft") is True
            and metadata.get("targetCommitish") == commit
            and isinstance(metadata.get("assets"), list)
            and len(metadata["assets"]) == len(files)
            and {a.get("name") for a in metadata["assets"]} == set(files),
            "draft release identity/assets mismatch",
        )
        run(["gh", "release", "edit", tag, "--repo", repo, "--draft=false"])
        final = json.loads(
            github(repo, ["release", "view", tag, "--json", "isDraft,tagName"])
        )
        require(
            final.get("isDraft") is False and final.get("tagName") == tag,
            "GitHub did not publish verified release",
        )
    except Exception:
        # Intentionally leave the draft for investigation, never publish partial files.
        raise
    return {
        "schemaVersion": "launcher.release.publication.v1",
        "status": "published",
        "repository": repo,
        "tag": tag,
        "version": version,
        "commit": commit,
        "runId": verified["runId"],
        "runAttempt": verified["runAttempt"],
        "assetCount": len(files),
        "sha256sumsSha256": files["SHA256SUMS"],
        "gaApprovalSha256": verified["gaApprovalSha256"],
        "verifiedRemoteBytes": True,
        "publishedAtUtc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("verify", "publish"))
    for name in (
        "bundle",
        "ci",
        "dryrun",
        "version",
        "commit",
        "run-id",
        "run-attempt",
        "ga-key",
        "release-key",
        "trust-policy",
        "cli",
        "trust-state",
    ):
        p.add_argument("--" + name, required=True)
    p.add_argument("--repository", default="")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    output = Path(a.output)
    output.unlink(missing_ok=True)
    try:
        verified = validate(
            bundle=Path(a.bundle),
            ci=Path(a.ci),
            dryrun=Path(a.dryrun),
            version=a.version,
            commit=a.commit,
            run_id=int(a.run_id),
            attempt=int(a.run_attempt),
            ga_key=Path(a.ga_key),
            release_key=Path(a.release_key),
            trust_policy=Path(a.trust_policy),
            cli=Path(a.cli),
            trust_state=Path(a.trust_state),
        )
        result = (
            publish(a.repository, verified, Path(a.bundle))
            if a.action == "publish"
            else verified
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print("Release publication: " + result["status"])
        return 0
    except (
        Blocked,
        ValueError,
        TypeError,
        KeyError,
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        BadZipFile,
    ) as exc:
        print("RELEASE PUBLICATION BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
