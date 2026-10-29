#!/usr/bin/env python3
"""Fail-closed aggregate of actual GitHub Actions `needs` job conclusions.

The workflow is the source of the required job set, not a manually maintained
allowlist that can accidentally omit a new security/packaging job.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

JOB_RE = re.compile(r"^  ([a-zA-Z][a-zA-Z0-9_-]*):\s*(?:#.*)?$")
SHA_RE = re.compile(r"[a-fA-F0-9]{40}")


class GateFailure(ValueError):
    pass


def declared_jobs(workflow: str) -> set[str]:
    # GitHub Actions job IDs are top-level entries immediately below `jobs:`.
    # Parse without a third-party YAML dependency on the production gate runner.
    text = Path(workflow).read_text(encoding="utf-8")
    in_jobs = False
    seen_jobs = False
    jobs: set[str] = set()
    for line in text.splitlines():
        if line == "jobs:":
            if seen_jobs:
                raise GateFailure("duplicate jobs: section")
            in_jobs = True
            seen_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith((" ", "#")):
            in_jobs = False
            continue
        match = JOB_RE.match(line)
        if line.startswith("  ") and not line.startswith("    ") and not line.lstrip().startswith("#") and not match and line.strip():
            raise GateFailure(f"unrecognized job declaration (fail closed): {line!r}")
        if match:
            name = match.group(1)
            if name in jobs:
                raise GateFailure(f"duplicate job id: {name}")
            jobs.add(name)
    if not jobs:
        raise GateFailure("no jobs found in workflow")
    return jobs


def verify(
    *, workflow: str, gate: str, needs: object, source_sha: str,
    checked_out_sha: str, run_id: str, run_attempt: str, version: str,
) -> dict:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?", version):
        raise GateFailure("missing or malformed current product version")
    if not SHA_RE.fullmatch(source_sha) or not SHA_RE.fullmatch(checked_out_sha):
        raise GateFailure("missing or invalid 40-hex source SHA")
    if source_sha.lower() != checked_out_sha.lower():
        raise GateFailure("checked-out commit differs from workflow source SHA")
    if not run_id.isdigit() or int(run_id) <= 0 or not run_attempt.isdigit() or int(run_attempt) <= 0:
        raise GateFailure("missing CI run id/attempt")
    if not isinstance(needs, dict):
        raise GateFailure("GitHub needs context is missing or not an object")
    all_jobs = declared_jobs(workflow)
    expected = all_jobs - {gate}
    if gate not in all_jobs or not expected:
        raise GateFailure("gate job missing or required job set empty")
    actual = set(needs)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    outcomes: dict[str, str] = {}
    for key, details in needs.items():
        if not isinstance(details, dict) or not isinstance(details.get("result"), str):
            raise GateFailure(f"{key}: missing GitHub Actions job conclusion")
        outcomes[key] = details["result"]
    unsuccessful = {job: outcomes[job] for job in sorted(expected & actual) if outcomes[job] != "success"}
    report = {
        "schemaVersion": 1,
        "status": "passed" if not (missing or unexpected or unsuccessful) else "blocked",
        "sourceCommit": source_sha.lower(),
        "productVersion": version,
        "runId": int(run_id),
        "runAttempt": int(run_attempt),
        "gateJob": gate,
        "expectedJobCount": len(expected),
        "jobResults": {job: outcomes.get(job, "absent") for job in sorted(expected)},
        "missingJobs": missing,
        "unexpectedJobs": unexpected,
        "nonSuccessJobs": unsuccessful,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--needs-json", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version-file", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        needs = json.loads(Path(args.needs_json).read_text(encoding="utf-8"))
        product_version = Path(args.version_file).read_text(encoding="utf-8").strip()
        report = verify(
            workflow=args.workflow, gate=args.gate, needs=needs,
            source_sha=args.source_sha, checked_out_sha=checkout_sha,
            run_id=args.run_id, run_attempt=args.run_attempt, version=product_version,
        )
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(f"{args.gate}: {report['status']}, SHA={report['sourceCommit']}, "
              f"run={report['runId']}/{report['runAttempt']}, jobs={report['expectedJobCount']}")
        if report["status"] != "passed":
            print(json.dumps({k: report[k] for k in ("missingJobs", "unexpectedJobs", "nonSuccessJobs")}, indent=2), file=sys.stderr)
            return 2
        return 0
    except (GateFailure, ValueError, OSError, subprocess.CalledProcessError) as exc:
        path.write_text(json.dumps({"status": "blocked", "error": str(exc)}, indent=2) + "\n", encoding="utf-8")
        print(f"{args.gate}: BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
