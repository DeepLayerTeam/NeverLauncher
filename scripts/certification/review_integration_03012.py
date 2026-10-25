#!/usr/bin/env python3
"""Fail-closed review of *executed* cross-platform NeverLauncher release gates.

Evidence is emitted by run_integration_03012.py and collected from CI jobs.
Passing these tests does not prove full M01-M19 or live Minecraft parity.
"""
import argparse
import json
from pathlib import Path
import re

COMMON = {"java-sdk", "jvm-host-e2e", "gravit-e2e", "trusted-agent-e2e",
          "devtools-e2e", "discord-ipc", "devtools-security", "sentry-backend",
          "asset-integrity", "sentry-release", "module-parity"}
REQUIRED = {
    "linux": COMMON | {"java-supervisor-go", "lan-security", "java-lifecycle-e2e", "java-runtime-e2e"},
    "darwin": COMMON | {"lan-security", "java-lifecycle-e2e", "java-runtime-e2e"},
    "windows": COMMON,
}
HASH = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")


def review(paths: list[Path], revision: str) -> dict:
    if not REVISION.fullmatch(revision):
        raise ValueError("expected a 40-character Git commit SHA")
    found = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid evidence file: {path}")
        if path.stat().st_size > 512_000:
            raise ValueError(f"oversized evidence file: {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        platform = raw.get("platform")
        if platform not in REQUIRED or platform in found:
            raise ValueError(f"unknown or duplicate platform: {platform}")
        if raw.get("schemaVersion") != "1.0" or raw.get("release") != "0.30.12" or raw.get("revision") != revision:
            raise ValueError(f"wrong schema, release or checkout in {path}")
        if raw.get("passed") is not True or raw.get("fullyCertified") is not False:
            raise ValueError(f"failed case or unsupported full-parity claim in {path}")
        results = raw.get("results")
        if not isinstance(results, list) or {x.get("case") for x in results if isinstance(x, dict)} != REQUIRED[platform] or len(results) != len(REQUIRED[platform]):
            raise ValueError(f"incomplete required E2E suite on {platform}")
        for case in results:
            if case.get("status") != "passed" or not isinstance(case.get("steps"),list) or not case["steps"]:
                raise ValueError(f"failed/skipped E2E case {case.get('case')} on {platform}")
            for step in case["steps"]:
                if step.get("status") != "passed" or step.get("exitCode") != 0 or not HASH.fullmatch(str(step.get("outputSha256", ""))):
                    raise ValueError(f"invalid/failed subprocess evidence: {case['case']}")
        found[platform] = len(results)
    if set(found) != set(REQUIRED):
        raise ValueError(f"missing required operating systems: {sorted(set(REQUIRED)-set(found))}")
    return {"release": "0.30.12", "revision": revision, "crossPlatformIntegrationGatesPassed": True,
            "upstreamGravitParityCertified": False, "realMinecraftLoaderCertificationIncluded": False,
            "caseCounts": found}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence", type=Path, required=True, help="directory containing the three OS reports")
    p.add_argument("--revision", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    # Never follow symlinks in the collected evidence tree.
    if args.evidence.is_symlink():
        p.error("symlink evidence directory forbidden")
    paths = sorted(args.evidence.rglob("integration-03012.json"))
    try:
        result = review(paths, args.revision)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("0.30.12 cross-platform integration gates passed (not upstream functional parity)")

if __name__ == "__main__":
    main()
