#!/usr/bin/env python3
"""Aggregate platform evidence; missing/failed/skipped cases cannot become GA."""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import hashlib
import sys

REQUIRED_PLATFORMS = {"Linux", "Windows", "Darwin"}
REQUIRED_SUITES = {"fault-http-server", "prestarter", "component-updater", "rust-runtime",
                   "build-runtime-e2e", "real-runtime-e2e"}


def combine(paths: list[Path]) -> dict:
    report = {"schemaVersion":"1", "generatedAt":dt.datetime.now(dt.timezone.utc).isoformat(),
              "status":"incomplete", "commit":None, "platforms":{}, "unmetGates":[]}
    for path in paths:
        raw = path.read_bytes()
        evidence = json.loads(raw)
        os_name = evidence.get("platform", {}).get("system")
        if os_name not in REQUIRED_PLATFORMS or os_name in report["platforms"]:
            raise ValueError(f"unknown or duplicate platform in {path}: {os_name}")
        commit = evidence.get("commit")
        if not re.fullmatch(r"[a-f0-9]{40}", commit or "") or not evidence.get("gitTreeClean"):
            report["unmetGates"].append(f"{os_name}: missing exact clean commit")
        if report["commit"] is None: report["commit"] = commit
        elif commit != report["commit"]:
            report["unmetGates"].append(f"{os_name}: commit mismatch")
        result = {v.get("id"):v.get("status") for v in evidence.get("suites", [])}
        report["platforms"][os_name] = {"artifactSha256":hashlib.sha256(raw).hexdigest(),
                                        "status":evidence.get("status"), "suites":result}
        for case in REQUIRED_SUITES:
            if result.get(case) != "passed": report["unmetGates"].append(f"{os_name}: {case} not passed")
        if evidence.get("status") != "passed":
            report["unmetGates"].append(f"{os_name}: platform status {evidence.get('status')}")
    for name in sorted(REQUIRED_PLATFORMS - set(report["platforms"])):
        report["unmetGates"].append(f"{name}: missing platform report")
    if report["platforms"].get("Windows", {}).get("suites", {}).get("windows-locked-executable-test") != "passed":
        report["unmetGates"].append("Windows: exclusive executable lock test not passed")
    if not report["unmetGates"]: report["status"] = "passed"
    elif any(p.get("status") == "failed" for p in report["platforms"].values()): report["status"] = "failed"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()
    try: result = combine(args.reports)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"evidence verification error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n")
    print(f"0.23.13 platform certification: {result['status']}")
    return 0 if result["status"]=="passed" else 1

if __name__ == "__main__": raise SystemExit(main())
