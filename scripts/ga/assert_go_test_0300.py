#!/usr/bin/env python3
"""Fail-closed witness for GA: enforce PASS (not SKIP/absence) for named live Go tests.

Reads unmodified `go test -json` output. This is an assertion over actual
executions, not an attestation or a replacement for the test runner exit code.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def verify(path: Path, required: list[str]) -> None:
    if not required:
        raise ValueError("at least one required test is mandatory")
    wanted = set(required)
    if len(wanted) != len(required):
        raise ValueError("duplicate --require names are not allowed")
    observed: dict[str, str] = {}
    packages: dict[str, str] = {}
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError("go test JSON line must be object")
        action = obj.get("Action")
        test = obj.get("Test")
        pkg = obj.get("Package")
        if not isinstance(action, str) or not isinstance(pkg, str):
            raise ValueError("invalid or truncated Go test event")
        count += 1
        if action in {"fail", "skip", "pass"}:
            if isinstance(test, str) and test in wanted:
                # A fail/skip is terminal even if a second, unrelated package uses
                # the same name or a forged later 'pass' appears in the stream.
                previous = observed.get(test)
                if previous in {"fail", "skip"}:
                    continue
                observed[test] = action
            if test is None:
                packages[pkg] = action
    if not count:
        raise ValueError("empty Go test evidence")
    incomplete = sorted(name for name in wanted if observed.get(name) != "pass")
    failed_packages = sorted(pkg for pkg, action in packages.items() if action != "pass")
    if incomplete or failed_packages:
        raise ValueError(f"GA not certified: tests without PASS={incomplete}, failed/skipped packages={failed_packages}")
    if not packages or not any(v == "pass" for v in packages.values()):
        raise ValueError("no successful Go package result")
    print(f"verified {len(wanted)} mandatory Go tests passed; packages={len(packages)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--require", action="append", required=True)
    args = ap.parse_args()
    try:
        verify(args.report, args.require)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"GA gate denied: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
