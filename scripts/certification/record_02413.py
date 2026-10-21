#!/usr/bin/env python3
"""Capture 0.24.13 per-target evidence. Missing real attestations remain missing.

This collector never creates Guard or ServerBridge attestations. To set these
checks to passed, provide a separately obtained, target/commit-bound report;
local unit tests cannot substitute for process/join verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from components_02413 import current_target


def verify_external(path: Path | None, target: str, commit: str, kind: str) -> bool:
    if path is None or not path.is_file():
        return False
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    # Receipt must result from a real test run and be bound to this source.
    return (isinstance(doc, dict) and doc.get("kind") == kind and
            doc.get("status") == "passed" and doc.get("target") == target and
            doc.get("commit") == commit and isinstance(doc.get("evidenceSha256"), str) and
            bool(re.fullmatch(r"[a-f0-9]{64}", doc["evidenceSha256"])) and
            doc.get("actualIntegration") is True)


def collect(*, component: Path, minecraft: Path | None, guard: Path | None,
            bridge: Path | None, target: str, commit: str) -> dict:
    git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if git_sha != commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("GITHUB_SHA and source git HEAD disagree")
    tree_clean = not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], text=True).strip()
    if not component.is_file():
        component_doc = {"status": "missing"}
    else:
        component_doc = json.loads(component.read_text(encoding="utf-8"))
    mc_doc = {"status": "missing"}
    if minecraft is not None and minecraft.is_file():
        result = json.loads(minecraft.read_text(encoding="utf-8"))
        checks = result.get("checks") or {}
        detected = result.get("platform") or {}
        if (result.get("status") == "passed" and checks.get("actualClient") is True and
            str(detected.get("os", "")) + "-" + str(detected.get("arch", "")) == target and
            (result.get("minecraft") or {}).get("client") == "actual-mojang-client"):
            mc_doc = {"status": "passed", "target": target, "actualClient": True,
                      "loader": result["minecraft"].get("loader"),
                      "evidenceSha256": hashlib.sha256(minecraft.read_bytes()).hexdigest()}
    guard_ok = verify_external(guard, target, commit, "neverguard-live-attestation")
    bridge_ok = verify_external(bridge, target, commit, "serverbridge-real-join-replay")
    return {"schemaVersion": "1.0", "version": "0.24.13", "commit": commit,
            "gitTreeClean": tree_clean, "target": target, "nativeComponents": component_doc,
            "checks": {
                # The collector runs only after unit/Go/Rust/fault-suite CI steps succeed;
                # source chain independently enforced by workflow 'needs' and set -e.
                "rustUnitTests": "passed" if component_doc.get("status") == "passed" else "missing",
                "goModelTests": "passed" if component_doc.get("status") == "passed" else "missing",
                "faultInjection": "passed" if component_doc.get("status") == "passed" else "missing",
                "neverGuard": "passed" if guard_ok else "missing",
                "serverBridgePolicy": "passed" if bridge_ok else "missing",
            },
            "minecraft": mc_doc}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--component", type=Path, required=True)
    ap.add_argument("--minecraft", type=Path)
    ap.add_argument("--guard", type=Path)
    ap.add_argument("--bridge", type=Path)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    actual = "-".join(current_target())
    if args.target != actual:
        raise SystemExit(f"runner mismatch: expected {args.target}, detected {actual}")
    report = collect(component=args.component, minecraft=args.minecraft, guard=args.guard,
                     bridge=args.bridge, target=args.target, commit=args.commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"target": args.target,"component": report["nativeComponents"].get("status"),
                      "minecraft": report["minecraft"].get("status"),"guardLive": report["checks"]["neverGuard"],
                      "bridgeReplay": report["checks"]["serverBridgePolicy"]}))

if __name__ == "__main__": main()
