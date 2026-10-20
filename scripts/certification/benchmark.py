#!/usr/bin/env python3
"""Controlled same-host baseline Never 0.23.0 vs current NeverRuntime.

Requires actual *compiled* 0.23.0 executable. Never reports a "win" against a
synthetic sequential Python client; Gravit measurements are a separate run.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import hashlib
import re

from fault_server import FaultServer, Object
from runtime_e2e import manifest, payload, sign


def bench(baseline: Path, candidate: Path, signer: Path, repetitions: int = 3) -> dict:
    for path, expected in ((baseline, "0.23.0"), (candidate, "0.24.0")):
        proc = subprocess.run([str(path), "--help"], text=True, capture_output=True, timeout=15)
        if proc.returncode != 0:
            raise ValueError(f"version probe failed for {path}: {proc.stderr[-400:]}")
        try:
            version = json.loads(proc.stdout)["version"]
        except (ValueError, KeyError) as err:
            raise ValueError(f"version probe is not a NeverRuntime CLI: {path}") from err
        if version != expected:
            raise ValueError(f"baseline/candidate version mismatch: expected {expected}, got {version}")
    if repetitions < 3:
        raise ValueError("at least 3 repetitions required")
    rows = []
    with tempfile.TemporaryDirectory(prefix="nl-perf-02313-") as d:
        folder = Path(d)
        objects = {f"/good/{i}":Object(payload(i, 131072), delay=.1) for i in range(16)}
        with FaultServer(objects) as server:
            unsigned, signed = folder/"unsigned.json", folder/"manifest.json"
            data = [payload(i, 131072) for i in range(16)]
            key = sign(signer, unsigned, signed, manifest(server.url, data, profile="benchmark", poison=False))
            server.objects["/manifest"] = Object(signed.read_bytes())
            for round_id in range(repetitions):
                # Alternate ordering to reduce temperature/OS scheduler bias.
                for label, binary in (("baseline", baseline), ("candidate", candidate)) if round_id%2==0 else (("candidate", candidate), ("baseline", baseline)):
                    run_dir = folder/f"{round_id}-{label}"
                    run_dir.mkdir()
                    env = os.environ.copy()
                    if os.name == "nt": env["LOCALAPPDATA"] = str(run_dir/"cache")
                    elif __import__('sys').platform == "darwin": env["HOME"] = str(run_dir/"cache")
                    else: env["XDG_CACHE_HOME"] = str(run_dir/"cache")
                    before = server.metrics()["transferredBytes"]
                    cmd = [str(binary), "sync", "--manifest-url", server.url+"/manifest", "--pinned-public-key", key,
                        "--root", str(run_dir/"game")]
                    start = time.monotonic_ns()
                    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=240)
                    elapsed = time.monotonic_ns()-start
                    if result.returncode != 0:
                        raise RuntimeError(f"{label} run {round_id} failed: {result.stderr[-1200:]}")
                    for i, data_bytes in enumerate(data):
                        path = run_dir/"game"/"libraries"/"certification"/f"{i}.jar"
                        if not path.is_file() or hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(data_bytes).digest():
                            raise RuntimeError(f"{label} produced mismatched file {i}")
                    rows.append({"round":round_id, "implementation":label, "elapsedNs":elapsed,
                        "transferredBytes":server.metrics()["transferredBytes"]-before})
    baseline_times = [r["elapsedNs"] for r in rows if r["implementation"]=="baseline"]
    candidate_times = [r["elapsedNs"] for r in rows if r["implementation"]=="candidate"]
    base = statistics.median(baseline_times)
    newer = statistics.median(candidate_times)
    return {"id":"same-stand-benchmark", "status":"passed" if newer < base else "failed",
            "baseline":"compiled NeverLauncher 0.23.0; verified by supplied path",
            "baselineExecutableSha256":hashlib.sha256(baseline.read_bytes()).hexdigest(),
            "candidateExecutableSha256":hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "medianBaselineNs":base, "medianCandidateNs":newer,
            "speedup":round(base/newer, 3), "runs":rows,
            "note":"GravitLauncher comparison is not part of this measurement"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = bench(*[getattr(args, v).resolve() for v in ("baseline", "candidate", "signer")])
    # Only benchmark a committed source tree; bind published numbers to the
    # exact tested revision and to the compiled candidate binary.
    repository = Path(__file__).resolve().parents[2]
    rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, capture_output=True, text=True)
    clean = subprocess.run(["git", "status", "--porcelain"], cwd=repository, capture_output=True, text=True)
    if rev.returncode or clean.returncode or clean.stdout.strip() or not re.fullmatch(r"[0-9a-f]{40}",rev.stdout.strip()):
        raise RuntimeError("benchmark publication requires a clean Git HEAD")
    result.update(commit=rev.stdout.strip(),productVersion="0.24.0",gitTreeClean=True,simulated=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf8")
    print(json.dumps(result))
    if result["status"] != "passed": raise SystemExit(1)

if __name__ == "__main__":
    main()
