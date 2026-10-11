#!/usr/bin/env python3
"""Export a bounded, redacted Minecraft launch failure trace for CI artifacts."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

MAX_BYTES = 32 * 1024
MAX_LOGS = 3

# Never upload unredacted client logs: arguments may contain live session tokens.
REDACTIONS = (
    (re.compile(r"(?i)(--(?:accessToken|token|refreshToken|clientToken|password|session)\s+)([^\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([\"']?(?:accessToken|refreshToken|clientToken|authorization|password|secret|api[-_]?key)[\"']?\s*[:=]\s*[\"']?)([^\s,;\"']+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+"), "Bearer [REDACTED]"),
)


def export(runtime: Path, destination: Path) -> None:
    runtime = runtime.resolve()
    candidate_dir = runtime / "materialized-client" / "logs"
    found: list[Path] = []
    if candidate_dir.is_dir() and not candidate_dir.is_symlink():
        found = [p for p in candidate_dir.glob("neverruntime-vanilla-certification-*.log")
                 if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(candidate_dir.resolve())]
    found.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    output = ["Minecraft client diagnostics (bounded and redacted; no unfiltered logs)"]
    if not found:
        output.append("No certification log has been written (failure may predate JVM launch).")
    for index, path in enumerate(found[:MAX_LOGS], start=1):
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - MAX_BYTES))
            raw = handle.read(MAX_BYTES)
        text = raw.decode("utf-8", errors="replace")
        for pattern, replacement in REDACTIONS:
            text = pattern.sub(replacement, text)
        output.append(f"--- certification {index}, last {MAX_BYTES} bytes ---")
        output.append(text)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(output) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    export(args.runtime, args.output)


if __name__ == "__main__":
    main()
