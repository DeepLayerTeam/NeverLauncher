#!/usr/bin/env python3
"""Return 0 only for a reproducible class of native macOS SDL 3 startup aborts.

This is a *retry eligibility* check, never a compatibility success check. A
second real client launch must pass the unchanged launcher certification.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_LOG_BYTES = 64 * 1024


def is_retryable(report_path: Path, client_root: Path) -> bool:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            return False
        if (
            report.get("status") != "failed"
            or report.get("success") is not False
            or report.get("timedOut") is not False
            or report.get("exitCode") is not None
            or report.get("detectedJavaMajor") != 25
        ):
            return False
        root = (client_root / "logs").resolve(strict=True)
        log_path = Path(report.get("logPath", ""))
        if not log_path.is_file() or log_path.is_symlink():
            return False
        path = log_path.resolve(strict=True)
        if not path.is_relative_to(root):
            return False
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - MAX_LOG_BYTES))
            tail = handle.read(MAX_LOG_BYTES).decode("utf-8", errors="replace")
        return (
            "SDL revision: SDL-3." in tail
            and "--- runtime exit --- code=None signal=Some(6)" in tail
            and "Guard fail-closed" not in tail
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--client-root", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if is_retryable(args.report, args.client_root) else 1)


if __name__ == "__main__":
    main()
