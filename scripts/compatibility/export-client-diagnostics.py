#!/usr/bin/env python3
"""Export a bounded, redacted Minecraft launch failure trace for CI artifacts."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MAX_BYTES = 32 * 1024
MAX_LOGS = 3
MAX_NATIVE_REPORTS = 2

# Никогда не отправляйте клиентские журналы без удаления секретов: аргументы могут содержать действующие токены сеансов.
REDACTIONS = (
    (re.compile(r"(?i)(--(?:accessToken|token|refreshToken|clientToken|password|session)\s+)([^\s]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([\"']?(?:accessToken|refreshToken|clientToken|authorization|password|secret|api[-_]?key)[\"']?\s*[:=]\s*[\"']?)([^\s,;\"']+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+"), "Bearer [REDACTED]"),
)


def redacted_tail(path: Path) -> str:
    with path.open("rb") as handle:
        handle.seek(max(0, path.stat().st_size - MAX_BYTES))
        text = handle.read(MAX_BYTES).decode("utf-8", errors="replace")
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    # Нативные отчёты могут включать пользовательские имена и пути локальной установки.
    text = re.sub(r"/Users/[^/\s]+/", "/Users/[REDACTED]/", text)
    text = re.sub(r"(?i)[A-Z]:\\Users\\[^\\\s]+\\", r"C:\\Users\\[REDACTED]\\", text)
    return text


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
        output.append(f"--- certification {index}, last {MAX_BYTES} bytes ---")
        output.append(redacted_tail(path))

    # Нативные падения JVM иногда не оставляют ни Java-исключения, ни
    # stdout, особенно SDL 3 / AppKit в macOS. Собирайте ограниченный
    # отчёт HotSpot вместо пустого журнала. Не переходите по символическим
    # ссылкам и не выгружайте полные дампы процессов или core-файлы.
    client_dir = runtime / "materialized-client"
    native_reports: list[Path] = []
    if client_dir.is_dir() and not client_dir.is_symlink():
        native_reports.extend(client_dir.glob("hs_err_pid*.log"))
    if sys.platform == "darwin":
        mac_reports = Path.home() / "Library" / "Logs" / "DiagnosticReports"
        if mac_reports.is_dir() and not mac_reports.is_symlink():
            # Собирайте отчёты только этой изолированной CI-цели; не копируйте
            # старые пользовательские отчёты об ошибках с компьютера экспортёра.
            threshold = runtime.stat().st_mtime - 300 if runtime.exists() else 0
            native_reports.extend(
                p for pattern in ("java*.ips", "java*.crash", "Java*.ips", "Java*.crash")
                for p in mac_reports.glob(pattern)
                if p.is_file() and p.stat().st_mtime >= threshold
            )
    native_reports = [p for p in native_reports if p.is_file() and not p.is_symlink()]
    native_reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for index, path in enumerate(native_reports[:MAX_NATIVE_REPORTS], start=1):
        output.append(f"--- native crash report {index}, last {MAX_BYTES} bytes ---")
        output.append(redacted_tail(path))
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
