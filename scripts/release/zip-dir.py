#!/usr/bin/env python3
import argparse
import zipfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("source")
ap.add_argument("output")
ap.add_argument("--prefix", default="")
ns = ap.parse_args()
src = Path(ns.source).resolve()
out = Path(ns.output).resolve()
if not src.is_dir():
    raise SystemExit(f"directory missing: {src}")
out.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for path in sorted(src.rglob("*")):
        if path.is_symlink():
            raise SystemExit(f"symlink forbidden in release directory: {path}")
        if path.is_file():
            rel = path.relative_to(src).as_posix()
            arc = f"{ns.prefix.rstrip('/')}/{rel}" if ns.prefix else rel
            zf.write(path, arc)
print(out)
