#!/usr/bin/env python3
import argparse
from canonical_zip_0461 import write_zip
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("source")
ap.add_argument("output")
ap.add_argument("--prefix", default="")
ns = ap.parse_args()
src = Path(ns.source).resolve()
out = Path(ns.output).resolve()
if not src.is_dir():
    raise SystemExit(f"Отсутствует: каталог: {src}")
out.parent.mkdir(parents=True, exist_ok=True)
if out.is_relative_to(src):
    raise SystemExit("release directory ZIP output: требуется «вне исходного каталога»")
members = []
for path in sorted(src.rglob("*")):
    if path.is_symlink():
        raise SystemExit(f"Символические ссылки запрещены в каталоге релиза: {path}")
    if path.is_file():
        rel = path.relative_to(src).as_posix()
        arc = f"{ns.prefix.rstrip('/')}/{rel}" if ns.prefix else rel
        members.append((rel, arc))
write_zip(src, out, members)
print(out)
