#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
EXPECTED = ["velocity","bungeecord","waterfall","bukkit","spigot","paper","purpur","folia","fabric","forge","neoforge"]
ALLOWED_FAMILIES = {"proxy","bukkit","fabric","modloader"}
ALLOWED_ROLES = {"proxy","backend"}
ALLOWED_COVERAGE = {"runtime-e2e","build-compatibility"}
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schemaVersion") != "1.0":
        raise SystemExit("ServerBridge targets schemaVersion must be 1.0")
    if str(data.get("productVersion", "")) != VERSION:
        raise SystemExit(f"ServerBridge targets productVersion must equal VERSION={VERSION}")
    if data.get("protocolVersion") != 2:
        raise SystemExit("ServerBridge targets protocolVersion must be 2")
    rows = data.get("targets")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("ServerBridge targets must be a non-empty array")
    allowed = {"id","family","role","minecraft","coverage","required"}
    ids: list[str] = []
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise SystemExit(f"target #{i} must be an object")
        unknown = set(row) - allowed
        if unknown:
            raise SystemExit(f"target #{i} has unknown fields: {sorted(unknown)}")
        tid = str(row.get("id", "")).strip()
        if not ID_RE.fullmatch(tid):
            raise SystemExit(f"target #{i}: invalid id {tid!r}")
        if tid in ids:
            raise SystemExit(f"duplicate target {tid}")
        ids.append(tid)
        if row.get("family") not in ALLOWED_FAMILIES or row.get("role") not in ALLOWED_ROLES:
            raise SystemExit(f"{tid}: invalid family/role")
        if row.get("coverage") not in ALLOWED_COVERAGE:
            raise SystemExit(f"{tid}: invalid coverage")
        if str(row.get("minecraft", "")) != "1.21.1":
            raise SystemExit(f"{tid}: this release matrix is pinned to Minecraft 1.21.1")
        if row.get("required") is not True:
            raise SystemExit(f"{tid}: required must be true")
        if (row.get("role") == "proxy") != (row.get("family") == "proxy"):
            raise SystemExit(f"{tid}: proxy family/role mismatch")
        if tid == "bukkit" and row.get("coverage") != "build-compatibility":
            raise SystemExit("bukkit must transparently declare build-compatibility coverage")
        if tid != "bukkit" and row.get("coverage") != "runtime-e2e":
            raise SystemExit(f"{tid}: supported runtime target must declare runtime-e2e")
    if ids != EXPECTED:
        raise SystemExit(f"ServerBridge target ordering/set mismatch: {ids!r}")
    return data


def markdown(data: dict[str, Any]) -> str:
    lines = [
        f"# NeverLauncher {data['productVersion']} — Public ServerBridge Matrix",
        "",
        "> Capability matrix. Runtime PASS evidence is produced by CI; the Bukkit row is intentionally marked build-compatibility because the release CI does not redistribute a CraftBukkit runtime.",
        "",
        "| Platform | Family | Role | Minecraft | Coverage | Protocol | Zero-patch | Node identity | One-time join | Handoff |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in data["targets"]:
        handoff = "source" if row["role"] == "proxy" else "target"
        lines.append(f"| `{row['id']}` | `{row['family']}` | `{row['role']}` | `{row['minecraft']}` | `{row['coverage']}` | 2 | yes | Ed25519 | yes | {handoff} |")
    lines += ["", "Runtime status is not hard-coded into this document; CI evidence is attached to the exact commit/run.", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate"); v.add_argument("--targets", type=Path, default=ROOT / "serverbridge/targets.json")
    r = sub.add_parser("render"); r.add_argument("--targets", type=Path, default=ROOT / "serverbridge/targets.json"); r.add_argument("--out", type=Path, default=ROOT / "serverbridge/MATRIX.md")
    args = ap.parse_args()
    data = load(args.targets)
    if args.cmd == "render":
        args.out.write_text(markdown(data), encoding="utf-8")
        print(args.out)
    else:
        print(f"ServerBridge public matrix OK: {len(data['targets'])} targets for {VERSION}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
