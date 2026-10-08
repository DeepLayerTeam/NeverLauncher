#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
EXPECTED = ["velocity","bungeecord","waterfall","bukkit","spigot","paper","purpur","folia","fabric","quilt","forge","neoforge","sponge","vanilla"]
ALLOWED_FAMILIES = {"proxy","bukkit","fabric","quilt","modloader","sponge","vanilla-sidecar"}
ALLOWED_ROLES = {"proxy","backend"}
ALLOWED_COVERAGE = {"runtime-e2e","build-compatibility","sidecar-rcon-e2e"}
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schemaVersion") != "1.0":
        raise SystemExit("ServerBridge цели schemaVersion должен быть 1.0")
    if str(data.get("productVersion", "")) != VERSION:
        raise SystemExit(f"ServerBridge цели productVersion должен equal VERSION={VERSION}")
    if data.get("protocolVersion") != 3:
        raise SystemExit("ServerBridge цели protocolVersion должен быть 3")
    rows = data.get("targets")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("ServerBridge цели должен быть non-пустой array")
    allowed = {"id","family","role","minecraft","coverage","required"}
    ids: list[str] = []
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise SystemExit(f"цель #{i} должен быть объект")
        unknown = set(row) - allowed
        if unknown:
            raise SystemExit(f"цель #{i} имеет неизвестный fields: {sorted(unknown)}")
        tid = str(row.get("id", "")).strip()
        if not ID_RE.fullmatch(tid):
            raise SystemExit(f"цель #{i}: недопустимый ID {tid!r}")
        if tid in ids:
            raise SystemExit(f"дубликат цель {tid}")
        ids.append(tid)
        if row.get("family") not in ALLOWED_FAMILIES or row.get("role") not in ALLOWED_ROLES:
            raise SystemExit(f"{tid}: недопустимый family/role")
        if row.get("coverage") not in ALLOWED_COVERAGE:
            raise SystemExit(f"{tid}: недопустимый покрытие")
        if str(row.get("minecraft", "")) != "1.21.1":
            raise SystemExit(f"{tid}: этот релиз матрица является закреплённый к Minecraft 1.21.1")
        if row.get("required") is not True:
            raise SystemExit(f"{tid}: обязательный должен быть true")
        if (row.get("role") == "proxy") != (row.get("family") == "proxy"):
            raise SystemExit(f"{tid}: прокси family/role несоответствие")
        expected_coverage = {"bukkit":"build-compatibility", "quilt":"build-compatibility", "sponge":"build-compatibility", "vanilla":"sidecar-rcon-e2e"}.get(tid, "runtime-e2e")
        if row.get("coverage") != expected_coverage:
            raise SystemExit(f"{tid}: ожидаемый покрытие {expected_coverage}, получил {row.get('coverage')}")
    if ids != EXPECTED:
        raise SystemExit(f"ServerBridge цель ordering/set несоответствие: {ids!r}")
    return data


def markdown(data: dict[str, Any]) -> str:
    lines = [
        f"# NeverLauncher {data['productVersion']} — Public ServerBridge Matrix",
        "",
        "> ServerBridge 3 GA compatibility matrix. Protocol v3 is frozen; Protocol v2 is compatibility/deprecation-only and must migrate with `nl server-bridge migrate-v3`. Runtime PASS evidence is produced by CI; Bukkit, Quilt and Sponge declare build-compatibility where CI cannot legally/practically redistribute a full target runtime; Vanilla is certified through the sidecar RCON harness.",
        "",
        "| Platform | Family | Role | Minecraft | Coverage | Protocol | v2 compatibility | Zero-patch | Node identity | One-time join | Handoff |",
        "|---|---|---|---|---|---:|---|---:|---:|---:|---:|",
    ]
    for row in data["targets"]:
        handoff = "source" if row["role"] == "proxy" else "target"
        lines.append(f"| `{row['id']}` | `{row['family']}` | `{row['role']}` | `{row['minecraft']}` | `{row['coverage']}` | 3 GA (frozen) | deprecated; migrate to v3 | yes | Ed25519 | yes | {handoff} |")
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
        print(f"ServerBridge публичная матрица OK: {len(data['targets'])} цели для {VERSION}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
