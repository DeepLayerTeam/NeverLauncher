#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
EXPECTED = [
    "velocity",
    "bungeecord",
    "waterfall",
    "bukkit",
    "spigot",
    "paper",
    "purpur",
    "folia",
    "fabric",
    "quilt",
    "forge",
    "neoforge",
    "sponge",
    "vanilla",
]
ALLOWED_FAMILIES = {
    "proxy",
    "bukkit",
    "fabric",
    "quilt",
    "modloader",
    "sponge",
    "vanilla-sidecar",
}
ALLOWED_ROLES = {"proxy", "backend"}
ALLOWED_COVERAGE = {"runtime-e2e", "build-compatibility", "sidecar-rcon-e2e"}
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schemaVersion") != "1.0":
        raise SystemExit("Для «ServerBridge targets schemaVersion» требуется: «1.0»")
    if str(data.get("productVersion", "")) != VERSION:
        raise SystemExit(
            f"ServerBridge targets productVersion must equal VERSION={VERSION}"
        )
    if data.get("protocolVersion") != 3:
        raise SystemExit("Для «ServerBridge targets protocolVersion» требуется: «3»")
    rows = data.get("targets")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("Для «ServerBridge targets» требуется: «a non-empty array»")
    allowed = {"id", "family", "role", "minecraft", "coverage", "required"}
    ids: list[str] = []
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise SystemExit(f"Для «target #{i}» требуется: объект")
        unknown = set(row) - allowed
        if unknown:
            raise SystemExit(f"target #{i} has unknown fields: {sorted(unknown)}")
        tid = str(row.get("id", "")).strip()
        if not ID_RE.fullmatch(tid):
            raise SystemExit(f"target #{i}: invalid id {tid!r}")
        if tid in ids:
            raise SystemExit(f"Обнаружен дубликат: цель {tid}")
        ids.append(tid)
        if (
            row.get("family") not in ALLOWED_FAMILIES
            or row.get("role") not in ALLOWED_ROLES
        ):
            raise SystemExit(f"{tid}: invalid family/role")
        if row.get("coverage") not in ALLOWED_COVERAGE:
            raise SystemExit(f"{tid}: invalid coverage")
        if str(row.get("minecraft", "")) != "1.21.1":
            raise SystemExit(
                f"{tid}: this release matrix is pinned to Minecraft 1.21.1"
            )
        if row.get("required") is not True:
            raise SystemExit(f"{tid}: required must be true")
        if (row.get("role") == "proxy") != (row.get("family") == "proxy"):
            raise SystemExit(f"{tid}: proxy family/role mismatch")
        expected_coverage = {
            "bukkit": "build-compatibility",
            "quilt": "build-compatibility",
            "sponge": "build-compatibility",
            "vanilla": "sidecar-rcon-e2e",
        }.get(tid, "runtime-e2e")
        if row.get("coverage") != expected_coverage:
            raise SystemExit(
                f"{tid}: expected coverage {expected_coverage}, got {row.get('coverage')}"
            )
    if ids != EXPECTED:
        raise SystemExit(f"Несовпадение: «ServerBridge target ordering/set»: {ids!r}")
    return data


def markdown(data: dict[str, Any]) -> str:
    lines = [
        f"# Launcher {data['productVersion']} — публичная матрица ServerBridge",
        "",
        "> Матрица совместимости ServerBridge 3 GA. Протокол v3 зафиксирован; v2 поддерживается только для совместимости и подлежит миграции командой `nl server-bridge migrate-v3`. Свидетельства PASS при выполнении Runtime формируются в CI. Для Bukkit, Quilt и Sponge указывается совместимость сборки там, где полный целевой Runtime нельзя законно или практически распространять через CI. Vanilla сертифицируется через внешний компонент с RCON.",
        "",
        "| Платформа | Семейство | Роль | Minecraft | Охват | Протокол | Совместимость с v2 | Без патчей | Идентичность узла | Одноразовый вход | Передача управления |",
        "|---|---|---|---|---|---:|---|---:|---:|---:|---:|",
    ]
    for row in data["targets"]:
        handoff = "источник" if row["role"] == "proxy" else "цель"
        lines.append(
            f"| `{row['id']}` | `{row['family']}` | `{row['role']}` | `{row['minecraft']}` | `{row['coverage']}` | 3 GA (зафиксирован) | устарел; переходите на v3 | да | Ed25519 | да | {handoff} |"
        )
    lines += [
        "",
        "Состояние Runtime не прописано в документе вручную: свидетельства CI привязаны к точным коммиту и запуску.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--targets", type=Path, default=ROOT / "serverbridge/targets.json")
    r = sub.add_parser("render")
    r.add_argument("--targets", type=Path, default=ROOT / "serverbridge/targets.json")
    r.add_argument("--out", type=Path, default=ROOT / "serverbridge/MATRIX.md")
    args = ap.parse_args()
    data = load(args.targets)
    if args.cmd == "render":
        args.out.write_text(markdown(data), encoding="utf-8")
        print(args.out)
    else:
        print(
            f"ServerBridge public matrix OK: {len(data['targets'])} targets for {VERSION}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
