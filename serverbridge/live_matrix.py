#!/usr/bin/env python3
"""Fail-closed *runtime* certification of ServerBridge 0.41.13.

Reads evidence written while a real Docker JVM is running, plus independently
persisted network probes and unmodified runtime logs. Build-only, unit and
client-only certifications never satisfy this gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# These runtimes are exercised by run-minecraft-e2e.sh in full mode. Other
# required target IDs remain non-certified until a real server/proxy integration
# runner emits equally strong evidence. Do NOT equate API-compatible with live.
CORE = {
    "velocity": ("velocity-e2e-p3", 25570),
    "bungeecord": ("bungeecord-e2e-p3", 25575),
    "waterfall": ("waterfall-e2e-p3", 25576),
    "spigot": ("spigot-e2e-p3", 25573),
    "paper": ("paper-e2e-p3", 25571),
    "purpur": ("purpur-e2e-p3", 25572),
    "folia": ("folia-e2e-p3", 25574),
    "fabric": ("fabric-e2e-p3", 25577),
    "forge": ("forge-e2e-p3", 25578),
    "neoforge": ("neoforge-e2e-p3", 25579),
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def read_json(path: Path):
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"{path.name}: expected JSON object")
    return obj


def checksum(path: Path, expected: str) -> None:
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise ValueError(f"{path.name}: invalid expected SHA-256")
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"{path.name}: missing or altered evidence")


def verify_runtime(
    service: str,
    target: dict,
    runtime: Path,
    version: str,
    player: str,
    root: Path | None = None,
) -> dict:
    if service not in CORE:
        raise ValueError(
            "no native server-side live runner (client/compile tests do not qualify)"
        )
    node_id, port = CORE[service]
    proof = read_json(runtime / f"live-{service}-04113.json")
    if proof.get("schemaVersion") != "1.0" or proof.get("productVersion") != version:
        raise ValueError("product version mismatch")
    if (proof.get("service"), proof.get("nodeId"), proof.get("minecraftPort")) != (
        service,
        node_id,
        port,
    ):
        raise ValueError("wrong server/node/port identity")
    jar = ROOT if root is None else root  # use requested source checkout
    jar = jar / "artifacts/plugins" / f"launcher-{service}-bridge-{version}.jar"
    observed_digest = proof.get("bridgeJarSha256")
    if not isinstance(observed_digest, str) or not HEX64.fullmatch(observed_digest):
        raise ValueError("missing exact deployed ServerBridge JAR digest")
    if jar.is_symlink() or not jar.is_file() or jar.stat().st_size == 0:
        raise ValueError("missing exact built ServerBridge JAR")
    checksum(jar, observed_digest)
    meta = proof.get("runtime") or {}
    if (
        not isinstance(meta.get("containerId"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", meta["containerId"])
        or not isinstance(meta.get("imageId"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", meta["imageId"])
        or type(meta.get("hostJavaPid")) is not int
        or meta["hostJavaPid"] < 2
        or type(meta.get("javaMajor")) is not int
        or meta["javaMajor"] < 21
        or meta.get("health") != "healthy"
        or not isinstance(meta.get("startedAt"), str)
        or not meta["startedAt"]
    ):
        raise ValueError("missing real container / JVM process identity")
    observations = proof.get("observations") or {}
    if not all(
        observations.get(field) is True
        for field in (
            "signedBridgeHeartbeat",
            "allowAfterNetworkProbe",
            "denyAfterRevocation",
        )
    ):
        raise ValueError(
            "missing platform observation after real network join/revocation"
        )
    if service == "paper" and observations.get("actualClientJoin") is not True:
        raise ValueError("Paper actual Mojang JVM client join not confirmed")
    log_ref = proof.get("log") or {}
    log_file = log_ref.get("path")
    if log_file != f"live-{service}-04113.log":
        raise ValueError("runtime log reference mismatch")
    checksum(runtime / log_file, log_ref.get("sha256"))
    log = (runtime / log_file).read_text(encoding="utf-8")
    allow = f"launcher.join.allowed username={player}"
    deny = f"launcher.join.denied username={player}"
    if (
        not re.search(r"Launcher .* Bridge .*heartbeat=true", log, re.I)
        or allow not in log
        or deny not in log
        or log.index(deny) <= log.index(allow)
    ):
        raise ValueError(
            "Bridge platform log does not confirm join and subsequent revoke"
        )
    if service == "paper" and f"{player} joined the game" not in log:
        raise ValueError("Paper log lacks real player join")
    probes = proof.get("probes") or {}
    for kind in ("allow", "deny"):
        ref = probes.get(kind) or {}
        path = (
            (
                "runtime-launch-minecraft.json"
                if kind == "allow"
                else "probe-paper-deny.txt"
            )
            if service == "paper"
            else f"probe-{node_id}-{kind}.txt"
        )
        if ref.get("path") != path:
            raise ValueError(f"{kind}: wrong probe reference")
        checksum(runtime / path, ref.get("sha256"))
        actual_probe = (runtime / path).read_text(encoding="utf-8")
        if service == "paper" and kind == "allow":
            launch = json.loads(actual_probe)
            if launch.get("success") is not True and launch.get("timedOut") is not True:
                raise ValueError("Paper Mojang client was not actually launched")
        elif (
            f"port={port} username={player} " not in actual_probe
            or "probe host=" not in actual_probe
        ):
            raise ValueError(f"{kind}: wrong network probe")
    # Native log/health/probes corroborate each other. A status field alone is
    # *never* accepted as proof of a real JVM/platform run.
    return {
        "status": "passed",
        "kind": "real-jvm-and-game-protocol",
        "serverVersion": target.get("minecraft"),
        "containerId": meta["containerId"],
        "imageId": meta["imageId"],
        "javaMajor": meta["javaMajor"],
        "bridgeJarSha256": observed_digest,
        "evidenceFile": f"live-{service}-04113.json",
    }


def certify(
    root: Path, runtime: Path, scope: str = "all", player: str = "E2EPlayer"
) -> dict:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    targets = read_json(root / "serverbridge/targets.json")
    if targets.get("productVersion") != version:
        raise ValueError("targets version drift")
    ids = [r["id"] for r in targets.get("targets") or []]
    if (
        len(ids) != 14
        or len(set(ids)) != 14
        or set(ids) != set(CORE) | {"bukkit", "quilt", "sponge", "vanilla"}
    ):
        raise ValueError("unexpected/incomplete ServerBridge target matrix")
    outcome = {
        "productVersion": version,
        "schemaVersion": "1.0",
        "scope": scope,
        "targetCount": len(ids),
        "cases": {},
        "status": "incomplete",
    }
    result = None
    try:
        result = read_json(runtime / "result.json")
        if (
            result.get("version") != version
            or result.get("mode") != "full"
            or result.get("status") != "passed"
        ):
            raise ValueError(
                "full-stack Minecraft E2E result is missing or unsuccessful"
            )
    except (OSError, ValueError) as exc:
        result = None
        outcome["e2eError"] = str(exc)
    for target in targets["targets"]:
        name = target["id"]
        if name not in CORE and scope == "core":
            outcome["cases"][name] = {
                "status": "not-certified",
                "reason": "not included in core runtime suite",
            }
            continue
        if result is None:
            outcome["cases"][name] = {
                "status": "not-certified",
                "reason": "full E2E not passed",
            }
            continue
        try:
            outcome["cases"][name] = verify_runtime(
                name, target, runtime, version, player, root
            )
        except (ValueError, KeyError, OSError, TypeError) as exc:
            outcome["cases"][name] = {"status": "not-certified", "reason": str(exc)}
    needed = list(CORE) if scope == "core" else ids
    if result is not None and all(
        outcome["cases"][name]["status"] == "passed" for name in needed
    ):
        outcome["status"] = (
            "passed" if scope == "all" else "core-passed-not-full-matrix"
        )
    outcome["passedCount"] = sum(
        c["status"] == "passed" for c in outcome["cases"].values()
    )
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--runtime", type=Path, default=ROOT / "e2e/runtime")
    parser.add_argument("--scope", choices=("all", "core"), default="all")
    parser.add_argument("--player", default="E2EPlayer")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = certify(args.root, args.runtime, args.scope, args.player)
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.out.with_suffix(".tmp")
        tmp.write_text(output, encoding="utf-8")
        tmp.replace(args.out)
    print(output)
    return 0 if result["status"] in ("passed", "core-passed-not-full-matrix") else 1


if __name__ == "__main__":
    sys.exit(main())
