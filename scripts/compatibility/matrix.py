#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_LOADERS = {"vanilla", "fabric", "quilt", "forge", "neoforge"}
ALLOWED_OS = {"linux"}
ALLOWED_ARCH = {"x86_64"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
MUTABLE_SELECTORS = {"latest", "latest-stable", "stable", "recommended"}
ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def die(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"{path}: invalid JSON: {exc}")


def load_targets(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        die("targets document must be an object")
    if payload.get("schemaVersion") != "1.0":
        die("targets schemaVersion must be 1.0")
    declared_version = str(payload.get("productVersion", "")).strip()
    if declared_version and declared_version != PRODUCT_VERSION:
        die(f"targets productVersion {declared_version!r} does not match VERSION={PRODUCT_VERSION}")
    product_version = PRODUCT_VERSION
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows:
        die("targets must contain a non-empty array")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    allowed_target_keys = {"id", "minecraft", "loader", "loaderVersion", "os", "arch", "required"}
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            die(f"target #{index + 1} must be an object")
        unknown = sorted(set(raw) - allowed_target_keys)
        if unknown:
            die(f"target #{index + 1}: unknown fields are forbidden: {', '.join(unknown)}")
        target_id = str(raw.get("id", "")).strip()
        minecraft = str(raw.get("minecraft", "")).strip()
        loader = str(raw.get("loader", "")).strip().lower()
        selector = str(raw.get("loaderVersion", "")).strip()
        os_name = str(raw.get("os", "")).strip().lower()
        arch = str(raw.get("arch", "")).strip().lower()
        required = raw.get("required")
        if not ID_RE.fullmatch(target_id):
            die(f"target #{index + 1}: invalid id {target_id!r}")
        if target_id in seen:
            die(f"duplicate target id: {target_id}")
        seen.add(target_id)
        if not VERSION_RE.fullmatch(minecraft):
            die(f"{target_id}: invalid Minecraft version")
        if loader not in ALLOWED_LOADERS:
            die(f"{target_id}: unsupported loader {loader}")
        if loader == "vanilla" and selector:
            die(f"{target_id}: Vanilla target cannot specify loaderVersion")
        if loader != "vanilla" and not selector:
            die(f"{target_id}: loaderVersion is required")
        if selector and not VERSION_RE.fullmatch(selector):
            die(f"{target_id}: invalid loaderVersion")
        if os_name not in ALLOWED_OS:
            die(f"{target_id}: unsupported CI OS {os_name}")
        if arch not in ALLOWED_ARCH:
            die(f"{target_id}: unsupported CI architecture {arch}")
        if not isinstance(required, bool):
            die(f"{target_id}: required must be boolean")
        normalized.append({
            "id": target_id,
            "minecraft": minecraft,
            "loader": loader,
            "loaderVersion": selector,
            "os": os_name,
            "arch": arch,
            "required": required,
        })
    return {"schemaVersion": "1.0", "productVersion": product_version, "targets": normalized}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_validate(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(f"Compatibility targets OK: {len(payload['targets'])} targets for {payload['productVersion']}")
    return 0


def command_plan(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(json.dumps({"include": payload["targets"]}, separators=(",", ":")))
    return 0


def discover_results(root: Path) -> tuple[dict[str, tuple[Path, dict[str, Any]]], list[str]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    errors: list[str] = []
    for path in sorted(root.rglob("compatibility-result.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: invalid result JSON: {exc}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{path}: result must be an object")
            continue
        target_id = str(payload.get("targetId", "")).strip()
        if not ID_RE.fullmatch(target_id):
            errors.append(f"{path}: invalid targetId")
            continue
        if target_id in found:
            errors.append(f"duplicate compatibility result for {target_id}")
            continue
        found[target_id] = (path, payload)
    return found, errors


def verify_result(target: dict[str, Any], result: dict[str, Any], *, commit: str, run_id: str) -> list[str]:
    errors: list[str] = []
    expected = {
        "schemaVersion": "1.0",
        "targetId": target["id"],
        "productVersion": None,
        "minecraftVersion": target["minecraft"],
        "loader": target["loader"],
        "os": target["os"],
        "arch": target["arch"],
        "commit": commit,
        "runId": run_id,
    }
    for key, value in expected.items():
        if value is not None and str(result.get(key, "")) != str(value):
            errors.append(f"{key}: expected {value!r}, got {result.get(key)!r}")
    selector = str(result.get("loaderSelector", ""))
    if selector != target["loaderVersion"]:
        errors.append(f"loaderSelector mismatch: {selector!r}")
    resolved = str(result.get("resolvedLoaderVersion", ""))
    if target["loader"] == "vanilla":
        if resolved:
            errors.append("Vanilla result must not have resolvedLoaderVersion")
    else:
        if not resolved or resolved.lower() in MUTABLE_SELECTORS:
            errors.append("loader result did not resolve to a concrete immutable version")
    checks = result.get("checks")
    if not isinstance(checks, dict):
        errors.append("checks is missing")
    else:
        mandatory = ["actualClient", "packageVerified", "signedManifest", "cleanSync", "paperJoin", "sessionRevokeDeny", "paperHealthy"]
        for key in mandatory:
            if checks.get(key) is not True:
                errors.append(f"check {key} is not true")
    if result.get("exitCode") != 0:
        errors.append(f"exitCode is {result.get('exitCode')!r}")
    evidence = result.get("evidence")
    if not isinstance(evidence, dict):
        errors.append("evidence is missing")
    else:
        if str(evidence.get("manifestLoader", "")) != target["loader"]:
            errors.append("evidence manifestLoader mismatch")
        files = evidence.get("files")
        mandatory_files = {
            "result.json", "materialized-client-verify.json", "manifest.json", "runtime-verify.json",
            "runtime-sync.json", "runtime-launch-minecraft.json", "health-paper.json", "bridge-diagnostics.json",
        }
        if not isinstance(files, list) or not mandatory_files.issubset({str(value) for value in files}):
            errors.append("evidence files are incomplete")
    if result.get("status") != "passed":
        errors.append(f"status is {result.get('status')!r}")
    return errors


def render_markdown(product_version: str, targets: list[dict[str, Any]], records: dict[str, dict[str, Any]], commit: str, run_id: str, repository: str) -> str:
    lines = [
        f"# NeverLauncher {product_version} — CI Compatibility Matrix",
        "",
        "> Матрица сгенерирована автоматически из фактических E2E-результатов. Статусы PASS не хранятся и не редактируются вручную.",
        "",
        "| Target | Minecraft | Loader | Resolved loader | OS / arch | Actual client | Paper join | Paper health | Result |",
        "|---|---|---|---|---|---:|---:|---:|---:|",
    ]
    for target in targets:
        record = records.get(target["id"], {})
        checks = record.get("checks") if isinstance(record.get("checks"), dict) else {}
        status = "✅ PASS" if record.get("status") == "passed" else "❌ FAIL"
        resolved = str(record.get("resolvedLoaderVersion") or "—")
        lines.append(
            f"| `{target['id']}` | `{target['minecraft']}` | `{target['loader']}` | `{resolved}` | "
            f"`{target['os']}/{target['arch']}` | {'✅' if checks.get('actualClient') is True else '❌'} | "
            f"{'✅' if checks.get('paperJoin') is True else '❌'} | "
            f"{'✅' if checks.get('paperHealthy') is True else '❌'} | {status} |"
        )
    lines += [
        "",
        f"Commit: `{commit}`  ",
        f"GitHub Actions run: `{run_id}`  ",
        f"Repository: `{repository}`",
        "",
        "Проверяемый путь каждого PASS: materialize → local SHA-256 verify → canonical API upload → immutable Ed25519 release → clean NeverRuntime sync → actual Minecraft client under Xvfb → Paper world join → session revoke → fail-closed deny.",
        "",
    ]
    return "\n".join(lines)


def command_aggregate(args: argparse.Namespace) -> int:
    targets_doc = load_targets(args.targets)
    targets = targets_doc["targets"]
    results, discovery_errors = discover_results(args.results_root)
    errors: list[str] = list(discovery_errors)
    records: dict[str, dict[str, Any]] = {}
    allowed_ids = {target["id"] for target in targets}
    extras = sorted(set(results) - allowed_ids)
    if extras:
        errors.append("unexpected result targets: " + ", ".join(extras))
    for target in targets:
        target_id = target["id"]
        if target_id not in results:
            if target["required"]:
                errors.append(f"missing required result: {target_id}")
            records[target_id] = {"status": "missing", "checks": {}}
            continue
        path, result = results[target_id]
        product_version = str(result.get("productVersion", ""))
        if product_version != targets_doc["productVersion"]:
            errors.append(f"{target_id}: productVersion expected {targets_doc['productVersion']}, got {product_version}")
        result_errors = verify_result(target, result, commit=args.commit, run_id=args.run_id)
        result = dict(result)
        if result_errors:
            errors.extend(f"{target_id}: {message}" for message in result_errors)
            result["status"] = "invalid"
            result["validationErrors"] = result_errors
        result["evidenceSha256"] = sha256_file(path)
        records[target_id] = result

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    matrix = {
        "schemaVersion": "1.0",
        "productVersion": targets_doc["productVersion"],
        "generatedAt": generated_at,
        "repository": args.repository,
        "commit": args.commit,
        "runId": args.run_id,
        "status": "passed" if not errors else "failed",
        "targets": [records[target["id"]] for target in targets],
        "errors": errors,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "matrix.json"
    md_path = args.output_dir / "matrix.md"
    json_path.write_text(json.dumps(matrix, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(targets_doc["productVersion"], targets, records, args.commit, args.run_id, args.repository), encoding="utf-8")
    print(md_path.read_text(encoding="utf-8"))
    if errors:
        print("Compatibility matrix validation failed:", file=sys.stderr)
        for message in errors:
            print(f"- {message}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--targets", type=Path, default=Path("compatibility/targets.json"))
    validate.set_defaults(func=command_validate)

    plan = sub.add_parser("plan")
    plan.add_argument("--targets", type=Path, default=Path("compatibility/targets.json"))
    plan.set_defaults(func=command_plan)

    aggregate = sub.add_parser("aggregate")
    aggregate.add_argument("--targets", type=Path, default=Path("compatibility/targets.json"))
    aggregate.add_argument("--results-root", type=Path, required=True)
    aggregate.add_argument("--output-dir", type=Path, required=True)
    aggregate.add_argument("--commit", required=True)
    aggregate.add_argument("--run-id", required=True)
    aggregate.add_argument("--repository", required=True)
    aggregate.set_defaults(func=command_aggregate)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
