#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_LOADERS = {"vanilla", "fabric", "quilt", "forge", "neoforge"}
ALLOWED_OS = {"linux", "windows", "macos"}
ALLOWED_ARCH = {"x86_64", "aarch64"}
ALLOWED_SCOPES = {"client", "integration"}
ALLOWED_JAVA_MAJORS = {8, 16, 17, 21, 25}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
MUTABLE_SELECTORS = {"latest", "latest-stable", "stable", "recommended"}
ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

VANILLA_BASELINE_II: dict[str, tuple[int, str]] = {
    "1.7.10": (8, "client"),
    "1.12.2": (8, "client"),
    "1.16.5": (8, "client"),
    "1.17.1": (16, "client"),
    "1.18.2": (17, "client"),
    "1.20.4": (17, "client"),
    "1.20.6": (21, "client"),
    "1.21.1": (21, "integration"),
}

LEGACY_VANILLA_JAVA8_0163: tuple[str, ...] = (
    "1.7.10", "1.8.9", "1.9.4", "1.10.2", "1.11.2",
    "1.12.2", "1.13.2", "1.14.4", "1.15.2", "1.16.5",
)

LEGACY_VANILLA_PRE17_0164: tuple[str, ...] = (
    "1.0", "1.1", "1.2.5", "1.3.2", "1.4.7", "1.5.2", "1.6.4", "1.7.10",
)

JAVA16_17_VANILLA_0166: dict[str, int] = {
    "1.17.1": 16,
    "1.18.2": 17,
    "1.19.4": 17,
    "1.20.1": 17,
    "1.20.2": 17,
    "1.20.4": 17,
}

JAVA21_VANILLA_0167: tuple[str, ...] = (
    "1.20.5", "1.20.6", "1.21", "1.21.1", "1.21.2", "1.21.3",
    "1.21.4", "1.21.5", "1.21.6", "1.21.7", "1.21.8", "1.21.9", "1.21.10",
)

JAVA25_VANILLA_0168: tuple[str, ...] = (
    "26.1", "26.1.1", "26.1.2", "26.3",
)

CROSS_PLATFORM_VANILLA_0169: tuple[tuple[str, str], ...] = (
    ("linux", "x86_64"),
    ("linux", "aarch64"),
    ("windows", "x86_64"),
    ("windows", "aarch64"),
    ("macos", "x86_64"),
    ("macos", "aarch64"),
)

ACTUAL_CLIENT_E2E_II_01610: dict[str, int] = {
    "1.7.10": 8,
    "1.17.1": 16,
    "1.20.4": 17,
    "1.21.10": 21,
    "26.3": 25,
}


def die(message: str) -> None:
    raise SystemExit(message)


def semver_core(value: str) -> tuple[int, int, int]:
    core = value.split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) < 3:
        return (0, 0, 0)
    try:
        return tuple(int(part) for part in parts[:3])  # type: ignore[return-value]
    except ValueError:
        return (0, 0, 0)


def vanilla_baseline_ii_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 2)


def legacy_vanilla_java8_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 3)

def legacy_vanilla_pre17_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 4)


def java16_17_vanilla_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 6)


def java21_vanilla_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 7)


def java25_vanilla_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 8)


def cross_platform_vanilla_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 9)


def actual_client_e2e_ii_required() -> bool:
    return semver_core(PRODUCT_VERSION) >= (0, 16, 10)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"{path}: invalid JSON: {exc}")


def validate_baseline_ii(targets: list[dict[str, Any]]) -> None:
    if not vanilla_baseline_ii_required():
        return
    required_loaders = {target["loader"] for target in targets if target["required"]}
    missing_loaders = sorted(ALLOWED_LOADERS - required_loaders)
    if missing_loaders:
        die("Compatibility 0.16.2+ missing required loader families: " + ", ".join(missing_loaders))
    required_vanilla = {
        target["minecraft"]: target
        for target in targets
        if target["loader"] == "vanilla" and target["required"]
    }
    for minecraft, (java_major, scope) in VANILLA_BASELINE_II.items():
        target = required_vanilla.get(minecraft)
        if target is None:
            die(f"Vanilla Compatibility Baseline II missing required Minecraft {minecraft}")
        if target["javaMajor"] != java_major:
            die(f"Vanilla {minecraft}: Baseline II requires Java {java_major}")
        if target["scope"] != scope:
            die(f"Vanilla {minecraft}: Baseline II requires scope={scope}")
    java_coverage = {target["javaMajor"] for target in required_vanilla.values()}
    required_java = {8, 16, 17, 21}
    if not required_java.issubset(java_coverage):
        die(f"Vanilla Compatibility Baseline II requires Java coverage {sorted(required_java)}")
    if legacy_vanilla_java8_required():
        for minecraft in LEGACY_VANILLA_JAVA8_0163:
            target = required_vanilla.get(minecraft)
            if target is None:
                die(f"Legacy Vanilla 0.16.3 missing required Minecraft {minecraft}")
            if target["javaMajor"] != 8 or target["scope"] != "client":
                die(f"Legacy Vanilla {minecraft}: 0.16.3 requires Java 8 scope=client")
    if legacy_vanilla_pre17_required():
        for minecraft in LEGACY_VANILLA_PRE17_0164:
            target = required_vanilla.get(minecraft)
            if target is None:
                die(f"Legacy Vanilla 0.16.4 missing required Minecraft {minecraft}")
            if target["javaMajor"] != 8 or target["scope"] != "client":
                die(f"Legacy Vanilla {minecraft}: 0.16.4 requires Java 8 scope=client")
    if java16_17_vanilla_required():
        for minecraft, java_major in JAVA16_17_VANILLA_0166.items():
            target = required_vanilla.get(minecraft)
            if target is None:
                die(f"Java 16/17 Vanilla 0.16.6 missing required Minecraft {minecraft}")
            if target["javaMajor"] != java_major or target["scope"] != "client":
                die(f"Java 16/17 Vanilla {minecraft}: 0.16.6 requires Java {java_major} scope=client")
    if java21_vanilla_required():
        for minecraft in JAVA21_VANILLA_0167:
            target = required_vanilla.get(minecraft)
            if target is None:
                die(f"Java 21 Vanilla 0.16.7 missing required Minecraft {minecraft}")
            expected_scope = "integration" if minecraft == "1.21.1" else "client"
            if target["javaMajor"] != 21 or target["scope"] != expected_scope:
                die(f"Java 21 Vanilla {minecraft}: 0.16.7 requires Java 21 scope={expected_scope}")
    if java25_vanilla_required():
        for minecraft in JAVA25_VANILLA_0168:
            target = required_vanilla.get(minecraft)
            if target is None:
                die(f"Java 25 Vanilla 0.16.8 missing required Minecraft {minecraft}")
            if target["javaMajor"] != 25 or target["scope"] != "client":
                die(f"Java 25 Vanilla {minecraft}: 0.16.8 requires Java 25 scope=client")
    if cross_platform_vanilla_required():
        platform_targets = {
            (target["os"], target["arch"]): target
            for target in targets
            if target["loader"] == "vanilla" and target["required"] and target["minecraft"] == "26.3"
        }
        for os_name, arch in CROSS_PLATFORM_VANILLA_0169:
            target = platform_targets.get((os_name, arch))
            if target is None:
                die(f"Cross-platform Vanilla 0.16.9 missing required 26.3 target {os_name}/{arch}")
            if target["javaMajor"] != 25 or target["scope"] != "client":
                die(f"Cross-platform Vanilla 26.3 {os_name}/{arch}: 0.16.9 requires Java 25 scope=client")
    if actual_client_e2e_ii_required():
        for minecraft, java_major in ACTUAL_CLIENT_E2E_II_01610.items():
            matching = [
                target for target in targets
                if target["required"] and target["loader"] == "vanilla" and target["minecraft"] == minecraft
                and target["os"] == "linux" and target["arch"] == "x86_64" and target.get("matchingServer") is True
            ]
            if len(matching) != 1:
                die(f"Actual Client E2E II 0.16.10 requires one matching-server target for Minecraft {minecraft}")
            target = matching[0]
            if target["javaMajor"] != java_major or target["scope"] != "client":
                die(f"Actual Client E2E II {minecraft}: requires Java {java_major} scope=client on linux/x86_64")


def load_targets(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        die("targets document must be an object")
    if payload.get("schemaVersion") != "1.0":
        die("targets schemaVersion must be 1.0")
    declared_version = str(payload.get("productVersion", "")).strip()
    if declared_version and declared_version != PRODUCT_VERSION:
        die(f"targets productVersion {declared_version!r} does not match VERSION={PRODUCT_VERSION}")
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows:
        die("targets must contain a non-empty array")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    allowed_target_keys = {"id", "minecraft", "loader", "loaderVersion", "os", "arch", "javaMajor", "scope", "matchingServer", "required"}
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
        scope = str(raw.get("scope", "")).strip().lower()
        java_major = raw.get("javaMajor")
        required = raw.get("required")
        matching_server = raw.get("matchingServer", False)
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
        if not isinstance(java_major, int) or isinstance(java_major, bool) or java_major not in ALLOWED_JAVA_MAJORS:
            die(f"{target_id}: javaMajor must be one of {sorted(ALLOWED_JAVA_MAJORS)}")
        if scope not in ALLOWED_SCOPES:
            die(f"{target_id}: scope must be one of {sorted(ALLOWED_SCOPES)}")
        if scope == "client" and loader != "vanilla":
            die(f"{target_id}: client scope is allowed only for Vanilla")
        if not isinstance(required, bool):
            die(f"{target_id}: required must be boolean")
        if not isinstance(matching_server, bool):
            die(f"{target_id}: matchingServer must be boolean")
        if matching_server and not (loader == "vanilla" and scope == "client" and os_name == "linux" and arch == "x86_64"):
            die(f"{target_id}: matchingServer requires Vanilla client scope on linux/x86_64")
        normalized.append({
            "id": target_id,
            "minecraft": minecraft,
            "loader": loader,
            "loaderVersion": selector,
            "os": os_name,
            "arch": arch,
            "javaMajor": java_major,
            "scope": scope,
            "matchingServer": matching_server,
            "required": required,
        })
    validate_baseline_ii(normalized)
    return {"schemaVersion": "1.0", "productVersion": PRODUCT_VERSION, "targets": normalized}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_validate(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    vanilla = [target for target in payload["targets"] if target["loader"] == "vanilla"]
    java = sorted({target["javaMajor"] for target in vanilla})
    print(f"Compatibility targets OK: {len(payload['targets'])} targets for {payload['productVersion']}; Vanilla={len(vanilla)}; Java={java}")
    return 0


def runner_for_target(target: dict[str, Any]) -> str:
    key = (target["os"], target["arch"])
    runners = {
        ("linux", "x86_64"): "ubuntu-24.04",
        ("linux", "aarch64"): "ubuntu-24.04-arm",
        ("windows", "x86_64"): "windows-2025",
        ("windows", "aarch64"): "windows-11-arm",
        ("macos", "x86_64"): "macos-15-intel",
        ("macos", "aarch64"): "macos-15",
    }
    try:
        return runners[key]
    except KeyError:
        die(f"no GitHub-hosted runner mapping for {key[0]}/{key[1]}")


def java_distribution_for_target(target: dict[str, Any]) -> str:
    # Microsoft OpenJDK publishes Windows ARM64 for Java 25; Temurin remains
    # the default everywhere else. This affects CI certification only.
    if target["os"] == "windows" and target["arch"] == "aarch64" and target["javaMajor"] in {21, 25}:
        return "microsoft"
    return "temurin"


def command_plan(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    include = []
    for target in payload["targets"]:
        row = dict(target)
        row["runner"] = runner_for_target(target)
        row["javaDistribution"] = java_distribution_for_target(target)
        include.append(row)
    print(json.dumps({"include": include}, separators=(",", ":")))
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
        "minecraftVersion": target["minecraft"],
        "loader": target["loader"],
        "os": target["os"],
        "arch": target["arch"],
        "javaMajor": target["javaMajor"],
        "detectedJavaMajor": target["javaMajor"],
        "scope": target["scope"],
        "matchingServer": target.get("matchingServer", False),
        "commit": commit,
        "runId": run_id,
    }
    for key, value in expected.items():
        if str(result.get(key, "")) != str(value):
            errors.append(f"{key}: expected {value!r}, got {result.get(key)!r}")
    selector = str(result.get("loaderSelector", ""))
    if selector != target["loaderVersion"]:
        errors.append(f"loaderSelector mismatch: {selector!r}")
    resolved = str(result.get("resolvedLoaderVersion", ""))
    if target["loader"] == "vanilla":
        if resolved:
            errors.append("Vanilla result must not have resolvedLoaderVersion")
    elif not resolved or resolved.lower() in MUTABLE_SELECTORS:
        errors.append("loader result did not resolve to a concrete immutable version")

    checks = result.get("checks")
    mandatory = (
        ["materialized", "packageVerified", "runtimeResolved", "javaMatched", "platformMatched", "actualClient"]
        if target["scope"] == "client"
        else ["actualClient", "packageVerified", "signedManifest", "cleanSync", "paperJoin", "sessionRevokeDeny", "paperHealthy", "javaMatched", "platformMatched"]
    )
    if target.get("matchingServer") is True:
        mandatory = list(mandatory) + ["matchingServer", "serverVersionMatched", "serverHealthy", "clientJoinedServer"]
    if not isinstance(checks, dict):
        errors.append("checks is missing")
    else:
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
        runtime = evidence.get("javaRuntime")
        if not isinstance(runtime, dict) or runtime.get("matched") is not True or runtime.get("detectedMajor") != target["javaMajor"]:
            errors.append("evidence javaRuntime mismatch")
        platform_runtime = evidence.get("platformRuntime")
        if (not isinstance(platform_runtime, dict) or platform_runtime.get("matched") is not True
                or platform_runtime.get("detectedOS") != target["os"] or platform_runtime.get("detectedArch") != target["arch"]):
            errors.append("evidence platformRuntime mismatch")
        files = evidence.get("files")
        mandatory_files = (
            {"client-package.json", "materialized-client-verify.json", "vanilla-install.json", "vanilla-certification.json", "platform-runtime.json"}
            if target["scope"] == "client"
            else {
                "result.json", "materialized-client-verify.json", "manifest.json", "runtime-verify.json",
                "runtime-sync.json", "runtime-launch-minecraft.json", "health-paper.json", "bridge-diagnostics.json", "platform-runtime.json",
            }
        )
        if target.get("matchingServer") is True:
            mandatory_files = set(mandatory_files) | {"vanilla-server-install.json", "matching-server.json", "matching-server.log"}
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
        "| Target | Minecraft | Loader | Java | Scope | Actual client | Matching server | Paper join | Result |",
        "|---|---|---|---:|---|---:|---:|---:|---:|",
    ]
    for target in targets:
        record = records.get(target["id"], {})
        checks = record.get("checks") if isinstance(record.get("checks"), dict) else {}
        status = "✅ PASS" if record.get("status") == "passed" else "❌ FAIL"
        paper = "—" if target["scope"] == "client" else ("✅" if checks.get("paperJoin") is True else "❌")
        matching = "✅" if target.get("matchingServer") is True and checks.get("matchingServer") is True else ("—" if not target.get("matchingServer") else "❌")
        lines.append(
            f"| `{target['id']}` | `{target['minecraft']}` | `{target['loader']}` | `{target['javaMajor']}` | `{target['scope']}` | "
            f"{'✅' if checks.get('actualClient') is True else '❌'} | {matching} | {paper} | {status} |"
        )
    lines += [
        "",
        f"Commit: `{commit}`  ",
        f"GitHub Actions run: `{run_id}`  ",
        f"Repository: `{repository}`",
        "",
        "Vanilla client scope: verified Mojang materialization → local package integrity → exact target Java → host OS/arch binding → Compatibility Engine resolution → actual Minecraft process (Xvfb on Linux; native desktop launch on Windows/macOS). Matching-server targets additionally materialize verified Mojang server.jar for the exact same Minecraft version and require a real client join.",
        "Integration scope: canonical API upload → signed immutable release → clean NeverRuntime sync → actual client → Paper join → revoke/deny and health checks.",
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
