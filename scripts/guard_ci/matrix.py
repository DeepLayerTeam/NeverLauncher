#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
CHECK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,95}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_OS = {"linux", "windows", "macos"}
ALLOWED_ARCH = {"x86_64", "universal"}
ARTIFACT_ROLES = ("package", "launcher", "guard", "manifest", "allowlist")
COMMON_CHECKS = {
    "rustFormat", "guardUnitTests", "guardIntegrationTest", "clippy", "releaseBuild",
    "packageManifestVerified", "artifactHashesVerified", "authenticatedIpcV4",
    "runtimePolicyEnforced", "releasePackageBuilt", "guardRelease0139",
}
OS_CHECK = {"linux": "linuxProductionGate", "windows": "windowsProductionGate", "macos": "macosProductionGate"}
EXPECTED_PLATFORM = {"linux": "linux-amd64", "windows": "windows-amd64", "macos": "macos-universal"}
GENERIC_LIMITATION = "ci-certifies-build-test-artifacts-not-vendor-signing-credentials"


def die(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"{path}: invalid JSON: {exc}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        die(f"artifact is missing: {path}")
    size = path.stat().st_size
    if size <= 0:
        die(f"artifact is empty: {path}")
    return {"name": path.name, "size": size, "sha256": sha256_file(path)}


def load_targets(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict) or set(payload) != {"schemaVersion", "productVersion", "targets"}:
        die("guard CI targets must contain only schemaVersion/productVersion/targets")
    if payload.get("schemaVersion") != "1.0" or payload.get("productVersion") != PRODUCT_VERSION:
        die(f"guard CI targets must use schemaVersion=1.0 and productVersion={PRODUCT_VERSION}")
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows:
        die("guard CI targets must contain a non-empty targets array")
    allowed = {"id", "runner", "os", "arch", "required", "ciSigningMode", "requiredChecks"}
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    required_os: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            die(f"target #{index + 1} must be an object")
        unknown = sorted(set(raw) - allowed)
        if unknown:
            die(f"target #{index + 1}: unknown fields: {', '.join(unknown)}")
        target_id = str(raw.get("id", "")).strip()
        os_name = str(raw.get("os", "")).strip().lower()
        arch = str(raw.get("arch", "")).strip().lower()
        runner = str(raw.get("runner", "")).strip()
        signing = str(raw.get("ciSigningMode", "")).strip()
        required = raw.get("required")
        checks = raw.get("requiredChecks")
        if not ID_RE.fullmatch(target_id) or target_id in seen:
            die(f"target #{index + 1}: invalid or duplicate id {target_id!r}")
        seen.add(target_id)
        if os_name not in ALLOWED_OS or arch not in ALLOWED_ARCH:
            die(f"{target_id}: unsupported os/arch {os_name}/{arch}")
        if os_name != "macos" and arch != "x86_64":
            die(f"{target_id}: {os_name} certification currently requires x86_64")
        if os_name == "macos" and arch != "universal":
            die(f"{target_id}: macOS certification must be universal")
        if not runner or not signing or not isinstance(required, bool):
            die(f"{target_id}: runner/ciSigningMode/required are mandatory")
        if not isinstance(checks, list) or not checks or any(not isinstance(v, str) or not CHECK_RE.fullmatch(v) for v in checks):
            die(f"{target_id}: requiredChecks must be a non-empty string array")
        if len(checks) != len(set(checks)):
            die(f"{target_id}: duplicate requiredChecks")
        missing = sorted((COMMON_CHECKS | {OS_CHECK[os_name]}) - set(checks))
        if missing:
            die(f"{target_id}: weakened Guard baseline, missing {', '.join(missing)}")
        if required:
            required_os.add(os_name)
        normalized.append({
            "id": target_id, "runner": runner, "os": os_name, "arch": arch,
            "required": required, "ciSigningMode": signing, "requiredChecks": checks,
        })
    if required_os != ALLOWED_OS:
        die(f"required Guard CI coverage must be linux/windows/macos, got {sorted(required_os)}")
    return {"schemaVersion": "1.0", "productVersion": PRODUCT_VERSION, "targets": normalized}




def expected_artifact_names(os_name: str) -> dict[str, str]:
    if os_name == "linux":
        return {
            "package": f"neverlauncher-desktop-{PRODUCT_VERSION}-linux-amd64.zip",
            "launcher": "neverlauncher-desktop-linux-amd64",
            "guard": "neverguard-linux-amd64",
            "manifest": "LINUX_PACKAGE_MANIFEST.json",
            "allowlist": "GUARD_RELEASE_ALLOWLIST_LINUX.json",
        }
    if os_name == "windows":
        return {
            "package": f"neverlauncher-desktop-{PRODUCT_VERSION}-windows-amd64.zip",
            "launcher": "neverlauncher-desktop-windows-amd64.exe",
            "guard": "neverguard-windows-amd64.exe",
            "manifest": "WINDOWS_PACKAGE_MANIFEST.json",
            "allowlist": "GUARD_RELEASE_ALLOWLIST_WINDOWS.json",
        }
    if os_name == "macos":
        return {
            "package": f"neverlauncher-desktop-{PRODUCT_VERSION}-macos-universal.zip",
            "launcher": "neverlauncher-desktop-macos-universal",
            "guard": "neverguard-macos-universal",
            "manifest": "MACOS_PACKAGE_MANIFEST.json",
            "allowlist": "GUARD_RELEASE_ALLOWLIST_MACOS.json",
        }
    die(f"unsupported Guard CI OS: {os_name}")

def manifest_hashes(os_name: str, manifest: dict[str, Any]) -> tuple[str, str, str]:
    expected_platform = EXPECTED_PLATFORM[os_name]
    if manifest.get("schemaVersion") != "1.0" or manifest.get("productVersion") != PRODUCT_VERSION:
        die("package manifest version/schema mismatch")
    if manifest.get("platform") != expected_platform:
        die(f"package manifest platform mismatch: expected {expected_platform!r}, got {manifest.get('platform')!r}")
    if int(manifest.get("neverGuardProtocolVersion", 0)) != 4:
        die("package manifest does not enforce NeverGuard protocol v4")
    if os_name in {"linux", "windows"}:
        rows = manifest.get("artifacts")
        if not isinstance(rows, list) or len(rows) < 2:
            die("package manifest artifacts are missing")
        by_name = {str(row.get("name", "")): row for row in rows if isinstance(row, dict)}
        if os_name == "linux":
            desktop = by_name.get("neverlauncher-desktop")
            guard = by_name.get("neverguard")
        else:
            guard = by_name.get("neverguard.exe")
            desktop = next((row for name, row in by_name.items() if name.startswith("neverlauncher-desktop-") and name.endswith(".exe")), None)
        if not isinstance(desktop, dict) or not isinstance(guard, dict):
            die("package manifest does not contain Desktop/NeverGuard records")
        return str(desktop.get("sha256", "")).lower(), str(guard.get("sha256", "")).lower(), expected_platform
    return str(manifest.get("desktopSha256", "")).lower(), str(manifest.get("guardSha256", "")).lower(), expected_platform


def verify_package_metadata(target: dict[str, Any], artifacts: dict[str, dict[str, Any]], manifest_path: Path, allowlist_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        die("package manifest must be an object")
    desktop_hash, guard_hash, package_platform = manifest_hashes(target["os"], manifest)
    if desktop_hash != artifacts["launcher"]["sha256"] or guard_hash != artifacts["guard"]["sha256"]:
        die("package manifest SHA-256 does not match emitted Desktop/NeverGuard artifacts")
    allowlist = load_json(allowlist_path)
    if not isinstance(allowlist, dict) or not isinstance(allowlist.get(PRODUCT_VERSION), dict):
        die("Guard release allowlist does not contain current productVersion")
    row = allowlist[PRODUCT_VERSION]
    guard_values = [str(v).lower() for v in row.get("guardSha256", [])]
    launcher_values = [str(v).lower() for v in row.get("launcherSha256", [])]
    if guard_hash not in guard_values or desktop_hash not in launcher_values:
        die("Guard release allowlist is not bound to emitted Desktop/NeverGuard hashes")
    for digest in (desktop_hash, guard_hash):
        if not SHA256_RE.fullmatch(digest):
            die("invalid SHA-256 in package metadata")
    return {"packagePlatform": package_platform, "guardProtocolVersion": 4}


def verify_result(target: dict[str, Any], result: dict[str, Any], *, commit: str, run_id: str) -> list[str]:
    errors: list[str] = []
    expected = {
        "schemaVersion": "1.0", "productVersion": PRODUCT_VERSION, "targetId": target["id"],
        "runner": target["runner"], "os": target["os"], "arch": target["arch"],
        "commit": commit, "runId": run_id,
    }
    for key, value in expected.items():
        if str(result.get(key, "")) != str(value):
            errors.append(f"{key}: expected {value!r}, got {result.get(key)!r}")
    if result.get("status") != "passed" or result.get("exitCode") != 0:
        errors.append("status/exitCode must be passed/0")
    if not str(result.get("runtimeArch", "")).strip():
        errors.append("runtimeArch is missing")
    checks = result.get("checks")
    if not isinstance(checks, dict):
        errors.append("checks are missing")
    else:
        for check in target["requiredChecks"]:
            if checks.get(check) is not True:
                errors.append(f"required check {check} is not true")
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACT_ROLES):
        errors.append("artifacts must contain exactly package/launcher/guard/manifest/allowlist")
    else:
        names: set[str] = set()
        for role in ARTIFACT_ROLES:
            item = artifacts.get(role)
            if not isinstance(item, dict):
                errors.append(f"artifact {role} is invalid")
                continue
            name = str(item.get("name", ""))
            digest = str(item.get("sha256", "")).lower()
            size = item.get("size")
            if not name or Path(name).name != name or name in names:
                errors.append(f"artifact {role} has unsafe/duplicate name")
            names.add(name)
            if not SHA256_RE.fullmatch(digest) or not isinstance(size, int) or size <= 0:
                errors.append(f"artifact {role} has invalid digest/size")
    claims = result.get("claims")
    if not isinstance(claims, dict):
        errors.append("claims are missing")
    else:
        if claims.get("guardProtocolVersion") != 4 or claims.get("releaseCertification") != PRODUCT_VERSION:
            errors.append("Guard protocol/release certification claim mismatch")
        if claims.get("packagePlatform") != EXPECTED_PLATFORM[target["os"]]:
            errors.append("packagePlatform claim mismatch")
        if claims.get("ciSigningMode") != target["ciSigningMode"]:
            errors.append("ciSigningMode claim mismatch")
        if claims.get("vendorSigningProvenance") != "not-certified-by-ci":
            errors.append("vendor signing provenance must not be overclaimed")
        if claims.get("packageManifestBound") is not True or claims.get("artifactSetComplete") is not True:
            errors.append("artifact/package manifest claims must be true")
    limitations = result.get("limitations")
    if not isinstance(limitations, list) or GENERIC_LIMITATION not in limitations:
        errors.append("CI limitation about vendor signing credentials is missing")
    return errors


def command_validate(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(f"Guard CI targets OK: {len(payload['targets'])} targets for {PRODUCT_VERSION}")
    return 0


def command_plan(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(json.dumps({"include": payload["targets"]}, separators=(",", ":")))
    return 0


def command_result(args: argparse.Namespace) -> int:
    targets = load_targets(args.targets)["targets"]
    target = next((row for row in targets if row["id"] == args.target_id), None)
    if target is None:
        die(f"unknown Guard CI target: {args.target_id}")
    if args.signing_mode != target["ciSigningMode"]:
        die(f"{args.target_id}: signing mode mismatch")
    paths = {
        "package": args.package, "launcher": args.launcher, "guard": args.guard,
        "manifest": args.manifest, "allowlist": args.allowlist,
    }
    expected_names = expected_artifact_names(target["os"])
    for role, path in paths.items():
        if path.name != expected_names[role]:
            die(f"{target['id']}: non-canonical {role} artifact name: expected {expected_names[role]!r}, got {path.name!r}")
    artifacts = {role: artifact_record(path) for role, path in paths.items()}
    meta = verify_package_metadata(target, artifacts, args.manifest, args.allowlist)
    checks = {name: True for name in target["requiredChecks"]}
    result = {
        "schemaVersion": "1.0", "productVersion": PRODUCT_VERSION, "targetId": target["id"],
        "runner": target["runner"], "os": target["os"], "arch": target["arch"],
        "runtimeArch": platform.machine().lower() or "unknown", "commit": args.commit, "runId": args.run_id,
        "status": "passed", "exitCode": 0, "checks": checks, "artifacts": artifacts,
        "claims": {
            "guardProtocolVersion": meta["guardProtocolVersion"], "releaseCertification": PRODUCT_VERSION,
            "packagePlatform": meta["packagePlatform"], "ciSigningMode": args.signing_mode,
            "vendorSigningProvenance": "not-certified-by-ci", "packageManifestBound": True,
            "artifactSetComplete": True,
        },
        "limitations": [GENERIC_LIMITATION],
    }
    errors = verify_result(target, result, commit=args.commit, run_id=args.run_id)
    if errors:
        die("generated Guard CI result failed self-validation: " + "; ".join(errors))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Guard CI result PASS: {target['id']} -> {args.output}")
    return 0


def discover_results(root: Path) -> tuple[dict[str, tuple[Path, dict[str, Any]]], list[str]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    errors: list[str] = []
    if not root.exists():
        return found, [f"results root does not exist: {root}"]
    for path in sorted(root.rglob("guard-ci-result.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: invalid result JSON: {exc}")
            continue
        target_id = str(payload.get("targetId", "")).strip() if isinstance(payload, dict) else ""
        if not ID_RE.fullmatch(target_id):
            errors.append(f"{path}: invalid targetId")
            continue
        if target_id in found:
            errors.append(f"duplicate Guard CI result for {target_id}")
            continue
        found[target_id] = (path, payload)
    return found, errors


def render_markdown(targets: list[dict[str, Any]], records: dict[str, dict[str, Any]], commit: str, run_id: str, repository: str) -> str:
    lines = [
        f"# NeverLauncher {PRODUCT_VERSION} Guard CI certification", "",
        "| Target | Runner | Platform | Runtime arch | Status | Package SHA-256 |", "|---|---|---|---|---|---|",
    ]
    for target in targets:
        record = records[target["id"]]
        package = record.get("artifacts", {}).get("package", {}) if isinstance(record.get("artifacts"), dict) else {}
        digest = str(package.get("sha256", "—"))
        lines.append(f"| `{target['id']}` | `{target['runner']}` | `{target['os']}/{target['arch']}` | `{record.get('runtimeArch', '—')}` | **{record.get('status', 'missing').upper()}** | `{digest}` |")
    lines += ["", f"Commit: `{commit}`  ", f"GitHub Actions run: `{run_id}`  ", f"Repository: `{repository}`", "",
              "Certification binds the exact CI-built package, Desktop, NeverGuard, package manifest and release allowlist hashes for Linux, Windows and macOS. It deliberately does not claim possession or provenance of production Authenticode/Developer ID credentials.", ""]
    return "\n".join(lines)


def command_aggregate(args: argparse.Namespace) -> int:
    targets = load_targets(args.targets)["targets"]
    results, errors = discover_results(args.results_root)
    expected_ids = {row["id"] for row in targets}
    for extra in sorted(set(results) - expected_ids):
        errors.append(f"unexpected Guard CI result: {extra}")
    records: dict[str, dict[str, Any]] = {}
    artifact_names: set[str] = set()
    for target in targets:
        found = results.get(target["id"])
        if found is None:
            if target["required"]:
                errors.append(f"missing required Guard CI result: {target['id']}")
            records[target["id"]] = {"targetId": target["id"], "status": "missing", "checks": {}}
            continue
        path, result = found
        result_errors = verify_result(target, result, commit=args.commit, run_id=args.run_id)
        record = dict(result)
        record["evidenceSha256"] = sha256_file(path)
        if isinstance(result.get("artifacts"), dict):
            for role in ARTIFACT_ROLES:
                item = result["artifacts"].get(role, {})
                name = str(item.get("name", "")) if isinstance(item, dict) else ""
                if name in artifact_names:
                    result_errors.append(f"artifact filename collision across platforms: {name}")
                artifact_names.add(name)
        if result_errors:
            record["status"] = "invalid"
            errors.extend(f"{target['id']}: {item}" for item in result_errors)
        records[target["id"]] = record
    required_pass = all(records[row["id"]].get("status") == "passed" for row in targets if row["required"])
    status = "passed" if not errors and required_pass else "failed"
    matrix = {
        "schemaVersion": "1.0", "productVersion": PRODUCT_VERSION,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": args.repository, "commit": args.commit, "runId": args.run_id,
        "status": status, "targets": [records[row["id"]] for row in targets], "errors": errors,
        "generatorRuntime": {"python": platform.python_version(), "platform": platform.platform()},
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "matrix.json").write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "matrix.md").write_text(render_markdown(targets, records, args.commit, args.run_id, args.repository), encoding="utf-8")
    if errors:
        for item in errors:
            print(f"Guard CI matrix: {item}")
        return 1
    print(f"Guard CI matrix PASS: {len(targets)} targets, commit={args.commit}, run={args.run_id}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NeverLauncher cross-platform NeverGuard CI certification matrix")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate")
    p.add_argument("--targets", type=Path, required=True)
    p.set_defaults(func=command_validate)
    p = sub.add_parser("plan")
    p.add_argument("--targets", type=Path, required=True)
    p.set_defaults(func=command_plan)
    p = sub.add_parser("result")
    p.add_argument("--targets", type=Path, required=True)
    p.add_argument("--target-id", required=True)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--launcher", type=Path, required=True)
    p.add_argument("--guard", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--allowlist", type=Path, required=True)
    p.add_argument("--signing-mode", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=command_result)
    p = sub.add_parser("aggregate")
    p.add_argument("--targets", type=Path, required=True)
    p.add_argument("--results-root", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--repository", required=True)
    p.set_defaults(func=command_aggregate)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
