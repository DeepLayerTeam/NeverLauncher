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
RUNNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
CHECK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,95}$")
EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_KINDS = {"protocol-e2e", "native-tests"}
ALLOWED_OS = {"linux", "windows", "macos"}
ALLOWED_ARCH = {"x86_64", "arm64", "runner-native"}
KIND_MANDATORY_CHECKS = {
    "protocol-e2e": {
        "postgresRepository",
        "registrationReplayDenied",
        "sessionBindingEpoch",
        "boundRefreshProof",
        "rotationDualProof",
        "oldKeyTombstone",
        "serverBridgeBindingDeny",
        "revocationCascade",
        "riskStepUp",
        "p256AttestationProtocol",
        "attestationReplayDenied",
        "recoveryRequiresPhishingResistantStepUp",
        "recoveryPhishingResistantEndToEnd",
    },
    "native-tests": {
        "tauriCompile",
        "deviceKeyUnitTests",
        "generationScopedHardwareLabels",
        "replacementPayloadValidation",
        "refreshPayloadBinding",
        "attestationPayloadValidation",
    },
}


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
        die("device trust targets document must be an object")
    if set(payload) != {"schemaVersion", "productVersion", "targets"}:
        die("device trust targets must contain only schemaVersion/productVersion/targets")
    if payload.get("schemaVersion") != "1.0":
        die("device trust targets schemaVersion must be 1.0")
    if str(payload.get("productVersion", "")).strip() != PRODUCT_VERSION:
        die(f"device trust targets productVersion must match VERSION={PRODUCT_VERSION}")
    rows = payload.get("targets")
    if not isinstance(rows, list) or not rows:
        die("device trust targets must contain a non-empty array")
    allowed = {"id", "kind", "runner", "os", "arch", "required", "requiredChecks"}
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            die(f"target #{index + 1} must be an object")
        unknown = sorted(set(raw) - allowed)
        if unknown:
            die(f"target #{index + 1}: unknown fields are forbidden: {', '.join(unknown)}")
        target_id = str(raw.get("id", "")).strip()
        kind = str(raw.get("kind", "")).strip()
        runner = str(raw.get("runner", "")).strip()
        os_name = str(raw.get("os", "")).strip().lower()
        arch = str(raw.get("arch", "")).strip().lower()
        required = raw.get("required")
        checks = raw.get("requiredChecks")
        if not ID_RE.fullmatch(target_id) or target_id in seen:
            die(f"target #{index + 1}: invalid or duplicate id {target_id!r}")
        seen.add(target_id)
        if kind not in ALLOWED_KINDS:
            die(f"{target_id}: unsupported kind {kind!r}")
        if not RUNNER_RE.fullmatch(runner):
            die(f"{target_id}: invalid runner {runner!r}")
        if os_name not in ALLOWED_OS:
            die(f"{target_id}: unsupported os {os_name!r}")
        if arch not in ALLOWED_ARCH:
            die(f"{target_id}: unsupported arch {arch!r}")
        if not isinstance(required, bool):
            die(f"{target_id}: required must be boolean")
        if not isinstance(checks, list) or not checks or any(not isinstance(v, str) or not CHECK_RE.fullmatch(v) for v in checks):
            die(f"{target_id}: requiredChecks must be a non-empty unique string array")
        if len(checks) != len(set(checks)):
            die(f"{target_id}: duplicate requiredChecks")
        missing = sorted(KIND_MANDATORY_CHECKS[kind] - set(checks))
        if missing:
            die(f"{target_id}: requiredChecks weaken {kind} baseline: missing {', '.join(missing)}")
        normalized.append({
            "id": target_id,
            "kind": kind,
            "runner": runner,
            "os": os_name,
            "arch": arch,
            "required": required,
            "requiredChecks": checks,
        })
    return {"schemaVersion": "1.0", "productVersion": PRODUCT_VERSION, "targets": normalized}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_results(root: Path) -> tuple[dict[str, tuple[Path, dict[str, Any]]], list[str]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    errors: list[str] = []
    if not root.exists():
        return found, [f"results root does not exist: {root}"]
    for path in sorted(root.rglob("device-trust-result.json")):
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
            errors.append(f"duplicate device trust result for {target_id}")
            continue
        found[target_id] = (path, payload)
    return found, errors


def verify_result(target: dict[str, Any], result: dict[str, Any], *, result_path: Path, commit: str, run_id: str) -> list[str]:
    errors: list[str] = []
    expected = {
        "schemaVersion": "1.0",
        "productVersion": PRODUCT_VERSION,
        "targetId": target["id"],
        "kind": target["kind"],
        "os": target["os"],
        "arch": target["arch"],
        "commit": commit,
        "runId": run_id,
    }
    for key, value in expected.items():
        if str(result.get(key, "")) != str(value):
            errors.append(f"{key}: expected {value!r}, got {result.get(key)!r}")
    if result.get("status") != "passed":
        errors.append(f"status is {result.get('status')!r}")
    if result.get("exitCode") != 0:
        errors.append(f"exitCode is {result.get('exitCode')!r}")
    runtime_arch = str(result.get("runtimeArch", "")).strip()
    if not runtime_arch:
        errors.append("runtimeArch is missing")
    checks = result.get("checks")
    if not isinstance(checks, dict):
        errors.append("checks is missing")
    else:
        for check in target["requiredChecks"]:
            if checks.get(check) is not True:
                errors.append(f"required check {check} is not true")
    evidence = result.get("evidence")
    if not isinstance(evidence, dict):
        errors.append("evidence is missing")
    else:
        files = evidence.get("files")
        digests = evidence.get("sha256")
        if not isinstance(files, list) or not files or any(not isinstance(v, str) or not EVIDENCE_RE.fullmatch(v) for v in files):
            errors.append("evidence.files must be a non-empty safe-basename string array")
        elif len(files) != len(set(files)):
            errors.append("evidence.files contains duplicates")
        elif "device-trust-result.json" in files:
            errors.append("evidence.files cannot include device-trust-result.json")
        elif not isinstance(digests, dict) or set(digests) != set(files):
            errors.append("evidence.sha256 must contain exactly one digest for every evidence file")
        else:
            for name in files:
                expected_digest = digests.get(name)
                if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
                    errors.append(f"evidence digest for {name} is not canonical SHA-256")
                    continue
                evidence_path = result_path.parent / name
                if evidence_path.is_symlink() or not evidence_path.is_file():
                    errors.append(f"evidence file is missing or unsafe: {name}")
                    continue
                actual_digest = sha256_file(evidence_path)
                if actual_digest != expected_digest:
                    errors.append(f"evidence SHA-256 mismatch for {name}")
    claims = result.get("claims")
    if target["kind"] == "protocol-e2e":
        if not isinstance(claims, dict):
            errors.append("protocol result claims are missing")
        else:
            if claims.get("repository") != "postgresql":
                errors.append("protocol E2E did not declare PostgreSQL repository")
            if claims.get("vendorHardwareProvenance") != "not-verified":
                errors.append("protocol E2E must not claim vendor hardware provenance")
            if claims.get("privateKeyServerExposed") is not False:
                errors.append("protocol E2E must explicitly assert private key is not server-exposed")
    elif target["kind"] == "native-tests":
        limitations = result.get("limitations")
        if not isinstance(limitations, list) or "headless-ci-does-not-prove-os-secure-storage-runtime" not in limitations:
            errors.append("native result must disclose secure-storage runtime limitation")
    return errors


def render_markdown(product_version: str, targets: list[dict[str, Any]], records: dict[str, dict[str, Any]], commit: str, run_id: str, repository: str) -> str:
    lines = [
        f"# NeverLauncher {product_version} — Public Device Trust Matrix",
        "",
        "> Матрица генерируется только из CI evidence для exact commit/run ID. PASS нельзя записать вручную в targets.json.",
        "",
        "| Target | Scope | OS / target arch | Runtime arch | Checks | Result |",
        "|---|---|---|---|---:|---:|",
    ]
    for target in targets:
        record = records.get(target["id"], {})
        checks = record.get("checks") if isinstance(record.get("checks"), dict) else {}
        passed = sum(1 for name in target["requiredChecks"] if checks.get(name) is True)
        total = len(target["requiredChecks"])
        status = "PASS" if record.get("status") == "passed" else "FAIL"
        scope = "PostgreSQL protocol E2E" if target["kind"] == "protocol-e2e" else "Native Tauri compile + key-policy unit tests"
        lines.append(
            f"| `{target['id']}` | {scope} | `{target['os']}/{target['arch']}` | "
            f"`{record.get('runtimeArch', '—')}` | {passed}/{total} | **{status}** |"
        )
    lines += [
        "",
        f"Commit: `{commit}`  ",
        f"GitHub Actions run: `{run_id}`  ",
        f"Repository: `{repository}`",
        "",
        "Protocol E2E проверяет реальный PostgreSQL lifecycle: registration/replay protection, session binding epoch, device-bound refresh, dual-proof rotation, permanent fingerprint tombstone, ServerBridge binding invalidation, revocation cascade, risk step-up и P-256 challenge-response attestation protocol.",
        "",
        "Важно: P-256 challenge-response в этой матрице доказывает серверную проверку владения зарегистрированным ключом, но **не** vendor TPM/Secure Enclave provenance. Native Windows/macOS/Linux targets доказывают компиляцию и security-policy unit tests; headless CI не объявляется доказательством фактической работы OS secure storage/TPM/Secure Enclave на конкретном пользовательском устройстве.",
        "",
    ]
    return "\n".join(lines)


def command_validate(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(f"Device Trust targets OK: {len(payload['targets'])} targets for {PRODUCT_VERSION}")
    return 0


def command_plan(args: argparse.Namespace) -> int:
    payload = load_targets(args.targets)
    print(json.dumps({"include": payload["targets"]}, separators=(",", ":")))
    return 0


def command_aggregate(args: argparse.Namespace) -> int:
    targets_doc = load_targets(args.targets)
    targets = targets_doc["targets"]
    results, errors = discover_results(args.results_root)
    records: dict[str, dict[str, Any]] = {}
    expected_ids = {t["id"] for t in targets}
    for extra in sorted(set(results) - expected_ids):
        errors.append(f"unexpected device trust result: {extra}")
    for target in targets:
        found = results.get(target["id"])
        if found is None:
            if target["required"]:
                errors.append(f"missing required device trust result: {target['id']}")
            records[target["id"]] = {"targetId": target["id"], "status": "missing", "checks": {}}
            continue
        path, result = found
        result_errors = verify_result(target, result, result_path=path, commit=args.commit, run_id=args.run_id)
        record = dict(result)
        record["evidenceSha256"] = sha256_file(path)
        if result_errors:
            record["status"] = "invalid"
            errors.extend(f"{target['id']}: {item}" for item in result_errors)
        records[target["id"]] = record
    status = "passed" if not errors and all(records[t["id"]].get("status") == "passed" for t in targets if t["required"]) else "failed"
    matrix = {
        "schemaVersion": "1.0",
        "productVersion": PRODUCT_VERSION,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": args.repository,
        "commit": args.commit,
        "runId": args.run_id,
        "status": status,
        "targets": [records[t["id"]] for t in targets],
        "errors": errors,
        "generatorRuntime": {"python": platform.python_version(), "platform": platform.platform()},
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "matrix.json").write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "matrix.md").write_text(render_markdown(PRODUCT_VERSION, targets, records, args.commit, args.run_id, args.repository), encoding="utf-8")
    if errors:
        for item in errors:
            print(f"device trust matrix: {item}", flush=True)
        return 1
    print(f"Device Trust matrix PASS: {len(targets)} targets, commit={args.commit}, run={args.run_id}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NeverLauncher public Device Trust CI matrix")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate")
    p.add_argument("--targets", type=Path, required=True)
    p.set_defaults(func=command_validate)
    p = sub.add_parser("plan")
    p.add_argument("--targets", type=Path, required=True)
    p.set_defaults(func=command_plan)
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
