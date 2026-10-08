#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
SCHEMA_VERSION = "1.0"
CERT_KIND = "neverlauncher-windows-adversarial-certification"
CERTIFIED_JAVA_MAJORS = (8, 16, 17, 21, 25)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Scenario:
    id: str
    kind: str
    test_name: str
    description: str


SCENARIOS = (
    Scenario("sensor-early-load", "compatibility", "neverguard_sensor_agentpath_loads_before_jvm_startup", "Sensor загружается и проходит startup proof до Java main"),
    Scenario("trusted-module-lifecycle", "compatibility", "neverguard_module_guard_tracks_real_jvm_dll_load_and_heartbeat", "Доверенная native DLL проходит Module Guard и heartbeat"),
    Scenario("continuous-cross-check", "compatibility", "neverguard_continuous_guard_cross_checks_sensor_and_guard_heartbeat", "Sensor и Guard поддерживают двустороннюю rolling-chain сверку"),
    Scenario("job-bound-process-tree", "compatibility", "neverguard_thread_process_integrity_tracks_job_bound_descendant_processes", "Штатный дочерний процесс остаётся внутри Job boundary"),
    Scenario("hotspot-jit", "compatibility", "neverguard_jvm_aware_protection_accepts_certified_hotspot_jit", "Штатный HotSpot JIT допускается без false positive"),
    Scenario("unsigned-module", "adversarial", "neverguard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots", "Неподписанная DLL вне trusted roots приводит к fail-closed"),
    Scenario("code-page-drift", "adversarial", "neverguard_memory_integrity_fail_closed_on_executable_image_code_page_drift", "Изменение executable image page обнаруживается после восстановления protection"),
    Scenario("private-exec-thread", "adversarial", "neverguard_thread_integrity_fail_closed_on_private_executable_thread_start", "Поток из MEM_PRIVATE executable memory блокируется"),
    Scenario("startup-instrumentation", "adversarial", "neverguard_debug_instrumentation_guard_rejects_startup_agents_and_enforces_attach_disable", "JDWP/javaagent/agentlib/foreign agentpath блокируются до spawn"),
    Scenario("live-debugger", "adversarial", "neverguard_debug_instrumentation_guard_fail_closed_on_live_debugger_attach", "Live DebugActiveProcess attach приводит к fail-closed"),
    Scenario("foreign-executable-allocation", "adversarial", "neverguard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation", "Executable private allocation вне jvm.dll provenance блокируется"),
)
SCENARIO_BY_ID = {row.id: row for row in SCENARIOS}


def die(message: str) -> None:
    raise SystemExit(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def command_output(argv: list[str], env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60, check=False)
    output = proc.stdout.strip()
    if proc.returncode != 0:
        die(f"command failed ({proc.returncode}): {' '.join(argv)}\n{output}")
    return output


def required_file(path: Path, label: str) -> dict[str, Any]:
    path = path.resolve()
    if not path.is_file() or path.stat().st_size <= 0:
        die(f"{label} is missing or empty: {path}")
    return {"name": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)}


def run_scenario(scenario: Scenario, env: dict[str, str], timeout_seconds: int) -> dict[str, Any]:
    argv = [
        "cargo", "test", "--manifest-path", "runtime/neverruntime/Cargo.toml",
        "--test", "neverguard_sensor_windows", scenario.test_name,
        "--", "--exact", "--nocapture",
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            timeout=timeout_seconds,
            check=False,
        )
        output = proc.stdout or b""
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"") + (exc.stderr or b"")
        exit_code = 124
        timed_out = True
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "id": scenario.id,
        "kind": scenario.kind,
        "test": scenario.test_name,
        "description": scenario.description,
        "status": "passed" if exit_code == 0 and not timed_out else "failed",
        "exitCode": exit_code,
        "timedOut": timed_out,
        "durationMs": duration_ms,
        "outputSha256": sha256_bytes(output),
        "outputBytes": len(output),
    }


def result_evidence_root(result: dict[str, Any]) -> str:
    rows = []
    for item in result["scenarios"]:
        rows.append({
            "id": item["id"], "kind": item["kind"], "status": item["status"],
            "exitCode": item["exitCode"], "timedOut": item["timedOut"],
            "outputSha256": item["outputSha256"],
        })
    material = {
        "schemaVersion": result["schemaVersion"],
        "productVersion": result["productVersion"],
        "javaMajor": result["javaMajor"],
        "runtimeArch": result["runtimeArch"],
        "repository": result["repository"],
        "commit": result["commit"],
        "runId": result["runId"],
        "javaVersionOutputSha256": result["javaVersionOutputSha256"],
        "rustcVersionOutputSha256": result["rustcVersionOutputSha256"],
        "artifacts": result["artifacts"],
        "scenarios": rows,
    }
    return sha256_bytes(canonical_json(material))


def validate_result(payload: dict[str, Any], *, repository: str | None = None, commit: str | None = None, run_id: str | None = None) -> list[str]:
    errors: list[str] = []
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("schemaVersion mismatch")
    if payload.get("kind") != "neverlauncher-windows-adversarial-result":
        errors.append("kind mismatch")
    if payload.get("productVersion") != PRODUCT_VERSION:
        errors.append("productVersion mismatch")
    java_major = payload.get("javaMajor")
    if java_major not in CERTIFIED_JAVA_MAJORS:
        errors.append(f"unsupported javaMajor {java_major!r}")
    if str(payload.get("runtimeArch", "")).lower() not in {"amd64", "x86_64"}:
        errors.append("runtimeArch is not x86_64/amd64")
    for field in ("javaVersionOutputSha256", "rustcVersionOutputSha256"):
        if not SHA256_RE.fullmatch(str(payload.get(field, ""))):
            errors.append(f"invalid {field}")
    if repository is not None and payload.get("repository") != repository:
        errors.append("repository mismatch")
    if commit is not None and payload.get("commit") != commit:
        errors.append("commit mismatch")
    if run_id is not None and payload.get("runId") != run_id:
        errors.append("runId mismatch")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        errors.append("scenarios missing")
        scenarios = []
    ids = [row.get("id") for row in scenarios if isinstance(row, dict)]
    expected_ids = [row.id for row in SCENARIOS]
    if ids != expected_ids:
        errors.append("scenario set/order mismatch")
    for row in scenarios:
        if not isinstance(row, dict):
            errors.append("invalid scenario row")
            continue
        sid = row.get("id")
        expected = SCENARIO_BY_ID.get(str(sid))
        if expected is None:
            errors.append(f"unknown scenario {sid!r}")
            continue
        if row.get("kind") != expected.kind or row.get("test") != expected.test_name:
            errors.append(f"scenario metadata mismatch for {sid}")
        if row.get("status") != "passed" or row.get("exitCode") != 0 or row.get("timedOut") is not False:
            errors.append(f"scenario failed: {sid}")
        if not SHA256_RE.fullmatch(str(row.get("outputSha256", ""))):
            errors.append(f"invalid outputSha256 for {sid}")
    artifacts = payload.get("artifacts")
    expected_artifacts = {"sensor", "memoryProbe", "threadProbe", "debugProbe", "jvmProbe"}
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        errors.append("artifact set mismatch")
    else:
        for name, item in artifacts.items():
            if not isinstance(item, dict) or not SHA256_RE.fullmatch(str(item.get("sha256", ""))) or not isinstance(item.get("size"), int) or item["size"] <= 0:
                errors.append(f"invalid artifact evidence: {name}")
    compatibility_count = sum(1 for row in scenarios if isinstance(row, dict) and row.get("kind") == "compatibility")
    adversarial_count = sum(1 for row in scenarios if isinstance(row, dict) and row.get("kind") == "adversarial")
    if payload.get("compatibilityScenarioCount") != compatibility_count:
        errors.append("compatibilityScenarioCount mismatch")
    if payload.get("adversarialScenarioCount") != adversarial_count:
        errors.append("adversarialScenarioCount mismatch")
    if payload.get("status") != "passed" or payload.get("allRequiredScenariosPassed") is not True:
        errors.append("result is not passed")
    expected_root = result_evidence_root(payload) if isinstance(payload.get("artifacts"), dict) else ""
    if payload.get("evidenceRootSha256") != expected_root:
        errors.append("evidenceRootSha256 mismatch")
    return errors


def cmd_run(args: argparse.Namespace) -> int:
    if args.java_major not in CERTIFIED_JAVA_MAJORS:
        die(f"Java {args.java_major} is outside certified set {CERTIFIED_JAVA_MAJORS}")
    artifacts = {
        "sensor": required_file(args.sensor, "NeverGuard Sensor"),
        "memoryProbe": required_file(args.memory_probe, "Memory probe"),
        "threadProbe": required_file(args.thread_probe, "Thread probe"),
        "debugProbe": required_file(args.debug_probe, "Debug probe"),
        "jvmProbe": required_file(args.jvm_probe, "JVM probe"),
    }
    env = os.environ.copy()
    env.update({
        "NEVERGUARD_SENSOR_TEST_DLL": str(args.sensor.resolve()),
        "NEVERGUARD_MEMORY_PROBE_DLL": str(args.memory_probe.resolve()),
        "NEVERGUARD_THREAD_PROBE_DLL": str(args.thread_probe.resolve()),
        "NEVERGUARD_DEBUG_PROBE_EXE": str(args.debug_probe.resolve()),
        "NEVERGUARD_JVM_PROBE_DLL": str(args.jvm_probe.resolve()),
        "NEVERGUARD_EXPECTED_JAVA_MAJOR": str(args.java_major),
    })
    java_version = command_output([str(Path(os.environ["JAVA_HOME"]) / "bin" / "java.exe"), "-version"], env)
    rustc_version = command_output(["rustc", "-Vv"], env)
    scenarios = [run_scenario(row, env, args.timeout_seconds) for row in SCENARIOS]
    all_passed = all(row["status"] == "passed" for row in scenarios)
    result: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "neverlauncher-windows-adversarial-result",
        "productVersion": PRODUCT_VERSION,
        "javaMajor": args.java_major,
        "runtimeArch": platform.machine().lower() or "unknown",
        "repository": args.repository,
        "commit": args.commit,
        "runId": args.run_id,
        "javaVersionOutputSha256": sha256_bytes(java_version.encode("utf-8")),
        "rustcVersionOutputSha256": sha256_bytes(rustc_version.encode("utf-8")),
        "artifacts": artifacts,
        "scenarios": scenarios,
        "compatibilityScenarioCount": sum(1 for row in scenarios if row["kind"] == "compatibility"),
        "adversarialScenarioCount": sum(1 for row in scenarios if row["kind"] == "adversarial"),
        "allRequiredScenariosPassed": all_passed,
        "status": "passed" if all_passed else "failed",
    }
    result["evidenceRootSha256"] = result_evidence_root(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    errors = validate_result(result, repository=args.repository, commit=args.commit, run_id=args.run_id)
    if errors:
        print("Windows adversarial result FAILED validation: " + "; ".join(errors), file=sys.stderr)
        return 1
    print(f"Windows adversarial result PASS: Java {args.java_major}, {len(SCENARIOS)} scenarios -> {args.output}")
    return 0


def discover_results(root: Path) -> tuple[dict[int, dict[str, Any]], list[str]]:
    found: dict[int, dict[str, Any]] = {}
    errors: list[str] = []
    for path in sorted(root.rglob("windows-adversarial-result.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: invalid JSON: {exc}")
            continue
        major = payload.get("javaMajor") if isinstance(payload, dict) else None
        if not isinstance(major, int) or major in found:
            errors.append(f"{path}: invalid or duplicate javaMajor {major!r}")
            continue
        found[major] = payload
    return found, errors


def certificate_evidence_root(results: dict[int, dict[str, Any]]) -> str:
    material = [
        {"javaMajor": major, "evidenceRootSha256": results[major]["evidenceRootSha256"]}
        for major in sorted(results)
    ]
    return sha256_bytes(canonical_json(material))


def cmd_aggregate(args: argparse.Namespace) -> int:
    results, errors = discover_results(args.results_root)
    expected = set(CERTIFIED_JAVA_MAJORS)
    missing = sorted(expected - set(results))
    extra = sorted(set(results) - expected)
    if missing:
        errors.append(f"missing Java results: {missing}")
    if extra:
        errors.append(f"unexpected Java results: {extra}")
    for major, payload in sorted(results.items()):
        errors.extend(f"Java {major}: {err}" for err in validate_result(payload, repository=args.repository, commit=args.commit, run_id=args.run_id))
    if errors:
        die("Windows adversarial certification failed: " + "; ".join(errors))

    compatibility_ids = [row.id for row in SCENARIOS if row.kind == "compatibility"]
    adversarial_ids = [row.id for row in SCENARIOS if row.kind == "adversarial"]
    certificate = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": CERT_KIND,
        "productVersion": PRODUCT_VERSION,
        "repository": args.repository,
        "commit": args.commit,
        "runId": args.run_id,
        "platform": "windows-x86_64",
        "javaMajors": list(CERTIFIED_JAVA_MAJORS),
        "requiredJavaMajorCount": len(CERTIFIED_JAVA_MAJORS),
        "passedJavaMajorCount": len(results),
        "compatibilityScenarios": compatibility_ids,
        "adversarialScenarios": adversarial_ids,
        "scenarioExecutions": len(SCENARIOS) * len(CERTIFIED_JAVA_MAJORS),
        "evidenceRootSha256": certificate_evidence_root(results),
        "javaEvidence": [
            {"javaMajor": major, "evidenceRootSha256": results[major]["evidenceRootSha256"]}
            for major in CERTIFIED_JAVA_MAJORS
        ],
        "invariants": {
            "allCertifiedJavaMajorsPassed": True,
            "allCompatibilityScenariosPassed": True,
            "allAdversarialScenariosDetected": True,
            "sensorGuardContinuousCrossCheckPassed": True,
            "failClosedAttackBoundaryPassed": True,
            "exactScenarioSetBound": True,
            "sensorAndFixtureHashesBound": True,
        },
        "policy": "windows-adversarial-ci-0.18.11-live-jvm-attack-simulation-and-java-compatibility-certification",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cert_path = args.output_dir / "WINDOWS_ADVERSARIAL_CERTIFICATE.json"
    cert_path.write_text(json.dumps(certificate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# NeverLauncher {PRODUCT_VERSION} Windows Adversarial CI", "",
        f"Evidence root: `{certificate['evidenceRootSha256']}`", "",
        "| Java | Compatibility | Adversarial | Result |", "|---:|---:|---:|---|",
    ]
    for major in CERTIFIED_JAVA_MAJORS:
        lines.append(f"| {major} | {len(compatibility_ids)} | {len(adversarial_ids)} | PASS |")
    lines += ["", f"Total live scenario executions: **{certificate['scenarioExecutions']}**.", ""]
    (args.output_dir / "WINDOWS_ADVERSARIAL_CERTIFICATE.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Windows adversarial certification PASS -> {cert_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NeverLauncher Windows adversarial CI runner and certifier")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run live adversarial/compatibility scenarios for one Java major")
    run.add_argument("--java-major", type=int, required=True)
    run.add_argument("--sensor", type=Path, required=True)
    run.add_argument("--memory-probe", type=Path, required=True)
    run.add_argument("--thread-probe", type=Path, required=True)
    run.add_argument("--debug-probe", type=Path, required=True)
    run.add_argument("--jvm-probe", type=Path, required=True)
    run.add_argument("--repository", required=True)
    run.add_argument("--commit", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=180)
    run.set_defaults(func=cmd_run)

    aggregate = sub.add_parser("aggregate", help="validate all Java results and issue certification")
    aggregate.add_argument("--results-root", type=Path, required=True)
    aggregate.add_argument("--repository", required=True)
    aggregate.add_argument("--commit", required=True)
    aggregate.add_argument("--run-id", required=True)
    aggregate.add_argument("--output-dir", type=Path, required=True)
    aggregate.set_defaults(func=cmd_aggregate)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
