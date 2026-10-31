#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, path: str, needles: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(
            f"[Launcher] Windows Adversarial CI 0.18.11 gate: {path} missing: {', '.join(missing)}"
        )


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"invalid VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 18, 11):
    raise SystemExit(f"Windows Adversarial CI gate requires >=0.18.11, got {version}")

runner = read("scripts/guard_ci/windows_adversarial.py")
require(
    runner,
    "scripts/guard_ci/windows_adversarial.py",
    [
        "CERTIFIED_JAVA_MAJORS = (8, 16, 17, 21, 25)",
        'Scenario("sensor-early-load", "compatibility"',
        'Scenario("trusted-module-lifecycle", "compatibility"',
        'Scenario("continuous-cross-check", "compatibility"',
        'Scenario("job-bound-process-tree", "compatibility"',
        'Scenario("hotspot-jit", "compatibility"',
        'Scenario("unsigned-module", "adversarial"',
        'Scenario("code-page-drift", "adversarial"',
        'Scenario("private-exec-thread", "adversarial"',
        'Scenario("startup-instrumentation", "adversarial"',
        'Scenario("live-debugger", "adversarial"',
        'Scenario("foreign-executable-allocation", "adversarial"',
        '"cargo", "test", "--manifest-path", "runtime/runtime/Cargo.toml"',
        '"evidenceRootSha256"',
        '"allAdversarialScenariosDetected": True',
        '"allCompatibilityScenariosPassed": True',
        '"sensorAndFixtureHashesBound": True',
        "WINDOWS_ADVERSARIAL_CERTIFICATE.json",
        "windows-adversarial-ci-0.18.11-live-jvm-attack-simulation-and-java-compatibility-certification",
    ],
)

unit_tests = read("scripts/guard_ci/test_windows_adversarial.py")
require(
    unit_tests,
    "scripts/guard_ci/test_windows_adversarial.py",
    [
        "test_valid_result_is_accepted",
        "test_tampered_scenario_is_rejected",
        "test_aggregate_requires_every_certified_java_major",
    ],
)

windows_tests = read("runtime/runtime/tests/guard_sensor_windows.rs")
for test_name in [
    "guard_sensor_agentpath_loads_before_jvm_startup",
    "guard_module_guard_tracks_real_jvm_dll_load_and_heartbeat",
    "guard_continuous_guard_cross_checks_sensor_and_guard_heartbeat",
    "guard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots",
    "guard_memory_integrity_fail_closed_on_executable_image_code_page_drift",
    "guard_thread_process_integrity_tracks_job_bound_descendant_processes",
    "guard_thread_integrity_fail_closed_on_private_executable_thread_start",
    "guard_debug_instrumentation_guard_rejects_startup_agents_and_enforces_attach_disable",
    "guard_debug_instrumentation_guard_fail_closed_on_live_debugger_attach",
    "guard_jvm_aware_protection_accepts_certified_hotspot_jit",
    "guard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation",
]:
    if test_name not in windows_tests:
        raise SystemExit(
            f"[Launcher] Windows Adversarial CI 0.18.11 gate: live test missing: {test_name}"
        )

ci = read(".github/workflows/ci.yml")
require(
    ci,
    ".github/workflows/ci.yml",
    [
        "guard-windows-adversarial:",
        "java: [8, 16, 17, 21, 25]",
        "scripts/guard_ci/windows_adversarial.py run",
        "guard-windows-adversarial-certificate:",
        "scripts/guard_ci/windows_adversarial.py aggregate",
        "WINDOWS_ADVERSARIAL_CERTIFICATE.json",
        "guard-windows-adversarial-ci-01811.py",
    ],
)
for manifest in [
    "runtime/guard-sensor/Cargo.toml",
    "runtime/guard-memory-probe/Cargo.toml",
    "runtime/guard-thread-probe/Cargo.toml",
    "runtime/guard-debug-probe/Cargo.toml",
    "runtime/guard-jvm-probe/Cargo.toml",
]:
    if manifest not in ci:
        raise SystemExit(
            f"[Launcher] Windows Adversarial CI 0.18.11 gate: CI does not build {manifest}"
        )

preflight = read("scripts/release/preflight.sh")
if (
    "guard-windows-adversarial-ci-01811.py" not in preflight
    or "test_windows_adversarial.py" not in preflight
):
    raise SystemExit(
        "[Launcher] Windows Adversarial CI 0.18.11 gate: release preflight/self-test wiring missing"
    )

for rel, text in [
    ("scripts/guard_ci/windows_adversarial.py", runner),
    ("scripts/guard_ci/test_windows_adversarial.py", unit_tests),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(
                f"[Launcher] Windows Adversarial CI 0.18.11 gate: placeholder {placeholder!r} in {rel}"
            )

print(
    f"[Launcher] Windows Adversarial CI attack-simulation + compatibility certification 0.18.11 gate: OK ({version})"
)
