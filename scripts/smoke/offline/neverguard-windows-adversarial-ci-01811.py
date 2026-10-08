#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, path: str, needles: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"[NeverLauncher] Windows Атакующий CI 0.18.11 контроль: {path} отсутствующий: {', '.join(missing)}")


def version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise SystemExit(f"недопустимый VERSION: {value}")
    return tuple(int(part) for part in match.groups())


version = read("VERSION").strip()
if version_tuple(version) < (0, 18, 11):
    raise SystemExit(f"Windows Атакующий CI контроль требует >=0.18.11, получил {version}")

runner = read("scripts/guard_ci/windows_adversarial.py")
require(runner, "scripts/guard_ci/windows_adversarial.py", [
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
    '"cargo", "test", "--manifest-path", "runtime/neverruntime/Cargo.toml"',
    '"evidenceRootSha256"',
    '"allAdversarialScenariosDetected": True',
    '"allCompatibilityScenariosPassed": True',
    '"sensorAndFixtureHashesBound": True',
    'WINDOWS_ADVERSARIAL_CERTIFICATE.json',
    'windows-adversarial-ci-0.18.11-live-jvm-attack-simulation-and-java-compatibility-certification',
])

unit_tests = read("scripts/guard_ci/test_windows_adversarial.py")
require(unit_tests, "scripts/guard_ci/test_windows_adversarial.py", [
    "test_valid_result_is_accepted",
    "test_tampered_scenario_is_rejected",
    "test_aggregate_requires_every_certified_java_major",
])

windows_tests = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
for test_name in [
    "neverguard_sensor_agentpath_loads_before_jvm_startup",
    "neverguard_module_guard_tracks_real_jvm_dll_load_and_heartbeat",
    "neverguard_continuous_guard_cross_checks_sensor_and_guard_heartbeat",
    "neverguard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots",
    "neverguard_memory_integrity_fail_closed_on_executable_image_code_page_drift",
    "neverguard_thread_process_integrity_tracks_job_bound_descendant_processes",
    "neverguard_thread_integrity_fail_closed_on_private_executable_thread_start",
    "neverguard_debug_instrumentation_guard_rejects_startup_agents_and_enforces_attach_disable",
    "neverguard_debug_instrumentation_guard_fail_closed_on_live_debugger_attach",
    "neverguard_jvm_aware_protection_accepts_certified_hotspot_jit",
    "neverguard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation",
]:
    if test_name not in windows_tests:
        raise SystemExit(f"[NeverLauncher] Windows Атакующий CI 0.18.11 контроль: актуальный тест отсутствующий: {test_name}")

ci = read(".github/workflows/ci.yml")
require(ci, ".github/workflows/ci.yml", [
    "neverguard-windows-adversarial:",
    "java: [8, 16, 17, 21, 25]",
    "scripts/guard_ci/windows_adversarial.py run",
    "neverguard-windows-adversarial-certificate:",
    "scripts/guard_ci/windows_adversarial.py aggregate",
    "WINDOWS_ADVERSARIAL_CERTIFICATE.json",
    "neverguard-windows-adversarial-ci-01811.py",
])
for manifest in [
    "runtime/neverguard-sensor/Cargo.toml",
    "runtime/neverguard-memory-probe/Cargo.toml",
    "runtime/neverguard-thread-probe/Cargo.toml",
    "runtime/neverguard-debug-probe/Cargo.toml",
    "runtime/neverguard-jvm-probe/Cargo.toml",
]:
    if manifest not in ci:
        raise SystemExit(f"[NeverLauncher] Windows Атакующий CI 0.18.11 контроль: CI делает не сборка {manifest}")

preflight = read("scripts/release/preflight.sh")
if "neverguard-windows-adversarial-ci-01811.py" not in preflight or "test_windows_adversarial.py" not in preflight:
    raise SystemExit("[NeverLauncher] Windows Атакующий CI 0.18.11 контроль: релиз preflight/self-test wiring отсутствующий")

for rel, text in [
    ("scripts/guard_ci/windows_adversarial.py", runner),
    ("scripts/guard_ci/test_windows_adversarial.py", unit_tests),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(f"[NeverLauncher] Windows Атакующий CI 0.18.11 контроль: placeholder {placeholder!r} в {rel}")

print(f"[NeverLauncher] Windows Атакующий CI attack-simulation + совместимость сертификация 0.18.11 контроль: OK ({version})")
