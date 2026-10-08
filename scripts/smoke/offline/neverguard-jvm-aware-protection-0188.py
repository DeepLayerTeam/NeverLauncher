#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"[NeverLauncher] JVM-Учитывающий Защита 0.18.8 контроль: отсутствующий {rel}")
    return path.read_text(encoding="utf-8")


def require(text: str, rel: str, values: list[str]) -> None:
    missing = [value for value in values if value not in text]
    if missing:
        raise SystemExit(
            f"[NeverLauncher] JVM-Учитывающий Защита 0.18.8 контроль: {rel} отсутствующий {missing}"
        )


if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 8):
    raise SystemExit(f"[NeverLauncher] JVM-Учитывающий Защита 0.18.8 контроль: VERSION является {VERSION}")

sensor = read("runtime/neverguard-sensor/src/jvm_awareness.rs")
stream = read("runtime/neverguard-sensor/src/lib.rs")
hooks = read("runtime/neverguard-sensor/src/hook_engine.rs")
parent = read("runtime/neverruntime/src/windows_module_guard.rs")
report = read("runtime/neverruntime/src/windows_jvm_aware.rs")
integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
probe = read("runtime/neverguard-jvm-probe/src/lib.rs")
managed_java = read("runtime/neverruntime/src/managed_java.rs")
ci = read(".github/workflows/ci.yml")
adversarial_ci = read("scripts/guard_ci/windows_adversarial.py")
preflight = read("scripts/release/preflight.sh")

require(sensor, "runtime/neverguard-sensor/src/jvm_awareness.rs", [
    "CERTIFIED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
    "GetModuleHandleW",
    "GetFileVersionInfoW",
    "VerQueryValueW",
    "RtlCaptureStackBackTrace",
    "MEM_PRIVATE",
    "capture_transition_provenance",
    "observe_memory_transition",
    "outside jvm.dll provenance",
    "count_private_executable_regions",
    "reconcile_and_verify",
])
require(hooks, "runtime/neverguard-sensor/src/hook_engine.rs", [
    "jvm_awareness::capture_transition_provenance",
    "jvm_awareness::observe_memory_transition",
    "hook_virtual_alloc",
    "hook_virtual_protect",
])
require(stream, "runtime/neverguard-sensor/src/lib.rs", [
    "MODULE_EVENT_REASON_JVM_AWARE_READY",
    "MODULE_EVENT_REASON_JVM_AWARE_HEARTBEAT",
    "MODULE_EVENT_REASON_JVM_AWARE_TAMPER",
    "JVM_AWARE_CHECK_INTERVAL",
    "jvm_awareness::initialize(vm)",
    "jvm_awareness::reconcile_and_verify()",
    "jvm_awareness::shutdown()",
])
require(parent, "runtime/neverruntime/src/windows_module_guard.rs", [
    "jvm_aware: crate::WindowsJvmAwareProtectionReport",
    "expected JVM_AWARE_READY as fifth event",
    "jvm_aware_report_from_event",
    "NEVERGUARD_CERTIFIED_JAVA_MAJORS",
    "non-JVM executable-memory transition",
])
require(report, "runtime/neverruntime/src/windows_jvm_aware.rs", [
    "NEVERGUARD_JVM_AWARE_PROTECTION_VERSION",
    "NEVERGUARD_CERTIFIED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
    "baseline_private_executable_region_count",
    "jit_transition_count",
    "foreign_executable_transition_count",
    "jvm_path_sha256",
    "state_sha256",
])
require(integration, "runtime/neverruntime/tests/neverguard_sensor_windows.rs", [
    "neverguard_jvm_aware_protection_accepts_certified_hotspot_jit",
    "neverguard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation",
    "-Xbatch",
    "-XX:CompileThreshold=100",
    "NEVERGUARD_EXPECTED_JAVA_MAJOR",
    "NEVERGUARD_JVM_PROBE_DLL",
])
require(probe, "runtime/neverguard-jvm-probe/src/lib.rs", [
    "VirtualAlloc",
    "PAGE_EXECUTE_READWRITE",
    "neverguard-jvm-aware-probe",
])
require(managed_java, "runtime/neverruntime/src/managed_java.rs", [
    "MANAGED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
])
require(ci, ".github/workflows/ci.yml", [
    "neverguard-jvm-aware-protection-0188.py",
    "runtime/neverguard-jvm-probe/Cargo.toml",
    "java: [8, 16, 17, 21, 25]",
    "scripts/guard_ci/windows_adversarial.py run",
])
require(adversarial_ci, "scripts/guard_ci/windows_adversarial.py", [
    "NEVERGUARD_JVM_PROBE_DLL",
    "NEVERGUARD_EXPECTED_JAVA_MAJOR",
    "neverguard_jvm_aware_protection_accepts_certified_hotspot_jit",
    "neverguard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation",
])
if "neverguard-jvm-aware-protection-0188.py" not in preflight:
    raise SystemExit("[NeverLauncher] JVM-Учитывающий Защита 0.18.8 контроль: предварительная проверка wiring отсутствующий")

for rel, text in [
    ("runtime/neverguard-sensor/src/jvm_awareness.rs", sensor),
    ("runtime/neverruntime/src/windows_jvm_aware.rs", report),
    ("runtime/neverguard-jvm-probe/src/lib.rs", probe),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(
                f"[NeverLauncher] JVM-Учитывающий Защита 0.18.8 контроль: placeholder {placeholder!r} в {rel}"
            )

print("[NeverLauncher] JVM-Учитывающий Защита 0.18.8 контроль: OK")
