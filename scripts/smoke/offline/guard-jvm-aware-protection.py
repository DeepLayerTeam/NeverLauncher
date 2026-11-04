#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"[Launcher] JVM-Aware Protection 0.18.8 gate: missing {rel}")
    return path.read_text(encoding="utf-8")


def require(text: str, rel: str, values: list[str]) -> None:
    missing = [value for value in values if value not in text]
    if missing:
        raise SystemExit(
            f"[Launcher] JVM-Aware Protection 0.18.8 gate: {rel} missing {missing}"
        )


if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) < (
    0,
    18,
    8,
):
    raise SystemExit(
        f"[Launcher] JVM-Aware Protection 0.18.8 gate: VERSION is {VERSION}"
    )

sensor = read("runtime/guard-sensor/src/jvm_awareness.rs")
stream = read("runtime/guard-sensor/src/lib.rs")
hooks = read("runtime/guard-sensor/src/hook_engine.rs")
parent = read("runtime/runtime/src/windows_module_guard.rs")
report = read("runtime/runtime/src/windows_jvm_aware.rs")
integration = read("runtime/runtime/tests/guard_sensor_windows.rs")
probe = read("runtime/guard-jvm-probe/src/lib.rs")
managed_java = read("runtime/runtime/src/managed_java.rs")
ci = read(".github/workflows/ci.yml")
adversarial_ci = read("scripts/guard_ci/windows_adversarial.py")
preflight = read("scripts/release/preflight.sh")

require(
    sensor,
    "runtime/guard-sensor/src/jvm_awareness.rs",
    [
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
    ],
)
require(
    hooks,
    "runtime/guard-sensor/src/hook_engine.rs",
    [
        "jvm_awareness::capture_transition_provenance",
        "jvm_awareness::observe_memory_transition",
        "hook_virtual_alloc",
        "hook_virtual_protect",
    ],
)
require(
    stream,
    "runtime/guard-sensor/src/lib.rs",
    [
        "MODULE_EVENT_REASON_JVM_AWARE_READY",
        "MODULE_EVENT_REASON_JVM_AWARE_HEARTBEAT",
        "MODULE_EVENT_REASON_JVM_AWARE_TAMPER",
        "JVM_AWARE_CHECK_INTERVAL",
        "jvm_awareness::initialize(vm)",
        "jvm_awareness::reconcile_and_verify()",
        "jvm_awareness::shutdown()",
    ],
)
require(
    parent,
    "runtime/runtime/src/windows_module_guard.rs",
    [
        "jvm_aware: crate::WindowsJvmAwareProtectionReport",
        "expected JVM_AWARE_READY as fifth event",
        "jvm_aware_report_from_event",
        "GUARD_CERTIFIED_JAVA_MAJORS",
        "non-JVM executable-memory transition",
    ],
)
require(
    report,
    "runtime/runtime/src/windows_jvm_aware.rs",
    [
        "GUARD_JVM_AWARE_PROTECTION_VERSION",
        "GUARD_CERTIFIED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
        "baseline_private_executable_region_count",
        "jit_transition_count",
        "foreign_executable_transition_count",
        "jvm_path_sha256",
        "state_sha256",
    ],
)
require(
    integration,
    "runtime/runtime/tests/guard_sensor_windows.rs",
    [
        "guard_jvm_aware_protection_accepts_certified_hotspot_jit",
        "guard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation",
        "-Xbatch",
        "-XX:CompileThreshold=100",
        "GUARD_EXPECTED_JAVA_MAJOR",
        "GUARD_JVM_PROBE_DLL",
    ],
)
require(
    probe,
    "runtime/guard-jvm-probe/src/lib.rs",
    [
        "VirtualAlloc",
        "PAGE_EXECUTE_READWRITE",
        "guard-jvm-aware-probe",
    ],
)
require(
    managed_java,
    "runtime/runtime/src/managed_java.rs",
    [
        "MANAGED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25]",
    ],
)
require(
    ci,
    ".github/workflows/ci.yml",
    [
        "guard-jvm-aware-protection-0188.py",
        "runtime/guard-jvm-probe/Cargo.toml",
        "java: [8, 16, 17, 21, 25]",
        "scripts/guard_ci/windows_adversarial.py run",
    ],
)
require(
    adversarial_ci,
    "scripts/guard_ci/windows_adversarial.py",
    [
        "GUARD_JVM_PROBE_DLL",
        "GUARD_EXPECTED_JAVA_MAJOR",
        "guard_jvm_aware_protection_accepts_certified_hotspot_jit",
        "guard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation",
    ],
)
if "guard-jvm-aware-protection-0188.py" not in preflight:
    raise SystemExit(
        "[Launcher] JVM-Aware Protection 0.18.8 gate: preflight wiring missing"
    )

for rel, text in [
    ("runtime/guard-sensor/src/jvm_awareness.rs", sensor),
    ("runtime/runtime/src/windows_jvm_aware.rs", report),
    ("runtime/guard-jvm-probe/src/lib.rs", probe),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(
                f"[Launcher] JVM-Aware Protection 0.18.8 gate: placeholder {placeholder!r} in {rel}"
            )

print("[Launcher] JVM-Aware Protection 0.18.8 gate: OK")
