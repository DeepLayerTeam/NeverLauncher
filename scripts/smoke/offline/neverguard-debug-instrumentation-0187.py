#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: отсутствующий {rel}")
    return path.read_text(encoding="utf-8")


def require(text: str, rel: str, values: list[str]) -> None:
    missing = [value for value in values if value not in text]
    if missing:
        raise SystemExit(
            f"[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: {rel} отсутствующий {missing}"
        )


if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 7):
    raise SystemExit(f"[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: VERSION является {VERSION}")

sensor = read("runtime/neverguard-sensor/src/debug_instrumentation.rs")
stream = read("runtime/neverguard-sensor/src/lib.rs")
launcher = read("runtime/neverruntime/src/windows_sensor.rs")
parent = read("runtime/neverruntime/src/windows_module_guard.rs")
report = read("runtime/neverruntime/src/windows_debug_instrumentation.rs")
integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
probe = read("runtime/neverguard-debug-probe/src/main.rs")
ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")

require(sensor, "runtime/neverguard-sensor/src/debug_instrumentation.rs", [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "PROCESS_DEBUG_PORT",
    "PROCESS_DEBUG_OBJECT_HANDLE",
    "PROCESS_DEBUG_FLAGS",
    "STATUS_PORT_NOT_SET",
    "reconcile_and_verify",
    "detected debugger boundary",
    "Debug & Instrumentation Guard state v1",
])
for forbidden in ["DebugActiveProcess(", "WriteProcessMemory", "CreateRemoteThread", "NtSetInformationThread"]:
    if forbidden in sensor:
        raise SystemExit(
            f"[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: Sensor использует forbidden anti-analysis primitive {forbidden}"
        )

require(stream, "runtime/neverguard-sensor/src/lib.rs", [
    "MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_READY",
    "MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_HEARTBEAT",
    "MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_TAMPER",
    "DEBUG_INSTRUMENTATION_CHECK_INTERVAL",
    "debug_instrumentation::initialize()",
    "debug_instrumentation::reconcile_and_verify()",
    "debug_instrumentation::shutdown()",
])
require(launcher, "runtime/neverruntime/src/windows_sensor.rs", [
    "-XX:+DisableAttachMechanism",
    "-javaagent:",
    "-agentlib:",
    "-agentpath:",
    "-Xrunjdwp:",
    "-Xdebug",
    "-XX:+StartAttachListener",
    "-XX:-DisableAttachMechanism",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "validate_startup_instrumentation_boundary",
])
require(parent, "runtime/neverruntime/src/windows_module_guard.rs", [
    "debug_instrumentation: crate::WindowsDebugInstrumentationReport",
    "expected DEBUG_INSTRUMENTATION_READY as fourth event",
    "debug_instrumentation_report_from_event",
    "unwanted debug/instrumentation boundary detected",
    "fail_closed",
])
require(report, "runtime/neverruntime/src/windows_debug_instrumentation.rs", [
    "pub struct WindowsDebugInstrumentationReport",
    "NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION",
    "attach_mechanism_disabled",
    "debug_port_present",
    "debug_object_present",
    "state_sha256",
])
require(integration, "runtime/neverruntime/tests/neverguard_sensor_windows.rs", [
    "neverguard_debug_instrumentation_guard_rejects_startup_agents_and_enforces_attach_disable",
    "neverguard_debug_instrumentation_guard_fail_closed_on_live_debugger_attach",
    "live debugger attach must be fail-closed",
    "NEVERGUARD_DEBUG_PROBE_EXE",
])
require(probe, "runtime/neverguard-debug-probe/src/main.rs", [
    "DebugActiveProcess",
    "WaitForDebugEvent",
    "ContinueDebugEvent",
    "DebugSetProcessKillOnExit",
])
require(ci, ".github/workflows/ci.yml", [
    "neverguard-debug-instrumentation-0187.py",
    "runtime/neverguard-debug-probe/Cargo.toml",
    "NEVERGUARD_DEBUG_PROBE_EXE",
    "cargo clippy --manifest-path runtime/neverguard-debug-probe/Cargo.toml --all-targets -- -D warnings",
    "--test neverguard_sensor_windows",
])
if "neverguard-debug-instrumentation-0187.py" not in preflight:
    raise SystemExit("[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: предварительная проверка wiring отсутствующий")

for rel, text in [
    ("runtime/neverguard-sensor/src/debug_instrumentation.rs", sensor),
    ("runtime/neverruntime/src/windows_debug_instrumentation.rs", report),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(
                f"[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: placeholder {placeholder!r} в {rel}"
            )

print("[NeverLauncher] Отладка и Инструментирование Защита 0.18.7 контроль: OK")
