#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"[Launcher] Continuous Guard 0.18.9 gate: missing {rel}")
    return path.read_text(encoding="utf-8")


def require(text: str, rel: str, values: list[str]) -> None:
    missing = [value for value in values if value not in text]
    if missing:
        raise SystemExit(
            f"[Launcher] Continuous Guard 0.18.9 gate: {rel} missing {missing}"
        )


if tuple(int(p) for p in VERSION.split("-")[0].split("+")[0].split(".")[:3]) < (
    0,
    18,
    9,
):
    raise SystemExit(f"[Launcher] Continuous Guard 0.18.9 gate: VERSION is {VERSION}")

sensor = read("runtime/guard-sensor/src/continuous_guard.rs")
stream = read("runtime/guard-sensor/src/lib.rs")
parent = read("runtime/runtime/src/windows_module_guard.rs")
report = read("runtime/runtime/src/windows_continuous_guard.rs")
integration = read("runtime/runtime/tests/guard_sensor_windows.rs")
ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")

require(
    sensor,
    "runtime/guard-sensor/src/continuous_guard.rs",
    [
        "Launcher Continuous Guard sensor-event-chain v1",
        "NGCGAK01",
        "guard-continuous-guard-ack-v1",
        "PeekNamedPipe",
        "GUARD_ACK_TIMEOUT",
        "advance_event_chain",
        "cross_check_event",
        "wait_for_guard_ack",
        "Guard-ACK HMAC mismatch",
        "Guard-ACK event-chain mismatch",
    ],
)
require(
    stream,
    "runtime/guard-sensor/src/lib.rs",
    [
        "MODULE_EVENT_REASON_CONTINUOUS_READY",
        "MODULE_EVENT_REASON_CONTINUOUS_HEARTBEAT",
        "MODULE_EVENT_REASON_CONTINUOUS_TAMPER",
        "CONTINUOUS_GUARD_HEARTBEAT_INTERVAL",
        "continuous_guard::reset_event_chain()",
        "continuous_guard::cross_check_event",
        "continuous_guard::wait_for_guard_ack",
        "module_worker(channel, sequence, guard_sequence)",
    ],
)
require(
    parent,
    "runtime/runtime/src/windows_module_guard.rs",
    [
        "continuous_guard: crate::WindowsContinuousGuardReport",
        "expected CONTINUOUS_READY as sixth event",
        "advance_continuous_event_chain",
        "write_continuous_guard_ack",
        "event-chain cross-check mismatch",
        "guard-sequence mismatch",
        "sensor_event_chain_sha256",
        "last_cross_check_sha256",
    ],
)
require(
    report,
    "runtime/runtime/src/windows_continuous_guard.rs",
    [
        "GUARD_CONTINUOUS_GUARD_VERSION",
        "WindowsContinuousGuardReport",
        "sensor_heartbeat_count",
        "guard_heartbeat_count",
        "cross_check_count",
        "last_sensor_sequence",
        "last_guard_sequence",
        "sensor_event_chain_sha256",
        "last_cross_check_sha256",
    ],
)
require(
    integration,
    "runtime/runtime/tests/guard_sensor_windows.rs",
    [
        "guard_continuous_guard_cross_checks_sensor_and_guard_heartbeat",
        "GUARD_CONTINUOUS_GUARD_VERSION",
        "sensor_heartbeat_count",
        "guard_heartbeat_count",
        "cross_check_count",
        "every Sensor heartbeat must receive exactly one Guard ACK",
    ],
)
require(
    ci,
    ".github/workflows/ci.yml",
    [
        "guard-continuous-guard-0189.py",
        "guard_continuous_guard_cross_checks_sensor_and_guard_heartbeat",
        "cargo clippy --manifest-path runtime/guard-sensor/Cargo.toml --all-targets -- -D warnings",
    ],
)
if "guard-continuous-guard-0189.py" not in preflight:
    raise SystemExit(
        "[Launcher] Continuous Guard 0.18.9 gate: preflight wiring missing"
    )

for rel, text in [
    ("runtime/guard-sensor/src/continuous_guard.rs", sensor),
    ("runtime/runtime/src/windows_continuous_guard.rs", report),
]:
    lowered = text.lower()
    for placeholder in ["todo!", "unimplemented!", "placeholder", "stub"]:
        if placeholder in lowered:
            raise SystemExit(
                f"[Launcher] Continuous Guard 0.18.9 gate: placeholder {placeholder!r} in {rel}"
            )

print("[Launcher] Continuous Guard 0.18.9 gate: OK")
