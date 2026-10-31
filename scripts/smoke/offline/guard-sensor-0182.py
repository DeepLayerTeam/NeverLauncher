#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(
            f"[Launcher] Guard Sensor 0.18.2 gate: {label} missing {missing}"
        )


def main() -> int:
    version = read("VERSION").strip()
    if tuple(
        int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]
    ) < (0, 18, 2):
        raise SystemExit(f"[Launcher] Guard Sensor 0.18.2 gate: VERSION is {version}")

    sensor = read("runtime/guard-sensor/src/lib.rs")
    sensor_manifest = read("runtime/guard-sensor/Cargo.toml")
    bootstrap = read("runtime/runtime/src/windows_sensor.rs")
    runtime = read("runtime/runtime/src/lib.rs")
    supervisor = read("runtime/runtime/src/supervisor.rs")
    ipc = read("runtime/runtime/src/guard_ipc.rs")
    integration = read("runtime/runtime/tests/guard_sensor_windows.rs")
    windows_build = read("scripts/release/build-windows-desktop.ps1")
    updater = read("cli/cmd/launcher/component_update.go")
    signing = read("cli/cmd/launcher/windows_signing.go")
    release = read("cli/cmd/launcher/release_commands.go")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(
        sensor_manifest,
        ['crate-type = ["cdylib"]', 'name = "guard_sensor"'],
        "native DLL build",
    )
    require(
        sensor,
        [
            'pub extern "system" fn Agent_OnLoad',
            'pub extern "system" fn Agent_OnUnload',
            "SENSOR_MAGIC",
            "SENSOR_DOMAIN",
            "HmacSha256::new_from_slice",
            "OpenOptions::new()",
            ".write_all(&packet)",
            "return JNI_ERR",
        ],
        "real JVM agent/HMAC startup proof",
    )
    require(
        bootstrap,
        [
            'GUARD_SENSOR_FILE_NAME: &str = "guard-sensor.dll"',
            "OsRng.fill_bytes(&mut secret)",
            'OsString::from("-agentpath:")',
            "create_secure_pipe_server(&endpoint)",
            "verify_windows_authenticode_trust(&sensor_path)",
            "expected[..].ct_eq(&packet[16..])",
            "pub async fn authenticate_sensor_or_kill",
            "child.start_kill()",
            "loaded_before_main: true",
            "arm_module_guard",
        ],
        "launcher-side fail-closed bootstrap",
    )
    for label, body, count in [
        ("direct runtime launch paths", runtime, 2),
        ("supervised runtime launch path", supervisor, 1),
    ]:
        if body.count("prepare_sensor_command(&mut command)") < count:
            raise SystemExit(
                f"[Launcher] Guard Sensor 0.18.2 gate: {label} does not prepare sensor"
            )
        if (
            body.count("authenticate_sensor_or_kill(sensor_bootstrap, &mut child)")
            < count
        ):
            raise SystemExit(
                f"[Launcher] Guard Sensor 0.18.2 gate: {label} does not authenticate sensor fail-closed"
            )
    require(
        supervisor,
        ["pub windows_sensor: Option<crate::WindowsSensorReport>"],
        "runtime status evidence",
    )
    require(
        ipc,
        [
            "GUARD_SENSOR_FILE_NAME",
            "verify_package_artifact(&manifest, &sensor_path)",
            "verify_windows_authenticode_trust(&sensor_path)",
        ],
        "package/runtime signature boundary",
    )
    require(
        windows_build,
        [
            "runtime\\guard-sensor\\Cargo.toml",
            "cargo build --release --target $Target.RustTarget --manifest-path $SensorManifest",
            "guard_sensor.dll",
            "Sign-And-VerifyAuthenticode $SensorPackagePath",
            'sensorVerification = "sha256+pe-machine+authenticode-before-agentpath"',
            '@("guard.exe", "guard-sensor.dll", "runtime.exe", "launcher-cli.exe")',
            'component = "sensor"',
            "guard-sensor-windows-$Arch.dll",
        ],
        "signed x64/ARM64 production delivery",
    )
    require(updater, ['expected["sensor"] = false'], "transactional sensor update")
    require(
        signing,
        [
            "func guardSensorRequired0182",
            'artifacts["sensor"] = "guard-sensor-windows-" + arch + ".dll"',
            'packageEntries["sensor"] = "guard-sensor.dll"',
            "expectedComponentCount = 4",
        ],
        "delivery verification",
    )
    require(
        release,
        ["guard-sensor-windows-x64.dll", "guard-sensor-windows-arm64.dll"],
        "publish gate",
    )
    require(
        integration,
        [
            "guard_sensor_agentpath_loads_before_jvm_startup",
            "prepare_sensor_command_with_path",
            "enforce_runtime_process(&mut child)",
            "authenticate_sensor_or_kill(bootstrap, &mut child)",
            "let report = session.report()",
            "assert!(report.loaded_before_main)",
        ],
        "real Java integration test",
    )
    require(
        ci,
        [
            "actions/setup-java@v4",
            "cargo build --manifest-path runtime/guard-sensor/Cargo.toml",
            "GUARD_SENSOR_TEST_DLL",
            "cargo test --manifest-path runtime/runtime/Cargo.toml --test guard_sensor_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/guard-sensor/Cargo.toml --all-targets -- -D warnings",
        ],
        "Windows compile/integration/clippy CI",
    )
    if "guard-sensor-0182.py" not in preflight:
        raise SystemExit(
            "[Launcher] Guard Sensor 0.18.2 gate: preflight wiring missing"
        )

    for path, body in [
        ("runtime/guard-sensor/src/lib.rs", sensor),
        ("runtime/runtime/src/windows_sensor.rs", bootstrap),
        ("scripts/release/build-windows-desktop.ps1", windows_build),
    ]:
        for forbidden in (
            "todo!()",
            "unimplemented!()",
            "TODO: stub",
            "foundation placeholder",
        ):
            if forbidden in body:
                raise SystemExit(
                    f"[Launcher] Guard Sensor 0.18.2 gate: placeholder {forbidden!r} in {path}"
                )

    print("[Launcher] Guard Sensor 0.18.2 gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
