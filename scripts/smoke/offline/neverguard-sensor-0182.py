#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"[NeverLauncher] NeverGuard Sensor 0.18.2 gate: {label} missing {missing}")


def main() -> int:
    version = read("VERSION").strip()
    if tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 2):
        raise SystemExit(f"[NeverLauncher] NeverGuard Sensor 0.18.2 gate: VERSION is {version}")

    sensor = read("runtime/neverguard-sensor/src/lib.rs")
    sensor_manifest = read("runtime/neverguard-sensor/Cargo.toml")
    bootstrap = read("runtime/neverruntime/src/windows_sensor.rs")
    runtime = read("runtime/neverruntime/src/lib.rs")
    supervisor = read("runtime/neverruntime/src/supervisor.rs")
    ipc = read("runtime/neverruntime/src/guard_ipc.rs")
    integration = read("runtime/neverruntime/tests/neverguard_sensor_windows.rs")
    windows_build = read("scripts/release/build-windows-desktop.ps1")
    updater = read("cli/cmd/neverlauncher/component_update.go")
    signing = read("cli/cmd/neverlauncher/windows_signing.go")
    release = read("cli/cmd/neverlauncher/release_commands.go")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(sensor_manifest, ['crate-type = ["cdylib"]', 'name = "neverguard_sensor"'], "native DLL build")
    require(
        sensor,
        [
            'pub extern "system" fn Agent_OnLoad',
            'pub extern "system" fn Agent_OnUnload',
            'b"NGSENS03"',
            'b"neverguard-sensor-startup-v2"',
            'HmacSha256::new_from_slice',
            'OpenOptions::new()',
            '.write_all(&packet)',
            'return JNI_ERR',
        ],
        "real JVM agent/HMAC startup proof",
    )
    require(
        bootstrap,
        [
            'NEVERGUARD_SENSOR_FILE_NAME: &str = "neverguard-sensor.dll"',
            'OsRng.fill_bytes(&mut secret)',
            'OsString::from("-agentpath:")',
            'create_secure_pipe_server(&endpoint)',
            'verify_windows_authenticode_trust(&sensor_path)',
            'expected[..].ct_eq(&packet[16..])',
            'pub async fn authenticate_sensor_or_kill',
            'child.start_kill()',
            'loaded_before_main: true',
            'arm_module_guard',
        ],
        "launcher-side fail-closed bootstrap",
    )
    for label, body, count in [
        ("direct runtime launch paths", runtime, 2),
        ("supervised runtime launch path", supervisor, 1),
    ]:
        if body.count("prepare_sensor_command(&mut command)") < count:
            raise SystemExit(f"[NeverLauncher] NeverGuard Sensor 0.18.2 gate: {label} does not prepare sensor")
        if body.count("authenticate_sensor_or_kill(sensor_bootstrap, &mut child)") < count:
            raise SystemExit(f"[NeverLauncher] NeverGuard Sensor 0.18.2 gate: {label} does not authenticate sensor fail-closed")
    require(supervisor, ["pub windows_sensor: Option<crate::WindowsSensorReport>"], "runtime status evidence")
    require(
        ipc,
        [
            'NEVERGUARD_SENSOR_FILE_NAME',
            'verify_package_artifact(&manifest, &sensor_path)',
            'verify_windows_authenticode_trust(&sensor_path)',
        ],
        "package/runtime signature boundary",
    )
    require(
        windows_build,
        [
            'runtime\\neverguard-sensor\\Cargo.toml',
            'cargo build --release --target $Target.RustTarget --manifest-path $SensorManifest',
            'neverguard_sensor.dll',
            'Sign-And-VerifyAuthenticode $SensorPackagePath',
            'sensorVerification = "sha256+pe-machine+authenticode-before-agentpath"',
            '@("neverguard.exe", "neverguard-sensor.dll", "neverruntime.exe", "neverlauncher-cli.exe")',
            'component = "sensor"',
            'neverguard-sensor-windows-$Arch.dll',
        ],
        "signed x64/ARM64 production delivery",
    )
    require(updater, ['expected["sensor"] = false'], "transactional sensor update")
    require(
        signing,
        [
            'func neverguardSensorRequired0182',
            'artifacts["sensor"] = "neverguard-sensor-windows-" + arch + ".dll"',
            'packageEntries["sensor"] = "neverguard-sensor.dll"',
            'expectedComponentCount = 4',
        ],
        "delivery verification",
    )
    require(release, ['neverguard-sensor-windows-x64.dll', 'neverguard-sensor-windows-arm64.dll'], "publish gate")
    require(
        integration,
        [
            'neverguard_sensor_agentpath_loads_before_jvm_startup',
            'prepare_sensor_command_with_path',
            'enforce_runtime_process(&mut child)',
            'authenticate_sensor_or_kill(bootstrap, &mut child)',
            'let report = session.report()',
            'assert!(report.loaded_before_main)',
        ],
        "real Java integration test",
    )
    require(
        ci,
        [
            'actions/setup-java@v4',
            'cargo build --manifest-path runtime/neverguard-sensor/Cargo.toml',
            'NEVERGUARD_SENSOR_TEST_DLL',
            'cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_sensor_windows -- --nocapture',
            'cargo clippy --manifest-path runtime/neverguard-sensor/Cargo.toml --all-targets -- -D warnings',
        ],
        "Windows compile/integration/clippy CI",
    )
    if "neverguard-sensor-0182.py" not in preflight:
        raise SystemExit("[NeverLauncher] NeverGuard Sensor 0.18.2 gate: preflight wiring missing")

    for path, body in [
        ("runtime/neverguard-sensor/src/lib.rs", sensor),
        ("runtime/neverruntime/src/windows_sensor.rs", bootstrap),
        ("scripts/release/build-windows-desktop.ps1", windows_build),
    ]:
        for forbidden in ("todo!()", "unimplemented!()", "TODO: stub", "foundation placeholder"):
            if forbidden in body:
                raise SystemExit(f"[NeverLauncher] NeverGuard Sensor 0.18.2 gate: placeholder {forbidden!r} in {path}")

    print("[NeverLauncher] NeverGuard Sensor 0.18.2 gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
