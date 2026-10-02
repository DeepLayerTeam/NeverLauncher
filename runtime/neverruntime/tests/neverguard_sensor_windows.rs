#![cfg(windows)]

use neverruntime::{
    windows_policy::{enforce_runtime_process, prepare_runtime_command},
    windows_sensor::{
        authenticate_sensor_or_kill, prepare_sensor_command_with_path,
        NEVERGUARD_SENSOR_PROTOCOL_VERSION,
    },
    NEVERGUARD_HOOK_ENGINE_VERSION, NEVERGUARD_MODULE_GUARD_VERSION,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, time::{sleep, Duration}};

fn java_tools() -> (PathBuf, PathBuf) {
    let java_home = std::env::var("JAVA_HOME").expect("JAVA_HOME must be set by Windows CI");
    let java_home = PathBuf::from(java_home);
    let java = java_home.join("bin").join("java.exe");
    let javac = java_home.join("bin").join("javac.exe");
    assert!(java.is_file(), "java.exe missing: {}", java.display());
    assert!(javac.is_file(), "javac.exe missing: {}", javac.display());
    (java, javac)
}

fn sensor_path() -> PathBuf {
    let sensor = PathBuf::from(
        std::env::var("NEVERGUARD_SENSOR_TEST_DLL")
            .expect("NEVERGUARD_SENSOR_TEST_DLL must point to built neverguard_sensor.dll"),
    );
    assert!(sensor.is_file(), "sensor DLL missing: {}", sensor.display());
    sensor
}

fn unique_test_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "neverguard-module-guard-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn compile_module_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create Java probe directory");
    fs::write(
        directory.join("ModuleGuardProbe.java"),
        r#"public final class ModuleGuardProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("native DLL path required");
        System.load(args[0]);
        Thread.sleep(3500L);
    }
}
"#,
    )
    .expect("write Java probe");
    let status = std::process::Command::new(javac)
        .arg("ModuleGuardProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac");
    assert!(status.success(), "javac failed: {status}");
}

#[tokio::test]
async fn neverguard_sensor_agentpath_loads_before_jvm_startup() {
    let (java, _) = java_tools();
    let sensor = sensor_path();

    let mut command = Command::new(java);
    command.current_dir(std::env::current_dir().expect("current dir"));
    let bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command.arg("-version");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    let pid = child.id().expect("Java PID");
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("sensor Agent_OnLoad + Module Guard arm handshake");
    let report = session.report();

    assert_eq!(report.protocol_version, NEVERGUARD_SENSOR_PROTOCOL_VERSION);
    assert_eq!(report.pid, pid);
    assert!(report.authenticated);
    assert!(report.loaded_before_main);
    assert_eq!(report.module_guard.version, NEVERGUARD_MODULE_GUARD_VERSION);
    assert!(report.module_guard.healthy);
    assert!(report.module_guard.baseline_module_count > 0);
    assert_eq!(report.module_guard.violation_count, 0);
    assert_eq!(report.module_guard.hook_engine.version, NEVERGUARD_HOOK_ENGINE_VERSION);
    assert!(report.module_guard.hook_engine.active);
    assert!(report.module_guard.hook_engine.healthy);
    assert!(report.module_guard.hook_engine.hooked_module_count > 0);
    assert!(report.module_guard.hook_engine.hooked_slot_count > 0);
    assert_eq!(report.module_guard.hook_engine.hook_set_sha256.len(), 64);
    assert!(runtime_policy.report().enforced);

    let status = child.wait().await.expect("wait Java");
    assert!(status.success(), "java -version failed after sensor load: {status}");
}

#[tokio::test]
async fn neverguard_module_guard_tracks_real_jvm_dll_load_and_heartbeat() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("track");
    let trusted = root.join("trusted");
    compile_module_probe(&javac, &trusted);
    let probe_dll = trusted.join("probe-native.dll");
    fs::copy(&sensor, &probe_dll).expect("copy probe DLL into trusted runtime root");
    let probe_dll = fs::canonicalize(&probe_dll).expect("canonical probe DLL");

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java probe suspended");
    let _runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("arm Module Guard before Java main");
    let status = child.wait().await.expect("wait Java probe");
    assert!(status.success(), "trusted native probe failed: {status}");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(report.healthy, "Module Guard violation: {}", report.last_violation);
    assert_eq!(report.violation_count, 0);
    assert!(report.load_events >= 1, "expected at least one DLL load event: {report:?}");
    assert!(report.heartbeat_count >= 1, "expected continuous heartbeat: {report:?}");
    assert!(report.event_count >= report.load_events + report.heartbeat_count);
    assert!(report.hook_engine.healthy, "Hook Engine violation: {}", report.hook_engine.last_violation);
    assert!(report.hook_engine.hooked_module_count > 0);
    assert!(report.hook_engine.hooked_slot_count > 0);
    assert!(report.hook_engine.integrity_check_count >= 2);
    assert!(report.hook_engine.intercepted_call_count >= 1, "expected real intercepted JVM/native API call: {report:?}");
    assert_eq!(report.hook_engine.hook_set_sha256.len(), 64);
    assert_eq!(report.event_chain_sha256.len(), 64);
    assert_eq!(report.module_set_sha256.len(), 64);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn neverguard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("block");
    let trusted = root.join("trusted");
    let untrusted = root.join("untrusted");
    compile_module_probe(&javac, &trusted);
    fs::create_dir_all(&untrusted).expect("create untrusted directory");
    let probe_dll = untrusted.join("unsigned-probe-native.dll");
    fs::copy(&sensor, &probe_dll).expect("copy unsigned probe DLL outside trusted roots");
    let probe_dll = fs::canonicalize(&probe_dll).expect("canonical untrusted probe DLL");

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java probe suspended");
    let _runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("arm Module Guard before Java main");
    let status = child.wait().await.expect("wait blocked Java probe");
    assert!(!status.success(), "unsigned module outside trusted roots must be fail-closed");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy);
    assert!(report.violation_count >= 1, "expected Module Guard violation: {report:?}");
    assert!(
        report.last_violation.contains("outside trusted roots")
            || report.last_violation.contains("Authenticode"),
        "unexpected violation: {}",
        report.last_violation
    );

    let _ = fs::remove_dir_all(root);
}
