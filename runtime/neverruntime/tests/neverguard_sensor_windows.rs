#![cfg(windows)]

use neverruntime::{
    windows_policy::{enforce_runtime_process, prepare_runtime_command},
    windows_sensor::{
        authenticate_sensor_or_kill, prepare_sensor_command_with_path,
        NEVERGUARD_SENSOR_PROTOCOL_VERSION,
    },
    NEVERGUARD_CONTINUOUS_GUARD_VERSION, NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION, NEVERGUARD_HOOK_ENGINE_VERSION,
    NEVERGUARD_JVM_AWARE_PROTECTION_VERSION, NEVERGUARD_MEMORY_INTEGRITY_VERSION,
    NEVERGUARD_MODULE_GUARD_VERSION, NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION,
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

fn memory_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("NEVERGUARD_MEMORY_PROBE_DLL")
            .expect("NEVERGUARD_MEMORY_PROBE_DLL must point to built neverguard_memory_probe.dll"),
    );
    assert!(probe.is_file(), "memory probe DLL missing: {}", probe.display());
    probe
}

fn thread_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("NEVERGUARD_THREAD_PROBE_DLL")
            .expect("NEVERGUARD_THREAD_PROBE_DLL must point to built neverguard_thread_probe.dll"),
    );
    assert!(probe.is_file(), "thread probe DLL missing: {}", probe.display());
    probe
}

fn debug_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("NEVERGUARD_DEBUG_PROBE_EXE")
            .expect("NEVERGUARD_DEBUG_PROBE_EXE must point to built neverguard-debug-probe.exe"),
    );
    assert!(probe.is_file(), "debug probe EXE missing: {}", probe.display());
    probe
}


fn jvm_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("NEVERGUARD_JVM_PROBE_DLL")
            .expect("NEVERGUARD_JVM_PROBE_DLL must point to built neverguard_jvm_probe.dll"),
    );
    assert!(probe.is_file(), "JVM-aware probe DLL missing: {}", probe.display());
    probe
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

fn compile_memory_integrity_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create Memory Integrity Java probe directory");
    fs::write(
        directory.join("MemoryIntegrityProbe.java"),
        r#"public final class MemoryIntegrityProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("native DLL path required");
        System.load(args[0]);
        Thread.sleep(8000L);
    }
}
"#,
    )
    .expect("write Memory Integrity Java probe");
    let status = std::process::Command::new(javac)
        .arg("MemoryIntegrityProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac for Memory Integrity probe");
    assert!(status.success(), "Memory Integrity javac failed: {status}");
}

fn compile_process_tree_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create Process Tree Java probe directory");
    fs::write(
        directory.join("ProcessTreeProbe.java"),
        r#"public final class ProcessTreeProbe {
    public static void main(String[] args) throws Exception {
        Process child = new ProcessBuilder("cmd.exe", "/c", "ping -n 6 127.0.0.1 >NUL").start();
        Thread.sleep(3500L);
        if (child.isAlive()) child.destroyForcibly();
        child.waitFor();
        Thread.sleep(1200L);
    }
}
"#,
    )
    .expect("write Process Tree Java probe");
    let status = std::process::Command::new(javac)
        .arg("ProcessTreeProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac for Process Tree probe");
    assert!(status.success(), "Process Tree javac failed: {status}");
}

fn compile_debug_boundary_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create Debug Guard Java probe directory");
    fs::write(
        directory.join("DebugBoundaryProbe.java"),
        r#"public final class DebugBoundaryProbe {
    public static void main(String[] args) throws Exception {
        Thread.sleep(15000L);
    }
}
"#,
    )
    .expect("write Debug Guard Java probe");
    let status = std::process::Command::new(javac)
        .arg("DebugBoundaryProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac for Debug Guard probe");
    assert!(status.success(), "Debug Guard javac failed: {status}");
}

fn compile_thread_integrity_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create Thread Integrity Java probe directory");
    fs::write(
        directory.join("ThreadIntegrityProbe.java"),
        r#"public final class ThreadIntegrityProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("native DLL path required");
        System.load(args[0]);
        Thread.sleep(12000L);
    }
}
"#,
    )
    .expect("write Thread Integrity Java probe");
    let status = std::process::Command::new(javac)
        .arg("ThreadIntegrityProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac for Thread Integrity probe");
    assert!(status.success(), "Thread Integrity javac failed: {status}");
}

fn compile_jvm_jit_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create JVM-Aware JIT Java probe directory");
    fs::write(
        directory.join("JvmAwareJitProbe.java"),
        r#"public final class JvmAwareJitProbe {
    private static long hot(long value) {
        long x = value;
        x ^= (x << 13);
        x ^= (x >>> 7);
        x ^= (x << 17);
        return x + 0x9E3779B97F4A7C15L;
    }
    public static void main(String[] args) throws Exception {
        long value = 1L;
        for (int outer = 0; outer < 120; outer++) {
            for (int i = 0; i < 200000; i++) value = hot(value + i);
        }
        if (value == 0L) throw new AssertionError("unreachable");
        Thread.sleep(2200L);
    }
}
"#,
    )
    .expect("write JVM-Aware JIT probe");
    let status = std::process::Command::new(javac)
        .arg("JvmAwareJitProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac for JVM-Aware JIT probe");
    assert!(status.success(), "JVM-Aware JIT javac failed: {status}");
}

fn compile_jvm_foreign_exec_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create JVM-Aware foreign exec Java probe directory");
    fs::write(
        directory.join("JvmAwareForeignExecProbe.java"),
        r#"public final class JvmAwareForeignExecProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("native DLL path required");
        System.load(args[0]);
        Thread.sleep(12000L);
    }
}
"#,
    )
    .expect("write JVM-Aware foreign exec probe");
    let status = std::process::Command::new(javac)
        .arg("JvmAwareForeignExecProbe.java")
        .current_dir(directory)
        .status()
        .expect("run javac for JVM-Aware foreign exec probe");
    assert!(status.success(), "JVM-Aware foreign exec javac failed: {status}");
}

fn expected_java_major() -> u32 {
    std::env::var("NEVERGUARD_EXPECTED_JAVA_MAJOR")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(21)
}

#[tokio::test]
async fn neverguard_sensor_agentpath_loads_before_jvm_startup() {
    let (java, _) = java_tools();
    let sensor = sensor_path();

    let mut command = Command::new(java);
    command.current_dir(std::env::current_dir().expect("current dir"));
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command.arg("-version");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
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
    assert_eq!(report.module_guard.memory_integrity.version, NEVERGUARD_MEMORY_INTEGRITY_VERSION);
    assert!(report.module_guard.memory_integrity.active);
    assert!(report.module_guard.memory_integrity.healthy);
    assert!(report.module_guard.memory_integrity.executable_region_count > 0);
    assert!(report.module_guard.memory_integrity.image_code_region_count > 0);
    assert_eq!(report.module_guard.memory_integrity.code_set_sha256.len(), 64);
    assert_eq!(report.module_guard.memory_integrity.executable_map_sha256.len(), 64);
    assert_eq!(
        report.module_guard.thread_process_integrity.version,
        NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION
    );
    assert!(report.module_guard.thread_process_integrity.active);
    assert!(report.module_guard.thread_process_integrity.healthy);
    assert!(report.module_guard.thread_process_integrity.current_thread_count > 0);
    assert!(report.module_guard.thread_process_integrity.job_bound);
    assert!(!report.module_guard.thread_process_integrity.breakaway_allowed);
    assert_eq!(report.module_guard.thread_process_integrity.thread_set_sha256.len(), 64);
    assert_eq!(report.module_guard.thread_process_integrity.process_tree_sha256.len(), 64);
    assert_eq!(
        report.module_guard.debug_instrumentation.version,
        NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION
    );
    assert!(report.module_guard.debug_instrumentation.active);
    assert!(report.module_guard.debug_instrumentation.healthy);
    assert!(report.module_guard.debug_instrumentation.attach_mechanism_disabled);
    assert!(!report.module_guard.debug_instrumentation.debugger_present);
    assert!(!report.module_guard.debug_instrumentation.remote_debugger_present);
    assert!(!report.module_guard.debug_instrumentation.debug_port_present);
    assert!(!report.module_guard.debug_instrumentation.debug_object_present);
    assert!(report.module_guard.debug_instrumentation.debug_flags_no_debug_inherit);
    assert_eq!(report.module_guard.debug_instrumentation.state_sha256.len(), 64);
    assert_eq!(
        report.module_guard.jvm_aware.version,
        NEVERGUARD_JVM_AWARE_PROTECTION_VERSION
    );
    assert!(report.module_guard.jvm_aware.active);
    assert!(report.module_guard.jvm_aware.healthy);
    assert!(report.module_guard.jvm_aware.certified_major);
    assert!([8, 16, 17, 21, 25].contains(&report.module_guard.jvm_aware.java_major));
    assert!(report.module_guard.jvm_aware.jvm_module_size > 0);
    assert_eq!(report.module_guard.jvm_aware.jvm_path_sha256.len(), 64);
    assert_eq!(report.module_guard.jvm_aware.state_sha256.len(), 64);
    assert_eq!(report.module_guard.jvm_aware.foreign_executable_transition_count, 0);
    assert_eq!(report.module_guard.jvm_aware.unknown_executable_transition_count, 0);
    assert_eq!(
        report.module_guard.continuous_guard.version,
        NEVERGUARD_CONTINUOUS_GUARD_VERSION
    );
    assert!(report.module_guard.continuous_guard.active);
    assert!(report.module_guard.continuous_guard.healthy);
    assert!(report.module_guard.continuous_guard.cross_check_count >= 1);
    assert_eq!(report.module_guard.continuous_guard.last_guard_sequence, 1);
    assert_eq!(report.module_guard.continuous_guard.last_cross_check_sha256.len(), 64);
    assert_eq!(report.module_guard.continuous_guard.sensor_event_chain_sha256.len(), 64);
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
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java probe suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
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
    assert!(report.memory_integrity.healthy, "Memory Integrity violation: {}", report.memory_integrity.last_violation);
    assert!(report.memory_integrity.integrity_check_count >= 2);
    assert!(report.memory_integrity.executable_region_count > 0);
    assert!(report.memory_integrity.image_code_region_count > 0);
    assert_eq!(report.memory_integrity.code_set_sha256.len(), 64);
    assert_eq!(report.memory_integrity.executable_map_sha256.len(), 64);
    assert!(report.thread_process_integrity.healthy);
    assert!(report.thread_process_integrity.integrity_check_count >= 2);
    assert!(report.thread_process_integrity.current_thread_count > 0);
    assert_eq!(report.thread_process_integrity.thread_set_sha256.len(), 64);
    assert_eq!(report.thread_process_integrity.thread_origin_set_sha256.len(), 64);
    assert_eq!(report.thread_process_integrity.process_tree_sha256.len(), 64);
    assert!(report.debug_instrumentation.healthy);
    assert!(report.debug_instrumentation.attach_mechanism_disabled);
    assert!(report.debug_instrumentation.integrity_check_count >= 2);
    assert_eq!(report.debug_instrumentation.state_sha256.len(), 64);
    assert_eq!(report.event_chain_sha256.len(), 64);
    assert_eq!(report.module_set_sha256.len(), 64);
    assert!(report.continuous_guard.healthy, "Continuous Guard violation: {}", report.continuous_guard.last_violation);
    assert!(report.continuous_guard.sensor_heartbeat_count >= 2, "expected Sensor heartbeats: {report:?}");
    assert!(report.continuous_guard.guard_heartbeat_count >= 2, "expected Guard heartbeats: {report:?}");
    assert!(report.continuous_guard.cross_check_count >= 2, "expected bidirectional cross-checks: {report:?}");
    assert_eq!(
        report.continuous_guard.sensor_heartbeat_count,
        report.continuous_guard.guard_heartbeat_count,
        "every Sensor heartbeat must receive exactly one Guard ACK"
    );
    assert_eq!(report.continuous_guard.last_cross_check_sha256.len(), 64);
    assert_eq!(report.continuous_guard.sensor_event_chain_sha256.len(), 64);
    assert!(report.continuous_guard.last_guard_sequence >= 2);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn neverguard_continuous_guard_cross_checks_sensor_and_guard_heartbeat() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("continuous-guard");
    let trusted = root.join("trusted");
    compile_module_probe(&javac, &trusted);
    let probe_dll = trusted.join("continuous-probe-native.dll");
    fs::copy(&sensor, &probe_dll).expect("copy continuous guard probe DLL");
    let probe_dll = fs::canonicalize(&probe_dll).expect("canonical continuous guard probe DLL");

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Continuous Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Continuous Guard Java probe");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce Continuous Guard runtime policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("Continuous Guard startup cross-check");
    let status = child.wait().await.expect("wait Continuous Guard Java probe");
    assert!(status.success(), "Continuous Guard healthy workload failed: {status}");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard.continuous_guard;
    assert_eq!(report.version, NEVERGUARD_CONTINUOUS_GUARD_VERSION);
    assert!(report.healthy, "Continuous Guard violation: {}", report.last_violation);
    assert!(report.sensor_heartbeat_count >= 3, "expected startup + runtime Sensor heartbeats: {report:?}");
    assert_eq!(report.sensor_heartbeat_count, report.guard_heartbeat_count);
    assert_eq!(report.sensor_heartbeat_count, report.cross_check_count);
    assert_eq!(report.last_guard_sequence, report.guard_heartbeat_count);
    assert!(report.last_sensor_sequence >= 6);
    assert_eq!(report.sensor_event_chain_sha256.len(), 64);
    assert_eq!(report.last_cross_check_sha256.len(), 64);
    assert_eq!(report.violation_count, 0);

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
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java probe suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
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


#[tokio::test]
async fn neverguard_memory_integrity_fail_closed_on_executable_image_code_page_drift() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let memory_probe = memory_probe_path();
    let root = unique_test_root("memory-drift");
    let trusted = root.join("trusted");
    compile_memory_integrity_probe(&javac, &trusted);
    let probe_dll = trusted.join("memory-tamper-probe.dll");
    fs::copy(&memory_probe, &probe_dll).expect("copy Memory Integrity tamper probe");
    let probe_dll = fs::canonicalize(&probe_dll).expect("canonical Memory Integrity probe DLL");

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("MemoryIntegrityProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Memory Integrity Java probe suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("arm Memory Integrity before Java main");
    let status = child.wait().await.expect("wait Memory Integrity tamper probe");
    assert!(!status.success(), "executable image code-page drift must be fail-closed");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy, "Module Guard must reflect Memory Integrity failure");
    assert!(!report.memory_integrity.healthy);
    assert!(report.memory_integrity.violation_count >= 1, "expected Memory Integrity violation: {report:?}");
    assert!(
        report.memory_integrity.last_violation.contains("code-page drift")
            || report.last_violation.contains("code-page drift"),
        "unexpected Memory Integrity violation: {}",
        report.memory_integrity.last_violation
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn neverguard_thread_process_integrity_tracks_job_bound_descendant_processes() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("process-tree");
    let trusted = root.join("trusted");
    compile_process_tree_probe(&javac, &trusted);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command.arg("-cp").arg(&trusted).arg("ProcessTreeProbe");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Process Tree Java probe suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("arm Thread & Process Integrity before Java main");
    let status = child.wait().await.expect("wait Process Tree Java probe");
    assert!(status.success(), "Process Tree probe failed: {status}");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard.thread_process_integrity;
    assert!(report.healthy, "Thread & Process Integrity violation: {}", report.last_violation);
    assert!(report.job_bound);
    assert!(!report.breakaway_allowed);
    assert!(report.descendant_process_peak >= 1, "expected observed job-bound descendant: {report:?}");
    assert!(report.process_transition_count >= 1, "expected process-tree transition: {report:?}");
    assert!(report.integrity_check_count >= 2);
    assert_eq!(report.process_tree_sha256.len(), 64);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn neverguard_thread_integrity_fail_closed_on_private_executable_thread_start() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let thread_probe = thread_probe_path();
    let root = unique_test_root("private-thread");
    let trusted = root.join("trusted");
    compile_thread_integrity_probe(&javac, &trusted);
    let probe_dll = trusted.join("thread-tamper-probe.dll");
    fs::copy(&thread_probe, &probe_dll).expect("copy Thread Integrity tamper probe");
    let probe_dll = fs::canonicalize(&probe_dll).expect("canonical Thread Integrity probe DLL");

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ThreadIntegrityProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Thread Integrity Java probe suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("arm Thread & Process Integrity before Java main");
    let status = child.wait().await.expect("wait Thread Integrity tamper probe");
    assert!(!status.success(), "private executable thread start must be fail-closed");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy, "Module Guard must reflect Thread Integrity failure");
    assert!(!report.thread_process_integrity.healthy);
    assert!(
        report.thread_process_integrity.violation_count >= 1,
        "expected Thread & Process Integrity violation: {report:?}"
    );
    assert!(
        report.thread_process_integrity.last_violation.contains("non-image executable memory")
            || report.last_violation.contains("non-image executable memory"),
        "unexpected Thread Integrity violation: {}",
        report.thread_process_integrity.last_violation
    );

    let _ = fs::remove_dir_all(root);
}



#[test]
fn neverguard_debug_instrumentation_guard_rejects_startup_agents_and_enforces_attach_disable() {
    let (java, _) = java_tools();
    let sensor = sensor_path();

    for forbidden in [
        "-javaagent:C:\\tmp\\agent.jar",
        "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005",
        "-agentpath:C:\\tmp\\foreign-agent.dll",
        "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005",
        "-Xdebug",
        "-XX:+StartAttachListener",
        "-XX:-DisableAttachMechanism",
    ] {
        let mut command = Command::new(&java);
        command.arg(forbidden);
        let err = match prepare_sensor_command_with_path(&mut command, sensor.clone()) {
            Ok(_) => panic!("startup instrumentation must be rejected before JVM spawn: {forbidden}"),
            Err(err) => err,
        };
        assert!(
            err.contains("Debug & Instrumentation Guard rejected"),
            "unexpected rejection for {forbidden}: {err}"
        );
    }

    let mut env_command = Command::new(&java);
    env_command.env("JAVA_TOOL_OPTIONS", "-javaagent:C:\\tmp\\env-agent.jar -Xmx512m");
    let err = match prepare_sensor_command_with_path(&mut env_command, sensor.clone()) {
        Ok(_) => panic!("JAVA_TOOL_OPTIONS instrumentation must be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("JAVA_TOOL_OPTIONS"), "unexpected env rejection: {err}");

    let mut clean = Command::new(java);
    let _bootstrap = prepare_sensor_command_with_path(&mut clean, sensor)
        .expect("clean JVM command must be accepted");
    let args = clean
        .as_std()
        .get_args()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    assert!(
        args.iter().any(|arg| arg == "-XX:+DisableAttachMechanism"),
        "NeverGuard must enforce DisableAttachMechanism: {args:?}"
    );
}

#[tokio::test]
async fn neverguard_debug_instrumentation_guard_fail_closed_on_live_debugger_attach() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let debugger = debug_probe_path();
    let root = unique_test_root("debug-attach");
    let trusted = root.join("trusted");
    compile_debug_boundary_probe(&javac, &trusted);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command.arg("-cp").arg(&trusted).arg("DebugBoundaryProbe");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Debug Guard Java probe suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let pid = child.id().expect("Debug Guard Java PID");
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("arm Debug & Instrumentation Guard before Java main");

    let mut debugger_child = Command::new(debugger)
        .arg(pid.to_string())
        .spawn()
        .expect("attach adversarial debugger probe");
    let status = child.wait().await.expect("wait debugger-attached JVM");
    assert!(!status.success(), "live debugger attach must be fail-closed");
    let _ = debugger_child.wait().await;
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy, "Module Guard must reflect debugger boundary failure");
    assert!(!report.debug_instrumentation.healthy);
    assert!(
        report.debug_instrumentation.violation_count >= 1,
        "expected Debug & Instrumentation Guard violation: {report:?}"
    );
    assert!(
        report.debug_instrumentation.last_violation.contains("debugger")
            || report.last_violation.contains("debugger"),
        "unexpected Debug Guard violation: {}",
        report.debug_instrumentation.last_violation
    );

    let _ = fs::remove_dir_all(root);
}


#[tokio::test]
async fn neverguard_jvm_aware_protection_accepts_certified_hotspot_jit() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("jvm-aware-jit");
    let trusted = root.join("trusted");
    compile_jvm_jit_probe(&javac, &trusted);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-Xbatch")
        .arg("-XX:CompileThreshold=100")
        .arg("-cp")
        .arg(&trusted)
        .arg("JvmAwareJitProbe");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn JVM-aware JIT Java");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("authenticate JVM-aware Sensor");
    let status = child.wait().await.expect("wait JVM-aware JIT Java");
    assert!(status.success(), "certified HotSpot JIT workload must remain allowed: {status}");

    let report = session.report().module_guard.jvm_aware;
    assert!(report.healthy, "JVM-Aware Protection must remain healthy: {report:?}");
    assert_eq!(report.java_major, expected_java_major());
    assert!(report.certified_major);
    assert!(report.integrity_check_count >= 2);
    assert!(
        report.baseline_private_executable_region_count > 0 || report.jit_transition_count > 0,
        "expected HotSpot executable private baseline or observed JIT transitions: {report:?}"
    );
    assert_eq!(report.foreign_executable_transition_count, 0);
    assert_eq!(report.unknown_executable_transition_count, 0);
    assert_eq!(report.jvm_path_sha256.len(), 64);
    assert_eq!(report.state_sha256.len(), 64);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn neverguard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let probe = jvm_probe_path();
    let root = unique_test_root("jvm-aware-foreign-exec");
    let trusted = root.join("trusted");
    compile_jvm_foreign_exec_probe(&javac, &trusted);
    let probe_dll = trusted.join("jvm-aware-foreign-probe.dll");
    fs::copy(&probe, &probe_dll).expect("copy JVM-aware adversarial probe");
    let probe_dll = fs::canonicalize(&probe_dll).expect("canonical JVM-aware probe");

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("JvmAwareForeignExecProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn JVM-aware adversarial Java");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("authenticate JVM-aware adversarial Sensor");
    let status = child.wait().await.expect("wait JVM-aware adversarial Java");
    assert!(!status.success(), "foreign executable MEM_PRIVATE allocation must be fail-closed");

    let report = session.report().module_guard;
    assert!(!report.healthy, "Module Guard must reflect JVM-aware violation");
    assert!(!report.jvm_aware.healthy);
    assert!(report.jvm_aware.violation_count >= 1, "expected JVM-aware violation: {report:?}");
    assert!(
        report.jvm_aware.last_violation.contains("outside jvm.dll provenance")
            || report.last_violation.contains("outside jvm.dll provenance"),
        "unexpected JVM-aware violation: {}",
        report.jvm_aware.last_violation
    );

    let _ = fs::remove_dir_all(root);
}
