#![cfg(windows)]

use runtime::{
    windows_policy::{enforce_runtime_process, prepare_runtime_command},
    windows_sensor::{
        authenticate_sensor_or_kill, prepare_sensor_command_with_path,
        GUARD_SENSOR_PROTOCOL_VERSION,
    },
    GUARD_CONTINUOUS_GUARD_VERSION, GUARD_DEBUG_INSTRUMENTATION_VERSION, GUARD_HOOK_ENGINE_VERSION,
    GUARD_JVM_AWARE_PROTECTION_VERSION, GUARD_MEMORY_INTEGRITY_VERSION,
    GUARD_MODULE_GUARD_VERSION, GUARD_THREAD_PROCESS_INTEGRITY_VERSION,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, time::{sleep, Duration}};

fn java_tools() -> (PathBuf, PathBuf) {
    let java_home = std::env::var("JAVA_HOME").expect("JAVA_HOME должен быть задан в CI для Windows");
    let java_home = PathBuf::from(java_home);
    let java = java_home.join("bin").join("java.exe");
    let javac = java_home.join("bin").join("javac.exe");
    assert!(java.is_file(), "файл java.exe отсутствует: {}", java.display());
    assert!(javac.is_file(), "файл javac.exe отсутствует: {}", javac.display());
    (java, javac)
}

fn sensor_path() -> PathBuf {
    let sensor = PathBuf::from(
        std::env::var("GUARD_SENSOR_TEST_DLL")
            .expect("GUARD_SENSOR_TEST_DLL должен указывать на собранный guard_sensor.dll"),
    );
    assert!(sensor.is_file(), "sensor DLL missing: {}", sensor.display());
    sensor
}

fn memory_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("GUARD_MEMORY_PROBE_DLL")
            .expect("GUARD_MEMORY_PROBE_DLL должен указывать на собранный guard_memory_probe.dll"),
    );
    assert!(probe.is_file(), "отсутствует DLL проверки памяти: {}", probe.display());
    probe
}

fn thread_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("GUARD_THREAD_PROBE_DLL")
            .expect("GUARD_THREAD_PROBE_DLL должен указывать на собранный guard_thread_probe.dll"),
    );
    assert!(probe.is_file(), "отсутствует DLL проверки потоков: {}", probe.display());
    probe
}

fn debug_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("GUARD_DEBUG_PROBE_EXE")
            .expect("GUARD_DEBUG_PROBE_EXE должен указывать на собранный guard-debug-probe.exe"),
    );
    assert!(probe.is_file(), "отсутствует EXE проверки отладки: {}", probe.display());
    probe
}


fn jvm_probe_path() -> PathBuf {
    let probe = PathBuf::from(
        std::env::var("GUARD_JVM_PROBE_DLL")
            .expect("GUARD_JVM_PROBE_DLL должен указывать на собранный guard_jvm_probe.dll"),
    );
    assert!(probe.is_file(), "отсутствует DLL проверки JVM: {}", probe.display());
    probe
}

fn unique_test_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "guard-module-guard-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn compile_module_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог проверочной Java-программы");
    fs::write(
        directory.join("ModuleGuardProbe.java"),
        r#"public final class ModuleGuardProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("native DLL path required");
        System.load(args[0]);
        // Полная проверка целостности Hook Engine запускается каждые две секунды.
        // Раннер Java 17 Windows CI должен успеть выполнить две аутентифицированные
        // проверки, даже если первоначальный обход DLL/модулей медленный.
        Thread.sleep(10000L);
    }
}
"#,
    )
    .expect("записать проверочную Java-программу");
    let status = std::process::Command::new(javac)
        .arg("ModuleGuardProbe.java")
        .current_dir(directory)
        .status()
        .expect("запустить компилятор javac");
    assert!(status.success(), "ошибка javac: {status}");
}

fn compile_memory_integrity_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог Java-проверки целостности памяти");
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
    .expect("записать Java-проверку целостности памяти");
    let status = std::process::Command::new(javac)
        .arg("MemoryIntegrityProbe.java")
        .current_dir(directory)
        .status()
        .expect("скомпилировать Java-проверку целостности памяти");
    assert!(status.success(), "ошибка javac при проверке целостности памяти: {status}");
}

fn compile_process_tree_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог Java-проверки дерева процессов");
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
    .expect("записать Java-проверку дерева процессов");
    let status = std::process::Command::new(javac)
        .arg("ProcessTreeProbe.java")
        .current_dir(directory)
        .status()
        .expect("скомпилировать Java-проверку дерева процессов");
    assert!(status.success(), "ошибка javac при проверке дерева процессов: {status}");
}

fn compile_debug_boundary_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог Java-проверки защиты отладки");
    fs::write(
        directory.join("DebugBoundaryProbe.java"),
        r#"public final class DebugBoundaryProbe {
    public static void main(String[] args) throws Exception {
        Thread.sleep(15000L);
    }
}
"#,
    )
    .expect("записать Java-проверку защиты отладки");
    let status = std::process::Command::new(javac)
        .arg("DebugBoundaryProbe.java")
        .current_dir(directory)
        .status()
        .expect("скомпилировать Java-проверку защиты отладки");
    assert!(status.success(), "ошибка javac при проверке защиты от отладки: {status}");
}

fn compile_thread_integrity_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог Java-проверки целостности потоков");
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
    .expect("записать Java-проверку целостности потоков");
    let status = std::process::Command::new(javac)
        .arg("ThreadIntegrityProbe.java")
        .current_dir(directory)
        .status()
        .expect("скомпилировать Java-проверку целостности потоков");
    assert!(status.success(), "ошибка javac при проверке целостности потоков: {status}");
}

fn compile_jvm_jit_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог Java-проверки JIT с учётом JVM");
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
        .expect("скомпилировать Java-проверку JIT с учётом JVM");
    assert!(status.success(), "ошибка javac в проверке JIT для JVM: {status}");
}

fn compile_jvm_foreign_exec_probe(javac: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("создать каталог Java-проверки внешнего исполнения в JVM");
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
    .expect("записать проверку внешнего исполнения в JVM");
    let status = std::process::Command::new(javac)
        .arg("JvmAwareForeignExecProbe.java")
        .current_dir(directory)
        .status()
        .expect("скомпилировать проверку внешнего исполнения в JVM");
    assert!(status.success(), "ошибка javac в проверке стороннего исполняемого кода JVM: {status}");
}

// Java 8/16/17 System.load() не принимает дословные Win32 namespace-пути вида (\\?\C:\...).
// Продолжайте каноникализацию, но передавайте обычный абсолютный путь Windows.
fn java_native_load_path(path: &Path) -> PathBuf {
    let absolute = fs::canonicalize(path).expect("получить канонический путь к нативной проверочной DLL");
    let value = absolute.to_string_lossy();
    if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", unc));
    }
    if let Some(local) = value.strip_prefix(r"\\?\") {
        return PathBuf::from(local);
    }
    absolute
}

fn expected_java_major() -> u32 {
    std::env::var("GUARD_EXPECTED_JAVA_MAJOR")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(21)
}

#[tokio::test]
async fn guard_sensor_agentpath_loads_before_jvm_startup() {
    let (java, _) = java_tools();
    let sensor = sensor_path();

    let mut command = Command::new(java);
    command.current_dir(std::env::current_dir().expect("получить текущий каталог"));
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command.arg("-version");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let pid = child.id().expect("Java PID");
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("выполнить согласование Agent_OnLoad датчика с активацией защиты модулей");
    let report = session.report();

    assert_eq!(report.protocol_version, GUARD_SENSOR_PROTOCOL_VERSION);
    assert_eq!(report.pid, pid);
    assert!(report.authenticated);
    assert!(report.loaded_before_main);
    assert_eq!(report.module_guard.version, GUARD_MODULE_GUARD_VERSION);
    assert!(report.module_guard.healthy);
    assert!(report.module_guard.baseline_module_count > 0);
    assert_eq!(report.module_guard.violation_count, 0);
    assert_eq!(report.module_guard.hook_engine.version, GUARD_HOOK_ENGINE_VERSION);
    assert!(report.module_guard.hook_engine.active);
    assert!(report.module_guard.hook_engine.healthy);
    assert!(report.module_guard.hook_engine.hooked_module_count > 0);
    assert!(report.module_guard.hook_engine.hooked_slot_count > 0);
    assert_eq!(report.module_guard.hook_engine.hook_set_sha256.len(), 64);
    assert_eq!(report.module_guard.memory_integrity.version, GUARD_MEMORY_INTEGRITY_VERSION);
    assert!(report.module_guard.memory_integrity.active);
    assert!(report.module_guard.memory_integrity.healthy);
    assert!(report.module_guard.memory_integrity.executable_region_count > 0);
    assert!(report.module_guard.memory_integrity.image_code_region_count > 0);
    assert_eq!(report.module_guard.memory_integrity.code_set_sha256.len(), 64);
    assert_eq!(report.module_guard.memory_integrity.executable_map_sha256.len(), 64);
    assert_eq!(
        report.module_guard.thread_process_integrity.version,
        GUARD_THREAD_PROCESS_INTEGRITY_VERSION
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
        GUARD_DEBUG_INSTRUMENTATION_VERSION
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
        GUARD_JVM_AWARE_PROTECTION_VERSION
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
        GUARD_CONTINUOUS_GUARD_VERSION
    );
    assert!(report.module_guard.continuous_guard.active);
    assert!(report.module_guard.continuous_guard.healthy);
    assert!(report.module_guard.continuous_guard.cross_check_count >= 1);
    assert_eq!(report.module_guard.continuous_guard.last_guard_sequence, 1);
    assert_eq!(report.module_guard.continuous_guard.last_cross_check_sha256.len(), 64);
    assert_eq!(report.module_guard.continuous_guard.sensor_event_chain_sha256.len(), 64);
    assert!(runtime_policy.report().enforced);

    let status = child.wait().await.expect("wait Java");
    assert!(status.success(), "команда java -version завершилась ошибкой после загрузки датчика: {status}");
}

#[tokio::test]
async fn guard_module_guard_tracks_real_jvm_dll_load_and_heartbeat() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("track");
    let trusted = root.join("trusted");
    compile_module_probe(&javac, &trusted);
    let probe_dll = trusted.join("probe-native.dll");
    fs::copy(&sensor, &probe_dll).expect("скопировать проверочную DLL в доверенный каталог среды выполнения");
    let probe_dll = java_native_load_path(&probe_dll);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить проверочную Java-программу в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("активировать защиту модулей до запуска основного метода Java");
    let status = child.wait().await.expect("дождаться завершения проверочной Java-программы");
    assert!(status.success(), "сбой доверенной нативной проверки: {status}");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(report.healthy, "нарушение защиты модулей: {}", report.last_violation);
    assert_eq!(report.violation_count, 0);
    assert!(report.load_events >= 1, "ожидалось хотя бы одно событие загрузки DLL: {report:?}");
    assert!(report.heartbeat_count >= 1, "ожидались непрерывные сигналы работоспособности: {report:?}");
    assert!(report.event_count >= report.load_events + report.heartbeat_count);
    assert!(report.hook_engine.healthy, "нарушение механизма перехватов: {}", report.hook_engine.last_violation);
    assert!(report.hook_engine.hooked_module_count > 0);
    assert!(report.hook_engine.hooked_slot_count > 0);
    assert!(report.hook_engine.integrity_check_count >= 2);
    assert!(report.hook_engine.intercepted_call_count >= 1, "expected real intercepted JVM/native API call: {report:?}");
    assert_eq!(report.hook_engine.hook_set_sha256.len(), 64);
    assert!(report.memory_integrity.healthy, "нарушение целостности памяти: {}", report.memory_integrity.last_violation);
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
    assert!(report.continuous_guard.healthy, "нарушение непрерывной защиты Guard: {}", report.continuous_guard.last_violation);
    assert!(report.continuous_guard.sensor_heartbeat_count >= 2, "ожидались сигналы работоспособности датчика: {report:?}");
    assert!(report.continuous_guard.guard_heartbeat_count >= 2, "ожидались сигналы работоспособности Guard: {report:?}");
    assert!(report.continuous_guard.cross_check_count >= 2, "ожидались двусторонние взаимные проверки: {report:?}");
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
async fn guard_continuous_guard_cross_checks_sensor_and_guard_heartbeat() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("continuous-guard");
    let trusted = root.join("trusted");
    compile_module_probe(&javac, &trusted);
    let probe_dll = trusted.join("continuous-probe-native.dll");
    fs::copy(&sensor, &probe_dll).expect("скопировать DLL непрерывной проверки Guard");
    let probe_dll = java_native_load_path(&probe_dll);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare Guard Continuous Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java-проверку непрерывной защиты Guard");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику непрерывной защиты Guard");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("выполнить перекрёстную проверку при запуске непрерывной защиты Guard");
    let status = child.wait().await.expect("дождаться завершения Java-проверки непрерывной защиты Guard");
    assert!(status.success(), "ошибка нормальной нагрузки непрерывной защиты Guard: {status}");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard.continuous_guard;
    assert_eq!(report.version, GUARD_CONTINUOUS_GUARD_VERSION);
    assert!(report.healthy, "нарушение непрерывной защиты Guard: {}", report.last_violation);
    assert!(report.sensor_heartbeat_count >= 3, "ожидались сигналы датчика при запуске и во время работы: {report:?}");
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
async fn guard_module_guard_fail_closed_on_unsigned_dll_outside_trusted_roots() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("block");
    let trusted = root.join("trusted");
    let untrusted = root.join("untrusted");
    compile_module_probe(&javac, &trusted);
    fs::create_dir_all(&untrusted).expect("создать недоверенный каталог");
    let probe_dll = untrusted.join("unsigned-probe-native.dll");
    fs::copy(&sensor, &probe_dll).expect("скопировать неподписанную DLL за пределы доверенных каталогов");
    let probe_dll = java_native_load_path(&probe_dll);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ModuleGuardProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить проверочную Java-программу в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("активировать защиту модулей до запуска основного метода Java");
    let status = child.wait().await.expect("дождаться завершения заблокированной Java-проверки");
    assert!(!status.success(), "неподписанный модуль вне доверенных каталогов должен блокироваться");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy);
    assert!(report.violation_count >= 1, "ожидалось нарушение защиты модулей: {report:?}");
    assert!(
        report.last_violation.contains("outside trusted roots")
            || report.last_violation.contains("Authenticode"),
        "unexpected violation: {}",
        report.last_violation
    );

    let _ = fs::remove_dir_all(root);
}


#[tokio::test]
async fn guard_memory_integrity_fail_closed_on_executable_image_code_page_drift() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let memory_probe = memory_probe_path();
    let root = unique_test_root("memory-drift");
    let trusted = root.join("trusted");
    compile_memory_integrity_probe(&javac, &trusted);
    let probe_dll = trusted.join("memory-tamper-probe.dll");
    fs::copy(&memory_probe, &probe_dll).expect("скопировать проверку вмешательства в память");
    let probe_dll = java_native_load_path(&probe_dll);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("MemoryIntegrityProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java-проверку целостности памяти в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("активировать контроль целостности памяти до запуска основного метода Java");
    let status = child.wait().await.expect("дождаться завершения проверки вмешательства в память");
    assert!(!status.success(), "изменение страниц кода исполняемого образа должно блокироваться");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy, "защита модулей должна отражать нарушение целостности памяти");
    assert!(!report.memory_integrity.healthy);
    assert!(report.memory_integrity.violation_count >= 1, "ожидалось нарушение целостности памяти: {report:?}");
    assert!(
        report.memory_integrity.last_violation.contains("code-page drift")
            || report.last_violation.contains("code-page drift"),
        "unexpected Memory Integrity violation: {}",
        report.memory_integrity.last_violation
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn guard_thread_process_integrity_tracks_job_bound_descendant_processes() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("process-tree");
    let trusted = root.join("trusted");
    compile_process_tree_probe(&javac, &trusted);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command.arg("-cp").arg(&trusted).arg("ProcessTreeProbe");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java-проверку дерева процессов в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("активировать контроль целостности потоков и процессов до запуска основного метода Java");
    let status = child.wait().await.expect("дождаться завершения Java-проверки дерева процессов");
    sleep(Duration::from_millis(250)).await;
    let module_report = session.report().module_guard;
    assert!(
        status.success(),
        "Process Tree probe failed: {status}; guard violation: {}; process-tree violation: {}",
        module_report.last_violation,
        module_report.thread_process_integrity.last_violation,
    );

    let report = module_report.thread_process_integrity;
    assert!(report.healthy, "нарушение целостности потоков и процессов: {}", report.last_violation);
    assert!(report.job_bound);
    assert!(!report.breakaway_allowed);
    assert!(report.descendant_process_peak >= 1, "ожидалось обнаружение дочернего процесса, привязанного к заданию: {report:?}");
    assert!(report.process_transition_count >= 1, "ожидалось изменение дерева процессов: {report:?}");
    assert!(report.integrity_check_count >= 2);
    assert_eq!(report.process_tree_sha256.len(), 64);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn guard_thread_integrity_fail_closed_on_private_executable_thread_start() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let thread_probe = thread_probe_path();
    let root = unique_test_root("private-thread");
    let trusted = root.join("trusted");
    compile_thread_integrity_probe(&javac, &trusted);
    let probe_dll = trusted.join("thread-tamper-probe.dll");
    fs::copy(&thread_probe, &probe_dll).expect("скопировать проверку вмешательства в потоки");
    let probe_dll = java_native_load_path(&probe_dll);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("ThreadIntegrityProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java-проверку целостности потоков в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("активировать контроль целостности потоков и процессов до запуска основного метода Java");
    let status = child.wait().await.expect("дождаться завершения проверки вмешательства в потоки");
    assert!(!status.success(), "запуск потока из приватной исполняемой памяти должен блокироваться");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(!report.healthy, "защита модулей должна отражать нарушение целостности потоков");
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



#[tokio::test]
async fn guard_debug_instrumentation_guard_rejects_startup_agents_and_enforces_attach_disable() {
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
            Ok(_) => panic!("инструментирование при запуске должно блокироваться до создания процесса JVM: {forbidden}"),
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
        Ok(_) => panic!("инструментирование через JAVA_TOOL_OPTIONS должно отклоняться"),
        Err(err) => err,
    };
    assert!(err.contains("JAVA_TOOL_OPTIONS"), "неожиданный отказ по переменным окружения: {err}");

    let mut clean = Command::new(java);
    let _bootstrap = prepare_sensor_command_with_path(&mut clean, sensor)
        .expect("команда запуска JVM без запрещённых аргументов должна приниматься");
    let args = clean
        .as_std()
        .get_args()
        .map(|arg| arg.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    assert!(
        args.iter().any(|arg| arg == "-XX:+DisableAttachMechanism"),
        "Guard must enforce DisableAttachMechanism: {args:?}"
    );
}

#[tokio::test]
async fn guard_debug_instrumentation_guard_fail_closed_on_live_debugger_attach() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let debugger = debug_probe_path();
    let root = unique_test_root("debug-attach");
    let trusted = root.join("trusted");
    compile_debug_boundary_probe(&javac, &trusted);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command.arg("-cp").arg(&trusted).arg("DebugBoundaryProbe");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java-проверку защиты отладки в приостановленном состоянии");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let pid = child.id().expect("Debug Guard Java PID");
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("активировать защиту отладки и инструментирования до запуска основного метода Java");

    let mut debugger_child = Command::new(debugger)
        .arg(pid.to_string())
        .spawn()
        .expect("подключить тестовый отладчик для проверки обхода защиты");
    let status = child.wait().await.expect("дождаться завершения JVM с подключённым отладчиком");
    assert!(!status.success(), "подключение отладчика к работающему процессу должно блокироваться");
    let debugger_status = debugger_child.wait().await.expect("дождаться завершения проверки обхода защиты отладчиком");
    sleep(Duration::from_millis(250)).await;

    let report = session.report().module_guard;
    assert!(
        debugger_status.success(),
        "adversarial debugger did not attach/complete (status={debugger_status}); guard report={report:?}"
    );
    assert!(!report.healthy, "защита модулей должна отражать нарушение границ отладки: {report:?}");
    assert!(
        !report.debug_instrumentation.healthy,
        "live debugger must be detected specifically by Debug & Instrumentation Guard: {report:?}"
    );
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
async fn guard_jvm_aware_protection_accepts_certified_hotspot_jit() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let root = unique_test_root("jvm-aware-jit");
    let trusted = root.join("trusted");
    compile_jvm_jit_probe(&javac, &trusted);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command
        .arg("-Xbatch")
        .arg("-XX:CompileThreshold=100")
        .arg("-cp")
        .arg(&trusted)
        .arg("JvmAwareJitProbe");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn JVM-aware JIT Java");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("authenticate JVM-aware Sensor");
    let status = child.wait().await.expect("wait JVM-aware JIT Java");
    assert!(status.success(), "сертифицированная JIT-нагрузка HotSpot должна оставаться разрешённой: {status}");

    let report = session.report().module_guard.jvm_aware;
    assert!(report.healthy, "защита с учётом JVM должна оставаться работоспособной: {report:?}");
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
async fn guard_jvm_aware_protection_fail_closed_on_foreign_executable_private_allocation() {
    let (java, javac) = java_tools();
    let sensor = sensor_path();
    let probe = jvm_probe_path();
    let root = unique_test_root("jvm-aware-foreign-exec");
    let trusted = root.join("trusted");
    compile_jvm_foreign_exec_probe(&javac, &trusted);
    let probe_dll = trusted.join("jvm-aware-foreign-probe.dll");
    fs::copy(&probe, &probe_dll).expect("скопировать проверку обхода защиты с учётом JVM");
    let probe_dll = java_native_load_path(&probe_dll);

    let mut command = Command::new(java);
    command.current_dir(&trusted);
    let mut bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("подготовить путь к агенту Guard Sensor");
    command
        .arg("-cp")
        .arg(&trusted)
        .arg("JvmAwareForeignExecProbe")
        .arg(&probe_dll);
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("запустить Java-проверку обхода защиты с учётом JVM");
    let runtime_policy = enforce_runtime_process(&mut child).expect("применить политику процессов среды выполнения");
    bootstrap.bind_runtime_policy(&runtime_policy);
    let session = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("аутентифицировать датчик проверки обхода защиты с учётом JVM");
    let status = child.wait().await.expect("дождаться завершения Java-проверки обхода защиты с учётом JVM");
    assert!(!status.success(), "стороннее выделение исполняемой памяти MEM_PRIVATE должно блокироваться");

    let report = session.report().module_guard;
    assert!(!report.healthy, "защита модулей должна отражать нарушение защиты JVM");
    assert!(!report.jvm_aware.healthy);
    assert!(report.jvm_aware.violation_count >= 1, "ожидалось нарушение защиты JVM: {report:?}");
    assert!(
        report.jvm_aware.last_violation.contains("outside jvm.dll provenance")
            || report.last_violation.contains("outside jvm.dll provenance"),
        "unexpected JVM-aware violation: {}",
        report.jvm_aware.last_violation
    );

    let _ = fs::remove_dir_all(root);
}
