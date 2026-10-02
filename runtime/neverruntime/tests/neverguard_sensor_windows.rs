#![cfg(windows)]

use neverruntime::{
    windows_policy::{enforce_runtime_process, prepare_runtime_command},
    windows_sensor::{
        authenticate_sensor_or_kill, prepare_sensor_command_with_path, NEVERGUARD_SENSOR_PROTOCOL_VERSION,
    },
};
use std::path::PathBuf;
use tokio::process::Command;

#[tokio::test]
async fn neverguard_sensor_agentpath_loads_before_jvm_startup() {
    let java_home = std::env::var("JAVA_HOME").expect("JAVA_HOME must be set by Windows CI");
    let java = PathBuf::from(java_home).join("bin").join("java.exe");
    assert!(java.is_file(), "java.exe missing: {}", java.display());

    let sensor = PathBuf::from(
        std::env::var("NEVERGUARD_SENSOR_TEST_DLL")
            .expect("NEVERGUARD_SENSOR_TEST_DLL must point to built neverguard_sensor.dll"),
    );
    assert!(sensor.is_file(), "sensor DLL missing: {}", sensor.display());

    let mut command = Command::new(java);
    let bootstrap = prepare_sensor_command_with_path(&mut command, sensor)
        .expect("prepare NeverGuard Sensor agentpath");
    command.arg("-version");
    prepare_runtime_command(&mut command);

    let mut child = command.spawn().expect("spawn Java suspended");
    let runtime_policy = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
    let pid = child.id().expect("Java PID");
    let report = authenticate_sensor_or_kill(bootstrap, &mut child)
        .await
        .expect("sensor Agent_OnLoad handshake");

    assert_eq!(report.protocol_version, NEVERGUARD_SENSOR_PROTOCOL_VERSION);
    assert_eq!(report.pid, pid);
    assert!(report.authenticated);
    assert!(report.loaded_before_main);
    assert!(runtime_policy.report().enforced);

    let status = child.wait().await.expect("wait Java");
    assert!(status.success(), "java -version failed after sensor load: {status}");
}
