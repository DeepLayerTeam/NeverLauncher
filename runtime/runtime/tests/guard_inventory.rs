#![cfg(target_os = "linux")]

use runtime::guard_inventory_0501::collect_guard_inventory_0501;
use std::path::PathBuf;

// Real Guard child, authenticated Unix IPC, process policy and fresh challenge.
// No sensor/game PASS can originate from this local-only probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_native_inventory_exercises_guard_instead_of_using_fixtures() {
    let dir = std::env::temp_dir().join(format!("launcher-inventory-real-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::env::set_var("XDG_RUNTIME_DIR", &dir);
    let report = collect_guard_inventory_0501(
        Some(PathBuf::from(env!("CARGO_BIN_EXE_guard"))),
        None, None, None,
    ).await;
    let status = |id: &str| report.checks.iter().find(|item| item.id == id).map(|item| item.status);
    assert_eq!(status("guard.authenticated-ipc"), Some("PASS"), "{:?}", report.checks);
    assert_eq!(status("guard.process-policy"), Some("PASS"), "{:?}", report.checks);
    assert_eq!(status("guard.integrity-evidence"), Some("PASS"), "{:?}", report.checks);
    assert_eq!(status("guard.remote-attestation"), Some("PASS"), "{:?}", report.checks);
    assert_eq!(status("sensor.jvm-awareness"), Some("UNSUPPORTED"));
    assert_eq!(status("minecraft.real-join"), Some("BLOCKED"));
    assert_eq!(report.status, "BLOCKED");
    std::env::remove_var("XDG_RUNTIME_DIR");
    std::fs::remove_dir_all(dir).unwrap();
}
