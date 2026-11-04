#![cfg(target_os = "macos")]

#[tokio::test]
async fn missing_guard_cannot_satisfy_running_heartbeat_or_restart_transparently() {
    let guard = runtime::macos_guard::GuardSupervisor::new();
    let error = guard.ping_running().await.expect_err("lost Guard must not be auto-started");
    assert!(error.contains("disappeared"));
}
