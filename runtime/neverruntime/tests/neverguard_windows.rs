#![cfg(windows)]

use neverruntime::{NeverGuardSupervisor, NEVERGUARD_PROTOCOL_VERSION};
use std::path::PathBuf;

#[tokio::test]
async fn neverguard_process_boundary_authenticates_and_shuts_down() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_neverguard"));
    let supervisor = NeverGuardSupervisor::with_executable(executable);

    let status = supervisor.ensure_started().await.expect("NeverGuard must start");
    assert_eq!(status.state, "ready");
    assert!(status.authenticated);
    assert_eq!(status.parent_pid, std::process::id());
    assert_eq!(status.protocol_version, NEVERGUARD_PROTOCOL_VERSION);
    assert!(status.pid > 0);

    supervisor.ping().await.expect("authenticated ping must pass");
    let status_again = supervisor.status().await.expect("status must pass");
    assert_eq!(status_again.pid, status.pid);

    supervisor.shutdown().await.expect("shutdown must pass");
    supervisor.shutdown().await.expect("shutdown must be idempotent");
}
