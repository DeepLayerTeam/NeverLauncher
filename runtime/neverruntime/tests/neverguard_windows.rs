#![cfg(windows)]

use neverruntime::{
    NeverGuardSupervisor, NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA,
    NEVERGUARD_INTEGRITY_EVIDENCE_VERSION, NEVERGUARD_PROTOCOL_VERSION,
};
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

    let evidence = supervisor
        .integrity_evidence()
        .await
        .expect("Windows integrity evidence must be collected and authenticated");
    assert_eq!(evidence.schema, NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA);
    assert_eq!(
        evidence.evidence_version,
        NEVERGUARD_INTEGRITY_EVIDENCE_VERSION
    );
    assert_eq!(evidence.guard.pid, status.pid);
    assert_eq!(evidence.launcher.pid, std::process::id());
    assert!(evidence.boundary.parent_matches);
    assert_eq!(evidence.boundary.observed_parent_pid, std::process::id());
    assert_eq!(evidence.guard.image_sha256.len(), 64);
    assert_eq!(evidence.launcher.image_sha256.len(), 64);
    assert_eq!(evidence.evidence_sha256.len(), 64);
    assert_eq!(evidence.session_proof.len(), 64);
    assert!(evidence.guard.modules.module_count > 0);
    assert!(evidence.launcher.modules.module_count > 0);

    supervisor.shutdown().await.expect("shutdown must pass");
    supervisor.shutdown().await.expect("shutdown must be idempotent");
}
