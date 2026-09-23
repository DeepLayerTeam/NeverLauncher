#![cfg(target_os = "macos")]

use neverruntime::{
    NeverGuardSupervisor, NEVERGUARD_MACOS_INTEGRITY_EVIDENCE_SCHEMA,
    NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA,
};
use std::path::PathBuf;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn macos_neverguard_authenticated_boundary_and_attestation() {
    let guard = PathBuf::from(env!("CARGO_BIN_EXE_neverguard"));
    let supervisor = NeverGuardSupervisor::with_executable(guard);

    let status = supervisor.ensure_started().await.expect("start NeverGuard");
    assert!(status.authenticated && status.process_policy_enforced && status.hardening_enforced);
    assert!(status.secure_pipe_acl && status.lifetime_job_enforced);
    supervisor.ping().await.expect("authenticated ping");

    let policy = supervisor.process_policy().await.expect("macOS process policy");
    assert_eq!(policy.schema, NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA);
    let macos = policy.macos.expect("macOS policy details");
    assert!(macos.core_dumps_disabled && macos.debugger_attach_denied);
    assert!(macos.code_signature_valid && macos.hardened_runtime && macos.library_validation);
    assert!(macos.dyld_environment_sanitized && macos.parent_exit_watch && macos.private_umask);

    let evidence = supervisor.integrity_evidence().await.expect("macOS integrity evidence");
    assert_eq!(evidence.schema, NEVERGUARD_MACOS_INTEGRITY_EVIDENCE_SCHEMA);
    assert!(evidence.boundary.parent_matches);
    let guard_state = evidence.guard.macos.as_ref().expect("guard macOS evidence");
    assert!(guard_state.code_signature_valid && guard_state.hardened_runtime && guard_state.library_validation);

    let attestation = supervisor.remote_attestation("challenge-macos-1", "server-random-challenge").await.expect("macOS attestation");
    assert_eq!(attestation.challenge_id, "challenge-macos-1");
    assert_eq!(attestation.evidence.evidence_sha256.len(), 64);
    assert_eq!(attestation.attestation_sha256.len(), 64);

    supervisor.shutdown().await.expect("shutdown NeverGuard");
}
