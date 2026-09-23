#![cfg(target_os = "linux")]

use neverruntime::{NeverGuardSupervisor, NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA, NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

fn private_runtime_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("neverlauncher-test-runtime-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test runtime dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod runtime dir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_neverguard_authenticated_boundary_and_attestation() {
    let runtime_dir = private_runtime_dir();
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);
    let guard = PathBuf::from(env!("CARGO_BIN_EXE_neverguard"));
    let supervisor = NeverGuardSupervisor::with_executable(guard);

    let status = supervisor.ensure_started().await.expect("start NeverGuard");
    assert!(status.authenticated && status.process_policy_enforced && status.hardening_enforced);
    assert!(status.secure_pipe_acl && status.lifetime_job_enforced);
    supervisor.ping().await.expect("authenticated ping");

    let policy = supervisor.process_policy().await.expect("Linux process policy");
    assert_eq!(policy.schema, NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA);
    let linux = policy.linux.expect("Linux policy details");
    assert!(linux.no_new_privs && linux.dumpable_disabled && linux.core_dumps_disabled);
    assert!(linux.ptrace_restricted && linux.parent_death_signal && linux.private_umask);

    let evidence = supervisor.integrity_evidence().await.expect("Linux integrity evidence");
    assert_eq!(evidence.schema, NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA);
    assert!(evidence.boundary.parent_matches);
    assert!(evidence.guard.linux.as_ref().expect("guard Linux evidence").no_new_privs);

    let attestation = supervisor.remote_attestation("challenge-linux-1", "server-random-challenge").await.expect("Linux attestation");
    assert_eq!(attestation.challenge_id, "challenge-linux-1");
    assert_eq!(attestation.evidence.evidence_sha256.len(), 64);
    assert_eq!(attestation.attestation_sha256.len(), 64);

    supervisor.shutdown().await.expect("shutdown NeverGuard");
    let _ = std::fs::remove_dir_all(runtime_dir);
}
