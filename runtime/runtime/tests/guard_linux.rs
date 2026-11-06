#![cfg(target_os = "linux")]

use runtime::{GuardSupervisor, GUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA, GUARD_LINUX_PROCESS_POLICY_SCHEMA};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

fn private_runtime_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("launcher-test-runtime-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("создать тестовый каталог среды выполнения");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("установить права доступа к каталогу среды выполнения");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_guard_authenticated_boundary_and_attestation() {
    let runtime_dir = private_runtime_dir();
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);
    let guard = PathBuf::from(env!("CARGO_BIN_EXE_guard"));
    let supervisor = GuardSupervisor::with_executable(guard);

    let status = supervisor.ensure_started().await.expect("start Guard");
    assert!(status.authenticated && status.process_policy_enforced && status.hardening_enforced);
    assert!(status.secure_pipe_acl && status.lifetime_job_enforced);
    supervisor.ping().await.expect("authenticated ping");
    supervisor.ping_running().await.expect("выполнить проверку активности без автоматического перезапуска");

    let policy = supervisor.process_policy().await.expect("получить политику процессов Linux");
    assert_eq!(policy.schema, GUARD_LINUX_PROCESS_POLICY_SCHEMA);
    let linux = policy.linux.expect("получить сведения о политике Linux");
    assert!(linux.no_new_privs && linux.dumpable_disabled && linux.core_dumps_disabled);
    assert!(linux.ptrace_restricted && linux.parent_death_signal && linux.private_umask);

    let evidence = supervisor.integrity_evidence().await.expect("получить данные о целостности Linux");
    assert_eq!(evidence.schema, GUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA);
    assert!(evidence.boundary.parent_matches);
    assert!(evidence.guard.linux.as_ref().expect("получить данные Guard для Linux").no_new_privs);

    let attestation = supervisor.remote_attestation("challenge-linux-1", "server-random-challenge").await.expect("получить аттестацию Linux");
    assert_eq!(attestation.challenge_id, "challenge-linux-1");
    assert_eq!(attestation.evidence.evidence_sha256.len(), 64);
    assert_eq!(attestation.attestation_sha256.len(), 64);

    supervisor.shutdown().await.expect("shutdown Guard");
    assert!(supervisor.ping_running().await.is_err(), "закрытый Guard не должен незаметно перезапускаться");
    let _ = std::fs::remove_dir_all(runtime_dir);
}
