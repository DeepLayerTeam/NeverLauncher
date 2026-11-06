#![cfg(windows)]

use runtime::{
    GuardSupervisor, GUARD_INTEGRITY_EVIDENCE_SCHEMA,
    GUARD_INTEGRITY_EVIDENCE_VERSION, GUARD_PROTOCOL_VERSION,
    GUARD_REMOTE_ATTESTATION_SCHEMA, GUARD_REMOTE_ATTESTATION_VERSION,
    WindowsProtectionProfile, GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
    GUARD_WINDOWS_HARDENING_VERSION, GUARD_WINDOWS_PROCESS_POLICY_SCHEMA,
    GUARD_WINDOWS_PROCESS_POLICY_VERSION, GUARD_WINDOWS_PROTECTION_CORE_VERSION,
};
use std::path::PathBuf;

#[tokio::test]
async fn guard_process_boundary_authenticates_and_shuts_down() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_guard"));
    let supervisor = GuardSupervisor::with_executable(executable);

    let status = supervisor.ensure_started().await.expect("Guard должен запуститься");
    assert_eq!(status.state, "ready");
    assert!(status.authenticated);
    assert_eq!(status.parent_pid, std::process::id());
    assert_eq!(status.protocol_version, GUARD_PROTOCOL_VERSION);
    assert_eq!(
        status.process_policy_version,
        GUARD_WINDOWS_PROCESS_POLICY_VERSION
    );
    assert!(status.process_policy_enforced);
    assert_eq!(status.hardening_version, GUARD_WINDOWS_HARDENING_VERSION);
    assert!(status.hardening_enforced);
    assert_eq!(
        status.windows_protection_core_version,
        GUARD_WINDOWS_PROTECTION_CORE_VERSION
    );
    assert_eq!(
        status.windows_capability_model_version,
        GUARD_WINDOWS_CAPABILITY_MODEL_VERSION
    );
    assert_eq!(status.windows_protection_profile, "aggressive");
    assert!(status.secure_pipe_acl);
    assert!(status.lifetime_job_enforced);
    assert!(!status.package_manifest_verified); // Интеграционный исполняемый файл намеренно пропускает проверку пакета релиза.
    assert!(status.pid > 0);

    supervisor.ping().await.expect("аутентифицированный запрос доступности должен пройти");
    let status_again = supervisor.status().await.expect("запрос состояния должен пройти");
    assert_eq!(status_again.pid, status.pid);
    assert!(status_again.hardening_enforced);
    assert!(status_again.secure_pipe_acl);
    assert!(status_again.lifetime_job_enforced);

    let process_policy = supervisor
        .process_policy()
        .await
        .expect("политика процессов Windows должна применяться и подтверждаться");
    assert_eq!(process_policy.schema, GUARD_WINDOWS_PROCESS_POLICY_SCHEMA);
    assert_eq!(
        process_policy.policy_version,
        GUARD_WINDOWS_PROCESS_POLICY_VERSION
    );
    assert_eq!(process_policy.pid, status.pid);
    assert!(process_policy.enforced);
    assert!(process_policy.dynamic_code_prohibited);
    assert!(process_policy.extension_points_disabled);
    assert!(process_policy.strict_handle_checks);
    assert!(process_policy.remote_images_blocked);
    assert!(process_policy.low_mandatory_label_images_blocked);
    assert!(process_policy.prefer_system32_images);
    assert!(process_policy.child_process_creation_blocked);
    let windows = process_policy
        .windows
        .as_ref()
        .expect("сведения ядра защиты Windows должны быть подтверждены");
    assert_eq!(windows.core_version, GUARD_WINDOWS_PROTECTION_CORE_VERSION);
    assert_eq!(
        windows.capability_model_version,
        GUARD_WINDOWS_CAPABILITY_MODEL_VERSION
    );
    assert_eq!(windows.profile, WindowsProtectionProfile::Aggressive);
    assert!(windows.remote_attestation_eligible);
    assert!(windows.requirements_satisfied);
    assert!(windows.capabilities.requirements_satisfied());
    assert!(windows.capabilities.guard_lifetime_job_bound);
    assert!(!windows.capabilities.architecture.is_empty());

    let evidence = supervisor
        .integrity_evidence()
        .await
        .expect("данные о целостности Windows должны быть собраны и подтверждены");
    assert_eq!(evidence.schema, GUARD_INTEGRITY_EVIDENCE_SCHEMA);
    assert_eq!(
        evidence.evidence_version,
        GUARD_INTEGRITY_EVIDENCE_VERSION
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
    assert_eq!(evidence.guard.mitigations.dynamic_code.map(|flags| flags & 0x1), Some(0x1));
    assert_eq!(
        evidence.guard.mitigations.extension_point_disable.map(|flags| flags & 0x1),
        Some(0x1)
    );
    assert_eq!(evidence.guard.mitigations.image_load.map(|flags| flags & 0x7), Some(0x7));
    assert_eq!(evidence.guard.mitigations.child_process.map(|flags| flags & 0x1), Some(0x1));

    let challenge_id = "integration-guard-attestation-0134";
    let challenge = "integration-server-challenge-launcher-0134";
    let attestation = supervisor
        .remote_attestation(challenge_id, challenge)
        .await
        .expect("аттестация Guard, привязанная к запросу, должна создаваться и проверяться");
    assert_eq!(attestation.schema, GUARD_REMOTE_ATTESTATION_SCHEMA);
    assert_eq!(
        attestation.attestation_version,
        GUARD_REMOTE_ATTESTATION_VERSION
    );
    assert_eq!(attestation.challenge_id, challenge_id);
    assert_eq!(attestation.evidence.guard.pid, status.pid);
    assert_eq!(attestation.evidence.launcher.pid, std::process::id());
    assert_eq!(attestation.process_policy.pid, status.pid);
    assert!(attestation.process_policy.enforced);
    assert_eq!(attestation.attestation_sha256.len(), 64);
    assert_eq!(attestation.session_proof.len(), 64);

    supervisor.shutdown().await.expect("завершение работы должно пройти успешно");
    supervisor.shutdown().await.expect("завершение работы должно быть идемпотентным");
}

#[tokio::test]
async fn guard_compat_profile_enforces_its_runtime_capabilities() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_guard"));
    let supervisor = GuardSupervisor::with_executable_and_profile(
        executable,
        WindowsProtectionProfile::Compat,
    );

    let status = supervisor.ensure_started().await.expect("Guard в режиме совместимости должен запуститься");
    assert_eq!(status.windows_protection_profile, "compat");
    let policy = supervisor
        .process_policy()
        .await
        .expect("политика совместимости должна быть подтверждена");
    let windows = policy.windows.as_ref().expect("сведения о совместимости с Windows");
    assert_eq!(windows.profile, WindowsProtectionProfile::Compat);
    assert!(!windows.remote_attestation_eligible);
    assert!(windows.requirements_satisfied);
    assert!(windows.capabilities.requirements_satisfied());
    assert!(windows.capabilities.guard_lifetime_job_bound);
    assert_eq!(windows.requirements.dynamic_code, 0);
    assert_eq!(windows.requirements.image_load, 0x3);
    assert!(supervisor
        .remote_attestation("compat-not-eligible", "challenge")
        .await
        .is_err());
    supervisor.shutdown().await.expect("завершение режима совместимости должно пройти успешно");
}

#[tokio::test]
async fn guard_audit_profile_measures_without_claiming_remote_trust() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_guard"));
    let supervisor = GuardSupervisor::with_executable_and_profile(
        executable,
        WindowsProtectionProfile::Audit,
    );

    let status = supervisor.ensure_started().await.expect("Guard в режиме аудита должен запуститься");
    assert_eq!(status.windows_protection_profile, "audit");
    let policy = supervisor
        .process_policy()
        .await
        .expect("измерение возможностей в режиме аудита должно быть подтверждено");
    let windows = policy.windows.as_ref().expect("сведения аудита Windows");
    assert_eq!(windows.profile, WindowsProtectionProfile::Audit);
    assert!(!windows.remote_attestation_eligible);
    assert_eq!(windows.requirements.dynamic_code, 0);
    assert_eq!(windows.requirements.extension_point_disable, 0);
    assert_eq!(windows.requirements.strict_handle_check, 0);
    assert_eq!(windows.requirements.image_load, 0);
    assert_eq!(windows.requirements.child_process, 0);
    assert!(windows.capabilities.guard_lifetime_job_bound);
    assert!(supervisor
        .remote_attestation("audit-not-eligible", "challenge")
        .await
        .is_err());
    supervisor.shutdown().await.expect("завершение режима аудита должно пройти успешно");
}
