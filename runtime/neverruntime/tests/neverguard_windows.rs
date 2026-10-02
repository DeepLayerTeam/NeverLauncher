#![cfg(windows)]

use neverruntime::{
    NeverGuardSupervisor, NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA,
    NEVERGUARD_INTEGRITY_EVIDENCE_VERSION, NEVERGUARD_PROTOCOL_VERSION,
    NEVERGUARD_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_REMOTE_ATTESTATION_VERSION,
    WindowsProtectionProfile, NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
    NEVERGUARD_WINDOWS_HARDENING_VERSION, NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA,
    NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION, NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION,
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
    assert_eq!(
        status.process_policy_version,
        NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION
    );
    assert!(status.process_policy_enforced);
    assert_eq!(status.hardening_version, NEVERGUARD_WINDOWS_HARDENING_VERSION);
    assert!(status.hardening_enforced);
    assert_eq!(
        status.windows_protection_core_version,
        NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION
    );
    assert_eq!(
        status.windows_capability_model_version,
        NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION
    );
    assert_eq!(status.windows_protection_profile, "aggressive");
    assert!(status.secure_pipe_acl);
    assert!(status.lifetime_job_enforced);
    assert!(!status.package_manifest_verified); // integration binary deliberately bypasses release package validation
    assert!(status.pid > 0);

    supervisor.ping().await.expect("authenticated ping must pass");
    let status_again = supervisor.status().await.expect("status must pass");
    assert_eq!(status_again.pid, status.pid);
    assert!(status_again.hardening_enforced);
    assert!(status_again.secure_pipe_acl);
    assert!(status_again.lifetime_job_enforced);

    let process_policy = supervisor
        .process_policy()
        .await
        .expect("Windows process policy must be enforced and authenticated");
    assert_eq!(process_policy.schema, NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA);
    assert_eq!(
        process_policy.policy_version,
        NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION
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
        .expect("Windows Protection Core details must be authenticated");
    assert_eq!(windows.core_version, NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION);
    assert_eq!(
        windows.capability_model_version,
        NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION
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
    assert_eq!(evidence.guard.mitigations.dynamic_code.map(|flags| flags & 0x1), Some(0x1));
    assert_eq!(
        evidence.guard.mitigations.extension_point_disable.map(|flags| flags & 0x1),
        Some(0x1)
    );
    assert_eq!(evidence.guard.mitigations.image_load.map(|flags| flags & 0x7), Some(0x7));
    assert_eq!(evidence.guard.mitigations.child_process.map(|flags| flags & 0x1), Some(0x1));

    let challenge_id = "integration-guard-attestation-0134";
    let challenge = "integration-server-challenge-neverlauncher-0134";
    let attestation = supervisor
        .remote_attestation(challenge_id, challenge)
        .await
        .expect("challenge-bound Guard Attestation must be produced and authenticated");
    assert_eq!(attestation.schema, NEVERGUARD_REMOTE_ATTESTATION_SCHEMA);
    assert_eq!(
        attestation.attestation_version,
        NEVERGUARD_REMOTE_ATTESTATION_VERSION
    );
    assert_eq!(attestation.challenge_id, challenge_id);
    assert_eq!(attestation.evidence.guard.pid, status.pid);
    assert_eq!(attestation.evidence.launcher.pid, std::process::id());
    assert_eq!(attestation.process_policy.pid, status.pid);
    assert!(attestation.process_policy.enforced);
    assert_eq!(attestation.attestation_sha256.len(), 64);
    assert_eq!(attestation.session_proof.len(), 64);

    supervisor.shutdown().await.expect("shutdown must pass");
    supervisor.shutdown().await.expect("shutdown must be idempotent");
}

#[tokio::test]
async fn neverguard_compat_profile_enforces_its_runtime_capabilities() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_neverguard"));
    let supervisor = NeverGuardSupervisor::with_executable_and_profile(
        executable,
        WindowsProtectionProfile::Compat,
    );

    let status = supervisor.ensure_started().await.expect("compat NeverGuard must start");
    assert_eq!(status.windows_protection_profile, "compat");
    let policy = supervisor
        .process_policy()
        .await
        .expect("compat policy must be authenticated");
    let windows = policy.windows.as_ref().expect("compat Windows details");
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
    supervisor.shutdown().await.expect("compat shutdown must pass");
}

#[tokio::test]
async fn neverguard_audit_profile_measures_without_claiming_remote_trust() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_neverguard"));
    let supervisor = NeverGuardSupervisor::with_executable_and_profile(
        executable,
        WindowsProtectionProfile::Audit,
    );

    let status = supervisor.ensure_started().await.expect("audit NeverGuard must start");
    assert_eq!(status.windows_protection_profile, "audit");
    let policy = supervisor
        .process_policy()
        .await
        .expect("audit capability measurement must be authenticated");
    let windows = policy.windows.as_ref().expect("audit Windows details");
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
    supervisor.shutdown().await.expect("audit shutdown must pass");
}
