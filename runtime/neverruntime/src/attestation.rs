use crate::integrity::NeverGuardIntegrityEvidence;
use crate::windows_policy::GuardProcessPolicyReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NEVERGUARD_REMOTE_ATTESTATION_VERSION: u32 = 1;
pub const NEVERGUARD_REMOTE_ATTESTATION_SCHEMA: &str = "neverguard/windows-guard-attestation/v1";
pub const NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA: &str = "neverguard/linux-guard-attestation/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GuardAttestationRequest {
    pub challenge_id: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NeverGuardRemoteAttestation {
    pub schema: String,
    pub attestation_version: u32,
    pub challenge_id: String,
    pub challenge_sha256: String,
    pub collected_at_unix: u64,
    pub evidence: NeverGuardIntegrityEvidence,
    pub process_policy: GuardProcessPolicyReport,
    pub attestation_sha256: String,
    pub session_proof: String,
}

pub(crate) fn challenge_sha256(challenge: &str) -> String {
    hex::encode(Sha256::digest(challenge.as_bytes()))
}

pub(crate) fn canonical_attestation_core(attestation: &NeverGuardRemoteAttestation) -> Result<String, String> {
    validate_attestation_shape(attestation)?;
    if attestation.schema == NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA {
        let linux = attestation.process_policy.linux.as_ref().ok_or_else(|| "Linux Guard Attestation missing Linux process policy details".to_string())?;
        return Ok(format!(
            concat!(
                "NeverLauncher Guard Attestation Core Linux v1\n",
                "challenge-id={}\n","challenge-sha256={}\n","evidence-id={}\n","evidence-sha256={}\n",
                "guard-sha256={}\n","launcher-sha256={}\n","guard-module-set-sha256={}\n","launcher-module-set-sha256={}\n",
                "process-policy-version={}\n","process-policy-enforced={}\n","no-new-privs={}\n","dumpable-disabled={}\n",
                "core-dumps-disabled={}\n","ptrace-restricted={}\n","parent-death-signal={}\n","private-umask={}\n","collected-at={}\n"
            ),
            attestation.challenge_id, attestation.challenge_sha256, attestation.evidence.evidence_id,
            attestation.evidence.evidence_sha256, attestation.evidence.guard.image_sha256,
            attestation.evidence.launcher.image_sha256, attestation.evidence.guard.modules.module_set_sha256,
            attestation.evidence.launcher.modules.module_set_sha256, attestation.process_policy.policy_version,
            attestation.process_policy.enforced, linux.no_new_privs, linux.dumpable_disabled,
            linux.core_dumps_disabled, linux.ptrace_restricted, linux.parent_death_signal,
            linux.private_umask, attestation.collected_at_unix,
        ));
    }
    Ok(format!(
        concat!(
            "NeverLauncher Guard Attestation Core v1\n",
            "challenge-id={}\n","challenge-sha256={}\n","evidence-id={}\n","evidence-sha256={}\n",
            "guard-sha256={}\n","launcher-sha256={}\n","guard-module-set-sha256={}\n","launcher-module-set-sha256={}\n",
            "guard-authenticode-trusted={}\n","launcher-authenticode-trusted={}\n","process-policy-version={}\n",
            "process-policy-enforced={}\n","dynamic-code-prohibited={}\n","extension-points-disabled={}\n",
            "strict-handle-checks={}\n","remote-images-blocked={}\n","low-mandatory-label-images-blocked={}\n",
            "prefer-system32-images={}\n","child-process-creation-blocked={}\n","collected-at={}\n"
        ),
        attestation.challenge_id, attestation.challenge_sha256, attestation.evidence.evidence_id,
        attestation.evidence.evidence_sha256, attestation.evidence.guard.image_sha256,
        attestation.evidence.launcher.image_sha256, attestation.evidence.guard.modules.module_set_sha256,
        attestation.evidence.launcher.modules.module_set_sha256, attestation.evidence.guard.authenticode.trusted,
        attestation.evidence.launcher.authenticode.trusted, attestation.process_policy.policy_version,
        attestation.process_policy.enforced, attestation.process_policy.dynamic_code_prohibited,
        attestation.process_policy.extension_points_disabled, attestation.process_policy.strict_handle_checks,
        attestation.process_policy.remote_images_blocked, attestation.process_policy.low_mandatory_label_images_blocked,
        attestation.process_policy.prefer_system32_images, attestation.process_policy.child_process_creation_blocked,
        attestation.collected_at_unix,
    ))
}

pub(crate) fn recompute_attestation_sha256(attestation: &NeverGuardRemoteAttestation) -> Result<[u8; 32], String> {
    let mut clone = attestation.clone();
    clone.attestation_sha256.clear();
    clone.session_proof.clear();
    let digest = Sha256::digest(canonical_attestation_core(&clone)?.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub(crate) fn validate_attestation_shape(attestation: &NeverGuardRemoteAttestation) -> Result<(), String> {
    if (attestation.schema != NEVERGUARD_REMOTE_ATTESTATION_SCHEMA
        && attestation.schema != NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA)
        || attestation.attestation_version != NEVERGUARD_REMOTE_ATTESTATION_VERSION
    {
        return Err("NeverGuard remote attestation schema/version mismatch".to_string());
    }
    if attestation.challenge_id.is_empty() || attestation.challenge_id.len() > 160 {
        return Err("NeverGuard remote attestation challengeId malformed".to_string());
    }
    for (label, value) in [
        ("challengeSha256", attestation.challenge_sha256.as_str()),
        ("attestationSha256", attestation.attestation_sha256.as_str()),
        ("sessionProof", attestation.session_proof.as_str()),
    ] {
        if !value.is_empty()
            && (value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(format!("NeverGuard remote attestation {label} malformed"));
        }
    }
    if !attestation.process_policy.enforced {
        return Err("NeverGuard remote attestation process policy is not enforced".to_string());
    }
    if attestation.collected_at_unix != attestation.evidence.collected_at_unix {
        return Err("NeverGuard remote attestation collection timestamp mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthenticodeEvidence, BoundaryEvidence, ModuleSetEvidence, ProcessIntegrityEvidence,
        ProcessMitigationEvidence, NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA,
        NEVERGUARD_INTEGRITY_EVIDENCE_VERSION, NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA,
        NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
    };

    fn process(pid: u32, hash: &str) -> ProcessIntegrityEvidence {
        ProcessIntegrityEvidence {
            pid,
            image_path: format!("C:/NeverLauncher/{pid}.exe"),
            image_sha256: hash.to_string(),
            image_size: 10,
            image_modified_unix_ms: 20,
            process_created_filetime: 30,
            authenticode: AuthenticodeEvidence { trusted: true, status: "0x00000000".to_string() },
            mitigations: ProcessMitigationEvidence {
                dep: Some(1), aslr: Some(1), dynamic_code: Some(1), extension_point_disable: Some(1),
                control_flow_guard: Some(1), binary_signature: Some(1), image_load: Some(7),
                child_process: Some(1), user_shadow_stack: Some(1), sehop: Some(1), query_failures: vec![],
            },
            modules: ModuleSetEvidence { module_count: 1, module_set_sha256: "33".repeat(32), non_system_module_names: vec![] },
            linux: None,
        }
    }

    fn sample() -> NeverGuardRemoteAttestation {
        NeverGuardRemoteAttestation {
            schema: NEVERGUARD_REMOTE_ATTESTATION_SCHEMA.to_string(),
            attestation_version: 1,
            challenge_id: "challenge-1".to_string(),
            challenge_sha256: "11".repeat(32),
            collected_at_unix: 100,
            evidence: NeverGuardIntegrityEvidence {
                schema: NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA.to_string(),
                evidence_version: NEVERGUARD_INTEGRITY_EVIDENCE_VERSION,
                evidence_id: "a".repeat(32),
                collected_at_unix: 100,
                boundary: BoundaryEvidence { expected_parent_pid: 10, observed_parent_pid: 10, parent_matches: true },
                guard: process(11, &"44".repeat(32)),
                launcher: process(10, &"55".repeat(32)),
                evidence_sha256: "66".repeat(32),
                session_proof: "77".repeat(32),
            },
            process_policy: GuardProcessPolicyReport {
                schema: NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
                policy_version: NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
                pid: 11,
                enforced: true,
                dynamic_code_prohibited: true,
                extension_points_disabled: true,
                strict_handle_checks: true,
                remote_images_blocked: true,
                low_mandatory_label_images_blocked: true,
                prefer_system32_images: true,
                child_process_creation_blocked: true,
                linux: None,
            },
            attestation_sha256: String::new(),
            session_proof: String::new(),
        }
    }

    #[test]
    fn digest_changes_with_challenge() {
        let mut a = sample();
        let first = recompute_attestation_sha256(&a).unwrap();
        a.challenge_sha256 = "22".repeat(32);
        let second = recompute_attestation_sha256(&a).unwrap();
        assert_ne!(first, second);
    }
}
