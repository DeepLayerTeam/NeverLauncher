use crate::{ProcessStatus, WindowsSensorReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_VERSION: u32 = 2;
pub const NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_SCHEMA: &str =
    "neverguard/windows-continuous-evidence/v2";
pub const NEVERGUARD_WINDOWS_REMOTE_ATTESTATION_V2_VERSION: u32 = 2;
pub const NEVERGUARD_WINDOWS_REMOTE_ATTESTATION_V2_SCHEMA: &str =
    "neverguard/windows-guard-attestation/v2";
const CONTINUOUS_EVIDENCE_MAX_STALENESS_MS: u64 = 5_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsContinuousEvidenceV2 {
    pub schema: String,
    pub evidence_version: u32,
    pub process_id: String,
    pub runtime_pid: u32,
    pub collected_at_unix_ms: u64,
    pub sensor_protocol_version: u32,
    pub sensor_authenticated: bool,
    pub sensor_loaded_before_main: bool,
    pub module_guard_version: u32,
    pub module_guard_healthy: bool,
    pub module_event_count: u64,
    pub module_last_sequence: u64,
    pub module_event_chain_sha256: String,
    pub module_set_sha256: String,
    pub hook_engine_healthy: bool,
    pub hook_set_sha256: String,
    pub memory_integrity_healthy: bool,
    pub code_set_sha256: String,
    pub executable_map_sha256: String,
    pub thread_process_integrity_healthy: bool,
    pub job_bound: bool,
    pub thread_set_sha256: String,
    pub thread_origin_set_sha256: String,
    pub process_tree_sha256: String,
    pub debug_instrumentation_healthy: bool,
    pub debug_state_sha256: String,
    pub jvm_aware_healthy: bool,
    pub java_major: u32,
    pub jvm_state_sha256: String,
    pub continuous_guard_version: u32,
    pub continuous_guard_healthy: bool,
    pub sensor_heartbeat_count: u64,
    pub guard_heartbeat_count: u64,
    pub cross_check_count: u64,
    pub last_sensor_sequence: u64,
    pub last_guard_sequence: u64,
    pub sensor_event_chain_sha256: String,
    pub last_cross_check_sha256: String,
    pub last_sensor_heartbeat_unix_ms: u64,
    pub last_guard_heartbeat_unix_ms: u64,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NeverGuardRemoteAttestationV2 {
    pub schema: String,
    pub attestation_version: u32,
    pub challenge_id: String,
    pub challenge_sha256: String,
    pub collected_at_unix_ms: u64,
    pub base_attestation: crate::NeverGuardRemoteAttestation,
    pub continuous_evidence: WindowsContinuousEvidenceV2,
    pub attestation_sha256: String,
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn now_unix_ms() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock до UNIX эпоха: {err}"))?
        .as_millis() as u64)
}

fn require_hash(label: &str, value: &str) -> Result<(), String> {
    if !is_sha256_hex(value) {
        return Err(format!("NeverGuard Аттестация v2 {label} повреждённый"));
    }
    Ok(())
}

pub fn continuous_evidence_core(evidence: &WindowsContinuousEvidenceV2) -> String {
    format!(
        concat!(
            "NeverLauncher Windows Continuous Evidence v2\n",
            "process-id={}\n","runtime-pid={}\n","collected-at-ms={}\n",
            "sensor-protocol-version={}\n","sensor-authenticated={}\n","sensor-loaded-before-main={}\n",
            "module-guard-version={}\n","module-guard-healthy={}\n","module-event-count={}\n","module-last-sequence={}\n",
            "module-event-chain-sha256={}\n","module-set-sha256={}\n",
            "hook-engine-healthy={}\n","hook-set-sha256={}\n",
            "memory-integrity-healthy={}\n","code-set-sha256={}\n","executable-map-sha256={}\n",
            "thread-process-integrity-healthy={}\n","job-bound={}\n","thread-set-sha256={}\n","thread-origin-set-sha256={}\n","process-tree-sha256={}\n",
            "debug-instrumentation-healthy={}\n","debug-state-sha256={}\n",
            "jvm-aware-healthy={}\n","java-major={}\n","jvm-state-sha256={}\n",
            "continuous-guard-version={}\n","continuous-guard-healthy={}\n",
            "sensor-heartbeat-count={}\n","guard-heartbeat-count={}\n","cross-check-count={}\n",
            "last-sensor-sequence={}\n","last-guard-sequence={}\n",
            "sensor-event-chain-sha256={}\n","last-cross-check-sha256={}\n",
            "last-sensor-heartbeat-ms={}\n","last-guard-heartbeat-ms={}\n"
        ),
        evidence.process_id,
        evidence.runtime_pid,
        evidence.collected_at_unix_ms,
        evidence.sensor_protocol_version,
        evidence.sensor_authenticated,
        evidence.sensor_loaded_before_main,
        evidence.module_guard_version,
        evidence.module_guard_healthy,
        evidence.module_event_count,
        evidence.module_last_sequence,
        evidence.module_event_chain_sha256,
        evidence.module_set_sha256,
        evidence.hook_engine_healthy,
        evidence.hook_set_sha256,
        evidence.memory_integrity_healthy,
        evidence.code_set_sha256,
        evidence.executable_map_sha256,
        evidence.thread_process_integrity_healthy,
        evidence.job_bound,
        evidence.thread_set_sha256,
        evidence.thread_origin_set_sha256,
        evidence.process_tree_sha256,
        evidence.debug_instrumentation_healthy,
        evidence.debug_state_sha256,
        evidence.jvm_aware_healthy,
        evidence.java_major,
        evidence.jvm_state_sha256,
        evidence.continuous_guard_version,
        evidence.continuous_guard_healthy,
        evidence.sensor_heartbeat_count,
        evidence.guard_heartbeat_count,
        evidence.cross_check_count,
        evidence.last_sensor_sequence,
        evidence.last_guard_sequence,
        evidence.sensor_event_chain_sha256,
        evidence.last_cross_check_sha256,
        evidence.last_sensor_heartbeat_unix_ms,
        evidence.last_guard_heartbeat_unix_ms,
    )
}

pub fn recompute_continuous_evidence_sha256(evidence: &WindowsContinuousEvidenceV2) -> String {
    hex::encode(Sha256::digest(continuous_evidence_core(evidence).as_bytes()))
}

pub fn validate_continuous_evidence_v2(
    evidence: &WindowsContinuousEvidenceV2,
    now_ms: u64,
) -> Result<(), String> {
    if evidence.schema != NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_SCHEMA
        || evidence.evidence_version != NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_VERSION
        || evidence.process_id.trim().is_empty()
        || evidence.runtime_pid == 0
    {
        return Err("NeverGuard Attestation v2 continuous evidence schema/identity mismatch".to_string());
    }
    if evidence.sensor_protocol_version != crate::NEVERGUARD_SENSOR_PROTOCOL_VERSION
        || evidence.module_guard_version != crate::NEVERGUARD_MODULE_GUARD_VERSION
        || evidence.continuous_guard_version != crate::NEVERGUARD_CONTINUOUS_GUARD_VERSION
    {
        return Err("NeverGuard Attestation v2 continuous component version mismatch".to_string());
    }
    if !evidence.sensor_authenticated
        || !evidence.sensor_loaded_before_main
        || !evidence.module_guard_healthy
        || !evidence.hook_engine_healthy
        || !evidence.memory_integrity_healthy
        || !evidence.thread_process_integrity_healthy
        || !evidence.job_bound
        || !evidence.debug_instrumentation_healthy
        || !evidence.jvm_aware_healthy
        || !evidence.continuous_guard_healthy
    {
        return Err("NeverGuard Attestation v2 continuous protection is not healthy".to_string());
    }
    if evidence.module_event_count == 0
        || evidence.module_last_sequence == 0
        || evidence.sensor_heartbeat_count == 0
        || evidence.guard_heartbeat_count == 0
        || evidence.cross_check_count == 0
        || evidence.last_sensor_sequence == 0
        || evidence.last_guard_sequence == 0
    {
        return Err("NeverGuard Attestation v2 continuous counters are not armed".to_string());
    }
    if evidence.sensor_heartbeat_count != evidence.guard_heartbeat_count
        || evidence.sensor_heartbeat_count != evidence.cross_check_count
    {
        return Err("NeverGuard Attestation v2 Sensor/Guard heartbeat counters diverged".to_string());
    }
    if evidence.java_major != 8
        && evidence.java_major != 16
        && evidence.java_major != 17
        && evidence.java_major != 21
        && evidence.java_major != 25
    {
        return Err("NeverGuard Attestation v2 Java major is not certified".to_string());
    }
    for (label, value) in [
        ("moduleEventChainSha256", evidence.module_event_chain_sha256.as_str()),
        ("moduleSetSha256", evidence.module_set_sha256.as_str()),
        ("hookSetSha256", evidence.hook_set_sha256.as_str()),
        ("codeSetSha256", evidence.code_set_sha256.as_str()),
        ("executableMapSha256", evidence.executable_map_sha256.as_str()),
        ("threadSetSha256", evidence.thread_set_sha256.as_str()),
        ("threadOriginSetSha256", evidence.thread_origin_set_sha256.as_str()),
        ("processTreeSha256", evidence.process_tree_sha256.as_str()),
        ("debugStateSha256", evidence.debug_state_sha256.as_str()),
        ("jvmStateSha256", evidence.jvm_state_sha256.as_str()),
        ("sensorEventChainSha256", evidence.sensor_event_chain_sha256.as_str()),
        ("lastCrossCheckSha256", evidence.last_cross_check_sha256.as_str()),
        ("evidenceSha256", evidence.evidence_sha256.as_str()),
    ] {
        require_hash(label, value)?;
    }
    if evidence.collected_at_unix_ms > now_ms.saturating_add(2_000)
        || now_ms.saturating_sub(evidence.collected_at_unix_ms) > CONTINUOUS_EVIDENCE_MAX_STALENESS_MS
        || now_ms.saturating_sub(evidence.last_sensor_heartbeat_unix_ms) > CONTINUOUS_EVIDENCE_MAX_STALENESS_MS
        || now_ms.saturating_sub(evidence.last_guard_heartbeat_unix_ms) > CONTINUOUS_EVIDENCE_MAX_STALENESS_MS
    {
        return Err("NeverGuard Attestation v2 continuous evidence is stale".to_string());
    }
    let expected = recompute_continuous_evidence_sha256(evidence);
    if !expected.eq_ignore_ascii_case(&evidence.evidence_sha256) {
        return Err("NeverGuard Attestation v2 continuous evidence digest mismatch".to_string());
    }
    Ok(())
}

pub fn collect_windows_continuous_evidence_v2(
    process_id: &str,
    status: &ProcessStatus,
) -> Result<WindowsContinuousEvidenceV2, String> {
    if status.id != process_id || status.state != "running" {
        return Err("NeverGuard Attestation v2 requires the requested running runtime process".to_string());
    }
    let runtime_pid = status.pid.ok_or_else(|| "NeverGuard Attestation v2 runtime PID unavailable".to_string())?;
    let sensor: &WindowsSensorReport = status.windows_sensor.as_ref().ok_or_else(|| {
        "NeverGuard Attestation v2 requires authenticated Windows Sensor evidence".to_string()
    })?;
    if sensor.pid != runtime_pid {
        return Err("NeverGuard Attestation v2 Sensor/runtime PID mismatch".to_string());
    }
    let module = &sensor.module_guard;
    let hook = &module.hook_engine;
    let memory = &module.memory_integrity;
    let threads = &module.thread_process_integrity;
    let debug = &module.debug_instrumentation;
    let jvm = &module.jvm_aware;
    let continuous = &module.continuous_guard;
    if !module.active || module.violation_count != 0 || module.dropped_event_count != 0
        || !hook.active || hook.violation_count != 0
        || !memory.active || memory.violation_count != 0
        || !threads.active || threads.violation_count != 0 || threads.suspicious_thread_count != 0 || threads.breakaway_allowed
        || !debug.active || debug.violation_count != 0 || debug.debugger_present || debug.remote_debugger_present || debug.debug_port_present || debug.debug_object_present
        || !jvm.active || !jvm.certified_major || jvm.violation_count != 0 || jvm.foreign_executable_transition_count != 0 || jvm.unknown_executable_transition_count != 0
        || !continuous.active || continuous.violation_count != 0
    {
        return Err("NeverGuard Attestation v2 runtime protection reports a violation".to_string());
    }
    let collected_at_unix_ms = now_unix_ms()?;
    let mut evidence = WindowsContinuousEvidenceV2 {
        schema: NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_SCHEMA.to_string(),
        evidence_version: NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_VERSION,
        process_id: process_id.to_string(),
        runtime_pid,
        collected_at_unix_ms,
        sensor_protocol_version: sensor.protocol_version,
        sensor_authenticated: sensor.authenticated,
        sensor_loaded_before_main: sensor.loaded_before_main,
        module_guard_version: module.version,
        module_guard_healthy: module.healthy,
        module_event_count: module.event_count,
        module_last_sequence: module.last_sequence,
        module_event_chain_sha256: module.event_chain_sha256.clone(),
        module_set_sha256: module.module_set_sha256.clone(),
        hook_engine_healthy: hook.healthy,
        hook_set_sha256: hook.hook_set_sha256.clone(),
        memory_integrity_healthy: memory.healthy,
        code_set_sha256: memory.code_set_sha256.clone(),
        executable_map_sha256: memory.executable_map_sha256.clone(),
        thread_process_integrity_healthy: threads.healthy,
        job_bound: threads.job_bound,
        thread_set_sha256: threads.thread_set_sha256.clone(),
        thread_origin_set_sha256: threads.thread_origin_set_sha256.clone(),
        process_tree_sha256: threads.process_tree_sha256.clone(),
        debug_instrumentation_healthy: debug.healthy,
        debug_state_sha256: debug.state_sha256.clone(),
        jvm_aware_healthy: jvm.healthy,
        java_major: jvm.java_major,
        jvm_state_sha256: jvm.state_sha256.clone(),
        continuous_guard_version: continuous.version,
        continuous_guard_healthy: continuous.healthy,
        sensor_heartbeat_count: continuous.sensor_heartbeat_count,
        guard_heartbeat_count: continuous.guard_heartbeat_count,
        cross_check_count: continuous.cross_check_count,
        last_sensor_sequence: continuous.last_sensor_sequence,
        last_guard_sequence: continuous.last_guard_sequence,
        sensor_event_chain_sha256: continuous.sensor_event_chain_sha256.clone(),
        last_cross_check_sha256: continuous.last_cross_check_sha256.clone(),
        last_sensor_heartbeat_unix_ms: continuous.last_sensor_heartbeat_unix_ms,
        last_guard_heartbeat_unix_ms: continuous.last_guard_heartbeat_unix_ms,
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = recompute_continuous_evidence_sha256(&evidence);
    validate_continuous_evidence_v2(&evidence, collected_at_unix_ms)?;
    Ok(evidence)
}

pub fn windows_attestation_v2_core(attestation: &NeverGuardRemoteAttestationV2) -> String {
    format!(
        concat!(
            "NeverLauncher Guard Attestation Core Windows v2\n",
            "challenge-id={}\n","challenge-sha256={}\n","collected-at-ms={}\n",
            "base-attestation-sha256={}\n","continuous-evidence-sha256={}\n",
            "runtime-pid={}\n","last-sensor-sequence={}\n","last-guard-sequence={}\n",
            "sensor-event-chain-sha256={}\n","last-cross-check-sha256={}\n"
        ),
        attestation.challenge_id,
        attestation.challenge_sha256,
        attestation.collected_at_unix_ms,
        attestation.base_attestation.attestation_sha256,
        attestation.continuous_evidence.evidence_sha256,
        attestation.continuous_evidence.runtime_pid,
        attestation.continuous_evidence.last_sensor_sequence,
        attestation.continuous_evidence.last_guard_sequence,
        attestation.continuous_evidence.sensor_event_chain_sha256,
        attestation.continuous_evidence.last_cross_check_sha256,
    )
}

pub fn recompute_windows_attestation_v2_sha256(attestation: &NeverGuardRemoteAttestationV2) -> String {
    hex::encode(Sha256::digest(windows_attestation_v2_core(attestation).as_bytes()))
}

pub fn build_windows_attestation_v2(
    challenge_id: String,
    challenge: &str,
    base_attestation: crate::NeverGuardRemoteAttestation,
    continuous_evidence: WindowsContinuousEvidenceV2,
) -> Result<NeverGuardRemoteAttestationV2, String> {
    if challenge_id.trim().is_empty() || challenge_id.len() > 160 || challenge.is_empty() || challenge.len() > 4096 {
        return Err("NeverGuard Attestation v2 challenge malformed".to_string());
    }
    if base_attestation.challenge_id != challenge_id
        || base_attestation.challenge_sha256 != crate::attestation::challenge_sha256(challenge)
    {
        return Err("NeverGuard Attestation v2 base attestation challenge mismatch".to_string());
    }
    validate_continuous_evidence_v2(&continuous_evidence, continuous_evidence.collected_at_unix_ms)?;
    let mut attestation = NeverGuardRemoteAttestationV2 {
        schema: NEVERGUARD_WINDOWS_REMOTE_ATTESTATION_V2_SCHEMA.to_string(),
        attestation_version: NEVERGUARD_WINDOWS_REMOTE_ATTESTATION_V2_VERSION,
        challenge_id,
        challenge_sha256: crate::attestation::challenge_sha256(challenge),
        collected_at_unix_ms: continuous_evidence.collected_at_unix_ms,
        base_attestation,
        continuous_evidence,
        attestation_sha256: String::new(),
    };
    attestation.attestation_sha256 = recompute_windows_attestation_v2_sha256(&attestation);
    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(ch: char) -> String {
        std::iter::repeat(ch).take(64).collect()
    }

    fn evidence(now: u64) -> WindowsContinuousEvidenceV2 {
        let mut value = WindowsContinuousEvidenceV2 {
            schema: NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_SCHEMA.to_string(),
            evidence_version: NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_VERSION,
            process_id: "runtime-test".to_string(),
            runtime_pid: 4242,
            collected_at_unix_ms: now,
            sensor_protocol_version: 3,
            sensor_authenticated: true,
            sensor_loaded_before_main: true,
            module_guard_version: 1,
            module_guard_healthy: true,
            module_event_count: 8,
            module_last_sequence: 8,
            module_event_chain_sha256: hash('1'),
            module_set_sha256: hash('2'),
            hook_engine_healthy: true,
            hook_set_sha256: hash('3'),
            memory_integrity_healthy: true,
            code_set_sha256: hash('4'),
            executable_map_sha256: hash('5'),
            thread_process_integrity_healthy: true,
            job_bound: true,
            thread_set_sha256: hash('6'),
            thread_origin_set_sha256: hash('7'),
            process_tree_sha256: hash('8'),
            debug_instrumentation_healthy: true,
            debug_state_sha256: hash('9'),
            jvm_aware_healthy: true,
            java_major: 21,
            jvm_state_sha256: hash('a'),
            continuous_guard_version: 1,
            continuous_guard_healthy: true,
            sensor_heartbeat_count: 2,
            guard_heartbeat_count: 2,
            cross_check_count: 2,
            last_sensor_sequence: 10,
            last_guard_sequence: 2,
            sensor_event_chain_sha256: hash('b'),
            last_cross_check_sha256: hash('c'),
            last_sensor_heartbeat_unix_ms: now,
            last_guard_heartbeat_unix_ms: now,
            evidence_sha256: String::new(),
        };
        value.evidence_sha256 = recompute_continuous_evidence_sha256(&value);
        value
    }

    #[test]
    fn continuous_evidence_digest_and_freshness_are_enforced() {
        let now = 1_800_000_000_000u64;
        let value = evidence(now);
        validate_continuous_evidence_v2(&value, now).expect("fresh evidence");

        let mut wrong_version = value.clone();
        wrong_version.sensor_protocol_version = wrong_version.sensor_protocol_version.saturating_add(1);
        wrong_version.evidence_sha256 = recompute_continuous_evidence_sha256(&wrong_version);
        assert!(validate_continuous_evidence_v2(&wrong_version, now).is_err());

        let mut diverged = value.clone();
        diverged.guard_heartbeat_count += 1;
        diverged.evidence_sha256 = recompute_continuous_evidence_sha256(&diverged);
        assert!(validate_continuous_evidence_v2(&diverged, now).is_err());

        let mut stale = value;
        stale.collected_at_unix_ms = now - 6_000;
        stale.last_sensor_heartbeat_unix_ms = now - 6_000;
        stale.last_guard_heartbeat_unix_ms = now - 6_000;
        stale.evidence_sha256 = recompute_continuous_evidence_sha256(&stale);
        assert!(validate_continuous_evidence_v2(&stale, now).is_err());
    }
}
