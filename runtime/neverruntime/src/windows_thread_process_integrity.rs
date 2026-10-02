use serde::{Deserialize, Serialize};

pub const NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsThreadProcessIntegrityReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub baseline_thread_count: u32,
    pub current_thread_count: u32,
    pub new_thread_count: u64,
    pub retired_thread_count: u64,
    pub suspicious_thread_count: u32,
    pub baseline_process_count: u32,
    pub current_process_count: u32,
    pub descendant_process_count: u32,
    pub descendant_process_peak: u32,
    pub process_transition_count: u64,
    pub integrity_check_count: u64,
    pub violation_count: u32,
    pub job_bound: bool,
    pub breakaway_allowed: bool,
    pub thread_set_sha256: String,
    pub thread_origin_set_sha256: String,
    pub process_tree_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsThreadProcessIntegrityReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION,
            active: false,
            healthy: false,
            baseline_thread_count: 0,
            current_thread_count: 0,
            new_thread_count: 0,
            retired_thread_count: 0,
            suspicious_thread_count: 0,
            baseline_process_count: 0,
            current_process_count: 0,
            descendant_process_count: 0,
            descendant_process_peak: 0,
            process_transition_count: 0,
            integrity_check_count: 0,
            violation_count: 0,
            job_bound: false,
            breakaway_allowed: true,
            thread_set_sha256: String::new(),
            thread_origin_set_sha256: String::new(),
            process_tree_sha256: String::new(),
            last_violation: String::new(),
        }
    }
}
