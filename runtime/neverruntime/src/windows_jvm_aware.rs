use serde::{Deserialize, Serialize};

pub const NEVERGUARD_JVM_AWARE_PROTECTION_VERSION: u32 = 1;
pub const NEVERGUARD_CERTIFIED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsJvmAwareProtectionReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub java_major: u32,
    pub certified_major: bool,
    pub jvm_module_size: u32,
    pub baseline_private_executable_region_count: u32,
    pub jit_transition_count: u64,
    pub foreign_executable_transition_count: u64,
    pub unknown_executable_transition_count: u64,
    pub integrity_check_count: u64,
    pub violation_count: u32,
    pub jvm_path_sha256: String,
    pub state_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsJvmAwareProtectionReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_JVM_AWARE_PROTECTION_VERSION,
            active: false,
            healthy: false,
            java_major: 0,
            certified_major: false,
            jvm_module_size: 0,
            baseline_private_executable_region_count: 0,
            jit_transition_count: 0,
            foreign_executable_transition_count: 0,
            unknown_executable_transition_count: 0,
            integrity_check_count: 0,
            violation_count: 0,
            jvm_path_sha256: String::new(),
            state_sha256: String::new(),
            last_violation: String::new(),
        }
    }
}
