use serde::{Deserialize, Serialize};

pub const NEVERGUARD_MEMORY_INTEGRITY_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsMemoryIntegrityReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub executable_region_count: u32,
    pub image_code_region_count: u32,
    pub dynamic_executable_region_count: u32,
    pub rwx_region_count: u32,
    pub executable_bytes: u64,
    pub observed_transition_count: u64,
    pub integrity_check_count: u64,
    pub violation_count: u32,
    pub code_set_sha256: String,
    pub executable_map_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsMemoryIntegrityReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_MEMORY_INTEGRITY_VERSION,
            active: false,
            healthy: false,
            executable_region_count: 0,
            image_code_region_count: 0,
            dynamic_executable_region_count: 0,
            rwx_region_count: 0,
            executable_bytes: 0,
            observed_transition_count: 0,
            integrity_check_count: 0,
            violation_count: 0,
            code_set_sha256: String::new(),
            executable_map_sha256: String::new(),
            last_violation: String::new(),
        }
    }
}
