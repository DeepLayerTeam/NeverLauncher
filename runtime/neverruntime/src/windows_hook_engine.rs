use serde::{Deserialize, Serialize};

pub const NEVERGUARD_HOOK_ENGINE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsHookEngineReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub hooked_module_count: u32,
    pub hooked_slot_count: u32,
    pub intercepted_call_count: u64,
    pub integrity_check_count: u64,
    pub violation_count: u32,
    pub hook_set_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsHookEngineReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_HOOK_ENGINE_VERSION,
            active: false,
            healthy: false,
            hooked_module_count: 0,
            hooked_slot_count: 0,
            intercepted_call_count: 0,
            integrity_check_count: 0,
            violation_count: 0,
            hook_set_sha256: String::new(),
            last_violation: String::new(),
        }
    }
}
