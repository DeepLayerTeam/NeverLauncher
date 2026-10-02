use serde::{Deserialize, Serialize};

pub const NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsDebugInstrumentationReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub attach_mechanism_disabled: bool,
    pub debugger_present: bool,
    pub remote_debugger_present: bool,
    pub debug_port_present: bool,
    pub debug_object_present: bool,
    pub debug_flags_no_debug_inherit: bool,
    pub blocked_startup_instrumentation_count: u32,
    pub integrity_check_count: u64,
    pub violation_count: u32,
    pub state_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsDebugInstrumentationReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION,
            active: false,
            healthy: false,
            attach_mechanism_disabled: false,
            debugger_present: false,
            remote_debugger_present: false,
            debug_port_present: false,
            debug_object_present: false,
            debug_flags_no_debug_inherit: false,
            blocked_startup_instrumentation_count: 0,
            integrity_check_count: 0,
            violation_count: 0,
            state_sha256: String::new(),
            last_violation: String::new(),
        }
    }
}
