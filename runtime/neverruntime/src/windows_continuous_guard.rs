use serde::{Deserialize, Serialize};

pub const NEVERGUARD_CONTINUOUS_GUARD_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsContinuousGuardReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub sensor_heartbeat_count: u64,
    pub guard_heartbeat_count: u64,
    pub cross_check_count: u64,
    pub last_sensor_sequence: u64,
    pub last_guard_sequence: u64,
    pub sensor_event_chain_sha256: String,
    pub last_cross_check_sha256: String,
    pub last_sensor_heartbeat_unix_ms: u64,
    pub last_guard_heartbeat_unix_ms: u64,
    pub violation_count: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsContinuousGuardReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_CONTINUOUS_GUARD_VERSION,
            active: false,
            healthy: false,
            sensor_heartbeat_count: 0,
            guard_heartbeat_count: 0,
            cross_check_count: 0,
            last_sensor_sequence: 0,
            last_guard_sequence: 0,
            sensor_event_chain_sha256: String::new(),
            last_cross_check_sha256: String::new(),
            last_sensor_heartbeat_unix_ms: 0,
            last_guard_heartbeat_unix_ms: 0,
            violation_count: 0,
            last_violation: String::new(),
        }
    }
}
