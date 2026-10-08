// Код сгенерирован scripts/sdk/generate-types.py; НЕ РЕДАКТИРОВАТЬ.
use serde::{Deserialize, Serialize};

pub const DESKTOP_PROTOCOL_VERSION: &str = "neverextensions.desktop-rpc.v1";
pub const EXTENSION_API_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopContext {
    pub extension_id: String,
    pub version: String,
    pub extension_api_version: String,
    pub scope: String,
    pub scope_id: String,
    pub page_id: String,
    pub action_id: String,
    pub bridge_allowed: bool,
}
