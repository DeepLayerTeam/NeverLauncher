//! Настольный Rust SDK Extensions. Этот crate содержит типы протокола
//! и помощники для нативного сопутствующего кода. Он не открывает внутренности
//! Tauri; интерфейс в песочнице использует мост с проверкой разрешений.

mod generated;
pub use generated::*;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRequest {
    pub protocol: String,
    pub r#type: String,
    pub id: String,
    pub method: String,
    pub params: Value,
}

impl RpcRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.protocol != DESKTOP_PROTOCOL_VERSION { return Err("unsupported desktop protocol"); }
        if self.r#type != "rpc.request" || self.id.trim().is_empty() || self.method.trim().is_empty() { return Err("invalid desktop RPC request"); }
        Ok(())
    }
}
