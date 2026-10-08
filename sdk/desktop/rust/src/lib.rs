//! NeverExtensions Настольное приложение Rust SDK.
//! Этот crate содержит протокол types/helpers для нативный companion код. Это делает
//! не предоставлять Tauri внутренний; песочница UI по-прежнему goes через разрешение мост.

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
