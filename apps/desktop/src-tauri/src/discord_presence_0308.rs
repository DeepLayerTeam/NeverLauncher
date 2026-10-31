//! Opt-in Rich Presence through Discord's documented local RPC transport.
//! This is desktop IPC, not Discord's removed Game SDK networking facility.
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tauri::State;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};

const MAX_FRAME: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(4);

trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}

struct Connection {
    application_id: String,
    socket: Box<dyn Socket>,
    nonce: u64,
}

#[derive(Default)]
pub struct DiscordPresence {
    session: Mutex<Option<Connection>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceRequest {
    application_id: String,
    details: String,
    state: String,
    #[serde(default)]
    action_url: Option<String>,
}

fn validate(req: &PresenceRequest) -> Result<(), String> {
    if !(17..=20).contains(&req.application_id.len())
        || !req.application_id.bytes().all(|c| c.is_ascii_digit()) {
        return Err("Discord application ID must be a decimal snowflake".into());
    }
    if req.details.chars().count() > 128 || req.state.chars().count() > 128 {
        return Err("Discord activity fields exceed 128 characters".into());
    }
    if let Some(url) = req.action_url.as_deref().filter(|s| !s.is_empty()) {
        let parsed = reqwest::Url::parse(url).map_err(|_| "Invalid Discord action URL")?;
        if parsed.scheme() != "https" || parsed.host_str().is_none()
            || !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("Discord activity actions require public HTTPS URLs".into());
        }
    }
    Ok(())
}

async fn connect() -> Result<Box<dyn Socket>, String> {
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        for index in 0..10 {
            let name = format!(r"\\.\pipe\discord-ipc-{index}");
            if let Ok(socket) = ClientOptions::new().open(name) {
                return Ok(Box::new(socket));
            }
        }
    }
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let mut roots = Vec::new();
        for env in ["XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"] {
            if let Some(value) = std::env::var_os(env) {
                if !value.is_empty() { roots.push(std::path::PathBuf::from(value)); }
            }
        }
        roots.push(std::path::PathBuf::from("/tmp"));
        for root in roots {
            for index in 0..10 {
                if let Ok(socket) = timeout(IO_TIMEOUT,
                    UnixStream::connect(root.join(format!("discord-ipc-{index}")))).await {
                    if let Ok(socket) = socket { return Ok(Box::new(socket)); }
                }
            }
        }
    }
    Err("Discord desktop client IPC is unavailable".into())
}

impl Connection {
    async fn send(&mut self, opcode: u32, body: &Value) -> Result<(), String> {
        let payload = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        if payload.len() > MAX_FRAME { return Err("Discord payload is oversized".into()); }
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&opcode.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        timeout(IO_TIMEOUT, self.socket.write_all(&frame)).await
            .map_err(|_| "Discord IPC write timed out")?
            .map_err(|e| format!("Discord IPC write: {e}"))
    }

    async fn receive(&mut self) -> Result<(u32, Value), String> {
        let mut header = [0u8; 8];
        timeout(IO_TIMEOUT, self.socket.read_exact(&mut header)).await
            .map_err(|_| "Discord IPC header timed out")?
            .map_err(|e| format!("Discord IPC header: {e}"))?;
        let opcode = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if length > MAX_FRAME { return Err("Discord IPC frame too large".into()); }
        let mut body = vec![0u8; length];
        timeout(IO_TIMEOUT, self.socket.read_exact(&mut body)).await
            .map_err(|_| "Discord IPC response timed out")?
            .map_err(|e| format!("Discord IPC response: {e}"))?;
        let parsed = serde_json::from_slice(&body).map_err(|e| format!("Discord IPC JSON: {e}"))?;
        Ok((opcode, parsed))
    }

    async fn ready(application_id: String) -> Result<Self, String> {
        let socket = connect().await?;
        let mut session = Self { application_id: application_id.clone(), socket, nonce: 0 };
        session.send(0, &json!({"v": 1, "client_id": application_id})).await?;
        for _ in 0..8 {
            let (opcode, message) = session.receive().await?;
            if opcode == 2 { return Err("Discord closed handshake".into()); }
            if message.get("evt").and_then(Value::as_str) == Some("ERROR") {
                return Err(format!("Discord rejected handshake: {}", message["data"]));
            }
            if opcode == 1 && message.get("evt").and_then(Value::as_str) == Some("READY") {
                return Ok(session);
            }
        }
        Err("Discord IPC READY was not received".into())
    }

    async fn set_activity(&mut self, activity: Option<Value>) -> Result<(), String> {
        self.nonce += 1;
        let nonce = self.nonce.to_string();
        self.send(1, &json!({"cmd": "SET_ACTIVITY", "nonce": nonce,
            "args": {"pid": std::process::id(), "activity": activity}})).await?;
        for _ in 0..16 {
            let (opcode, message) = self.receive().await?;
            if opcode == 2 { return Err("Discord IPC closed".into()); }
            if message.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) { continue; }
            if message.get("evt").and_then(Value::as_str) == Some("ERROR") {
                return Err(format!("Discord rejected activity: {}", message["data"]));
            }
            if message.get("cmd").and_then(Value::as_str) == Some("SET_ACTIVITY") {
                return Ok(());
            }
        }
        Err("Discord SET_ACTIVITY acknowledgement not received".into())
    }
}

#[tauri::command]
pub async fn discord_presence_set(
    manager: State<'_, DiscordPresence>, request: PresenceRequest,
) -> Result<(), String> {
    validate(&request)?;
    let mut guard = manager.session.lock().await;
    if guard.as_ref().is_none_or(|session| session.application_id != request.application_id) {
        *guard = None;
        *guard = Some(Connection::ready(request.application_id).await?);
    }
    let mut activity = json!({"type": 0, "state": request.state, "details": request.details});
    if let Some(url) = request.action_url.filter(|value| !value.is_empty()) {
        activity["buttons"] = json!([{"label": "Открыть проект", "url": url}]);
    }
    if let Some(session) = guard.as_mut() {
        if let Err(error) = session.set_activity(Some(activity)).await {
            *guard = None;
            return Err(error);
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn discord_presence_clear(manager: State<'_, DiscordPresence>) -> Result<(), String> {
    let mut guard = manager.session.lock().await;
    if let Some(session) = guard.as_mut() {
        let result = session.set_activity(None).await;
        *guard = None;
        return result;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activity_needs_valid_snowflake_and_action() {
        let mut req = PresenceRequest{application_id:"123456789012345678".into(),details:"Launcher".into(),state:"In launcher".into(),action_url:None};
        assert!(validate(&req).is_ok());
        req.action_url=Some("javascript:alert(1)".into());
        assert!(validate(&req).is_err());
        req.action_url=Some("https://example.org".into());
        assert!(validate(&req).is_ok());
        req.application_id="unsafe".into();
        assert!(validate(&req).is_err());
    }
}
