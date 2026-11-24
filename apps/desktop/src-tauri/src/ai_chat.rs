//! Native authenticated AI transport: fixed endpoints, OS keyring, cancellable bounded SSE.
//! Desktop never needs an OpenAI credential or a browser CORS exception.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client, Response, Url};
use serde::Serialize;
use serde_json::{json, Value};
use std::{sync::Mutex, time::{Duration, Instant}};
use tauri::ipc::Channel;
use tokio::sync::watch;

const MAX_PROMPT: usize = 16_384;
const MAX_STREAM: usize = 8 * 1024 * 1024;
const MAX_USAGE: usize = 64 * 1024;
const BEGIN_TTL: Duration = Duration::from_secs(15);
const STREAM_TIMEOUT: Duration = Duration::from_secs(105);

struct Job { id: String, created: Instant, started: bool, cancel: watch::Sender<bool> }
static ACTIVE: Mutex<Option<Job>> = Mutex::new(None);
fn valid_id(id: &str) -> bool { id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn reserve(slot: &mut Option<Job>, id: String) -> Result<(), String> {
    if !valid_id(&id) { return Err("invalid".into()); }
    if slot.as_ref().is_some_and(|job| job.started || job.created.elapsed() < BEGIN_TTL) { return Err("limit".into()); }
    let (cancel, _) = watch::channel(false);
    *slot = Some(Job { id, created: Instant::now(), started: false, cancel });
    Ok(())
}
fn claim(slot: &mut Option<Job>, id: &str) -> Result<watch::Receiver<bool>, String> {
    let job = slot.as_mut().filter(|job| job.id == id && !job.started && job.created.elapsed() < BEGIN_TTL).ok_or("cancelled")?;
    job.started = true;
    Ok(job.cancel.subscribe())
}
fn stop(slot: &mut Option<Job>, id: &str) {
    if let Some(job) = slot.as_ref().filter(|job| job.id == id) {
        if job.started { let _ = job.cancel.send(true); } else { *slot = None; }
    }
}
struct Guard(String);
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut slot) = ACTIVE.lock() {
            if slot.as_ref().is_some_and(|job| job.id == self.0) { *slot = None; }
        }
    }
}
#[tauri::command]
pub(super) fn desktop_ai_begin(request_id: String) -> Result<(), String> {
    let mut slot = ACTIVE.lock().map_err(|_| "unavailable")?;
    reserve(&mut slot, request_id)
}
#[tauri::command]
pub(super) fn desktop_ai_cancel(request_id: String) -> Result<(), String> {
    let mut slot = ACTIVE.lock().map_err(|_| "unavailable")?;
    stop(&mut slot, &request_id);
    Ok(())
}
fn base(raw: &str) -> Result<Url, String> {
    let url = super::skif4er_login::backend(raw).map_err(|_| "invalid")?;
    if url.scheme() != "https" { return Err("invalid".into()); }
    Ok(url)
}
fn client(timeout: Duration) -> Result<Client, String> {
    Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10)).timeout(timeout).build().map_err(|_| "unavailable".into())
}
async fn token(backend: &str, expected_session_id: &str, expected_user_id: &str) -> Result<zeroize::Zeroizing<String>, String> {
    if expected_session_id.is_empty() || expected_user_id.is_empty() { return Err("unauthorized".into()); }
    // Copy the current access credential under the existing rotation lock; release it before network I/O.
    let _lock = super::desktop_auth::lock_session().await.map_err(|_| "unavailable")?;
    let mut session = super::load_auth_session(backend.to_owned()).await.map_err(|_| "unavailable")?.ok_or("unauthorized")?;
    use zeroize::Zeroize;
    let valid = super::desktop_auth::session_matches(&session, expected_session_id, expected_user_id);
    session.refresh_token.zeroize();
    if !valid { session.access_token.zeroize(); return Err("unauthorized".into()); }
    Ok(zeroize::Zeroizing::new(session.access_token))
}
fn status(response: &Response) -> Result<(), String> {
    match response.status().as_u16() {
        200 => Ok(()), 400 => Err("invalid".into()), 401 => Err("unauthorized".into()),
        403 => Err("forbidden".into()), 422 => Err("sensitive".into()), 429 => Err("limit".into()), _ => Err("unavailable".into()),
    }
}
fn content_type(response: &Response, expected: &str) -> bool {
    response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next()).is_some_and(|v| v.trim().eq_ignore_ascii_case(expected))
}
#[tauri::command]
pub(super) async fn desktop_ai_usage(backend_url: String, expected_session_id: String, expected_user_id: String) -> Result<Value, String> {
    let base = base(&backend_url)?;
    let token = token(&backend_url, &expected_session_id, &expected_user_id).await?;
    let mut response = client(Duration::from_secs(14))?.get(base.join("/api/v1/ai/usage").map_err(|_| "invalid")?)
        .bearer_auth(token.as_str()).header(reqwest::header::CACHE_CONTROL, "no-store")
        .send().await.map_err(|_| "network")?;
    status(&response)?;
    if !content_type(&response, "application/json") { return Err("protocol".into()); }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "network")? {
        if chunk.len() > MAX_USAGE.saturating_sub(body.len()) { return Err("protocol".into()); }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "protocol".into())
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(super) enum Packet { Chunk { data: String }, End }

async fn transfer(backend_url: &str, expected_session_id: &str, expected_user_id: &str, prompt: &str, channel: &Channel<Packet>) -> Result<(), String> {
    if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT { return Err("too_large".into()); }
    let base = base(backend_url)?;
    let token = token(backend_url, expected_session_id, expected_user_id).await?;
    let mut response = client(STREAM_TIMEOUT)?.post(base.join("/api/v1/ai/responses").map_err(|_| "invalid")?)
        .bearer_auth(token.as_str()).header(reqwest::header::ACCEPT, "text/event-stream")
        .header(reqwest::header::CACHE_CONTROL, "no-store").json(&json!({"prompt": prompt}))
        .send().await.map_err(|_| "network")?;
    status(&response)?;
    if !content_type(&response, "text/event-stream") { return Err("protocol".into()); }
    let mut bytes = 0usize;
    while let Some(chunk) = response.chunk().await.map_err(|_| "interrupted")? {
        if chunk.len() > MAX_STREAM.saturating_sub(bytes) { return Err("too_large".into()); }
        bytes += chunk.len();
        // Small bounded IPC messages. Encoding the raw bytes preserves fragmented UTF-8.
        for piece in chunk.chunks(16 * 1024) {
            channel.send(Packet::Chunk { data: STANDARD.encode(piece) }).map_err(|_| "cancelled")?;
        }
    }
    channel.send(Packet::End).map_err(|_| "cancelled")?;
    Ok(())
}
#[tauri::command]
pub(super) async fn desktop_ai_stream(request_id: String, backend_url: String, expected_session_id: String, expected_user_id: String, prompt: String, channel: Channel<Packet>) -> Result<(), String> {
    let mut cancel = {
        let mut slot = ACTIVE.lock().map_err(|_| "unavailable")?;
        claim(&mut slot, &request_id)?
    };
    let _guard = Guard(request_id);
    // The future is dropped on cancellation/timeout, closing reqwest's response and upstream request.
    tokio::select! {
        biased;
        _ = cancel.changed() => Err("cancelled".into()),
        result = tokio::time::timeout(STREAM_TIMEOUT, transfer(&backend_url, &expected_session_id, &expected_user_id, &prompt, &channel)) => result.map_err(|_| "cancelled")?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_cancellation_and_no_duplicate_stream() {
        let mut slot = None;
        let a = "a".repeat(32); let b = "b".repeat(32);
        reserve(&mut slot, a.clone()).unwrap();
        assert!(reserve(&mut slot, b.clone()).is_err());
        stop(&mut slot, &b); // another operation cannot cancel this one
        assert!(slot.is_some());
        stop(&mut slot, &a); // cancellation before dispatch
        assert!(claim(&mut slot, &a).is_err());
        reserve(&mut slot, a.clone()).unwrap();
        let rx = claim(&mut slot, &a).unwrap();
        assert!(claim(&mut slot, &a).is_err());
        stop(&mut slot, &a);
        assert!(*rx.borrow());
    }
    #[test]
    fn abandoned_reservation_expires_and_backend_is_https_only() {
        let mut slot = None; let a = "a".repeat(32);
        reserve(&mut slot, a.clone()).unwrap();
        slot.as_mut().unwrap().created = Instant::now() - BEGIN_TTL;
        assert!(claim(&mut slot, &a).is_err());
        reserve(&mut slot, "b".repeat(32)).unwrap();
        assert!(base("https://launcher.example.com").is_ok());
        assert!(base("http://localhost:8080").is_err());
        assert!(base("https://user:pass@launcher.example.com").is_err());
        assert!(base("https://launcher.example.com/?secret=1").is_err());
    }
}
