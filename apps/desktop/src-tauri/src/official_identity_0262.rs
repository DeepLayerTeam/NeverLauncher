//! 0.26.2: Native boundary for the existing official Minecraft backend flow.
//! The renderer never receives Microsoft/Minecraft credentials or the opaque
//! encrypted backend ticket (which itself contains refresh/game tokens).
use std::{collections::HashMap, net::IpAddr, sync::Mutex, time::{Duration, Instant}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use reqwest::{Client, Method, Url};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use rand::RngCore;
use base64::Engine as _;
use neverruntime::MinecraftLaunchCredentials;

const SERVICE: &str = "NeverLauncher Official Minecraft 0.26.2";
const PREFIX: &str = "/api/v1/minecraft/official";
const RESPONSE_LIMIT: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfficialProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub skins: Vec<OfficialSkin>,
    #[serde(default)]
    pub capes: Vec<OfficialCape>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfficialSkin { pub id: String, pub state: String, pub url: String, pub variant: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfficialCape { pub id: String, pub state: String, pub url: String, #[serde(default)] pub alias: Option<String> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChallenge { pub verification_uri: String, pub user_code: String, pub interval_seconds: u64, pub expires_in: u64 }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PollResult { pub pending: bool, #[serde(skip_serializing_if="Option::is_none")] pub profile: Option<OfficialProfile>, #[serde(skip_serializing_if="Option::is_none")] pub interval_seconds: Option<u64> }

// Never serialize this struct back over IPC. Keyring payload is all-or-nothing.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredAccount { schema: u32, ticket: String, profile: OfficialProfile }
impl Drop for StoredAccount { fn drop(&mut self) { self.ticket.zeroize(); } }

struct PendingFlow { ticket: String, next: Instant, expires: Instant }
impl Drop for PendingFlow { fn drop(&mut self) { self.ticket.zeroize(); } }

pub struct IdentityManager {
    client: Client,
    pending: Mutex<HashMap<String, PendingFlow>>,
    vault_lock: tokio::sync::Mutex<()>,
}

fn uuid_valid(uuid: &str) -> bool { uuid.len() == 32 && uuid.bytes().all(|c| c.is_ascii_hexdigit()) }
fn scope(backend: &str, session_id: &str) -> Result<(Url, String), String> {
    if session_id.is_empty() || session_id.len() > 256 || !session_id.is_ascii() { return Err("Неверная Never session identity".into()); }
    let url = Url::parse(backend).map_err(|_| "Некорректный Backend URL")?;
    let is_loopback = match url.host_str() {
        Some("localhost") => true,
        Some(host) => host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false),
        None => false,
    };
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) { return Err("Для official identity требуется HTTPS Backend (HTTP только localhost)".into()); }
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() || url.query().is_some() || url.path() != "/" {
        return Err("Backend URL должен содержать только origin".into());
    }
    let origin = url.origin().ascii_serialization();
    let mut digest = Sha256::new();
    digest.update(b"neverlauncher/official-identity/0262\0");
    digest.update(origin.as_bytes());
    digest.update(b"\0");
    digest.update(session_id.as_bytes());
    Ok((url, hex::encode(digest.finalize())))
}

// Windows Generic Credentials limit the blob size (commonly 2560 bytes).
// Write a new randomly named set of OS-keyring fragments first, then commit a
// small pointer credential last: rotation is crash-safe without plaintext files.
// All fragments are OS-protected, not browser/device localStorage.
const CHUNK_BYTES: usize = 1024;
const MAX_CHUNKS: usize = 64;
#[derive(Serialize, Deserialize)]
struct VaultPointer { version: u32, generation: String, count: usize, digest: String }

fn entry(id: &str) -> Result<keyring::v1::Entry, String> {
    keyring::v1::Entry::new(SERVICE, id).map_err(|_| "OS credential storage недоступно".into())
}
fn fragment_id(id: &str, generation: &str, index: usize) -> String {
    format!("{id}.{generation}.{index}")
}
fn read_pointer(id: &str) -> Result<Option<VaultPointer>, String> {
    let mut raw = match entry(id)?.get_password() {
        Ok(value) => value,
        Err(keyring::v1::Error::NoEntry) => return Ok(None),
        Err(_) => return Err("Чтение OS credential storage невозможно".into()),
    };
    let pointer = serde_json::from_str::<VaultPointer>(&raw)
        .map_err(|_| "Сохранённый указатель игрового аккаунта повреждён".to_string());
    raw.zeroize();
    let pointer = pointer?;
    if pointer.version != 1 || pointer.count == 0 || pointer.count > MAX_CHUNKS || pointer.generation.len() != 24
        || !pointer.generation.bytes().all(|b| b.is_ascii_hexdigit()) || pointer.digest.len() != 64
        || !pointer.digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Некорректный указатель игрового vault".into());
    }
    Ok(Some(pointer))
}
fn remove_fragment(id: &str, generation: &str, index: usize) -> Result<(), String> {
    match entry(&fragment_id(id, generation, index))?.delete_credential() {
        Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(_) => Err("Не удалось удалить защищённый фрагмент".into()),
    }
}
fn remove_fragments(id: &str, pointer: &VaultPointer) -> Result<(), String> {
    let mut failed = false;
    for index in 0..pointer.count {
        if remove_fragment(id, &pointer.generation, index).is_err() { failed = true; }
    }
    if failed { Err("Очистка защищённого хранилища не завершена".into()) } else { Ok(()) }
}
fn read(id: &str) -> Result<Option<StoredAccount>, String> {
    let Some(pointer) = read_pointer(id)? else { return Ok(None) };
    let mut raw = Vec::new();
    for index in 0..pointer.count {
        let mut part = entry(&fragment_id(id, &pointer.generation, index))?
            .get_password().map_err(|_| "Защищённая запись игрового аккаунта неполная".to_string())?;
        let decoded = base64::engine::general_purpose::STANDARD.decode(&part)
            .map_err(|_| "Некорректный фрагмент игрового аккаунта".to_string());
        part.zeroize();
        let mut decoded = decoded?;
        if decoded.is_empty() || decoded.len() > CHUNK_BYTES || raw.len().saturating_add(decoded.len()) > CHUNK_BYTES * MAX_CHUNKS {
            decoded.zeroize(); raw.zeroize();
            return Err("Слишком большая защищённая запись".into());
        }
        raw.extend_from_slice(&decoded);
        decoded.zeroize();
    }
    if hex::encode(Sha256::digest(&raw)) != pointer.digest {
        raw.zeroize();
        return Err("Целостность OS credential storage нарушена".into());
    }
    let record = serde_json::from_slice::<StoredAccount>(&raw)
        .map_err(|_| "Сохранённый игровой аккаунт повреждён".to_string());
    raw.zeroize();
    let record = record?;
    if record.schema != 1 || !uuid_valid(&record.profile.id) || record.ticket.is_empty() {
        return Err("Некорректная запись игрового аккаунта".into());
    }
    Ok(Some(record))
}
fn save(id: &str, record: &StoredAccount) -> Result<(), String> {
    let prior = read_pointer(id)?;
    let mut bytes = serde_json::to_vec(record).map_err(|_| "Не удалось сериализовать vault".to_string())?;
    let count = bytes.len().div_ceil(CHUNK_BYTES);
    if count == 0 || count > MAX_CHUNKS { bytes.zeroize(); return Err("Игровой аккаунт превышает допустимый размер OS vault".into()); }
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let generation = hex::encode(nonce);
    let pointer = VaultPointer {version: 1, generation, count, digest: hex::encode(Sha256::digest(&bytes))};
    let mut written = 0;
    let mut write_error: Option<String> = None;
    for (index, part) in bytes.chunks(CHUNK_BYTES).enumerate() {
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(part);
        let result = entry(&fragment_id(id, &pointer.generation, index))
            .and_then(|slot| slot.set_password(&encoded).map_err(|_| "Не удалось записать сегмент OS vault".to_string()));
        encoded.zeroize();
        if let Err(err) = result { write_error = Some(err); break; }
        written += 1;
    }
    bytes.zeroize();
    if let Some(err) = write_error {
        for index in 0..written { let _ = remove_fragment(id, &pointer.generation, index); }
        return Err(err);
    }
    let mut header = serde_json::to_string(&pointer).map_err(|_| "Невозможно создать указатель OS vault".to_string())?;
    let result = entry(id).and_then(|slot| slot.set_password(&header).map_err(|_| "Не удалось зафиксировать OS vault".to_string()));
    header.zeroize();
    if let Err(err) = result {
        let _ = remove_fragments(id, &pointer);
        return Err(err);
    }
    // Committed generation is already readable. Clean the old generation only
    // after the pointer switches. Failure to clean must not roll back the login.
    if let Some(prior) = prior { let _ = remove_fragments(id, &prior); }
    Ok(())
}
fn delete(id: &str) -> Result<(), String> {
    let prior = read_pointer(id)?;
    // Invalidate the account pointer first, including on partial cleanup.
    match entry(id)?.delete_credential() {
        Ok(()) | Err(keyring::v1::Error::NoEntry) => {},
        Err(_) => return Err("Не удалось отвязать игровой аккаунт в OS vault".into()),
    }
    if let Some(pointer) = prior { remove_fragments(id, &pointer) } else { Ok(()) }
}

struct Response { status: u16, data: Value, rotation: Option<String> }
impl Drop for Response { fn drop(&mut self) { if let Some(token) = &mut self.rotation { token.zeroize(); } } }

impl IdentityManager {
    pub fn new() -> Result<Self, String> {
        let client = Client::builder().timeout(Duration::from_secs(45))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("NeverLauncher/", env!("CARGO_PKG_VERSION")))
            .build().map_err(|_| "Не удалось инициализировать защищённый HTTP-клиент".to_string())?;
        Ok(Self { client, pending: Mutex::new(HashMap::new()), vault_lock: tokio::sync::Mutex::new(()) })
    }
    async fn request(&self, base: &Url, access: &str, route: &str, method: Method, ticket: Option<&str>, body: Option<Value>, skin: Option<(Vec<u8>, String)>) -> Result<Response, String> {
        if access.len() < 16 || access.len() > 8192 { return Err("Необходимо войти в NeverLauncher".into()); }
        let url = base.join(&format!("{PREFIX}{route}")).map_err(|_| "Некорректный official API URL".to_string())?;
        let mut req = self.client.request(method, url).bearer_auth(access);
        if let Some(ticket) = ticket { req = req.header("X-Official-Minecraft-Session", ticket); }
        if let Some(body) = body { req = req.json(&body); }
        if let Some((bytes, variant)) = skin {
            if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 || !["classic", "slim"].contains(&variant.as_str()) || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                return Err("Неверный PNG или модель скина".into());
            }
            let part = reqwest::multipart::Part::bytes(bytes).file_name("skin.png").mime_str("image/png").map_err(|_| "Некорректный PNG".to_string())?;
            req = req.multipart(reqwest::multipart::Form::new().text("variant", variant).part("file", part));
        }
        let mut response = req.send().await.map_err(|_| "Сервис официальной авторизации недоступен".to_string())?;
        let status = response.status().as_u16();
        let rotation = response.headers().get("X-Official-Minecraft-Session").and_then(|v| v.to_str().ok()).map(str::to_owned);
        if response.content_length().is_some_and(|n| n > RESPONSE_LIMIT as u64) {
            return Err("Official API вернул слишком большой ответ".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "Ошибка чтения official API".to_string())? {
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_LIMIT { return Err("Official API вернул слишком большой ответ".into()); }
            bytes.extend_from_slice(&chunk);
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| "Official API вернул невалидный JSON".to_string())?;
        // Discard any HTTP body containing secret tickets as soon as it is decoded.
        bytes.zeroize();
        if !(200..300).contains(&status) { return Err(match status {
            401 => "Сессия Never/Minecraft недействительна; войдите повторно".into(),
            403 => "Доступ Minecraft запрещён провайдером или настройками аккаунта".into(),
            429 => "Слишком много запросов; повторите позднее".into(),
            502..=599 => "Сервис Microsoft/Minecraft временно недоступен".into(),
            _ => format!("Официальная авторизация: HTTP {status}"),
        }); }
        let data = payload.get("data").cloned().unwrap_or(payload);
        Ok(Response { status, data, rotation })
    }
    fn profile(data: &Value) -> Result<OfficialProfile, String> {
        let value = data.get("profile").unwrap_or(data);
        let profile: OfficialProfile = serde_json::from_value(value.clone()).map_err(|_| "Неверный официальный профиль".to_string())?;
        if !uuid_valid(&profile.id) || profile.name.is_empty() || profile.name.len() > 16 || !profile.name.is_ascii() { return Err("Minecraft Services вернул неверный профиль".into()); }
        Ok(profile)
    }
    fn pending_remove(&self, id: &str) -> Result<Option<PendingFlow>, String> {
        Ok(self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?.remove(id))
    }
    fn pending_insert(&self, id: String, pending: PendingFlow) -> Result<(), String> {
        self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?.insert(id, pending);
        Ok(())
    }
    pub async fn begin(&self, backend: &str, access: &str, session: &str) -> Result<DeviceChallenge, String> {
        let (base, id) = scope(backend, session)?;
        self.pending_remove(&id)?;
        let result = self.request(&base, access, "/device/start", Method::POST, None, None, None).await?;
        let ticket = result.data.get("flow").and_then(Value::as_str).filter(|v| !v.is_empty() && v.len() < 8192).ok_or("Microsoft не вернул flow")?.to_owned();
        let uri = result.data.get("verificationUri").and_then(Value::as_str).ok_or("Microsoft не вернул verificationUri")?;
        let url = Url::parse(uri).map_err(|_| "Некорректная ссылка Microsoft")?;
        if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() { return Err("Небезопасная ссылка авторизации".into()); }
        let code = result.data.get("userCode").and_then(Value::as_str).ok_or("Microsoft не вернул код")?;
        let interval = result.data.get("intervalSeconds").and_then(Value::as_u64).unwrap_or(5).max(5);
        let expiry = result.data.get("expiresIn").and_then(Value::as_u64).unwrap_or(900);
        if !(1..=1800).contains(&expiry) || interval > 120 || code.is_empty() || code.len() > 64 { return Err("Некорректный Device Code challenge".into()); }
        self.pending_insert(id, PendingFlow { ticket, next: Instant::now() + Duration::from_secs(interval), expires: Instant::now() + Duration::from_secs(expiry) })?;
        Ok(DeviceChallenge { verification_uri: uri.into(), user_code: code.into(), interval_seconds: interval, expires_in: expiry })
    }
    pub async fn poll(&self, backend: &str, access: &str, session: &str) -> Result<PollResult, String> {
        let (base, id) = scope(backend, session)?;
        let pending = self.pending_remove(&id)?.ok_or("Нет незавершённой Microsoft-авторизации")?;
        if Instant::now() >= pending.expires { return Err("Microsoft Device Code истёк".into()); }
        if Instant::now() < pending.next { self.pending_insert(id, pending)?; return Err("Device Code: соблюдайте интервал опроса".into()); }
        let response = self.request(&base, access, "/device/poll", Method::POST, Some(&pending.ticket), None, None).await;
        let result = match response {
            Ok(result) => result,
            Err(err) => {
                // A timeout or 429 must not trigger immediate repeated polling.
                let mut pending = pending;
                pending.next = Instant::now() + Duration::from_secs(10);
                self.pending_insert(id, pending)?;
                return Err(err);
            }
        };
        if result.status == 202 {
            let ticket = result.data.get("flow").and_then(Value::as_str).filter(|v| !v.is_empty() && v.len() < 8192).ok_or("Нет продолжения Device Code")?.to_owned();
            let interval = result.data.get("intervalSeconds").and_then(Value::as_u64).unwrap_or(5).clamp(5, 120);
            self.pending_insert(id, PendingFlow { ticket, next: Instant::now() + Duration::from_secs(interval), expires: pending.expires })?;
            return Ok(PollResult { pending: true, profile: None, interval_seconds: Some(interval) });
        }
        let profile = Self::profile(&result.data)?;
        let ticket = result.data.get("session").and_then(Value::as_str).filter(|v| !v.is_empty() && v.len() < 8192).ok_or("Official API не выдал защищённую игровую сессию")?.to_owned();
        save(&id, &StoredAccount { schema: 1, ticket, profile: profile.clone() })?;
        Ok(PollResult { pending: false, profile: Some(profile), interval_seconds: None })
    }
    async fn associated(&self, base: &Url, id: &str, access: &str, path: &str, method: Method, body: Option<Value>, skin: Option<(Vec<u8>, String)>) -> Result<(Response, StoredAccount), String> {
        let _guard = self.vault_lock.lock().await;
        let mut record = read(id)?.ok_or("Официальный Minecraft-аккаунт не подключён")?;
        let result = self.request(base, access, path, method, Some(&record.ticket), body, skin).await?;
        let mut changed = false;
        if let Some(ticket) = &result.rotation {
            if ticket.is_empty() || ticket.len() > 8192 { return Err("Некорректная ротация official session".into()); }
            record.ticket.zeroize();
            record.ticket = ticket.clone();
            changed = true;
        }
        if result.data.get("profile").is_some() {
            let profile = Self::profile(&result.data)?;
            if !record.profile.id.eq_ignore_ascii_case(&profile.id) {
                return Err("Minecraft identity mismatch".into());
            }
            record.profile = profile;
            changed = true;
        }
        if changed { save(id, &record)?; }
        Ok((result, record))
    }
    pub async fn status(&self, backend: &str, access: &str, session: &str) -> Result<Option<OfficialProfile>, String> {
        let (base, id) = scope(backend, session)?;
        if read(&id)?.is_none() { return Ok(None); }
        let (response, record) = self.associated(&base, &id, access, "/profile", Method::GET, None, None).await?;
        let profile = Self::profile(&response.data)?;
        if !record.profile.id.eq_ignore_ascii_case(&profile.id) { return Err("Смена официальной Minecraft identity запрещена".into()); }
        Ok(Some(profile))
    }
    pub async fn modify(&self, backend: &str, access: &str, session: &str, operation: &str, cape_id: Option<&str>, skin: Option<(Vec<u8>, String)>) -> Result<OfficialProfile, String> {
        let (base, id) = scope(backend, session)?;
        let (path, method, body) = match operation {
            "resetSkin" => ("/skin", Method::DELETE, None),
            "resetCape" => ("/cape", Method::DELETE, None),
            "selectCape" => {
                let cape_id = cape_id.filter(|v| !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).ok_or("Недопустимый ID плаща")?;
                ("/cape", Method::PUT, Some(json!({"capeId":cape_id})))
            },
            "uploadSkin" if skin.is_some() => ("/skin", Method::POST, None),
            _ => return Err("Недопустимая операция Minecraft texture".into()),
        };
        let (response, record) = self.associated(&base, &id, access, path, method, body, skin).await?;
        let profile = Self::profile(&response.data)?;
        if !record.profile.id.eq_ignore_ascii_case(&profile.id) { return Err("Minecraft identity mismatch".into()); }
        Ok(profile)
    }
    pub async fn launch_credentials(&self, backend: &str, access: &str, session: &str) -> Result<MinecraftLaunchCredentials, String> {
        let (base, id) = scope(backend, session)?;
        let (response, record) = self.associated(&base, &id, access, "/launch-credentials", Method::POST, None, None).await?;
        if response.data.get("realm").and_then(Value::as_str) != Some("official-minecraft") { return Err("Backend вернул неофициальную игровую сессию".into()); }
        let cred: MinecraftLaunchCredentials = serde_json::from_value(response.data.clone()).map_err(|_| "Некорректный ответ Minecraft launch credentials".to_string())?;
        if cred.user_type != "msa" || !cred.auth_server_base_url.is_empty() || !uuid_valid(&cred.uuid)
            || !cred.uuid.eq_ignore_ascii_case(&record.profile.id) || cred.username != record.profile.name
            || cred.access_token.is_empty() || cred.access_token.len() > 8192 {
            return Err("Backend не подтвердил official Minecraft identity".into());
        }
        Ok(cred)
    }
    pub fn cancel(&self, backend: &str, session: &str) -> Result<(), String> {
        let (_, id) = scope(backend, session)?;
        self.pending_remove(&id)?;
        Ok(())
    }
    pub async fn disconnect(&self, backend: &str, session: &str) -> Result<(), String> {
        let (_, id) = scope(backend, session)?;
        self.pending_remove(&id)?;
        let _guard = self.vault_lock.lock().await;
        delete(&id)
    }
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Context { backend_url: String, never_token: String, never_session_id: String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
pub struct LaunchContext { pub backend_url: String, pub never_token: String, pub never_session_id: String }

#[tauri::command]
pub async fn official_identity_begin_0262(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<DeviceChallenge, String> {
    manager.begin(&context.backend_url, &context.never_token, &context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_poll_0262(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<PollResult, String> {
    manager.poll(&context.backend_url, &context.never_token, &context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_status_0262(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<Option<OfficialProfile>, String> {
    manager.status(&context.backend_url, &context.never_token, &context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_texture_0262(manager: tauri::State<'_, IdentityManager>, context: Context, operation: String, cape_id: Option<String>, skin_bytes: Option<Vec<u8>>, variant: Option<String>) -> Result<OfficialProfile, String> {
    let skin = skin_bytes.map(|v| (v, variant.unwrap_or_default()));
    manager.modify(&context.backend_url, &context.never_token, &context.never_session_id, &operation, cape_id.as_deref(), skin).await
}
#[tauri::command]
pub fn official_identity_cancel_0262(manager: tauri::State<'_, IdentityManager>, backend_url: String, never_session_id: String) -> Result<(), String> {
    manager.cancel(&backend_url, &never_session_id)
}
#[tauri::command]
pub async fn official_identity_disconnect_0262(manager: tauri::State<'_, IdentityManager>, backend_url: String, never_session_id: String) -> Result<(), String> {
    manager.disconnect(&backend_url, &never_session_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_insecure_or_cross_origin_scopes() {
        assert!(scope("http://example.com", "session-1").is_err());
        assert!(scope("https://example.com/path", "session-1").is_err());
        assert!(scope("https://other:pass@example.com", "session-1").is_err());
        assert!(scope("https://example.com?redirect=http://evil.test", "session-1").is_err());
        assert!(scope("http://127.0.0.1:8080", "session-1").is_ok());
        assert!(scope("https://example.com", "").is_err());
    }
    #[test] fn credentials_scoped_to_backend_and_session() {
        let (_, a) = scope("https://example.com", "session-1").unwrap();
        let (_, b) = scope("https://example.com", "session-2").unwrap();
        let (_, c) = scope("https://other.example", "session-1").unwrap();
        assert_ne!(a, b); assert_ne!(a, c);
    }
    #[test] fn minecraft_identity_requires_java_uuid() {
        assert!(uuid_valid("123456781234123412341234567890ab"));
        assert!(!uuid_valid("e-mail@example.com"));
        assert!(!uuid_valid("12345678-1234-1234-1234-1234567890ab"));
    }
}
