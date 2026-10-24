//! 0.26.2: Native boundary for the existing official Minecraft backend flow.
//! The renderer never receives Microsoft/Minecraft credentials or the opaque
//! encrypted backend ticket (which itself contains refresh/game tokens).
use std::{collections::HashMap, net::IpAddr, sync::Mutex, time::{Duration, Instant}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use reqwest::{Client, Method, Url};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
use rand::RngCore;
use base64::Engine as _;
use neverruntime::MinecraftLaunchCredentials;
use tokio::sync::watch;
use crate::{official_browser_0263, official_exchange_0265::{NativeProvider, MicrosoftGrant, ProviderError, now}};

const SERVICE: &str = "NeverLauncher Official Minecraft 0.26.2"; // preserve existing vault slots
const PREFIX: &str = "/api/v1/minecraft/official";
const RESPONSE_LIMIT: usize = 256 * 1024;
const MAX_ACCOUNTS: usize = 16;

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
struct StoredAccount {
    schema: u32,
    #[serde(default)] ticket: String, // 0.26.4 backend ticket; retained for migration
    profile: OfficialProfile,
    #[serde(default, skip_serializing_if="Option::is_none")] native: Option<NativeAccount0265>,
}
#[derive(Serialize, Deserialize)]
struct NativeAccount0265 {
    client_id: String,
    refresh_token: String,
    minecraft_token: String,
    minecraft_expires_at: u64,
}
impl Drop for NativeAccount0265 {
    fn drop(&mut self) { self.refresh_token.zeroize(); self.minecraft_token.zeroize(); }
}
impl Drop for StoredAccount { fn drop(&mut self) { self.ticket.zeroize(); } }


struct BrowserFlow0263 { state: String, cancel: watch::Sender<bool> }

struct NativePending0265 {
    client_id: String,
    device: Zeroizing<String>,
    grant: Option<MicrosoftGrant>,
    next: Instant,
    expires: Instant,
    nonce: u64,
    in_flight: bool,
    failures: u32,
    interval: u64,
    cancel: watch::Sender<bool>,
}
struct PendingFlow {
    ticket: String,
    next: Instant,
    expires: Instant,
    nonce: u64,
    in_flight: bool,
    failures: u32,
    interval: u64,
    cancel: watch::Sender<bool>,
}
impl Drop for PendingFlow { fn drop(&mut self) { self.ticket.zeroize(); } }

fn retry_delay(base: u64, failures: u32, server_hint: Option<u64>) -> u64 {
    // Exponential backoff, preserving Microsoft's original/slow_down interval.
    base.max(5).max(5u64.saturating_mul(1u64 << failures.min(5)))
        .max(server_hint.unwrap_or(0)).clamp(5, 3600)
}

// Closing a watch channel after SUCCESS must not be mistaken for user cancel.
// Only an explicit true signal ends an in-flight login.
async fn await_device_cancel(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() { return; }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

pub struct IdentityManager {
    browser: Mutex<HashMap<String, BrowserFlow0263>>,
    client: Client,
    provider: NativeProvider,
    native_pending: Mutex<HashMap<String, NativePending0265>>,
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
    if !uuid_valid(&record.profile.id) || !((record.schema == 1 && !record.ticket.is_empty() && record.native.is_none()) ||
        (record.schema == 2 && record.ticket.is_empty() && record.native.as_ref().is_some_and(|n|
            official_browser_0263::valid_client_id(&n.client_id) &&
            crate::official_exchange_0265::valid_token(&n.refresh_token) &&
            crate::official_exchange_0265::valid_token(&n.minecraft_token) && n.minecraft_expires_at > 0))) {
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

// 0.26.7: account directory is metadata only. Each account's Microsoft refresh
// and Minecraft bearer remain in an independent, chunked OS credential record.
// The original 0.26.2 slot is only read while migrating to this directory.
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AccountDirectory0267 {
    version: u32,
    active: Option<String>,
    ids: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfficialAccount0267 {
    pub id: String,
    pub name: String,
    pub active: bool,
}
fn normalized_uuid(uuid: &str) -> Result<String, String> {
    if !uuid_valid(uuid) { return Err("Некорректный Minecraft UUID".into()); }
    Ok(uuid.to_ascii_lowercase())
}
fn account_slot(id: &str, uuid: &str) -> Result<String, String> {
    Ok(format!("{id}.account.{}", normalized_uuid(uuid)?))
}
fn directory_slot(id: &str) -> String { format!("{id}.directory.0267") }
fn validate_directory(dir: &AccountDirectory0267) -> Result<(), String> {
    if dir.version != 1 || dir.ids.len() > MAX_ACCOUNTS ||
        dir.ids.iter().any(|id| normalized_uuid(id).map_or(true, |v| v != *id)) ||
        dir.ids.iter().enumerate().any(|(i, id)| dir.ids[..i].contains(id)) ||
        dir.active.as_ref().is_some_and(|id| !dir.ids.contains(id)) ||
        (dir.ids.is_empty() && dir.active.is_some()) ||
        (!dir.ids.is_empty() && dir.active.is_none()) {
        return Err("Реестр официальных Minecraft-аккаунтов повреждён".into());
    }
    Ok(())
}
fn load_directory(id: &str) -> Result<AccountDirectory0267, String> {
    let mut raw = match entry(&directory_slot(id))?.get_password() {
        Ok(raw) => raw,
        Err(keyring::v1::Error::NoEntry) => return Ok(AccountDirectory0267 {version: 1, ..Default::default()}),
        Err(_) => return Err("Невозможно прочитать реестр Minecraft-аккаунтов".into()),
    };
    let result = serde_json::from_str::<AccountDirectory0267>(&raw)
        .map_err(|_| "Некорректный реестр Minecraft-аккаунтов".to_string());
    raw.zeroize();
    let dir = result?;
    validate_directory(&dir)?;
    Ok(dir)
}
fn save_directory(id: &str, dir: &AccountDirectory0267) -> Result<(), String> {
    validate_directory(dir)?;
    let mut raw = serde_json::to_string(dir).map_err(|_| "Невозможно записать реестр аккаунтов".to_string())?;
    // Windows Credential Manager stores a small directory (< 2560 bytes).
    if raw.len() > 2000 {raw.zeroize();return Err("Превышен размер реестра аккаунтов".into());}
    let result = entry(&directory_slot(id))?.set_password(&raw)
        .map_err(|_| "Не удалось сохранить реестр аккаунтов в OS vault".to_string());
    raw.zeroize();
    result
}
// Must be called while holding vault_lock. A failure leaves the old slot intact.
fn migrate_legacy(id: &str) -> Result<(), String> {
    let Some(legacy) = read(id)? else { return Ok(()); };
    let uuid = normalized_uuid(&legacy.profile.id)?;
    let mut dir = load_directory(id)?;
    let slot = account_slot(id, &uuid)?;
    if !dir.ids.contains(&uuid) {
        if dir.ids.len() >= MAX_ACCOUNTS { return Err("Превышен лимит Minecraft-аккаунтов".into()); }
        save(&slot, &legacy)?;
        dir.ids.push(uuid.clone());
        if dir.active.is_none() { dir.active = Some(uuid); }
        save_directory(id, &dir)?;
    }
    // Deleting the original only after new record and index are durably written.
    // Retrying after interruption is safe: the indexed account wins.
    delete(id)
}
fn selected_record(id: &str) -> Result<Option<(String, StoredAccount)>, String> {
    let dir = load_directory(id)?;
    let Some(uuid) = dir.active else { return Ok(None) };
    let slot = account_slot(id, &uuid)?;
    let record = read(&slot)?.ok_or("Выбранный Minecraft-аккаунт отсутствует в OS vault")?;
    if normalized_uuid(&record.profile.id)? != uuid {return Err("Minecraft identity mismatch в OS vault".into());}
    Ok(Some((slot, record)))
}
fn add_account(id: &str, record: &StoredAccount) -> Result<(), String> {
    let uuid = normalized_uuid(&record.profile.id)?;
    let mut dir = load_directory(id)?;
    if !dir.ids.contains(&uuid) && dir.ids.len() >= MAX_ACCOUNTS {return Err("Превышен лимит Minecraft-аккаунтов".into());}
    let slot = account_slot(id, &uuid)?;
    // Save verified tokens first; if committing metadata fails, old active
    // selection remains usable. The orphaned new slot contains no plaintext.
    save(&slot, record)?;
    if !dir.ids.contains(&uuid) {dir.ids.push(uuid.clone());}
    dir.active = Some(uuid);
    save_directory(id, &dir)
}
fn remove_account(id: &str, uuid: &str) -> Result<(), String> {
    let uuid = normalized_uuid(uuid)?;
    let mut dir = load_directory(id)?;
    if !dir.ids.contains(&uuid) { return Err("Minecraft-аккаунт не найден".into()); }
    // Invalidate selection before deleting credentials. No removed account
    // can be launched even if OS keyring cleanup subsequently fails.
    dir.ids.retain(|value| value != &uuid);
    if dir.active.as_deref() == Some(&uuid) {dir.active = dir.ids.first().cloned();}
    save_directory(id, &dir)?;
    delete(&account_slot(id, &uuid)?)
}
struct Response { status: u16, data: Value, rotation: Option<String>, retry_after: Option<u64> }
impl Drop for Response {
    fn drop(&mut self) {
        if let Some(token) = &mut self.rotation { token.zeroize(); }
        for name in ["flow", "session"] {
            if let Some(Value::String(value)) = self.data.get_mut(name) { value.zeroize(); }
        }
    }
}

impl IdentityManager {
    pub fn new() -> Result<Self, String> {
        let client = Client::builder().timeout(Duration::from_secs(80))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("NeverLauncher/", env!("CARGO_PKG_VERSION")))
            .build().map_err(|_| "Не удалось инициализировать защищённый HTTP-клиент".to_string())?;
        Ok(Self { client, provider: NativeProvider::new()?, native_pending: Mutex::new(HashMap::new()), pending: Mutex::new(HashMap::new()), browser: Mutex::new(HashMap::new()), vault_lock: tokio::sync::Mutex::new(()) })
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
        let retry_after = response.headers().get("Retry-After").and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok()).map(|v| v.clamp(5, 3600));
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
        if !(200..300).contains(&status) {
            // The Device Code waiter owns retries. Do not turn provider backoff
            // or temporary HTTP failures into terminal sign-out errors.
            if route == "/device/poll" && (status == 408 || status == 429 || (500..600).contains(&status)) {
                return Ok(Response { status, data: Value::Null, rotation: None, retry_after });
            }
            return Err(match status {
            401 => "Сессия Never/Minecraft недействительна; войдите повторно".into(),
            403 => "Доступ Minecraft запрещён провайдером или настройками аккаунта".into(),
            409 if route == "/link" => "Minecraft UUID уже связан с другой учётной записью Never".into(),
            429 => "Слишком много запросов; повторите позднее".into(),
            502..=599 => "Сервис Microsoft/Minecraft временно недоступен".into(),
            _ => format!("Официальная авторизация: HTTP {status}"),
        }); }
        let data = payload.get("data").cloned().unwrap_or(payload);
        Ok(Response { status, data, rotation, retry_after })
    }
    fn profile(data: &Value) -> Result<OfficialProfile, String> {
        let value = data.get("profile").unwrap_or(data);
        let profile: OfficialProfile = serde_json::from_value(value.clone()).map_err(|_| "Неверный официальный профиль".to_string())?;
        if !uuid_valid(&profile.id) || profile.name.is_empty() || profile.name.len() > 16 || !profile.name.is_ascii() { return Err("Minecraft Services вернул неверный профиль".into()); }
        Ok(profile)
    }
    fn pending_remove(&self, id: &str) -> Result<(), String> {
        let previous = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?.remove(id);
        if let Some(flow) = previous { let _ = flow.cancel.send(true); }
        Ok(())
    }
    // On every asynchronous boundary match the flow nonce. Cancellation or a
    // replacement login must not resurrect an older Device Code or save its account.
    pub async fn begin(&self, backend: &str, access: &str, session: &str) -> Result<DeviceChallenge, String> {
        let (base, id) = scope(backend, session)?;
        self.pending_remove(&id)?;
        self.cancel_browser(&id)?;
        let nonce = rand::random::<u64>();
        let (cancel, _) = watch::channel(false);
        self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?.insert(id.clone(), PendingFlow {
            ticket: String::new(), next: Instant::now(), expires: Instant::now() + Duration::from_secs(1800),
            nonce, in_flight: false, failures: 0, interval: 5, cancel,
        });
        let result = self.request(&base, access, "/device/start", Method::POST, None, None, None).await;
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                let mut flows = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?;
                if flows.get(&id).is_some_and(|f| f.nonce == nonce) { flows.remove(&id); }
                return Err(err);
            }
        };
        let validated = (|| -> Result<(String, DeviceChallenge), String> {
            let ticket = result.data.get("flow").and_then(Value::as_str).filter(|v| !v.is_empty() && v.len() < 8192).ok_or("Microsoft не вернул flow")?.to_owned();
            let uri = result.data.get("verificationUri").and_then(Value::as_str).ok_or("Microsoft не вернул verificationUri")?;
            let url = Url::parse(uri).map_err(|_| "Некорректная ссылка Microsoft")?;
            let trusted = matches!(url.host_str(), Some("microsoft.com" | "microsoftonline.com"))
                || url.host_str().is_some_and(|h| h.ends_with(".microsoft.com") || h.ends_with(".microsoftonline.com"));
            if url.scheme() != "https" || !trusted || !url.username().is_empty() || url.password().is_some() { return Err("Небезопасная ссылка авторизации".into()); }
            let code = result.data.get("userCode").and_then(Value::as_str).ok_or("Microsoft не вернул код")?;
            let interval = result.data.get("intervalSeconds").and_then(Value::as_u64).unwrap_or(5).max(5);
            let expiry = result.data.get("expiresIn").and_then(Value::as_u64).unwrap_or(900);
            if !(1..=1800).contains(&expiry) || interval > 1800 || code.is_empty() || code.len() > 64 { return Err("Некорректный Device Code challenge".into()); }
            Ok((ticket, DeviceChallenge { verification_uri: uri.into(), user_code: code.into(), interval_seconds: interval, expires_in: expiry }))
        })();
        let mut flows = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?;
        if !flows.get(&id).is_some_and(|f| f.nonce == nonce) { return Err("Microsoft-авторизация отменена".into()); }
        match validated {
            Ok((ticket, challenge)) => {
                let flow = flows.get_mut(&id).ok_or("Microsoft-авторизация отменена")?;
                flow.ticket = ticket;
                flow.interval = challenge.interval_seconds;
                flow.next = Instant::now() + Duration::from_secs(challenge.interval_seconds);
                flow.expires = Instant::now() + Duration::from_secs(challenge.expires_in);
                Ok(challenge)
            }
            Err(err) => { flows.remove(&id); Err(err) }
        }
    }
    pub async fn poll(&self, backend: &str, access: &str, session: &str) -> Result<PollResult, String> {
        let (base, id) = scope(backend, session)?;
        let (mut ticket, nonce) = {
            let mut flows = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?;
            let flow = flows.get_mut(&id).ok_or("Нет незавершённой Microsoft-авторизации")?;
            if Instant::now() >= flow.expires { flows.remove(&id); return Err("Microsoft Device Code истёк".into()); }
            if flow.ticket.is_empty() { return Err("Получение Device Code ещё не завершено".into()); }
            if flow.in_flight { return Err("Проверка Microsoft-авторизации уже выполняется".into()); }
            if Instant::now() < flow.next {
                return Ok(PollResult { pending: true, profile: None,
                    interval_seconds: Some(flow.next.saturating_duration_since(Instant::now()).as_secs().max(1)) });
            }
            flow.in_flight = true;
            (Zeroizing::new(flow.ticket.clone()), flow.nonce)
        };
        let response = self.request(&base, access, "/device/poll", Method::POST, Some(ticket.as_str()), None, None).await;
        ticket.zeroize();
        // Acquire the async lock before the std mutex: Tauri command futures must
        // remain Send, and no flow mutex may be held across an await.
        let _vault = self.vault_lock.lock().await;
        let mut flows = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?;
        if !flows.get(&id).is_some_and(|f| f.nonce == nonce) { return Err("Microsoft-авторизация отменена".into()); }
        let flow = flows.get_mut(&id).ok_or("Microsoft-авторизация отменена")?;
        flow.in_flight = false;
        if Instant::now() >= flow.expires { flows.remove(&id); return Err("Microsoft Device Code истёк".into()); }
        let result = match response {
            Ok(result) => result,
            Err(err) => {
                // Network and malformed upstream responses are recoverable; a
                // revoked Never session, denial, and expired OAuth grant are not.
                let transient = err.contains("недоступен") || err.contains("Ошибка чтения") || err.contains("невалидный JSON");
                if !transient { flows.remove(&id); return Err(err); }
                flow.failures = flow.failures.saturating_add(1);
                let interval = retry_delay(flow.interval, flow.failures, None);
                flow.next = Instant::now() + Duration::from_secs(interval);
                return Ok(PollResult { pending: true, profile: None, interval_seconds: Some(interval) });
            }
        };
        if result.status == 202 {
            let continuation = result.data.get("flow").and_then(Value::as_str)
                .filter(|v| !v.is_empty() && v.len() < 8192).ok_or("Нет продолжения Device Code")?.to_owned();
            let interval = result.data.get("intervalSeconds").and_then(Value::as_u64).unwrap_or(5).clamp(5, 3600);
            flow.ticket.zeroize();
            flow.ticket = continuation;
            flow.interval = interval; // Includes provider slow_down (+5 seconds).
            // After a successful Microsoft grant the Backend may allow a short
            // recovery window to finish Xbox/Minecraft without reusing the code.
            if let Some(expires_in) = result.data.get("expiresIn").and_then(Value::as_u64) {
                if expires_in > 0 && expires_in <= 3600 {
                    flow.expires = Instant::now() + Duration::from_secs(expires_in);
                }
            }
            flow.failures = 0;
            flow.next = Instant::now() + Duration::from_secs(interval);
            return Ok(PollResult { pending: true, profile: None, interval_seconds: Some(interval) });
        }
        if result.status == 408 || result.status == 429 || result.status >= 500 {
            flow.failures = flow.failures.saturating_add(1);
            let interval = retry_delay(flow.interval, flow.failures, result.retry_after);
            flow.next = Instant::now() + Duration::from_secs(interval);
            return Ok(PollResult { pending: true, profile: None, interval_seconds: Some(interval) });
        }
        let profile = Self::profile(&result.data)?;
        let ticket = result.data.get("session").and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.len() < 8192).ok_or("Official API не выдал защищённую игровую сессию")?;
        // Keep the nonce guard held across vault persistence. A cancellation
        // cannot race a successful write and leave a cancelled account linked.
        migrate_legacy(&id)?;
        add_account(&id, &StoredAccount { schema: 1, ticket: ticket.to_owned(), profile: profile.clone(), native: None })?;
        flows.remove(&id);
        Ok(PollResult { pending: false, profile: Some(profile), interval_seconds: None })
    }
    /// A single native waiter owns pacing, temporary retry backoff and expiry.
    /// No browser timer can leak session tickets or generate tight poll loops.
    pub async fn wait_device(&self, backend: &str, access: &str, session: &str) -> Result<OfficialProfile, String> {
        let (_, id) = scope(backend, session)?;
        let mut cancelled = {
            let flows = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?;
            flows.get(&id).ok_or("Нет незавершённой Microsoft-авторизации")?.cancel.subscribe()
        };
        loop {
            if *cancelled.borrow() { return Err("Microsoft-авторизация отменена".into()); }
            let delay = {
                let mut flows = self.pending.lock().map_err(|_| "Identity Manager заблокирован".to_string())?;
                let flow = flows.get(&id).ok_or("Microsoft-авторизация отменена")?;
                if Instant::now() >= flow.expires { flows.remove(&id); return Err("Microsoft Device Code истёк".into()); }
                flow.next.saturating_duration_since(Instant::now())
                    .min(flow.expires.saturating_duration_since(Instant::now()))
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                _ = await_device_cancel(&mut cancelled) => return Err("Microsoft-авторизация отменена".into()),
            }
            if *cancelled.borrow() { return Err("Microsoft-авторизация отменена".into()); }
            let step = tokio::select! {
                outcome = self.poll(backend, access, session) => outcome?,
                _ = await_device_cancel(&mut cancelled) => return Err("Microsoft-авторизация отменена".into()),
            };
            match step {
                PollResult { pending: false, profile: Some(profile), .. } => return Ok(profile),
                PollResult { pending: true, .. } => {},
                _ => return Err("Minecraft Services не подтвердил игровой профиль".into()),
            }
        }
    }
    // Caller MUST hold vault_lock through network operation and credential rotation.
    // Account selection must not switch mid-operation (wrong-account texture/launch).
    async fn associated(&self, base: &Url, id: &str, access: &str, path: &str, method: Method, body: Option<Value>, skin: Option<(Vec<u8>, String)>) -> Result<(Response, StoredAccount), String> {
        let (slot, mut record) = selected_record(id)?.ok_or("Официальный Minecraft-аккаунт не подключён")?;
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
        if changed { save(&slot, &record)?; }
        Ok((result, record))
    }
    pub async fn status(&self, backend: &str, access: &str, session: &str) -> Result<Option<OfficialProfile>, String> {
        let (base, id) = scope(backend, session)?;
        let _guard=self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let Some((slot, mut record)) = selected_record(&id)? else {return Ok(None)};
        if record.native.is_some() {
            self.native_validate(&base,&slot,access,&mut record,false).await?;
            return Ok(Some(record.profile.clone()));
        }
        let (response, record) = self.associated(&base, &id, access, "/profile", Method::GET, None, None).await?;
        let profile = Self::profile(&response.data)?;
        if !record.profile.id.eq_ignore_ascii_case(&profile.id) { return Err("Смена официальной Minecraft identity запрещена".into()); }
        Ok(Some(profile))
    }
    pub async fn modify(&self, backend: &str, access: &str, session: &str, operation: &str, cape_id: Option<&str>, skin: Option<(Vec<u8>, String)>) -> Result<OfficialProfile, String> {
        let (base, id) = scope(backend, session)?;
        let _guard=self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let (slot, mut record)=selected_record(&id)?.ok_or("Официальный аккаунт отсутствует")?;
        if record.native.is_some() {
            self.native_validate(&base,&slot,access,&mut record,false).await?;
            let token=&record.native.as_ref().unwrap().minecraft_token;
            let profile=self.provider.texture(token,operation,cape_id,skin).await.map_err(|e|e.message().to_string())?;
            if !profile.id.eq_ignore_ascii_case(&record.profile.id) {return Err("Minecraft official UUID mismatch".into());}
            record.profile=profile.clone();
            save(&slot,&record)?;
            return Ok(profile);
        }
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
        let _guard=self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let (slot, mut record)=selected_record(&id)?.ok_or("Официальный аккаунт отсутствует")?;
        if record.native.is_some() {
            self.native_validate(&base,&slot,access,&mut record,false).await?;
            return Ok(MinecraftLaunchCredentials {username:record.profile.name.clone(),uuid:record.profile.id.clone(),
                access_token:record.native.as_ref().unwrap().minecraft_token.clone(),user_type:"msa".into(),auth_server_base_url:String::new()});
        }
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

    // Xbox/XSTS/Minecraft are acquired in this process and persist only in the native vault.
    async fn verified_native_grant(&self, client_id: &str, grant: &MicrosoftGrant) -> Result<(OfficialProfile, NativeAccount0265),ProviderError> {
        let minecraft = self.provider.exchange(&grant.access_token).await?;
        // A playable Java profile is required even if mcstore is empty (Game Pass).
        // Both requests use the same bearer, in Rust, without renderer IPC.
        let profile = self.provider.verify_java(&minecraft.access_token, None).await?;
        let expires_at = now().saturating_add(minecraft.expires_in.saturating_sub(60));
        Ok((profile,NativeAccount0265 {client_id:client_id.into(),refresh_token:grant.refresh_token.clone(),
            minecraft_token:minecraft.access_token.clone(),minecraft_expires_at:expires_at}))
    }
    async fn native_validate(&self, base: &Url, id: &str, access: &str, record: &mut StoredAccount, force_refresh: bool) -> Result<(), String> {
        // Even with a native credential, the Never session must still be valid.
        let config = self.request(base,access,"/browser/config",Method::GET,None,None,None).await?;
        let native = record.native.as_ref().ok_or("Отсутствует native Minecraft identity")?;
        if config.data.get("clientId").and_then(Value::as_str) != Some(native.client_id.as_str()) {
            return Err("Microsoft Client ID проекта изменён: требуется повторный вход".into());
        }
        if force_refresh || native.minecraft_expires_at <= now().saturating_add(120) {
            let client_id = native.client_id.clone();
            let refresh_token = Zeroizing::new(native.refresh_token.clone());
            let grant = self.provider.refresh(&client_id,&refresh_token).await.map_err(|e|e.message().to_string())?;
            // Persist rotated refresh token immediately. A later Xbox outage
            // must not destroy a successfully rotated Microsoft grant.
            record.native.as_mut().ok_or("Отсутствует Minecraft identity")?.refresh_token.zeroize();
            record.native.as_mut().unwrap().refresh_token = grant.refresh_token.clone();
            save(id,record)?;
            let (profile,updated) = self.verified_native_grant(&client_id,&grant).await.map_err(|e|e.message().to_string())?;
            crate::official_verification_0266::verify_playable_profile(
                &profile, Some(&record.profile.id),
                crate::official_verification_0266::JavaAccessEvidence::ProfileBased,
            ).map_err(|e|e.message().to_string())?;
            record.native = Some(updated);
            record.profile = profile;
            save(id,record)?;
        }
        // Revalidate entitlements and authenticated Java profile on every
        // native status/launch/texture action; never trust cached membership.
        let profile = self.provider.verify_java(&record.native.as_ref().unwrap().minecraft_token,
            Some(&record.profile.id)).await.map_err(|e|e.message().to_string())?;
        record.profile = profile;
        save(id,record)?;
        Ok(())
    }
    fn native_pending_remove(&self, id: &str) -> Result<(),String> {
        let previous = self.native_pending.lock().map_err(|_|"Native identity заблокирован")?.remove(id);
        if let Some(flow) = previous { let _ = flow.cancel.send(true); }
        Ok(())
    }
    pub async fn native_begin(&self, backend: &str, access: &str, session: &str) -> Result<DeviceChallenge,String> {
        let (base,id) = scope(backend,session)?;
        self.pending_remove(&id)?;
        self.native_pending_remove(&id)?;
        self.cancel_browser(&id)?;
        // Reserve the flow BEFORE an async provider request. Cancellation or a
        // replacement is effective even during the initial network round trips.
        let nonce=rand::random::<u64>();
        let (cancel,_) = watch::channel(false);
        self.native_pending.lock().map_err(|_|"Native identity заблокирован")?.insert(id.clone(),NativePending0265 {
            client_id:String::new(),device:Zeroizing::new(String::new()),grant:None,
            next:Instant::now(),expires:Instant::now()+Duration::from_secs(1800),
            nonce,in_flight:true,failures:0,interval:5,cancel,
        });
        let result=async {
            let config = self.request(&base,access,"/browser/config",Method::GET,None,None,None).await?;
            let client_id = config.data.get("clientId").and_then(Value::as_str)
                .filter(|s|official_browser_0263::valid_client_id(s)).ok_or("Microsoft Client ID не настроен")?.to_owned();
            if !self.native_pending.lock().map_err(|_|"Native identity заблокирован")?.get(&id).is_some_and(|f|f.nonce==nonce) {
                return Err("Microsoft-авторизация отменена".into());
            }
            let challenge = self.provider.device_begin(&client_id).await.map_err(|e|e.message().to_string())?;
            let mut flows=self.native_pending.lock().map_err(|_|"Native identity заблокирован")?;
            let flow=flows.get_mut(&id).filter(|v|v.nonce==nonce).ok_or("Microsoft-авторизация отменена")?;
            let interval=challenge.interval;
            let expires_in=challenge.expires_in;
            flow.client_id=client_id;
            flow.device=challenge.secret;
            flow.next=Instant::now()+Duration::from_secs(interval);
            flow.expires=Instant::now()+Duration::from_secs(expires_in);
            flow.interval=interval;
            flow.in_flight=false;
            Ok(DeviceChallenge {verification_uri:challenge.verification_uri,user_code:challenge.code,
                interval_seconds:interval,expires_in})
        }.await;
        if result.is_err() {
            let mut flows=self.native_pending.lock().map_err(|_|"Native identity заблокирован")?;
            if flows.get(&id).is_some_and(|v|v.nonce==nonce) {flows.remove(&id);}
        }
        result
    }
    pub async fn native_poll(&self, backend: &str, access: &str, session: &str) -> Result<PollResult,String> {
        let (base,id) = scope(backend,session)?;
        let (client_id,device,nonce,prior_grant) = {
            let mut flows = self.native_pending.lock().map_err(|_|"Native identity заблокирован")?;
            let flow = flows.get_mut(&id).ok_or("Нет Device Code авторизации")?;
            if Instant::now() >= flow.expires { flows.remove(&id);return Err("Microsoft Device Code истёк".into()); }
            if flow.in_flight {return Err("Microsoft polling или Device Code initialization уже выполняется".into());}
            if Instant::now()<flow.next { return Ok(PollResult{pending:true,profile:None,interval_seconds:Some(flow.next.saturating_duration_since(Instant::now()).as_secs().max(1))}); }
            flow.in_flight=true;
            // Once redeemed, do not reuse a one-time Device Code after Xbox outage.
            (flow.client_id.clone(),flow.device.clone(),flow.nonce,flow.grant.take())
        };
        let mut microsoft = prior_grant;
        let grant_result = if microsoft.is_none() {
            Some(self.provider.device_poll(&client_id,device.as_str()).await)
        } else {None};
        if let Some(Ok(grant))=grant_result.as_ref() {
            // Copy is kept only inside native memory until the flow is committed.
            microsoft=Some(MicrosoftGrant {access_token:grant.access_token.clone(),refresh_token:grant.refresh_token.clone(),
                expires_in:grant.expires_in,token_type:grant.token_type.clone()});
        }
        let completed = if microsoft.is_some() {
            Some(self.verified_native_grant(&client_id,microsoft.as_ref().unwrap()).await)
        } else {None};
        let _vault=self.vault_lock.lock().await;
        let mut flows=self.native_pending.lock().map_err(|_|"Native identity заблокирован")?;
        if !flows.get(&id).is_some_and(|v|v.nonce==nonce) {return Err("Microsoft-авторизация отменена".into());}
        {
            let flow=flows.get_mut(&id).ok_or("Microsoft-авторизация отменена")?;
            flow.in_flight=false;
            if Instant::now()>=flow.expires {flows.remove(&id);return Err("Microsoft Device Code истёк".into());}
        }
        if completed.as_ref().is_some_and(|v|v.is_ok()) {
            // Revalidate Never session before saving native credentials. Do not
            // keep a synchronous mutex locked across an HTTP await.
            drop(flows);
            self.request(&base,access,"/browser/config",Method::GET,None,None,None).await?;
            let mut flows=self.native_pending.lock().map_err(|_|"Native identity заблокирован")?;
            if !flows.get(&id).is_some_and(|v|v.nonce==nonce) {return Err("Microsoft-авторизация отменена".into());}
            let (profile,account)=completed.unwrap().unwrap();
            migrate_legacy(&id)?;
            add_account(&id,&StoredAccount{schema:2,ticket:String::new(),profile:profile.clone(),native:Some(account)})?;
            flows.remove(&id);
            return Ok(PollResult{pending:false,profile:Some(profile),interval_seconds:None});
        }
        let flow=flows.get_mut(&id).ok_or("Microsoft-авторизация отменена")?;
        let mut server_hint=None;
        match completed {
            Some(Err(error)) => {
                if !error.retryable() {flows.remove(&id);return Err(error.message().into());}
                server_hint=error.retry_after();
                flow.failures=flow.failures.saturating_add(1);
            }
            None => match grant_result {
                Some(Err(ProviderError::Pending)) => {flow.failures=0;}
                Some(Err(ProviderError::SlowDown)) => {flow.interval=flow.interval.saturating_add(5).min(3600);flow.failures=0;}
                Some(Err(error)) if error.retryable() => {server_hint=error.retry_after();flow.failures=flow.failures.saturating_add(1);}
                Some(Err(error)) => {flows.remove(&id);return Err(error.message().into());}
                _ => {flows.remove(&id);return Err("Невозможно завершить native Device Code".into());}
            },
            Some(Ok(_)) => unreachable!(),
        }
        flow.grant=microsoft;
        let delay=retry_delay(flow.interval,flow.failures,server_hint);
        flow.next=Instant::now()+Duration::from_secs(delay);
        Ok(PollResult{pending:true,profile:None,interval_seconds:Some(delay)})
    }
    pub async fn native_wait_device(&self, backend:&str,access:&str,session:&str) -> Result<OfficialProfile,String> {
        let (_,id)=scope(backend,session)?;
        let mut cancel=self.native_pending.lock().map_err(|_|"Native identity заблокирован")?
            .get(&id).ok_or("Нет Device Code авторизации")?.cancel.subscribe();
        loop {
            let sleep_for={
                let mut flows=self.native_pending.lock().map_err(|_|"Native identity заблокирован")?;
                let flow=flows.get(&id).ok_or("Microsoft-авторизация отменена")?;
                if Instant::now()>=flow.expires {flows.remove(&id);return Err("Microsoft Device Code истёк".into());}
                flow.next.saturating_duration_since(Instant::now()).min(flow.expires.saturating_duration_since(Instant::now()))
            };
            tokio::select! { _=tokio::time::sleep(sleep_for)=>{}, _=await_device_cancel(&mut cancel)=>return Err("Microsoft-авторизация отменена".into()) }
            let reply=tokio::select! { result=self.native_poll(backend,access,session)=>result?, _=await_device_cancel(&mut cancel)=>return Err("Microsoft-авторизация отменена".into()) };
            if let PollResult{pending:false,profile:Some(profile),..}=reply {return Ok(profile);}
        }
    }
    fn cancel_browser(&self, id: &str) -> Result<(), String> {
        let removed = self.browser.lock().map_err(|_| "Native Identity Manager заблокирован")?.remove(id);
        if let Some(flow) = removed { let _ = flow.cancel.send(true); }
        Ok(())
    }
    fn browser_active(&self, id: &str, state: &str) -> Result<bool,String> {
        Ok(self.browser.lock().map_err(|_| "Native Identity Manager заблокирован")?
            .get(id).is_some_and(|flow| flow.state == state))
    }
    // await the callback and complete provider exchange wholly within Rust.
    // Renderer sees only the finished profile and never code/state/verifier.
    pub async fn login_browser(&self, backend: &str, access: &str, session: &str) -> Result<OfficialProfile,String> {
        let (base,id) = scope(backend,session)?;
        let state = official_browser_0263::random_secret(32);
        self.pending_remove(&id)?;
        self.native_pending_remove(&id)?;
        self.cancel_browser(&id)?;
        let (sender,receiver) = watch::channel(false);
        self.browser.lock().map_err(|_| "Native Identity Manager заблокирован")?.insert(id.clone(), BrowserFlow0263 {state: state.to_string(), cancel: sender});
        // Cleanup always removes only this specific flow. A newer login must
        // never be removed by completion/cancellation of an older one.
        let response = async {
            let client_info = self.request(&base,access,"/browser/config",Method::GET,None,None,None).await?;
            if !self.browser_active(&id,&state)? { return Err("Microsoft-авторизация отменена".into()); }
            let client_id = client_info.data.get("clientId").and_then(Value::as_str).filter(|v| official_browser_0263::valid_client_id(v))
                .ok_or("Собственная Microsoft app registration отсутствует или недействительна")?;
            let listener = official_browser_0263::bind_loopback().await?;
            let port = listener.local_addr().map_err(|_| "Не удалось определить OAuth порт")?.port();
            let redirect = format!("http://localhost:{port}{}",official_browser_0263::CALLBACK_PATH);
            let verifier = official_browser_0263::random_secret(64);
            let auth_url = official_browser_0263::authorization_uri(client_id,&redirect,&state,&verifier)?;
            if !self.browser_active(&id,&state)? { return Err("Microsoft-авторизация отменена".into()); }
            official_browser_0263::open_system_browser(&auth_url)?;
            let code = official_browser_0263::receive_callback(listener,&state,receiver).await?;
            if !self.browser_active(&id,&state)? { return Err("Microsoft-авторизация отменена".into()); }
            // 0.26.5: native MS authorization code exchange and native Xbox/XSTS/Minecraft chain.
            // No Backend browser/exchange request, no Backend session ticket.
            let grant = self.provider.authorization_code(client_id,&redirect,code.as_str(),verifier.as_str())
                .await.map_err(|e|e.message().to_string())?;
            let (profile, native) = self.verified_native_grant(client_id,&grant).await.map_err(|e|e.message().to_string())?;
            let _vault = self.vault_lock.lock().await;
            // Hold flow lock through persistence: a cancelled login must not commit.
            let flows = self.browser.lock().map_err(|_| "Native Identity Manager заблокирован")?;
            if !flows.get(&id).is_some_and(|flow| flow.state == state.as_str()) {
                return Err("Microsoft-авторизация отменена".into());
            }
            migrate_legacy(&id)?;
            add_account(&id,&StoredAccount {schema:2,ticket:String::new(),profile:profile.clone(),native:Some(native)})?;
            Ok(profile)
        }.await;
        let mut flows = self.browser.lock().map_err(|_| "Native Identity Manager заблокирован")?;
        if flows.get(&id).is_some_and(|flow| flow.state == state.as_str()) { flows.remove(&id); }
        response
    }

    pub fn cancel(&self, backend: &str, session: &str) -> Result<(), String> {
        let (_, id) = scope(backend, session)?;
        self.pending_remove(&id)?;
        self.native_pending_remove(&id)?;
        self.cancel_browser(&id)?;
        Ok(())
    }
    pub async fn list_accounts(&self, backend: &str, session: &str) -> Result<Vec<OfficialAccount0267>, String> {
        let (_, id) = scope(backend, session)?;
        let _guard = self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let dir = load_directory(&id)?;
        dir.ids.iter().map(|uuid| {
            let record = read(&account_slot(&id, uuid)?)?.ok_or("Minecraft-аккаунт отсутствует в OS vault")?;
            if normalized_uuid(&record.profile.id)? != *uuid {return Err("Minecraft identity mismatch в OS vault".into());}
            Ok(OfficialAccount0267 {id: uuid.clone(), name:record.profile.name.clone(), active:dir.active.as_deref()==Some(uuid)})
        }).collect()
    }
    pub async fn select_account(&self, backend: &str, access: &str, session: &str, uuid: &str) -> Result<OfficialProfile,String> {
        let (base, id) = scope(backend, session)?;
        let uuid = normalized_uuid(uuid)?;
        let _guard = self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let mut dir = load_directory(&id)?;
        if !dir.ids.contains(&uuid) {return Err("Minecraft-аккаунт не найден".into());}
        let slot = account_slot(&id, &uuid)?;
        let mut record=read(&slot)?.ok_or("Minecraft-аккаунт отсутствует в OS vault")?;
        if normalized_uuid(&record.profile.id)? != uuid {return Err("Minecraft identity mismatch".into());}
        if record.native.is_some() {
            self.native_validate(&base, &slot, access, &mut record, false).await?;
        } else {
            let response=self.request(&base,access,"/profile",Method::GET,Some(&record.ticket),None,None).await?;
            let fresh=Self::profile(&response.data)?;
            if normalized_uuid(&fresh.id)? != uuid {return Err("Minecraft identity mismatch".into());}
            record.profile=fresh;
            if let Some(rotated)=response.rotation.as_ref() {record.ticket.zeroize();record.ticket=rotated.clone();}
            save(&slot,&record)?;
        }
        dir.active=Some(uuid);
        save_directory(&id,&dir)?;
        Ok(record.profile.clone())
    }
    pub async fn refresh_active(&self, backend: &str, access: &str, session: &str) -> Result<OfficialProfile,String> {
        let (base, id)=scope(backend, session)?;
        let _guard=self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let (slot,mut record)=selected_record(&id)?.ok_or("Официальный Minecraft-аккаунт не выбран")?;
        if record.native.is_some() {
            self.native_validate(&base,&slot,access,&mut record,true).await?;
            Ok(record.profile.clone())
        } else {
            // Backend owns rotation for legacy accounts. Never send its ticket to renderer.
            let result=self.request(&base,access,"/profile",Method::GET,Some(&record.ticket),None,None).await?;
            let fresh=Self::profile(&result.data)?;
            if normalized_uuid(&fresh.id)? != normalized_uuid(&record.profile.id)? {return Err("Minecraft UUID mismatch".into());}
            record.profile=fresh;
            if let Some(ticket)=result.rotation.as_ref() {record.ticket.zeroize();record.ticket=ticket.clone();}
            save(&slot,&record)?;
            Ok(record.profile.clone())
        }
    }
    // Link is a server-side, durable Never relationship, not merely a local
    // vault association. Hold the selection lock across provider verification
    // and Backend transaction to prevent linking a just-switched account.
    pub async fn never_links_0268(&self, backend:&str, access:&str, session:&str) -> Result<Vec<NeverOfficialLink0268>,String> {
        let (base,_)=scope(backend,session)?;
        let response=self.request(&base,access,"/link",Method::GET,None,None,None).await?;
        serde_json::from_value(response.data.get("links").cloned().ok_or("Некорректный список Never links")?)
            .map_err(|_|"Некорректные записи Never identity".into())
    }
    pub async fn never_link_0268(&self, backend:&str, access:&str, session:&str, expected_uuid:&str, confirmed:bool) -> Result<NeverOfficialLink0268,String> {
        if !confirmed {return Err("Необходимо явное подтверждение привязки Never и Minecraft".into());}
        let (base,id)=scope(backend,session)?;
        let requested=normalized_uuid(expected_uuid)?;
        let _guard=self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        let (slot,mut record)=selected_record(&id)?.ok_or("Minecraft-аккаунт не выбран")?;
        if normalized_uuid(&record.profile.id)?!=requested {return Err("Выбранный Minecraft UUID изменился".into());}
        if record.native.is_none() {return Err("Для привязки требуется повторный официальный вход Microsoft через native flow".into());}
        self.native_validate(&base,&slot,access,&mut record,false).await?;
        if normalized_uuid(&record.profile.id)?!=requested {return Err("Minecraft UUID изменился при проверке".into());}
        let bearer=Zeroizing::new(record.native.as_ref().ok_or("Отсутствует официальный token")?.minecraft_token.clone());
        // Native-only credential: renderer sees only the verified result.
        let response=self.request(&base,access,"/link",Method::POST,None,Some(json!({
            "expectedUuid":requested,"minecraftAccessToken":bearer.as_str(),"confirm":true
        })),None).await?;
        let link:NeverOfficialLink0268=serde_json::from_value(response.data.clone()).map_err(|_|"Некорректный ответ привязки".to_string())?;
        if normalized_uuid(&link.minecraft_uuid)?!=requested{return Err("Backend изменил Minecraft identity".into());}
        Ok(link)
    }
    pub async fn never_unlink_0268(&self, backend:&str, access:&str, session:&str, uuid:&str, confirmed:bool) -> Result<(),String> {
        if !confirmed {return Err("Необходимо явное подтверждение отвязывания".into());}
        let (base,_)=scope(backend,session)?;
        let uuid=normalized_uuid(uuid)?;
        self.request(&base,access,&format!("/link/{uuid}"),Method::DELETE,None,None,None).await?;
        Ok(())
    }
    pub async fn disconnect(&self, backend: &str, session: &str) -> Result<(), String> {
        let (_, id) = scope(backend, session)?;
        self.cancel(backend,session)?;
        let _guard = self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        if let Some(uuid)=load_directory(&id)?.active {remove_account(&id,&uuid)?;}
        Ok(())
    }
    pub async fn disconnect_account(&self, backend: &str, session: &str, uuid: &str) -> Result<(), String> {
        let (_,id)=scope(backend,session)?;
        self.cancel(backend,session)?;
        let _guard=self.vault_lock.lock().await;
        migrate_legacy(&id)?;
        remove_account(&id,uuid)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all="camelCase")]
pub struct NeverOfficialLink0268 {
    pub minecraft_uuid: String,
    pub minecraft_name: String,
    pub verified_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Context { backend_url: String, never_token: String, never_session_id: String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
pub struct LaunchContext { pub backend_url: String, pub never_token: String, pub never_session_id: String }

#[tauri::command]
pub async fn official_identity_begin_0262(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<DeviceChallenge, String> {
    manager.native_begin(&context.backend_url, &context.never_token, &context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_poll_0262(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<PollResult, String> {
    manager.native_poll(&context.backend_url, &context.never_token, &context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_wait_device_0264(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<OfficialProfile, String> {
    manager.native_wait_device(&context.backend_url, &context.never_token, &context.never_session_id).await
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

#[tauri::command]
pub async fn official_identity_accounts_0267(manager: tauri::State<'_, IdentityManager>, backend_url: String, never_session_id: String) -> Result<Vec<OfficialAccount0267>,String> {
    manager.list_accounts(&backend_url,&never_session_id).await
}
#[tauri::command]
pub async fn official_identity_select_0267(manager: tauri::State<'_, IdentityManager>, context: Context, account_id: String) -> Result<OfficialProfile,String> {
    manager.select_account(&context.backend_url,&context.never_token,&context.never_session_id,&account_id).await
}
#[tauri::command]
pub async fn official_identity_refresh_0267(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<OfficialProfile,String> {
    manager.refresh_active(&context.backend_url,&context.never_token,&context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_logout_0267(manager: tauri::State<'_, IdentityManager>, backend_url: String, never_session_id: String, account_id: String) -> Result<(),String> {
    manager.disconnect_account(&backend_url,&never_session_id,&account_id).await
}

#[tauri::command]
pub async fn official_identity_links_0268(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<Vec<NeverOfficialLink0268>,String> {
    manager.never_links_0268(&context.backend_url,&context.never_token,&context.never_session_id).await
}
#[tauri::command]
pub async fn official_identity_link_0268(manager: tauri::State<'_, IdentityManager>, context: Context, account_id: String, confirmed: bool) -> Result<NeverOfficialLink0268,String> {
    manager.never_link_0268(&context.backend_url,&context.never_token,&context.never_session_id,&account_id,confirmed).await
}
#[tauri::command]
pub async fn official_identity_unlink_0268(manager: tauri::State<'_, IdentityManager>, context: Context, account_id: String, confirmed: bool) -> Result<(),String> {
    manager.never_unlink_0268(&context.backend_url,&context.never_token,&context.never_session_id,&account_id,confirmed).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn official_never_linking_requires_explicit_confirmation() {
        let manager=IdentityManager::new().expect("http manager");
        let uuid="123456789abcdef0123456789abcdef0";
        let result=manager.never_link_0268("https://example.com","never-access-token","never-session",uuid,false).await;
        assert!(result.unwrap_err().contains("подтверждение"));
        let result=manager.never_unlink_0268("https://example.com","never-access-token","never-session",uuid,false).await;
        assert!(result.unwrap_err().contains("подтверждение"));
    }
    #[test]
    fn never_link_response_only_contains_nonsecret_identity_fields() {
        let link=NeverOfficialLink0268{minecraft_uuid:"a".repeat(32),minecraft_name:"ValidUser".into(),verified_at:"2026-10-23T12:00:00Z".into()};
        let serialized=serde_json::to_string(&link).unwrap();
        assert!(serialized.contains("minecraftUuid"));
        assert!(!serialized.contains("Token") && !serialized.contains("ticket"));
    }

    #[test] fn account_directory_rejects_tampering_and_duplicates() {
        let a="0123456789abcdef0123456789abcdef".to_string();
        let b="abcdef0123456789abcdef0123456789".to_string();
        let mut dir=AccountDirectory0267 {version:1,active:Some(a.clone()),ids:vec![a.clone(),b.clone()]};
        assert!(validate_directory(&dir).is_ok());
        dir.ids.push(a.clone());assert!(validate_directory(&dir).is_err());dir.ids.pop();
        dir.active=Some("deadbeefdeadbeefdeadbeefdeadbeef".into());assert!(validate_directory(&dir).is_err());
        dir.active=Some(a.clone());dir.ids[0]=a.to_ascii_uppercase();assert!(validate_directory(&dir).is_err());
        dir.ids[0]=a.clone();dir.version=2;assert!(validate_directory(&dir).is_err());
        assert!(account_slot("scope",&a).unwrap()!=account_slot("scope",&b).unwrap());
    }
    #[test] fn account_directory_has_bounded_size() {
        let ids:Vec<String>=(0..MAX_ACCOUNTS).map(|i|format!("{i:032x}")).collect();
        let dir=AccountDirectory0267 {version:1,active:Some(ids[0].clone()),ids};
        assert!(validate_directory(&dir).is_ok());
        assert!(serde_json::to_string(&dir).unwrap().len()<2000);
        assert!(normalized_uuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }
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
    #[tokio::test]
    async fn cancelling_native_device_flow_notifies_waiter() {
        let manager = IdentityManager::new().unwrap();
        let backend = "https://official.example";
        let session = "never-sid";
        let (_, id) = scope(backend, session).unwrap();
        let (cancel, mut receiver) = watch::channel(false);
        manager.pending.lock().unwrap().insert(id.clone(), PendingFlow {
            ticket: "secret-device-ticket".into(), next: Instant::now() + Duration::from_secs(30),
            expires: Instant::now() + Duration::from_secs(900), nonce: 1, in_flight: false,
            failures: 0, interval: 5, cancel,
        });
        manager.cancel(backend, session).unwrap();
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
        assert!(manager.pending.lock().unwrap().get(&id).is_none());
    }
    #[tokio::test]
    async fn closing_successful_flow_is_not_mistaken_for_cancel() {
        let (sender, mut receiver) = watch::channel(false);
        drop(sender);
        assert!(tokio::time::timeout(Duration::from_millis(20), await_device_cancel(&mut receiver)).await.is_err());
    }
    #[tokio::test]
    async fn expired_device_flow_does_not_hit_provider() {
        let manager = IdentityManager::new().unwrap();
        let backend = "https://official.example";
        let session = "never-sid";
        let (_, id) = scope(backend, session).unwrap();
        let (cancel, _) = watch::channel(false);
        manager.pending.lock().unwrap().insert(id.clone(), PendingFlow {
            ticket: "secret-device-ticket".into(), next: Instant::now(),
            expires: Instant::now() - Duration::from_secs(1), nonce: 2, in_flight: false,
            failures: 0, interval: 5, cancel,
        });
        assert!(manager.wait_device(backend, "never-access-token", session).await.unwrap_err().contains("истёк"));
        assert!(manager.pending.lock().unwrap().get(&id).is_none());
    }
    #[test] fn device_retry_preserves_provider_interval_and_backoff() {
        assert_eq!(retry_delay(5, 1, None), 10);
        assert_eq!(retry_delay(15, 1, Some(30)), 30);
        assert_eq!(retry_delay(25, 0, Some(5)), 25);
        assert_eq!(retry_delay(5, 100, Some(999)), 999);
        assert_eq!(retry_delay(350, 1, Some(600)), 700);
    }
    #[test]
    fn native_schema2_serializes_refresh_and_game_credentials_only_inside_record() {
        let stored=StoredAccount {schema:2,ticket:String::new(),
            profile:OfficialProfile {id:"123456781234123412341234567890ab".into(),name:"TestPlayer".into(),skins:vec![],capes:vec![]},
            native:Some(NativeAccount0265 {client_id:"11111111-2222-3333-4444-555555555555".into(),
                refresh_token:"native-refresh".into(),minecraft_token:"native-game-bearer".into(),minecraft_expires_at:now()+3600})};
        let encoded=serde_json::to_vec(&stored).unwrap();
        let decoded:StoredAccount=serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.ticket.is_empty());
        assert_eq!(decoded.native.as_ref().unwrap().minecraft_token,"native-game-bearer");
        let renderer=serde_json::to_value(&decoded.profile).unwrap();
        let output=renderer.to_string();
        assert!(!output.contains("native-refresh") && !output.contains("native-game-bearer"));
    }
    #[tokio::test]
    async fn removing_native_pending_flow_prevents_late_commit() {
        let manager=IdentityManager::new().unwrap();
        let (_,id)=scope("https://example.com","sid-0265").unwrap();
        let (cancel,mut receiver)=watch::channel(false);
        manager.native_pending.lock().unwrap().insert(id.clone(),NativePending0265 {
            client_id:"11111111-2222-3333-4444-555555555555".into(),device:Zeroizing::new("device-secret".into()),
            grant:None,next:Instant::now(),expires:Instant::now()+Duration::from_secs(900),nonce:10,
            in_flight:true,failures:0,interval:5,cancel,
        });
        manager.native_pending_remove(&id).unwrap();
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
        assert!(!manager.native_pending.lock().unwrap().contains_key(&id));
    }
    #[test] fn minecraft_identity_requires_java_uuid() {
        assert!(uuid_valid("123456781234123412341234567890ab"));
        assert!(!uuid_valid("e-mail@example.com"));
        assert!(!uuid_valid("12345678-1234-1234-1234-1234567890ab"));
    }
}

#[tauri::command]
pub async fn official_identity_browser_login_0263(manager: tauri::State<'_, IdentityManager>, context: Context) -> Result<OfficialProfile,String> {
    manager.login_browser(&context.backend_url, &context.never_token, &context.never_session_id).await
}
