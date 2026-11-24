//! NeverLauncher session lifecycle. Refresh credentials stay in native keyring storage.
use super::{SecureAuthSession, load_auth_session, store_auth_session, delete_auth_session};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, MutexGuard};
use fs2::FileExt;

static SESSION_LOCK: Mutex<()> = Mutex::const_new(());
// The file contains no credentials. Its OS lock also serializes different desktop processes
// sharing a configuration directory. Closing/crashing the process releases the lock.
pub(super) struct SessionGuard { _local: MutexGuard<'static, ()>, _file: std::fs::File }
pub(super) async fn lock_session() -> Result<SessionGuard, String> {
    let local = SESSION_LOCK.lock().await;
    let file = tokio::task::spawn_blocking(|| {
        let dir = super::desktop_config_dir()?;
        std::fs::create_dir_all(&dir).map_err(|_| "Не удалось открыть каталог Desktop")?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let file = options.open(dir.join("auth-session.lock")).map_err(|_| "Не удалось открыть блокировку сессии")?;
        FileExt::try_lock_exclusive(&file).map_err(|_| "Сессия занята другим процессом Launcher")?;
        Ok::<_, String>(file)
    }).await.map_err(|_| "Ошибка блокировки сессии")??;
    Ok(SessionGuard { _local: local, _file: file })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SessionView {
    access_token: String,
    session_id: String,
    email: String,
    user_id: String,
    expires_at_unix: i64,
}
#[derive(Deserialize)]
struct Claims { sub: String, sid: String, exp: i64, #[serde(default)] device_id: String, #[serde(default)] binding_epoch: i64 }

// Claims are only local routing hints. The backend verifies signature, revocation and policy.
fn claims(session: &SecureAuthSession) -> Result<Claims, String> {
    let mut parts = session.access_token.split('.');
    let _ = parts.next();
    let payload = parts.next().ok_or("Некорректный токен Launcher")?;
    if payload.len() > 32768 || parts.next().is_none() || parts.next().is_some() { return Err("Некорректный токен Launcher".into()); }
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| "Некорректный токен Launcher")?;
    let parsed: Claims = serde_json::from_slice(&bytes).map_err(|_| "Некорректные данные токена Launcher")?;
    if parsed.sub.is_empty() || parsed.sid.is_empty() || parsed.sid != session.session_id || (!session.user_id.is_empty() && parsed.sub != session.user_id) || parsed.exp <= 0 { return Err("Несовпадение пользователя или сессии Launcher".into()); }
    Ok(parsed)
}
pub(super) fn view(session: &SecureAuthSession) -> Result<SessionView, String> {
    let c = claims(session)?;
    Ok(SessionView { access_token: session.access_token.clone(), session_id: session.session_id.clone(), email: session.email.clone(), user_id: c.sub, expires_at_unix: c.exp })
}
fn client() -> Result<Client, String> {
    Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(20)).build().map_err(|_| "Не удалось создать HTTP-клиент".into())
}
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64 }
async fn check(client: &Client, base: &Url, session: &SecureAuthSession) -> Result<StatusCode, String> {
    let response = client.get(base.join("/api/v1/auth/identities").map_err(|_| "Некорректный Backend")?).bearer_auth(&session.access_token).send().await.map_err(|_| "Backend недоступен; сохранённая сессия не изменена")?;
    let status = response.status();
    if status == StatusCode::OK {
        let data: Value = response.json().await.map_err(|_| "Некорректный ответ проверки сессии")?;
        if !data["data"]["items"].is_array() { return Err("Backend не подтвердил проверку сессии".into()); }
    }
    Ok(status)
}
async fn revoke(client: &Client, base: &Url, session: &SecureAuthSession) -> bool {
    match client.post(base.join("/api/v1/auth/logout").expect("fixed path")).bearer_auth(&session.access_token).send().await {
        Ok(r) if r.status() == StatusCode::OK => match r.json::<Value>().await { Ok(v) => v["data"]["status"] == "logged-out" && v["data"]["sessionId"].as_str() == Some(session.session_id.as_str()), Err(_) => false },
        _ => false,
    }
}

// Remove the old refresh credential BEFORE submitting it. If a response is lost, retrying
// that credential could compromise the whole refresh family. Require a fresh login instead.
async fn rotate(raw: &str, client: &Client, base: &Url, mut session: SecureAuthSession, persist: bool) -> Result<Option<SecureAuthSession>, String> {
    let c = claims(&session)?;
    if session.refresh_token.is_empty() { delete_auth_session(raw.to_owned()).await?; return Ok(None); }
    let mut body = json!({"refreshToken": &session.refresh_token});
    if !c.device_id.is_empty() {
        let proof = super::sign_session_refresh(raw.to_owned(), c.sub.clone(), c.sid.clone(), c.device_id.clone(), c.binding_epoch.max(1), session.refresh_token.clone()).await?;
        body["deviceId"] = json!(c.device_id);
        body["deviceSignature"] = json!(proof.signature);
    }
    delete_auth_session(raw.to_owned()).await?;
    let response = client.post(base.join("/api/v1/auth/refresh").map_err(|_| "Некорректный Backend")?).json(&body).send().await.map_err(|_| "Ответ обновления потерян; требуется новый вход")?;
    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN { return Ok(None); }
    if response.status() != StatusCode::OK { return Err(format!("Обновление отклонено (HTTP {}); войдите снова", response.status().as_u16())); }
    let result: Value = response.json().await.map_err(|_| "Некорректный ответ обновления; войдите снова")?;
    let data = &result["data"];
    if data["status"] != "rotated" || data["session"]["id"].as_str() != Some(c.sid.as_str()) || data["session"]["userId"].as_str() != Some(c.sub.as_str()) { return Err("Backend вернул другую сессию".into()); }
    session.access_token = data["tokens"]["accessToken"].as_str().filter(|s| !s.is_empty()).ok_or("Нет нового access token")?.to_owned();
    let next_refresh = data["tokens"]["refreshToken"].as_str().filter(|s| !s.is_empty() && *s != session.refresh_token.as_str()).ok_or("Нет нового refresh token")?.to_owned();
    session.refresh_token = next_refresh;
    session.user_id = c.sub;
    view(&session)?;
    if persist { if let Err(e) = store_auth_session(raw.to_owned(), session.clone()).await { revoke(client, base, &session).await; return Err(e); } }
    Ok(Some(session))
}

#[tauri::command]
pub(super) async fn desktop_password_login(backend_url: String, email: String, password: String, provider_id: Option<String>, totp: Option<String>, recovery_code: Option<String>) -> Result<SessionView, String> {
    let _lock = lock_session().await?;
    let base = super::skif4er_login::backend(&backend_url)?;
    let client = client()?;
    let password = zeroize::Zeroizing::new(password);
    let mut body = json!({"email": email, "password": password.as_str(), "deviceId": "desktop-client"});
    if let Some(provider) = provider_id.filter(|s| !s.is_empty()) { body["providerId"] = json!(provider); }
    let totp = zeroize::Zeroizing::new(totp.unwrap_or_default());
    let recovery = zeroize::Zeroizing::new(recovery_code.unwrap_or_default());
    if !totp.is_empty() && !recovery.is_empty() { return Err("Выберите один второй фактор".into()); }
    if !totp.is_empty() {
        if totp.len()!=6 || !totp.bytes().all(|b| b.is_ascii_digit()) { return Err("Некорректный TOTP".into()); }
        body["totp"] = json!(totp.as_str());
    }
    if !recovery.is_empty() {
        if recovery.len()>256 { return Err("Некорректный код восстановления".into()); }
        body["recoveryCode"] = json!(recovery.as_str());
    }
    let response = client.post(base.join("/api/v1/auth/login").map_err(|_| "Некорректный Backend")?).json(&body).send().await.map_err(|_| "Backend недоступен")?;
    if response.status() == StatusCode::ACCEPTED { return Err("Требуется дополнительная аутентификация; сессия не создана".into()); }
    if response.status() != StatusCode::OK { return Err(format!("Вход отклонён (HTTP {})", response.status().as_u16())); }
    let result: Value = response.json().await.map_err(|_| "Некорректный ответ Backend")?;
    let data = &result["data"];
    if data["status"] != "authenticated" { return Err("Backend не подтвердил вход".into()); }
    let field = |value: &Value| value.as_str().filter(|s| !s.is_empty()).map(str::to_owned).ok_or_else(|| "Некорректная сессия Backend".to_string());
    let session = SecureAuthSession {
        access_token: field(&data["tokens"]["accessToken"])?, refresh_token: field(&data["tokens"]["refreshToken"])?,
        session_id: field(&data["session"]["id"])?, user_id: field(&data["user"]["id"])?,
        email: field(&data["user"]["email"])?, expires_at: None,
    };
    persist_login(backend_url, session).await
}

#[tauri::command]
pub(super) async fn desktop_delete_session(backend_url: String, expected_session_id: String) -> Result<(), String> {
    let _lock = lock_session().await?;
    if let Some(session) = load_auth_session(backend_url.clone()).await? {
        if session.session_id != expected_session_id { return Err("Сессия изменилась".into()); }
        delete_auth_session(backend_url).await?;
    }
    Ok(())
}

pub(super) async fn persist_login(raw: String, session: SecureAuthSession) -> Result<SessionView, String> {
    let base = super::skif4er_login::backend(&raw)?;
    let client = client()?;
    let result = view(&session)?;
    if let Err(e) = store_auth_session(raw, session.clone()).await { revoke(&client, &base, &session).await; return Err(e); }
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
enum RestoreAction { Keep, Rotate, Remove, Unavailable }
fn restore_action(status: StatusCode, expires: i64, current: i64, force: bool) -> RestoreAction {
    match status {
        StatusCode::FORBIDDEN => RestoreAction::Remove,
        StatusCode::UNAUTHORIZED if expires > current => RestoreAction::Remove,
        StatusCode::UNAUTHORIZED => RestoreAction::Rotate,
        StatusCode::OK if force || expires <= current.saturating_add(90) => RestoreAction::Rotate,
        StatusCode::OK => RestoreAction::Keep,
        _ => RestoreAction::Unavailable,
    }
}

#[tauri::command]
pub(super) async fn desktop_restore_session(backend_url: String, expected_session_id: Option<String>, force_refresh: bool) -> Result<Option<SessionView>, String> {
    let _lock = lock_session().await?;
    let base = super::skif4er_login::backend(&backend_url)?;
    let client = client()?;
    let Some(session) = load_auth_session(backend_url.clone()).await? else { return Ok(None) };
    if expected_session_id.as_ref().is_some_and(|id| id != &session.session_id) { return Err("Сессия Launcher изменилась".into()); }
    let c = match claims(&session) { Ok(c) => c, Err(e) => { delete_auth_session(backend_url).await?; return Err(e); } };
    let status = check(&client, &base, &session).await?;
    match restore_action(status, c.exp, now(), force_refresh) {
        RestoreAction::Remove => { delete_auth_session(backend_url).await?; Ok(None) },
        RestoreAction::Unavailable => Err(format!("Проверка сессии недоступна (HTTP {})", status.as_u16())),
        RestoreAction::Keep => view(&session).map(Some),
        RestoreAction::Rotate => rotate(&backend_url, &client, &base, session, true).await?.as_ref().map(view).transpose(),
    }
}

#[tauri::command]
pub(super) async fn desktop_update_access(backend_url: String, session_id: String, previous_access: String, access_token: String) -> Result<SessionView, String> {
    let _lock = lock_session().await?;
    let mut session = load_auth_session(backend_url.clone()).await?.ok_or("Сессия завершена")?;
    if session.session_id != session_id || session.access_token != previous_access { return Err("Сессия изменилась; повторите операцию".into()); }
    session.access_token = access_token;
    let result = view(&session)?;
    let base = super::skif4er_login::backend(&backend_url)?;
    if check(&client()?, &base, &session).await? != StatusCode::OK { return Err("Backend не подтвердил новый токен".into()); }
    store_auth_session(backend_url, session).await?;
    Ok(result)
}

#[tauri::command]
pub(super) async fn desktop_logout_session(backend_url: String, expected_session_id: Option<String>) -> Result<bool, String> {
    let _lock = lock_session().await?;
    let base = super::skif4er_login::backend(&backend_url)?;
    let client = client()?;
    let Some(session) = load_auth_session(backend_url.clone()).await? else { return Ok(false) };
    if expected_session_id.as_ref().is_some_and(|id| id != &session.session_id) { return Err("Сессия Launcher изменилась".into()); }
    // Commit local logout before network I/O; never restore credentials after logout.
    delete_auth_session(backend_url.clone()).await?;
    if claims(&session).is_ok_and(|c| c.exp <= now()) {
        return Ok(match rotate(&backend_url, &client, &base, session, false).await {
            Ok(Some(next)) => revoke(&client, &base, &next).await,
            _ => false,
        });
    }
    Ok(revoke(&client, &base, &session).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> SecureAuthSession {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"u","sid":"s","exp":2000000000}"#);
        SecureAuthSession { access_token: format!("header.{payload}.sig"), refresh_token: "private-refresh".into(), session_id: "s".into(), user_id: "u".into(), email: "u@example.test".into(), expires_at: None }
    }
    #[test] fn view_never_serializes_refresh() {
        let result = serde_json::to_string(&view(&sample()).unwrap()).unwrap();
        assert!(!result.contains("private-refresh")); assert!(!result.contains("refreshToken"));
    }
    #[test] fn mismatched_session_rejected() { let mut s = sample(); s.session_id = "other".into(); assert!(view(&s).is_err()); }
    #[test] fn restore_decisions_fail_closed() {
        use RestoreAction::*;
        assert_eq!(restore_action(StatusCode::OK, 2000, 1000, false), Keep);
        assert_eq!(restore_action(StatusCode::OK, 1050, 1000, false), Rotate);
        assert_eq!(restore_action(StatusCode::OK, 2000, 1000, true), Rotate);
        assert_eq!(restore_action(StatusCode::UNAUTHORIZED, 2000, 1000, false), Remove);
        assert_eq!(restore_action(StatusCode::UNAUTHORIZED, 999, 1000, false), Rotate);
        assert_eq!(restore_action(StatusCode::FORBIDDEN, 999, 1000, false), Remove);
        for status in [StatusCode::TOO_MANY_REQUESTS, StatusCode::SERVICE_UNAVAILABLE, StatusCode::FOUND] {
            assert_eq!(restore_action(status, 999, 1000, true), Unavailable);
        }
    }
    #[test] fn mismatched_user_rejected() { let mut s = sample(); s.user_id = "other".into(); assert!(view(&s).is_err()); }
}
