//! Browser login with a backend-owned OIDC transaction. No Keycloak credentials cross IPC.
use super::{official_browser_0263, SecureAuthSession};
use serde::Deserialize;
use serde_json::json;
use reqwest::{Client, Url};
use std::time::Duration;
use tokio::{net::TcpListener, sync::watch};
use super::desktop_auth::{self, SessionView, lock_session};
use std::sync::Mutex;

static LOGIN_CANCEL: Mutex<Option<watch::Sender<bool>>> = Mutex::new(None);
struct LoginAttempt;
impl Drop for LoginAttempt { fn drop(&mut self) { if let Ok(mut pending) = LOGIN_CANCEL.lock() { *pending = None; } } }

#[tauri::command]
pub fn skif4er_cancel_login() -> Result<(), String> {
    let pending = LOGIN_CANCEL.lock().map_err(|_| "Ошибка состояния входа")?;
    if let Some(tx) = pending.as_ref() { let _ = tx.send(true); }
    Ok(())
}

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const AUTH_PATH: &str = "/realms/skif4er/protocol/openid-connect/auth";
#[derive(Deserialize)]
struct Envelope<T> { data: T }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Begin { authorization_url: String, state: String, transaction: String }
#[derive(Deserialize)]
struct Complete { status: String, provider: String, user: User, session: Session, tokens: Tokens }
#[derive(Deserialize)]
struct User { id: String, email: String }
#[derive(Deserialize)]
struct Session { id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tokens { access_token: String, refresh_token: String }

pub(super) fn backend(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw.trim()).map_err(|_| "Некорректный URL Backend")?;
    if (url.scheme() != "https" && !(url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost")))) || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err("Для SkiF4er ID необходим HTTPS Backend (HTTP только для локальной разработки)".into());
    }
    Ok(url)
}

fn authorization_url(raw: &str, state: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "Некорректный URL SkiF4er ID")?;
    if url.scheme() != "https" || url.host_str() != Some("id.skif4er.ru") || url.port_or_known_default() != Some(443) || url.path() != AUTH_PATH || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("Недоверенный адрес SkiF4er ID".into());
    }
    let pairs: Vec<_> = url.query_pairs().collect();
    let exact = |key: &str, value: &str| pairs.iter().filter(|(k, _)| k == key).count() == 1 && pairs.iter().any(|(k,v)| k == key && v == value);
    let single = |key: &str, min: usize| pairs.iter().filter(|(k, _)| k == key).count() == 1 && pairs.iter().any(|(k,v)| k == key && v.len() >= min);
    if !single("client_id", 1) || !single("nonce", 32) || !single("code_challenge", 43) || state.len() < 32 || !exact("state", state) || !exact("redirect_uri", REDIRECT) || !exact("response_type", "code") || !exact("code_challenge_method", "S256") {
        return Err("Некорректные параметры SkiF4er ID".into());
    }
    Ok(url)
}

#[tauri::command]
pub(super) async fn skif4er_login(backend_url: String) -> Result<SessionView, String> {
    let (tx_cancel, rx) = watch::channel(false);
    {
        let mut pending = LOGIN_CANCEL.lock().map_err(|_| "Ошибка состояния входа")?;
        if pending.is_some() { return Err("Вход уже выполняется".into()); }
        *pending = Some(tx_cancel);
    }
    let _attempt = LoginAttempt;
    let _lock = lock_session().await?;
    if *rx.borrow() { return Err("Вход отменён".into()); }
    let base = backend(&backend_url)?;
    // Fixed port is part of the registered redirect. Binding also prevents concurrent attempts.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 8765)).await.map_err(|_| "Порт 8765 занят; завершите предыдущий вход")?;
    let client = Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().map_err(|_| "Не удалось создать HTTP-клиент")?;
    let begin = client.post(base.join("/api/v1/auth/oidc/skif4er-id/begin").map_err(|_| "Некорректный Backend")?).json(&json!({"redirectUri": REDIRECT, "deviceId":"desktop-client"})).send().await.map_err(|_| "Backend недоступен")?;
    if !begin.status().is_success() { return Err(format!("SkiF4er ID недоступен (HTTP {})", begin.status().as_u16())); }
    let tx = begin.json::<Envelope<Begin>>().await.map_err(|_| "Некорректный ответ Backend")?.data;
    let url = authorization_url(&tx.authorization_url, &tx.state)?;
    if *rx.borrow() { return Err("Вход отменён".into()); }
    super::open_external_https_0356(url.to_string()).await?;
    let code = official_browser_0263::receive_callback_for(listener, &tx.state, rx.clone(), "127.0.0.1", "/callback").await?;
    if *rx.borrow() { return Err("Вход отменён".into()); }
    let result = client.post(base.join("/api/v1/auth/oidc/skif4er-id/complete").map_err(|_| "Некорректный Backend")?).json(&json!({"code":code.as_str(),"state":tx.state,"transaction":tx.transaction,"deviceId":"desktop-client"})).send().await.map_err(|_| "Не удалось завершить вход")?;
    if result.status().as_u16() == 202 { return Err("Требуется дополнительная локальная проверка MFA; сессия не создана".into()); }
    if !result.status().is_success() { return Err(format!("Авторизация отклонена (HTTP {})", result.status().as_u16())); }
    let data = result.json::<Envelope<Complete>>().await.map_err(|_| "Некорректная сессия Backend")?.data;
    if data.status != "authenticated" || data.provider != "skif4er-id" || data.user.id.is_empty() || data.session.id.is_empty() || data.tokens.access_token.is_empty() || data.tokens.refresh_token.is_empty() { return Err("Backend не подтвердил сессию SkiF4er ID".into()); }
    let session = SecureAuthSession { access_token:data.tokens.access_token, refresh_token:data.tokens.refresh_token, session_id:data.session.id, email:data.user.email, user_id:data.user.id, expires_at:None };
    // Once code exchange starts, finish it and revoke if cancellation arrived.
    if *rx.borrow() {
        let _ = client.post(base.join("/api/v1/auth/logout").map_err(|_| "Некорректный Backend")?).bearer_auth(&session.access_token).send().await;
        return Err("Вход отменён".into());
    }
    let result = desktop_auth::persist_login(backend_url.clone(), session.clone()).await?;
    if *rx.borrow() {
        super::delete_auth_session(backend_url).await?;
        let _ = client.post(base.join("/api/v1/auth/logout").map_err(|_| "Некорректный Backend")?).bearer_auth(&session.access_token).send().await;
        return Err("Вход отменён".into());
    }
    Ok(result)
}

#[tauri::command]
pub async fn skif4er_link(backend_url: String, expected_session_id: String) -> Result<(), String> {
    let base = backend(&backend_url)?;
    let session = super::load_auth_session(backend_url.clone()).await?.ok_or("Сначала войдите в Launcher")?;
    if session.session_id != expected_session_id { return Err("Сессия Launcher изменилась".into()); }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 8765)).await.map_err(|_| "Порт 8765 занят")?;
    let client = Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().map_err(|_| "Не удалось создать HTTP-клиент")?;
    let begin = client.post(base.join("/api/v1/auth/providers/skif4er-id/link/begin").map_err(|_| "Некорректный Backend")?).bearer_auth(&session.access_token).json(&json!({"redirectUri": REDIRECT, "deviceId":"desktop-client"})).send().await.map_err(|_| "Backend недоступен")?;
    if !begin.status().is_success() { return Err(format!("Привязка недоступна (HTTP {}); при 403 войдите заново", begin.status().as_u16())); }
    let tx = begin.json::<Envelope<Begin>>().await.map_err(|_| "Некорректная транзакция Backend")?.data;
    let url = authorization_url(&tx.authorization_url, &tx.state)?;
    if !url.query_pairs().any(|(k,v)| k == "prompt" && v == "login") { return Err("Backend не потребовал повторный вход SkiF4er ID".into()); }
    super::open_external_https_0356(url.to_string()).await?;
    let (_cancel, rx) = watch::channel(false);
    let code = official_browser_0263::receive_callback_for(listener, &tx.state, rx, "127.0.0.1", "/callback").await?;
    let current = super::load_auth_session(backend_url).await?.ok_or("Сессия Launcher завершена")?;
    if current.session_id != expected_session_id || current.user_id != session.user_id { return Err("Сессия Launcher изменилась".into()); }
    let result = client.post(base.join("/api/v1/auth/providers/skif4er-id/link/complete").map_err(|_| "Некорректный Backend")?).bearer_auth(&current.access_token).json(&json!({"code":code.as_str(),"state":tx.state,"transaction":tx.transaction})).send().await.map_err(|_| "Не удалось завершить привязку")?;
    if result.status().as_u16() == 409 { return Err("SkiF4er ID уже связан с аккаунтом или этот аккаунт имеет другую связь".into()); }
    if !result.status().is_success() { return Err(format!("Привязка отклонена (HTTP {})",result.status().as_u16())); }
    let body = result.json::<Envelope<serde_json::Value>>().await.map_err(|_| "Некорректный ответ привязки")?.data;
    if body["status"] != "linked" || body["provider"] != "skif4er-id" || body["identity"]["id"].as_str().unwrap_or("").is_empty() { return Err("Backend не подтвердил привязку".into()); }
    Ok(())
}

async fn management_session(backend_url: &str, expected: &str) -> Result<(Url, Client, SecureAuthSession), String> {
    let base = backend(backend_url)?;
    let session = super::load_auth_session(backend_url.to_string()).await?.ok_or("Сначала войдите в Launcher")?;
    if session.session_id != expected { return Err("Сессия Launcher изменилась".into()); }
    let client = Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().map_err(|_| "Не удалось создать HTTP-клиент")?;
    Ok((base, client, session))
}

#[tauri::command]
pub async fn skif4er_identities(backend_url: String, expected_session_id: String) -> Result<Vec<serde_json::Value>, String> {
    let (base, client, session) = management_session(&backend_url, &expected_session_id).await?;
    let response = client.get(base.join("/api/v1/auth/identities").map_err(|_| "Некорректный Backend")?).bearer_auth(&session.access_token).send().await.map_err(|_| "Backend недоступен")?;
    if !response.status().is_success() { return Err(format!("Не удалось загрузить идентичности (HTTP {})", response.status().as_u16())); }
    let data = response.json::<Envelope<serde_json::Value>>().await.map_err(|_| "Некорректный ответ Backend")?.data;
    let items = data["items"].as_array().ok_or("Некорректный список идентичностей")?;
    if items.iter().any(|i| i["id"].as_str().unwrap_or("").is_empty() || i["provider"].as_str().unwrap_or("").is_empty()) { return Err("Некорректная идентичность".into()); }
    Ok(items.clone())
}

#[tauri::command]
pub async fn skif4er_unlink(backend_url: String, expected_session_id: String, identity_id: String) -> Result<(), String> {
    if identity_id.is_empty() || identity_id.len() > 200 || !identity_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') { return Err("Некорректный идентификатор".into()); }
    let (base, client, session) = management_session(&backend_url, &expected_session_id).await?;
    let url = base.join(&format!("/api/v1/auth/identities/{identity_id}")).map_err(|_| "Некорректный Backend")?;
    let response = client.delete(url).bearer_auth(&session.access_token).send().await.map_err(|_| "Backend недоступен")?;
    match response.status().as_u16() {
        403 => return Err("Для отвязки заново войдите с локальным паролем Launcher".into()),
        409 => return Err("Необходим резервный локальный способ входа".into()),
        404 => return Err("Связь не найдена; обновите список".into()),
        _ if !response.status().is_success() => return Err(format!("Отвязка отклонена (HTTP {})", response.status().as_u16())),
        _ => {}
    }
    let data = response.json::<Envelope<serde_json::Value>>().await.map_err(|_| "Некорректный ответ Backend")?.data;
    if data["status"] != "unlinked" || data["identityId"].as_str() != Some(identity_id.as_str()) { return Err("Backend не подтвердил отвязку".into()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn validates_origin_and_callback() {
        let state = "abcdefghijklmnopqrstuvwxyz1234567890";
        let url = format!("https://id.skif4er.ru{AUTH_PATH}?state={state}&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&response_type=code&code_challenge_method=S256&client_id=desktop&nonce=abcdefghijklmnopqrstuvwxyz1234567890&code_challenge=abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG");
        assert!(authorization_url(&url,state).is_ok());
        assert!(authorization_url(&url.replace("id.skif4er.ru", "evil.test"),state).is_err());
        assert!(authorization_url(&format!("{url}&state={state}"),state).is_err());
        assert!(backend("http://example.com").is_err());
        assert!(backend("https://example.com").is_ok());
        let request = format!("GET /callback?state={state}&code=abc HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n");
        assert_eq!(official_browser_0263::parse_callback_for(&request,8765,state,"127.0.0.1","/callback"), official_browser_0263::Callback::Code("abc".into()));
    }
}
