//! Browser login with a backend-owned OIDC transaction. No Keycloak credentials cross IPC.
use super::{official_browser_0263, SecureAuthSession};
use serde::Deserialize;
use serde_json::json;
use reqwest::{Client, Url};
use std::time::Duration;
use tokio::{net::TcpListener, sync::watch};

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

fn backend(raw: &str) -> Result<Url, String> {
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
    if state.len() < 32 || !exact("state", state) || !exact("redirect_uri", REDIRECT) || !exact("response_type", "code") || !exact("code_challenge_method", "S256") {
        return Err("Некорректные параметры SkiF4er ID".into());
    }
    Ok(url)
}

#[tauri::command]
pub async fn skif4er_login(backend_url: String) -> Result<SecureAuthSession, String> {
    let base = backend(&backend_url)?;
    // Fixed port is part of the registered redirect. Binding also prevents concurrent attempts.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 8765)).await.map_err(|_| "Порт 8765 занят; завершите предыдущий вход")?;
    let client = Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30)).build().map_err(|_| "Не удалось создать HTTP-клиент")?;
    let begin = client.post(base.join("/api/v1/auth/oidc/skif4er-id/begin").map_err(|_| "Некорректный Backend")?).json(&json!({"redirectUri": REDIRECT, "deviceId":"desktop-client"})).send().await.map_err(|_| "Backend недоступен")?;
    if !begin.status().is_success() { return Err(format!("SkiF4er ID недоступен (HTTP {})", begin.status().as_u16())); }
    let tx = begin.json::<Envelope<Begin>>().await.map_err(|_| "Некорректный ответ Backend")?.data;
    let url = authorization_url(&tx.authorization_url, &tx.state)?;
    super::open_external_https_0356(url.to_string()).await?;
    let (_cancel, rx) = watch::channel(false);
    let code = official_browser_0263::receive_callback_for(listener, &tx.state, rx, "127.0.0.1", "/callback").await?;
    let result = client.post(base.join("/api/v1/auth/oidc/skif4er-id/complete").map_err(|_| "Некорректный Backend")?).json(&json!({"code":code.as_str(),"state":tx.state,"transaction":tx.transaction,"deviceId":"desktop-client"})).send().await.map_err(|_| "Не удалось завершить вход")?;
    if result.status().as_u16() == 202 { return Err("Требуется дополнительная локальная проверка MFA; сессия не создана".into()); }
    if !result.status().is_success() { return Err(format!("Авторизация отклонена (HTTP {})", result.status().as_u16())); }
    let data = result.json::<Envelope<Complete>>().await.map_err(|_| "Некорректная сессия Backend")?.data;
    if data.status != "authenticated" || data.provider != "skif4er-id" || data.user.id.is_empty() || data.session.id.is_empty() || data.tokens.access_token.is_empty() || data.tokens.refresh_token.is_empty() { return Err("Backend не подтвердил сессию SkiF4er ID".into()); }
    let session = SecureAuthSession { access_token:data.tokens.access_token, refresh_token:data.tokens.refresh_token, session_id:data.session.id, email:data.user.email, user_id:data.user.id, expires_at:None };
    super::store_auth_session(backend_url, session.clone()).await?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn validates_origin_and_callback() {
        let state = "abcdefghijklmnopqrstuvwxyz1234567890";
        let url = format!("https://id.skif4er.ru{AUTH_PATH}?state={state}&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&response_type=code&code_challenge_method=S256");
        assert!(authorization_url(&url,state).is_ok());
        assert!(authorization_url(&url.replace("id.skif4er.ru", "evil.test"),state).is_err());
        assert!(authorization_url(&format!("{url}&state={state}"),state).is_err());
        assert!(backend("http://example.com").is_err());
        assert!(backend("https://example.com").is_ok());
        let request = format!("GET /callback?state={state}&code=abc HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n");
        assert_eq!(official_browser_0263::parse_callback_for(&request,8765,state,"127.0.0.1","/callback"), official_browser_0263::Callback::Code("abc".into()));
    }
}
