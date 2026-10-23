//! 0.26.3: OAuth authorization code and PKCE S256 for the SYSTEM browser.
//! The only socket is on IPv4 loopback, not reachable from other hosts.
//! No token, code, verifier or state is ever returned through Tauri IPC.
use std::{net::Ipv4Addr, time::Duration};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use reqwest::Url;
use sha2::{Digest, Sha256};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::watch, time::{timeout, Instant}};
use zeroize::Zeroizing;

pub const CALLBACK_PATH: &str = "/minecraft-poc/callback";
const MAX_HEADER: usize = 8192;

pub fn random_secret(length: usize) -> Zeroizing<String> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    let result = Zeroizing::new(URL_SAFE_NO_PAD.encode(&bytes));
    use zeroize::Zeroize;
    bytes.zeroize();
    result
}

pub fn authorization_uri(client_id: &str, redirect: &str, state: &str, verifier: &str) -> Result<Url,String> {
    if !valid_client_id(client_id) || state.len() < 32 || state.len() > 256 ||
        !state.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') ||
        !(43..=128).contains(&verifier.len()) || !verifier.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c)) {
        return Err("Неправильная регистрация Microsoft или PKCE".into());
    }
    let mut url = Url::parse("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize").unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect)
        .append_pair("response_mode", "query")
        .append_pair("scope", "XboxLive.signin offline_access")
        .append_pair("state", state)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &challenge);
    Ok(url)
}

pub fn valid_client_id(v: &str) -> bool {
    if v.len() != 36 || v.eq_ignore_ascii_case("00000000-0000-0000-0000-000000000000") { return false; }
    v.bytes().enumerate().all(|(i, c)| if [8,13,18,23].contains(&i) { c == b'-' } else { c.is_ascii_hexdigit() })
}

// Keep callback parsing independent of network I/O to support adversarial tests.
fn equals_secret(expected: &str, candidate: &str) -> bool {
    if expected.len() != candidate.len() { return false; }
    let mismatch = expected.bytes().zip(candidate.bytes()).fold(0u8, |acc,(a,b)| acc | (a ^ b));
    mismatch == 0
}

#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    Irrelevant,
    Reject,
    Declined,
    Code(String),
}

pub fn parse_callback(request: &str, port: u16, state: &str) -> Callback {
    let mut lines = request.split("\r\n");
    let Some(line) = lines.next() else { return Callback::Reject };
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" || parts[1].len() > 5500 { return Callback::Reject; }
    let mut host_ok = false;
    for line in lines {
        if line.is_empty() { break; }
        if line.len() > 4096 || line.bytes().any(|b| b < 0x20 && b != b'\t') { return Callback::Reject; }
        if let Some((header, value)) = line.split_once(':') {
            if header.eq_ignore_ascii_case("host") {
                if host_ok { return Callback::Reject; }
                host_ok = value.trim().eq_ignore_ascii_case(&format!("localhost:{port}"));
                if !host_ok { return Callback::Reject; }
            }
        }
    }
    if !host_ok || !parts[1].starts_with('/') || parts[1].starts_with("//") { return Callback::Reject; }
    let Ok(url) = Url::parse(&format!("http://localhost:{port}{}", parts[1])) else { return Callback::Reject };
    // Reject parser normalization that changes the authority (e.g. URL
    // targets containing backslashes under special-scheme URL parsing).
    if url.host_str() != Some("localhost") || url.port() != Some(port) { return Callback::Reject; }
    if url.path() != CALLBACK_PATH || url.fragment().is_some() { return Callback::Irrelevant; }
    let mut values = std::collections::HashMap::<String,String>::new();
    for (k,v) in url.query_pairs() {
        if !matches!(k.as_ref(),"state"|"code"|"error"|"error_description"|"session_state") { continue; }
        if values.insert(k.into_owned(),v.into_owned()).is_some() { return Callback::Reject; }
    }
    if !values.get("state").is_some_and(|value| equals_secret(state,value)) { return Callback::Reject; }
    if values.contains_key("error") { return Callback::Declined; }
    let Some(code) = values.remove("code") else { return Callback::Reject };
    if code.is_empty() || code.len() > 4096 || code.bytes().any(|c| c < 0x21 || c > 0x7e) { return Callback::Reject; }
    Callback::Code(code)
}

async fn handle_connection(mut stream: TcpStream, port: u16, state: &str) -> Callback {
    let mut buf = Vec::with_capacity(1024);
    let result = timeout(Duration::from_secs(5), async {
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await?;
            if n == 0 || buf.len()+n > MAX_HEADER { break; }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|v| v == b"\r\n\r\n") { break; }
        }
        Ok::<(),std::io::Error>(())
    }).await;
    let callback = if result.is_ok() && buf.windows(4).any(|v| v == b"\r\n\r\n") {
        std::str::from_utf8(&buf).map(|request| parse_callback(request,port,state)).unwrap_or(Callback::Reject)
    } else { Callback::Reject };
    let (status,message) = match &callback {
        Callback::Code(_) => ("200 OK", "Microsoft sign-in received. Return to NeverLauncher."),
        Callback::Declined => ("200 OK", "Microsoft sign-in declined. Return to NeverLauncher."),
        Callback::Irrelevant => ("404 Not Found", "Not found"),
        Callback::Reject => ("400 Bad Request", "Invalid sign-in callback"),
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{message}",message.len());
    let _ = timeout(Duration::from_secs(2), stream.write_all(response.as_bytes())).await;
    callback
}

pub async fn bind_loopback() -> Result<TcpListener,String> {
    TcpListener::bind((Ipv4Addr::LOCALHOST,0)).await.map_err(|_| "Не удалось открыть локальный OAuth callback".to_string())
}

pub async fn receive_callback(listener: TcpListener, state: &str, mut cancelled: watch::Receiver<bool>) -> Result<Zeroizing<String>,String> {
    let port = listener.local_addr().map_err(|_| "OAuth callback без локального порта")?.port();
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut ignored = 0;
    loop {
        if *cancelled.borrow() { return Err("Вход через Microsoft отменён".into()); }
        let accepted = tokio::select! {
            conn = listener.accept() => conn.map_err(|_| "Ошибка локального Microsoft callback")?,
            _ = cancelled.changed() => return Err("Вход через Microsoft отменён".into()),
            _ = tokio::time::sleep_until(deadline) => return Err("Время Microsoft-авторизации истекло".into()),
        };
        if !accepted.1.ip().is_loopback() { continue; }
        match handle_connection(accepted.0,port,state).await {
            Callback::Code(code) => return Ok(Zeroizing::new(code)),
            Callback::Declined => return Err("Вход через Microsoft отклонён".into()),
            Callback::Irrelevant | Callback::Reject => { ignored += 1; if ignored >= 32 { return Err("Слишком много некорректных OAuth callback".into()); } }
        }
    }
}

pub fn open_system_browser(url: &Url) -> Result<(),String> {
    // Fixed HTTPS identity host, no shell parsing and no user-provided command.
    if url.scheme() != "https" || url.host_str() != Some("login.microsoftonline.com") || url.path() != "/consumers/oauth2/v2.0/authorize" {
        return Err("Недоверенный OAuth URL".into());
    }
    let mut cmd;
    #[cfg(windows)] { cmd = tokio::process::Command::new("rundll32"); cmd.arg("url.dll,FileProtocolHandler").arg(url.as_str()); }
    #[cfg(target_os = "macos")] { cmd = tokio::process::Command::new("open"); cmd.arg(url.as_str()); }
    #[cfg(target_os = "linux")] { cmd = tokio::process::Command::new("xdg-open"); cmd.arg(url.as_str()); }
    #[cfg(not(any(windows,target_os="macos",target_os="linux")))] { return Err("OS browser не поддерживается".into()); }
    let mut child = cmd.kill_on_drop(false).spawn().map_err(|_| "Не удалось открыть системный браузер".to_string())?;
    tokio::spawn(async move { let _ = child.wait().await; });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_pkce_s256_and_microsoft_url() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let redirect="http://localhost:23456/minecraft-poc/callback";
        let url = authorization_uri("01234567-89ab-cdef-0123-456789abcdef",redirect,"ABCDEFGHIJKLMNOPabcdefghijklmnop1234567890_-",verifier).unwrap();
        let pairs: std::collections::HashMap<_,_> = url.query_pairs().map(|(k,v)|(k.into_owned(),v.into_owned())).collect();
        assert_eq!(pairs["code_challenge"],"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert_eq!(pairs["code_challenge_method"],"S256");
        assert_eq!(pairs["redirect_uri"],redirect);
        assert_eq!(pairs["scope"],"XboxLive.signin offline_access");
        assert!(!url.as_str().contains(verifier));
    }
    #[test]
    fn callback_rejects_host_state_duplicates_and_wrong_path() {
        let state="ABCDEFGHIJKLMNOPabcdefghijklmnop1234567890_-";
        let req=|host:&str,path:&str| format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let ok=format!("{CALLBACK_PATH}?code=abc%2B0123&state={state}");
        assert_eq!(parse_callback(&req("localhost:18345",&ok),18345,state),Callback::Code("abc+0123".into()));
        assert_eq!(parse_callback(&req("evil.test:18345",&ok),18345,state),Callback::Reject);
        assert_eq!(parse_callback(&req("localhost:18345",&format!("{CALLBACK_PATH}?state=invalid&code=abc")),18345,state),Callback::Reject);
        assert_eq!(parse_callback(&req("localhost:18345",&format!("{ok}&state={state}")),18345,state),Callback::Reject);
        assert_eq!(parse_callback(&req("localhost:18345",&format!("{ok}&code=second")),18345,state),Callback::Reject);
        assert_eq!(parse_callback(&req("localhost:18345",&format!("{CALLBACK_PATH}?code=abc&state={state}&error=access_denied")),18345,state),Callback::Declined);
        assert_eq!(parse_callback(&req("localhost:18345","/other?state=hello"),18345,state),Callback::Irrelevant);
        assert_eq!(parse_callback(&req("localhost:18345",&format!("{CALLBACK_PATH}?state={state}&error=access_denied")),18345,state),Callback::Declined);
    }
    #[tokio::test]
    async fn real_loopback_rejects_then_accepts_and_does_not_leak_code() {
        let listener=bind_loopback().await.unwrap();
        let port=listener.local_addr().unwrap().port();
        let state="ABCDEFGHIJKLMNOPabcdefghijklmnop1234567890_-";
        let (_tx,rx)=watch::channel(false);
        let task=tokio::spawn(receive_callback(listener,state,rx));
        for (path,expected) in [(format!("{CALLBACK_PATH}?state=invalid&code=secret"),"400 Bad Request"),(format!("{CALLBACK_PATH}?state={state}&code=goodcode123"),"200 OK")] {
            let mut sock=TcpStream::connect((Ipv4Addr::LOCALHOST,port)).await.unwrap();
            sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
            let mut reply=String::new(); sock.read_to_string(&mut reply).await.unwrap();
            assert!(reply.contains(expected));assert!(!reply.contains("goodcode123"));
        }
        assert_eq!(task.await.unwrap().unwrap().as_str(),"goodcode123");
    }
    #[tokio::test]
    async fn cancellation_exits_callback_wait() {
        let listener=bind_loopback().await.unwrap();
        let (tx,rx)=watch::channel(false);
        let task=tokio::spawn(receive_callback(listener,"secret",rx));
        tx.send(true).unwrap();
        assert!(task.await.unwrap().unwrap_err().contains("отменён"));
    }
}
