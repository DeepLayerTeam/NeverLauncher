//! Диагностика только с явного согласия. Токены, URL, имена пользователей и необработанные ошибки JS не передаются.
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

static CONSENT: AtomicBool = AtomicBool::new(false);
static DIAGNOSTIC_DSN: OnceLock<Option<Destination>> = OnceLock::new();

#[derive(Clone)]
struct Destination { ingest: String, key: String, dsn: String }

fn destination(dsn: &str) -> Result<Destination, String> {
    let u = reqwest::Url::parse(dsn).map_err(|_| "Некорректный DSN Sentry".to_string())?;
    let host = u.host_str().ok_or("В DSN Sentry не указан хост")?;
    if u.scheme() != "https" && !(u.scheme() == "http" && (host == "localhost" || host == "127.0.0.1" || host == "[::1]")) {
        return Err("Для отправки событий в Sentry требуется HTTPS".into());
    }
    let key = u.username();
    if key.is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() { return Err("Некорректное значение: учётные данные DSN Sentry".into()); }
    let segments: Vec<_> = u.path_segments().ok_or("Некорректный путь Sentry")?.collect();
    let project = segments.last().ok_or("Отсутствует идентификатор проекта")?;
    if project.is_empty() || project.len() > 20 || !project.bytes().all(|c| c.is_ascii_digit()) { return Err("Некорректное значение: идентификатор проекта Sentry".into()); }
    let prefix = if segments.len() > 1 { format!("/{}", segments[..segments.len()-1].join("/")) } else { String::new() };
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    let ingest = format!("{}://{}{}{prefix}/api/{project}/envelope/", u.scheme(), host, port);
    Ok(Destination { ingest, key: key.to_owned(), dsn: dsn.to_owned() })
}
fn configured() -> Option<&'static Destination> {
    DIAGNOSTIC_DSN.get_or_init(|| std::env::var("LAUNCHER_SENTRY_DESKTOP_DSN").ok().or_else(|| option_env!("LAUNCHER_SENTRY_DESKTOP_DSN").map(str::to_string)).filter(|s| !s.is_empty()).and_then(|s| destination(&s).ok())).as_ref()
}
fn safe_code(value: &str) -> Option<&str> {
    if !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') { Some(value) } else { None }
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFrame { asset: String, line: u32, column: u32 }
fn frames(input: Vec<BrowserFrame>) -> Vec<serde_json::Value> {
    input.into_iter().take(16).filter_map(|f| {
        let filename = f.asset.strip_prefix("assets/").unwrap_or(&f.asset);
        if filename.len() > 120 || !filename.ends_with(".js") || !filename.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') || f.line == 0 || f.column == 0 {return None;}
        Some(json!({"filename":format!("~/assets/{filename}"), "lineno":f.line,"colno":f.column}))
    }).collect()
}
async fn transmit(category: &str, platform: &str, stack: Vec<serde_json::Value>) -> Result<(), String> {
    let Some(dest) = configured() else {return Ok(())};
    if !CONSENT.load(Ordering::SeqCst) {return Ok(())}
    let Some(category) = safe_code(category) else {return Err("Некорректное значение: категория диагностики".into())};
    let uuid = {
        // Два случайных UUID v4 избыточны; используйте криптографическую случайность ОС из rand.
        let mut bytes: [u8;16] = rand::random();bytes[6] = (bytes[6]&15)|64;bytes[8] = (bytes[8]&63)|128;
        hex::encode(bytes)
    };
    let mut report = json!({"event_id":uuid,"platform":platform,"level":"error",
      "release":option_env!("LAUNCHER_RELEASE_ID").map(str::to_string).unwrap_or_else(|| format!("launcher@{}",env!("CARGO_PKG_VERSION"))),"message":category,
      "sdk":{"name":"launcher.desktop","version":"0.30.9"}});
    if !stack.is_empty() { report["exception"] = json!({"values":[{"type":category,"value":"Ошибка среды выполнения Desktop","stacktrace":{"frames":stack}}]}); }
    let head = json!({"event_id":uuid,"dsn":dest.dsn});
    let item = json!({"type":"event"});
    let envelope = format!("{}\n{}\n{}\n", head, item, report);
    let response = reqwest::Client::builder()
      // Источник приёма настроен оператором. Ответ 30x не должен
      // перенаправлять конверт или заголовок X-Sentry-Auth другому источнику.
      .redirect(reqwest::redirect::Policy::none())
      .timeout(Duration::from_secs(3)).build().map_err(|_|"Не удалось создать клиент диагностики")?
      .post(&dest.ingest).header("Content-Type","application/x-sentry-envelope")
      .header("X-Sentry-Auth",format!("Sentry sentry_version=7,sentry_client=launcher.desktop/0.30.9,sentry_key={}",dest.key))
      .body(envelope).send().await.map_err(|_|"Ошибка: транспорт диагностики")?;
    if !response.status().is_success() {return Err(format!("Ошибка HTTP Sentry: {}",response.status().as_u16()))}
    Ok(())
}
#[tauri::command]
pub fn desktop_sentry_consent(enabled: bool) { CONSENT.store(enabled, Ordering::SeqCst); }
#[tauri::command]
pub async fn desktop_sentry_report(category: String, frames: Vec<BrowserFrame>) -> Result<(), String> {
    transmit(&category,"javascript",self::frames(frames)).await
}
/// Обработчик panic никогда не блокирует и не меняет семантику нативной паники; сообщение и полезная нагрузка panic не пересылаются.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Стандартный обработчик panic может записывать сообщение локально, но не включает его в удалённую диагностику.
        previous(info);
        if CONSENT.load(Ordering::SeqCst) && configured().is_some() {
            std::thread::spawn(|| {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    let _ = rt.block_on(transmit("native.panic","rust",Vec::new()));
                }
            });
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn validated_assets_only() {
        assert_eq!(frames(vec![BrowserFrame{asset:"assets/index-a23.js".into(),line:23,column:7}]).len(),1);
        assert!(frames(vec![BrowserFrame{asset:"../../token.js".into(),line:23,column:7}]).is_empty());
    }
    #[test] fn parse_dsn_fail_closed() {
        assert!(destination("http://public@example.com/42").is_err());
        assert!(destination("https://public@example.com/42").is_ok());
    }
}
