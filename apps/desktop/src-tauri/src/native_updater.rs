//! Product updater: Tauri validates the signed release, then the existing
//! transactional component installer maintains the Desktop/Guard/Runtime set.
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{io::{Cursor, Read}, sync::Mutex, time::{Duration, Instant}};
use tauri::{AppHandle, ipc::Channel, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::sync::{RwLock, RwLockReadGuard};

const MAX_PACKAGE: usize = 512 * 1024 * 1024;
const OFFER_TTL: Duration = Duration::from_secs(15 * 60);
const CURRENT: &str = env!("CARGO_PKG_VERSION");
static OPERATIONS: RwLock<()> = RwLock::const_new(());
static OFFER: Mutex<Option<(Instant, Update)>> = Mutex::new(None);
// Network checks/downloads must not block game operations. Serialize the
// updater itself, while reserving the existing game gate for installation.
static UPDATER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Prepared { version: String, bytes: Vec<u8>, suffix: &'static str }
static PREPARED: Mutex<Option<Prepared>> = Mutex::new(None);
fn prepared_matches(prepared: &Option<Prepared>, version: &str) -> bool {
    prepared.as_ref().is_some_and(|p| p.version == version && newer(CURRENT, &p.version))
}
fn take_prepared(prepared: &mut Option<Prepared>, version: &str) -> Result<Prepared, String> {
    if !prepared_matches(prepared, version) { return Err("Сначала скачайте и проверьте эту версию обновления".into()); }
    prepared.take().ok_or_else(|| "Пакет не скачан".into())
}


pub(super) fn operation() -> Result<RwLockReadGuard<'static, ()>, String> {
    OPERATIONS.try_read().map_err(|_| "Выполняется обновление Launcher".into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Offer {
    current_version: String,
    status: &'static str,
    version: Option<String>,
    notes: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Progress { stage: &'static str, downloaded: u64, total: Option<u64> }

fn https_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|_| "Некорректный URL обновления")?;
    if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("Разрешены только HTTPS URL без credentials и fragment".into());
    }
    Ok(url)
}
fn newer(current: &str, remote: &str) -> bool {
    match (Version::parse(current), Version::parse(remote)) {
        (Ok(a), Ok(b)) => b.pre.is_empty() && b.cmp_precedence(&a).is_gt(),
        _ => false,
    }
}
fn target() -> Result<(&'static str, &'static str, &'static str), String> {
    let (os, tauri_os) = match std::env::consts::OS { "windows" => ("windows", "windows"), "linux" => ("linux", "linux"), "macos" => ("macos", "darwin"), _ => return Err("Платформа обновления не поддерживается".into()) };
    let arch = match std::env::consts::ARCH { "x86_64" => "x64", "aarch64" => "arm64", _ => return Err("Архитектура обновления не поддерживается".into()) };
    Ok((os, tauri_os, arch))
}
fn response(status: &'static str, version: Option<String>) -> Offer {
    Offer { current_version: CURRENT.into(), status, version, notes: None }
}

#[tauri::command]
pub(super) async fn native_update_check(app: AppHandle) -> Result<Offer, String> {
    let _updater = UPDATER.try_lock().map_err(|_| "Обновление уже выполняется")?;
    *PREPARED.lock().map_err(|_| "Ошибка состояния обновления")? = None;
    *OFFER.lock().map_err(|_| "Ошибка состояния обновления")? = None;
    let key = option_env!("NL_UPDATER_PUBLIC_KEY").unwrap_or("").trim();
    let endpoint = option_env!("NL_UPDATER_ENDPOINT").unwrap_or("").trim();
    if key.is_empty() || endpoint.is_empty() { return Ok(response("disabled", None)); }
    https_url(endpoint)?;
    let (_, tauri_os, _) = target()?;
    let updater = app.updater_builder()
        .pubkey(key)
        .endpoints(vec![endpoint.parse().map_err(|_| "Некорректный endpoint")?])
        .map_err(|_| "Некорректный endpoint обновления")?
        .target(format!("{tauri_os}-{}", std::env::consts::ARCH))
        .timeout(Duration::from_secs(20))
        .configure_client(|builder| builder.https_only(true))
        .version_comparator(|current, release| newer(&current.to_string(), &release.version.to_string()))
        .build().map_err(|_| "Не удалось инициализировать Tauri Updater")?;
    let Some(update) = updater.check().await.map_err(|_| "Не удалось проверить обновления. Проверьте сеть и настройки публикации")? else { return Ok(response("current", None)); };
    https_url(update.download_url.as_str())?;
    if !newer(CURRENT, &update.version) || update.signature.trim().is_empty() { return Err("Некорректная версия или отсутствует подпись".into()); }
    let version = update.version.clone();
    // Remote notes are informational only; never render as HTML or trust as a signature.
    let notes = update.body.as_deref().map(|body| body.chars().take(16000).collect::<String>());
    *OFFER.lock().map_err(|_| "Ошибка состояния обновления")? = Some((Instant::now(), update));
    Ok(Offer { notes, ..response("available", Some(version)) })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentManifest { product: String, product_version: String, platform: String, architecture: String }
fn read_manifest<R: Read>(entry: R, size: u64, manifest: &mut Option<ComponentManifest>) -> Result<(), String> {
    if manifest.is_some() || size > 1024 * 1024 { return Err("Неоднозначный или слишком большой манифест компонентов".into()); }
    let mut raw = Vec::new();
    entry.take(1024 * 1024 + 1).read_to_end(&mut raw).map_err(|_| "Не удалось прочитать манифест компонентов")?;
    if raw.len() > 1024 * 1024 { return Err("Манифест слишком велик".into()); }
    *manifest = Some(serde_json::from_slice(&raw).map_err(|_| "Некорректный манифест компонентов")?);
    Ok(())
}
fn validate_package(bytes: &[u8], version: &str, os: &str, arch: &str) -> Result<&'static str, String> {
    let mut manifest = None;
    let suffix = if bytes.starts_with(b"PK\x03\x04") {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| "Повреждён ZIP")?;
        if zip.len() > 10_000 { return Err("Слишком много файлов в пакете".into()); }
        for i in 0..zip.len() {
            let entry = zip.by_index(i).map_err(|_| "Повреждён ZIP")?;
            let path = entry.enclosed_name().ok_or("Небезопасный путь в ZIP")?;
            if path.file_name().and_then(|s| s.to_str()) != Some("COMPONENT_UPDATE_MANIFEST.json") { continue; }
            if entry.is_dir() { return Err("Манифест не является файлом".into()); }
            let size = entry.size();
            read_manifest(entry, size, &mut manifest)?;
        }
        "zip"
    } else if os == "linux" && bytes.starts_with(b"\x1f\x8b") {
        // Linux's production component package is tar.gz. Limit decompression
        // during the preliminary scan, then let the existing installer verify all files.
        let decoder = flate2::read::GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(decoder.take(2 * 1024 * 1024 * 1024));
        for (index, entry) in archive.entries().map_err(|_| "Повреждён TAR")?.enumerate() {
            if index >= 10_000 { return Err("Слишком много файлов в пакете".into()); }
            let entry = entry.map_err(|_| "Повреждён TAR")?;
            let path = entry.path().map_err(|_| "Некорректный путь TAR")?;
            if path.components().any(|part| !matches!(part, std::path::Component::Normal(_))) { return Err("Небезопасный путь в TAR".into()); }
            if path.file_name().and_then(|s| s.to_str()) != Some("COMPONENT_UPDATE_MANIFEST.json") { continue; }
            if !entry.header().entry_type().is_file() { return Err("Манифест не является файлом".into()); }
            let size = entry.size();
            read_manifest(entry, size, &mut manifest)?;
        }
        "tar.gz"
    } else { return Err("Неподдерживаемый формат полного пакета компонентов".into()); };
    let m = manifest.ok_or("В пакете отсутствует манифест компонентов")?;
    if m.product != "Launcher" || m.product_version != version || m.platform != os || m.architecture != arch { return Err("Подписанный пакет не соответствует версии или целевой платформе".into()); }
    Ok(suffix)
}

async fn download(update: &Update, progress: &Channel<Progress>) -> Result<Vec<u8>, String> {
    // Stream with a strict byte limit. Tauri's Update::verify checks both
    // minisign authenticity and the authenticated version comment.
    let client = reqwest::Client::builder().https_only(true).connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(600)).redirect(reqwest::redirect::Policy::limited(5))
        .build().map_err(|_| "Не удалось создать HTTPS-клиент")?;
    let mut response = client.get(https_url(update.download_url.as_str())?).send().await
        .map_err(|_| "Не удалось скачать обновление")?.error_for_status().map_err(|_| "Сервер отклонил скачивание обновления")?;
    let total = response.content_length();
    if total.is_some_and(|n| n == 0 || n > MAX_PACKAGE as u64) { return Err("Недопустимый размер обновления".into()); }
    let _ = progress.send(Progress { stage: "download", downloaded: 0, total });
    let mut bytes = Vec::new();
    let mut last = Instant::now();
    while let Some(chunk) = response.chunk().await.map_err(|_| "Соединение при скачивании прервано")? {
        if chunk.len() > MAX_PACKAGE - bytes.len() { return Err("Превышен предел размера обновления".into()); }
        bytes.extend_from_slice(&chunk);
        if last.elapsed() >= Duration::from_millis(150) {
            let _ = progress.send(Progress { stage: "download", downloaded: bytes.len() as u64, total });
            last = Instant::now();
        }
    }
    if bytes.is_empty() || total.is_some_and(|n| n != bytes.len() as u64) { return Err("Пакет скачан не полностью".into()); }
    let _ = progress.send(Progress { stage: "verify", downloaded: bytes.len() as u64, total });
    Ok(bytes)
}

#[tauri::command]
pub(super) async fn native_update_download(version: String, progress: Channel<Progress>) -> Result<(), String> {
    let _updater = UPDATER.try_lock().map_err(|_| "Обновление уже выполняется")?;
    if prepared_matches(&*PREPARED.lock().map_err(|_| "Ошибка состояния обновления")?, &version) { return Ok(()); }
    let update = {
        let mut offer = OFFER.lock().map_err(|_| "Ошибка состояния обновления")?;
        let (when, update) = offer.as_ref().ok_or("Сначала проверьте обновления")?;
        if when.elapsed() > OFFER_TTL || update.version != version || !newer(CURRENT, &version) { *offer = None; return Err("Предложение устарело. Повторите проверку".into()); }
        update.clone()
    };
    let bytes = download(&update, &progress).await?;
    let (os, _, arch) = target()?;
    let prepared = tokio::task::spawn_blocking(move || -> Result<Prepared, String> {
        update.verify(&bytes).map_err(|_| "Подпись пакета или подписанная версия не прошла проверку")?;
        let suffix = validate_package(&bytes, &version, os, arch)?;
        Ok(Prepared { version, bytes, suffix })
    }).await.map_err(|_| "Ошибка проверки пакета")??;
    *PREPARED.lock().map_err(|_| "Ошибка состояния обновления")? = Some(prepared);
    Ok(())
}

#[tauri::command]
pub(super) async fn native_update_install(app: AppHandle, version: String, supervisor: State<'_, runtime::ProcessSupervisor>, guard: State<'_, runtime::GuardSupervisor>) -> Result<super::LauncherUpdateScheduleResult, String> {
    let _updater = UPDATER.try_lock().map_err(|_| "Обновление уже выполняется")?;
    let gate = OPERATIONS.try_write().map_err(|_| "Завершите текущие операции Launcher перед обновлением")?;
    if supervisor.list().await.iter().any(|p| p.finished_at.is_none()) { return Err("Завершите Minecraft перед обновлением".into()); }
    let prepared = {
        let mut slot = PREPARED.lock().map_err(|_| "Ошибка состояния обновления")?;
        take_prepared(&mut *slot, &version)?
    };
    let result = super::install_launcher_update(prepared.bytes, prepared.suffix, guard, app).await;
    if result.is_ok() {
        if let Ok(mut offer) = OFFER.lock() { *offer = None; }
        // No game or file mutations may begin before this process terminates.
        std::mem::forget(gate);
        std::mem::forget(_updater);
    }
    result
}

// Allows the UI to distinguish an install blocked by a running game from
// a scheduling failure that consumed the verified in-memory package.
#[tauri::command]
pub(super) fn native_update_ready(version: String) -> Result<bool, String> {
    Ok(prepared_matches(&*PREPARED.lock().map_err(|_| "Ошибка состояния обновления")?, &version))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn installation_consumes_only_exact_verified_version() {
        let version = "99.0.0";
        let mut slot = Some(Prepared { version: version.into(), bytes: vec![1, 2, 3], suffix: "zip" });
        assert!(!prepared_matches(&slot, "99.0.1"));
        assert!(take_prepared(&mut slot, "99.0.1").is_err());
        assert!(prepared_matches(&slot, version));
        assert_eq!(take_prepared(&mut slot, version).unwrap().bytes, vec![1, 2, 3]);
        assert!(take_prepared(&mut slot, version).is_err());
        let mut stale = Some(Prepared { version: CURRENT.into(), bytes: vec![1], suffix: "zip" });
        assert!(take_prepared(&mut stale, CURRENT).is_err());
    }
    #[test] fn stable_upgrade_only() {
        assert!(newer("1.1.1", "1.10.0"));
        for invalid in ["1.1.0", "1.1.1", "1.1.1+build", "2.0.0-beta.1", "broken"] { assert!(!newer("1.1.1", invalid)); }
    }
    #[test] fn transport_policy() {
        assert!(https_url("https://example.org/latest.json").is_ok());
        for url in ["http://example.org", "https://name@example.org", "file:///etc/passwd", "https://example.org/#frag"] { assert!(https_url(url).is_err()); }
    }
    fn fixture(version: &str, platform: &str) -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer.start_file("COMPONENT_UPDATE_MANIFEST.json", zip::write::SimpleFileOptions::default()).unwrap();
        writer.write_all(serde_json::json!({"product":"Launcher", "productVersion":version,"platform":platform,"architecture":"x64"}).to_string().as_bytes()).unwrap();
        writer.finish().unwrap().into_inner()
    }
    #[test] fn exact_package_identity() {
        assert!(validate_package(&fixture("1.2.0", "linux"), "1.2.0", "linux", "x64").is_ok());
        assert!(validate_package(&fixture("1.1.0", "linux"), "1.2.0", "linux", "x64").is_err());
        assert!(validate_package(&fixture("1.2.0", "windows"), "1.2.0", "linux", "x64").is_err());
        assert!(validate_package(b"bad", "1.2.0", "linux", "x64").is_err());
    }
}
