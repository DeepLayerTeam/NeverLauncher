//! Product updater: Tauri validates the signed release, then the existing
//! transactional component installer maintains the Desktop/Guard/Runtime set.
use semver::Version;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{io::{Cursor, Read}, sync::Mutex, time::{Duration, Instant}};
use tauri::{AppHandle, ipc::Channel, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::sync::{RwLock, RwLockReadGuard};

const MAX_PACKAGE: usize = 512 * 1024 * 1024;
const OFFER_TTL: Duration = Duration::from_secs(15 * 60);
const CURRENT: &str = env!("CARGO_PKG_VERSION");
static OPERATIONS: RwLock<()> = RwLock::const_new(());
static OFFER: Mutex<Option<(Instant, UpdateTrack, Update)>> = Mutex::new(None);
// Network checks/downloads must not block game operations. Serialize the
// updater itself, while reserving the existing game gate for installation.
static UPDATER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
struct Prepared { track: UpdateTrack, version: String, bytes: Vec<u8>, suffix: &'static str }
static PREPARED: Mutex<Option<Prepared>> = Mutex::new(None);
// Only one bounded partial package; never trusted until Tauri verifies all bytes.
static PARTIAL: Mutex<Option<Partial>> = Mutex::new(None);
static REJECTED: Mutex<Option<String>> = Mutex::new(None);
struct Partial { track: UpdateTrack, identity: String, etag: String, total: u64, bytes: Vec<u8> }
fn identity(update: &Update) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{}\n{}\n{}", update.version, update.download_url, update.signature).as_bytes()))
}
fn strong_etag(value: &str) -> bool {
    value.len() >= 2 && value.starts_with('"') && value.ends_with('"') &&
        value.as_bytes()[1..value.len()-1].iter().all(|b| *b >= 0x21 && *b != b'"' && *b != 0x7f)
}
fn valid_range(value: &str, start: u64, total: u64) -> bool {
    if total == 0 || start >= total { return false; }
    value == format!("bytes {start}-{}/{total}", total - 1)
}
fn discard_partial() -> Result<(), String> {
    *PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")? = None;
    Ok(())
}
fn retry_error(message: &str) -> String { format!("retry: {message}") }
fn reject_error(message: &str) -> String { format!("rejected: {message}") }

fn prepared_matches(prepared: &Option<Prepared>, version: &str, track: UpdateTrack) -> bool {
    prepared.as_ref().is_some_and(|p| p.track == track && p.version == version && newer(CURRENT, &p.version))
}
fn take_prepared(prepared: &mut Option<Prepared>, version: &str, track: UpdateTrack) -> Result<Prepared, String> {
    if !prepared_matches(prepared, version, track) { return Err("Сначала скачайте и проверьте эту версию обновления".into()); }
    prepared.take().ok_or_else(|| "Пакет не скачан".into())
}


fn operation_gate(gate: &RwLock<()>) -> Result<RwLockReadGuard<'_, ()>, String> {
    gate.try_read().map_err(|_| "Выполняется обновление Launcher".into())
}
pub(super) fn operation() -> Result<RwLockReadGuard<'static, ()>, String> { operation_gate(&OPERATIONS) }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum UpdateTrack { Stable, Beta }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Offer {
    current_version: String,
    channel: UpdateTrack,
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
        (Ok(a), Ok(b)) => b.pre.is_empty() && b.build.is_empty() && b.cmp_precedence(&a).is_gt(),
        _ => false,
    }
}
fn target() -> Result<(&'static str, &'static str, &'static str), String> {
    let (os, tauri_os) = match std::env::consts::OS { "windows" => ("windows", "windows"), "linux" => ("linux", "linux"), "macos" => ("macos", "darwin"), _ => return Err("Платформа обновления не поддерживается".into()) };
    let arch = match std::env::consts::ARCH { "x86_64" => "x64", "aarch64" => "arm64", _ => return Err("Архитектура обновления не поддерживается".into()) };
    Ok((os, tauri_os, arch))
}
fn response(status: &'static str, version: Option<String>, channel: UpdateTrack) -> Offer {
    Offer { current_version: CURRENT.into(), channel, status, version, notes: None }
}

#[derive(Deserialize)]
struct GithubAsset { name: String }
#[derive(Deserialize)]
struct GithubRelease { tag_name: String, draft: bool, prerelease: bool, assets: Vec<GithubAsset> }
fn release_candidate(row: &GithubRelease) -> Option<(Version, UpdateTrack)> {
    if row.draft { return None; }
    let version = Version::parse(row.tag_name.strip_prefix('v')?).ok()?;
    if !version.pre.is_empty() || !version.build.is_empty() || row.tag_name != format!("v{version}") { return None; }
    let (channel, feed) = if row.prerelease { (UpdateTrack::Beta, "latest-beta.json") } else { (UpdateTrack::Stable, "latest.json") };
    if !row.assets.iter().any(|asset| asset.name == feed) { return None; }
    // Reject ambiguous release metadata rather than treating it as either channel.
    if row.assets.iter().any(|asset| asset.name == if row.prerelease { "latest.json" } else { "latest-beta.json" }) { return None; }
    Some((version, channel))
}
fn consider_release(best: &mut Option<(Version, UpdateTrack)>, row: &GithubRelease) {
    if let Some(candidate) = release_candidate(row) {
        if best.as_ref().map_or(true, |(old, _)| candidate.0.cmp_precedence(old).is_gt()) { *best = Some(candidate); }
    }
}
fn valid_repository(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let valid = |part: &str| !part.is_empty() && part != "." && part != ".." && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    parts.next().is_some_and(valid) && parts.next().is_some_and(valid) && parts.next().is_none()
}
fn key_material(key: &str) -> Option<Vec<u8>> {
    let outer = STANDARD.decode(key).ok()?;
    let text = std::str::from_utf8(&outer).ok()?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 2 { return None; }
    let raw = STANDARD.decode(lines[1]).ok()?;
    if raw.len() != 42 || &raw[..2] != b"Ed" { return None; }
    Some(raw[10..].to_vec())
}
fn beta_configuration(stable: &str) -> Result<(&'static str, &'static str), String> {
    let beta = option_env!("NL_UPDATER_BETA_PUBLIC_KEY").unwrap_or("").trim();
    let repo = option_env!("NL_UPDATER_GITHUB_REPOSITORY").unwrap_or("").trim();
    if beta.is_empty() || !valid_repository(repo) { return Err("В этой сборке канал Beta не настроен".into()); }
    match (key_material(stable), key_material(beta)) {
        (Some(a), Some(b)) if a != b => Ok((beta, repo)),
        _ => Err("Каналы обновлений должны использовать разные доверенные ключи".into()),
    }
}
async fn github_candidate(repo: &str) -> Result<Option<(Version, UpdateTrack)>, String> {
    let client = reqwest::Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15)).user_agent("NeverLauncher-Updater").build().map_err(|_| "Ошибка HTTP клиента")?;
    let mut best: Option<(Version, UpdateTrack)> = None;
    let scan = async {
        for page in 1..=20 {
            let url = format!("https://api.github.com/repos/{repo}/releases?per_page=50&page={page}");
            let mut res = client.get(url).header("Accept", "application/vnd.github+json").header("X-GitHub-Api-Version", "2022-11-28")
                .send().await.map_err(|_| retry_error("Не удалось получить список выпусков GitHub"))?;
            if !res.status().is_success() { return Err(retry_error("GitHub не предоставил список выпусков")); }
            let mut data = Vec::new();
            while let Some(chunk) = res.chunk().await.map_err(|_| retry_error("Ошибка чтения списка выпусков"))? {
                if chunk.len() > 8 * 1024 * 1024 - data.len() { return Err(reject_error("Слишком большой список выпусков")); }
                data.extend_from_slice(&chunk);
            }
            let rows: Vec<GithubRelease> = serde_json::from_slice(&data).map_err(|_| "Некорректный список выпусков GitHub".to_string())?;
            for row in &rows { consider_release(&mut best, row); }
            if rows.len() < 50 { return Ok(best.take()); }
        }
        Err(retry_error("Превышен лимит страниц GitHub; проверка не завершена"))
    };
    tokio::time::timeout(Duration::from_secs(40), scan).await.map_err(|_| retry_error("Превышено время поиска выпуска GitHub"))?
}

#[tauri::command]
pub(super) async fn native_update_check(app: AppHandle, channel: UpdateTrack) -> Result<Offer, String> {
    let _updater = UPDATER.try_lock().map_err(|_| "Обновление уже выполняется")?;
    *PREPARED.lock().map_err(|_| "Ошибка состояния обновления")? = None;
    *OFFER.lock().map_err(|_| "Ошибка состояния обновления")? = None;
    { let mut partial = PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")?;
      if partial.as_ref().is_some_and(|p| p.track != channel) { *partial = None; } }
    let stable_key = option_env!("NL_UPDATER_PUBLIC_KEY").unwrap_or("").trim();
    let stable_endpoint = option_env!("NL_UPDATER_ENDPOINT").unwrap_or("").trim();
    if stable_key.is_empty() || stable_endpoint.is_empty() { discard_partial()?; return Ok(response("disabled", None, channel)); }
    let (key, endpoint, source, expected) = match channel {
        UpdateTrack::Stable => (stable_key, stable_endpoint.to_owned(), UpdateTrack::Stable, None),
        UpdateTrack::Beta => {
            let (beta_key, repo) = beta_configuration(stable_key)?;
            let Some((version, source)) = github_candidate(repo).await? else { discard_partial()?; return Ok(response("current", None, channel)); };
            if !newer(CURRENT, &version.to_string()) { discard_partial()?; return Ok(response("current", None, channel)); }
            let (key, feed) = match source { UpdateTrack::Stable => (stable_key, "latest.json"), UpdateTrack::Beta => (beta_key, "latest-beta.json") };
            (key, format!("https://github.com/{repo}/releases/download/v{version}/{feed}"), source, Some(version.to_string()))
        }
    };
    https_url(&endpoint)?;
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
    let Some(update) = updater.check().await.map_err(|_| retry_error("Не удалось проверить обновления. Проверьте сеть и настройки публикации"))? else {
        discard_partial()?;
        if expected.is_some() { return Err(reject_error("Лента не соответствует выбранному выпуску GitHub")); }
        return Ok(response("current", None, channel));
    };
    if expected.as_ref().is_some_and(|v| *v != update.version) { discard_partial()?; return Err(reject_error("Версия ленты не совпадает с тегом GitHub")); }
    https_url(update.download_url.as_str())?;
    if !newer(CURRENT, &update.version) || update.signature.trim().is_empty() { return Err("Некорректная версия или отсутствует подпись".into()); }
    let id = identity(&update);
    { let mut partial = PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")?;
      if partial.as_ref().is_some_and(|p| p.identity != id) { *partial = None; } }
    if REJECTED.lock().map_err(|_| "Ошибка состояния обновления")?.as_ref() == Some(&id) {
        return Err(reject_error("Этот пакет уже отклонён проверкой. Дождитесь исправленного подписанного выпуска."));
    }
    let version = update.version.clone();
    // Remote notes are informational only; never render as HTML or trust as a signature.
    let notes = update.body.as_deref().map(|body| body.chars().take(16000).collect::<String>());
    *OFFER.lock().map_err(|_| "Ошибка состояния обновления")? = Some((Instant::now(), channel, update));
    Ok(Offer { notes, ..response("available", Some(version), source) })
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

async fn download(update: &Update, track: UpdateTrack, progress: &Channel<Progress>) -> Result<Vec<u8>, String> {
    use reqwest::{header, StatusCode};
    let id = identity(update);
    let client = reqwest::Client::builder().https_only(true).connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(600)).redirect(reqwest::redirect::Policy::limited(5))
        .build().map_err(|_| "Не удалось создать HTTPS-клиент")?;
    let url = https_url(update.download_url.as_str())?;
    let mut partial = PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")?.take()
        .filter(|p| p.track == track && p.identity == id && !p.bytes.is_empty() && (p.bytes.len() as u64) < p.total);
    // Retry from zero once if the CDN no longer accepts the saved range.
    for _ in 0..2 {
        let mut request = client.get(url.clone()).header(header::ACCEPT_ENCODING, "identity");
        if let Some(p) = &partial {
            request = request.header(header::RANGE, format!("bytes={}-", p.bytes.len()))
                .header(header::IF_RANGE, p.etag.as_str());
        }
        let mut response = match request.send().await {
            Ok(r) => r,
            Err(_) => { *PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")? = partial;
                return Err(retry_error("Не удалось подключиться к серверу обновлений")); }
        };
        let status = response.status();
        if status == StatusCode::RANGE_NOT_SATISFIABLE && partial.is_some() { partial = None; continue; }
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            *PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")? = partial;
            return Err(retry_error("Сервер обновлений временно недоступен"));
        }
        let etag = response.headers().get(header::ETAG).and_then(|v| v.to_str().ok()).filter(|v| strong_etag(v)).map(str::to_owned);
        if response.headers().get(header::CONTENT_ENCODING).is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity")) {
            return Err(reject_error("Недопустимое кодирование пакета"));
        }
        let (mut bytes, total, validator) = if status == StatusCode::PARTIAL_CONTENT {
            let Some(p) = partial.take() else { return Err(retry_error("Сервер вернул неожиданный частичный ответ")); };
            let offset = p.bytes.len() as u64;
            let range = response.headers().get(header::CONTENT_RANGE).and_then(|v| v.to_str().ok());
            if etag.as_ref() != Some(&p.etag) || !range.is_some_and(|v| valid_range(v, offset, p.total)) ||
                response.content_length().is_some_and(|n| n != p.total - offset) { continue; }
            (p.bytes, Some(p.total), Some(p.etag))
        } else if status == StatusCode::OK && !response.headers().contains_key(header::CONTENT_RANGE) {
            partial = None; // HTTP 200 replaces, never appends, saved bytes.
            (Vec::new(), response.content_length(), etag)
        } else { return Err(retry_error("Сервер отклонил скачивание обновления")); };
        if total.is_some_and(|n| n == 0 || n > MAX_PACKAGE as u64) { return Err(reject_error("Недопустимый размер обновления")); }
        let _ = progress.send(Progress { stage: "download", downloaded: bytes.len() as u64, total });
        let mut last = Instant::now();
        let interrupted = loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if chunk.len() > MAX_PACKAGE - bytes.len() || total.is_some_and(|n| bytes.len() as u64 + chunk.len() as u64 > n) {
                        return Err(reject_error("Превышен объявленный размер обновления"));
                    }
                    bytes.extend_from_slice(&chunk);
                    if last.elapsed() >= Duration::from_millis(150) {
                        let _ = progress.send(Progress { stage: "download", downloaded: bytes.len() as u64, total });
                        last = Instant::now();
                    }
                }
                Ok(None) => break false,
                Err(_) => break true,
            }
        };
        if interrupted || bytes.is_empty() || total.is_some_and(|n| n != bytes.len() as u64) {
            if let (Some(etag), Some(total)) = (validator, total) {
                if !bytes.is_empty() && (bytes.len() as u64) < total {
                    *PARTIAL.lock().map_err(|_| "Ошибка состояния загрузки")? = Some(Partial { track, identity: id, etag, total, bytes });
                }
            }
            return Err(retry_error("Загрузка прервана. Повторите скачивание; безопасный диапазон будет продолжен, если сервер его поддерживает."));
        }
        let _ = progress.send(Progress { stage: "verify", downloaded: bytes.len() as u64, total });
        return Ok(bytes);
    }
    Err(retry_error("Сервер изменил пакет. Повторите скачивание с начала."))
}

#[tauri::command]
pub(super) async fn native_update_download(version: String, channel: UpdateTrack, progress: Channel<Progress>) -> Result<(), String> {
    let _updater = UPDATER.try_lock().map_err(|_| "Обновление уже выполняется")?;
    if prepared_matches(&*PREPARED.lock().map_err(|_| "Ошибка состояния обновления")?, &version, channel) { return Ok(()); }
    let update = {
        let mut offer = OFFER.lock().map_err(|_| "Ошибка состояния обновления")?;
        let (when, track, update) = offer.as_ref().ok_or("Сначала проверьте обновления")?;
        if *track != channel || when.elapsed() > OFFER_TTL || update.version != version || !newer(CURRENT, &version) { *offer = None; return Err("expired: Предложение устарело. Повторите проверку".into()); }
        update.clone()
    };
    let id = identity(&update);
    if REJECTED.lock().map_err(|_| "Ошибка состояния обновления")?.as_ref() == Some(&id) {
        return Err(reject_error("Этот пакет уже отклонён проверкой"));
    }
    let bytes = match download(&update, channel, &progress).await {
        Ok(bytes) => bytes,
        Err(e) => { if e.starts_with("rejected:") { *REJECTED.lock().map_err(|_| "Ошибка состояния обновления")? = Some(id); } return Err(e); }
    };
    let (os, _, arch) = target()?;
    let checked = tokio::task::spawn_blocking(move || -> Result<Prepared, String> {
        update.verify(&bytes).map_err(|_| "Подпись пакета или подписанная версия не прошла проверку")?;
        let suffix = validate_package(&bytes, &version, os, arch)?;
        Ok(Prepared { track: channel, version, bytes, suffix })
    }).await.map_err(|_| "Ошибка проверки пакета")?;
    let prepared = match checked {
        Ok(p) => p,
        Err(e) => { *REJECTED.lock().map_err(|_| "Ошибка состояния обновления")? = Some(id); return Err(reject_error(&e)); }
    };
    *PREPARED.lock().map_err(|_| "Ошибка состояния обновления")? = Some(prepared);
    Ok(())
}

#[tauri::command]
pub(super) async fn native_update_install(app: AppHandle, version: String, channel: UpdateTrack, supervisor: State<'_, runtime::ProcessSupervisor>, guard: State<'_, runtime::GuardSupervisor>) -> Result<super::LauncherUpdateScheduleResult, String> {
    let _updater = UPDATER.try_lock().map_err(|_| "Обновление уже выполняется")?;
    let gate = OPERATIONS.try_write().map_err(|_| "Завершите вход, AI-генерацию и другие активные операции Launcher перед обновлением")?;
    if supervisor.list().await.iter().any(|p| p.finished_at.is_none()) { return Err("Завершите Minecraft перед обновлением".into()); }
    let prepared = {
        let mut slot = PREPARED.lock().map_err(|_| "Ошибка состояния обновления")?;
        take_prepared(&mut *slot, &version, channel)?
    };
    let result = super::install_launcher_update(prepared.bytes, prepared.suffix, guard, app).await;
    if result.as_ref().err().is_some_and(|e| e.starts_with("rejected:")) {
        if let Ok(offer) = OFFER.lock() {
            if let Some((_, _, update)) = offer.as_ref() {
                if let Ok(mut rejected) = REJECTED.lock() { *rejected = Some(identity(update)); }
            }
        }
    }
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
pub(super) fn native_update_ready(version: String, channel: UpdateTrack) -> Result<bool, String> {
    Ok(prepared_matches(&*PREPARED.lock().map_err(|_| "Ошибка состояния обновления")?, &version, channel))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn unified_auth_ai_update_exclusion() {
        let gate = RwLock::new(());
        let auth = operation_gate(&gate).unwrap();
        let ai = operation_gate(&gate).unwrap();
        assert!(gate.try_write().is_err());
        drop(auth);
        assert!(gate.try_write().is_err());
        drop(ai);
        let installation = gate.try_write().unwrap();
        assert!(operation_gate(&gate).is_err());
        drop(installation);
        assert!(operation_gate(&gate).is_ok());
    }
    #[test] fn installation_consumes_only_exact_verified_version() {
        let version = "99.0.0";
        let mut slot = Some(Prepared { track: UpdateTrack::Stable, version: version.into(), bytes: vec![1, 2, 3], suffix: "zip" });
        assert!(!prepared_matches(&slot, "99.0.1", UpdateTrack::Stable));
        assert!(take_prepared(&mut slot, "99.0.1", UpdateTrack::Stable).is_err());
        assert!(prepared_matches(&slot, version, UpdateTrack::Stable));
        assert!(take_prepared(&mut slot, version, UpdateTrack::Beta).is_err());
        assert_eq!(take_prepared(&mut slot, version, UpdateTrack::Stable).unwrap().bytes, vec![1, 2, 3]);
        assert!(take_prepared(&mut slot, version, UpdateTrack::Stable).is_err());
        let mut stale = Some(Prepared { track: UpdateTrack::Stable, version: CURRENT.into(), bytes: vec![1], suffix: "zip" });
        assert!(take_prepared(&mut stale, CURRENT, UpdateTrack::Stable).is_err());
    }
    #[test] fn resume_requires_strong_etag_and_exact_complete_range() {
        assert!(strong_etag("\"abc\""));
        for value in ["W/\"abc\"", "abc", "\"a b\"", "\"a\r\nb\""] { assert!(!strong_etag(value)); }
        assert!(valid_range("bytes 20-99/100", 20, 100));
        for value in ["bytes 0-99/100", "bytes 20-98/100", "bytes 20-99/101", "bytes 20-99/*"] { assert!(!valid_range(value, 20, 100)); }
        assert!(!valid_range("bytes 0-0/0", 0, 0));
    }
    #[test] fn stable_upgrade_only() {
        assert!(newer("1.1.1", "1.10.0"));
        for invalid in ["1.1.0", "1.1.1", "1.1.1+build", "2.0.0-beta.1", "broken"] { assert!(!newer("1.1.1", invalid)); }
    }
    #[test] fn github_channel_discovery() {
        let row = |tag: &str, draft, prerelease, names: &[&str]| GithubRelease { tag_name: tag.into(), draft, prerelease, assets: names.iter().map(|n| GithubAsset { name: (*n).into() }).collect() };
        assert_eq!(release_candidate(&row("v1.3.0", false, true, &["latest-beta.json"])), Some((Version::parse("1.3.0").unwrap(), UpdateTrack::Beta)));
        assert_eq!(release_candidate(&row("v1.3.0", false, false, &["latest.json"])), Some((Version::parse("1.3.0").unwrap(), UpdateTrack::Stable)));
        for bad in [row("v1.3.0", true, true, &["latest-beta.json"]), row("v1.3.0", false, true, &["latest.json"]), row("v1.3.0", false, false, &["latest-beta.json"]), row("v1.3.0", false, true, &["latest.json", "latest-beta.json"]), row("v1.3.0+build", false, true, &["latest-beta.json"])] { assert!(release_candidate(&bad).is_none()); }
        let mut best = None;
        consider_release(&mut best, &row("v1.2.1", false, true, &["latest-beta.json"]));
        consider_release(&mut best, &row("v1.2.0", false, false, &["latest.json"]));
        assert_eq!(best.as_ref().unwrap().1, UpdateTrack::Beta);
        consider_release(&mut best, &row("v1.2.2", false, false, &["latest.json"]));
        assert_eq!(best, Some((Version::parse("1.2.2").unwrap(), UpdateTrack::Stable)));
        assert!(!newer("1.2.2", "1.2.1"));
        assert!(valid_repository("Owner/Repo"));
        for bad in ["owner/../repo", "owner/repo?x", "../repo", "owner/"] { assert!(!valid_repository(bad)); }
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
