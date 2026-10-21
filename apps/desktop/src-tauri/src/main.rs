mod device_keys;

use neverruntime::{
    self, CleanUnusedResult, DownloadResult, FileCheckResult, GuardProcessPolicyReport, JavaInfoResult,
    LaunchHistoryEntry, LaunchPlan, ManagedJavaResult, Manifest, MinecraftLaunchCredentials,
    NeverGuardIntegrityEvidence, NeverGuardRemoteAttestation, NeverGuardRemoteAttestationV2, NeverGuardStatus, NeverGuardSupervisor,
    ProcessStatus, ProcessSupervisor, RepairResult, SignatureCheckResult,
};
#[cfg(target_os = "linux")]
use neverruntime::{NEVERGUARD_LINUX_HARDENING_VERSION, NEVERGUARD_LINUX_PROCESS_POLICY_VERSION};
#[cfg(target_os = "macos")]
use neverruntime::{NEVERGUARD_MACOS_HARDENING_VERSION, NEVERGUARD_MACOS_PROCESS_POLICY_VERSION};
#[cfg(windows)]
use neverruntime::{NEVERGUARD_WINDOWS_HARDENING_VERSION, NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, process::Stdio, time::{Duration, SystemTime, UNIX_EPOCH}};
use device_keys::{DeviceKeyInfo, DeviceSignatureResult};
use tokio::{fs, process::Command};
use zeroize::Zeroize;
use std::sync::Arc;
use tauri::Emitter;


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecureAuthSession {
    access_token: String,
    refresh_token: String,
    session_id: String,
    email: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopExtensionPlatformInfo0209 {
    os: String,
    arch: String,
    launcher_version: String,
    bridge_protocol: String,
}

#[tauri::command]
fn desktop_extension_platform_info() -> DesktopExtensionPlatformInfo0209 {
    DesktopExtensionPlatformInfo0209 {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        bridge_protocol: "neverextensions.desktop-rpc.v1".to_string(),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuardAttestationSubmission {
    launcher_version: String,
    attestation: NeverGuardRemoteAttestation,
    signature: String,
    fingerprint: String,
    key_algorithm: String,
    key_binding: String,
    hardware_provider: String,
    hardware_bound: bool,
}


#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuardAttestationV2Submission {
    launcher_version: String,
    attestation: NeverGuardRemoteAttestationV2,
    signature: String,
    fingerprint: String,
    key_algorithm: String,
    key_binding: String,
    hardware_provider: String,
    hardware_bound: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GuardAttestationV2Request {
    backend_url: String,
    user_id: String,
    device_id: String,
    session_id: String,
    binding_epoch: i64,
    launcher_version: String,
    challenge_id: String,
    challenge: String,
    challenge_expires_at: String,
    process_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaunchMinecraftRequest {
    manifest: Manifest,
    root: String,
    java_path: Option<String>,
    username: Option<String>,
    minecraft_credentials: Option<MinecraftLaunchCredentials>,
    pinned_public_key: String,
    #[serde(default)]
    preferences: Option<neverruntime::LaunchPreferences>,
    #[serde(default)]
    component_preset: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GuardAttestationRequest {
    backend_url: String,
    user_id: String,
    device_id: String,
    session_id: String,
    binding_epoch: i64,
    launcher_version: String,
    challenge_id: String,
    challenge: String,
    challenge_expires_at: String,
}

const KEYRING_SERVICE: &str = "NeverLauncher Desktop";

fn auth_keyring_username(backend_url: &str) -> Result<String, String> {
    let normalized = backend_url.trim().trim_end_matches('/').to_ascii_lowercase();
    if normalized.is_empty() { return Err("Backend URL обязателен для secure credential storage".into()); }
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    Ok(format!("backend:{}", hex::encode(hasher.finalize())))
}

#[tauri::command]
async fn store_auth_session(backend_url: String, session: SecureAuthSession) -> Result<(), String> {
    let username = auth_keyring_username(&backend_url)?;
    let secret = serde_json::to_string(&session).map_err(|e| format!("не удалось сериализовать auth session: {e}"))?;
    tokio::task::spawn_blocking(move || {
        let mut secret = secret;
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, &username).map_err(|e| format!("secure credential store недоступен: {e}"))?;
        let result = entry.set_password(&secret).map_err(|e| format!("не удалось сохранить auth session в OS credential store: {e}"));
        secret.zeroize();
        result
    }).await.map_err(|e| format!("secure credential task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn load_auth_session(backend_url: String) -> Result<Option<SecureAuthSession>, String> {
    let username = auth_keyring_username(&backend_url)?;
    tokio::task::spawn_blocking(move || {
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, &username).map_err(|e| format!("secure credential store недоступен: {e}"))?;
        match entry.get_password() {
            Ok(mut secret) => {
                let parsed = serde_json::from_str::<SecureAuthSession>(&secret).map(Some).map_err(|e| format!("auth session в OS credential store повреждена: {e}"));
                secret.zeroize();
                parsed
            },
            Err(keyring::v1::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("не удалось прочитать auth session из OS credential store: {e}")),
        }
    }).await.map_err(|e| format!("secure credential task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn delete_auth_session(backend_url: String) -> Result<(), String> {
    let username = auth_keyring_username(&backend_url)?;
    tokio::task::spawn_blocking(move || {
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, &username).map_err(|e| format!("secure credential store недоступен: {e}"))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("не удалось удалить auth session из OS credential store: {e}")),
        }
    }).await.map_err(|e| format!("secure credential task завершилась ошибкой: {e}"))?
}


#[tauri::command]
async fn ensure_device_key(backend_url: String, user_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::ensure_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("device key task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn device_key_status(backend_url: String, user_id: String) -> Result<Option<DeviceKeyInfo>, String> {
    tokio::task::spawn_blocking(move || device_keys::device_key_status(&backend_url, &user_id))
        .await.map_err(|e| format!("device key task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_device_payload(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_device_payload(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("device key signing task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn attest_device_payload(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::attest_device_payload(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("device attestation signing task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_session_refresh(backend_url: String, user_id: String, session_id: String, device_id: String, binding_epoch: i64, refresh_token: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_session_refresh(&backend_url, &user_id, &session_id, &device_id, binding_epoch, &refresh_token))
        .await.map_err(|e| format!("session refresh device signing task завершилась ошибкой: {e}"))?
}



#[tauri::command]
async fn stage_device_key_replacement(backend_url: String, user_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::stage_device_key_replacement(&backend_url, &user_id))
        .await.map_err(|e| format!("device key staging task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn staged_device_key_status(backend_url: String, user_id: String) -> Result<Option<DeviceKeyInfo>, String> {
    tokio::task::spawn_blocking(move || device_keys::staged_device_key_status(&backend_url, &user_id))
        .await.map_err(|e| format!("staged device key status task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_staged_device_replacement(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_staged_device_replacement(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("staged device key signing task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_current_device_replacement(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_current_device_replacement(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("current device rotation signing task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn commit_staged_device_key(backend_url: String, user_id: String, device_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::commit_staged_device_key(&backend_url, &user_id, &device_id))
        .await.map_err(|e| format!("device key commit task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn abort_staged_device_key(backend_url: String, user_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || device_keys::abort_staged_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("device key rollback task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn bind_device_key(backend_url: String, user_id: String, device_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::bind_device_key(&backend_url, &user_id, &device_id))
        .await.map_err(|e| format!("device key bind task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn reset_device_key(backend_url: String, user_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::reset_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("device key reset task завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn delete_device_key(backend_url: String, user_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || device_keys::delete_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("device key delete task завершилась ошибкой: {e}"))?
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsCheckResult {
    valid: bool,
    status: String,
    messages: Vec<String>,
    normalized_game_directory: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticsExportResult { path: String, message: String }

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DesktopConfig {
    schema_version: String,
    backend_url: String,
    #[serde(default)] manifest_url: String,
    project_id: String,
    profile_id: String,
    channel: String,
    game_directory: String,
    java_path: String,
    username: String,
    memory_mb: u32,
    pinned_public_key: String,
    #[serde(default)] trust_policy_path: String,
    #[serde(default)] server_id: String,
    #[serde(default = "default_screen_width_0229")] screen_width: u32,
    #[serde(default = "default_screen_height_0229")] screen_height: u32,
    #[serde(default)] fullscreen: bool,
    #[serde(default)] auto_enter: bool,
    #[serde(default)] server_host: String,
    #[serde(default = "default_server_port_0229")] server_port: u16,
    #[serde(default)] offline_enabled: bool,
    // Persist the installed signed component choice across application restarts.
    #[serde(default)] component_preset: String,
    #[serde(default)]
    config_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopBindingResult { status: String, config_path: String, game_directory: String, message: String }

fn desktop_config_dir() -> Result<PathBuf, String> {
    if let Ok(value) = std::env::var("NEVERLAUNCHER_CONFIG_DIR") { if !value.trim().is_empty() { return Ok(PathBuf::from(value)); } }
    if cfg!(windows) { if let Ok(value) = std::env::var("APPDATA") { return Ok(PathBuf::from(value).join("NeverLauncher")); } }
    if cfg!(target_os = "macos") { if let Ok(value) = std::env::var("HOME") { return Ok(PathBuf::from(value).join("Library").join("Application Support").join("NeverLauncher")); } }
    if let Ok(value) = std::env::var("XDG_CONFIG_HOME") { return Ok(PathBuf::from(value).join("NeverLauncher")); }
    if let Ok(value) = std::env::var("HOME") { return Ok(PathBuf::from(value).join(".config").join("NeverLauncher")); }
    Ok(PathBuf::from(".neverlauncher").join("config"))
}
fn desktop_config_path() -> Result<PathBuf, String> { Ok(desktop_config_dir()?.join("config.json")) }
// The file location may be configured by a previously verified Prestarter;
// the Rust verifier still authenticates its content against pinnedPublicKey.
fn initialize_desktop_game_trust_02312() -> Result<(),String> {
    if std::env::var_os("NEVERLAUNCHER_GAME_TRUST_POLICY_FILE").is_some() {return Ok(())}
    let path=desktop_config_path()?;
    let bytes=match std::fs::read(&path) {Ok(b)=>b,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(()),Err(e)=>return Err(e.to_string())};
    let cfg:DesktopConfig=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
    if cfg.trust_policy_path.is_empty() {return Ok(())}
    let target=PathBuf::from(&cfg.trust_policy_path);
    if !target.is_absolute(){return Err("trust policy location must be absolute".into())}
    let meta=std::fs::symlink_metadata(&target).map_err(|e|e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len()>128*1024 {return Err("unsafe trust policy source".into())}
    std::env::set_var("NEVERLAUNCHER_GAME_TRUST_POLICY_FILE",&target);
    Ok(())
}

fn default_game_directory() -> String {
    let base = if cfg!(windows) { std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".")) }
    else if let Ok(home) = std::env::var("HOME") { PathBuf::from(home).join(".local").join("share") }
    else { PathBuf::from(".") };
    base.join("NeverLauncher").join("projects").to_string_lossy().to_string()
}
fn default_screen_width_0229() -> u32 { 1280 }
fn default_screen_height_0229() -> u32 { 720 }
fn default_server_port_0229() -> u16 { 25565 }
fn default_desktop_config() -> DesktopConfig {
    DesktopConfig { schema_version: "1.0".into(), backend_url: String::new(), manifest_url: String::new(), project_id: String::new(), profile_id: String::new(), channel: "stable".into(), game_directory: default_game_directory(), java_path: String::new(), username: "Player".into(), memory_mb: 4096, pinned_public_key: String::new(), trust_policy_path: String::new(), server_id: String::new(), screen_width: 1280, screen_height: 720, fullscreen: false, auto_enter: false, server_host: String::new(), server_port: 25565, offline_enabled: false, component_preset:String::new(), config_path: String::new() }
}
fn normalize_desktop_config(mut cfg: DesktopConfig) -> DesktopConfig {
    if cfg.schema_version.trim().is_empty() { cfg.schema_version = "1.0".into(); }
    if cfg.channel.trim().is_empty() { cfg.channel = "stable".into(); }
    if cfg.game_directory.trim().is_empty() { cfg.game_directory = default_game_directory(); }
    if cfg.username.trim().is_empty() { cfg.username = "Player".into(); }
    if cfg.memory_mb == 0 { cfg.memory_mb = 4096; }
    if cfg.screen_width == 0 { cfg.screen_width = 1280; }
    if cfg.screen_height == 0 { cfg.screen_height = 720; }
    if cfg.server_port == 0 { cfg.server_port = 25565; }
    // Corrupt/unsupported preferences are not authoritative for any release.
    if cfg.component_preset.len()>8192 || cfg.component_preset.bytes().any(|b|b<0x20||b==0x7f){
        cfg.component_preset.clear();
    }
    cfg
}

#[tauri::command]
async fn load_desktop_config() -> Result<DesktopConfig, String> {
    let path = desktop_config_path()?;
    let mut cfg = if fs::metadata(&path).await.is_ok() { serde_json::from_slice::<DesktopConfig>(&fs::read(&path).await.map_err(|e| e.to_string())?).map_err(|e| format!("desktop config повреждён: {e}"))? } else { default_desktop_config() };
    cfg = normalize_desktop_config(cfg); cfg.config_path = path.to_string_lossy().to_string(); Ok(cfg)
}
#[tauri::command]
async fn save_desktop_config(config: DesktopConfig) -> Result<DesktopBindingResult, String> {
    let path = desktop_config_path()?; let parent = path.parent().ok_or("не удалось определить каталог desktop config")?;
    fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
    let mut cfg = normalize_desktop_config(config); cfg.schema_version = "1.0".into(); cfg.config_path = path.to_string_lossy().to_string();
    fs::write(&path, serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
    Ok(DesktopBindingResult { status: "saved".into(), config_path: path.to_string_lossy().to_string(), game_directory: cfg.game_directory, message: "desktop binding сохранён; runtime выполняется NeverRuntime".into() })
}
#[tauri::command]
async fn reset_desktop_binding() -> Result<DesktopBindingResult, String> {
    let path = desktop_config_path()?; if fs::metadata(&path).await.is_ok() { fs::remove_file(&path).await.map_err(|e| e.to_string())?; }
    let cfg = default_desktop_config(); Ok(DesktopBindingResult { status: "reset".into(), config_path: path.to_string_lossy().to_string(), game_directory: cfg.game_directory, message: "desktop binding сброшен".into() })
}

#[tauri::command]
async fn load_manifest(url: String, pinned_public_key: String) -> Result<Manifest, String> { neverruntime::load_manifest(&url, &pinned_public_key).await }
#[tauri::command]
async fn verify_manifest_signature(manifest: Manifest, pinned_public_key: String) -> Result<SignatureCheckResult, String> { neverruntime::verify_manifest_signature(&manifest, &pinned_public_key) }
#[tauri::command]
async fn check_files(manifest: Manifest, root: String, preset: Option<String>) -> Result<Vec<FileCheckResult>, String> { neverruntime::check_files_with_preset(&manifest, &PathBuf::from(root), preset.as_deref()).await }
#[tauri::command]
async fn download_missing_files(app: tauri::AppHandle, manifest: Manifest, root: String, pinned_public_key: String, preset:Option<String>) -> Result<DownloadResult, String> {
    let sink: neverruntime::ProgressSink = Arc::new(move |progress| {
        let _ = app.emit(neverruntime::DOWNLOAD_PROGRESS_EVENT, progress);
    });
    neverruntime::download_missing_files_with_preset(&manifest, &PathBuf::from(root), &pinned_public_key, Some(sink), preset).await
}
#[tauri::command]
async fn repair_client(app: tauri::AppHandle, manifest: Manifest, root: String, pinned_public_key: String, preset:Option<String>) -> Result<RepairResult, String> {
    let sink: neverruntime::ProgressSink = Arc::new(move |progress| {
        let _ = app.emit(neverruntime::DOWNLOAD_PROGRESS_EVENT, progress);
    });
    neverruntime::repair_client_with_preset(&manifest, &PathBuf::from(root), &pinned_public_key, Some(sink), preset).await
}
#[tauri::command]
async fn pending_download_job(root: String, pinned_public_key: String) -> Result<Option<neverruntime::durable_downloads::PendingDownload>, String> {
    neverruntime::durable_downloads::pending(&PathBuf::from(root), &pinned_public_key).await
}
#[tauri::command]
async fn control_download_job(root: String, action: String) -> Result<(), String> {
    neverruntime::durable_downloads::control(&PathBuf::from(root), &action).await
}
#[tauri::command]
async fn resume_download_job(app: tauri::AppHandle, root: String, pinned_public_key: String) -> Result<DownloadResult, String> {
    let sink: neverruntime::ProgressSink = Arc::new(move |progress| {
        let _ = app.emit(neverruntime::DOWNLOAD_PROGRESS_EVENT, progress);
    });
    neverruntime::durable_downloads::resume(&PathBuf::from(root), &pinned_public_key, Some(sink)).await
}
#[tauri::command]
async fn rollback_client_release(root: String, pinned_public_key: String) -> Result<(), String> {
    neverruntime::transactional_release::rollback(&PathBuf::from(root), &pinned_public_key).await
}
#[tauri::command]
async fn recover_client_release(root: String, pinned_public_key: String) -> Result<(), String> {
    neverruntime::transactional_release::recover(&PathBuf::from(root), &pinned_public_key).await
}
#[tauri::command]
async fn clean_unused_files(manifest: Manifest, root: String, pinned_public_key: String) -> Result<CleanUnusedResult, String> { neverruntime::clean_unused_files(&manifest, &PathBuf::from(root), &pinned_public_key).await }
#[tauri::command]
async fn prepare_profile_directory(base_dir: String, project_id: String, profile_id: String) -> Result<String, String> { Ok(neverruntime::prepare_profile_directory(&PathBuf::from(base_dir), &project_id, &profile_id).await?.to_string_lossy().to_string()) }
#[tauri::command]
async fn check_java(java_path: Option<String>, required_major_version: Option<u32>) -> Result<JavaInfoResult, String> { neverruntime::check_java(java_path, required_major_version).await }
#[tauri::command]
async fn ensure_managed_java(required_major_version: u32, distribution: String) -> Result<ManagedJavaResult, String> {
    // Explicit administrative/CLI-style operation remains available.
    neverruntime::ensure_managed_java(required_major_version, &distribution, None).await
}
#[tauri::command]
async fn ensure_profile_managed_java(manifest: Manifest, pinned_public_key: String) -> Result<ManagedJavaResult, String> {
    neverruntime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    let java = &manifest.runtime.java;
    if java.major_version == 0 || (java.minimum_major_version > 0 && java.major_version < java.minimum_major_version)
        || (java.maximum_major_version > 0 && java.major_version > java.maximum_major_version) {
        return Err("Signed profile Java major is outside the supported range".into());
    }
    neverruntime::ensure_managed_java(java.major_version, &java.distribution, None).await
}
#[tauri::command]
async fn build_launch_plan(manifest: Manifest, root: String, java_path: Option<String>, username: Option<String>, pinned_public_key: String, preferences: Option<neverruntime::LaunchPreferences>) -> Result<LaunchPlan, String> {
    let root = PathBuf::from(root);
    let mut plan = neverruntime::build_launch_plan(&manifest, &root, java_path, username, &pinned_public_key).await?;
    if let Some(p) = preferences { neverruntime::apply_launch_preferences(&manifest, &root, &mut plan, &p, None)?; }
    Ok(plan)
}
// Cached manifests are never trusted solely because they are on disk.
// All offline reads verify the pinned Ed25519 signature again.
fn desktop_manifest_cache_path_0229(root: &str) -> Result<PathBuf, String> {
    let root = PathBuf::from(root).canonicalize().map_err(|e| format!("client root unavailable: {e}"))?;
    let dir = root.join(".neverlauncher");
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() || !meta.is_dir() { return Err("unsafe manifest cache directory".into()); }
    }
    Ok(dir.join("signed-manifest.json"))
}

#[tauri::command]
async fn cache_desktop_manifest(manifest: Manifest, root: String, pinned_public_key: String) -> Result<(), String> {
    neverruntime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    // The client directory may not exist until first install.
    fs::create_dir_all(&root).await.map_err(|e| format!("cannot create client root for cache: {e}"))?;
    let path = desktop_manifest_cache_path_0229(&root)?;
    let dir = path.parent().ok_or("missing cache directory")?;
    fs::create_dir_all(dir).await.map_err(|e| e.to_string())?;
    if let Ok(meta) = fs::symlink_metadata(&path).await {
        if meta.file_type().is_symlink() { return Err("unsafe manifest cache file".into()); }
    }
    let value = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("signed-manifest.{}.{}.tmp", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos()));
    let mut file = fs::OpenOptions::new().create_new(true).write(true).open(&tmp).await.map_err(|e| e.to_string())?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&value).await.map_err(|e| e.to_string())?;
    file.sync_all().await.map_err(|e| e.to_string())?;
    drop(file);
    // Windows rename does not overwrite an existing file. Keep a recoverable
    // previous signed cache until the new one is installed. Readers fail closed
    // during the replacement gap; neither variant can bypass signature checks.
    #[cfg(windows)]
    if fs::metadata(&path).await.is_ok() {
        let backup = tmp.with_extension("previous");
        fs::rename(&path, &backup).await.map_err(|e| format!("cannot preserve previous manifest cache: {e}"))?;
        if let Err(err) = fs::rename(&tmp, &path).await {
            let _ = fs::rename(&backup, &path).await;
            return Err(format!("manifest cache replacement failed: {err}"));
        }
        let _ = fs::remove_file(&backup).await;
        return Ok(());
    }
    fs::rename(&tmp, &path).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn load_cached_desktop_manifest(root: String, pinned_public_key: String, project_id: String, profile_id: String, channel: String) -> Result<Manifest, String> {
    let path = desktop_manifest_cache_path_0229(&root)?;
    let meta = fs::symlink_metadata(&path).await.map_err(|e| format!("no cached manifest: {e}"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 { return Err("unsafe manifest cache file".into()); }
    let manifest: Manifest = serde_json::from_slice(&fs::read(&path).await.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    neverruntime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    if (manifest.schema_version != "2.0" && manifest.schema_version != "3.0") || manifest.project_id != project_id || manifest.profile_id != profile_id || manifest.channel != channel || !manifest.runtime.launch.offline_mode {
        return Err("cached manifest is not authorized for this profile/channel in offline mode".into());
    }
    Ok(manifest)
}

#[tauri::command]
async fn preview_components_0244(
    manifest: neverruntime::Manifest,
    pinned_public_key: String,
    component_preset: Option<String>,
) -> Result<neverruntime::component_catalog_0241::ComponentSelectionPreview0244, String> {
    neverruntime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    neverruntime::component_catalog_0241::preview_components_0244(&manifest,component_preset.as_deref())
}

#[tauri::command]
async fn save_installed_component_choice_0247(
    manifest:neverruntime::Manifest,pinned_public_key:String,root:String,
    component_preset:String,mut config:DesktopConfig,
)->Result<(),String>{
    let chosen=neverruntime::transactional_release::matching_installed_preset_0247(
        &manifest,&PathBuf::from(root),&pinned_public_key)?
        .ok_or("cannot save a component choice for a different/uninstalled release")?;
    if chosen.unwrap_or_default()!=component_preset {
        return Err("installed component choice differs from requested preference".into());
    }
    if component_preset.len()>8192 {return Err("component choice too large".into())}
    if config.project_id!=manifest.project_id || config.profile_id!=manifest.profile_id
        || config.game_directory!=root || config.pinned_public_key!=pinned_public_key {
        return Err("desktop settings mismatch signed installed profile, directory or key".into());
    }
    config.component_preset=component_preset;
    save_desktop_config(config).await?;
    Ok(())
}


// Evidence is measured from the installed active release, never from the
// renderer-provided list of mods, manifest or chosen plan SHA-256.
#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
struct NativePlanChallenge02412 {
    backend_url:String, user_id:String, device_id:String, session_id:String, binding_epoch:i64,
    server_id:String, project_id:String,profile_id:String,channel:String,
    root:String,pinned_public_key:String,challenge_id:String,challenge:String,
    guard_attestation_sha256:String,
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct NativePlanEvidence02412 {
    challenge_id:String,challenge:String,user_id:String,device_id:String,session_id:String,binding_epoch:i64,
    server_id:String,project_id:String,profile_id:String,channel:String,
    release_signature:String,catalog_digest:String,plan_sha256:String,guard_attestation_sha256:String,signature:String,
}
#[tauri::command]
async fn attest_verified_component_plan_02412(request:NativePlanChallenge02412)->Result<NativePlanEvidence02412,String>{
    tokio::task::spawn_blocking(move || {
        let NativePlanChallenge02412 {backend_url,user_id,device_id,session_id,binding_epoch,
            server_id,project_id,profile_id,channel,root,pinned_public_key,challenge_id,challenge,guard_attestation_sha256}=request;
        if [ &user_id,&device_id,&session_id,&server_id,&project_id,&profile_id,&channel,&challenge_id,&challenge ].iter()
            .any(|v|v.is_empty()||v.len()>160||v.contains('\n')||v.contains('\r')) {
            return Err("invalid verified plan identity/challenge".to_string());
        }
        if guard_attestation_sha256.len()!=64|| !guard_attestation_sha256.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()){
            return Err("invalid continuous Guard attestation digest".into());
        }
        let root_path=PathBuf::from(root);
        let (manifest,preset)=neverruntime::transactional_release::verified_active_selection_02410(
            &root_path,&pinned_public_key)?.ok_or("no verified installed release")?;
        if manifest.schema_version!="3.0"||manifest.project_id!=project_id||manifest.profile_id!=profile_id||manifest.channel!=channel {
            return Err("installed signed release does not match requested server scope".into());
        }
        // verified_active_selection checks SHA-256 of every installed managed file.
        let plan=neverruntime::resolved_download_0246::resolve(&manifest,preset.as_deref())?;
        let catalog_digest=manifest.component_catalog.as_ref().ok_or("v3 catalog required")?.digest.clone();
        let release_signature=manifest.signature.as_ref().ok_or("unsigned installed release")?.signature.to_ascii_lowercase();
        if catalog_digest.len()!=64||release_signature.len()!=128{return Err("malformed signed release measurements".into());}
        let canonical=format!("NeverLauncher-Verified-Component-Plan-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            challenge_id,challenge,user_id,device_id,session_id,binding_epoch,server_id,project_id,profile_id,channel,
            release_signature,catalog_digest,plan.sha256,guard_attestation_sha256);
        let signer=device_keys::sign_verified_plan_payload_02412(&backend_url,&user_id,&device_id,&canonical)?;
        Ok(NativePlanEvidence02412{challenge_id,challenge,user_id,device_id,session_id,binding_epoch,
            server_id,project_id,profile_id,channel,release_signature,catalog_digest,
            plan_sha256:plan.sha256,guard_attestation_sha256,signature:signer.signature})
    }).await.map_err(|e|format!("native verified plan task failed: {e}"))?
}

#[derive(serde::Serialize)]
#[serde(rename_all="camelCase")]
struct ActiveSelection02410 { manifest:neverruntime::Manifest, component_preset:String }

#[tauri::command]
async fn active_selection_02410(root:String,pinned_public_key:String)->Result<Option<ActiveSelection02410>,String>{
    tokio::task::spawn_blocking(move || {
        let state=neverruntime::transactional_release::verified_active_selection_02410(
            &PathBuf::from(root),&pinned_public_key)?;
        Ok(state.map(|(manifest,preset)|ActiveSelection02410{manifest,component_preset:preset.unwrap_or_default()}))
    }).await.map_err(|e|format!("read active selection task failed: {e}"))?
}

#[tauri::command]
async fn export_component_selection_02410(root:String,pinned_public_key:String)->Result<String,String>{
    tokio::task::spawn_blocking(move || {
        let (manifest,preset)=neverruntime::transactional_release::verified_active_selection_02410(
            &PathBuf::from(root),&pinned_public_key)?.ok_or("no installed signed release to export")?;
        neverruntime::component_selection_02410::export_from_installed_02410(&manifest,preset.as_deref())
    }).await.map_err(|e|format!("export selection task failed: {e}"))?
}

#[tauri::command]
async fn preview_component_migration_02410(
    manifest:neverruntime::Manifest,root:String,pinned_public_key:String,
)->Result<Option<neverruntime::component_selection_02410::SelectionMigration02410>,String>{
    tokio::task::spawn_blocking(move || {
        neverruntime::verify_manifest_signature(&manifest,&pinned_public_key)?;
        let Some((source,preset))=neverruntime::transactional_release::verified_active_selection_02410(
            &PathBuf::from(root),&pinned_public_key)? else{return Ok(None)};
        // No migration is required when the exact signed release is active.
        if source.signature.as_ref().map(|s|(&s.signature,&s.public_key))==
            manifest.signature.as_ref().map(|s|(&s.signature,&s.public_key)) {return Ok(None)}
        if source.schema_version!="3.0" {return Ok(None)}
        let text=neverruntime::component_selection_02410::export_from_installed_02410(&source,preset.as_deref())?;
        let selection=neverruntime::component_selection_02410::parse_import_02410(&text)?;
        Ok(Some(neverruntime::component_selection_02410::migrate_02410(&selection,&manifest)?))
    }).await.map_err(|e|format!("component migration task failed: {e}"))?
}

#[tauri::command]
async fn preview_import_component_selection_02410(
    manifest:neverruntime::Manifest,pinned_public_key:String,selection_json:String,
)->Result<neverruntime::component_selection_02410::SelectionMigration02410,String>{
    tokio::task::spawn_blocking(move || {
        neverruntime::verify_manifest_signature(&manifest,&pinned_public_key)?;
        let selection=neverruntime::component_selection_02410::parse_import_02410(&selection_json)?;
        neverruntime::component_selection_02410::migrate_02410(&selection,&manifest)
    }).await.map_err(|e|format!("import selection task failed: {e}"))?
}

#[derive(serde::Serialize)]
#[serde(rename_all="camelCase")]
struct InstalledChoice0247 {installed:bool,preset:Option<String>}

#[tauri::command]
async fn installed_component_choice_0247(
    manifest:neverruntime::Manifest,pinned_public_key:String,root:String,
)->Result<InstalledChoice0247,String>{
    let selected=neverruntime::transactional_release::matching_installed_preset_0247(
        &manifest,&PathBuf::from(root),&pinned_public_key)?;
    Ok(match selected {
        Some(preset)=>InstalledChoice0247{installed:true,preset},
        None=>InstalledChoice0247{installed:false,preset:None},
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all="camelCase")]
struct ComponentDiff0247 {
    installed_preset:Option<String>,
    added_files:Vec<String>,
    removed_files:Vec<String>,
    download_files:Vec<String>,
    download_bytes_upper_bound:u64,
    total_selected_bytes:u64,
    plan_sha256:String,
}

#[tauri::command]
async fn preview_component_changes_0247(
    manifest:neverruntime::Manifest,
    pinned_public_key:String,
    root:String,
    component_preset:Option<String>,
) -> Result<ComponentDiff0247,String> {
    use std::collections::HashSet;
    neverruntime::verify_manifest_signature(&manifest,&pinned_public_key)?;
    let root=PathBuf::from(root);
    let plan=neverruntime::resolved_download_0246::resolve(&manifest,component_preset.as_deref())?;
    let (installed_preset, installed)=neverruntime::transactional_release::installed_component_state_0247(&manifest,&root,&pinned_public_key)?;
    let old:HashSet<_>=installed.into_iter().collect();
    // Never preview a download as "safe" when it would take ownership of
    // an existing user file, including a file with the expected SHA-256.
    for f in &plan.files {
        if old.contains(&f.path){continue}
        neverruntime::transactional_release::check_unowned_path_0247(&root,&f.path)?;
    }
    let wanted:HashSet<_>=plan.files.iter().map(|f|f.path.clone()).collect();
    let added_files=plan.files.iter().filter(|f|!old.contains(&f.path)).map(|f|f.path.clone()).collect();
    let removed_files=old.iter().filter(|p|!wanted.contains(*p)).cloned().collect::<Vec<_>>();
    let checks=neverruntime::check_files_with_preset(&manifest,&root,component_preset.as_deref()).await?;
    let missing:HashSet<_>=checks.iter().filter(|f|f.status!="ok").map(|f|f.path.as_str()).collect();
    let download_files=plan.files.iter().filter(|f|missing.contains(f.path.as_str())).map(|f|f.path.clone()).collect();
    let download_bytes_upper_bound=plan.files.iter().filter(|f|missing.contains(f.path.as_str())).map(|f|f.size).sum();
    let total_selected_bytes=plan.files.iter().map(|f|f.size).sum();
    Ok(ComponentDiff0247{installed_preset,added_files,removed_files,download_files,
        download_bytes_upper_bound,total_selected_bytes,plan_sha256:plan.sha256})
}

#[tauri::command]
async fn launch_minecraft(
    request: LaunchMinecraftRequest,
    supervisor: tauri::State<'_, ProcessSupervisor>,
    neverguard: tauri::State<'_, NeverGuardSupervisor>,
) -> Result<ProcessStatus, String> {
    let LaunchMinecraftRequest {
        manifest, root, java_path, username, minecraft_credentials, pinned_public_key, preferences, component_preset,
    } = request;
    #[cfg(windows)]
    {
        let status = neverguard.ensure_started().await?;
        if !status.authenticated || status.state != "ready" {
            return Err("launch заблокирован: NeverGuard Windows boundary не authenticated/ready".to_string());
        }
        if !status.process_policy_enforced
            || status.process_policy_version != NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION
        {
            return Err("launch заблокирован: NeverGuard Windows runtime/process policy не enforced".to_string());
        }
        if !status.hardening_enforced
            || status.hardening_version != NEVERGUARD_WINDOWS_HARDENING_VERSION
            || !status.secure_pipe_acl
            || !status.lifetime_job_enforced
            || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        {
            return Err("launch заблокирован: NeverGuard Windows production hardening verification failed".to_string());
        }
        neverguard.ping().await?;
        let process_policy = neverguard
            .process_policy()
            .await
            .map_err(|err| format!("launch заблокирован: NeverGuard Windows process policy verification failed: {err}"))?;
        if !process_policy.enforced
            || process_policy.policy_version != NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION
        {
            return Err("launch заблокирован: NeverGuard Windows process policy report rejected".to_string());
        }
        neverguard
            .integrity_evidence()
            .await
            .map_err(|err| format!("launch заблокирован: NeverGuard Windows Integrity Evidence v1 недоступен: {err}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        let status = neverguard.ensure_started().await?;
        if !status.authenticated || status.state != "ready" {
            return Err("launch заблокирован: NeverGuard Linux boundary не authenticated/ready".to_string());
        }
        if !status.process_policy_enforced || status.process_policy_version != NEVERGUARD_LINUX_PROCESS_POLICY_VERSION {
            return Err("launch заблокирован: NeverGuard Linux runtime/process policy не enforced".to_string());
        }
        if !status.hardening_enforced || status.hardening_version != NEVERGUARD_LINUX_HARDENING_VERSION
            || !status.secure_pipe_acl || !status.lifetime_job_enforced
            || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        {
            return Err("launch заблокирован: NeverGuard Linux production hardening verification failed".to_string());
        }
        neverguard.ping().await?;
        let policy = neverguard.process_policy().await
            .map_err(|err| format!("launch заблокирован: NeverGuard Linux process policy verification failed: {err}"))?;
        if !policy.enforced || policy.policy_version != NEVERGUARD_LINUX_PROCESS_POLICY_VERSION || policy.linux.is_none() {
            return Err("launch заблокирован: NeverGuard Linux process policy report rejected".to_string());
        }
        neverguard.integrity_evidence().await
            .map_err(|err| format!("launch заблокирован: NeverGuard Linux Integrity Evidence v1 недоступен: {err}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        let status = neverguard.ensure_started().await?;
        if !status.authenticated || status.state != "ready" {
            return Err("launch заблокирован: NeverGuard macOS boundary не authenticated/ready".to_string());
        }
        if !status.process_policy_enforced || status.process_policy_version != NEVERGUARD_MACOS_PROCESS_POLICY_VERSION {
            return Err("launch заблокирован: NeverGuard macOS runtime/process policy не enforced".to_string());
        }
        if !status.hardening_enforced || status.hardening_version != NEVERGUARD_MACOS_HARDENING_VERSION
            || !status.secure_pipe_acl || !status.lifetime_job_enforced
            || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        {
            return Err("launch заблокирован: NeverGuard macOS production hardening verification failed".to_string());
        }
        neverguard.ping().await?;
        let policy = neverguard.process_policy().await
            .map_err(|err| format!("launch заблокирован: NeverGuard macOS process policy verification failed: {err}"))?;
        if !policy.enforced || policy.policy_version != NEVERGUARD_MACOS_PROCESS_POLICY_VERSION || policy.macos.is_none() {
            return Err("launch заблокирован: NeverGuard macOS process policy report rejected".to_string());
        }
        neverguard.integrity_evidence().await
            .map_err(|err| format!("launch заблокирован: NeverGuard macOS Integrity Evidence v1 недоступен: {err}"))?;
    }
    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    let _ = &neverguard;

    neverruntime::transactional_release::ensure_active_preset(&manifest, &PathBuf::from(&root), &pinned_public_key, component_preset.as_deref()).await?;
    // Offline launch is strictly a replay of the verified on-disk release.
    // A caller cannot turn any arbitrary signed online manifest into an
    // offline entitlement just by setting preferences.offline = true.
    if preferences.as_ref().map(|p| p.offline).unwrap_or(false) {
        let cached = load_cached_desktop_manifest(
            root.clone(), pinned_public_key.clone(), manifest.project_id.clone(),
            manifest.profile_id.clone(), manifest.channel.clone(),
        ).await?;
        if cached.version != manifest.version ||
            cached.signature.as_ref().map(|s| s.signature.as_str()) != manifest.signature.as_ref().map(|s| s.signature.as_str()) {
            return Err("offline launch requires the exact cached signed release".into());
        }
    }
    if let Some(credentials) = minecraft_credentials {
        if let Some(p) = preferences {
            supervisor.start_authenticated_with_preferences(&manifest, &PathBuf::from(root), java_path, credentials, p, &pinned_public_key).await
        } else { supervisor.start_authenticated(&manifest, &PathBuf::from(root), java_path, credentials, &pinned_public_key).await }
    } else {
        match preferences {
            Some(p) if p.offline => supervisor.start_with_preferences(&manifest, &PathBuf::from(root), java_path, username, p, &pinned_public_key).await,
            _ => Err("online launch requires authenticated credentials; offline must be explicitly authorized".into()),
        }
    }
}

#[tauri::command]
async fn neverguard_guard_attestation(
    request: GuardAttestationRequest,
    neverguard: tauri::State<'_, NeverGuardSupervisor>,
) -> Result<GuardAttestationSubmission, String> {
    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    {
        let _ = (request, neverguard);
        return Err("Guard Attestation production implementation доступна только для Windows, Linux и macOS".to_string());
    }
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        let GuardAttestationRequest {
            backend_url, user_id, device_id, session_id, binding_epoch, launcher_version,
            challenge_id, challenge, challenge_expires_at,
        } = request;
        let attestation = neverguard.remote_attestation(&challenge_id, &challenge).await?;
        let evidence_sha256 = attestation.evidence.evidence_sha256.clone();
        let guard_sha256 = attestation.evidence.guard.image_sha256.clone();
        let launcher_sha256 = attestation.evidence.launcher.image_sha256.clone();
        let attestation_sha256 = attestation.attestation_sha256.clone();
        let submission_launcher_version = launcher_version.clone();
        let signing = tokio::task::spawn_blocking(move || {
            device_keys::sign_guard_attestation(device_keys::GuardAttestationSignRequest {
                backend_url,
                user_id,
                device_id,
                session_id,
                binding_epoch,
                launcher_version,
                challenge_id,
                challenge,
                challenge_expires_at,
                attestation_sha256,
                evidence_sha256,
                guard_sha256,
                launcher_sha256,
            })
        })
        .await
        .map_err(|e| format!("Guard Attestation device signing task завершилась ошибкой: {e}"))??;
        if signing.key_algorithm != "p256" || signing.key_binding != "hardware" || !signing.hardware_bound {
            return Err("Guard Attestation signer не является hardware-bound P-256 identity".to_string());
        }
        Ok(GuardAttestationSubmission {
            launcher_version: submission_launcher_version,
            attestation,
            signature: signing.signature,
            fingerprint: signing.fingerprint,
            key_algorithm: signing.key_algorithm,
            key_binding: signing.key_binding,
            hardware_provider: signing.hardware_provider,
            hardware_bound: signing.hardware_bound,
        })
    }
}


#[tauri::command]
async fn neverguard_guard_attestation_v2(
    request: GuardAttestationV2Request,
    neverguard: tauri::State<'_, NeverGuardSupervisor>,
    supervisor: tauri::State<'_, ProcessSupervisor>,
) -> Result<GuardAttestationV2Submission, String> {
    #[cfg(not(windows))]
    {
        let _ = (request, neverguard, supervisor);
        Err("Guard Attestation v2 continuous evidence доступна только для Windows".to_string())
    }
    #[cfg(windows)]
    {
        let GuardAttestationV2Request {
            backend_url, user_id, device_id, session_id, binding_epoch, launcher_version,
            challenge_id, challenge, challenge_expires_at, process_id,
        } = request;
        let process_status = supervisor.status(&process_id).await
            .map_err(|err| format!("Guard Attestation v2 runtime status недоступен: {err}"))?;
        let continuous_evidence = neverruntime::collect_windows_continuous_evidence_v2(&process_id, &process_status)?;
        let base_attestation = neverguard.remote_attestation(&challenge_id, &challenge).await?;
        let attestation = neverruntime::build_windows_attestation_v2(
            challenge_id.clone(),
            &challenge,
            base_attestation,
            continuous_evidence,
        )?;
        let continuous_evidence_sha256 = attestation.continuous_evidence.evidence_sha256.clone();
        let base_attestation_sha256 = attestation.base_attestation.attestation_sha256.clone();
        let runtime_pid = attestation.continuous_evidence.runtime_pid;
        let attestation_sha256 = attestation.attestation_sha256.clone();
        let submission_launcher_version = launcher_version.clone();
        let signing = tokio::task::spawn_blocking(move || {
            device_keys::sign_guard_attestation_v2(device_keys::GuardAttestationV2SignRequest {
                backend_url,
                user_id,
                device_id,
                session_id,
                binding_epoch,
                launcher_version,
                challenge_id,
                challenge,
                challenge_expires_at,
                attestation_sha256,
                continuous_evidence_sha256,
                base_attestation_sha256,
                runtime_pid,
            })
        })
        .await
        .map_err(|e| format!("Guard Attestation v2 device signing task завершилась ошибкой: {e}"))??;
        Ok(GuardAttestationV2Submission {
            launcher_version: submission_launcher_version,
            attestation,
            signature: signing.signature,
            fingerprint: signing.fingerprint,
            key_algorithm: signing.key_algorithm,
            key_binding: signing.key_binding,
            hardware_provider: signing.hardware_provider,
            hardware_bound: signing.hardware_bound,
        })
    }
}


fn create_staged_updater_helper02310(helper: &std::path::Path, bin_dir: &std::path::Path) -> Result<PathBuf, String> {
    let helper_meta = std::fs::symlink_metadata(helper).map_err(|e| e.to_string())?;
    if !helper_meta.file_type().is_file() || helper_meta.file_type().is_symlink() {
        return Err("unsafe native updater helper".into());
    }
    // Self-update must not overwrite the executable image of the running updater.
    // Execute a private staged copy instead of the adjacent live CLI binary.
    // A subsequent update cleans stale copies after their processes have exited.
    let helper_stage_root = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
            .ok_or("LOCALAPPDATA unavailable for updater staging")?
            .join("NeverLauncher").join("updater-helpers")
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(PathBuf::from)
            .ok_or("HOME unavailable for updater staging")?
            .join("Library").join("Caches").join("NeverLauncher").join("updater-helpers")
    } else {
        std::env::var_os("XDG_RUNTIME_DIR").or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from).ok_or("no private user directory for updater staging")?
            .join(".neverlauncher").join("updater-helpers")
    };
    std::fs::create_dir_all(&helper_stage_root)
        .map_err(|e| format!("не удалось подготовить updater helper staging: {e}"))?;
    let stage_meta = std::fs::symlink_metadata(&helper_stage_root).map_err(|e| e.to_string())?;
    if !stage_meta.file_type().is_dir() || stage_meta.file_type().is_symlink() {
        return Err("updater staging directory is not a safe directory".into());
    }
    for entry in std::fs::read_dir(&helper_stage_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            // Failed cleanup must not stop the current update (Windows file locks).
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let helper_stage_dir = helper_stage_root.join(hex::encode(nonce));
    std::fs::create_dir(&helper_stage_dir).map_err(|e| format!("updater staging: {e}"))?;
    let staged_helper = helper_stage_dir.join(launcher_update_helper_name());
    std::fs::copy(&helper, &staged_helper).map_err(|e| format!("updater helper copy: {e}"))?;
    let copied = std::fs::metadata(&staged_helper).map_err(|e| e.to_string())?;
    if !copied.is_file() || copied.len() != helper_meta.len() {
        return Err("updater helper staging verification failed".into());
    }
    fn digest_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
        use std::io::Read;
        let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut hash = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 { break; }
            hash.update(&buf[..n]);
        }
        Ok(hash.finalize().to_vec())
    }
    if digest_file(helper)? != digest_file(&staged_helper)? {
        return Err("staged updater helper SHA-256 mismatch".into());
    }
    Ok(staged_helper)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LauncherUpdateScheduleResult {
    status: String,
    updater_pid: u32,
    package_path: String,
    message: String,
}

fn launcher_update_helper_name() -> &'static str {
    if cfg!(target_os = "windows") { "neverlauncher-cli.exe" } else { "neverlauncher-cli" }
}

fn validate_update_sha256(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expectedSha256 должен быть SHA-256 в hex (64 символа)".into());
    }
    Ok(value)
}

#[tauri::command]
async fn install_launcher_update(
    package_path: String,
    expected_sha256: String,
    neverguard: tauri::State<'_, NeverGuardSupervisor>,
    app: tauri::AppHandle,
) -> Result<LauncherUpdateScheduleResult, String> {
    let expected_sha256 = validate_update_sha256(&expected_sha256)?;
    let package = fs::canonicalize(PathBuf::from(package_path.trim()))
        .await
        .map_err(|e| format!("update package недоступен: {e}"))?;
    let package_meta = fs::symlink_metadata(&package).await.map_err(|e| e.to_string())?;
    if !package_meta.file_type().is_file() || package_meta.file_type().is_symlink() || package_meta.len() == 0 {
        return Err("update package должен быть непустым обычным файлом, не symlink".into());
    }

    let current_exe = std::env::current_exe().map_err(|e| format!("не удалось определить Desktop executable: {e}"))?;
    let current_exe = std::fs::canonicalize(&current_exe).map_err(|e| format!("не удалось canonicalize Desktop executable: {e}"))?;
    let bin_dir = current_exe.parent().ok_or_else(|| "Desktop executable не имеет родительского каталога".to_string())?;
    let helper = if cfg!(target_os = "macos") {
        let contents = bin_dir.parent().ok_or_else(|| "macOS Desktop executable не находится внутри Contents/MacOS".to_string())?;
        let canonical = contents.join("Helpers").join(launcher_update_helper_name());
        if canonical.is_file() { canonical } else { bin_dir.join(launcher_update_helper_name()) }
    } else {
        bin_dir.join(launcher_update_helper_name())
    };
    let helper_meta = std::fs::symlink_metadata(&helper).map_err(|e| format!("transactional updater helper отсутствует {}: {e}", helper.display()))?;
    if !helper_meta.file_type().is_file() || helper_meta.file_type().is_symlink() || helper_meta.len() == 0 {
        return Err(format!("transactional updater helper небезопасен: {}", helper.display()));
    }

    let staged_helper = create_staged_updater_helper02310(&helper, bin_dir)?;
    // Guard удерживает дескрипторы и IPC, из-за которых Windows может считать исполняемый файл занятым.
    // Остановите его до того, как внешний помощник начнёт ожидание Desktop и выполнение транзакции.
    neverguard.shutdown().await.map_err(|e| format!("не удалось остановить NeverGuard перед обновлением: {e}"))?;

    let parent_pid = std::process::id().to_string();
    let mut command = Command::new(&staged_helper);
    command
        .arg("update")
        .arg("components")
        .arg("--package")
        .arg(&package)
        .arg("--expected-sha256")
        .arg(&expected_sha256)
        .arg("--current-desktop")
        .arg(&current_exe)
        .arg("--wait-pid")
        .arg(&parent_pid)
        .arg("--restart")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().map_err(|e| format!("не удалось запустить transactional updater helper: {e}"))?;
    let updater_pid = child.id().ok_or_else(|| "updater helper запущен без process id".to_string())?;
    drop(child);

    // Верните результат планирования в интерфейс, затем завершите процесс, чтобы помощник мог
    // атомарно заменить исполняемый файл Desktop или пакет приложения во всех поддерживаемых ОС.
    let exit_handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        exit_handle.exit(0);
    });

    Ok(LauncherUpdateScheduleResult {
        status: "scheduled".into(),
        updater_pid,
        package_path: package.to_string_lossy().to_string(),
        message: "Desktop/Guard/Runtime update передан внешнему transactional updater; Desktop будет перезапущен после commit".into(),
    })
}

#[tauri::command]
async fn neverguard_status(neverguard: tauri::State<'_, NeverGuardSupervisor>) -> Result<NeverGuardStatus, String> {
    neverguard.status().await
}
#[tauri::command]
async fn neverguard_integrity_evidence(neverguard: tauri::State<'_, NeverGuardSupervisor>) -> Result<NeverGuardIntegrityEvidence, String> {
    neverguard.integrity_evidence().await
}
#[tauri::command]
async fn neverguard_process_policy(neverguard: tauri::State<'_, NeverGuardSupervisor>) -> Result<GuardProcessPolicyReport, String> {
    neverguard.process_policy().await
}
#[tauri::command]
async fn runtime_process_status(process_id: String, supervisor: tauri::State<'_, ProcessSupervisor>) -> Result<ProcessStatus, String> { supervisor.status(&process_id).await }
#[tauri::command]
async fn runtime_processes(supervisor: tauri::State<'_, ProcessSupervisor>) -> Result<Vec<ProcessStatus>, String> { Ok(supervisor.list().await) }
#[tauri::command]
async fn stop_runtime_process(process_id: String, supervisor: tauri::State<'_, ProcessSupervisor>) -> Result<ProcessStatus, String> { supervisor.stop(&process_id).await }
#[tauri::command]
async fn load_launch_history(root: String) -> Result<Vec<LaunchHistoryEntry>, String> { neverruntime::load_launch_history(&PathBuf::from(root)).await }

#[tauri::command]
async fn validate_desktop_settings(game_directory: String, java_path: Option<String>, memory_mb: u32) -> Result<SettingsCheckResult, String> {
    let game_dir = PathBuf::from(game_directory.trim());
    if game_dir.as_os_str().is_empty() { return Ok(SettingsCheckResult { valid: false, status: "invalid".into(), messages: vec!["каталог клиента не указан".into()], normalized_game_directory: String::new() }); }
    fs::create_dir_all(&game_dir).await.map_err(|e| format!("не удалось создать каталог клиента: {e}"))?;
    let mut messages = vec![format!("каталог клиента готов: {}", game_dir.display())];
    let memory_valid = (512..=32768).contains(&memory_mb); if !memory_valid { messages.push(format!("некорректный объём памяти: {memory_mb} MB")); }
    if let Some(java) = java_path.filter(|v| !v.trim().is_empty()) { messages.push(format!("Java: {}", java)); }
    Ok(SettingsCheckResult { valid: memory_valid, status: if memory_valid { "ready" } else { "invalid" }.into(), messages, normalized_game_directory: game_dir.to_string_lossy().to_string() })
}

#[tauri::command]
async fn export_diagnostics_bundle(root: String, launcher_version: String, backend_url: String, stage: String, logs: Vec<String>) -> Result<DiagnosticsExportResult, String> {
    let dir = PathBuf::from(root).join("diagnostics"); fs::create_dir_all(&dir).await.map_err(|e| e.to_string())?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let path = dir.join(format!("neverlauncher-desktop-diagnostics-{timestamp}.json"));
    let safe_logs = logs.into_iter().map(|v| { let l=v.to_lowercase(); if l.contains("token")||l.contains("password")||l.contains("secret")||l.contains("authorization") { "[redacted]".into() } else { v } }).collect::<Vec<String>>();
    let payload = serde_json::json!({"schemaVersion":"1.0","launcherVersion":launcher_version,"backendUrl":backend_url.split('?').next().unwrap_or(&backend_url),"stage":stage,"runtime":"NeverRuntime","os":std::env::consts::OS,"arch":std::env::consts::ARCH,"logs":safe_logs});
    fs::write(&path, serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
    Ok(DiagnosticsExportResult { path: path.to_string_lossy().to_string(), message: format!("diagnostic bundle сохранён: {}", path.display()) })
}

#[tauri::command]
async fn open_game_directory(root: String) -> Result<String, String> {
    let root = PathBuf::from(root); fs::create_dir_all(&root).await.map_err(|e| e.to_string())?;
    let mut command = if cfg!(target_os="windows") { let mut c=Command::new("explorer"); c.arg(&root); c } else if cfg!(target_os="macos") { let mut c=Command::new("open"); c.arg(&root); c } else { let mut c=Command::new("xdg-open"); c.arg(&root); c };
    command.spawn().map_err(|e| format!("не удалось открыть каталог клиента: {e}"))?; Ok(root.to_string_lossy().to_string())
}

// Startup is fail-closed: do not initialize Guard or the launcher UI with a
// partially switched component set. Recovery runs in a separate executable
// image, after this Desktop process has exited (Windows sharing violations).
fn recover_components_before_desktop02310() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = std::fs::canonicalize(exe).map_err(|e| e.to_string())?;
    let bin_dir = exe.parent().ok_or("Desktop executable has no parent directory")?;
    let root = if cfg!(target_os = "macos") {
        bin_dir.parent().and_then(std::path::Path::parent).and_then(std::path::Path::parent)
            .ok_or("invalid macOS .app path")?
    } else { bin_dir };
    let helper = if cfg!(target_os = "macos") {
        bin_dir.parent().ok_or("invalid macOS Contents path")?.join("Helpers").join(launcher_update_helper_name())
    } else { bin_dir.join(launcher_update_helper_name()) };
    if !helper.is_file() { return Ok(()); } // Prestarter-only layout has no CLI updater.
    let hm = std::fs::symlink_metadata(&helper).map_err(|e| e.to_string())?;
    if !hm.file_type().is_file() || hm.file_type().is_symlink() {
        return Err("unsafe installed updater helper".into());
    }
    let status = std::process::Command::new(&helper)
        .args(["update", "status", "--root"])
        .arg(root)
        .output().map_err(|e| format!("component recovery status failed: {e}"))?;
    if !status.status.success() {
        return Err(format!("component journal check failed: {}", String::from_utf8_lossy(&status.stderr)));
    }
    let report: serde_json::Value = serde_json::from_slice(&status.stdout)
        .map_err(|e| format!("invalid component update status: {e}"))?;
    if report.get("status").and_then(serde_json::Value::as_str) != Some("recovery-required") { return Ok(()); }
    let staged = create_staged_updater_helper02310(&helper, bin_dir)?;
    std::process::Command::new(staged)
        .args(["update", "recover", "--root"])
        .arg(root)
        .args(["--wait-pid", &std::process::id().to_string(), "--restart-desktop"])
        .arg(&exe)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|e| format!("could not start component recovery: {e}"))?;
    std::process::exit(0);
}

fn main() {
    if let Err(err) = recover_components_before_desktop02310() {
        eprintln!("NeverLauncher component-set recovery gate failed: {err}");
        std::process::exit(71);
    }
    #[cfg(windows)]
    if let Err(err) = neverruntime::ensure_windows_production_hardening() {
        eprintln!("NeverLauncher Desktop Windows production hardening failed: {err}");
        std::process::exit(70);
    }

    #[cfg(target_os = "linux")]
    if let Err(err) = neverruntime::linux_policy::ensure_linux_production_hardening() {
        eprintln!("NeverLauncher Desktop Linux production hardening failed: {err}");
        std::process::exit(70);
    }

    #[cfg(target_os = "macos")]
    if let Err(err) = neverruntime::macos_policy::ensure_macos_production_hardening() {
        eprintln!("NeverLauncher Desktop macOS production hardening failed: {err}");
        std::process::exit(70);
    }

    if let Err(err)=initialize_desktop_game_trust_02312(){
        eprintln!("NeverLauncher Desktop trust configuration refused: {err}");
        std::process::exit(71);
    }
    tauri::Builder::default()
        .manage(ProcessSupervisor::new())
        .manage(NeverGuardSupervisor::new())
        .setup(|app| { println!("NeverLauncher Desktop {} / NeverRuntime", env!("CARGO_PKG_VERSION")); let _=app.handle(); Ok(()) })
        .invoke_handler(tauri::generate_handler![load_desktop_config,save_desktop_config,reset_desktop_binding,store_auth_session,load_auth_session,delete_auth_session,ensure_device_key,device_key_status,sign_device_payload,attest_device_payload,stage_device_key_replacement,staged_device_key_status,sign_staged_device_replacement,sign_current_device_replacement,commit_staged_device_key,abort_staged_device_key,bind_device_key,sign_session_refresh,reset_device_key,delete_device_key,load_manifest,preview_components_0244,preview_component_changes_0247,installed_component_choice_0247,save_installed_component_choice_0247,active_selection_02410,attest_verified_component_plan_02412,export_component_selection_02410,preview_component_migration_02410,preview_import_component_selection_02410,cache_desktop_manifest,load_cached_desktop_manifest,verify_manifest_signature,check_files,validate_desktop_settings,export_diagnostics_bundle,open_game_directory,download_missing_files,repair_client,pending_download_job,control_download_job,resume_download_job,rollback_client_release,recover_client_release,clean_unused_files,prepare_profile_directory,check_java,ensure_managed_java,ensure_profile_managed_java,build_launch_plan,launch_minecraft,neverguard_status,neverguard_integrity_evidence,neverguard_process_policy,neverguard_guard_attestation,neverguard_guard_attestation_v2,install_launcher_update,runtime_process_status,runtime_processes,stop_runtime_process,load_launch_history,desktop_extension_platform_info])
        .run(tauri::generate_context!()).expect("ошибка запуска Tauri-приложения");
}
