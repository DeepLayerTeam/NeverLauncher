mod tpm_wire_0313;
#[cfg(target_os = "linux")]
mod tpm_linux_0314;
#[cfg(target_os = "windows")]
mod tpm_windows_0313;
mod discord_presence_0308;
mod sentry_diagnostics_0309;
mod diagnostics_bundle_03510;
mod device_keys;
mod signed_first_run_0352;
mod hwid_risk_0299;
mod official_identity_0262;
mod official_browser_0263;
mod official_exchange_0265;
mod official_verification_0266;
mod game_guard_watchdog_0438;

use runtime::{
    self, CleanUnusedResult, DownloadResult, FileCheckResult, GuardProcessPolicyReport, JavaInfoResult,
    LaunchHistoryEntry, LaunchPlan, ManagedJavaResult, Manifest, MinecraftLaunchCredentials,
    GuardIntegrityEvidence, GuardRemoteAttestation, GuardRemoteAttestationV2, GuardStatus, GuardSupervisor,
    ProcessStatus, ProcessSupervisor, RepairResult, SignatureCheckResult,
};
#[cfg(target_os = "linux")]
use runtime::{GUARD_LINUX_HARDENING_VERSION, GUARD_LINUX_PROCESS_POLICY_VERSION};
#[cfg(target_os = "macos")]
use runtime::{GUARD_MACOS_HARDENING_VERSION, GUARD_MACOS_PROCESS_POLICY_VERSION};
#[cfg(windows)]
use runtime::{GUARD_WINDOWS_HARDENING_VERSION, GUARD_WINDOWS_PROCESS_POLICY_VERSION};
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

// 0.35.7: Состояние ОС и окна ведётся нативным кодом; webview лишь отображает его.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopNativeUI0357 {
    os: &'static str,
    scale_factor: f64,
}

#[tauri::command]
fn desktop_native_ui_info_0357(window: tauri::WebviewWindow) -> Result<DesktopNativeUI0357, String> {
    let factor = window.scale_factor().map_err(|err| err.to_string())?;
    if !factor.is_finite() || factor <= 0.0 {return Err("Недопустимый масштаб нативного экрана".into());}
    Ok(DesktopNativeUI0357 { os: std::env::consts::OS, scale_factor: factor })
}

#[derive(Debug, PartialEq, Eq)]
enum DesktopWindowAction0357 {Minimize, ToggleMaximized}
fn parse_desktop_window_action_0357(action: &str) -> Result<DesktopWindowAction0357, String> {
    match action {
        "minimize" => Ok(DesktopWindowAction0357::Minimize),
        "toggleMaximized" => Ok(DesktopWindowAction0357::ToggleMaximized),
        _ => Err("Неподдерживаемое действие с окном Desktop".into()),
    }
}

#[tauri::command]
fn desktop_window_action_0357(window: tauri::WebviewWindow, action: String) -> Result<(), String> {
    match parse_desktop_window_action_0357(&action)? {
        DesktopWindowAction0357::Minimize => window.minimize().map_err(|err| err.to_string()),
        DesktopWindowAction0357::ToggleMaximized => {
            if window.is_maximized().map_err(|err| err.to_string())? {
                window.unmaximize().map_err(|err| err.to_string())
            } else {
                window.maximize().map_err(|err| err.to_string())
            }
        }
    }
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
        bridge_protocol: "extensions.desktop-rpc.v1".to_string(),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuardAttestationSubmission {
    launcher_version: String,
    attestation: GuardRemoteAttestation,
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
    attestation: GuardRemoteAttestationV2,
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

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LaunchRealm0269 { Official, Yggdrasil, Offline }

// Проверяйте весь выбор до обращения к Runtime ОС. Вызывающий код JS
// не может заявить «офлайн», подставив токен доступа, или выдать токен проекта за MSA.
fn validate_launch_realm_0269(
    mode: LaunchRealm0269,
    credentials: Option<&MinecraftLaunchCredentials>,
    official: bool,
    preferences: Option<&runtime::LaunchPreferences>,
) -> Result<(), String> {
    match mode {
        LaunchRealm0269::Official if official && credentials.is_none() &&
            !preferences.is_some_and(|p|p.offline) => Ok(()),
        LaunchRealm0269::Yggdrasil if !official &&
            credentials.is_some_and(|c|c.user_type=="mojang" && !c.auth_server_base_url.is_empty()) &&
            !preferences.is_some_and(|p|p.offline) => Ok(()),
        LaunchRealm0269::Offline if !official && credentials.is_none() &&
            preferences.is_some_and(|p|p.offline) => Ok(()),
        _ => Err("Режим авторизации запуска Minecraft не соответствует учётным данным".into()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaunchMinecraftRequest {
    manifest: Manifest,
    auth_mode: LaunchRealm0269,
    root: String,
    java_path: Option<String>,
    username: Option<String>,
    minecraft_credentials: Option<MinecraftLaunchCredentials>,
    #[serde(default)]
    official_identity: Option<official_identity_0262::LaunchContext>,
    pinned_public_key: String,
    #[serde(default)]
    preferences: Option<runtime::LaunchPreferences>,
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

const KEYRING_SERVICE: &str = "Launcher Desktop";

fn auth_keyring_username(backend_url: &str) -> Result<String, String> {
    let normalized = backend_url.trim().trim_end_matches('/').to_ascii_lowercase();
    if normalized.is_empty() { return Err("Для защищённого хранения учётных данных необходим URL серверной части".into()); }
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    Ok(format!("backend:{}", hex::encode(hasher.finalize())))
}

#[tauri::command]
async fn store_auth_session(backend_url: String, session: SecureAuthSession) -> Result<(), String> {
    let username = auth_keyring_username(&backend_url)?;
    let secret = serde_json::to_string(&session).map_err(|e| format!("не удалось сериализовать сеанс авторизации: {e}"))?;
    tokio::task::spawn_blocking(move || {
        let mut secret = secret;
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, &username).map_err(|e| format!("Защищённое хранилище учётных данных недоступно: {e}"))?;
        let result = entry.set_password(&secret).map_err(|e| format!("Не удалось сохранить сеанс авторизации в защищённом хранилище ОС: {e}"));
        secret.zeroize();
        result
    }).await.map_err(|e| format!("Задача безопасного хранения учётных данных завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn load_auth_session(backend_url: String) -> Result<Option<SecureAuthSession>, String> {
    let username = auth_keyring_username(&backend_url)?;
    tokio::task::spawn_blocking(move || {
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, &username).map_err(|e| format!("Защищённое хранилище учётных данных недоступно: {e}"))?;
        match entry.get_password() {
            Ok(mut secret) => {
                let parsed = serde_json::from_str::<SecureAuthSession>(&secret).map(Some).map_err(|e| format!("Сеанс авторизации в защищённом хранилище ОС повреждён: {e}"));
                secret.zeroize();
                parsed
            },
            Err(keyring::v1::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("Не удалось прочитать сеанс авторизации из защищённого хранилища ОС: {e}")),
        }
    }).await.map_err(|e| format!("Задача безопасного хранения учётных данных завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn delete_auth_session(backend_url: String) -> Result<(), String> {
    let username = auth_keyring_username(&backend_url)?;
    tokio::task::spawn_blocking(move || {
        let entry = keyring::v1::Entry::new(KEYRING_SERVICE, &username).map_err(|e| format!("Защищённое хранилище учётных данных недоступно: {e}"))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("Не удалось удалить сеанс авторизации из защищённого хранилища ОС: {e}")),
        }
    }).await.map_err(|e| format!("Задача безопасного хранения учётных данных завершилась ошибкой: {e}"))?
}


#[tauri::command]
async fn windows_tpm_certify_0313(
    backend_url: String, user_id: String, device_id: String,
    tpm_extra_data_sha256: String, ak_key_name: String,
    ak_certificate_pem: String, intermediates_pem: Vec<String>,
) -> Result<serde_json::Value, String> {
    tokio::task::spawn_blocking(move || {
        device_keys::windows_tpm_certify_0313(
            &backend_url, &user_id, &device_id, &tpm_extra_data_sha256,
            &ak_key_name, &ak_certificate_pem, intermediates_pem,
        )
    }).await.map_err(|e| format!("Ошибка обработчика свидетельств TPM: {e}"))?
}

#[tauri::command]
async fn linux_tpm_certify_0314(
    backend_url: String, user_id: String, device_id: String,
    tpm_extra_data_sha256: String, ak_handle: String,
    ak_certificate_pem: String, intermediates_pem: Vec<String>,
) -> Result<serde_json::Value,String> {
    tokio::task::spawn_blocking(move || {
        device_keys::linux_tpm_certify_0314(
            &backend_url,&user_id,&device_id,&tpm_extra_data_sha256,
            &ak_handle,&ak_certificate_pem,intermediates_pem,
        )
    }).await.map_err(|e|format!("Ошибка обработчика свидетельств TPM в Linux: {e}"))?
}

#[tauri::command]
async fn measured_boot_quote_0315(
 backend_url:String,user_id:String,device_id:String,tpm_extra_data_sha256:String,
 pcr_selection:String,ak_key:String,ak_certificate_pem:String,intermediates_pem:Vec<String>,
)->Result<serde_json::Value,String>{
 tokio::task::spawn_blocking(move || device_keys::measured_boot_quote_0315(
  &backend_url,&user_id,&device_id,&tpm_extra_data_sha256,&pcr_selection,&ak_key,&ak_certificate_pem,intermediates_pem,
 )).await.map_err(|e|format!("Ошибка обработчика TPM Quote: {e}"))?
}

#[tauri::command]
async fn ensure_device_key(backend_url: String, user_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::ensure_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("Задача обработки ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn device_key_status(backend_url: String, user_id: String) -> Result<Option<DeviceKeyInfo>, String> {
    tokio::task::spawn_blocking(move || device_keys::device_key_status(&backend_url, &user_id))
        .await.map_err(|e| format!("Задача обработки ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn macos_trust_status_0316(backend_url: String, user_id: String) -> Result<device_keys::MacOSTrustStatus0316, String> {
    tokio::task::spawn_blocking(move || device_keys::macos_trust_status_0316(&backend_url, &user_id))
        .await.map_err(|e| format!("Ошибка обработчика проверки доверия macOS: {e}"))?
}

#[tauri::command]
async fn sign_device_payload(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_device_payload(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("Операция подписи ключом устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn attest_device_payload(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::attest_device_payload(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("Операция подписания аттестации устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_session_refresh(backend_url: String, user_id: String, session_id: String, device_id: String, binding_epoch: i64, refresh_token: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_session_refresh(&backend_url, &user_id, &session_id, &device_id, binding_epoch, &refresh_token))
        .await.map_err(|e| format!("Операция подписи обновления сеанса завершилась ошибкой: {e}"))?
}



#[tauri::command]
async fn stage_device_key_replacement(backend_url: String, user_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::stage_device_key_replacement(&backend_url, &user_id))
        .await.map_err(|e| format!("Операция подготовки ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn staged_device_key_status(backend_url: String, user_id: String) -> Result<Option<DeviceKeyInfo>, String> {
    tokio::task::spawn_blocking(move || device_keys::staged_device_key_status(&backend_url, &user_id))
        .await.map_err(|e| format!("Операция проверки состояния подготовленного ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_staged_device_replacement(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_staged_device_replacement(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("Операция подписи подготовленным ключом устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn sign_current_device_replacement(backend_url: String, user_id: String, payload: String) -> Result<DeviceSignatureResult, String> {
    tokio::task::spawn_blocking(move || device_keys::sign_current_device_replacement(&backend_url, &user_id, &payload))
        .await.map_err(|e| format!("Задача подписи при смене ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn commit_staged_device_key(backend_url: String, user_id: String, device_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::commit_staged_device_key(&backend_url, &user_id, &device_id))
        .await.map_err(|e| format!("Операция подтверждения ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn abort_staged_device_key(backend_url: String, user_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || device_keys::abort_staged_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("Операция отката ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn bind_device_key(backend_url: String, user_id: String, device_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::bind_device_key(&backend_url, &user_id, &device_id))
        .await.map_err(|e| format!("Операция привязки ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn reset_device_key(backend_url: String, user_id: String) -> Result<DeviceKeyInfo, String> {
    tokio::task::spawn_blocking(move || device_keys::reset_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("Операция сброса ключа устройства завершилась ошибкой: {e}"))?
}

#[tauri::command]
async fn delete_device_key(backend_url: String, user_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || device_keys::delete_device_key(&backend_url, &user_id))
        .await.map_err(|e| format!("Операция удаления ключа устройства завершилась ошибкой: {e}"))?
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
    // Сохраняйте выбор установленных подписанных компонентов между перезапусками.
    #[serde(default)] component_preset: String,
    #[serde(default)]
    discord_presence_enabled: bool,
    #[serde(default)] sentry_diagnostics_enabled: bool,
    #[serde(default)]
    discord_application_id: String,
    #[serde(default)]
    discord_action_url: String,
    #[serde(default)]
    config_path: String,
    #[serde(default)] onboarding_completed: bool,
    #[serde(default)] onboarding_bootstrap_digest: String,
    #[serde(flatten)] extra_preferences_0359: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopBindingResult { status: String, config_path: String, game_directory: String, message: String }

fn desktop_config_dir() -> Result<PathBuf, String> {
    if let Ok(value) = std::env::var("LAUNCHER_CONFIG_DIR") { if !value.trim().is_empty() { return Ok(PathBuf::from(value)); } }
    if cfg!(windows) { if let Ok(value) = std::env::var("APPDATA") { return Ok(PathBuf::from(value).join("Launcher")); } }
    if cfg!(target_os = "macos") { if let Ok(value) = std::env::var("HOME") { return Ok(PathBuf::from(value).join("Library").join("Application Support").join("Launcher")); } }
    if let Ok(value) = std::env::var("XDG_CONFIG_HOME") { return Ok(PathBuf::from(value).join("Launcher")); }
    if let Ok(value) = std::env::var("HOME") { return Ok(PathBuf::from(value).join(".config").join("Launcher")); }
    Ok(PathBuf::from(".launcher").join("config"))
}
fn desktop_config_path() -> Result<PathBuf, String> { Ok(desktop_config_dir()?.join("config.json")) }
// Расположение файла может задаваться ранее проверенным Prestarter;
// проверяющий модуль Rust всё равно сверяет его содержимое с pinnedPublicKey.
fn initialize_desktop_game_trust_02312() -> Result<(),String> {
    if std::env::var_os("LAUNCHER_GAME_TRUST_POLICY_FILE").is_some() {return Ok(())}
    let path=desktop_config_path()?;
    let bytes=match std::fs::read(&path) {Ok(b)=>b,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(()),Err(e)=>return Err(e.to_string())};
    let cfg:DesktopConfig=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
    if cfg.trust_policy_path.is_empty() {return Ok(())}
    let target=PathBuf::from(&cfg.trust_policy_path);
    if !target.is_absolute(){return Err("Путь к политике доверия должен быть абсолютным".into())}
    let meta=std::fs::symlink_metadata(&target).map_err(|e|e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len()>128*1024 {return Err("Небезопасный источник политики доверия".into())}
    std::env::set_var("LAUNCHER_GAME_TRUST_POLICY_FILE",&target);
    Ok(())
}

fn default_game_directory() -> String {
    let base = if cfg!(windows) { std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".")) }
    else if let Ok(home) = std::env::var("HOME") { PathBuf::from(home).join(".local").join("share") }
    else { PathBuf::from(".") };
    base.join("Launcher").join("projects").to_string_lossy().to_string()
}
fn default_screen_width_0229() -> u32 { 1280 }
fn default_screen_height_0229() -> u32 { 720 }
fn default_server_port_0229() -> u16 { 25565 }
fn default_desktop_config() -> DesktopConfig {
    DesktopConfig { schema_version: "1.0".into(), backend_url: String::new(), manifest_url: String::new(), project_id: String::new(), profile_id: String::new(), channel: "stable".into(), game_directory: default_game_directory(), java_path: String::new(), username: "Player".into(), memory_mb: 4096, pinned_public_key: String::new(), trust_policy_path: String::new(), server_id: String::new(), screen_width: 1280, screen_height: 720, fullscreen: false, auto_enter: false, server_host: String::new(), server_port: 25565, offline_enabled: false, component_preset:String::new(), discord_presence_enabled: false, sentry_diagnostics_enabled: false, discord_application_id: String::new(), discord_action_url: String::new(), config_path: String::new(), onboarding_completed:false, onboarding_bootstrap_digest:String::new(),extra_preferences_0359:serde_json::Map::new() }
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
    // Повреждённые или неподдерживаемые настройки не определяют состояние выпуска.
    if cfg.component_preset.len()>8192 || cfg.component_preset.bytes().any(|b|b<0x20||b==0x7f){
        cfg.component_preset.clear();
    }
    if cfg.discord_application_id.len() > 20 || cfg.discord_action_url.len() > 2048 {
        cfg.discord_presence_enabled = false;
        cfg.discord_application_id.clear();
        cfg.discord_action_url.clear();
    }
    cfg
}

fn validate_desktop_config_schema_0359(schema:&str)->Result<(),String>{
    match schema{"1.0"|"1.1"=>Ok(()), _=>Err(format!("Версия конфигурации Desktop {schema} не поддерживается; настройки не перезаписаны"))}
}
async fn preserve_legacy_config_0359(path:&std::path::Path)->Result<(),String>{
    let backup=path.with_file_name("config.pre-0359.json");
    match fs::symlink_metadata(&backup).await {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink()=>return Ok(()),
        Ok(_)=>return Err("Небезопасная резервная копия прежних настроек Desktop".into()),
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
        Err(e)=>return Err(e.to_string()),
    }
    let meta=fs::symlink_metadata(path).await.map_err(|e|e.to_string())?;
    if !meta.is_file()||meta.file_type().is_symlink()||meta.len()>1024*1024 {
        return Err("Небезопасный источник прежних настроек Desktop".into());
    }
    let bytes=fs::read(path).await.map_err(|e|e.to_string())?;
    use tokio::io::AsyncWriteExt;
    let mut options=fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] options.mode(0o600);
    let mut copy=match options.open(&backup).await {
        Ok(f)=>f,
        Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>{
            let meta=fs::symlink_metadata(&backup).await.map_err(|e|e.to_string())?;
            if !meta.is_file()||meta.file_type().is_symlink(){return Err("Конфликт с небезопасной резервной копией прежнего Desktop".into());}
            return Ok(());
        },
        Err(e)=>return Err(e.to_string()),
    };
    let result=async {copy.write_all(&bytes).await.map_err(|e|e.to_string())?;
        copy.sync_all().await.map_err(|e|e.to_string())?;Ok::<(),String>(())}.await;
    drop(copy);
    if result.is_err(){let _=fs::remove_file(backup).await;}
    result
}

// Подписанная привязка владельца применяется в нативном процессе при каждом чтении и
// записи. Renderer/localStorage не может изменить доверенный корень или направить пользователя
// к другому серверу, проекту, профилю или подписанному манифесту.
fn enforce_signed_binding_0352(cfg:&mut DesktopConfig, dir:&std::path::Path)->Result<Option<signed_first_run_0352::Provisioning0352>,String>{
    let signed=signed_first_run_0352::load(dir)?;
    if let Some(ref p)=signed {
        cfg.backend_url=p.backend_url.clone();
        cfg.manifest_url=p.manifest_url.clone();
        cfg.project_id=p.project_id.clone();
        cfg.profile_id=p.profile_id.clone();
        cfg.channel=p.channel.clone();
        cfg.pinned_public_key=p.pinned_public_key.clone();
        if !p.server_id.is_empty(){cfg.server_id=p.server_id.clone();}
        if !p.server_host.is_empty(){cfg.server_host=p.server_host.clone();}
        if p.server_port!=0{cfg.server_port=p.server_port;}
        if p.auto_enter{cfg.auto_enter=true;}
    }
    Ok(signed)
}
#[tauri::command]
async fn load_signed_provisioning_0352()->Result<Option<signed_first_run_0352::Provisioning0352>,String>{
    signed_first_run_0352::load(&desktop_config_dir()?)
}
#[tauri::command]
async fn load_desktop_config() -> Result<DesktopConfig, String> {
    let path = desktop_config_path()?;
    let config_existed=fs::symlink_metadata(&path).await.is_ok();
    let mut cfg = if config_existed { serde_json::from_slice::<DesktopConfig>(&fs::read(&path).await.map_err(|e| e.to_string())?).map_err(|e| format!("Конфигурация Desktop повреждена: {e}"))? } else { default_desktop_config() };
    cfg = normalize_desktop_config(cfg);
    validate_desktop_config_schema_0359(&cfg.schema_version)?;
    let verified=enforce_signed_binding_0352(&mut cfg,&desktop_config_dir()?)?;
    if let Some(p)=verified {
        // Завершение действительно только для точного bootstrap с подписью владельца.
        if cfg.onboarding_bootstrap_digest!=p.digest {cfg.onboarding_completed=false;}
    }
    if config_existed && cfg.schema_version=="1.0" {
        // Миграция выполняется один раз после проверки подписанной привязки. Записывающий модуль
        // атомарно заменяет файл и сохраняет исходные байты в точности.
        save_desktop_config_impl_0352(cfg.clone(),None).await?;
        cfg.schema_version="1.1".into();
    }
    cfg.config_path = path.to_string_lossy().to_string(); Ok(cfg)
}
async fn save_desktop_config_impl_0352(config: DesktopConfig, complete_for_digest: Option<String>) -> Result<DesktopBindingResult, String> {
    let path = desktop_config_path()?; let parent = path.parent().ok_or("Не удалось определить каталог конфигурации Desktop")?;
    fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
    let mut cfg = normalize_desktop_config(config); validate_desktop_config_schema_0359(&cfg.schema_version)?; cfg.schema_version = "1.1".into(); cfg.config_path = path.to_string_lossy().to_string();
    // Флаги завершения из renderer НЕ принимаются при сохранении настроек.
    cfg.onboarding_completed=false;
    let old=if let Ok(existing)=fs::read(&path).await {
        let stored=serde_json::from_slice::<DesktopConfig>(&existing).map_err(|e|format!("Существующая конфигурация Desktop повреждена: {e}"))?;
        validate_desktop_config_schema_0359(&stored.schema_version)?;
        Some(stored)
    }else{None};
    let signed=enforce_signed_binding_0352(&mut cfg,parent)?;
    if let Some(p)=signed {
        if let Some(ref desired)=complete_for_digest {
            if desired!=&p.digest {return Err("Подписанный bootstrap изменился во время проверки установки".into())}
        }
        cfg.onboarding_completed=complete_for_digest.is_some()||old.as_ref().map(|v|v.onboarding_completed&&v.onboarding_bootstrap_digest==p.digest).unwrap_or(false);
        cfg.onboarding_bootstrap_digest=p.digest;
    }else{
        cfg.onboarding_completed=false;
        cfg.onboarding_bootstrap_digest.clear();
    }
    // Защитите прежние настройки до первого обновления. Оригинал остаётся
    // авторитетным, пока новый файл не записан на диск и атомарно не заменён.
    if old.as_ref().is_some_and(|v|v.schema_version=="1.0") {
        preserve_legacy_config_0359(&path).await?;
    }
    let encoded=serde_json::to_vec_pretty(&cfg).map_err(|e|e.to_string())?;
    let temp=path.with_extension(format!("{}-{}.tmp",std::process::id(),rand::random::<u64>()));
    let result=async {
        use tokio::io::AsyncWriteExt;
        let mut options=fs::OpenOptions::new();options.write(true).create_new(true);
        #[cfg(unix)] options.mode(0o600);
        let mut f=options.open(&temp).await.map_err(|e|e.to_string())?;
        f.write_all(&encoded).await.map_err(|e|e.to_string())?;
        f.sync_all().await.map_err(|e|e.to_string())?;
        drop(f);
        fs::rename(&temp,&path).await.map_err(|e|e.to_string())?;
        Ok::<(),String>(())
    }.await;
    if result.is_err(){let _=fs::remove_file(&temp).await;}
    result?;
    Ok(DesktopBindingResult { status: "saved".into(), config_path: path.to_string_lossy().to_string(), game_directory: cfg.game_directory, message: "Привязка Desktop сохранена и проверена нативным механизмом доверия".into() })
}
#[tauri::command]
async fn save_desktop_config(config: DesktopConfig)->Result<DesktopBindingResult,String>{
    save_desktop_config_impl_0352(config,None).await
}

// Завершённый первый запуск подтверждается нативным проверяющим модулем по
// установленным файлам, а не флагом `onboardingCompleted: true`, управляемым renderer.
#[tauri::command]
async fn complete_first_run_0352(config:DesktopConfig,manifest:Manifest)->Result<DesktopBindingResult,String>{
    let signed=signed_first_run_0352::load(&desktop_config_dir()?)?
        .ok_or("Первый запуск без подписанного bundle запрещён")?;
    let mut cfg=normalize_desktop_config(config);
    enforce_signed_binding_0352(&mut cfg,&desktop_config_dir()?)?;
    if manifest.project_id!=signed.project_id||manifest.profile_id!=signed.profile_id||manifest.channel!=signed.channel{
        return Err("Установленный профиль не соответствует подписанной конфигурации владельца".into())
    }
    runtime::verify_manifest_signature(&manifest,&signed.pinned_public_key)?;
    let root=PathBuf::from(&cfg.game_directory);
    if !root.is_absolute(){return Err("Каталог игры должен быть абсолютным".into())}
    // Проверка первого запуска должна использовать тот же краткосрочный допуск сервера,
    // что и последующие установки. Иначе легальный мод с ограничением доступа не завершит
    // первичную настройку, а обход молча примет локально заявленные права.
    let grant=component_permissions_for_manifest_0392(&manifest,&signed.pinned_public_key).await?;
    let checks=runtime::component_catalog_0241::with_verified_component_scope_0392(grant,async {
        runtime::check_files_with_preset(&manifest,&root,
            if cfg.component_preset.is_empty(){None}else{Some(cfg.component_preset.as_str())}).await
    }).await?;
    if checks.is_empty()||checks.iter().any(|f|f.status!="ok"){
        return Err(format!("Установка не завершена: {} файлов отсутствуют или повреждены",
            checks.iter().filter(|f|f.status!="ok").count()))
    }
    save_desktop_config_impl_0352(cfg,Some(signed.digest)).await
}

#[tauri::command]
async fn reset_desktop_binding() -> Result<DesktopBindingResult, String> {
    let path=desktop_config_path()?;
    if signed_first_run_0352::load(&desktop_config_dir()?)?.is_some(){
        return Err("Подписанная привязка проекта управляется владельцем; сбросьте пользовательские параметры через настройки, а не через начальную конфигурацию".into())
    }
    if fs::metadata(&path).await.is_ok(){fs::remove_file(&path).await.map_err(|e|e.to_string())?;}
    let cfg=default_desktop_config();
    Ok(DesktopBindingResult {status:"reset".into(),config_path:path.to_string_lossy().to_string(),game_directory:cfg.game_directory,message:"Привязка Desktop сброшена".into()})
}

#[tauri::command]
async fn load_manifest(url: String, pinned_public_key: String) -> Result<Manifest, String> { runtime::load_manifest(&url, &pinned_public_key).await }
#[tauri::command]
async fn verify_manifest_signature(manifest: Manifest, pinned_public_key: String) -> Result<SignatureCheckResult, String> { runtime::verify_manifest_signature(&manifest, &pinned_public_key) }
#[tauri::command]
async fn check_files(manifest: Manifest, root: String, preset: Option<String>) -> Result<Vec<FileCheckResult>, String> {
    let cfg=load_desktop_config().await?;
    let auth=component_permissions_for_manifest_0392(&manifest,&cfg.pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,async {
        runtime::check_files_with_preset(&manifest,&PathBuf::from(root),preset.as_deref()).await
    }).await
}
#[tauri::command]
async fn download_missing_files(app: tauri::AppHandle, manifest: Manifest, root: String, pinned_public_key: String, preset:Option<String>) -> Result<DownloadResult,String> {
    let mut grants=release_permission_scopes_0393(&root,&pinned_public_key,false).await?;
    grants.insert(0,component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?);
    let result=runtime::component_catalog_0241::with_verified_release_scopes_0393(grants,
        download_missing_files_inner_0392(app,manifest,root.clone(),pinned_public_key.clone(),preset)).await?;
    // Указатель выпуска фиксируется до ответа Tauri. Сохраняйте точный
    // нативный выбор установленных компонентов даже при успешном ответе renderer.
    if result.failed==0 {reconcile_component_preference_0393(&root,&pinned_public_key).await?;}
    Ok(result)
}
async fn download_missing_files_inner_0392(app: tauri::AppHandle, manifest: Manifest, root: String, pinned_public_key: String, preset:Option<String>) -> Result<DownloadResult, String> {
    let sink: runtime::ProgressSink = Arc::new(move |progress| {
        let _ = app.emit(runtime::DOWNLOAD_PROGRESS_EVENT, progress);
    });
    runtime::download_missing_files_with_preset(&manifest, &PathBuf::from(root), &pinned_public_key, Some(sink), preset).await
}
#[tauri::command]
async fn repair_client(app: tauri::AppHandle, manifest: Manifest, root: String, pinned_public_key: String, preset:Option<String>) -> Result<RepairResult,String> {
    let mut grants=release_permission_scopes_0393(&root,&pinned_public_key,false).await?;
    grants.insert(0,component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?);
    let result=runtime::component_catalog_0241::with_verified_release_scopes_0393(grants,
        repair_client_inner_0392(app,manifest,root.clone(),pinned_public_key.clone(),preset)).await?;
    if result.status=="ready" {reconcile_component_preference_0393(&root,&pinned_public_key).await?;}
    Ok(result)
}
async fn repair_client_inner_0392(app: tauri::AppHandle, manifest: Manifest, root: String, pinned_public_key: String, preset:Option<String>) -> Result<RepairResult, String> {
    let sink: runtime::ProgressSink = Arc::new(move |progress| {
        let _ = app.emit(runtime::DOWNLOAD_PROGRESS_EVENT, progress);
    });
    runtime::repair_client_with_preset(&manifest, &PathBuf::from(root), &pinned_public_key, Some(sink), preset).await
}
#[tauri::command]
async fn pending_download_job(root: String, pinned_public_key: String) -> Result<Option<runtime::durable_downloads::PendingDownload>, String> {
    let manifest=runtime::durable_downloads::pending_manifest_for_permissions_0392(
        &PathBuf::from(&root),&pinned_public_key).await?;
    let Some(manifest)=manifest else{return Ok(None)};
    let grant=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(grant,async {
        runtime::durable_downloads::pending(&PathBuf::from(root), &pinned_public_key).await
    }).await
}
#[tauri::command]
async fn control_download_job(root: String, action: String) -> Result<(), String> {
    runtime::durable_downloads::control(&PathBuf::from(root), &action).await
}
#[tauri::command]
async fn resume_download_job(app: tauri::AppHandle, root: String, pinned_public_key: String) -> Result<DownloadResult, String> {
    // Пользователь может изменить байты журнала: проверяйте подпись и закреплённый ключ,
    // получайте права на этот точный каталог и перепроверяйте журнал при возобновлении.
    // Подменённый каталог не совпадёт с областью доступа и будет отклонён.
    let manifest=runtime::durable_downloads::pending_manifest_for_permissions_0392(
        &PathBuf::from(&root),&pinned_public_key).await?
        .ok_or("Нет подписанного задания скачивания для возобновления")?;
    let mut grants=release_permission_scopes_0393(&root,&pinned_public_key,false).await?;
    grants.insert(0,component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?);
    let sink: runtime::ProgressSink = Arc::new(move |progress| {
        let _ = app.emit(runtime::DOWNLOAD_PROGRESS_EVENT, progress);
    });
    let result=runtime::component_catalog_0241::with_verified_release_scopes_0393(grants,async {
        runtime::durable_downloads::resume(&PathBuf::from(&root), &pinned_public_key, Some(sink)).await
    }).await?;
    if result.failed==0 {reconcile_component_preference_0393(&root,&pinned_public_key).await?;}
    Ok(result)
}
async fn release_permission_scopes_0393(root:&str,key:&str,include_lkg:bool)->Result<Vec<runtime::component_catalog_0241::VerifiedComponentScope0392>,String>{
    let root_path=PathBuf::from(root);let signed_key=key.to_owned();
    let manifests=tokio::task::spawn_blocking(move ||
        runtime::transactional_release::release_manifests_for_permissions_0393(&root_path,&signed_key,include_lkg))
        .await.map_err(|e|format!("Ошибка чтения каталогов подписанных выпусков: {e}"))??;
    let mut grants=Vec::with_capacity(manifests.len());
    for manifest in manifests {
        grants.push(component_permissions_for_manifest_0392(&manifest,key).await?);
    }
    Ok(grants)
}
// После сбоя или отката авторитетным источником выбранного пресета служит
// нативный подписанный указатель выпуска. Синхронизируйте настройки Desktop, даже
// если renderer завершится до получения ответа Tauri.
async fn reconcile_component_preference_0393(root:&str,key:&str)->Result<(),String>{
    let scope=installed_component_scope_0392(root,key).await?;
    let Some(scope)=scope else{return Ok(())};
    let active=runtime::component_catalog_0241::with_verified_component_scope_0392(scope,async {
        runtime::component_catalog_0241::spawn_blocking_with_permissions_0392({
            let root=root.to_owned();let key=key.to_owned();
            move || runtime::transactional_release::verified_active_selection_02410(&PathBuf::from(root),&key)
        }).await.map_err(|e|format!("Ошибка чтения восстановленного выбора: {e}"))?
    }).await?;
    let Some((manifest,preset))=active else{return Ok(())};
    let mut cfg=load_desktop_config().await?;
    if cfg.project_id!=manifest.project_id || cfg.profile_id!=manifest.profile_id || cfg.channel!=manifest.channel ||
       cfg.pinned_public_key!=key {return Err("Восстановленный выпуск не соответствует подписанной привязке Desktop".into());}
    let saved_root=PathBuf::from(&cfg.game_directory).canonicalize().map_err(|e|e.to_string())?;
    let actual_root=PathBuf::from(root).canonicalize().map_err(|e|e.to_string())?;
    if saved_root!=actual_root {return Err("Восстановленный выпуск находится за пределами игрового каталога Desktop".into());}
    let installed=preset.unwrap_or_default();
    let update_offline_cache=cfg.onboarding_completed && manifest.runtime.launch.offline_mode;
    if cfg.component_preset!=installed {
        cfg.component_preset=installed;
        save_desktop_config(cfg).await?;
    }
    // Успешный откат не должен оставлять офлайн-кеш с указателем на
    // заменённый выпуск. Операция проверяет установленные байты и
    // подписанную привязку владельца до атомарной замены кешированного манифеста.
    if update_offline_cache {
        let grant=component_permissions_for_manifest_0392(&manifest,key).await?;
        runtime::component_catalog_0241::with_verified_component_scope_0392(grant,async {
            cache_desktop_manifest(manifest,root.to_owned(),key.to_owned()).await
        }).await?;
    }
    Ok(())
}
#[tauri::command]
async fn rollback_client_release(root: String, pinned_public_key: String) -> Result<(), String> {
    let cfg=load_desktop_config().await?;
    if cfg.pinned_public_key!=pinned_public_key || PathBuf::from(&cfg.game_directory).canonicalize().map_err(|e|e.to_string())?!=
        PathBuf::from(&root).canonicalize().map_err(|e|e.to_string())? {
        return Err("Откат за пределы настроенного подписанного игрового каталога запрещён".into());
    }
    let grants=release_permission_scopes_0393(&root,&pinned_public_key,true).await?;
    runtime::component_catalog_0241::with_verified_release_scopes_0393(grants,async {
        runtime::transactional_release::rollback(&PathBuf::from(&root), &pinned_public_key).await
    }).await?;
    reconcile_component_preference_0393(&root,&pinned_public_key).await
}
#[tauri::command]
async fn recover_client_release(root: String, pinned_public_key: String) -> Result<(), String> {
    let grants=release_permission_scopes_0393(&root,&pinned_public_key,false).await?;
    runtime::component_catalog_0241::with_verified_release_scopes_0393(grants,async {
        runtime::transactional_release::recover(&PathBuf::from(&root), &pinned_public_key).await
    }).await?;
    reconcile_component_preference_0393(&root,&pinned_public_key).await
}
#[tauri::command]
async fn clean_unused_files(manifest: Manifest, root: String, pinned_public_key: String) -> Result<CleanUnusedResult, String> { runtime::clean_unused_files(&manifest, &PathBuf::from(root), &pinned_public_key).await }
#[tauri::command]
async fn prepare_profile_directory(base_dir: String, project_id: String, profile_id: String) -> Result<String, String> { Ok(runtime::prepare_profile_directory(&PathBuf::from(base_dir), &project_id, &profile_id).await?.to_string_lossy().to_string()) }
#[tauri::command]
async fn check_java(java_path: Option<String>, required_major_version: Option<u32>) -> Result<JavaInfoResult, String> { runtime::check_java(java_path, required_major_version).await }
#[tauri::command]
async fn ensure_managed_java(required_major_version: u32, distribution: String) -> Result<ManagedJavaResult, String> {
    // Явная административная операция в стиле CLI остаётся доступной.
    runtime::ensure_managed_java(required_major_version, &distribution, None).await
}
#[tauri::command]
async fn ensure_profile_managed_java(manifest: Manifest, pinned_public_key: String) -> Result<ManagedJavaResult, String> {
    runtime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    let java = &manifest.runtime.java;
    if java.major_version == 0 || (java.minimum_major_version > 0 && java.major_version < java.minimum_major_version)
        || (java.maximum_major_version > 0 && java.major_version > java.maximum_major_version) {
        return Err("Основная версия Java в подписанном профиле не входит в поддерживаемый диапазон".into());
    }
    runtime::ensure_managed_java(java.major_version, &java.distribution, None).await
}
#[tauri::command]
async fn build_launch_plan(manifest: Manifest, root: String, java_path: Option<String>, username: Option<String>, pinned_public_key: String, preferences: Option<runtime::LaunchPreferences>) -> Result<LaunchPlan, String> {
    let root = PathBuf::from(root);
    let mut plan = runtime::build_launch_plan(&manifest, &root, java_path, username, &pinned_public_key).await?;
    if let Some(p) = preferences { runtime::apply_launch_preferences(&manifest, &root, &mut plan, &p, None)?; }
    Ok(plan)
}
// 0.35.8: автономный сеанс — повторное воспроизведение установки, подготовленной владельцем, права
// доступа, входа или произвольного открытого ключа, предоставленного визуализатором. Нативная проверка
// повторяется при каждом чтении кеша и каждом запуске.
fn check_offline_owner_binding_0358(
    cfg: &DesktopConfig,
    owner: &signed_first_run_0352::Provisioning0352,
    manifest: &Manifest,
    root: &str,
    key: &str,
    require_installed: bool,
) -> Result<(), String> {
    if owner.project_id != manifest.project_id || owner.profile_id != manifest.profile_id ||
        owner.channel != manifest.channel ||
        !owner.pinned_public_key.eq_ignore_ascii_case(key) ||
        !cfg.pinned_public_key.eq_ignore_ascii_case(key) ||
        cfg.project_id != owner.project_id || cfg.profile_id != owner.profile_id ||
        cfg.channel != owner.channel {
        return Err("Автономный запуск запрещён: проект, профиль, канал или закреплённый ключ не соответствует подписанному пакету владельца".into());
    }
    if !manifest.runtime.launch.offline_mode ||
        (manifest.schema_version != "2.0" && manifest.schema_version != "3.0") {
        return Err("Автономный запуск запрещён: подписанный профиль игры не разрешает локальную игру без сети".into());
    }
    if require_installed && (!cfg.onboarding_completed || cfg.onboarding_bootstrap_digest != owner.digest) {
        return Err("Автономный запуск запрещён: сначала завершите первоначальную подписанную установку с подключением к сети".into());
    }
    let requested = PathBuf::from(root).canonicalize().map_err(|e|format!("Автономный игровой каталог недоступен: {e}"))?;
    let saved = PathBuf::from(&cfg.game_directory).canonicalize().map_err(|e|format!("Сохранённый автономный игровой каталог недоступен: {e}"))?;
    if requested != saved {
        return Err("Автономный запуск запрещён: игровой каталог отличается от установленного подписанного профиля".into());
    }
    Ok(())
}

async fn verified_offline_owner_0358() -> Result<(DesktopConfig, signed_first_run_0352::Provisioning0352), String> {
    let cfg = load_desktop_config().await?;
    let owner = signed_first_run_0352::load(&desktop_config_dir()?)?
        .ok_or("Автономный запуск запрещён: требуется начальный пакет с подписью владельца")?;
    Ok((cfg, owner))
}

async fn verify_offline_files_0358(manifest: &Manifest, root: &str, key: &str, preset: &str) -> Result<(), String> {
    let path = PathBuf::from(root);
    let selected = if preset.is_empty() { None } else { Some(preset) };
    runtime::transactional_release::ensure_active_preset(manifest, &path, key, selected).await?;
    let checks = runtime::check_files_with_preset(manifest, &path, selected).await?;
    if checks.is_empty() {return Err("Автономный запуск запрещён: в установленном выпуске нет проверенных управляемых файлов".into());}
    if let Some(broken) = checks.iter().find(|f|f.status != "ok") {
        return Err(format!("Автономный запуск запрещён: {} ({}) не проверен; подключитесь к сети и восстановите установку", broken.path, broken.status));
    }
    Ok(())
}

// Команда выполняет настоящую нативную проверку целостности; визуализатору разрешено лишь показать
// результат. Сетевые вызовы и токены не создаются.
#[tauri::command]
async fn prepare_offline_launch_0358(root: String, pinned_public_key: String,
    project_id: String, profile_id: String, channel: String) -> Result<Manifest, String> {
    let cached = load_cached_desktop_manifest(root.clone(), pinned_public_key.clone(), project_id, profile_id, channel).await?;
    let (cfg, owner) = verified_offline_owner_0358().await?;
    check_offline_owner_binding_0358(&cfg, &owner, &cached, &root, &pinned_public_key, true)?;
    verify_offline_files_0358(&cached, &root, &pinned_public_key, &cfg.component_preset).await?;
    Ok(cached)
}

fn matching_offline_release_0358(requested: &Manifest, cached: &Manifest) -> Result<(), String> {
    // Подпись проверяется независимо для обоих входных данных.
    if requested.project_id != cached.project_id || requested.profile_id != cached.profile_id ||
        requested.channel != cached.channel || requested.version != cached.version ||
        requested.signature.as_ref().map(|v|(&v.signature,&v.public_key)) !=
            cached.signature.as_ref().map(|v|(&v.signature,&v.public_key)) {
        return Err("Автономный запуск запрещён: запрошенный выпуск отличается от проверенного локального кеша".into());
    }
    Ok(())
}

// Кешированные манифесты не становятся доверенными только из-за нахождения на диске. Любое автономное
// чтение повторно проверяет подпись Ed25519 по закреплённому ключу.
fn desktop_manifest_cache_path_0229(root: &str) -> Result<PathBuf, String> {
    let root = PathBuf::from(root).canonicalize().map_err(|e| format!("Корневой каталог клиента недоступен: {e}"))?;
    let dir = root.join(".launcher");
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() || !meta.is_dir() { return Err("Небезопасный каталог кеша манифестов".into()); }
    }
    Ok(dir.join("signed-manifest.json"))
}

#[tauri::command]
async fn cache_desktop_manifest(manifest: Manifest, root: String, pinned_public_key: String) -> Result<(), String> {
    runtime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    let (cfg, owner) = verified_offline_owner_0358().await?;
    // Кешированным выпуском для повторного запуска может стать только установленный и проверенный профиль,
    // явно разрешающий автономный режим.
    if !manifest.runtime.launch.offline_mode { return Err("Автономный кеш отключён политикой подписанного профиля".into()); }
    // Идентичность владельца проверяется до обращения к дисковому кешу.
    if owner.project_id != manifest.project_id || owner.profile_id != manifest.profile_id ||
        owner.channel != manifest.channel || !owner.pinned_public_key.eq_ignore_ascii_case(&pinned_public_key) ||
        !cfg.pinned_public_key.eq_ignore_ascii_case(&pinned_public_key) {
        return Err("Доступ к автономному кешу запрещён: несоответствие области пакета владельца или закреплённого ключа".into());
    }
    // Не создавайте произвольные каталоги по целевым путям кеша, переданным визуализатором.
    check_offline_owner_binding_0358(&cfg, &owner, &manifest, &root, &pinned_public_key, true)?;
    // Не перезаписывайте прежний пригодный кеш неустановленным обновлением. Заменять его может только активный
    // полностью проверенный выпуск.
    verify_offline_files_0358(&manifest, &root, &pinned_public_key, &cfg.component_preset).await?;
    let path = desktop_manifest_cache_path_0229(&root)?;
    let dir = path.parent().ok_or("Отсутствует каталог кэша")?;
    fs::create_dir_all(dir).await.map_err(|e| e.to_string())?;
    if let Ok(meta) = fs::symlink_metadata(&path).await {
        if meta.file_type().is_symlink() { return Err("Небезопасный файл кеша манифестов".into()); }
    }
    let value = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("signed-manifest.{}.{}.tmp", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos()));
    let mut file = fs::OpenOptions::new().create_new(true).write(true).open(&tmp).await.map_err(|e| e.to_string())?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&value).await.map_err(|e| e.to_string())?;
    file.sync_all().await.map_err(|e| e.to_string())?;
    drop(file);
    // В Windows rename не перезаписывает существующий файл. Сохраняйте восстанавливаемую предыдущую
    // подписанную копию до установки новой. Во время промежутка замены чтение завершается отказом; ни одна
    // копия не обходит проверку подписи.
    #[cfg(windows)]
    if fs::metadata(&path).await.is_ok() {
        let backup = tmp.with_extension("previous");
        fs::rename(&path, &backup).await.map_err(|e| format!("Не удалось сохранить предыдущий кеш манифестов: {e}"))?;
        if let Err(err) = fs::rename(&tmp, &path).await {
            let _ = fs::rename(&backup, &path).await;
            return Err(format!("Не удалось заменить кеш манифестов: {err}"));
        }
        let _ = fs::remove_file(&backup).await;
        return Ok(());
    }
    fs::rename(&tmp, &path).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn load_cached_desktop_manifest(root: String, pinned_public_key: String, project_id: String, profile_id: String, channel: String) -> Result<Manifest, String> {
    let path = desktop_manifest_cache_path_0229(&root)?;
    let meta = fs::symlink_metadata(&path).await.map_err(|e| format!("Нет кешированного манифеста: {e}"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 { return Err("Небезопасный файл кеша манифестов".into()); }
    let manifest: Manifest = serde_json::from_slice(&fs::read(&path).await.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    runtime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    let (cfg, owner) = verified_offline_owner_0358().await?;
    check_offline_owner_binding_0358(&cfg, &owner, &manifest, &root, &pinned_public_key, true)?;
    if (manifest.schema_version != "2.0" && manifest.schema_version != "3.0") || manifest.project_id != project_id || manifest.profile_id != profile_id || manifest.channel != channel || !manifest.runtime.launch.offline_mode {
        return Err("Кешированный манифест не разрешён для этого профиля и канала в автономном режиме".into());
    }
    Ok(manifest)
}

// Нативный Rust получает серверные разрешения из сеанса в хранилище секретов ОС. JavaScript не передаёт
// список прав, Bearer или адрес Backend.
async fn component_permissions_for_manifest_0392(manifest:&Manifest,pinned:&str)
    ->Result<runtime::component_catalog_0241::VerifiedComponentScope0392,String> {
    use runtime::component_catalog_0241::VerifiedComponentScope0392;
    runtime::verify_manifest_signature(manifest,pinned)?;
    let catalog=manifest.component_catalog.as_ref();
    let digest=catalog.map(|c|c.digest.clone()).unwrap_or_default();
    let cfg=load_desktop_config().await?;
    if cfg.project_id!=manifest.project_id || cfg.profile_id!=manifest.profile_id ||
       cfg.channel!=manifest.channel || cfg.pinned_public_key!=pinned {
        return Err("Область разрешений компонента отличается от привязанного профиля Desktop".into());
    }
    let needs_grant=catalog.is_some_and(|cat|cat.components.iter().any(|c|c.conditions.as_ref().is_some_and(|v|!v.permissions.is_empty())));
    let empty=||VerifiedComponentScope0392{project_id:manifest.project_id.clone(),profile_id:manifest.profile_id.clone(),
       channel:manifest.channel.clone(),catalog_digest:digest.clone(),valid_until:0,permissions:Default::default()};
    if !needs_grant {return Ok(empty());}
    let cat=catalog.ok_or("Отсутствует: каталог компонентов с условиями")?;
    let origin=reqwest::Url::parse(&cfg.backend_url).map_err(|_|"Недопустимый URL серверной части")?;
    if origin.scheme()!="https" || origin.username()!="" || origin.password().is_some() ||
       origin.query().is_some() || origin.fragment().is_some() || origin.host_str().is_none() {
        return Err("Для доступа к компоненту необходим HTTPS-адрес серверной части".into());
    }
    let session=load_auth_session(cfg.backend_url.clone()).await?.ok_or("Для доступа к компоненту требуется вход в учётную запись Launcher")?;
    if session.access_token.is_empty() || session.session_id.is_empty() || session.user_id.is_empty(){return Err("Неполный аутентифицированный сеанс Launcher".into())}
    let mut url=origin.clone();
    {let mut segments=url.path_segments_mut().map_err(|_|"Недопустимые сегменты URL серверной части")?;
      segments.pop_if_empty(); segments.extend(&["api","v1","projects",&manifest.project_id,"profiles",&manifest.profile_id,"component-permissions"]);}
    url.query_pairs_mut().append_pair("channel",&manifest.channel).append_pair("catalogDigest",&cat.digest);
    let client=reqwest::Client::builder().timeout(Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none())
         .build().map_err(|_|"HTTP-клиент проверки разрешений компонентов недоступен")?;
    let response=client.get(url).bearer_auth(&session.access_token).header(reqwest::header::CACHE_CONTROL,"no-store")
          .send().await.map_err(|_|"Backend проверки разрешений компонентов недоступен")?;
    if !response.status().is_success(){return Err(format!("Сервер отказал в авторизации компонента: {}",response.status()));}
    if response.content_length().is_some_and(|v|v>64*1024){return Err("Ответ авторизации компонента превышает допустимый размер".into());}
    let bytes=response.bytes().await.map_err(|_|"Недопустимый ответ авторизации компонента")?;
    if bytes.len()>64*1024{return Err("Ответ авторизации компонента превышает допустимый размер".into())}
    #[derive(Deserialize)]#[serde(rename_all="camelCase",deny_unknown_fields)]
    struct Reply { project_id:String,profile_id:String,channel:String,catalog_digest:String,
        subject:String,session_id:String,valid_until:i64,permissions:Vec<String> }
    let granted:Reply=serde_json::from_slice(&bytes).map_err(|_|"Неверно сформированный ответ авторизации компонента")?;
    let now=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"Недопустимое системное время")?.as_secs() as i64;
    if granted.project_id!=manifest.project_id || granted.profile_id!=manifest.profile_id || granted.channel!=manifest.channel ||
       granted.catalog_digest!=cat.digest || granted.subject!=session.user_id || granted.session_id!=session.session_id ||
       granted.valid_until<=now || granted.valid_until>now+1800 {
        return Err("В ответе разрешений компонента не совпадает область действия, сеанс или срок действия".into());
    }
    let allowed_names:std::collections::HashSet<&str>=cat.components.iter().filter_map(|c|c.conditions.as_ref())
         .flat_map(|c|c.permissions.iter().map(String::as_str)).collect();
    let mut rights=std::collections::HashSet::new();
    for permission in granted.permissions {
        if !allowed_names.contains(permission.as_str())||!rights.insert(permission){
            return Err("В ответе обнаружено неожиданное или повторяющееся разрешение компонента".into());
        }
    }
    Ok(VerifiedComponentScope0392{project_id:manifest.project_id.clone(),profile_id:manifest.profile_id.clone(),
         channel:manifest.channel.clone(),catalog_digest:cat.digest.clone(),valid_until:granted.valid_until,permissions:rights})
}

// Не разрешайте установленные компоненты с ограниченным доступом до запроса прав. Первое чтение с диска
// проверяет только подписанный манифест; владение установленными файлами, хеши и план проверяются повторно
// в области действия разрешения.
async fn installed_component_scope_0392(root:&str,pinned:&str)
    ->Result<Option<runtime::component_catalog_0241::VerifiedComponentScope0392>,String>{
    let root=PathBuf::from(root);let key=pinned.to_owned();
    let manifest=tokio::task::spawn_blocking(move ||
        runtime::transactional_release::active_manifest_for_permissions_0392(&root,&key))
        .await.map_err(|_|"Ошибка задачи проверки области установленных компонентов")??;
    match manifest {Some(m)=>Ok(Some(component_permissions_for_manifest_0392(&m,pinned).await?)),None=>Ok(None)}
}
#[tauri::command]
async fn preview_components_0244(manifest: runtime::Manifest,
    pinned_public_key: String,
    component_preset: Option<String>,) -> Result<runtime::component_catalog_0241::ComponentSelectionPreview0244,String> {
    let auth=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,
        preview_components_0244_inner_0392(manifest,pinned_public_key,component_preset)).await
}
async fn preview_components_0244_inner_0392(
    manifest: runtime::Manifest,
    pinned_public_key: String,
    component_preset: Option<String>,
) -> Result<runtime::component_catalog_0241::ComponentSelectionPreview0244, String> {
    runtime::verify_manifest_signature(&manifest, &pinned_public_key)?;
    runtime::component_catalog_0241::preview_components_0244(&manifest,component_preset.as_deref())
}

#[tauri::command]
async fn save_installed_component_choice_0247(manifest:runtime::Manifest,pinned_public_key:String,root:String,
    component_preset:String,config:DesktopConfig)->Result<(),String>{
    let auth=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,
        save_installed_component_choice_0247_inner_0392(manifest,pinned_public_key,root,component_preset,config)).await
}
async fn save_installed_component_choice_0247_inner_0392(
    manifest:runtime::Manifest,pinned_public_key:String,root:String,
    component_preset:String,mut config:DesktopConfig,
)->Result<(),String>{
    let chosen=runtime::transactional_release::matching_installed_preset_0247(
        &manifest,&PathBuf::from(root),&pinned_public_key)?
        .ok_or("Нельзя сохранить выбор компонентов для другого или неустановленного релиза")?;
    if chosen.unwrap_or_default()!=component_preset {
        return Err("Выбор установленного компонента отличается от запрошенной настройки".into());
    }
    if component_preset.len()>8192 {return Err("Слишком большой набор выбранных компонентов".into())}
    if config.project_id!=manifest.project_id || config.profile_id!=manifest.profile_id
        || config.game_directory!=root || config.pinned_public_key!=pinned_public_key {
        return Err("Настройки Desktop не соответствуют подписанному установленному профилю, каталогу или ключу".into());
    }
    config.component_preset=component_preset;
    save_desktop_config(config).await?;
    Ok(())
}


// Доказательства измеряются по установленному активному выпуску, по списку модов, манифесту или SHA-256
// выбранного плана, переданным визуализатором.
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
    let scope=installed_component_scope_0392(&request.root,&request.pinned_public_key).await?
        .ok_or("Нет установленного подписанного релиза")?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(scope, async {
    runtime::component_catalog_0241::spawn_blocking_with_permissions_0392(move || {
        let NativePlanChallenge02412 {backend_url,user_id,device_id,session_id,binding_epoch,
            server_id,project_id,profile_id,channel,root,pinned_public_key,challenge_id,challenge,guard_attestation_sha256}=request;
        if [ &user_id,&device_id,&session_id,&server_id,&project_id,&profile_id,&channel,&challenge_id,&challenge ].iter()
            .any(|v|v.is_empty()||v.len()>160||v.contains('\n')||v.contains('\r')) {
            return Err("Недопустимый идентификатор или запрос проверки подтверждённого плана".to_string());
        }
        if guard_attestation_sha256.len()!=64|| !guard_attestation_sha256.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()){
            return Err("Недопустимый хеш непрерывной аттестации Guard".into());
        }
        let root_path=PathBuf::from(root);
        let (manifest,preset)=runtime::transactional_release::verified_active_selection_02410(
            &root_path,&pinned_public_key)?.ok_or("Нет установленного релиза с подтверждённой подписью")?;
        if manifest.schema_version!="3.0"||manifest.project_id!=project_id||manifest.profile_id!=profile_id||manifest.channel!=channel {
            return Err("Установленный подписанный выпуск не соответствует запрошенной области сервера".into());
        }
        // verified_active_selection проверяет SHA-256 каждого установленного управляемого файла.
        let plan=runtime::resolved_download_0246::resolve(&manifest,preset.as_deref())?;
        let catalog_digest=manifest.component_catalog.as_ref().ok_or("Требуется: каталог v3")?.digest.clone();
        let release_signature=manifest.signature.as_ref().ok_or("Установленный релиз не подписан")?.signature.to_ascii_lowercase();
        if catalog_digest.len()!=64||release_signature.len()!=128{return Err("Неверно сформированные измерения подписанного выпуска".into());}
        let canonical=format!("Launcher-Verified-Component-Plan-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            challenge_id,challenge,user_id,device_id,session_id,binding_epoch,server_id,project_id,profile_id,channel,
            release_signature,catalog_digest,plan.sha256,guard_attestation_sha256);
        let signer=device_keys::sign_verified_plan_payload_02412(&backend_url,&user_id,&device_id,&canonical)?;
        Ok(NativePlanEvidence02412{challenge_id,challenge,user_id,device_id,session_id,binding_epoch,
            server_id,project_id,profile_id,channel,release_signature,catalog_digest,
            plan_sha256:plan.sha256,guard_attestation_sha256,signature:signer.signature})
    }).await.map_err(|e|format!("Ошибка нативной задачи проверки подтверждённого плана: {e}"))?
    }).await
}

#[derive(serde::Serialize)]
#[serde(rename_all="camelCase")]
struct ActiveSelection02410 { manifest:runtime::Manifest, component_preset:String }

#[tauri::command]
async fn active_selection_02410(root:String,pinned_public_key:String)->Result<Option<ActiveSelection02410>,String>{
    let scope=installed_component_scope_0392(&root,&pinned_public_key).await?;
    if scope.is_none(){return Ok(None)}
    runtime::component_catalog_0241::with_verified_component_scope_0392(scope.unwrap(),async {
    runtime::component_catalog_0241::spawn_blocking_with_permissions_0392(move || {
        let state=runtime::transactional_release::verified_active_selection_02410(
            &PathBuf::from(root),&pinned_public_key)?;
        Ok(state.map(|(manifest,preset)|ActiveSelection02410{manifest,component_preset:preset.unwrap_or_default()}))
    }).await.map_err(|e|format!("Ошибка задачи чтения активного выбора: {e}"))?
    }).await
}

#[tauri::command]
async fn export_component_selection_02410(root:String,pinned_public_key:String)->Result<String,String>{
    let scope=installed_component_scope_0392(&root,&pinned_public_key).await?
        .ok_or("Нет установленного подписанного релиза для экспорта")?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(scope,async {
    runtime::component_catalog_0241::spawn_blocking_with_permissions_0392(move || {
        let (manifest,preset)=runtime::transactional_release::verified_active_selection_02410(
            &PathBuf::from(root),&pinned_public_key)?.ok_or("Нет установленного подписанного релиза для экспорта")?;
        runtime::component_selection_02410::export_from_installed_02410(&manifest,preset.as_deref())
    }).await.map_err(|e|format!("Ошибка задачи экспорта выбора: {e}"))?
    }).await
}

#[tauri::command]
async fn preview_component_migration_02410(
    manifest:runtime::Manifest,root:String,pinned_public_key:String,
)->Result<Option<runtime::component_selection_02410::SelectionMigration02410>,String>{
    runtime::verify_manifest_signature(&manifest,&pinned_public_key)?;
    let Some(previous_grant)=installed_component_scope_0392(&root,&pinned_public_key).await? else {return Ok(None)};
    let target_pinned=pinned_public_key.clone();
    let installed=runtime::component_catalog_0241::with_verified_component_scope_0392(previous_grant,async {
        runtime::component_catalog_0241::spawn_blocking_with_permissions_0392(move ||
            runtime::transactional_release::verified_active_selection_02410(
                &PathBuf::from(root),&pinned_public_key))
            .await.map_err(|e|format!("Ошибка чтения миграции компонентов: {e}"))?
    }).await?;
    let Some((source,preset))=installed else{return Ok(None)};
    if source.signature.as_ref().map(|s|(&s.signature,&s.public_key))==
        manifest.signature.as_ref().map(|s|(&s.signature,&s.public_key)) {return Ok(None)}
    if source.schema_version!="3.0" {return Ok(None)}
    let target_grant=component_permissions_for_manifest_0392(&manifest,&target_pinned).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(target_grant,async {
        let text=runtime::component_selection_02410::export_from_installed_02410(&source,preset.as_deref())?;
        let selection=runtime::component_selection_02410::parse_import_02410(&text)?;
        runtime::component_selection_02410::migrate_02410(&selection,&manifest).map(Some)
    }).await
}

#[tauri::command]
async fn preview_import_component_selection_02410(
    manifest:runtime::Manifest,pinned_public_key:String,selection_json:String,
)->Result<runtime::component_selection_02410::SelectionMigration02410,String>{
    let grant=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(grant,async {
        let selection=runtime::component_selection_02410::parse_import_02410(&selection_json)?;
        runtime::component_selection_02410::migrate_02410(&selection,&manifest)
    }).await
}

#[derive(serde::Serialize)]
#[serde(rename_all="camelCase")]
struct InstalledChoice0247 {installed:bool,preset:Option<String>}

#[tauri::command]
async fn installed_component_choice_0247(
    manifest:runtime::Manifest,pinned_public_key:String,root:String,
)->Result<InstalledChoice0247,String>{
    let selected=runtime::transactional_release::matching_installed_preset_0247(
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
    conflicting_user_files:Vec<runtime::transactional_release::PlayerConflict0359>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all="camelCase")]
struct ReleaseRequirements0359 {
    installed_version: Option<String>,
    target_version: String,
    target_signature: String,
    changes: Vec<String>,
    proposed_preset: Option<String>,
    blockers: Vec<String>,
    requires_confirmation: bool,
}

// Сравнивайте два проверенных подписанных выпуска: установленный и целевой. Память UI и localStorage
// принимаются как источник установленных требований.
#[tauri::command]
async fn preview_release_requirements_0359(
    manifest: Manifest,root:String,pinned_public_key:String,component_preset:Option<String>,
) -> Result<ReleaseRequirements0359,String> {
    runtime::verify_manifest_signature(&manifest,&pinned_public_key)?;
    // Для миграции между выпусками могут потребоваться два РАЗНЫХ разрешения на каталог. Читайте проверенный
    // установленный план по его разрешению, а новый подписанный план разрешайте по свежему целевому
    // разрешению. Не используйте прежние привилегии повторно.
    let old_scope=installed_component_scope_0392(&root,&pinned_public_key).await?;
    let active=if let Some(scope)=old_scope {
        let existing_root=root.clone();let existing_key=pinned_public_key.clone();
        runtime::component_catalog_0241::with_verified_component_scope_0392(scope,async {
            runtime::component_catalog_0241::spawn_blocking_with_permissions_0392(move ||
                runtime::transactional_release::verified_active_selection_02410(
                    &PathBuf::from(existing_root),&existing_key))
                .await.map_err(|e|format!("Не удалось прочитать предыдущий выбор установленных компонентов: {e}"))?
        }).await?
    }else{None};
    let target_scope=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(target_scope,async {
    runtime::component_catalog_0241::spawn_blocking_with_permissions_0392(move || {
        let target_signature=manifest.signature.as_ref().ok_or("Требуется подписанный манифест")?.signature.clone();
        let Some((old,preset))=active else {
            return Ok(ReleaseRequirements0359{installed_version:None,target_version:manifest.version,target_signature:target_signature.clone(),
                changes:Vec::new(),proposed_preset:None,blockers:Vec::new(),requires_confirmation:false});
        };
        if (old.project_id.as_str(),old.profile_id.as_str(),old.channel.as_str())!=
           (manifest.project_id.as_str(),manifest.profile_id.as_str(),manifest.channel.as_str()){
            return Err("Обновлённый манифест не относится к установленному проекту, профилю и каналу".into());
        }
        if old.signature.as_ref().map(|s|(&s.signature,&s.public_key))==
           manifest.signature.as_ref().map(|s|(&s.signature,&s.public_key)){
            return Ok(ReleaseRequirements0359{installed_version:Some(old.version),target_version:manifest.version,target_signature:target_signature.clone(),
                changes:Vec::new(),proposed_preset:preset,blockers:Vec::new(),requires_confirmation:false});
        }
        let mut changes=Vec::new();
        if old.runtime.java.major_version!=manifest.runtime.java.major_version ||
           old.runtime.java.distribution!=manifest.runtime.java.distribution {
            changes.push(format!("Java: {} ({}) → {} ({})",old.runtime.java.major_version,old.runtime.java.distribution,
                manifest.runtime.java.major_version,manifest.runtime.java.distribution));
        }
        if (old.runtime.java.minimum_major_version,old.runtime.java.recommended_major_version,old.runtime.java.maximum_major_version)!=
           (manifest.runtime.java.minimum_major_version,manifest.runtime.java.recommended_major_version,manifest.runtime.java.maximum_major_version){
            changes.push(format!("Допустимые версии Java (минимальная/рекомендуемая/максимальная): {}/{}/{} → {}/{}/{}",
                old.runtime.java.minimum_major_version,old.runtime.java.recommended_major_version,old.runtime.java.maximum_major_version,
                manifest.runtime.java.minimum_major_version,manifest.runtime.java.recommended_major_version,manifest.runtime.java.maximum_major_version));
        }
        let a=&old.runtime.memory;let b=&manifest.runtime.memory;
        if (a.minimum_mb,a.recommended_mb,a.maximum_mb)!=(b.minimum_mb,b.recommended_mb,b.maximum_mb){
            changes.push(format!("Оперативная память: минимум/рекомендуется/максимум (МиБ): {}/{}/{} → {}/{}/{}",
                a.minimum_mb,a.recommended_mb,a.maximum_mb,b.minimum_mb,b.recommended_mb,b.maximum_mb));
        }
        if old.minecraft.version!=manifest.minecraft.version || old.minecraft.loader!=manifest.minecraft.loader {
            changes.push(format!("Minecraft/loader: {} {} → {} {}",old.minecraft.version,old.minecraft.loader,
                manifest.minecraft.version,manifest.minecraft.loader));
        }
        let mut proposed_preset=preset.clone();
        let mut blockers=Vec::new();
        if old.schema_version=="3.0" && old.component_catalog.is_some() && manifest.component_catalog.is_some(){
            let selection=runtime::component_selection_02410::export_from_installed_02410(&old,preset.as_deref())?;
            let parsed=runtime::component_selection_02410::parse_import_02410(&selection)?;
            let migrated=runtime::component_selection_02410::migrate_02410(&parsed,&manifest)?;
            proposed_preset=migrated.choice;
            blockers=migrated.blockers;
            if !migrated.added_ids.is_empty(){changes.push(format!("Новые обязательные/зависимые компоненты: {}",migrated.added_ids.join(", ")));}
            if !migrated.removed_ids.is_empty(){changes.push(format!("Удалённые из нового каталога компоненты: {}",migrated.removed_ids.join(", ")));}
            if migrated.preset_changed{changes.push("Предыдущий preset изменился или исчез: требуется подтверждение новой конфигурации".into());}
        } else if old.component_catalog.is_some()!=manifest.component_catalog.is_some() {
            blockers.push("Изменился тип каталога компонентов: выберите новый preset вручную".into());
            proposed_preset=None;
        }
        // Игрок вправе явно выбрать другой подписанный план после предварительного просмотра миграции. Проверяйте
        // этот выбор, а не молча одобряйте предложенный автоматически. Подтверждение UI привязано именно к нему.
        if let Some(ref requested)=component_preset {
            if manifest.component_catalog.is_some() {
                runtime::component_catalog_0241::preview_components_0244(&manifest,Some(requested))?;
                if proposed_preset.as_deref()!=Some(requested.as_str()) {
                    changes.push(format!("Изменён выбор компонентов: {} → {}",
                        proposed_preset.as_deref().unwrap_or("<unavailable>"),requested));
                }
                blockers.clear();
                proposed_preset=Some(requested.clone());
            }
        }
        if changes.is_empty(){changes.push("Опубликован новый подписанный релиз; проверьте изменения файлов перед установкой".into());}
        Ok(ReleaseRequirements0359{installed_version:Some(old.version),target_version:manifest.version,
            target_signature,changes,proposed_preset,blockers,requires_confirmation:true})
    }).await.map_err(|e|format!("Ошибка задачи проверки требований: {e}"))?
    }).await
}

async fn validate_native_conflict_scope_0359(manifest:&Manifest,root:&str,key:&str)->Result<(),String>{
    let cfg=load_desktop_config().await?;
    if cfg.pinned_public_key!=key || cfg.project_id!=manifest.project_id ||
       cfg.profile_id!=manifest.profile_id || cfg.channel!=manifest.channel {
        return Err("Операция разрешения конфликта игрока выходит за пределы проверенных проекта, профиля и канала Desktop".into());
    }
    std::fs::create_dir_all(&cfg.game_directory).map_err(|e|format!("Игровой каталог недоступен: {e}"))?;
    let configured=std::fs::canonicalize(&cfg.game_directory).map_err(|e|format!("Игровой каталог недоступен: {e}"))?;
    let requested=std::fs::canonicalize(root).map_err(|e|format!("Запрошенный игровой каталог недоступен: {e}"))?;
    if configured!=requested {return Err("Операция разрешения конфликта не может перемещать файлы за пределы активного игрового каталога".into());}
    Ok(())
}

#[tauri::command]
async fn preview_player_conflicts_0359(manifest:Manifest,root:String,pinned_public_key:String,preset:Option<String>)
    -> Result<runtime::transactional_release::PlayerConflictResult0359,String> {
    validate_native_conflict_scope_0359(&manifest,&root,&pinned_public_key).await?;
    let auth=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,async {
        runtime::transactional_release::preview_player_conflicts_0359(
        &manifest,&PathBuf::from(root),&pinned_public_key,preset.as_deref())
    }).await
}

#[tauri::command]
async fn preserve_player_conflicts_0359(manifest:Manifest,root:String,pinned_public_key:String,preset:Option<String>,
    expected:Vec<runtime::transactional_release::PlayerConflict0359>)
    -> Result<runtime::transactional_release::PlayerConflictResult0359,String> {
    validate_native_conflict_scope_0359(&manifest,&root,&pinned_public_key).await?;
    let auth=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,async {
        runtime::transactional_release::preserve_player_conflicts_0359(
        &manifest,&PathBuf::from(root),&pinned_public_key,preset.as_deref(),&expected)
    }).await
}

#[tauri::command]
async fn preview_component_changes_0247(manifest:runtime::Manifest,
    pinned_public_key:String,
    root:String,
    component_preset:Option<String>,) -> Result<ComponentDiff0247,String> {
    let auth=component_permissions_for_manifest_0392(&manifest,&pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,
        preview_component_changes_0247_inner_0392(manifest,pinned_public_key,root,component_preset)).await
}
async fn preview_component_changes_0247_inner_0392(
    manifest:runtime::Manifest,
    pinned_public_key:String,
    root:String,
    component_preset:Option<String>,
) -> Result<ComponentDiff0247,String> {
    use std::collections::HashSet;
    runtime::verify_manifest_signature(&manifest,&pinned_public_key)?;
    let root=PathBuf::from(root);
    let plan=runtime::resolved_download_0246::resolve(&manifest,component_preset.as_deref())?;
    let (installed_preset, installed)=runtime::transactional_release::installed_component_state_0247(&manifest,&root,&pinned_public_key)?;
    let old:HashSet<_>=installed.into_iter().collect();
    // Показывайте конфликты как блокировки с явной проверенной процедурой сохранения, а не как вводящую в
    // заблуждение общую ошибку сравнения.
    let conflicts=runtime::transactional_release::preview_player_conflicts_0359(
        &manifest,&root,&pinned_public_key,component_preset.as_deref())?;
    let wanted:HashSet<_>=plan.files.iter().map(|f|f.path.clone()).collect();
    let added_files=plan.files.iter().filter(|f|!old.contains(&f.path)).map(|f|f.path.clone()).collect();
    let removed_files=old.iter().filter(|p|!wanted.contains(*p)).cloned().collect::<Vec<_>>();
    let checks=runtime::check_files_with_preset(&manifest,&root,component_preset.as_deref()).await?;
    let missing:HashSet<_>=checks.iter().filter(|f|f.status!="ok").map(|f|f.path.as_str()).collect();
    let download_files=plan.files.iter().filter(|f|missing.contains(f.path.as_str())).map(|f|f.path.clone()).collect();
    let download_bytes_upper_bound=plan.files.iter().filter(|f|missing.contains(f.path.as_str())).map(|f|f.size).sum();
    let total_selected_bytes=plan.files.iter().map(|f|f.size).sum();
    Ok(ComponentDiff0247{installed_preset,added_files,removed_files,download_files,
        download_bytes_upper_bound,total_selected_bytes,plan_sha256:plan.sha256,
        conflicting_user_files:conflicts.files})
}

#[tauri::command]
async fn launch_minecraft(
    request: LaunchMinecraftRequest,
    supervisor: tauri::State<'_, ProcessSupervisor>,
    guard: tauri::State<'_, GuardSupervisor>,
    official_manager: tauri::State<'_, official_identity_0262::IdentityManager>,
) -> Result<ProcessStatus, String> {
    let auth=component_permissions_for_manifest_0392(&request.manifest,&request.pinned_public_key).await?;
    runtime::component_catalog_0241::with_verified_component_scope_0392(auth,
        launch_minecraft_inner_0392(request,supervisor,guard,official_manager)).await
}
async fn launch_minecraft_inner_0392(
    request: LaunchMinecraftRequest,
    supervisor: tauri::State<'_, ProcessSupervisor>,
    guard: tauri::State<'_, GuardSupervisor>,
    official_manager: tauri::State<'_, official_identity_0262::IdentityManager>,
) -> Result<ProcessStatus, String> {
    let LaunchMinecraftRequest {
        manifest, auth_mode, root, java_path, username, minecraft_credentials, official_identity, pinned_public_key, preferences, component_preset,
    } = request;
    validate_launch_realm_0269(auth_mode, minecraft_credentials.as_ref(), official_identity.is_some(), preferences.as_ref())?;
    if preferences.as_ref().is_some_and(|p|p.offline) {
        // До взаимодействия с Guard проверяйте политику владельца и точный кешированный подписанный выпуск.
        // Супервизор выполняет окончательную проверку SHA-256 под арендой выпуска прямо перед запуском; не
        // хешируйте многогигабайтный клиент третий раз без необходимости.
        let cached = load_cached_desktop_manifest(root.clone(), pinned_public_key.clone(),
            manifest.project_id.clone(), manifest.profile_id.clone(), manifest.channel.clone()).await?;
        runtime::verify_manifest_signature(&manifest, &pinned_public_key)?;
        matching_offline_release_0358(&manifest, &cached)?;
        let (cfg, _) = verified_offline_owner_0358().await?;
        if component_preset.as_deref().unwrap_or("") != cfg.component_preset {
            return Err("Автономный запуск запрещён: выбранный набор компонентов отличается от установленной конфигурации".into());
        }
    }
    #[cfg(windows)]
    {
        let status = guard.ensure_started().await?;
        if !status.authenticated || status.state != "ready" {
            return Err("Запуск заблокирован: защитная граница Guard для Windows не аутентифицирована или не готова".to_string());
        }
        if !status.process_policy_enforced
            || status.process_policy_version != GUARD_WINDOWS_PROCESS_POLICY_VERSION
        {
            return Err("Запуск заблокирован: политика защиты среды выполнения и процессов Guard для Windows не применяется".to_string());
        }
        if !status.hardening_enforced
            || status.hardening_version != GUARD_WINDOWS_HARDENING_VERSION
            || !status.secure_pipe_acl
            || !status.lifetime_job_enforced
            || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        {
            return Err("Запуск заблокирован: проверка усиленной защиты Guard для промышленной сборки Windows не пройдена".to_string());
        }
        guard.ping().await?;
        let process_policy = guard
            .process_policy()
            .await
            .map_err(|err| format!("Запуск заблокирован: не удалось проверить политику процессов Guard для Windows: {err}"))?;
        if !process_policy.enforced
            || process_policy.policy_version != GUARD_WINDOWS_PROCESS_POLICY_VERSION
        {
            return Err("Запуск заблокирован: отчёт о политике процессов Guard для Windows отклонён".to_string());
        }
        guard
            .integrity_evidence()
            .await
            .map_err(|err| format!("Запуск заблокирован: подтверждение целостности Guard v1 для Windows недоступно: {err}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        let status = guard.ensure_started().await?;
        if !status.authenticated || status.state != "ready" {
            return Err("Запуск заблокирован: защитная граница Guard для Linux не аутентифицирована или не готова".to_string());
        }
        if !status.process_policy_enforced || status.process_policy_version != GUARD_LINUX_PROCESS_POLICY_VERSION {
            return Err("Запуск заблокирован: политика защиты среды выполнения и процессов Guard для Linux не применяется".to_string());
        }
        if !status.hardening_enforced || status.hardening_version != GUARD_LINUX_HARDENING_VERSION
            || !status.secure_pipe_acl || !status.lifetime_job_enforced
            || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        {
            return Err("Запуск заблокирован: не пройдена проверка усиленной защиты Guard для рабочей сборки Linux".to_string());
        }
        guard.ping().await?;
        let policy = guard.process_policy().await
            .map_err(|err| format!("Запуск заблокирован: не удалось проверить политику процессов Guard для Linux: {err}"))?;
        if !policy.enforced || policy.policy_version != GUARD_LINUX_PROCESS_POLICY_VERSION || policy.linux.is_none() {
            return Err("Запуск заблокирован: отчёт о политике процессов Guard для Linux отклонён".to_string());
        }
        guard.integrity_evidence().await
            .map_err(|err| format!("Запуск заблокирован: подтверждение целостности Guard v1 для Linux недоступно: {err}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        let status = guard.ensure_started().await?;
        if !status.authenticated || status.state != "ready" {
            return Err("Запуск заблокирован: защитная граница Guard для macOS не аутентифицирована или не готова".to_string());
        }
        if !status.process_policy_enforced || status.process_policy_version != GUARD_MACOS_PROCESS_POLICY_VERSION {
            return Err("Запуск заблокирован: политика защиты среды выполнения и процессов Guard для macOS не применяется".to_string());
        }
        if !status.hardening_enforced || status.hardening_version != GUARD_MACOS_HARDENING_VERSION
            || !status.secure_pipe_acl || !status.lifetime_job_enforced
            || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        {
            return Err("Запуск заблокирован: не пройдена проверка усиленной защиты Guard для рабочей сборки macOS".to_string());
        }
        guard.ping().await?;
        let policy = guard.process_policy().await
            .map_err(|err| format!("Запуск заблокирован: не удалось проверить политику процессов Guard для macOS: {err}"))?;
        if !policy.enforced || policy.policy_version != GUARD_MACOS_PROCESS_POLICY_VERSION || policy.macos.is_none() {
            return Err("Запуск заблокирован: отчёт о политике процессов Guard для macOS отклонён".to_string());
        }
        guard.integrity_evidence().await
            .map_err(|err| format!("Запуск заблокирован: подтверждение целостности Guard v1 для macOS недоступно: {err}"))?;
    }
    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    let _ = &guard;

    runtime::transactional_release::ensure_active_preset(&manifest, &PathBuf::from(&root), &pinned_public_key, component_preset.as_deref()).await?;
    // Никогда не принимайте MSA-токены из JS. Только нативный менеджер получает официальные игровые учётные
    // данные и передаёт их непосредственно в Runtime.
    if minecraft_credentials.as_ref().is_some_and(|v| v.user_type == "msa") {
        return Err("Токены запуска официального Minecraft нельзя передавать из интерфейса рендеринга".into());
    }
    if official_identity.is_some() && minecraft_credentials.is_some() {
        return Err("Смешивание идентификаторов Minecraft запрещено".into());
    }
    if official_identity.is_some() && preferences.as_ref().is_some_and(|v| v.offline) {
        return Err("Официальный запуск Minecraft не может выполняться без сети".into());
    }
    let minecraft_credentials = if let Some(context) = official_identity {
        let credentials=official_manager.launch_credentials(&context.backend_url, &context.token, &context.session_id).await?;
        // Для запуска игры должна использоваться та же учётная запись, что выбрана для авторизации ServerBridge,
        // даже при асинхронном переключении хранилища.
        if credentials.uuid.replace('-', "").to_ascii_lowercase()!=context.expected_uuid.replace('-', "").to_ascii_lowercase() {
            return Err("UUID официального запуска отличается от авторизованной идентификации ServerBridge".into());
        }
        Some(credentials)
    } else { minecraft_credentials };
    // Привязывайте время жизни игры к конкретному аутентифицированному Guard на момент запуска. Супервизор не
    // примет перезапущенный Guard как продолжающийся сеанс.
    let guard_identity = game_guard_watchdog_0438::baseline_guard_0438(&guard).await?;
    let launched = if let Some(credentials) = minecraft_credentials {
        if let Some(p) = preferences {
            supervisor.start_authenticated_with_preferences(&manifest, &PathBuf::from(root), java_path, credentials, p, &pinned_public_key).await
        } else { supervisor.start_authenticated(&manifest, &PathBuf::from(root), java_path, credentials, &pinned_public_key).await }
    } else {
        match preferences {
            Some(p) if p.offline => supervisor.start_with_preferences(&manifest, &PathBuf::from(root), java_path, username, p, &pinned_public_key).await,
            _ => Err("Для сетевого запуска необходимы подтверждённые учётные данные; автономный запуск должен быть явно разрешён".into()),
        }
    }?;
    game_guard_watchdog_0438::start_game_watchdog_0438(
        guard.inner().clone(), supervisor.inner().clone(), launched.clone(), guard_identity,
    );
    Ok(launched)
}

#[tauri::command]
async fn guard_guard_attestation(
    request: GuardAttestationRequest,
    guard: tauri::State<'_, GuardSupervisor>,
) -> Result<GuardAttestationSubmission, String> {
    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    {
        let _ = (request, guard);
        return Err("Проверка аттестации Guard в рабочей сборке доступна только для Windows, Linux и macOS".to_string());
    }
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        let GuardAttestationRequest {
            backend_url, user_id, device_id, session_id, binding_epoch, launcher_version,
            challenge_id, challenge, challenge_expires_at,
        } = request;
        let attestation = guard.remote_attestation(&challenge_id, &challenge).await?;
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
        .map_err(|e| format!("Операция подписи аттестации Guard ключом устройства завершилась ошибкой: {e}"))??;
        if signing.key_algorithm != "p256" || signing.key_binding != "hardware" || !signing.hardware_bound {
            return Err("Подписывающий ключ аттестации Guard не является аппаратно привязанным ключом P-256".to_string());
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
async fn guard_guard_attestation_v2(
    request: GuardAttestationV2Request,
    guard: tauri::State<'_, GuardSupervisor>,
    supervisor: tauri::State<'_, ProcessSupervisor>,
) -> Result<GuardAttestationV2Submission, String> {
    #[cfg(not(windows))]
    {
        let _ = (request, guard, supervisor);
        Err("Непрерывное подтверждение аттестации Guard v2 доступно только для Windows".to_string())
    }
    #[cfg(windows)]
    {
        let GuardAttestationV2Request {
            backend_url, user_id, device_id, session_id, binding_epoch, launcher_version,
            challenge_id, challenge, challenge_expires_at, process_id,
        } = request;
        let process_status = supervisor.status(&process_id).await
            .map_err(|err| format!("Состояние среды выполнения для аттестации Guard v2 недоступно: {err}"))?;
        let continuous_evidence = runtime::collect_windows_continuous_evidence_v2(&process_id, &process_status)?;
        let base_attestation = guard.remote_attestation(&challenge_id, &challenge).await?;
        let attestation = runtime::build_windows_attestation_v2(
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
        .map_err(|e| format!("Операция подписи аттестации Guard v2 ключом устройства завершилась ошибкой: {e}"))??;
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
        return Err("Небезопасный нативный вспомогательный процесс обновления".into());
    }
    // Самообновление не должно перезаписывать исполняемый образ работающего обновлятора. Запускайте отдельную
    // подготовленную копию, а не соседний действующий бинарник CLI. Следующее обновление очищает старые копии
    // после выхода их процессов.
    let helper_stage_root = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
            .ok_or("Переменная LOCALAPPDATA недоступна для подготовки обновления")?
            .join("Launcher").join("updater-helpers")
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(PathBuf::from)
            .ok_or("Переменная HOME недоступна для подготовки обновления")?
            .join("Library").join("Caches").join("Launcher").join("updater-helpers")
    } else {
        std::env::var_os("XDG_RUNTIME_DIR").or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from).ok_or("Нет закрытого пользовательского каталога для подготовки обновления")?
            .join(".launcher").join("updater-helpers")
    };
    std::fs::create_dir_all(&helper_stage_root)
        .map_err(|e| format!("Не удалось подготовить временные файлы вспомогательной программы обновления: {e}"))?;
    let stage_meta = std::fs::symlink_metadata(&helper_stage_root).map_err(|e| e.to_string())?;
    if !stage_meta.file_type().is_dir() || stage_meta.file_type().is_symlink() {
        return Err("Промежуточный каталог обновления небезопасен".into());
    }
    for entry in std::fs::read_dir(&helper_stage_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            // Неудачная очистка не должна останавливать текущее обновление (блокировки файлов Windows).
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let helper_stage_dir = helper_stage_root.join(hex::encode(nonce));
    std::fs::create_dir(&helper_stage_dir).map_err(|e| format!("Подготовка области обновления: {e}"))?;
    let staged_helper = helper_stage_dir.join(launcher_update_helper_name());
    std::fs::copy(&helper, &staged_helper).map_err(|e| format!("Копирование вспомогательного файла обновления: {e}"))?;
    let copied = std::fs::metadata(&staged_helper).map_err(|e| e.to_string())?;
    if !copied.is_file() || copied.len() != helper_meta.len() {
        return Err("Проверка промежуточной области вспомогательного файла обновления не пройдена".into());
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
        return Err("Несовпадение SHA-256 подготовленного вспомогательного файла обновления".into());
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
    if cfg!(target_os = "windows") { "launcher-cli.exe" } else { "launcher-cli" }
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
    guard: tauri::State<'_, GuardSupervisor>,
    app: tauri::AppHandle,
) -> Result<LauncherUpdateScheduleResult, String> {
    let expected_sha256 = validate_update_sha256(&expected_sha256)?;
    let package = fs::canonicalize(PathBuf::from(package_path.trim()))
        .await
        .map_err(|e| format!("Пакет обновления недоступен: {e}"))?;
    let package_meta = fs::symlink_metadata(&package).await.map_err(|e| e.to_string())?;
    if !package_meta.file_type().is_file() || package_meta.file_type().is_symlink() || package_meta.len() == 0 {
        return Err("Пакет обновления должен быть непустым обычным файлом, а не символической ссылкой".into());
    }

    let current_exe = std::env::current_exe().map_err(|e| format!("Не удалось определить исполняемый файл Desktop: {e}"))?;
    let current_exe = std::fs::canonicalize(&current_exe).map_err(|e| format!("Не удалось получить канонический путь к исполняемому файлу Desktop: {e}"))?;
    let bin_dir = current_exe.parent().ok_or_else(|| "Не найден родительский каталог исполняемого файла Desktop".to_string())?;
    let helper = if cfg!(target_os = "macos") {
        let contents = bin_dir.parent().ok_or_else(|| "Исполняемый файл Desktop для macOS расположен вне каталога Contents/MacOS".to_string())?;
        let canonical = contents.join("Helpers").join(launcher_update_helper_name());
        if canonical.is_file() { canonical } else { bin_dir.join(launcher_update_helper_name()) }
    } else {
        bin_dir.join(launcher_update_helper_name())
    };
    let helper_meta = std::fs::symlink_metadata(&helper).map_err(|e| format!("Не найдена вспомогательная программа транзакционного обновления {}: {e}", helper.display()))?;
    if !helper_meta.file_type().is_file() || helper_meta.file_type().is_symlink() || helper_meta.len() == 0 {
        return Err(format!("Вспомогательный процесс транзакционного обновления небезопасен: {}", helper.display()));
    }

    let staged_helper = create_staged_updater_helper02310(&helper, bin_dir)?;
    // Guard удерживает дескрипторы и IPC, из-за которых Windows может считать исполняемый файл занятым.
    // Остановите его до того, как внешний помощник начнёт ожидание Desktop и выполнение транзакции.
    guard.shutdown().await.map_err(|e| format!("не удалось остановить Guard перед обновлением: {e}"))?;

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
    let child = command.spawn().map_err(|e| format!("Не удалось запустить вспомогательную программу транзакционного обновления: {e}"))?;
    let updater_pid = child.id().ok_or_else(|| "Вспомогательная программа обновления запущена без идентификатора процесса".to_string())?;
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
        message: "Обновление Desktop, Guard и Runtime передано внешней программе транзакционного обновления; Desktop будет перезапущен после подтверждения изменений".into(),
    })
}

#[tauri::command]
async fn guard_status(guard: tauri::State<'_, GuardSupervisor>) -> Result<GuardStatus, String> {
    guard.status().await
}
#[tauri::command]
async fn guard_integrity_evidence(guard: tauri::State<'_, GuardSupervisor>) -> Result<GuardIntegrityEvidence, String> {
    guard.integrity_evidence().await
}
#[tauri::command]
async fn guard_process_policy(guard: tauri::State<'_, GuardSupervisor>) -> Result<GuardProcessPolicyReport, String> {
    guard.process_policy().await
}
#[tauri::command]
async fn runtime_process_status(process_id: String, supervisor: tauri::State<'_, ProcessSupervisor>) -> Result<ProcessStatus, String> { supervisor.status(&process_id).await }
#[tauri::command]
async fn runtime_processes(supervisor: tauri::State<'_, ProcessSupervisor>) -> Result<Vec<ProcessStatus>, String> { Ok(supervisor.list().await) }
#[tauri::command]
async fn stop_runtime_process(process_id: String, supervisor: tauri::State<'_, ProcessSupervisor>) -> Result<ProcessStatus, String> { supervisor.stop(&process_id).await }
#[tauri::command]
async fn load_launch_history(root: String) -> Result<Vec<LaunchHistoryEntry>, String> { runtime::load_launch_history(&PathBuf::from(root)).await }

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

// Недоверенные URL ведут привилегированный Tauri WebView. Только явный щелчок игрока может открыть
// корректную HTTPS-ссылку в СИСТЕМНОМ браузере.
fn validate_external_https_0356(raw: &str) -> Result<reqwest::Url, String> {
    if raw.len() > 2048 || raw.bytes().any(|b| b.is_ascii_control() || b == b'\\') || !raw.starts_with("https://") {
        return Err("Разрешены только внешние ссылки HTTPS".into());
    }
    let url = reqwest::Url::parse(raw).map_err(|_| "Недопустимый внешний URL")?;
    if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("Небезопасный внешний URL".into());
    }
    Ok(url)
}

#[tauri::command]
async fn open_external_https_0356(url: String) -> Result<(), String> {
    let url = validate_external_https_0356(&url)?;
    let mut cmd;
    #[cfg(windows)] { cmd = Command::new("rundll32"); cmd.arg("url.dll,FileProtocolHandler").arg(url.as_str()); }
    #[cfg(target_os = "macos")] { cmd = Command::new("open"); cmd.arg(url.as_str()); }
    #[cfg(target_os = "linux")] { cmd = Command::new("xdg-open"); cmd.arg(url.as_str()); }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))] { return Err("Неподдерживаемая ОС".into()); }
    let mut child = cmd.kill_on_drop(false).spawn().map_err(|_| "Не удалось открыть системный браузер".to_string())?;
    tokio::spawn(async move { let _ = child.wait().await; });
    Ok(())
}

#[tauri::command]
async fn open_game_directory(root: String) -> Result<String, String> {
    // Расширения могут запрашивать лишь настроенный игровой корень активного игрока. Не передавайте их
    // относительный или произвольный путь как вызов файлового проводника ОС.
    let configured = load_desktop_config().await?;
    let allowed = PathBuf::from(configured.game_directory.trim());
    if !allowed.is_absolute() || !PathBuf::from(root.trim()).is_absolute() {
        return Err("Игровой каталог должен быть абсолютным настроенным путём".into());
    }
    fs::create_dir_all(&allowed).await.map_err(|e| format!("Не удалось подготовить игровой каталог: {e}"))?;
    let safe = fs::canonicalize(&allowed).await.map_err(|e| e.to_string())?;
    let requested = fs::canonicalize(root.trim()).await.map_err(|_| "Игровой каталог не существует")?;
    if requested != safe || !safe.is_dir() { return Err("Путь не соответствует активному настроенному игровому каталогу".into()); }
    let mut command = if cfg!(target_os="windows") { let mut c=Command::new("explorer"); c.arg(&safe); c } else if cfg!(target_os="macos") { let mut c=Command::new("open"); c.arg(&safe); c } else { let mut c=Command::new("xdg-open"); c.arg(&safe); c };
    command.spawn().map_err(|e| format!("Не удалось открыть игровой каталог: {e}"))?;
    Ok(safe.to_string_lossy().to_string())
}

// Запуск выполняется с отказом при ошибке: нельзя инициализировать Guard или интерфейс Launcher с частично
// переключённым набором компонентов. Восстановление запускается отдельным исполняемым файлом после выхода
// Desktop (ограничения совместного доступа Windows).
fn recover_components_before_desktop02310() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = std::fs::canonicalize(exe).map_err(|e| e.to_string())?;
    let bin_dir = exe.parent().ok_or("Не удалось определить каталог исполняемого файла Desktop")?;
    let root = if cfg!(target_os = "macos") {
        bin_dir.parent().and_then(std::path::Path::parent).and_then(std::path::Path::parent)
            .ok_or("Некорректный путь к приложению .app в macOS")?
    } else { bin_dir };
    let helper = if cfg!(target_os = "macos") {
        bin_dir.parent().ok_or("Некорректный путь к каталогу Contents в macOS")?.join("Helpers").join(launcher_update_helper_name())
    } else { bin_dir.join(launcher_update_helper_name()) };
    if !helper.is_file() { return Ok(()); } // В конфигурации только с Prestarter отсутствует средство обновления CLI.
    let hm = std::fs::symlink_metadata(&helper).map_err(|e| e.to_string())?;
    if !hm.file_type().is_file() || hm.file_type().is_symlink() {
        return Err("Небезопасный установленный вспомогательный файл обновления".into());
    }
    let status = std::process::Command::new(&helper)
        .args(["update", "status", "--root"])
        .arg(root)
        .output().map_err(|e| format!("Не удалось получить состояние восстановления компонентов: {e}"))?;
    if !status.status.success() {
        return Err(format!("Проверка журнала компонентов завершилась ошибкой: {}", String::from_utf8_lossy(&status.stderr)));
    }
    let report: serde_json::Value = serde_json::from_slice(&status.stdout)
        .map_err(|e| format!("Некорректное значение: состояние обновления компонентов: {e}"))?;
    if report.get("status").and_then(serde_json::Value::as_str) != Some("recovery-required") { return Ok(()); }
    let staged = create_staged_updater_helper02310(&helper, bin_dir)?;
    std::process::Command::new(staged)
        .args(["update", "recover", "--root"])
        .arg(root)
        .args(["--wait-pid", &std::process::id().to_string(), "--restart-desktop"])
        .arg(&exe)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|e| format!("Не удалось запустить восстановление компонентов: {e}"))?;
    std::process::exit(0);
}

// MIG09: не исполняйте ПО Gravit и не доверяйте его сеансам или ключам. Единственный источник доверия к
// повторно используемым байтам — существующий закреплённый манифест Launcher с Ed25519.
#[tauri::command]
fn player_migration_discover_0339() -> Vec<String> {
    runtime::player_migration_0339::discover()
}

#[tauri::command]
async fn player_migration_preview_0339(
    manifest: Manifest, pinned_public_key: String, legacy_root: String,
    component_preset: Option<String>,
) -> Result<runtime::player_migration_0339::PlayerMigrationPreview0339, String> {
    tokio::task::spawn_blocking(move || runtime::player_migration_0339::preview(
        &manifest, &pinned_public_key, std::path::Path::new(&legacy_root), component_preset.as_deref(),
    )).await.map_err(|e| format!("Ошибка: обработчик предварительного просмотра миграции: {e}"))?
}

#[tauri::command]
async fn player_migration_adopt_0339(
    manifest: Manifest, pinned_public_key: String, legacy_root: String,
    component_preset: Option<String>,
) -> Result<runtime::player_migration_0339::PlayerMigrationResult0339, String> {
    runtime::player_migration_0339::adopt(
        &manifest, &pinned_public_key, std::path::Path::new(&legacy_root), component_preset.as_deref(),
    ).await
}

/// Инструментирование производительности отключено без согласия родительского процесса. Вызывается только
/// после рендеринга React на двух кадрах анимации. Возвращает визуализатору данные окружения либо открывает
/// произвольный файловый ввод-вывод.
#[tauri::command]
fn benchmark_ui_ready_03511() -> Result<(), String> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    let filename = match std::env::var_os("LAUNCHER_BENCH_READY_FILE") {
        Some(name) => name,
        None => return Ok(()),
    };
    let path = std::path::PathBuf::from(filename);
    if !path.is_absolute() {
        return Err("Для маркер теста производительности требуется абсолютный путь".into());
    }
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "Недоступно: системные часы".to_string())?.as_nanos();
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
        .open(&path).map_err(|_| "маркер теста производительности: запрещено «be created»".to_string())?;
    write!(file, "{{\"wallClockUnixNs\":{nanos},\"stage\":\"react-first-paint\"}}")
        .map_err(|_| "Ошибка: запись маркера теста производительности".to_string())?;
    file.sync_all().map_err(|_| "Ошибка: синхронизация маркера теста производительности".to_string())?;
    Ok(())
}

fn main() {
    sentry_diagnostics_0309::install_panic_hook();
    if let Err(err) = recover_components_before_desktop02310() {
        eprintln!("Ошибка: контроль восстановления набора компонентов Launcher: {err}");
        std::process::exit(71);
    }
    #[cfg(windows)]
    if let Err(err) = runtime::ensure_windows_production_hardening() {
        eprintln!("Ошибка: промышленное усиление защиты Launcher Desktop в Windows: {err}");
        std::process::exit(70);
    }

    #[cfg(target_os = "linux")]
    if let Err(err) = runtime::linux_policy::ensure_linux_production_hardening() {
        eprintln!("Ошибка: промышленное усиление защиты Launcher Desktop в Linux: {err}");
        std::process::exit(70);
    }

    #[cfg(target_os = "macos")]
    if let Err(err) = runtime::macos_policy::ensure_macos_production_hardening() {
        eprintln!("Ошибка: промышленное усиление защиты Launcher Desktop в macOS: {err}");
        std::process::exit(70);
    }

    if let Err(err)=initialize_desktop_game_trust_02312(){
        eprintln!("Конфигурация доверия Launcher Desktop отклонена: {err}");
        std::process::exit(71);
    }
    tauri::Builder::default()
        .manage(official_identity_0262::IdentityManager::new().expect("Не удалось инициализировать нативный HTTP-клиент официальной авторизации"))
        .manage(discord_presence_0308::DiscordPresence::default())
        .manage(diagnostics_bundle_03510::DiagnosticsSession03510::default())
        .manage(ProcessSupervisor::new())
        .manage(GuardSupervisor::new())
        .setup(|app| { println!("Launcher Desktop {} / среда выполнения", env!("CARGO_PKG_VERSION")); let _=app.handle(); Ok(()) })
        .invoke_handler(tauri::generate_handler![benchmark_ui_ready_03511,preview_release_requirements_0359,preview_player_conflicts_0359,preserve_player_conflicts_0359,player_migration_discover_0339,player_migration_preview_0339,player_migration_adopt_0339,official_identity_0262::official_identity_prepare_join_0397,official_identity_0262::official_identity_links_0268,official_identity_0262::official_identity_link_0268,official_identity_0262::official_identity_unlink_0268,official_identity_0262::official_identity_accounts_0267,official_identity_0262::official_identity_select_0267,official_identity_0262::official_identity_refresh_0267,official_identity_0262::official_identity_logout_0267,official_identity_0262::official_identity_browser_login_0263,official_identity_0262::official_identity_begin_0262,official_identity_0262::official_identity_poll_0262,official_identity_0262::official_identity_wait_device_0264,official_identity_0262::official_identity_status_0262,official_identity_0262::official_identity_texture_0262,official_identity_0262::official_identity_cancel_0262,official_identity_0262::official_identity_disconnect_0262,load_desktop_config,load_signed_provisioning_0352,save_desktop_config,complete_first_run_0352,reset_desktop_binding,store_auth_session,load_auth_session,delete_auth_session,ensure_device_key,device_key_status,macos_trust_status_0316,windows_tpm_certify_0313,linux_tpm_certify_0314,measured_boot_quote_0315,hwid_risk_0299::hardware_risk_signal_0299,sign_device_payload,attest_device_payload,stage_device_key_replacement,staged_device_key_status,sign_staged_device_replacement,sign_current_device_replacement,commit_staged_device_key,abort_staged_device_key,bind_device_key,sign_session_refresh,reset_device_key,delete_device_key,load_manifest,preview_components_0244,preview_component_changes_0247,installed_component_choice_0247,save_installed_component_choice_0247,active_selection_02410,attest_verified_component_plan_02412,export_component_selection_02410,preview_component_migration_02410,preview_import_component_selection_02410,cache_desktop_manifest,load_cached_desktop_manifest,prepare_offline_launch_0358,verify_manifest_signature,check_files,validate_desktop_settings,diagnostics_bundle_03510::preview_diagnostics_bundle_03510,diagnostics_bundle_03510::export_diagnostics_bundle_03510,open_game_directory,open_external_https_0356,download_missing_files,repair_client,pending_download_job,control_download_job,resume_download_job,rollback_client_release,recover_client_release,clean_unused_files,prepare_profile_directory,check_java,ensure_managed_java,ensure_profile_managed_java,build_launch_plan,launch_minecraft,guard_status,guard_integrity_evidence,guard_process_policy,guard_guard_attestation,guard_guard_attestation_v2,install_launcher_update,runtime_process_status,runtime_processes,stop_runtime_process,load_launch_history,desktop_extension_platform_info,desktop_native_ui_info_0357,desktop_window_action_0357,discord_presence_0308::discord_presence_set,discord_presence_0308::discord_presence_clear,sentry_diagnostics_0309::desktop_sentry_consent,sentry_diagnostics_0309::desktop_sentry_report])
        .run(tauri::generate_context!()).expect("ошибка запуска Tauri-приложения");
}

#[cfg(test)]
mod launch_realm_0269_tests {
    use super::*;
    fn local() -> MinecraftLaunchCredentials {
        MinecraftLaunchCredentials{username:"LauncherPlayer".into(),uuid:"11111111222233334444555555555555".into(),access_token:"project-token".into(),user_type:"mojang".into(),auth_server_base_url:"https://example".into()}
    }
    #[test]
    fn native_rejects_cross_realm_launch() {
        let local=local();
        let online=runtime::LaunchPreferences::default();
        let offline=runtime::LaunchPreferences{offline:true,..Default::default()};
        assert!(validate_launch_realm_0269(LaunchRealm0269::Yggdrasil,Some(&local),false,Some(&online)).is_ok());
        assert!(validate_launch_realm_0269(LaunchRealm0269::Yggdrasil,Some(&local),false,Some(&offline)).is_err());
        assert!(validate_launch_realm_0269(LaunchRealm0269::Official,Some(&local),true,Some(&online)).is_err());
        assert!(validate_launch_realm_0269(LaunchRealm0269::Official,None,true,Some(&online)).is_ok());
        assert!(validate_launch_realm_0269(LaunchRealm0269::Offline,None,false,Some(&offline)).is_ok());
        assert!(validate_launch_realm_0269(LaunchRealm0269::Offline,Some(&local),false,Some(&offline)).is_err());
    }
}

#[cfg(test)]
mod external_https_security_0356_tests {
    use super::validate_external_https_0356;
    #[test]
    fn only_https_absolute_browser_urls() {
        for ok in ["https://example.com/help", "https://example.com:443/news?a=b"] {
            assert!(validate_external_https_0356(ok).is_ok(),"{ok}");
        }
        for bad in ["http://example.com", "file:///etc/passwd", "javascript:alert(1)",
            "https://user:password@example.com/", "https://example.com/#secret",
            "https://example.com\\@evil.test", "https://example.com\nfoo"] {
            assert!(validate_external_https_0356(bad).is_err(),"{bad}");
        }
    }
}

#[cfg(test)]
mod desktop_window_0357_tests {
    use super::*;
    #[test]
    fn actions_are_explicit_and_no_shell_or_file_access_is_accepted() {
        assert_eq!(parse_desktop_window_action_0357("minimize").unwrap(), DesktopWindowAction0357::Minimize);
        assert_eq!(parse_desktop_window_action_0357("toggleMaximized").unwrap(), DesktopWindowAction0357::ToggleMaximized);
        for unsupported in ["close","open","execute","shell", "resize", "", "togglemaximized"] {
            assert!(parse_desktop_window_action_0357(unsupported).is_err());
        }
    }
}

#[cfg(test)]
mod offline_policy_0358_tests {
    use super::*;
    fn manifest() -> Manifest {
        serde_json::from_value(serde_json::json!({
            "schemaVersion":"2.0", "projectId":"owner", "profileId":"client", "channel":"stable",
            "version":"release-1", "createdAt":"2026-10-28T00:00:00Z",
            "minecraft":{"version":"1.21.1", "loader":"vanilla"},
            "runtime":{"java":{"majorVersion":21,"distribution":"temurin"},
                       "launch":{"offlineMode":true}},
            "files":[],
            "signature":{"algorithm":"ed25519","publicKey":"aa","signature":"signed","signedAt":"2026-10-28T00:00:00Z"}
        })).unwrap()
    }
    #[test]
    fn offline_requires_owner_scope_exact_release_and_completed_install() {
        let dir=std::env::temp_dir().join(format!("nl-offline-policy-{}-{}",std::process::id(),rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path=dir.to_string_lossy().to_string();
        let mut cfg=default_desktop_config();
        cfg.game_directory=path.clone();cfg.project_id="owner".into();cfg.profile_id="client".into();
        cfg.channel="stable".into();cfg.pinned_public_key="aa".into();
        cfg.onboarding_completed=true;cfg.onboarding_bootstrap_digest="digest".into();
        let owner=signed_first_run_0352::Provisioning0352 {
            backend_url:"https://example.test".into(),project_id:"owner".into(),profile_id:"client".into(),
            channel:"stable".into(),manifest_url:"https://example.test/manifest".into(),
            pinned_public_key:"aa".into(),display_name:"Owner".into(),server_id:String::new(),
            server_host:String::new(),server_port:25565,auto_enter:false,digest:"digest".into(),branding:None,
        };
        let m=manifest();
        assert!(check_offline_owner_binding_0358(&cfg,&owner,&m,&path,"aa",true).is_ok());
        cfg.onboarding_completed=false;
        assert!(check_offline_owner_binding_0358(&cfg,&owner,&m,&path,"aa",true).is_err());
        cfg.onboarding_completed=true;
        assert!(check_offline_owner_binding_0358(&cfg,&owner,&m,&path,"bb",true).is_err());
        let mut changed=m.clone();changed.project_id="other".into();
        assert!(check_offline_owner_binding_0358(&cfg,&owner,&changed,&path,"aa",true).is_err());
        changed=m.clone();changed.channel="beta".into();
        assert!(check_offline_owner_binding_0358(&cfg,&owner,&changed,&path,"aa",true).is_err());
        changed=m.clone();changed.runtime.launch.offline_mode=false;
        assert!(check_offline_owner_binding_0358(&cfg,&owner,&changed,&path,"aa",true).is_err());
        changed=m.clone();changed.version="release-2".into();
        assert!(matching_offline_release_0358(&m,&changed).is_err());
        changed=m.clone();changed.signature.as_mut().unwrap().signature="tampered".into();
        assert!(matching_offline_release_0358(&m,&changed).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod desktop_settings_0359_tests {
    use super::*;
    #[test]
    fn old_preferences_survive_upgrade_and_future_schema_fails_closed(){
        let mut old=default_desktop_config();
        old.schema_version="1.0".into();
        old.username="Saved Player".into();
        old.memory_mb=6144;old.component_preset="performance".into();
        old.extra_preferences_0359.insert("customZoom".into(),serde_json::json!(125));
        let encoded=serde_json::to_vec(&old).unwrap();
        let mut decoded:DesktopConfig=serde_json::from_slice(&encoded).unwrap();
        validate_desktop_config_schema_0359(&decoded.schema_version).unwrap();
        decoded=normalize_desktop_config(decoded);
        decoded.schema_version="1.1".into();
        let migrated:DesktopConfig=serde_json::from_slice(&serde_json::to_vec(&decoded).unwrap()).unwrap();
        assert_eq!(migrated.username,"Saved Player");
        assert_eq!(migrated.memory_mb,6144);
        assert_eq!(migrated.component_preset,"performance");
        assert_eq!(migrated.extra_preferences_0359.get("customZoom"),Some(&serde_json::json!(125)));
        assert!(validate_desktop_config_schema_0359("9.0").is_err());
    }
    #[tokio::test]
    async fn backup_before_first_settings_upgrade_is_exact_and_non_destructive(){
        let dir=std::env::temp_dir().join(format!("nl-settings-0359-{:x}",rand::random::<u64>()));
        fs::create_dir_all(&dir).await.unwrap();
        let file=dir.join("config.json");
        let original=serde_json::to_vec(&default_desktop_config()).unwrap();
        fs::write(&file,&original).await.unwrap();
        preserve_legacy_config_0359(&file).await.unwrap();
        assert_eq!(fs::read(dir.join("config.pre-0359.json")).await.unwrap(),original);
        assert_eq!(fs::read(&file).await.unwrap(),original);
        fs::remove_dir_all(&dir).await.unwrap();
    }
}
