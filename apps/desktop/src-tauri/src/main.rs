mod device_keys;

use neverruntime::{
    self, CleanUnusedResult, DownloadResult, FileCheckResult, JavaInfoResult, LaunchHistoryEntry,
    GuardProcessPolicyReport, LaunchPlan, ManagedJavaResult, Manifest, MinecraftLaunchCredentials,
    NeverGuardIntegrityEvidence, NeverGuardStatus, NeverGuardSupervisor, ProcessStatus,
    ProcessSupervisor, RepairResult, SignatureCheckResult, NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use tauri::Manager;
use device_keys::{DeviceKeyInfo, DeviceSignatureResult};
use tokio::{fs, process::Command};
use zeroize::Zeroize;


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
    project_id: String,
    profile_id: String,
    channel: String,
    game_directory: String,
    java_path: String,
    username: String,
    memory_mb: u32,
    pinned_public_key: String,
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
fn default_game_directory() -> String {
    let base = if cfg!(windows) { std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".")) }
    else if let Ok(home) = std::env::var("HOME") { PathBuf::from(home).join(".local").join("share") }
    else { PathBuf::from(".") };
    base.join("NeverLauncher").join("projects").to_string_lossy().to_string()
}
fn default_desktop_config() -> DesktopConfig {
    DesktopConfig { schema_version: "1.0".into(), backend_url: String::new(), project_id: String::new(), profile_id: String::new(), channel: "stable".into(), game_directory: default_game_directory(), java_path: String::new(), username: "Player".into(), memory_mb: 4096, pinned_public_key: String::new(), config_path: String::new() }
}
fn normalize_desktop_config(mut cfg: DesktopConfig) -> DesktopConfig {
    if cfg.schema_version.trim().is_empty() { cfg.schema_version = "1.0".into(); }
    if cfg.channel.trim().is_empty() { cfg.channel = "stable".into(); }
    if cfg.game_directory.trim().is_empty() { cfg.game_directory = default_game_directory(); }
    if cfg.username.trim().is_empty() { cfg.username = "Player".into(); }
    if cfg.memory_mb == 0 { cfg.memory_mb = 4096; }
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
async fn check_files(manifest: Manifest, root: String) -> Result<Vec<FileCheckResult>, String> { neverruntime::check_files(&manifest, &PathBuf::from(root)).await }
#[tauri::command]
async fn download_missing_files(manifest: Manifest, root: String, pinned_public_key: String) -> Result<DownloadResult, String> { neverruntime::download_missing_files(&manifest, &PathBuf::from(root), &pinned_public_key).await }
#[tauri::command]
async fn repair_client(manifest: Manifest, root: String, pinned_public_key: String) -> Result<RepairResult, String> { neverruntime::repair_client(&manifest, &PathBuf::from(root), &pinned_public_key).await }
#[tauri::command]
async fn clean_unused_files(manifest: Manifest, root: String) -> Result<CleanUnusedResult, String> { neverruntime::clean_unused_files(&manifest, &PathBuf::from(root)).await }
#[tauri::command]
async fn prepare_profile_directory(base_dir: String, project_id: String, profile_id: String) -> Result<String, String> { Ok(neverruntime::prepare_profile_directory(&PathBuf::from(base_dir), &project_id, &profile_id).await?.to_string_lossy().to_string()) }
#[tauri::command]
async fn check_java(java_path: Option<String>, required_major_version: Option<u32>) -> Result<JavaInfoResult, String> { neverruntime::check_java(java_path, required_major_version).await }
#[tauri::command]
async fn ensure_managed_java(required_major_version: u32, distribution: String) -> Result<ManagedJavaResult, String> { neverruntime::ensure_managed_java(required_major_version, &distribution, None).await }
#[tauri::command]
async fn build_launch_plan(manifest: Manifest, root: String, java_path: Option<String>, username: Option<String>, pinned_public_key: String) -> Result<LaunchPlan, String> { neverruntime::build_launch_plan(&manifest, &PathBuf::from(root), java_path, username, &pinned_public_key).await }
#[tauri::command]
async fn launch_minecraft(manifest: Manifest, root: String, java_path: Option<String>, username: Option<String>, minecraft_credentials: Option<MinecraftLaunchCredentials>, pinned_public_key: String, supervisor: tauri::State<'_, ProcessSupervisor>, neverguard: tauri::State<'_, NeverGuardSupervisor>) -> Result<ProcessStatus, String> {
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
    #[cfg(not(windows))]
    let _ = &neverguard;

    if let Some(credentials) = minecraft_credentials {
        supervisor.start_authenticated(&manifest, &PathBuf::from(root), java_path, credentials, &pinned_public_key).await
    } else {
        supervisor.start(&manifest, &PathBuf::from(root), java_path, username, &pinned_public_key).await
    }
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

fn main() {
    tauri::Builder::default()
        .manage(ProcessSupervisor::new())
        .manage(NeverGuardSupervisor::new())
        .setup(|app| { println!("NeverLauncher Desktop {} / NeverRuntime", env!("CARGO_PKG_VERSION")); let _=app.handle(); Ok(()) })
        .invoke_handler(tauri::generate_handler![load_desktop_config,save_desktop_config,reset_desktop_binding,store_auth_session,load_auth_session,delete_auth_session,ensure_device_key,device_key_status,sign_device_payload,attest_device_payload,stage_device_key_replacement,staged_device_key_status,sign_staged_device_replacement,sign_current_device_replacement,commit_staged_device_key,abort_staged_device_key,bind_device_key,sign_session_refresh,reset_device_key,delete_device_key,load_manifest,verify_manifest_signature,check_files,validate_desktop_settings,export_diagnostics_bundle,open_game_directory,download_missing_files,repair_client,clean_unused_files,prepare_profile_directory,check_java,ensure_managed_java,build_launch_plan,launch_minecraft,neverguard_status,neverguard_integrity_evidence,neverguard_process_policy,runtime_process_status,runtime_processes,stop_runtime_process,load_launch_history])
        .run(tauri::generate_context!()).expect("ошибка запуска Tauri-приложения");
}
