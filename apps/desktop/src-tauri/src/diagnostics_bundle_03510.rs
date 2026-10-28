//! 0.35.10 player diagnostics: explicit preview, no raw logs, one-time export.
//! The untrusted WebView never selects an output path or supplies the exported JSON.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::{self, OpenOptions}, io::Write, path::Path, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};
use tauri::State;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticEvent03510 { pub code: String, pub count: u32 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlayerReport03510 {
    pub schema_version: String,
    pub launcher_version: String,
    pub generated_at_unix: u64,
    pub os: String,
    pub arch: String,
    pub stage: String,
    pub events: Vec<DiagnosticEvent03510>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticPreview03510 { pub review_token: String, pub report: PlayerReport03510 }
struct PendingPreview { token: String, report: PlayerReport03510, created: u64 }
#[derive(Default)]
pub struct DiagnosticsSession03510(Mutex<Option<PendingPreview>>);
fn now() -> Result<u64, String> { Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "invalid system clock")?.as_secs()) }
fn stage(raw: &str) -> &'static str { match raw {
    "idle" => "idle", "ready" => "ready", "installing" => "installing",
    "checking" => "checking", "running" => "running", "failed" => "failed",
    "downloading" => "downloading", "staged" => "staged", "verifying" => "verifying",
    "launching" => "launching", _ => "other" } }
// No free-form log data is ever preserved. Classify known operational conditions
// and discard paths, URLs, account IDs, secrets, usernames, commands and stacks.
fn classify(line: &str) -> &'static str {
    let s = line.to_ascii_lowercase();
    if s.contains("signature") || s.contains("подпис") || s.contains("ed25519") { "signature" }
    else if s.contains("offline") || s.contains("кеш") || s.contains("cache") { "offline-cache" }
    else if s.contains("download") || s.contains("загрузк") || s.contains("http ") { "download" }
    else if s.contains("auth") || s.contains("вход") || s.contains("session") { "authentication" }
    else if s.contains("sha256") || s.contains("хеш") || s.contains("integrity") { "integrity" }
    else if s.contains("java") || s.contains("minecraft") || s.contains("запуск") { "runtime" }
    else if s.contains("repair") || s.contains("восстанов") || s.contains("rollback") { "recovery" }
    else if s.contains("permission") || s.contains("доступ") { "permission" }
    else if s.contains("error") || s.contains("ошиб") || s.contains("failed") { "other-error" }
    else { "other" }
}
fn make_report(lines: Vec<String>, raw_stage: String, at: u64) -> PlayerReport03510 {
    let mut summary = BTreeMap::<&'static str, u32>::new();
    // Renderer input is bounded before classification. Raw strings never escape this function.
    for line in lines.into_iter().take(80) {
        let code = classify(&line.chars().take(2048).collect::<String>());
        *summary.entry(code).or_default() += 1;
    }
    PlayerReport03510 { schema_version: "1.1".into(), launcher_version: env!("CARGO_PKG_VERSION").into(),
        generated_at_unix: at, os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into(),
        stage: stage(&raw_stage).into(), events: summary.into_iter().map(|(code,count)| DiagnosticEvent03510{code:code.into(),count}).collect() }
}
#[tauri::command]
pub fn preview_diagnostics_bundle_03510(stage: String, logs: Vec<String>, session: State<'_, DiagnosticsSession03510>) -> Result<DiagnosticPreview03510, String> {
    if logs.len()>80 || logs.iter().any(|line|line.len()>8192) {return Err("diagnostics log input too large".into());}
    let at = now()?;
    let report = make_report(logs, stage, at);
    let token = hex::encode(rand::random::<[u8; 24]>());
    *session.0.lock().map_err(|_| "diagnostics preview unavailable")? = Some(PendingPreview {token: token.clone(), report: report.clone(), created: at});
    Ok(DiagnosticPreview03510{review_token:token,report})
}
fn write_private_bundle(base: &Path, report: &PlayerReport03510) -> Result<String, String> {
    fs::create_dir_all(base).map_err(|_| "cannot prepare diagnostics directory")?;
    let meta = fs::symlink_metadata(base).map_err(|_| "diagnostics directory inaccessible")?;
    if !meta.is_dir() || meta.file_type().is_symlink() { return Err("unsafe diagnostics directory".into()); }
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(base,fs::Permissions::from_mode(0o700)).map_err(|_|"cannot restrict diagnostics directory")?; }
    let file_id = hex::encode(rand::random::<[u8; 16]>());
    let name = format!("neverlauncher-player-{file_id}.json");
    let path = base.join(&name);
    let mut opts = OpenOptions::new(); opts.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
    let mut file = opts.open(&path).map_err(|_| "cannot create diagnostics file")?;
    let content = serde_json::to_vec_pretty(report).map_err(|_| "diagnostics serialization failed")?;
    let result = file.write_all(&content).and_then(|_| file.sync_all());
    if result.is_err() { let _ = fs::remove_file(&path); return Err("cannot safely save diagnostics".into()); }
    Ok(path.to_string_lossy().into_owned())
}
#[tauri::command]
pub fn export_diagnostics_bundle_03510(review_token: String, session: State<'_, DiagnosticsSession03510>) -> Result<super::DiagnosticsExportResult, String> {
    let mut guard=session.0.lock().map_err(|_|"diagnostics preview unavailable")?;
    let preview=guard.as_ref().ok_or("Create a new diagnostic preview first")?;
    if preview.token != review_token || now()?.saturating_sub(preview.created) > 600 {return Err("Diagnostic preview expired; review again".into());}
    let report=preview.report.clone();
    // A report is only written into the app-owned config directory, never into
    // an arbitrary renderer-chosen path or a game-managed directory.
    let base=super::desktop_config_dir()?.join("diagnostics");
    let path=write_private_bundle(&base,&report)?;
    *guard=None;
    Ok(super::DiagnosticsExportResult { path, message: "Проверенный диагностический пакет сохранён локально".into() })
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn raw_sensitive_data_never_leaves_classification() {
        let lines=vec!["Authorization: Bearer SECRET_123 https://private.test?token=abc C:\\Users\\alice\\private".into(),
          "ошибка загрузки /home/alice/auth.json password=123".into()];
        let r=make_report(lines,"file:///private/path".into(),123);
        let serialized=serde_json::to_string(&r).unwrap();
        for secret in ["SECRET_123","private.test","abc","alice","password=123", "file://"] {assert!(!serialized.contains(secret),"leaked {secret}");}
        assert_eq!(r.stage,"other");
        assert_eq!(r.events.iter().map(|v|v.count).sum::<u32>(),2);
    }
    #[test] fn disk_file_is_exact_preview_and_private() {
        let dir=std::env::temp_dir().join(format!("nl-diagnostics-{}",hex::encode(rand::random::<[u8;8]>())));
        let r=make_report(vec!["java crash token=XYZ".into()],"failed".into(),123);
        let name=write_private_bundle(&dir,&r).unwrap();
        let stored:PlayerReport03510=serde_json::from_slice(&fs::read(&name).unwrap()).unwrap();
        assert_eq!(stored,r);
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(fs::metadata(name).unwrap().permissions().mode() & 0o777,0o600);}
        let _=fs::remove_dir_all(dir);
    }
}
