pub mod compatibility;
pub mod supervisor;
pub use compatibility::{resolve_compatibility, CompatibilityContext, CompatibilityEnvironment, CompatibilityResolution, ResolvedLibrary, ResolvedNative};
pub use supervisor::{ProcessStatus, ProcessSupervisor};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    process::Stdio,
    io::SeekFrom,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process::Command,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: String,
    pub project_id: String,
    pub profile_id: String,
    pub channel: String,
    pub version: String,
    pub created_at: String,
    pub minecraft: MinecraftInfo,
    pub runtime: RuntimeInfo,
    #[serde(default)]
    pub directories: Directories,
    pub files: Vec<ManifestFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftInfo {
    pub version: String,
    pub loader: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub loader_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub game_args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInfo {
    pub java: JavaInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jvm_args: Vec<String>,
    #[serde(default)]
    pub memory: MemoryInfo,
    #[serde(default)]
    pub launch: RuntimeLaunch,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JavaInfo {
    pub major_version: u32,
    pub distribution: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_custom_path: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct MemoryInfo {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub minimum_mb: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub recommended_mb: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub maximum_mb: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLaunch {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main_class: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub classpath_strategy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub natives_directory: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version_metadata_path: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub features: HashMap<String, bool>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub offline_mode: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Directories {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub game: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub assets: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub libraries: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub natives: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub url: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_os: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureCheckResult {
    pub valid: bool,
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileCheckResult {
    pub path: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DownloadResult {
    pub downloaded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub repaired: usize,
    pub bytes_downloaded: u64,
    pub failed_files: Vec<String>,
    pub messages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RepairResult {
    pub status: String,
    pub before: Vec<FileCheckResult>,
    pub download: DownloadResult,
    pub after: Vec<FileCheckResult>,
    pub repaired: usize,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CleanUnusedResult {
    pub moved: usize,
    pub preserved: usize,
    pub quarantine_dir: String,
    pub messages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchHistoryEntry {
    pub started_at: String,
    pub project_id: String,
    pub profile_id: String,
    pub version: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub log_path: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JavaInfoResult {
    pub found: bool,
    pub compatible: bool,
    pub required_major_version: u32,
    pub detected_major_version: Option<u32>,
    pub executable: String,
    pub version_output: String,
    pub recommended_memory_mb: Option<u32>,
    pub maximum_memory_mb: Option<u32>,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchPlan {
    pub java_executable: String,
    pub working_directory: String,
    pub main_class: String,
    pub classpath_entries: Vec<String>,
    pub jvm_args: Vec<String>,
    pub game_args: Vec<String>,
    pub command_preview: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchResult {
    pub exit_code: Option<i32>,
    pub success: bool,
    pub log_path: String,
    pub stdout: String,
    pub stderr: String,
    pub message: String,
}

pub async fn load_manifest(url: &str, pinned_public_key: &str) -> Result<Manifest, String> {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|err| format!("не удалось запросить манифест: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("backend вернул статус {}", response.status()));
    }
    let manifest = response
        .json::<Manifest>()
        .await
        .map_err(|err| format!("не удалось разобрать манифест: {err}"))?;
    verify_manifest_signature(&manifest, pinned_public_key)?;
    Ok(manifest)
}

pub fn verify_manifest_signature(manifest: &Manifest, pinned_public_key: &str) -> Result<SignatureCheckResult, String> {
    let pinned = pinned_public_key.trim();
    if pinned.is_empty() {
        return Err("pinned Ed25519 public key обязателен; trust-on-first-use запрещён".to_string());
    }
    let signature_info = manifest
        .signature
        .clone()
        .ok_or_else(|| "в манифесте отсутствует блок signature".to_string())?;
    if signature_info.algorithm != "Ed25519" {
        return Err(format!("неподдерживаемый алгоритм подписи: {}", signature_info.algorithm));
    }
    let public_key_hex = signature_info.public_key.trim().to_string();
    if !pinned.eq_ignore_ascii_case(&public_key_hex) {
        return Err("публичный ключ манифеста не совпадает с закреплённым ключом проекта".to_string());
    }
    let public_key_bytes = hex::decode(&public_key_hex)
        .map_err(|err| format!("публичный ключ не является hex-строкой: {err}"))?;
    let signature_bytes = hex::decode(&signature_info.signature)
        .map_err(|err| format!("подпись не является hex-строкой: {err}"))?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "публичный ключ Ed25519 должен иметь длину 32 байта".to_string())?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "подпись Ed25519 должна иметь длину 64 байта".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|err| format!("публичный ключ Ed25519 некорректен: {err}"))?;
    let signature = Signature::from_bytes(&signature_array);
    let payload = manifest_signing_payload(manifest)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| "подпись манифеста не прошла проверку".to_string())?;
    Ok(SignatureCheckResult {
        valid: true,
        public_key: public_key_hex,
        message: "подпись манифеста корректна и соответствует pinned key".to_string(),
    })
}

pub fn sign_manifest(manifest: &mut Manifest, private_key_hex: &str, signed_at: &str) -> Result<String, String> {
    let bytes = hex::decode(private_key_hex.trim()).map_err(|err| format!("private key не является hex: {err}"))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| "Ed25519 private key seed должен быть 32 байта".to_string())?;
    manifest.signature = None;
    let payload = manifest_signing_payload(manifest)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(&payload);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    manifest.signature = Some(SignatureInfo {
        algorithm: "Ed25519".to_string(),
        public_key: public_key.clone(),
        signature: hex::encode(signature.to_bytes()),
        signed_at: signed_at.to_string(),
    });
    Ok(public_key)
}

fn manifest_signing_payload(manifest: &Manifest) -> Result<Vec<u8>, String> {
    let mut unsigned = manifest.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned).map_err(|err| format!("не удалось сериализовать payload подписи: {err}"))
}

pub async fn check_files(manifest: &Manifest, root: &Path) -> Result<Vec<FileCheckResult>, String> {
    let mut results = Vec::with_capacity(manifest.files.len());
    for file in &manifest.files {
        if !manifest_file_applies(file) { continue; }
        let local_path = safe_join(root, &file.path)?;
        match fs::metadata(&local_path).await {
            Ok(metadata) => {
                if metadata.len() != file.size {
                    results.push(FileCheckResult { path: file.path.clone(), status: "invalid".into(), message: "размер файла не совпадает".into() });
                    continue;
                }
                let hash = sha256_file(&local_path).await?;
                if hash.eq_ignore_ascii_case(&file.sha256) {
                    results.push(FileCheckResult { path: file.path.clone(), status: "ok".into(), message: "файл актуален".into() });
                } else {
                    results.push(FileCheckResult { path: file.path.clone(), status: "invalid".into(), message: "SHA-256 не совпадает".into() });
                }
            }
            Err(_) => results.push(FileCheckResult { path: file.path.clone(), status: "missing".into(), message: "файл отсутствует".into() }),
        }
    }
    Ok(results)
}

pub async fn download_missing_files(manifest: &Manifest, root: &Path, pinned_public_key: &str) -> Result<DownloadResult, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    let client = reqwest::Client::new();
    let mut result = DownloadResult { downloaded: 0, skipped: 0, failed: 0, repaired: 0, bytes_downloaded: 0, failed_files: Vec::new(), messages: Vec::new() };

    for file in &manifest.files {
        if !manifest_file_applies(file) { result.skipped += 1; continue; }
        let local_path = safe_join(root, &file.path)?;
        let is_actual = match fs::metadata(&local_path).await {
            Ok(metadata) if metadata.len() == file.size => sha256_file(&local_path).await.map(|hash| hash.eq_ignore_ascii_case(&file.sha256)).unwrap_or(false),
            _ => false,
        };
        if is_actual {
            result.skipped += 1;
            continue;
        }
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await.map_err(|err| format!("не удалось создать каталог {}: {err}", parent.display()))?;
        }

        let mut response = match client.get(&file.url).send().await {
            Ok(response) => response,
            Err(err) => {
                result.failed += 1;
                result.failed_files.push(file.path.clone());
                result.messages.push(format!("{}: ошибка запроса: {err}", file.path));
                continue;
            }
        };
        if !response.status().is_success() {
            result.failed += 1;
            result.failed_files.push(file.path.clone());
            result.messages.push(format!("{}: HTTP {}", file.path, response.status()));
            continue;
        }

        let part_path = local_path.with_extension("nlpart");
        let mut output = fs::File::create(&part_path).await.map_err(|err| format!("не удалось создать временный файл {}: {err}", part_path.display()))?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        while let Some(chunk) = response.chunk().await.map_err(|err| format!("{}: ошибка чтения response stream: {err}", file.path))? {
            hasher.update(&chunk);
            output.write_all(&chunk).await.map_err(|err| format!("не удалось записать {}: {err}", part_path.display()))?;
            written += chunk.len() as u64;
        }
        output.flush().await.map_err(|err| format!("не удалось flush {}: {err}", part_path.display()))?;
        let hash = hex::encode(hasher.finalize());
        if written != file.size || !hash.eq_ignore_ascii_case(&file.sha256) {
            let _ = fs::remove_file(&part_path).await;
            result.failed += 1;
            result.failed_files.push(file.path.clone());
            result.messages.push(format!("{}: скачанный файл не прошёл size/SHA-256 verification", file.path));
            continue;
        }
        fs::rename(&part_path, &local_path).await.map_err(|err| format!("не удалось атомарно заменить {}: {err}", local_path.display()))?;
        set_executable_if_needed(&local_path, file.executable).await?;
        result.downloaded += 1;
        result.repaired += 1;
        result.bytes_downloaded += written;
    }
    Ok(result)
}

pub async fn repair_client(manifest: &Manifest, root: &Path, pinned_public_key: &str) -> Result<RepairResult, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    let before = check_files(manifest, root).await?;
    let download = download_missing_files(manifest, root, pinned_public_key).await?;
    let after = check_files(manifest, root).await?;
    let broken_after = after.iter().filter(|item| item.status != "ok").count();
    Ok(RepairResult {
        status: if broken_after == 0 { "ready" } else { "failed" }.to_string(),
        before,
        repaired: download.repaired,
        download,
        after,
        message: if broken_after == 0 { "Repair завершён: клиент соответствует manifest".to_string() } else { format!("Repair завершён, но осталось проблемных файлов: {broken_after}") },
    })
}

pub async fn clean_unused_files(manifest: &Manifest, root: &Path) -> Result<CleanUnusedResult, String> {
    let mut expected: HashSet<String> = HashSet::new();
    for file in &manifest.files { expected.insert(file.path.replace('\\', "/")); }
    let preserve_prefixes = ["saves", "screenshots", "resourcepacks", "shaderpacks", "logs", "diagnostics"];
    let preserve_files = ["options.txt", "servers.dat"];
    let started_at = now_unix()?;
    let quarantine = root.join(".neverlauncher-quarantine").join(started_at.to_string());
    let mut moved = 0usize;
    let mut preserved = 0usize;
    let mut messages = Vec::new();
    if !root.exists() {
        return Ok(CleanUnusedResult { moved, preserved, quarantine_dir: quarantine.to_string_lossy().to_string(), messages: vec!["каталог клиента не существует".to_string()] });
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(err) => { messages.push(format!("{}: {err}", dir.display())); continue; } };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == quarantine || path.starts_with(root.join(".neverlauncher-quarantine")) { continue; }
            if path.is_dir() { stack.push(path); continue; }
            let rel = match path.strip_prefix(root) { Ok(rel) => rel.to_string_lossy().replace('\\', "/"), Err(_) => continue };
            let top = rel.split('/').next().unwrap_or("");
            if expected.contains(&rel) || preserve_prefixes.contains(&top) || preserve_files.contains(&rel.as_str()) { preserved += 1; continue; }
            let target = quarantine.join(&rel);
            if let Some(parent) = target.parent() { std::fs::create_dir_all(parent).map_err(|err| format!("не удалось создать quarantine: {err}"))?; }
            match std::fs::rename(&path, &target) { Ok(_) => { moved += 1; messages.push(format!("{} → {}", rel, target.display())); }, Err(err) => messages.push(format!("{}: {err}", rel)) }
        }
    }
    Ok(CleanUnusedResult { moved, preserved, quarantine_dir: quarantine.to_string_lossy().to_string(), messages })
}

pub async fn prepare_profile_directory(base_dir: &Path, project_id: &str, profile_id: &str) -> Result<PathBuf, String> {
    let project = safe_component(project_id)?;
    let profile = safe_component(profile_id)?;
    let path = base_dir.join(project).join(profile);
    fs::create_dir_all(&path).await.map_err(|err| format!("не удалось создать каталог профиля: {err}"))?;
    Ok(path)
}

pub async fn check_java(java_path: Option<String>, required_major_version: Option<u32>) -> Result<JavaInfoResult, String> {
    let executable = java_path.filter(|value| !value.trim().is_empty()).unwrap_or_else(|| "java".to_string());
    let required = required_major_version.unwrap_or(17);
    let output = Command::new(&executable).arg("-version").stderr(Stdio::piped()).stdout(Stdio::piped()).output().await;
    match output {
        Ok(output) => {
            let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            let detected = parse_java_major_version(&text);
            let compatible = detected.map(|major| major >= required).unwrap_or(false);
            let message = match detected { Some(major) if compatible => format!("Java {major} подходит для профиля"), Some(major) => format!("Java {major} найдена, но требуется Java {required}+"), None => "Java найдена, но версию определить не удалось".to_string() };
            Ok(JavaInfoResult { found: output.status.success(), compatible, required_major_version: required, detected_major_version: detected, executable, version_output: text.trim().to_string(), recommended_memory_mb: None, maximum_memory_mb: None, message })
        }
        Err(err) => Ok(JavaInfoResult { found: false, compatible: false, required_major_version: required, detected_major_version: None, executable, version_output: format!("Java не найдена: {err}"), recommended_memory_mb: None, maximum_memory_mb: None, message: "Java не найдена".to_string() }),
    }
}

pub async fn build_launch_plan(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>, pinned_public_key: &str) -> Result<LaunchPlan, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    create_launch_plan(manifest, root, java_path, username).await
}

pub async fn launch(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>, pinned_public_key: &str) -> Result<LaunchResult, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    fs::create_dir_all(root).await.map_err(|err| format!("не удалось создать рабочий каталог: {err}"))?;
    let checks = check_files(manifest, root).await?;
    if checks.iter().any(|item| item.status != "ok") {
        return Err("launch заблокирован: client files не прошли integrity check".to_string());
    }
    let plan = create_launch_plan(manifest, root, java_path, username).await?;
    let logs_dir = root.join("logs");
    fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
    let started_at = now_unix()?;
    let log_path = logs_dir.join(format!("neverruntime-launch-{started_at}.log"));
    let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)
        .map_err(|err| format!("не удалось открыть runtime log {}: {err}", log_path.display()))?;
    use std::io::Write as _;
    writeln!(log_file, "NeverRuntime {}", env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
    writeln!(log_file, "Команда: {}", plan.command_preview).map_err(|e| e.to_string())?;
    writeln!(log_file, "--- process output ---").map_err(|e| e.to_string())?;
    log_file.flush().map_err(|e| e.to_string())?;
    let stdout_file = log_file.try_clone().map_err(|e| format!("не удалось клонировать runtime log handle: {e}"))?;
    let status = Command::new(&plan.java_executable)
        .args(&plan.jvm_args)
        .arg("-cp")
        .arg(join_classpath(&plan.classpath_entries))
        .arg(&plan.main_class)
        .args(&plan.game_args)
        .current_dir(Path::new(&plan.working_directory))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(log_file))
        .spawn()
        .map_err(|err| format!("не удалось запустить runtime: {err}"))?
        .wait()
        .await
        .map_err(|err| format!("не удалось дождаться runtime: {err}"))?;
    let success = status.success();
    let exit_code = status.code();
    let stdout = read_log_tail(&log_path, 256 * 1024).await.unwrap_or_default();
    let stderr = String::new();
    let history = LaunchHistoryEntry { started_at: started_at.to_string(), project_id: manifest.project_id.clone(), profile_id: manifest.profile_id.clone(), version: manifest.version.clone(), success, exit_code, log_path: log_path.to_string_lossy().to_string(), message: if success { "Runtime завершился успешно" } else { "Runtime завершился с ошибкой" }.to_string() };
    append_launch_history(root, &history).await?;
    Ok(LaunchResult { exit_code, success, log_path: log_path.to_string_lossy().to_string(), stdout, stderr, message: history.message })
}

pub async fn load_launch_history(root: &Path) -> Result<Vec<LaunchHistoryEntry>, String> {
    let path = root.join("logs").join("launch-history.jsonl");
    if fs::metadata(&path).await.is_err() { return Ok(Vec::new()); }
    let data = fs::read_to_string(&path).await.map_err(|err| format!("не удалось прочитать launch history: {err}"))?;
    Ok(data.lines().filter(|line| !line.trim().is_empty()).filter_map(|line| serde_json::from_str::<LaunchHistoryEntry>(line).ok()).collect())
}

async fn create_launch_plan(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>) -> Result<LaunchPlan, String> {
    let java_executable = java_path.filter(|value| !value.trim().is_empty()).unwrap_or_else(|| "java".to_string());
    let strategy = manifest.runtime.launch.classpath_strategy.trim().to_ascii_lowercase();
    let mut required_java = manifest.runtime.java.major_version;
    let mut plan = if strategy == "compatibility" || strategy == "mojang" {
        let game_dir = manifest_directory(root, &manifest.directories.game, ".")?;
        let assets_dir = manifest_directory(root, &manifest.directories.assets, "assets")?;
        let natives_name = if !manifest.runtime.launch.natives_directory.trim().is_empty() {
            manifest.runtime.launch.natives_directory.as_str()
        } else if !manifest.directories.natives.trim().is_empty() {
            manifest.directories.natives.as_str()
        } else {
            "natives"
        };
        let natives_dir = manifest_directory(root, natives_name, "natives")?;
        let player_name = username.unwrap_or_else(|| "Player".to_string());
        let metadata_path = if manifest.runtime.launch.version_metadata_path.trim().is_empty() {
            None
        } else {
            Some(manifest.runtime.launch.version_metadata_path.as_str())
        };
        let context = CompatibilityContext {
            username: player_name,
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            access_token: "offline".to_string(),
            user_type: "legacy".to_string(),
            launcher_name: "NeverLauncher".to_string(),
            launcher_version: env!("CARGO_PKG_VERSION").to_string(),
            game_directory: game_dir.to_string_lossy().to_string(),
            assets_directory: assets_dir.to_string_lossy().to_string(),
            natives_directory: natives_dir.to_string_lossy().to_string(),
            features: manifest.runtime.launch.features.clone(),
        };
        let resolution = resolve_compatibility(root, &manifest.minecraft.version, metadata_path, &context).await?;
        if let Some(major) = resolution.java_major_version {
            required_java = required_java.max(major);
        }
        validate_compatibility_resolution_trust(manifest, &resolution)?;
        if !manifest.runtime.launch.main_class.trim().is_empty() && manifest.runtime.launch.main_class != resolution.main_class {
            return Err(format!("manifest mainClass {} расходится с Compatibility Engine mainClass {}", manifest.runtime.launch.main_class, resolution.main_class));
        }
        if !manifest.minecraft.main_class.trim().is_empty() && manifest.minecraft.main_class != resolution.main_class {
            return Err(format!("minecraft.mainClass {} расходится с Compatibility Engine mainClass {}", manifest.minecraft.main_class, resolution.main_class));
        }
        let classpath_entries = resolution.classpath.iter().map(|path| safe_join(root, path).map(|value| value.to_string_lossy().to_string())).collect::<Result<Vec<_>, _>>()?;
        let mut jvm_args = resolution.jvm_args;
        jvm_args.extend(manifest.runtime.jvm_args.clone());
        let mut game_args = resolution.game_args;
        game_args.extend(manifest.minecraft.game_args.clone());
        LaunchPlan {
            java_executable: java_executable.clone(),
            working_directory: game_dir.to_string_lossy().to_string(),
            main_class: resolution.main_class,
            classpath_entries,
            jvm_args,
            game_args,
            command_preview: String::new(),
        }
    } else {
        create_manifest_launch_plan(manifest, root, &java_executable, username).await?
    };

    if required_java > 0 {
        let java = check_java(Some(java_executable.clone()), Some(required_java)).await?;
        if !java.found || !java.compatible {
            return Err(format!("launch заблокирован: {}", java.message));
        }
    }
    apply_memory_policy(&manifest.runtime.memory, &mut plan.jvm_args);
    plan.command_preview = format!("{} {} -cp {} {} {}", plan.java_executable, plan.jvm_args.join(" "), join_classpath(&plan.classpath_entries), plan.main_class, plan.game_args.join(" "));
    Ok(plan)
}

async fn create_manifest_launch_plan(manifest: &Manifest, root: &Path, java_executable: &str, username: Option<String>) -> Result<LaunchPlan, String> {
    let main_class = if !manifest.runtime.launch.main_class.trim().is_empty() { manifest.runtime.launch.main_class.clone() } else { manifest.minecraft.main_class.clone() };
    if main_class.trim().is_empty() { return Err("в манифесте не указан mainClass".to_string()); }
    let mut classpath_entries = Vec::new();
    for file in &manifest.files {
        if !manifest_file_applies(file) { continue; }
        if file.path.ends_with(".jar") && !file.path.contains("/mods/") && !file.path.starts_with("mods/") {
            let local_path = safe_join(root, &file.path)?;
            if fs::metadata(&local_path).await.is_ok() { classpath_entries.push(local_path.to_string_lossy().to_string()); }
        }
    }
    if classpath_entries.is_empty() { return Err("classpath пуст: JAR-файлы для запуска не найдены".to_string()); }
    let mut jvm_args = manifest.runtime.jvm_args.clone();
    if !jvm_args.iter().any(|arg| arg.starts_with("-Djava.library.path=")) {
        let natives_dir = if manifest.runtime.launch.natives_directory.trim().is_empty() { "natives" } else { manifest.runtime.launch.natives_directory.as_str() };
        jvm_args.push(format!("-Djava.library.path={}", root.join(natives_dir).to_string_lossy()));
    }
    let mut game_args = manifest.minecraft.game_args.clone();
    replace_or_append_arg_pair(&mut game_args, "--username", username.unwrap_or_else(|| "Player".to_string()));
    replace_or_append_arg_pair(&mut game_args, "--version", manifest.minecraft.version.clone());
    replace_or_append_arg_pair(&mut game_args, "--gameDir", root.to_string_lossy().to_string());
    replace_or_append_arg_pair(&mut game_args, "--assetsDir", root.join("assets").to_string_lossy().to_string());
    Ok(LaunchPlan { java_executable: java_executable.to_string(), working_directory: root.to_string_lossy().to_string(), main_class, classpath_entries, jvm_args, game_args, command_preview: String::new() })
}

fn apply_memory_policy(memory: &MemoryInfo, jvm_args: &mut Vec<String>) {
    if memory.minimum_mb > 0 && !jvm_args.iter().any(|arg| arg.starts_with("-Xms")) { jvm_args.push(format!("-Xms{}M", memory.minimum_mb)); }
    if memory.recommended_mb > 0 && !jvm_args.iter().any(|arg| arg.starts_with("-Xmx")) {
        let max = if memory.maximum_mb > 0 { memory.recommended_mb.min(memory.maximum_mb) } else { memory.recommended_mb };
        jvm_args.push(format!("-Xmx{}M", max));
    }
}

fn manifest_directory(root: &Path, configured: &str, fallback: &str) -> Result<PathBuf, String> {
    let value = if configured.trim().is_empty() { fallback } else { configured.trim() };
    if value == "." { return Ok(root.to_path_buf()); }
    safe_join(root, value)
}

fn validate_compatibility_resolution_trust(manifest: &Manifest, resolution: &CompatibilityResolution) -> Result<(), String> {
    let trusted = manifest.files.iter().filter(|file| manifest_file_applies(file)).map(|file| file.path.replace('\\', "/")).collect::<HashSet<_>>();
    for path in resolution.metadata_paths.iter().chain(resolution.classpath.iter()).chain(resolution.natives.iter().map(|native| &native.path)) {
        if !trusted.contains(path) {
            return Err(format!("Compatibility Engine отклонил неподписанный release path: {path}"));
        }
    }
    Ok(())
}

async fn read_log_tail(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = fs::File::open(path).await.map_err(|err| format!("не удалось открыть runtime log: {err}"))?;
    let len = file.metadata().await.map_err(|err| format!("не удалось получить размер runtime log: {err}"))?.len();
    if len > max_bytes {
        file.seek(SeekFrom::Start(len - max_bytes)).await.map_err(|err| format!("не удалось выполнить seek runtime log: {err}"))?;
    }
    let mut data = Vec::with_capacity(len.min(max_bytes) as usize);
    file.read_to_end(&mut data).await.map_err(|err| format!("не удалось прочитать runtime log: {err}"))?;
    Ok(String::from_utf8_lossy(&data).to_string())
}

async fn append_launch_history(root: &Path, entry: &LaunchHistoryEntry) -> Result<(), String> {
    let logs_dir = root.join("logs");
    fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
    let path = logs_dir.join("launch-history.jsonl");
    let mut line = serde_json::to_string(entry).map_err(|err| format!("не удалось сериализовать launch history: {err}"))?;
    line.push('\n');
    let mut file = fs::OpenOptions::new().create(true).append(true).open(&path).await.map_err(|err| format!("не удалось открыть launch history: {err}"))?;
    file.write_all(line.as_bytes()).await.map_err(|err| format!("не удалось записать launch history: {err}"))
}

async fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).await.map_err(|err| format!("не удалось прочитать {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buffer).await.map_err(|err| format!("не удалось прочитать {}: {err}", path.display()))?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn manifest_file_applies(file: &ManifestFile) -> bool {
    if file.target_os.is_empty() { return true; }
    let current = match std::env::consts::OS {
        "macos" => "osx",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    };
    file.target_os.iter().any(|item| {
        let normalized = match item.trim().to_ascii_lowercase().as_str() {
            "macos" | "darwin" | "osx" => "osx",
            "win" | "windows" => "windows",
            "linux" => "linux",
            other => other,
        };
        normalized == current
    })
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() { return Err(format!("небезопасный путь файла: {relative}")); }
    for component in relative_path.components() { if !matches!(component, Component::Normal(_)) { return Err(format!("небезопасный путь файла: {relative}")); } }
    Ok(root.join(relative_path))
}

fn safe_component(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\\') || trimmed == "." || trimmed == ".." { return Err(format!("небезопасный path component: {value}")); }
    Ok(trimmed.to_string())
}

fn parse_java_major_version(output: &str) -> Option<u32> {
    let marker = "version \"";
    let start = output.find(marker)? + marker.len();
    let rest = &output[start..];
    let end = rest.find('"')?;
    let version = &rest[..end];
    let mut parts = version.split('.');
    let first = parts.next()?.parse::<u32>().ok()?;
    if first == 1 { parts.next()?.parse::<u32>().ok() } else { Some(first) }
}

fn replace_or_append_arg_pair(args: &mut Vec<String>, key: &str, value: String) {
    if let Some(index) = args.iter().position(|item| item == key) {
        if index + 1 < args.len() { args[index + 1] = value; } else { args.push(value); }
        return;
    }
    args.push(key.to_string());
    args.push(value);
}

fn join_classpath(entries: &[String]) -> String { entries.join(if cfg!(windows) { ";" } else { ":" }) }
fn is_false(value: &bool) -> bool { !*value }
fn is_zero(value: &u32) -> bool { *value == 0 }
fn now_unix() -> Result<u64, String> { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|err| err.to_string()) }

#[cfg(unix)]
async fn set_executable_if_needed(path: &Path, executable: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !executable { return Ok(()); }
    let meta = fs::metadata(path).await.map_err(|err| format!("permissions {}: {err}", path.display()))?;
    let mut permissions = meta.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(path, permissions).await.map_err(|err| format!("chmod {}: {err}", path.display()))
}

#[cfg(not(unix))]
async fn set_executable_if_needed(_path: &Path, _executable: bool) -> Result<(), String> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            schema_version: "1.0".to_string(),
            project_id: "demo".to_string(),
            profile_id: "vanilla".to_string(),
            channel: "stable".to_string(),
            version: "0.10.1-test".to_string(),
            created_at: "2026-09-13T00:00:00Z".to_string(),
            minecraft: MinecraftInfo {
                version: "1.21.1".to_string(),
                loader: "fixture".to_string(),
                loader_version: String::new(),
                main_class: "ru.neverlauncher.e2e.LaunchFixture".to_string(),
                game_args: Vec::new(),
            },
            runtime: RuntimeInfo {
                java: JavaInfo {
                    major_version: 17,
                    distribution: "temurin".to_string(),
                    allow_custom_path: true,
                },
                jvm_args: Vec::new(),
                memory: MemoryInfo {
                    minimum_mb: 64,
                    recommended_mb: 128,
                    maximum_mb: 256,
                },
                launch: RuntimeLaunch {
                    main_class: "ru.neverlauncher.e2e.LaunchFixture".to_string(),
                    classpath_strategy: "manifest".to_string(),
                    natives_directory: "natives".to_string(),
                    version_metadata_path: String::new(),
                    features: HashMap::new(),
                    offline_mode: true,
                },
            },
            directories: Directories::default(),
            files: vec![ManifestFile {
                path: "libraries/fixture.jar".to_string(),
                size: 123,
                sha256: "00".repeat(32),
                url: "https://example.invalid/fixture.jar".to_string(),
                required: true,
                executable: false,
                target_os: Vec::new(),
            }],
            signature: None,
        }
    }

    #[test]
    fn sign_and_verify_manifest_with_pinned_key() {
        let mut manifest = sample_manifest();
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let public_key = sign_manifest(&mut manifest, seed, "2026-09-13T00:00:00Z").expect("sign");
        let result = verify_manifest_signature(&manifest, &public_key).expect("verify");
        assert!(result.valid);
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn signature_verification_is_fail_closed() {
        let mut manifest = sample_manifest();
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let public_key = sign_manifest(&mut manifest, seed, "2026-09-13T00:00:00Z").expect("sign");
        manifest.version = "tampered".to_string();
        assert!(verify_manifest_signature(&manifest, &public_key).is_err());
        assert!(verify_manifest_signature(&manifest, "").is_err());
    }

    #[test]
    fn safe_join_rejects_path_traversal() {
        let root = Path::new("/tmp/neverruntime-test");
        assert!(safe_join(root, "libraries/a.jar").is_ok());
        assert!(safe_join(root, "../secret").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
    }

    #[test]
    fn parses_modern_and_legacy_java_versions() {
        assert_eq!(parse_java_major_version("openjdk version \"21.0.4\" 2024-07-16"), Some(21));
        assert_eq!(parse_java_major_version("java version \"1.8.0_402\""), Some(8));
        assert_eq!(parse_java_major_version("unexpected output"), None);
    }
}
