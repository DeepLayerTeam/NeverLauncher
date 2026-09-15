use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{fs, io::AsyncWriteExt, process::Command, time::sleep};

const ADOPTIUM_API: &str = "https://api.adoptium.net/v3";
const MAX_RUNTIME_ARCHIVE_SIZE: u64 = 1_500_000_000;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ManagedJavaResult {
    pub status: String,
    pub distribution: String,
    pub major_version: u32,
    pub release_name: String,
    pub java_executable: String,
    pub install_directory: String,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub cached: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct AdoptiumAsset {
    binary: AdoptiumBinary,
    release_name: String,
    version: AdoptiumVersion,
}

#[derive(Debug, Deserialize)]
struct AdoptiumBinary {
    architecture: String,
    image_type: String,
    jvm_impl: String,
    os: String,
    package: AdoptiumPackage,
}

#[derive(Debug, Deserialize)]
struct AdoptiumPackage {
    checksum: String,
    link: String,
    name: String,
    size: u64,
}

#[derive(Debug, Deserialize)]
struct AdoptiumVersion {
    major: u32,
    #[serde(default)]
    semver: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedJavaRecord {
    schema_version: String,
    distribution: String,
    major_version: u32,
    release_name: String,
    semver: String,
    os: String,
    arch: String,
    source_url: String,
    archive_sha256: String,
    archive_size: u64,
    java_relative_path: String,
    installed_at: u64,
}

pub async fn ensure_managed_java(
    required_major: u32,
    distribution: &str,
    runtime_root_override: Option<&Path>,
) -> Result<ManagedJavaResult, String> {
    if required_major == 0 {
        return Err("Managed Java требует majorVersion > 0".to_string());
    }
    if !matches!(required_major, 8 | 17 | 21 | 25) {
        return Err(format!(
            "Managed Java 0.10.3 поддерживает Java 8/17/21/25; запрошена Java {required_major}"
        ));
    }
    let distribution = normalize_distribution(distribution)?;
    let runtime_root = match runtime_root_override {
        Some(path) => path.to_path_buf(),
        None => managed_runtime_root()?,
    };
    fs::create_dir_all(&runtime_root)
        .await
        .map_err(|err| format!("не удалось создать runtime root {}: {err}", runtime_root.display()))?;

    if let Some(cached) = find_cached_runtime(&runtime_root, required_major, &distribution).await? {
        return Ok(cached);
    }

    let platform = adoptium_platform()?;
    let asset = resolve_adoptium_asset(required_major, &platform.0, &platform.1).await?;
    if asset.version.major != required_major {
        return Err(format!(
            "Adoptium вернул Java {}, ожидалась Java {required_major}",
            asset.version.major
        ));
    }
    if asset.binary.image_type != "jre" || asset.binary.jvm_impl != "hotspot" {
        return Err("Adoptium metadata не соответствует JRE/HotSpot policy".to_string());
    }
    if normalize_adoptium_os(&asset.binary.os) != platform.0 || normalize_adoptium_arch(&asset.binary.architecture) != platform.1 {
        return Err("Adoptium metadata platform mismatch".to_string());
    }
    let checksum = normalize_sha256(&asset.binary.package.checksum)?;
    validate_https_url(&asset.binary.package.link)?;
    if asset.binary.package.size == 0 || asset.binary.package.size > MAX_RUNTIME_ARCHIVE_SIZE {
        return Err(format!("некорректный размер Java runtime archive: {}", asset.binary.package.size));
    }

    let platform_dir = runtime_root
        .join(&distribution)
        .join(required_major.to_string())
        .join(format!("{}-{}", platform.0, platform.1));
    fs::create_dir_all(&platform_dir)
        .await
        .map_err(|err| format!("не удалось создать platform runtime dir: {err}"))?;

    let release_component = safe_release_component(&asset.release_name);
    let final_dir = platform_dir.join(&release_component);
    if fs::metadata(&final_dir).await.is_ok() {
        if let Some(result) = validate_installed_runtime(&final_dir, required_major, &distribution, true).await? {
            return Ok(result);
        }
        quarantine_broken_runtime(&final_dir).await?;
    }

    let _lock = acquire_install_lock(&platform_dir).await?;
    if fs::metadata(&final_dir).await.is_ok() {
        if let Some(result) = validate_installed_runtime(&final_dir, required_major, &distribution, true).await? {
            return Ok(result);
        }
        quarantine_broken_runtime(&final_dir).await?;
    }

    let downloads = runtime_root.join(".downloads");
    fs::create_dir_all(&downloads).await.map_err(|err| format!("runtime downloads: {err}"))?;
    let extension = archive_extension(&asset.binary.package.name, &platform.0)?;
    let archive_path = downloads.join(format!("{checksum}{extension}"));
    ensure_archive(
        &Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(15 * 60))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|err| format!("не удалось создать HTTP client: {err}"))?,
        &asset.binary.package.link,
        &archive_path,
        &checksum,
        asset.binary.package.size,
    )
    .await?;

    let stamp = now_unix()?;
    let staging = platform_dir.join(format!(".staging-{}-{stamp}", std::process::id()));
    if fs::metadata(&staging).await.is_ok() {
        fs::remove_dir_all(&staging).await.map_err(|err| format!("staging cleanup: {err}"))?;
    }
    fs::create_dir_all(&staging).await.map_err(|err| format!("staging create: {err}"))?;

    let extraction_result = if platform.0 == "windows" {
        extract_windows_zip(&archive_path, &staging).await
    } else {
        extract_tar_gz(&archive_path, &staging).await
    };
    if let Err(err) = extraction_result {
        let _ = fs::remove_dir_all(&staging).await;
        return Err(err);
    }
    validate_extracted_symlinks(&staging)?;
    let java = find_java_executable(&staging).ok_or_else(|| "в распакованном JRE не найден bin/java".to_string())?;
    let java_info = super::check_java(Some(java.to_string_lossy().to_string()), Some(required_major)).await?;
    if !java_info.found || java_info.detected_major_version != Some(required_major) {
        let _ = fs::remove_dir_all(&staging).await;
        return Err(format!("установленный runtime не прошёл java -version: {}", java_info.message));
    }
    let java_relative = java
        .strip_prefix(&staging)
        .map_err(|_| "java executable вышел за staging".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    let record = ManagedJavaRecord {
        schema_version: "1.0".to_string(),
        distribution: distribution.clone(),
        major_version: required_major,
        release_name: asset.release_name.clone(),
        semver: asset.version.semver.clone(),
        os: platform.0.clone(),
        arch: platform.1.clone(),
        source_url: asset.binary.package.link.clone(),
        archive_sha256: checksum.clone(),
        archive_size: asset.binary.package.size,
        java_relative_path: java_relative,
        installed_at: stamp,
    };
    fs::write(
        staging.join(".neverruntime.json"),
        serde_json::to_vec_pretty(&record).map_err(|err| format!("runtime record serialize: {err}"))?,
    )
    .await
    .map_err(|err| format!("runtime record write: {err}"))?;

    fs::rename(&staging, &final_dir)
        .await
        .map_err(|err| format!("atomic Java runtime install {}: {err}", final_dir.display()))?;
    validate_installed_runtime(&final_dir, required_major, &distribution, false)
        .await?
        .ok_or_else(|| "Java runtime post-install verification failed".to_string())
}

pub async fn select_java_executable(
    custom_path: Option<String>,
    required_major: u32,
    distribution: &str,
    allow_custom_path: bool,
) -> Result<(String, Option<ManagedJavaResult>), String> {
    if let Some(custom) = custom_path.filter(|value| !value.trim().is_empty()) {
        if !allow_custom_path {
            return Err("профиль запрещает custom Java path".to_string());
        }
        let info = super::check_java(Some(custom.clone()), Some(required_major)).await?;
        if !info.found || info.detected_major_version != Some(required_major) {
            return Err(format!("custom Java отклонена: требуется Java {required_major}, {}", info.message));
        }
        return Ok((custom, None));
    }

    let normalized = distribution.trim().to_ascii_lowercase();
    if normalized == "system" {
        let info = super::check_java(Some("java".to_string()), Some(required_major)).await?;
        if !info.found || info.detected_major_version != Some(required_major) {
            return Err(format!("system Java не соответствует Java {required_major}: {}", info.message));
        }
        return Ok(("java".to_string(), None));
    }

    if normalized.is_empty() || normalized == "any" {
        let system = super::check_java(Some("java".to_string()), Some(required_major)).await?;
        if system.found && system.detected_major_version == Some(required_major) {
            return Ok(("java".to_string(), None));
        }
    }

    let managed = ensure_managed_java(required_major, distribution, None).await?;
    Ok((managed.java_executable.clone(), Some(managed)))
}

async fn resolve_adoptium_asset(major: u32, os: &str, arch: &str) -> Result<AdoptiumAsset, String> {
    let api_os = match os {
        "osx" => "mac",
        other => other,
    };
    let api_arch = match arch {
        "x86_64" => "x64",
        "aarch64" => "aarch64",
        "x86" => "x86",
        "arm" => "arm",
        other => return Err(format!("Adoptium не поддержан для architecture {other}")),
    };
    let url = format!(
        "{ADOPTIUM_API}/assets/latest/{major}/hotspot?architecture={api_arch}&heap_size=normal&image_type=jre&jvm_impl=hotspot&os={api_os}&vendor=eclipse"
    );
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|err| format!("Adoptium client: {err}"))?;
    let response = client
        .get(&url)
        .header("User-Agent", format!("NeverLauncher/{} ManagedJava", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(|err| format!("Adoptium API request: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("Adoptium API вернул HTTP {} для Java {major}/{api_os}/{api_arch}", response.status()));
    }
    let assets = response
        .json::<Vec<AdoptiumAsset>>()
        .await
        .map_err(|err| format!("Adoptium API JSON: {err}"))?;
    assets
        .into_iter()
        .find(|asset| asset.version.major == major && asset.binary.image_type == "jre" && asset.binary.jvm_impl == "hotspot")
        .ok_or_else(|| format!("Adoptium API не вернул Temurin JRE {major} для {api_os}/{api_arch}"))
}

async fn ensure_archive(client: &Client, url: &str, path: &Path, checksum: &str, size: u64) -> Result<(), String> {
    if fs::metadata(path).await.is_ok() && verify_file_sha256(path, checksum, size).await? {
        return Ok(());
    }
    validate_https_url(url)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.map_err(|err| format!("archive parent: {err}"))?;
    }
    let mut response = client
        .get(url)
        .header("User-Agent", format!("NeverLauncher/{} ManagedJava", env!("CARGO_PKG_VERSION")))
        .send()
        .await
        .map_err(|err| format!("Java runtime download: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("Java runtime download HTTP {}", response.status()));
    }
    if let Some(content_length) = response.content_length() {
        if content_length != size {
            return Err(format!("Java runtime Content-Length {content_length}, ожидалось {size}"));
        }
    }
    let part = path.with_extension(format!("{}nlpart", path.extension().and_then(|v| v.to_str()).unwrap_or("")));
    let mut file = fs::File::create(&part).await.map_err(|err| format!("archive temp create: {err}"))?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(|err| format!("Java runtime stream: {err}"))? {
        written = written.saturating_add(chunk.len() as u64);
        if written > MAX_RUNTIME_ARCHIVE_SIZE || written > size {
            let _ = fs::remove_file(&part).await;
            return Err("Java runtime archive превышает ожидаемый размер".to_string());
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|err| format!("archive temp write: {err}"))?;
    }
    file.flush().await.map_err(|err| format!("archive temp flush: {err}"))?;
    file.sync_all().await.map_err(|err| format!("archive temp fsync: {err}"))?;
    drop(file);
    let got = hex::encode(hasher.finalize());
    if written != size || !got.eq_ignore_ascii_case(checksum) {
        let _ = fs::remove_file(&part).await;
        return Err(format!("Java runtime SHA-256/size mismatch: got {got}/{written}"));
    }
    fs::rename(&part, path).await.map_err(|err| format!("archive atomic rename: {err}"))?;
    Ok(())
}

async fn verify_file_sha256(path: &Path, expected: &str, expected_size: u64) -> Result<bool, String> {
    let metadata = match fs::metadata(path).await {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if metadata.len() != expected_size {
        return Ok(false);
    }
    let mut file = fs::File::open(path).await.map_err(|err| format!("runtime archive open: {err}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        use tokio::io::AsyncReadExt;
        let n = file.read(&mut buffer).await.map_err(|err| format!("runtime archive read: {err}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()).eq_ignore_ascii_case(expected))
}

async fn extract_tar_gz(archive: &Path, destination: &Path) -> Result<(), String> {
    let list = Command::new("tar")
        .args(["-tzf"])
        .arg(archive)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|err| format!("tar недоступен для Managed Java: {err}"))?;
    if !list.status.success() {
        return Err(format!("tar -tzf failed: {}", String::from_utf8_lossy(&list.stderr)));
    }
    for line in String::from_utf8_lossy(&list.stdout).lines() {
        validate_archive_entry(line)?;
    }
    let output = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .output()
        .await
        .map_err(|err| format!("tar extraction: {err}"))?;
    if !output.status.success() {
        return Err(format!("tar extraction failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

async fn extract_windows_zip(archive: &Path, destination: &Path) -> Result<(), String> {
    let script = destination.with_extension("extract.ps1");
    let script_body = r#"
param([string]$Archive, [string]$Destination)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = [IO.Path]::GetFullPath($Destination + [IO.Path]::DirectorySeparatorChar)
$zip = [IO.Compression.ZipFile]::OpenRead($Archive)
try {
  foreach ($entry in $zip.Entries) {
    if ([string]::IsNullOrEmpty($entry.FullName)) { continue }
    $normalized = $entry.FullName.Replace('\\','/')
    if ($normalized.StartsWith('/') -or $normalized.Contains('../') -or $normalized -eq '..') { throw "unsafe zip entry: $normalized" }
    $target = [IO.Path]::GetFullPath([IO.Path]::Combine($Destination, $normalized.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw "zip path escape: $normalized" }
    if ($normalized.EndsWith('/')) { [IO.Directory]::CreateDirectory($target) | Out-Null; continue }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
    $input = $entry.Open()
    try {
      $output = [IO.File]::Open($target, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $input.CopyTo($output); $output.Flush() } finally { $output.Dispose() }
    } finally { $input.Dispose() }
  }
} finally { $zip.Dispose() }
"#;
    fs::write(&script, script_body).await.map_err(|err| format!("PowerShell extractor script: {err}"))?;
    let output = Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-Archive")
        .arg(archive)
        .arg("-Destination")
        .arg(destination)
        .output()
        .await
        .map_err(|err| format!("PowerShell extraction: {err}"))?;
    let _ = fs::remove_file(&script).await;
    if !output.status.success() {
        return Err(format!("PowerShell extraction failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

fn validate_archive_entry(entry: &str) -> Result<(), String> {
    let normalized = entry.replace('\\', "/");
    if normalized.trim().is_empty() {
        return Ok(());
    }
    let path = Path::new(normalized.trim_end_matches('/'));
    if path.is_absolute() {
        return Err(format!("runtime archive absolute path: {entry}"));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(format!("runtime archive traversal path: {entry}"));
        }
    }
    Ok(())
}

fn validate_extracted_symlinks(root: &Path) -> Result<(), String> {
    let canonical_root = std::fs::canonicalize(root).map_err(|err| format!("runtime staging canonicalize: {err}"))?;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|err| format!("runtime staging scan: {err}"))? {
            let entry = entry.map_err(|err| format!("runtime staging entry: {err}"))?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|err| format!("runtime staging metadata: {err}"))?;
            if metadata.file_type().is_symlink() {
                let resolved = std::fs::canonicalize(&path).map_err(|err| format!("runtime symlink {}: {err}", path.display()))?;
                if !resolved.starts_with(&canonical_root) {
                    return Err(format!("runtime archive содержит внешний symlink: {}", path.display()));
                }
            } else if metadata.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

async fn find_cached_runtime(root: &Path, major: u32, distribution: &str) -> Result<Option<ManagedJavaResult>, String> {
    let (os, arch) = adoptium_platform()?;
    let base = root.join(distribution).join(major.to_string()).join(format!("{os}-{arch}"));
    let mut entries = match fs::read_dir(&base).await {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    let mut candidates = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(|err| format!("runtime cache scan: {err}"))? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        candidates.push(entry.path());
    }
    candidates.sort();
    candidates.reverse();
    for candidate in candidates {
        if let Some(result) = validate_installed_runtime(&candidate, major, distribution, true).await? {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

async fn validate_installed_runtime(dir: &Path, major: u32, distribution: &str, cached: bool) -> Result<Option<ManagedJavaResult>, String> {
    let record_path = dir.join(".neverruntime.json");
    let bytes = match fs::read(&record_path).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let record: ManagedJavaRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(_) => return Ok(None),
    };
    if record.major_version != major || record.distribution != distribution {
        return Ok(None);
    }
    let java = safe_record_join(dir, &record.java_relative_path)?;
    let info = super::check_java(Some(java.to_string_lossy().to_string()), Some(major)).await?;
    if !info.found || info.detected_major_version != Some(major) {
        return Ok(None);
    }
    Ok(Some(ManagedJavaResult {
        status: "ready".to_string(),
        distribution: distribution.to_string(),
        major_version: major,
        release_name: record.release_name,
        java_executable: java.to_string_lossy().to_string(),
        install_directory: dir.to_string_lossy().to_string(),
        archive_sha256: record.archive_sha256,
        archive_size: record.archive_size,
        cached,
        message: if cached { "Managed Java найдена в проверенном runtime cache" } else { "Managed Java установлена и проверена" }.to_string(),
    }))
}

fn safe_record_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let rel = Path::new(relative);
    if rel.is_absolute() || relative.is_empty() {
        return Err("runtime record содержит небезопасный java path".to_string());
    }
    for component in rel.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("runtime record содержит traversal java path".to_string());
        }
    }
    Ok(root.join(rel))
}

fn find_java_executable(root: &Path) -> Option<PathBuf> {
    let expected = if cfg!(windows) { "java.exe" } else { "java" };
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 5 {
            continue;
        }
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            if entry.file_name().to_string_lossy().eq_ignore_ascii_case(expected)
                && path.parent().and_then(|value| value.file_name()).map(|value| value == "bin").unwrap_or(false)
            {
                return Some(path);
            }
        }
    }
    None
}

fn managed_runtime_root() -> Result<PathBuf, String> {
    if let Ok(value) = std::env::var("NEVERLAUNCHER_RUNTIME_DIR") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    if cfg!(windows) {
        if let Ok(value) = std::env::var("LOCALAPPDATA") {
            return Ok(PathBuf::from(value).join("NeverLauncher").join("runtimes"));
        }
    }
    if cfg!(target_os = "macos") {
        if let Ok(value) = std::env::var("HOME") {
            return Ok(PathBuf::from(value).join("Library").join("Application Support").join("NeverLauncher").join("runtimes"));
        }
    }
    if let Ok(value) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(value).join("NeverLauncher").join("runtimes"));
    }
    if let Ok(value) = std::env::var("HOME") {
        return Ok(PathBuf::from(value).join(".local").join("share").join("NeverLauncher").join("runtimes"));
    }
    Err("не удалось определить каталог Managed Java; задайте NEVERLAUNCHER_RUNTIME_DIR".to_string())
}

fn adoptium_platform() -> Result<(String, String), String> {
    let os = match std::env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "osx",
        other => return Err(format!("Managed Java не поддерживает OS {other}")),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "x86" => "x86",
        "arm" => "arm",
        other => return Err(format!("Managed Java не поддерживает arch {other}")),
    };
    Ok((os.to_string(), arch.to_string()))
}

fn normalize_adoptium_os(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "mac" | "macos" | "osx" => "osx".to_string(),
        other => other.to_string(),
    }
}

fn normalize_adoptium_arch(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "x64" | "amd64" | "x86_64" => "x86_64".to_string(),
        "arm64" | "aarch64" => "aarch64".to_string(),
        "x86" | "i386" | "i686" => "x86".to_string(),
        other => other.to_string(),
    }
}

fn normalize_distribution(value: &str) -> Result<String, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "managed" | "adoptium" | "temurin" => Ok("temurin".to_string()),
        "system" => Err("distribution=system не является Managed Java runtime".to_string()),
        other => Err(format!("Managed Java distribution {other} не поддерживается в 0.10.3")),
    }
}

fn normalize_sha256(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("Adoptium checksum должен быть SHA-256 hex".to_string());
    }
    Ok(value)
}

fn validate_https_url(value: &str) -> Result<(), String> {
    let url = Url::parse(value).map_err(|err| format!("некорректный runtime URL: {err}"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err("Managed Java разрешает только HTTPS URL".to_string());
    }
    Ok(())
}

fn archive_extension(name: &str, os: &str) -> Result<&'static str, String> {
    let lower = name.to_ascii_lowercase();
    if os == "windows" && lower.ends_with(".zip") {
        return Ok(".zip");
    }
    if os != "windows" && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz")) {
        return Ok(".tar.gz");
    }
    Err(format!("неподдерживаемый формат Java runtime archive: {name}"))
}

fn safe_release_component(value: &str) -> String {
    let cleaned = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+') { ch } else { '_' })
        .collect::<String>();
    if cleaned.trim_matches('_').is_empty() {
        format!("release-{}", now_unix().unwrap_or_default())
    } else {
        cleaned
    }
}

async fn quarantine_broken_runtime(path: &Path) -> Result<(), String> {
    let stamp = now_unix()?;
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("runtime");
    let target = path.with_file_name(format!(".broken-{name}-{stamp}"));
    fs::rename(path, &target).await.map_err(|err| format!("не удалось quarantine повреждённую Java: {err}"))
}

struct InstallLock {
    path: PathBuf,
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn acquire_install_lock(dir: &Path) -> Result<InstallLock, String> {
    let path = dir.join(".install.lock");
    for _ in 0..120 {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "pid={} started={}", std::process::id(), now_unix().unwrap_or_default());
                return Ok(InstallLock { path });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if SystemTime::now().duration_since(modified).unwrap_or_default() > Duration::from_secs(15 * 60) {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }
                    }
                }
                sleep(Duration::from_millis(500)).await;
            }
            Err(err) => return Err(format!("Managed Java install lock: {err}")),
        }
    }
    Err("Managed Java installation занята другим процессом".to_string())
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_entry_validation_rejects_escape() {
        assert!(validate_archive_entry("jdk/bin/java").is_ok());
        assert!(validate_archive_entry("../escape").is_err());
        assert!(validate_archive_entry("/absolute").is_err());
    }

    #[test]
    fn checksum_validation_is_strict() {
        assert!(normalize_sha256(&"a".repeat(64)).is_ok());
        assert!(normalize_sha256("abc").is_err());
    }

    #[test]
    fn distribution_policy_is_explicit() {
        assert_eq!(normalize_distribution("any").unwrap(), "temurin");
        assert_eq!(normalize_distribution("adoptium").unwrap(), "temurin");
        assert!(normalize_distribution("oracle").is_err());
    }
}
