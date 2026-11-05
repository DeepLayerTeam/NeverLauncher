use reqwest::{Client, Url};
use fs2::FileExt;
use crate::{content_cache::CacheStore, network_resilience, ManifestFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
    collections::BTreeMap,
};
use tokio::{fs, process::Command, time::sleep, sync::watch};

const ADOPTIUM_API: &str = "https://api.adoptium.net/v3";
const MAX_RUNTIME_ARCHIVE_SIZE: u64 = 1_500_000_000;
const MANAGED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25];
const MANAGED_JAVA_HTTP_ATTEMPTS: usize = 4;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ManagedJavaResult {
    pub status: String,
    pub distribution: String,
    pub major_version: u32,
    pub image_type: String,
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
struct AdoptiumFeatureRelease {
    binaries: Vec<AdoptiumBinary>,
    release_name: String,
    version_data: AdoptiumVersion,
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


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedJREDistributionManifest {
    schema_version: String,
    product: String,
    product_version: String,
    distribution: String,
    vendor: String,
    major_version: u32,
    targets: Vec<ManagedJREDistributionTarget>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ManagedJREDistributionTarget {
    platform: String,
    architecture: String,
    distribution: String,
    major_version: u32,
    release_name: String,
    semver: String,
    archive: String,
    format: String,
    sha256: String,
    size: u64,
    java_entry: String,
    source_url: String,
    source_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagedJavaRecord {
    schema_version: String,
    distribution: String,
    major_version: u32,
    #[serde(default = "default_managed_image_type")]
    image_type: String,
    release_name: String,
    semver: String,
    os: String,
    arch: String,
    source_url: String,
    archive_sha256: String,
    archive_size: u64,
    java_relative_path: String,
    #[serde(default)]
    java_sha256: String,
    installed_at: u64,
    #[serde(default)]
    file_hashes: BTreeMap<String, String>,
}

pub async fn ensure_managed_java(
    required_major: u32,
    distribution: &str,
    runtime_root_override: Option<&Path>,
) -> Result<ManagedJavaResult, String> {
    if required_major == 0 {
        return Err("Managed Java требует majorVersion > 0".to_string());
    }
    validate_managed_java_major(required_major)?;
    let distribution = normalize_distribution(distribution)?;
    let runtime_root = match runtime_root_override {
        Some(path) => path.to_path_buf(),
        None => managed_runtime_root()?,
    };
    fs::create_dir_all(&runtime_root)
        .await
        .map_err(|err| format!("не удалось создать runtime root {}: {err}", runtime_root.display()))?;

    // Если настроен доверенный пакет распространения, сначала проверьте его закреплённый SHA-256. Ранее закэшированный выпуск без закрепления не эквивалентен ему. Встроенный архив поставки сейчас содержит Java 21. Явно заданный манифест поставки профиля может содержать любую поддерживаемую основную версию; не навязывайте Java 21 подписанным профилям Java 8/16/17/25.
    let explicit_manifest = std::env::var("LAUNCHER_MANAGED_JRE_MANIFEST")
        .is_ok_and(|v| !v.trim().is_empty());
    if required_major == 21 || explicit_manifest {
        if let Some((location, sha256)) = configured_distribution_manifest()? {
            return ensure_managed_java_from_distribution(required_major, &distribution,
                Some(&runtime_root), &location, sha256.as_deref()).await;
        }
    }
    if let Some(cached) = find_cached_runtime(&runtime_root, required_major, &distribution).await? {
        return Ok(cached);
    }
    // Если установленная JVM повреждена, но исходный архив с закреплённым хешем сохранился, восстанавливайте её непосредственно из проверенного кэша. В офлайн-режиме это нужно сделать ДО отклонения сетевого доступа или обращения к Adoptium.
    if let Some(recovered) = restore_cached_managed_java(&runtime_root, required_major, &distribution).await? {
        return Ok(recovered);
    }
    if managed_java_offline() {
        return Err("Для автономной Managed Java требуется локально закреплённый манифест дистрибутива либо уже проверенная установленная среда выполнения".into());
    }

    // Другие поддерживаемые основные версии ищутся в выпусках Adoptium после проверки существующей установки и автономной политики.
    let platform = adoptium_platform()?;
    let asset = resolve_adoptium_asset(required_major, &platform.0, &platform.1).await?;
    if asset.version.major != required_major {
        return Err(format!(
            "Adoptium вернул Java {}, ожидалась Java {required_major}",
            asset.version.major
        ));
    }
    if !matches!(asset.binary.image_type.as_str(), "jre" | "jdk") || asset.binary.jvm_impl != "hotspot" {
        return Err("Adoptium metadata не соответствует JRE/JDK HotSpot policy".to_string());
    }
    if normalize_adoptium_os(&asset.binary.os) != platform.0 || normalize_adoptium_arch(&asset.binary.architecture) != platform.1 {
        return Err("Метаданные платформы Adoptium не совпадают".to_string());
    }
    let checksum = normalize_sha256(&asset.binary.package.checksum)?;
    validate_https_url(&asset.binary.package.link)?;
    if asset.binary.package.size == 0 || asset.binary.package.size > MAX_RUNTIME_ARCHIVE_SIZE {
        return Err(format!("некорректный размер Java runtime archive: {}", asset.binary.package.size));
    }

    install_managed_java_archive(
        &runtime_root,
        ManagedJavaInstallRequest {
            distribution: &distribution,
            required_major,
            image_type: &asset.binary.image_type,
            platform_os: &platform.0,
            platform_arch: &platform.1,
            release_name: &asset.release_name,
            semver: &asset.version.semver,
            source_url: &asset.binary.package.link,
            archive_name: &asset.binary.package.name,
            checksum: &checksum,
            archive_size: asset.binary.package.size,
            local_archive: None,
            expected_java_entry: None,
        },
    )
    .await
}


pub async fn ensure_managed_java_from_distribution(
    required_major: u32,
    distribution: &str,
    runtime_root_override: Option<&Path>,
    manifest_location: &str,
    manifest_sha256: Option<&str>,
) -> Result<ManagedJavaResult, String> {
    validate_managed_java_major(required_major)?;
    let distribution = normalize_distribution(distribution)?;
    let runtime_root = match runtime_root_override {
        Some(path) => path.to_path_buf(),
        None => managed_runtime_root()?,
    };
    fs::create_dir_all(&runtime_root)
        .await
        .map_err(|err| format!("не удалось создать runtime root {}: {err}", runtime_root.display()))?;
    // Никакой общий кэшированный кандидат не должен обходить закреплённую цель релиза.
    let (manifest_bytes, archive_base) = load_distribution_manifest(manifest_location).await?;
    if let Some(expected) = manifest_sha256.filter(|value| !value.trim().is_empty()) {
        let expected = normalize_sha256(expected)?;
        let actual = hex::encode(Sha256::digest(&manifest_bytes));
        if actual != expected {
            return Err(format!("Несовпадение SHA-256 манифеста Managed JRE: получено {actual}, ожидалось {expected}"));
        }
    } else if archive_base.is_remote() {
        return Err("remote Managed JRE manifest требует LAUNCHER_MANAGED_JRE_MANIFEST_SHA256/--manifest-sha256".to_string());
    }

    let manifest: ManagedJREDistributionManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| format!("Ошибка JSON-манифеста Managed JRE: {err}"))?;
    if manifest.schema_version != "1.0"
        || manifest.product != "Launcher"
        || manifest.distribution != "temurin"
        || manifest.vendor != "Eclipse Adoptium"
        || manifest.major_version != required_major
        || manifest.product_version != env!("CARGO_PKG_VERSION")
    {
        return Err("Несовпадение идентификатора или схемы манифеста Managed JRE".to_string());
    }

    let (platform, arch) = distribution_platform()?;
    let mut matching_targets = manifest
        .targets
        .into_iter()
        .filter(|target| target.platform == platform && target.architecture == arch);
    let target = matching_targets
        .next()
        .ok_or_else(|| format!("Managed JRE manifest не содержит target {platform}/{arch}"))?;
    if matching_targets.next().is_some() {
        return Err(format!("Managed JRE manifest содержит duplicate target {platform}/{arch}"));
    }
    if target.distribution != distribution || target.major_version != required_major {
        return Err("Несовпадение дистрибутива или основной версии целевой Managed JRE".to_string());
    }
    validate_distribution_target(&target, &platform)?;
    let (record_os, record_arch) = adoptium_platform()?;
    let (archive_source, local_archive) = archive_base.resolve(&target.archive)?;
    install_managed_java_archive(
        &runtime_root,
        ManagedJavaInstallRequest {
            distribution: &distribution,
            required_major,
            image_type: "jre",
            platform_os: &record_os,
            platform_arch: &record_arch,
            release_name: &target.release_name,
            semver: &target.semver,
            source_url: &archive_source,
            archive_name: &target.archive,
            checksum: &target.sha256,
            archive_size: target.size,
            local_archive: local_archive.as_deref(),
            expected_java_entry: Some(&target.java_entry),
        },
    )
    .await
}

#[derive(Debug, Clone)]
enum DistributionArchiveBase {
    Remote(Url),
    Local(PathBuf),
}

impl DistributionArchiveBase {
    fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }

    fn resolve(&self, archive: &str) -> Result<(String, Option<PathBuf>), String> {
        validate_distribution_archive_name(archive)?;
        match self {
            Self::Remote(base) => {
                let url = base.join(archive).map_err(|err| format!("Недопустимый URL архива Managed JRE: {err}"))?;
                validate_https_url(url.as_str())?;
                Ok((url.to_string(), None))
            }
            Self::Local(base) => {
                let path = base.join(archive);
                let canonical_base = std::fs::canonicalize(base).map_err(|err| format!("Не удалось привести базовый путь Managed JRE к каноническому виду: {err}"))?;
                let canonical_path = std::fs::canonicalize(&path).map_err(|err| format!("Ошибка архива Managed JRE {}: {err}", path.display()))?;
                if !canonical_path.starts_with(&canonical_base) {
                    return Err("Путь к архиву Managed JRE выходит за пределы каталога манифеста".to_string());
                }
                Ok((canonical_path.to_string_lossy().to_string(), Some(canonical_path)))
            }
        }
    }
}

async fn load_distribution_manifest(location: &str) -> Result<(Vec<u8>, DistributionArchiveBase), String> {
    let location = location.trim();
    if location.is_empty() {
        return Err("Местоположение манифеста Managed JRE не задано".to_string());
    }
    if location.to_ascii_lowercase().starts_with("https://") {
        if managed_java_offline() { return Err("В автономном режиме запрещено получать манифест из сети".into()); }
        let url = Url::parse(location).map_err(|err| format!("Недопустимый URL манифеста Managed JRE: {err}"))?;
        validate_https_url(location)?;
        let client = managed_java_http_client()?;
        let response = managed_java_send_with_retry(
            &client,
            url.as_str(),
            &format!("Launcher/{} ManagedJRE", env!("CARGO_PKG_VERSION")),
        )
        .await
        .map_err(|err| format!("Ошибка загрузки манифеста Managed JRE: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("Ошибка HTTP при получении манифеста Managed JRE: {}", response.status()));
        }
        if response.content_length().unwrap_or_default() > 8 * 1024 * 1024 {
            return Err("Манифест Managed JRE превышает 8 МиБ".to_string());
        }
        let bytes = response.bytes().await.map_err(|err| format!("Ошибка чтения содержимого манифеста Managed JRE: {err}"))?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err("Манифест Managed JRE превышает 8 МиБ".to_string());
        }
        let mut base = url;
        base.set_query(None);
        base.set_fragment(None);
        {
            let mut segments = base.path_segments_mut().map_err(|_| "URL манифеста Managed JRE не может использоваться как базовый адрес".to_string())?;
            segments.pop_if_empty();
            segments.pop();
            segments.push("");
        }
        return Ok((bytes.to_vec(), DistributionArchiveBase::Remote(base)));
    }
    if location.contains("://") {
        return Err("Managed JRE manifest поддерживает только HTTPS URL или локальный path".to_string());
    }
    let path = PathBuf::from(location);
    let original_metadata = std::fs::symlink_metadata(&path).map_err(|err| format!("Ошибка метаданных манифеста Managed JRE {}: {err}", path.display()))?;
    if original_metadata.file_type().is_symlink() {
        return Err("Локальный файл манифеста Managed JRE не должен быть символической ссылкой".to_string());
    }
    let canonical = std::fs::canonicalize(&path).map_err(|err| format!("Ошибка манифеста Managed JRE {}: {err}", path.display()))?;
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|err| format!("Ошибка метаданных манифеста Managed JRE: {err}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
        return Err("Недопустимый локальный файл манифеста Managed JRE".to_string());
    }
    let bytes = fs::read(&canonical).await.map_err(|err| format!("Ошибка чтения манифеста Managed JRE: {err}"))?;
    let base = canonical.parent().ok_or_else(|| "Managed JRE manifest has no parent directory".to_string())?.to_path_buf();
    Ok((bytes, DistributionArchiveBase::Local(base)))
}

fn validate_distribution_target(target: &ManagedJREDistributionTarget, platform: &str) -> Result<(), String> {
    if target.release_name.trim().is_empty() || target.semver.trim().is_empty() {
        return Err("Метаданные целевого выпуска Managed JRE пусты".to_string());
    }
    let checksum = normalize_sha256(&target.sha256)?;
    let source_checksum = normalize_sha256(&target.source_sha256)?;
    if checksum != source_checksum {
        return Err("Целевой выпуск Managed JRE должен сохранять точный SHA-256 архива поставщика".to_string());
    }
    if target.size == 0 || target.size > MAX_RUNTIME_ARCHIVE_SIZE {
        return Err("Недопустимый размер целевого архива Managed JRE".to_string());
    }
    validate_https_url(&target.source_url)?;
    validate_distribution_archive_name(&target.archive)?;
    validate_distribution_java_entry(&target.java_entry, platform)?;
    match platform {
        "windows" if target.format != "zip" || !target.archive.to_ascii_lowercase().ends_with(".zip") => {
            Err("Для Managed JRE на Windows требуется архив ZIP".to_string())
        }
        "linux" | "macos" if target.format != "tar.gz" || !target.archive.to_ascii_lowercase().ends_with(".tar.gz") => {
            Err(format!("Для Managed JRE на платформе {platform} требуется архив tar.gz"))
        }
        _ => Ok(()),
    }
}

fn validate_distribution_archive_name(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.trim().is_empty() || path.is_absolute() || path.components().any(|part| !matches!(part, Component::Normal(_))) || path.components().count() != 1 {
        return Err("Имя архива Managed JRE должно быть безопасным именем файла без компонентов пути".to_string());
    }
    Ok(())
}

fn validate_distribution_java_entry(value: &str, platform: &str) -> Result<(), String> {
    let normalized = value.replace('\\', "/");
    let path = Path::new(&normalized);
    if normalized.is_empty() || path.is_absolute() || path.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err("Небезопасное значение javaEntry в Managed JRE".to_string());
    }
    let expected = if platform == "windows" { "/bin/java.exe" } else { "/bin/java" };
    if !normalized.to_ascii_lowercase().ends_with(expected) {
        return Err("javaEntry Managed JRE не указывает на bin/java".to_string());
    }
    Ok(())
}

fn distribution_platform() -> Result<(String, String), String> {
    let platform = match std::env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        other => return Err(format!("Managed JRE Distribution не поддерживает OS {other}")),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => return Err(format!("Managed JRE Distribution не поддерживает architecture {other}")),
    };
    Ok((platform.to_string(), arch.to_string()))
}

fn configured_distribution_manifest() -> Result<Option<(String, Option<String>)>, String> {
    if let Ok(value) = std::env::var("LAUNCHER_MANAGED_JRE_MANIFEST") {
        if !value.trim().is_empty() {
            let pin = std::env::var("LAUNCHER_MANAGED_JRE_MANIFEST_SHA256").ok().filter(|v| !v.trim().is_empty());
            return Ok(Some((value, pin)));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let manifest = parent.join("MANAGED_JRE_MANIFEST.json");
            if manifest.is_file() {
                return Ok(Some((manifest.to_string_lossy().to_string(), None)));
            }
        }
    }
    Ok(None)
}

struct ManagedJavaInstallRequest<'a> {
    distribution: &'a str,
    required_major: u32,
    image_type: &'a str,
    platform_os: &'a str,
    platform_arch: &'a str,
    release_name: &'a str,
    semver: &'a str,
    source_url: &'a str,
    archive_name: &'a str,
    checksum: &'a str,
    archive_size: u64,
    local_archive: Option<&'a Path>,
    expected_java_entry: Option<&'a str>,
}

async fn install_managed_java_archive(
    runtime_root: &Path,
    request: ManagedJavaInstallRequest<'_>,
) -> Result<ManagedJavaResult, String> {
    let ManagedJavaInstallRequest {
        distribution,
        required_major,
        image_type,
        platform_os,
        platform_arch,
        release_name,
        semver,
        source_url,
        archive_name,
        checksum,
        archive_size,
        local_archive,
        expected_java_entry,
    } = request;
    let checksum = normalize_sha256(checksum)?;
    if archive_size == 0 || archive_size > MAX_RUNTIME_ARCHIVE_SIZE {
        return Err(format!("некорректный размер Java runtime archive: {archive_size}"));
    }
    let platform_dir = runtime_root
        .join(distribution)
        .join(required_major.to_string())
        .join(format!("{platform_os}-{platform_arch}"));
    fs::create_dir_all(&platform_dir)
        .await
        .map_err(|err| format!("не удалось создать platform runtime dir: {err}"))?;

    // Привяжите идентичность установленного Runtime к точному проверенному дайджесту пакета. Разные подписанные выпуски с одинаковым читаемым именем должны сосуществовать, сохраняя предыдущую исправную JVM как последнюю работоспособную для отката.
    let release_component = format!("{}-{}", safe_release_component(release_name), &checksum[..16]);
    let final_dir = platform_dir.join(&release_component);
    // Быстрый путь только для чтения безопасен; отмена действительности и переименование всегда выполняются под межпроцессной блокировкой установки, чтобы избежать гонки со вторым установщиком.
    if fs::metadata(&final_dir).await.is_ok() {
        if let Some(result) = validate_installed_runtime(&final_dir, required_major, distribution, true).await? {
            if result.archive_sha256.eq_ignore_ascii_case(&checksum) { return Ok(result); }
        }
    }

    let _lock = acquire_install_lock(&platform_dir).await?;
    // Принудительное завершение не выполняет Rust Drop. Очищайте незавершённые каталоги распаковки только после получения межпроцессной блокировки установки.
    cleanup_interrupted_java_staging(&platform_dir).await?;
    if fs::metadata(&final_dir).await.is_ok() {
        if let Some(result) = validate_installed_runtime(&final_dir, required_major, distribution, true).await? {
            if result.archive_sha256.eq_ignore_ascii_case(&checksum) { return Ok(result); }
        }
        quarantine_broken_runtime(&final_dir).await?;
    }

    let archive_path = ensure_managed_archive(runtime_root, source_url, archive_name,
        &checksum, archive_size, platform_os, local_archive).await?;

    let stamp = now_unix()?;
    let staging = platform_dir.join(format!(".staging-{}-{:016x}", std::process::id(), rand::random::<u64>()));
    fs::create_dir(&staging).await.map_err(|err| format!("Ошибка создания промежуточного каталога: {err}"))?;
    let _staging_cleanup = StagingCleanup(staging.clone());
    let extraction_result = if platform_os == "windows" {
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
    let java_relative = java
        .strip_prefix(&staging)
        .map_err(|_| "java executable вышел за staging".to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    if let Some(expected) = expected_java_entry {
        if java_relative != expected {
            let _ = fs::remove_dir_all(&staging).await;
            return Err(format!("Несовпадение javaEntry Managed JRE: извлечено={java_relative}, в манифесте={expected}"));
        }
    }
    self_test_java(&java, required_major, platform_os, platform_arch).await?;
    let (java_sha256, _) = sha256_file(&java).await?;
    let record = ManagedJavaRecord {
        schema_version: "1.3".to_string(),
        distribution: distribution.to_string(),
        major_version: required_major,
        image_type: image_type.to_string(),
        release_name: release_name.to_string(),
        semver: semver.to_string(),
        os: platform_os.to_string(),
        arch: platform_arch.to_string(),
        source_url: source_url.to_string(),
        archive_sha256: checksum,
        archive_size,
        java_relative_path: java_relative,
        java_sha256,
        installed_at: stamp,
        file_hashes: inventory_runtime_files(&staging).await?,
    };
    let record_path = staging.join(".runtime.json");
    let mut record_file = fs::File::create(&record_path).await.map_err(|err| format!("Ошибка создания записи Runtime: {err}"))?;
    use tokio::io::AsyncWriteExt;
    record_file.write_all(&serde_json::to_vec_pretty(&record).map_err(|err| format!("Ошибка сериализации записи Runtime: {err}"))?)
        .await.map_err(|err| format!("Ошибка записи Runtime: {err}"))?;
    record_file.sync_all().await.map_err(|err| format!("Ошибка синхронизации записи Runtime на диск: {err}"))?;
    drop(record_file);
    sync_directory(&staging)?;
    fs::rename(&staging, &final_dir)
        .await
        .map_err(|err| format!("Ошибка атомарной установки среды Java {}: {err}", final_dir.display()))?;
    sync_directory(&platform_dir)?;
    validate_installed_runtime(&final_dir, required_major, distribution, false)
        .await?
        .ok_or_else(|| "Java runtime post-install verification failed".to_string())
}

fn managed_java_http_client() -> Result<Client, String> {
    let mut builder = Client::builder();
    if let Ok(proxy) = std::env::var("LAUNCHER_MANAGED_JAVA_PROXY") {
        if !proxy.trim().is_empty() {
            let url = Url::parse(&proxy).map_err(|e| format!("Недопустимый URL прокси Managed Java: {e}"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err("Прокси Managed Java должен использовать HTTP(S)".into());
            }
            builder = builder.proxy(reqwest::Proxy::all(&proxy).map_err(|e| format!("Ошибка прокси Managed Java: {e}"))?);
        }
    }
    builder
        .connect_timeout(Duration::from_secs(12))
        .timeout(Duration::from_secs(15 * 60))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 { return attempt.error("too many Managed Java redirects"); }
            if attempt.url().scheme() != "https" { return attempt.error("Managed Java HTTPS downgrade rejected"); }
            attempt.follow()
        }))
        .build()
        .map_err(|err| format!("не удалось создать Managed Java HTTP client: {err}"))
}

async fn managed_java_send_with_retry(client: &Client, url: &str, user_agent: &str) -> Result<reqwest::Response, String> {
    let mut last_error = String::new();
    for attempt in 0..MANAGED_JAVA_HTTP_ATTEMPTS {
        match client.get(url).header("User-Agent", user_agent).send().await {
            Ok(response) => {
                if response.url().scheme() != "https" {
                    return Err("Перенаправление Managed Java понизило соединение с HTTPS".to_string());
                }
                let status = response.status().as_u16();
                let retryable = matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504);
                if !retryable || attempt + 1 == MANAGED_JAVA_HTTP_ATTEMPTS {
                    return Ok(response);
                }
                last_error = format!("HTTP {status}");
            }
            Err(err) => {
                last_error = err.to_string();
                if attempt + 1 == MANAGED_JAVA_HTTP_ATTEMPTS {
                    break;
                }
            }
        }
        let delay_ms = 250u64.saturating_mul(1u64 << attempt.min(4));
        sleep(Duration::from_millis(delay_ms.min(4_000))).await;
    }
    Err(format!(
        "Managed Java upstream failed after {MANAGED_JAVA_HTTP_ATTEMPTS} attempts: {last_error}"
    ))
}

fn managed_java_offline() -> bool {
    std::env::var("LAUNCHER_OFFLINE").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"))
}

struct StagingCleanup(PathBuf);
impl Drop for StagingCleanup {
    fn drop(&mut self) {
        // Если переименование зафиксировано, каталог уже не существует.
        if self.0.exists() { let _ = std::fs::remove_dir_all(&self.0); }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    std::fs::File::open(path).and_then(|file| file.sync_all())
        .map_err(|e| format!("Ошибка обеспечения устойчивой записи каталога Runtime {}: {e}", path.display()))
}
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> { Ok(()) }

fn safe_offline_archive(archive_name: &str, digest: &str, ext: &str) -> Result<Option<PathBuf>, String> {
    let Some(root) = std::env::var_os("LAUNCHER_MANAGED_JAVA_OFFLINE_DIR") else { return Ok(None); };
    validate_distribution_archive_name(archive_name)?;
    let base = PathBuf::from(root);
    let meta = std::fs::symlink_metadata(&base).map_err(|e| format!("Ошибка автономного каталога Java: {e}"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() { return Err("Автономный каталог Java не должен быть символической ссылкой".into()); }
    for name in [format!("{digest}{ext}"), archive_name.to_string()] {
        let path = base.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(format!("Недопустимый автономный архив Java: {}", path.display()));
            }
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Используются то же хранилище объектов SHA-256 и загрузчик Range/If-Range, что и в Desktop и Repair. Аренда кэша сериализует получение и публикацию между процессами. Проверенный архив можно установить без сети.
async fn ensure_managed_archive(runtime_root: &Path, source_url: &str,
    archive_name: &str, checksum: &str, size: u64, os: &str,
    local_archive: Option<&Path>) -> Result<PathBuf, String> {
    let ext = archive_extension(archive_name, os)?;
    let downloads = runtime_root.join(".downloads");
    fs::create_dir_all(&downloads).await.map_err(|e| format!("Ошибка каталога загрузок Runtime: {e}"))?;
    let archive = downloads.join(format!("{checksum}{ext}"));
    let file = ManifestFile {
        path: format!(".downloads/{checksum}{ext}"), size,
        sha256: checksum.to_owned(), url: source_url.to_owned(),
        mirrors: vec![], required: true, executable: false,
        target_os: vec![], ownership: "required".to_owned(),
    };
    let store = CacheStore::standard()?;
    let lease = store.lock(&file).await?;
    if lease.restore(runtime_root, &file, &archive).await? { return Ok(archive); }
    if verify_file_sha256(&archive, checksum, size).await? {
        lease.publish(&file, &archive).await?;
        return Ok(archive);
    }
    if fs::symlink_metadata(&archive).await.is_ok() { quarantine_broken_archive(&archive).await?; }

    let offline_source = if local_archive.is_some() { None } else {
        safe_offline_archive(archive_name, checksum, ext)?
    };
    if let Some(source) = local_archive.or(offline_source.as_deref()) {
        if !verify_file_sha256(source, checksum, size).await? {
            return Err("Несовпадение SHA-256 или размера локального архива Managed Java".into());
        }
        let tmp = downloads.join(format!(".{checksum}-{:016x}.partial", rand::random::<u64>()));
        let result = async {
            fs::copy(source, &tmp).await.map_err(|e| format!("Ошибка копирования автономного архива Java: {e}"))?;
            if !verify_file_sha256(&tmp, checksum, size).await? {
                return Err("Источник автономного архива Java изменился во время копирования".into());
            }
            fs::rename(&tmp, &archive).await.map_err(|e| format!("Ошибка сохранения автономного архива Java: {e}"))?;
            Ok::<(), String>(())
        }.await;
        if result.is_err() { let _ = fs::remove_file(&tmp).await; }
        result?;
    } else {
        if managed_java_offline() { return Err(format!("Архив Java {checksum} отсутствует в автономном кеше и источнике")); }
        validate_https_url(source_url)?;
        let client = managed_java_http_client()?;
        let (_sender, receiver) = watch::channel(network_resilience::Directive::Running);
        let mut last_error = String::new();
        for attempt in 0..network_resilience::MAX_ATTEMPTS {
            match crate::http_resume::download_verified_controlled(&client, runtime_root,
                &file, &archive, |_| {}, receiver.clone()).await {
                Ok(()) => { last_error.clear(); break; }
                Err(error) => {
                    let delay = network_resilience::retry_delay(&error, attempt);
                    last_error = error;
                    if attempt + 1 == network_resilience::MAX_ATTEMPTS || delay.is_none() { break; }
                    sleep(delay.unwrap()).await;
                }
            }
        }
        if !last_error.is_empty() { return Err(format!("Ошибка проверенной загрузки Managed Java: {last_error}")); }
    }
    if !verify_file_sha256(&archive, checksum, size).await? {
        return Err("Целостность архива Managed Java изменилась до публикации в кеше".into());
    }
    lease.publish(&file, &archive).await?;
    Ok(archive)
}

/// Непосредственно перед созданием игрового процесса повторно проверьте всю установленную JVM. Закэшированный результат прошлой проверки плана запуска не является решением безопасности: файлы могли измениться между планированием и созданием процесса.
pub async fn revalidate_managed_java_before_spawn(java_executable: &str) -> Result<(), String> {
    let java = Path::new(java_executable);
    if !java.is_absolute() {
        // Путь "java", найденный через PATH, разрешён только явной подписанной политикой профиля и не считается управляемой JVM.
        return Ok(());
    }
    for directory in java.ancestors().take(8) {
        let record_path = directory.join(".runtime.json");
        if !record_path.exists() { continue; }
        let raw = fs::read(&record_path).await
            .map_err(|e| format!("Запись Managed Java недоступна перед запуском: {e}"))?;
        let record: ManagedJavaRecord = serde_json::from_slice(&raw)
            .map_err(|e| format!("Запись Managed Java повреждена перед запуском: {e}"))?;
        let verified = validate_installed_runtime(directory, record.major_version,
            &record.distribution, true).await?
            .ok_or_else(|| "managed Java installation changed after launch planning".to_string())?;
        if std::fs::canonicalize(&verified.java_executable).map_err(|e|e.to_string())?
            != std::fs::canonicalize(java).map_err(|e|e.to_string())? {
            return Err("Исполняемый файл Managed Java не соответствует проверенному реестру Runtime".into());
        }
        return Ok(());
    }
    // Управляемый Runtime с удалёнными метаданными не должен незаметно превращаться в доверенный пользовательский путь Java.
    if let Ok(root) = managed_runtime_root() {
        if java.starts_with(&root) {
            return Err("Запись Managed Java отсутствует перед запуском".into());
        }
    }
    Ok(())
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
    validate_managed_java_major(major)?;
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
    let client = managed_java_http_client()?;

    // Предпочитайте компактные JRE. Java 16 устарела и исчезла из
    // интерфейса текущих выпусков, поэтому Managed Java II также
    // ищет исторические GA. JDK допустим только если у Adoptium нет
    // JRE для запрошенной версии и платформы; перед использованием
    // извлечённой среды всё равно проверяется java -version.
    for image_type in ["jre", "jdk"] {
        if let Some(asset) = resolve_adoptium_latest_asset(&client, major, api_os, api_arch, image_type).await? {
            return Ok(asset);
        }
        if let Some(asset) = resolve_adoptium_feature_release_asset(&client, major, api_os, api_arch, image_type).await? {
            return Ok(asset);
        }
    }
    Err(format!(
        "Adoptium не вернул GA Temurin Java {major} для {api_os}/{api_arch} (JRE/JDK)"
    ))
}

async fn resolve_adoptium_latest_asset(
    client: &Client,
    major: u32,
    api_os: &str,
    api_arch: &str,
    image_type: &str,
) -> Result<Option<AdoptiumAsset>, String> {
    let url = format!(
        "{ADOPTIUM_API}/assets/latest/{major}/hotspot?architecture={api_arch}&heap_size=normal&image_type={image_type}&jvm_impl=hotspot&os={api_os}&vendor=eclipse"
    );
    let response = managed_java_send_with_retry(
        client,
        &url,
        &format!("Launcher/{} ManagedJavaII", env!("CARGO_PKG_VERSION")),
    )
    .await
    .map_err(|err| format!("Adoptium latest API request: {err}"))?;
    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!("Adoptium latest API вернул HTTP {} для Java {major}/{api_os}/{api_arch}/{image_type}", response.status()));
    }
    let assets = response
        .json::<Vec<AdoptiumAsset>>()
        .await
        .map_err(|err| format!("Adoptium latest API JSON: {err}"))?;
    Ok(assets.into_iter().find(|asset| {
        asset.version.major == major
            && asset.binary.image_type == image_type
            && asset.binary.jvm_impl == "hotspot"
            && normalize_adoptium_os(&asset.binary.os) == normalize_adoptium_os(api_os)
            && normalize_adoptium_arch(&asset.binary.architecture) == normalize_adoptium_arch(api_arch)
    }))
}

async fn resolve_adoptium_feature_release_asset(
    client: &Client,
    major: u32,
    api_os: &str,
    api_arch: &str,
    image_type: &str,
) -> Result<Option<AdoptiumAsset>, String> {
    let url = format!(
        "{ADOPTIUM_API}/assets/feature_releases/{major}/ga?architecture={api_arch}&heap_size=normal&image_type={image_type}&jvm_impl=hotspot&os={api_os}&project=jdk&vendor=eclipse&page_size=20&sort_order=DESC"
    );
    let response = managed_java_send_with_retry(
        client,
        &url,
        &format!("Launcher/{} ManagedJavaII", env!("CARGO_PKG_VERSION")),
    )
    .await
    .map_err(|err| format!("Adoptium feature release API request: {err}"))?;
    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!("Adoptium feature release API вернул HTTP {} для Java {major}/{api_os}/{api_arch}/{image_type}", response.status()));
    }
    let releases = response
        .json::<Vec<AdoptiumFeatureRelease>>()
        .await
        .map_err(|err| format!("Adoptium feature release API JSON: {err}"))?;
    for release in releases {
        if release.version_data.major != major {
            continue;
        }
        for binary in release.binaries {
            if binary.image_type == image_type
                && binary.jvm_impl == "hotspot"
                && normalize_adoptium_os(&binary.os) == normalize_adoptium_os(api_os)
                && normalize_adoptium_arch(&binary.architecture) == normalize_adoptium_arch(api_arch)
            {
                return Ok(Some(AdoptiumAsset {
                    binary,
                    release_name: release.release_name.clone(),
                    version: AdoptiumVersion {
                        major: release.version_data.major,
                        semver: release.version_data.semver.clone(),
                    },
                }));
            }
        }
    }
    Ok(None)
}

fn validate_managed_java_major(major: u32) -> Result<(), String> {
    if MANAGED_JAVA_MAJORS.contains(&major) {
        Ok(())
    } else {
        Err(format!(
            "Managed Java {} поддерживает Java 8/16/17/21/25; запрошена Java {major}",
            env!("CARGO_PKG_VERSION")
        ))
    }
}

fn default_managed_image_type() -> String {
    "jre".to_string()
}

async fn quarantine_broken_archive(path: &Path) -> Result<(), String> {
    let stamp = now_unix()?;
    let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("runtime-archive");
    let quarantine = path.with_file_name(format!(".broken-{name}-{stamp}-{:016x}", rand::random::<u64>()));
    fs::rename(path, &quarantine)
        .await
        .map_err(|err| format!("Managed Java corrupt archive quarantine: {err}"))
}

async fn verify_file_sha256(path: &Path, expected: &str, expected_size: u64) -> Result<bool, String> {
    // Никогда не переходите по символической ссылке архива: ни попадание в прогретый кэш, ни предоставленный оператором офлайн-архив не могут разрешаться за пределы доверенного Storage.
    let metadata = match fs::symlink_metadata(path).await {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != expected_size {
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

async fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    use tokio::io::AsyncReadExt;
    let metadata = fs::metadata(path)
        .await
        .map_err(|err| format!("runtime file metadata {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("runtime file is not regular: {}", path.display()));
    }
    let mut file = fs::File::open(path)
        .await
        .map_err(|err| format!("runtime file open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|err| format!("runtime file read {}: {err}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok((hex::encode(hasher.finalize()), metadata.len()))
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

/// Восстанавливайте повреждённую установку из ранее проверенного SHA-256 архива поставщика, а не скрытым переходом к PATH или загрузкой другой JVM. Полная установка повторяет распаковку, проверку исполняемого байткода, инвентаризацию файлов и атомарное переименование до публикации восстановленной JVM.
async fn restore_cached_managed_java(
    root: &Path, major: u32, distribution: &str,
) -> Result<Option<ManagedJavaResult>, String> {
    let (os, arch) = adoptium_platform()?;
    let base = root.join(distribution).join(major.to_string()).join(format!("{os}-{arch}"));
    let mut entries = match fs::read_dir(&base).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Managed Java recovery scan: {e}")),
    };
    let extension = if os == "windows" { ".zip" } else { ".tar.gz" };
    let mut candidates = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(|e| format!("Java recovery scan: {e}"))? {
        if entry.file_name().to_string_lossy().starts_with('.') { continue; }
        candidates.push(entry.path());
    }
    candidates.sort();
    candidates.reverse();
    for dir in candidates {
        let meta = match fs::symlink_metadata(&dir).await { Ok(v) => v, Err(_) => continue };
        if meta.file_type().is_symlink() || !meta.is_dir() { continue; }
        let bytes = match fs::read(dir.join(".runtime.json")).await { Ok(b) => b, Err(_) => continue };
        let record: ManagedJavaRecord = match serde_json::from_slice(&bytes) { Ok(r) => r, Err(_) => continue };
        if record.schema_version != "1.3" || record.distribution != distribution || record.major_version != major
            || record.os != os || record.arch != arch || record.archive_size == 0
            || record.archive_size > MAX_RUNTIME_ARCHIVE_SIZE
            || !matches!(record.image_type.as_str(), "jre" | "jdk")
            || record.release_name.trim().is_empty()
        { continue; }
        let digest = match normalize_sha256(&record.archive_sha256) { Ok(v) => v, Err(_) => continue };
        if dir.file_name().and_then(|n| n.to_str())
            != Some(format!("{}-{}", safe_release_component(&record.release_name), &digest[..16]).as_str()) {
            continue;
        }
        let manifest_platform = if os == "osx" { "macos" } else { os.as_str() };
        if validate_distribution_java_entry(&record.java_relative_path, manifest_platform).is_err() { continue; }
        let archive = root.join(".downloads").join(format!("{digest}{extension}"));
        if !verify_file_sha256(&archive, &digest, record.archive_size).await? { continue; }
        let archive_name = if os == "windows" { "verified-recovery.zip" } else { "verified-recovery.tar.gz" };
        let restored = install_managed_java_archive(root, ManagedJavaInstallRequest {
            distribution, required_major: major, image_type: &record.image_type,
            platform_os: &os, platform_arch: &arch, release_name: &record.release_name,
            semver: &record.semver, source_url: &record.source_url,
            archive_name, checksum: &digest, archive_size: record.archive_size,
            local_archive: Some(&archive), expected_java_entry: Some(&record.java_relative_path),
        }).await?;
        return Ok(Some(restored));
    }
    Ok(None)
}

async fn validate_installed_runtime(dir: &Path, major: u32, distribution: &str, cached: bool) -> Result<Option<ManagedJavaResult>, String> {
    let dir_meta = match std::fs::symlink_metadata(dir) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return Ok(None);
    }
    let record_path = dir.join(".runtime.json");
    let bytes = match fs::read(&record_path).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let record: ManagedJavaRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(_) => return Ok(None),
    };
    let (expected_os, expected_arch) = adoptium_platform()?;
    if record.schema_version != "1.3"
        || record.major_version != major
        || record.distribution != distribution
        || record.os != expected_os
        || record.arch != expected_arch
        || record.archive_size == 0
        || record.archive_size > MAX_RUNTIME_ARCHIVE_SIZE
        || normalize_sha256(&record.archive_sha256).is_err()
        || normalize_sha256(&record.java_sha256).is_err()
    {
        return Ok(None);
    }
    if !verify_runtime_inventory(dir, &record.file_hashes).await? { return Ok(None); }
    let java = match safe_record_join(dir, &record.java_relative_path) {
        Ok(java) => java,
        Err(_) => return Ok(None),
    };
    let (java_sha256, _) = match sha256_file(&java).await {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if !java_sha256.eq_ignore_ascii_case(&record.java_sha256) {
        return Ok(None);
    }
    if self_test_java(&java, major, &record.os, &record.arch).await.is_err() {
        return Ok(None);
    }
    Ok(Some(ManagedJavaResult {
        status: "ready".to_string(),
        distribution: distribution.to_string(),
        major_version: major,
        image_type: record.image_type,
        release_name: record.release_name,
        java_executable: java.to_string_lossy().to_string(),
        install_directory: dir.to_string_lossy().to_string(),
        archive_sha256: record.archive_sha256,
        archive_size: record.archive_size,
        cached,
        message: if cached { "Managed Java найдена в проверенном runtime cache" } else { "Managed Java установлена и проверена" }.to_string(),
    }))
}

/// Вычисляйте хеш каждого файла установленного Runtime, а не только bin/java. Повреждение libjvm или хранилища безопасности тоже должно делать кэш недействительным.
async fn inventory_runtime_files(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<BTreeMap<String, String>, String> {
        use std::io::Read;
        let mut files = BTreeMap::new();
        let mut pending = vec![root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).map_err(|e| format!("Java inventory scan: {e}"))? {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if meta.is_dir() { pending.push(path); continue; }
                let relative = path.strip_prefix(&root).map_err(|e| e.to_string())?
                    .to_string_lossy().replace('\\', "/");
                if relative == ".runtime.json" { continue; }
                if !(meta.is_file() || meta.file_type().is_symlink()) {
                    return Err(format!("Не поддерживается: «Java runtime entry»: {relative}"));
                }
                if meta.file_type().is_symlink() {
                    let resolved = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
                    if !resolved.starts_with(std::fs::canonicalize(&root).map_err(|e| e.to_string())?) {
                        return Err(format!("Java runtime symlink escapes installation: {relative}"));
                    }
                    // Символическую ссылку на каталог нельзя открывать как файл.
                    let link = std::fs::read_link(&path).map_err(|e| e.to_string())?;
                    let identity = format!("symlink:{}", link.to_string_lossy());
                    files.insert(relative, hex::encode(Sha256::digest(identity.as_bytes())));
                    continue;
                }
                let mut file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
                let mut digest = Sha256::new();
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                    if n == 0 { break; }
                    digest.update(&buffer[..n]);
                }
                files.insert(relative, hex::encode(digest.finalize()));
            }
        }
        if files.is_empty() { return Err("Пустое значение: среда выполнения Java".into()); }
        Ok(files)
    }).await.map_err(|e| format!("Java inventory worker: {e}"))?
}

async fn verify_runtime_inventory(root: &Path, expected: &BTreeMap<String, String>) -> Result<bool, String> {
    if expected.is_empty() { return Ok(false); }
    // Проверка точного набора также отклоняет посторонние файлы, добавленные в управляемый Runtime.
    let actual = match inventory_runtime_files(root).await {
        Ok(files) => files,
        Err(_) => return Ok(false),
    };
    Ok(&actual == expected)
}

// Проверяйте физический формат исполняемого файла, а не только значение os.arch от Java. Так обнаруживаются Rosetta, QEMU и JRE неверной платформы до загрузки Minecraft нативных библиотек LWJGL, JNI или загрузчика.
fn verify_native_java_executable(java: &Path, os: &str, arch: &str) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom};
    let expected_arch = normalize_adoptium_arch(arch);
    if expected_arch != "x86_64" && expected_arch != "aarch64" {
        return Err(format!("Не поддерживается: «native Java architecture» {arch}"));
    }
    let mut file = std::fs::File::open(java).map_err(|e| format!("Java executable open: {e}"))?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    let mut header = [0u8; 64];
    file.read_exact(&mut header).map_err(|e| format!("Java executable header: {e}"))?;
    let le16 = |bytes: &[u8]| u16::from_le_bytes([bytes[0], bytes[1]]);
    let le32 = |bytes: &[u8]| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let be32 = |bytes: &[u8]| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let cpu_macho = if expected_arch == "aarch64" { 0x0100000c } else { 0x01000007 };
    let valid = match normalize_adoptium_os(os).as_str() {
        "linux" => header.starts_with(b"\x7fELF")
            && header[4] == 2 && header[5] == 1
            && le16(&header[18..20]) == if expected_arch == "aarch64" { 183 } else { 62 },
        "windows" => {
            if &header[..2] != b"MZ" { false } else {
                let offset = le32(&header[60..64]) as u64;
                if offset < 64 || offset.checked_add(6).is_none_or(|end| end > len) {
                    false
                } else {
                    let mut pe = [0u8; 6];
                    file.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
                    file.read_exact(&mut pe).map_err(|e| e.to_string())?;
                    &pe[..4] == b"PE\0\0"
                        && le16(&pe[4..6]) == if expected_arch == "aarch64" { 0xaa64 } else { 0x8664 }
                }
            }
        },
        "osx" => {
            if header[..4] == [0xcf, 0xfa, 0xed, 0xfe] {
                le32(&header[4..8]) == cpu_macho
            } else if header[..4] == [0xca, 0xfe, 0xba, 0xbe]
                || header[..4] == [0xca, 0xfe, 0xba, 0xbf] {
                let is_fat64 = header[3] == 0xbf;
                let count = be32(&header[4..8]) as usize;
                let entry_len: usize = if is_fat64 { 32 } else { 20 };
                if count == 0 || count > 32 || 8u64 + (entry_len * count) as u64 > len {
                    false
                } else {
                    let mut entries = vec![0u8; count * entry_len];
                    file.seek(SeekFrom::Start(8)).map_err(|e| e.to_string())?;
                    file.read_exact(&mut entries).map_err(|e| e.to_string())?;
                    let mut matched = false;
                    for entry in entries.chunks_exact(entry_len) {
                        if be32(&entry[..4]) != cpu_macho { continue; }
                        let offset = if is_fat64 {
                            u64::from_be_bytes(entry[8..16].try_into().unwrap())
                        } else { be32(&entry[8..12]) as u64 };
                        let size = if is_fat64 {
                            u64::from_be_bytes(entry[16..24].try_into().unwrap())
                        } else { be32(&entry[12..16]) as u64 };
                        if size < 8 || offset.checked_add(size).is_none_or(|end| end > len) {
                            continue;
                        }
                        let mut thin = [0u8; 8];
                        file.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
                        file.read_exact(&mut thin).map_err(|e| e.to_string())?;
                        if thin[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                            && le32(&thin[4..8]) == cpu_macho {
                            matched = true;
                            break;
                        }
                    }
                    matched
                }
            } else { false }
        },
        _ => return Err(format!("Не поддерживается: «native Java OS» {os}")),
    };
    if valid { Ok(()) } else {
        Err(format!("Managed Java executable machine mismatch: expected {os}/{expected_arch}"))
    }
}

/// Запускайте настоящую JVM с ограниченным временем жизни, проверяя сообщаемые Runtime архитектуру и ОС, а не только основную версию java -version.
async fn self_test_java(java: &Path, major: u32, os: &str, arch: &str) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(java).map_err(|e| format!("Java executable metadata: {e}"))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("«Managed Java executable»: требуется обычный файл".into());
    }
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 { return Err("Managed Java executable lacks execute permission".into()); }
    }
    verify_native_java_executable(java, os, arch)?;
    let mut command = Command::new(java);
    command.args(["-XshowSettings:properties", "-version"])
        .stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    // При проверке пакета никогда не наследуйте JAVA_TOOL_OPTIONS/JDK_JAVA_OPTIONS/_JAVA_OPTIONS.
    for key in ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"] {
        command.env_remove(key);
    }
    let output = tokio::time::timeout(Duration::from_secs(20), command.output())
        .await.map_err(|_| "Managed Java self-test exceeded 20 seconds".to_string())?
        .map_err(|e| format!("Ошибка: «Managed Java self-test»: {e}"))?;
    if !output.status.success() { return Err("Ошибка: «Managed Java JVM self-test»".into()); }
    let details = format!("{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let detected = crate::parse_java_major_version(&details);
    if detected != Some(major) { return Err(format!("Managed Java major mismatch: expected {major}, got {detected:?}")); }
    let reported_arch = java_property(&details, "os.arch").ok_or("Managed Java missing os.arch")?;
    if normalize_adoptium_arch(reported_arch) != normalize_adoptium_arch(arch) {
        return Err(format!("Несовпадение: «Managed Java architecture»: {reported_arch}, expected {arch}"));
    }
    let reported_os = java_property(&details, "os.name").ok_or("Managed Java missing os.name")?.to_ascii_lowercase();
    let expected_os = normalize_adoptium_os(os);
    let os_ok = match expected_os.as_str() {
        "windows" => reported_os.contains("windows"),
        "linux" => reported_os.contains("linux"),
        "osx" => reported_os.contains("mac"),
        _ => false,
    };
    if !os_ok { return Err(format!("Несовпадение: «Managed Java OS»: {reported_os}, expected {os}")); }
    // Одного `java -version` недостаточно, чтобы доказать способность скачанного пакета выполнять классы Java: оболочечная заглушка может имитировать этот вывод. Запустите байткод Java 8 в установленной JVM и докажите, что java.home находится внутри распакованного пакета, а не у системной JDK.
    verify_java_bytecode_execution(java, major).await?;
    Ok(())
}

async fn verify_java_bytecode_execution(java: &Path, major: u32) -> Result<(), String> {
    // Случайный каталог, созданный с исключительным владением, препятствует замене теста classpath конкурентным процессом. Он не записывается в установку Runtime, поэтому инвентаризация целостности остаётся неизменной при чтении кэша.
    let temp = std::env::temp_dir().join(format!(
        "launcher-java-probe-{}-{:016x}", std::process::id(), rand::random::<u64>()
    ));
    fs::create_dir(&temp).await.map_err(|e| format!("Java probe directory: {e}"))?;
    let _cleanup = StagingCleanup(temp.clone());
    fs::write(temp.join("LauncherJvmProbe.class"),
        include_bytes!("../fixtures/LauncherJvmProbe.class"))
        .await.map_err(|e| format!("Java bytecode probe write: {e}"))?;
    let nonce = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
    let mut command = Command::new(java);
    command.arg("-cp").arg(&temp).arg("LauncherJvmProbe").arg(&nonce)
        .stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    for key in ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"] {
        command.env_remove(key);
    }
    let output = tokio::time::timeout(Duration::from_secs(20), command.output())
        .await.map_err(|_| "Managed Java bytecode execution exceeded 20 seconds".to_string())?
        .map_err(|e| format!("Ошибка: «Managed Java bytecode execution»: {e}"))?;
    if !output.status.success() {
        return Err(format!("Managed Java failed to run Java 8-compatible bytecode: {}",
            String::from_utf8_lossy(&output.stderr)));
    }
    let output_text = String::from_utf8(output.stdout)
        .map_err(|_| "Managed Java probe emitted non-UTF8 output".to_string())?;
    let parts = output_text.splitn(4, '|').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "LAUNCHER_JVM_PROBE" || parts[1] != nonce {
        return Err("Managed Java did not execute the expected bytecode probe".into());
    }
    let probed_major = if parts[2] == "1.8" { 8 } else {
        parts[2].parse::<u32>().map_err(|_| "Managed Java probe returned invalid specification version".to_string())?
    };
    if probed_major != major {
        return Err(format!("Несовпадение: «Managed Java bytecode major»: {probed_major} vs {major}"));
    }
    // JVM должна использовать собственные библиотеки среды выполнения образа. Обёртка, запускающая постороннюю системную Java, не является управляемой установкой.
    let packaged_home = java.parent().and_then(Path::parent)
        .ok_or_else(|| "Managed Java executable is not under bin/".to_string())?;
    let packaged_home = std::fs::canonicalize(packaged_home)
        .map_err(|e| format!("Managed Java package home: {e}"))?;
    let actual_home = std::fs::canonicalize(parts[3])
        .map_err(|e| format!("Managed Java java.home: {e}"))?;
    if !actual_home.starts_with(&packaged_home) {
        return Err(format!("Managed Java runs outside its installed image: {}", actual_home.display()));
    }
    Ok(())
}

fn java_property<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().filter_map(|line| line.trim().split_once('=')).find_map(|(name, value)| {
        if name.trim() == key { Some(value.trim()) } else { None }
    })
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
    let candidate = root.join(rel);
    if candidate.exists() {
        let canonical_root = std::fs::canonicalize(root)
            .map_err(|err| format!("runtime root canonicalize: {err}"))?;
        let canonical_candidate = std::fs::canonicalize(&candidate)
            .map_err(|err| format!("runtime java canonicalize: {err}"))?;
        if !canonical_candidate.starts_with(&canonical_root) {
            return Err("runtime record java path вышел за Managed Java root через symlink".to_string());
        }
    }
    Ok(candidate)
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
    if let Ok(value) = std::env::var("LAUNCHER_RUNTIME_DIR") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    if cfg!(windows) {
        if let Ok(value) = std::env::var("LOCALAPPDATA") {
            return Ok(PathBuf::from(value).join("Launcher").join("runtimes"));
        }
    }
    if cfg!(target_os = "macos") {
        if let Ok(value) = std::env::var("HOME") {
            return Ok(PathBuf::from(value).join("Library").join("Application Support").join("Launcher").join("runtimes"));
        }
    }
    if let Ok(value) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(value).join("Launcher").join("runtimes"));
    }
    if let Ok(value) = std::env::var("HOME") {
        return Ok(PathBuf::from(value).join(".local").join("share").join("Launcher").join("runtimes"));
    }
    Err("не удалось определить каталог Managed Java; задайте LAUNCHER_RUNTIME_DIR".to_string())
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
        other => Err(format!("Managed Java distribution {other} не поддерживается в {}", env!("CARGO_PKG_VERSION"))),
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
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
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

async fn cleanup_interrupted_java_staging(platform_dir: &Path) -> Result<(), String> {
    let mut entries = fs::read_dir(platform_dir).await
        .map_err(|e| format!("Java staging scan: {e}"))?;
    while let Some(entry) = entries.next_entry().await
        .map_err(|e| format!("Java staging entry: {e}"))? {
        if !entry.file_name().to_string_lossy().starts_with(".staging-") { continue; }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).await
            .map_err(|e| format!("Java abandoned staging metadata: {e}"))?;
        if meta.file_type().is_symlink() {
            // Удаляйте ссылку без следования по пути, управляемому злоумышленником.
            fs::remove_file(&path).await.map_err(|e| format!("Java abandoned staging link: {e}"))?;
        } else if meta.is_dir() {
            fs::remove_dir_all(&path).await.map_err(|e| format!("Java abandoned staging: {e}"))?;
        } else {
            fs::remove_file(&path).await.map_err(|e| format!("Java abandoned staging file: {e}"))?;
        }
    }
    Ok(())
}

async fn quarantine_broken_runtime(path: &Path) -> Result<(), String> {
    let stamp = now_unix()?;
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("runtime");
    let target = path.with_file_name(format!(".broken-{name}-{stamp}-{:016x}", rand::random::<u64>()));
    fs::rename(path, &target).await.map_err(|err| format!("не удалось quarantine повреждённую Java: {err}"))
}

struct InstallLock { _file: std::fs::File }

async fn acquire_install_lock(dir: &Path) -> Result<InstallLock, String> {
    let path = dir.join(".install.lock");
    // Сохраняйте файл постоянно: удаление inode активной блокировки flock/LockFileEx позволяет второму процессу создать новый файл и войти одновременно.
    let file = std::fs::OpenOptions::new().read(true).write(true).create(true)
        .open(&path).map_err(|e| format!("Managed Java lock open: {e}"))?;
    for _ in 0..120 {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(InstallLock { _file: file }),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => sleep(Duration::from_millis(500)).await,
            Err(e) => return Err(format!("Managed Java lock acquire: {e}")),
        }
    }
    Err("Managed Java installation occupied by another process".into())
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

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_java_archive_does_not_follow_symlink() {
        let root = std::env::temp_dir().join(format!("java-archive-link-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&root).await.unwrap();
        let original = root.join("vendor.tar.gz");
        fs::write(&original, b"signed vendor bytes").await.unwrap();
        let digest = hex::encode(Sha256::digest(b"signed vendor bytes"));
        assert!(verify_file_sha256(&original, &digest, 19).await.unwrap());
        let linked = root.join("cached.tar.gz");
        std::os::unix::fs::symlink(&original, &linked).unwrap();
        assert!(!verify_file_sha256(&linked, &digest, 19).await.unwrap());
        fs::remove_dir_all(root).await.unwrap();
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

    #[test]
    fn managed_java_ii_major_policy_is_exact() {
        for major in MANAGED_JAVA_MAJORS {
            assert!(validate_managed_java_major(major).is_ok(), "Java {major} must be managed");
        }
        for major in [7, 11, 22, 26] {
            assert!(validate_managed_java_major(major).is_err(), "Для Java {major} требуется: «rejected»");
        }
    }

    #[test]
    fn managed_distribution_paths_are_fail_closed() {
        assert!(validate_distribution_archive_name("launcher-jre-temurin21-linux-x64.tar.gz").is_ok());
        assert!(validate_distribution_archive_name("../runtime.tar.gz").is_err());
        assert!(validate_distribution_archive_name("nested/runtime.tar.gz").is_err());
        assert!(validate_distribution_java_entry("jdk-21/bin/java", "linux").is_ok());
        assert!(validate_distribution_java_entry("../bin/java", "linux").is_err());
        assert!(validate_distribution_java_entry("jdk/bin/java.exe", "windows").is_ok());
    }

    #[test]
    fn managed_java_https_policy_rejects_credentials_and_fragments() {
        assert!(validate_https_url("https://api.adoptium.net/v3/assets/latest/21/hotspot").is_ok());
        assert!(validate_https_url("http://api.adoptium.net/runtime.tar.gz").is_err());
        assert!(validate_https_url("https://user:secret@example.com/runtime.tar.gz").is_err());
        assert!(validate_https_url("https://example.com/runtime.tar.gz#fragment").is_err());
    }

    #[test]
    fn native_managed_java_machine_checks_cover_all_arm64_targets() {
        let root = std::env::temp_dir().join(format!("managed-native-machine-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        let java = root.join("java");
        let mut elf = vec![0u8; 64];
        elf[0..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        std::fs::write(&java, &elf).unwrap();
        assert!(verify_native_java_executable(&java, "linux", "aarch64").is_ok());
        assert!(verify_native_java_executable(&java, "linux", "x86_64").is_err());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        std::fs::write(&java, &elf).unwrap();
        assert!(verify_native_java_executable(&java, "linux", "arm64").is_err());

        let mut pe = vec![0u8; 256];
        pe[0..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&128u32.to_le_bytes());
        pe[128..132].copy_from_slice(b"PE\0\0");
        pe[132..134].copy_from_slice(&0xaa64u16.to_le_bytes());
        std::fs::write(&java, &pe).unwrap();
        assert!(verify_native_java_executable(&java, "windows", "aarch64").is_ok());
        assert!(verify_native_java_executable(&java, "windows", "amd64").is_err());
        pe[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        std::fs::write(&java, &pe).unwrap();
        assert!(verify_native_java_executable(&java, "windows", "aarch64").is_err());

        let mut mach = vec![0u8; 64];
        mach[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        mach[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes());
        std::fs::write(&java, &mach).unwrap();
        assert!(verify_native_java_executable(&java, "macos", "arm64").is_ok());
        assert!(verify_native_java_executable(&java, "macos", "x64").is_err());

        let mut fat = vec![0u8; 96];
        fat[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        fat[4..8].copy_from_slice(&1u32.to_be_bytes());
        fat[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
        fat[16..20].copy_from_slice(&32u32.to_be_bytes());
        fat[20..24].copy_from_slice(&64u32.to_be_bytes());
        fat[32..36].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        fat[36..40].copy_from_slice(&0x0100000cu32.to_le_bytes());
        std::fs::write(&java, &fat).unwrap();
        assert!(verify_native_java_executable(&java, "macos", "aarch64").is_ok());
        fat[36..40].copy_from_slice(&0x01000007u32.to_le_bytes());
        std::fs::write(&java, &fat).unwrap();
        assert!(verify_native_java_executable(&java, "macos", "aarch64").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn java_property_and_arch_validation() {
        let output = "Property settings:\n    os.arch = amd64\n    os.name = Linux\nopenjdk version \"21.0.5\"";
        assert_eq!(java_property(output, "os.arch"), Some("amd64"));
        assert_eq!(java_property(output, "os.name"), Some("Linux"));
        assert_eq!(normalize_adoptium_arch("amd64"), normalize_adoptium_arch("x86_64"));
        assert_eq!(crate::parse_java_major_version(output), Some(21));
        assert_eq!(java_property(output, "java.home"), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn interrupted_install_cleanup_follows_symlink() {
        let root = std::env::temp_dir().join(format!("neverjava-interrupted-{:016x}", rand::random::<u64>()));
        let platform = root.join("runtime");
        let external = root.join("unrelated-user-data");
        fs::create_dir_all(platform.join(".staging-dead-process")).await.unwrap();
        fs::write(platform.join(".staging-dead-process/jvm.tmp"), b"partial install").await.unwrap();
        fs::create_dir_all(&external).await.unwrap();
        fs::write(external.join("keep.txt"), b"keep").await.unwrap();
        std::os::unix::fs::symlink(&external, platform.join(".staging-link")).unwrap();
        cleanup_interrupted_java_staging(&platform).await.unwrap();
        assert!(!platform.join(".staging-dead-process").exists());
        assert!(!platform.join(".staging-link").exists());
        assert_eq!(fs::read(external.join("keep.txt")).await.unwrap(), b"keep");
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn inventory_detects_non_executable_corruption_and_added_files() {
        let root = std::env::temp_dir().join(format!("java-files-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(root.join("bin")).await.unwrap();
        fs::create_dir_all(root.join("lib")).await.unwrap();
        fs::write(root.join("bin/java"), b"java executable").await.unwrap();
        fs::write(root.join("lib/libjvm.so"), b"real runtime library").await.unwrap();
        let inventory = inventory_runtime_files(&root).await.unwrap();
        assert!(verify_runtime_inventory(&root, &inventory).await.unwrap());
        fs::write(root.join("lib/libjvm.so"), b"damaged runtime library").await.unwrap();
        assert!(!verify_runtime_inventory(&root, &inventory).await.unwrap());
        fs::write(root.join("lib/libjvm.so"), b"real runtime library").await.unwrap();
        fs::write(root.join("lib/unknown"), b"unexpected file").await.unwrap();
        assert!(!verify_runtime_inventory(&root, &inventory).await.unwrap());
        let _ = fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn real_java_executes_bytecode_and_detects_corruption() {
        // При наличии настоящей JRE/JDK на машине разработчика или нативном CI-узле используется она. `javac` не требуется; поддерживается Java 8+.
        let check = Command::new("java").args(["-XshowSettings:properties", "-version"])
            .output().await;
        let Ok(output) = check else { eprintln!("Java отсутствует на тестовом хосте: проверка нативной JVM пропущена"); return; };
        if !output.status.success() { return; }
        let properties = format!("{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        let Some(home) = java_property(&properties, "java.home") else { return; };
        let executable = PathBuf::from(home).join("bin").join(if cfg!(windows) { "java.exe" } else { "java" });
        let Some(major) = crate::parse_java_major_version(&properties) else { return; };
        let (os, arch) = adoptium_platform().unwrap();
        self_test_java(&executable, major, &os, &arch).await.unwrap();
        let root = std::env::temp_dir().join(format!("neverjava-tamper-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&root).await.unwrap();
        let target = root.join("java");
        fs::write(&target, b"not a JVM").await.unwrap();
        let result = verify_java_bytecode_execution(&target, major).await;
        assert!(result.is_err());
        let _ = fs::remove_dir_all(root).await;
    }

    // Полная локальная установка и автоматическое восстановление используют тот же кэш архивов и путь подготовки, что Desktop/CLI. На Unix необходим tar.
    #[cfg(unix)]
    #[tokio::test]
    async fn version_spoofing_runtime_is_not_installed() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("java-release-{:016x}", rand::random::<u64>()));
        let source = root.join("source/jdk/bin");
        fs::create_dir_all(&source).await.unwrap();
        let (os, arch) = adoptium_platform().unwrap();
        let script = format!("#!/bin/sh\nprintf '    os.arch = {}\\n    os.name = {}\\nopenjdk version \\\"21.0.5\\\"\\n' 1>&2\n", arch,
            if os == "osx" { "Mac OS X" } else { "Linux" });
        let java = source.join("java");
        fs::write(&java, script).await.unwrap();
        std::fs::set_permissions(&java, std::fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(root.join("pkg")).await.unwrap();
        let archive = root.join("pkg/temurin.tar.gz");
        let output = Command::new("tar").args(["-czf"]).arg(&archive).arg("-C")
            .arg(root.join("source")).arg("jdk").output().await.unwrap();
        assert!(output.status.success());
        let (checksum, size) = sha256_file(&archive).await.unwrap();
        let (platform, architecture) = distribution_platform().unwrap();
        let manifest = serde_json::json!({
            "schemaVersion": "1.0", "product": "Launcher", "productVersion": env!("CARGO_PKG_VERSION"),
            "distribution": "temurin", "vendor": "Eclipse Adoptium", "majorVersion": 21,
            "targets": [{
                "platform": platform, "architecture": architecture, "distribution": "temurin", "majorVersion": 21,
                "releaseName": "test-runtime", "semver": "21.0.5", "archive": "temurin.tar.gz", "format": "tar.gz",
                "sha256": checksum, "size": size, "javaEntry": "jdk/bin/java",
                "sourceUrl": "https://not-reachable.invalid/temurin.tar.gz", "sourceSha256": checksum
            }]
        });
        let manifest_path = root.join("pkg/MANAGED_JRE_MANIFEST.json");
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &bytes).await.unwrap();
        let manifest_sha256 = hex::encode(Sha256::digest(&bytes));
        let runtimes = root.join("runtimes");
        let error = ensure_managed_java_from_distribution(21, "temurin", Some(&runtimes),
            manifest_path.to_str().unwrap(), Some(&manifest_sha256)).await.unwrap_err();
        assert!(error.contains("bytecode") || error.contains("probe"), "{error}");
        // Архив, подделывающий допустимый java -version, никогда не должен публиковать установленный Runtime или повторно использоваться как проверенная запись кэша.
        let base = runtimes.join("temurin/21");
        let (_, arch) = adoptium_platform().unwrap();
        assert!(!base.join(format!("{}-{}", os, arch)).join(
            format!("test-runtime-{}", &checksum[..16])).exists());
        let _ = fs::remove_dir_all(root).await;
    }

}
