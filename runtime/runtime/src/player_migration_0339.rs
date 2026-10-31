//! MIG09. Adoption of *content* from a player's old Gravit installation.
//! A Gravit folder is untrusted input: no code, config, credentials or trust is executed or copied.
//! Only bytes independently pinned by a Launcher Ed25519 signed manifest may enter
//! Runtime's ordinary, OS-locked, SHA-256 content cache. The existing download/install
//! path then consumes those objects and performs its own integrity checks.
use crate::{content_cache::CacheStore, file_ownership, manifest_file_applies, resolved_download_0246,
    verify_manifest_signature, Manifest, ManifestFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, HashSet}, fs, io::{BufRead, BufReader, Read}, path::{Component, Path, PathBuf}};

const MAX_SCAN_FILES: usize = 30_000;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024 * 1024;
const MAX_SETTINGS_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerSettings0339 {
    pub fullscreen: Option<bool>,
    pub screen_width: Option<u32>,
    pub screen_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerMigrationPreview0339 {
    pub source: String,
    pub project_id: String,
    pub profile_id: String,
    pub channel: String,
    pub release_version: String,
    pub selected_preset: String,
    pub matched_files: usize,
    pub missing_files: usize,
    pub matched_bytes: u64,
    pub matched_paths: Vec<String>,
    /// Heuristic only: a component is a candidate when all of its signed file bytes exist.
    /// A player must choose a preset separately using the normal signed component resolver.
    pub optional_component_candidates: Vec<String>,
    pub suggested_settings: PlayerSettings0339,
    pub warning: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerMigrationResult0339 {
    pub cached_files: usize,
    pub cached_bytes: u64,
    pub unavailable_files: usize,
    pub optional_component_candidates: Vec<String>,
    pub suggested_settings: PlayerSettings0339,
    pub message: String,
}

fn valid_relative(path: &str) -> Result<&Path, String> {
    let p = Path::new(path);
    if p.as_os_str().is_empty() || p.is_absolute() || path.contains('\\') || path.contains(':') ||
        !p.components().all(|x| matches!(x, Component::Normal(_))) {
        return Err("unsafe signed path for source lookup".into());
    }
    Ok(p)
}

fn safe_source(source: &Path) -> Result<PathBuf, String> {
    // A manually selected root must exist. Do not silently create or traverse a symlink root.
    let meta = fs::symlink_metadata(source).map_err(|e| format!("legacy directory: {e}"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("legacy root must be an existing real directory".into());
    }
    let root = fs::canonicalize(source).map_err(|e| e.to_string())?;
    if !root.is_absolute() { return Err("legacy root is not absolute".into()); }
    Ok(root)
}

fn candidate_roots(source: &Path, profile_id: &str) -> Result<Vec<PathBuf>, String> {
    // Only known directory layouts; no recursive glob or unbounded scan of an untrusted tree.
    if profile_id.is_empty() || profile_id.contains('/') || profile_id.contains('\\') ||
        profile_id == "." || profile_id == ".." || profile_id.contains(':') {
        return Err("unsafe profile identifier".into());
    }
    Ok(vec![source.to_path_buf(), source.join(".minecraft"),
        source.join("updates").join(profile_id), source.join("clients").join(profile_id),
        source.join(profile_id)])
}

fn is_safe_file(root: &Path, path: &Path, size: u64) -> bool {
    if file_ownership::ensure_no_symlinks(root, path).is_err() { return false; }
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink() && m.len() == size)
}

fn digest_file(path: &Path, expected: &ManifestFile) -> Result<bool, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("read legacy content: {e}"))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() != expected.size { return Ok(false); }
    let mut buffer = [0u8; 128 * 1024];
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 { break }
        bytes = bytes.checked_add(read as u64).ok_or("source byte count overflow")?;
        if bytes > expected.size { return Ok(false) }
        hash.update(&buffer[..read]);
    }
    Ok(bytes == expected.size && hex::encode(hash.finalize()).eq_ignore_ascii_case(&expected.sha256))
}

fn locate_verified(root: &Path, layouts: &[PathBuf], file: &ManifestFile) -> Result<Option<PathBuf>, String> {
    let rel = valid_relative(&file.path)?;
    for layout in layouts {
        // The entire candidate tree is checked for symlinks/reparse points, including layout.
        let candidate = layout.join(rel);
        if !is_safe_file(root, &candidate, file.size) { continue }
        if digest_file(&candidate, file)? { return Ok(Some(candidate)); }
    }
    Ok(None)
}

fn options_from(source: &Path, layouts: &[PathBuf]) -> PlayerSettings0339 {
    let mut result = PlayerSettings0339 { fullscreen: None, screen_width: None, screen_height: None };
    // options.txt is Minecraft's ordinary display preferences; do not read or copy
    // launcher config, auth cache, account database, Java args, server settings or scripts.
    for base in layouts {
        let file = base.join("options.txt");
        if !is_safe_file(source, &file, fs::symlink_metadata(&file).map_or(u64::MAX, |m| m.len())) { continue }
        let Ok(meta) = fs::metadata(&file) else { continue };
        if meta.len() > MAX_SETTINGS_BYTES { continue }
        let Ok(open) = fs::File::open(file) else { continue };
        for line in BufReader::new(open).lines().take(512).flatten() {
            let Some((key, value)) = line.split_once(':') else { continue };
            match key {
                "fullscreen" => result.fullscreen = match value.trim() { "true" => Some(true), "false" => Some(false), _ => result.fullscreen },
                "overrideWidth" => result.screen_width = value.trim().parse::<u32>().ok().filter(|v| (640..=7680).contains(v)),
                "overrideHeight" => result.screen_height = value.trim().parse::<u32>().ok().filter(|v| (480..=4320).contains(v)),
                _ => {},
            }
        }
        break;
    }
    result
}

struct Scan0339 {
    preview: PlayerMigrationPreview0339,
    verified: Vec<(ManifestFile, PathBuf)>,
}

fn scan(manifest: &Manifest, pinned_public_key: &str, legacy_root: &Path, preset: Option<&str>) -> Result<Scan0339, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    file_ownership::validate_download_targets(manifest)?;
    let plan = resolved_download_0246::resolve(manifest, preset)?;
    if plan.files.len() > MAX_SCAN_FILES { return Err("too many signed files for player migration".into()) }
    let root = safe_source(legacy_root)?;
    let layouts = candidate_roots(&root, &manifest.profile_id)?;
    let mut verified = Vec::new();
    let mut total = 0u64;
    let mut matched = 0u64;
    for file in manifest.files.iter().filter(|f| plan.selected_paths.contains(&f.path)) {
        if !manifest_file_applies(file) { continue }
        if file.size > MAX_FILE_BYTES { return Err(format!("signed file exceeds player migration limit: {}", file.path)); }
        total = total.checked_add(file.size).ok_or("signed total size overflow")?;
        if total > MAX_SCAN_BYTES { return Err("signed release exceeds player migration scan limit".into()) }
        if let Some(source) = locate_verified(&root, &layouts, file)? {
            matched += file.size;
            verified.push((file.clone(), source));
        }
    }
    let matched_paths: Vec<String> = verified.iter().map(|(f, _)| f.path.clone()).collect();
    // Determine legacy optional selections independently of the Never preset chosen for
    // cache adoption. This is an advisory *mapping by verified content*, never an
    // implicit selection or execution of optional actions.
    let mut found: HashSet<String> = matched_paths.iter().cloned().collect();
    let by_path: HashMap<_, _> = manifest.files.iter().map(|f| (f.path.as_str(), f)).collect();
    let mut examined = 0usize;
    let mut optional_bytes = 0u64;
    if let Some(catalog) = &manifest.component_catalog {
        for component in &catalog.components {
            for path in &component.files {
                if found.contains(path) { continue }
                let Some(file) = by_path.get(path.as_str()) else { continue };
                examined += 1;
                if examined > MAX_SCAN_FILES { return Err("too many optional sources for player migration".into()) }
                if file.size > MAX_FILE_BYTES { continue }
                optional_bytes = optional_bytes.checked_add(file.size).ok_or("optional source size overflow")?;
                if optional_bytes > MAX_SCAN_BYTES { return Err("optional migration scan exceeds byte limit".into()) }
                if locate_verified(&root, &layouts, file)?.is_some() { found.insert(path.clone()); }
            }
        }
    }
    let optional_component_candidates = manifest.component_catalog.as_ref().map(|c| c.components.iter()
        .filter(|c| !c.required && !c.files.is_empty() && c.files.iter().all(|p| found.contains(p)))
        .map(|c| c.id.clone()).collect()).unwrap_or_default();
    let missing = plan.files.len().saturating_sub(verified.len());
    let preview = PlayerMigrationPreview0339 {
        source: root.to_string_lossy().into_owned(),
        project_id: manifest.project_id.clone(), profile_id: manifest.profile_id.clone(),
        channel: manifest.channel.clone(), release_version: manifest.version.clone(),
        selected_preset: preset.unwrap_or_default().to_owned(), matched_files: verified.len(),
        missing_files: missing, matched_bytes: matched, matched_paths,
        optional_component_candidates, suggested_settings: options_from(&root, &layouts),
        warning: "Only signed Never content is reused. Cached bytes are verified again during installation; login, device enrollment and component selection remain separate.".into(),
    };
    Ok(Scan0339 { preview, verified })
}

pub fn preview(manifest: &Manifest, pinned_public_key: &str, legacy_root: &Path, preset: Option<&str>) -> Result<PlayerMigrationPreview0339, String> {
    Ok(scan(manifest, pinned_public_key, legacy_root, preset)?.preview)
}

pub async fn adopt(manifest: &Manifest, pinned_public_key: &str, legacy_root: &Path, preset: Option<&str>) -> Result<PlayerMigrationResult0339, String> {
    // Re-scan after the user's confirmation; NEVER trust a renderer-supplied list or old preview.
    let signed = manifest.clone(); let pin = pinned_public_key.to_owned();
    let root = legacy_root.to_path_buf(); let choice = preset.map(str::to_owned);
    let scanned = tokio::task::spawn_blocking(move || scan(&signed, &pin, &root, choice.as_deref()))
        .await.map_err(|e| format!("scan task: {e}"))??;
    let cache = CacheStore::standard()?;
    adopt_scanned(scanned, &cache).await
}

async fn adopt_scanned(scanned: Scan0339, cache: &CacheStore) -> Result<PlayerMigrationResult0339, String> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for (file, source) in scanned.verified {
        // The store's OS lock prevents conflicts with ongoing installs/downloads.
        let lease = cache.lock(&file).await?;
        // Source could change while scan is running: verify before publishing.
        let source_root = PathBuf::from(&scanned.preview.source);
        if !is_safe_file(&source_root, &source, file.size) || !digest_file(&source, &file)? {
            return Err(format!("legacy source changed during adoption: {}", file.path))
        }
        lease.publish(&file, &source).await?; // copy, fsync, rehash, atomic publication
        count += 1;
        bytes += file.size;
    }
    Ok(PlayerMigrationResult0339 { cached_files: count, cached_bytes: bytes,
        unavailable_files: scanned.preview.missing_files,
        optional_component_candidates: scanned.preview.optional_component_candidates,
        suggested_settings: scanned.preview.suggested_settings,
        message: "Verified Never content objects published to the shared cache. Install/repair through the ordinary signed release workflow; no Gravit credentials or executables were adopted.".into() })
}

/// Suggested legacy roots only; the player selects and confirms the actual folder.
pub fn discover() -> Vec<String> {
    let Some(home) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from) else { return Vec::new() };
    let mut places = vec![home.join(".minecraft"), home.join(".gravitlauncher"), home.join("GravitLauncher")];
    if let Some(appdata) = std::env::var_os("APPDATA") { places.push(PathBuf::from(appdata).join(".minecraft")); places.push(PathBuf::from(appdata).join("GravitLauncher")); }
    if cfg!(target_os = "macos") { places.push(home.join("Library/Application Support/minecraft")); }
    let mut unique = HashSet::new();
    places.into_iter().filter(|p| p.is_dir() && !fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
        .filter_map(|p| fs::canonicalize(p).ok()).filter(|p| unique.insert(p.clone()))
        .map(|p| p.to_string_lossy().into_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_manifest;
    use serde_json::json;
    fn fixture() -> (PathBuf, Manifest, String) {
        let root = std::env::temp_dir().join(format!("nl-mig09-{}-{}", std::process::id(), rand::random::<u64>()));
        fs::create_dir_all(root.join("updates/default/mods")).unwrap();
        fs::write(root.join("updates/default/mods/test.jar"), b"SAFE").unwrap();
        fs::write(root.join("options.txt"), "fullscreen:true\noverrideWidth:1920\noverrideHeight:1080\nauthToken:secret\n").unwrap();
        let mut m: Manifest = serde_json::from_value(json!({"schemaVersion":"2.0", "projectId":"p", "profileId":"default", "channel":"stable", "version":"1", "createdAt":"2026-10-20T00:00:00Z", "minecraft":{"version":"1.20.4","loader":"vanilla"}, "runtime":{"java":{"majorVersion":17,"distribution":"temurin"}}, "files":[{"path":"mods/test.jar","size":4,"sha256":hex::encode(Sha256::digest(b"SAFE")),"url":"https://example.test/test.jar","required":true,"ownership":"managed"}], "profileSnapshot":{"schemaVersion":"2.0","revision":1,"digest":hex::encode(Sha256::digest(b"p\0default\0Default\0\0vanilla\0\0true")),"spec":{"projectId":"p","id":"default","name":"Default","description":"","loader":"vanilla","preset":"","isDefault":true}}})).unwrap();
        let key = sign_manifest(&mut m, &"1a".repeat(32), "2026-10-20T00:00:00Z").unwrap();
        (root,m,key)
    }
    #[test]
    fn scan_real_bytes_and_safe_settings() {
        let (root,m,key) = fixture();
        let report = preview(&m,&key,&root,None).unwrap();
        assert_eq!(report.matched_files,1);
        assert_eq!(report.matched_bytes,4);
        assert_eq!(report.suggested_settings.fullscreen,Some(true));
        assert!(!serde_json::to_string(&report).unwrap().contains("secret"));
        fs::write(root.join("updates/default/mods/test.jar"),b"EVIL").unwrap();
        assert_eq!(preview(&m,&key,&root,None).unwrap().matched_files,0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unsigned_or_wrong_pin_rejected_and_bad_paths_rejected() {
        let (root,mut m,key) = fixture();
        assert!(preview(&m,&"ff".repeat(32),&root,None).is_err());
        m.signature=None;
        assert!(preview(&m,&key,&root,None).is_err());
        assert!(valid_relative("../../secret").is_err());
        assert!(valid_relative("C:/Windows/win.ini").is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn adopted_bytes_are_consumable_by_regular_content_cache() {
        let (root, m, key) = fixture();
        let cache_path = root.join("test-never-cache");
        let store = CacheStore::at(cache_path);
        let first = scan(&m, &key, &root, None).unwrap();
        let result = adopt_scanned(first, &store).await.unwrap();
        assert_eq!(result.cached_files, 1);
        let file = &m.files[0];
        let restored = root.join("restored.jar");
        let lease = store.lock(file).await.unwrap();
        assert!(lease.restore(&root, file, &restored).await.unwrap());
        assert_eq!(fs::read(restored).unwrap(), b"SAFE");
        drop(lease);
        // A repeated adoption reuses the same locked object instead of duplicating it.
        assert_eq!(adopt_scanned(scan(&m, &key, &root, None).unwrap(), &store)
            .await.unwrap().cached_files, 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn source_mutation_after_preview_never_publishes() {
        let (root, m, key) = fixture();
        let scan = scan(&m, &key, &root, None).unwrap();
        fs::write(root.join("updates/default/mods/test.jar"), b"EVIL").unwrap();
        let store = CacheStore::at(root.join("test-never-cache"));
        assert!(adopt_scanned(scan, &store).await.is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_source_rejected() {
        use std::os::unix::fs::symlink;
        let (root,m,key) = fixture();
        fs::remove_file(root.join("updates/default/mods/test.jar")).unwrap();
        symlink("/etc/passwd",root.join("updates/default/mods/test.jar")).unwrap();
        assert_eq!(preview(&m,&key,&root,None).unwrap().matched_files,0);
        fs::remove_dir_all(root).unwrap();
    }
}
