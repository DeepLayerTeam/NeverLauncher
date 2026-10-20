//! Crash-recoverable, whole-release client installation. Network workers only write
//! into staging. A durable write-ahead journal is published before touching any
//! live file, and old file bytes are preserved until the next release is safe.
use crate::{download_scheduler::{self, DownloadLimits, ProgressSink}, file_ownership, platform_fs,
    manifest_file_applies, network_resilience::Directive, safe_join, sha256_file, release_generations,
    verify_manifest_signature, DownloadResult, Manifest};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, io::{Read, Write}, path::{Path, PathBuf}};
use tokio::sync::watch;

const MAX_STATE: u64 = 32 * 1024 * 1024;
const SCHEMA: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    manifest: Manifest,
    installed: Vec<String>,
    id: String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    preset: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pointer { schema: u32, generation: u64, active: Option<Release> }
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Backup {
    path: String,
    old_sha256: Option<String>,
    new_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    schema: u32,
    generation: u64,
    state: String,
    previous: Option<Release>,
    next: Release,
    backup_id: String,
    entries: Vec<Backup>,
}

fn base(root: &Path) -> PathBuf { root.join(".neverlauncher").join("client-releases") }
fn state_path(root: &Path, kind: &str, slot: usize) -> PathBuf {
    base(root).join(format!("{kind}-{slot}.json"))
}
fn validate_id(id: &str) -> Result<(), String> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid release transaction id".into()); }
    Ok(())
}
fn io_err(context: &str, err: std::io::Error) -> String { format!("{context}: {err}") }
fn safe_dir(root: &Path, path: &Path) -> Result<(), String> {
    file_ownership::ensure_no_symlinks(root, path)?;
    fs::create_dir_all(path).map_err(|e| io_err("create release directory", e))?;
    file_ownership::ensure_no_symlinks(root, path)
}
fn sync_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)] {
        fs::File::open(path).and_then(|f| f.sync_all())
            .map_err(|e| format!("persist directory {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))] { let _ = path; }
    Ok(())
}
fn write_slot<T: Serialize>(root: &Path, kind: &str, generation: u64, value: &T) -> Result<(), String> {
    let dest = state_path(root, kind, (generation % 2) as usize);
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_STATE { return Err("release state exceeds maximum size".into()); }
    let temp = dest.with_extension(format!("{:016x}.tmp", rand::random::<u64>()));
    file_ownership::ensure_no_symlinks(root, &dest)?;
    let mut created = false;
    let result = (|| -> Result<(), String> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&temp)
            .map_err(|e| e.to_string())?;
        created = true;
        f.write_all(&data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
        drop(f);
        // Never unlink a pointer slot before replacing it. A sharing violation
        // or power failure must leave the last durable pointer intact.
        platform_fs::replace_file(root, &temp, &dest)?;
        sync_dir(&base(root))
    })();
    if result.is_err() && created { let _ = fs::remove_file(&temp); }
    result
}
fn read_slot<T: for<'de> Deserialize<'de>>(root: &Path, kind: &str, slot: usize) -> Option<T> {
    let path = state_path(root, kind, slot);
    file_ownership::ensure_no_symlinks(root, &path).ok()?;
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_STATE { return None; }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}
fn state_exists(root: &Path, kind: &str) -> bool {
    (0..2).any(|slot| fs::symlink_metadata(state_path(root, kind, slot)).is_ok())
}
fn pointer(root: &Path) -> Result<Pointer, String> {
    let a: Option<Pointer> = read_slot(root, "active", 0);
    let b: Option<Pointer> = read_slot(root, "active", 1);
    let valid = [a, b].into_iter().flatten().filter(|x| x.schema == SCHEMA).max_by_key(|x| x.generation);
    valid.ok_or_else(|| "client release pointer is damaged".to_string()).or_else(|e| {
        if state_exists(root, "active") { Err(e) } else { Ok(Pointer { schema: SCHEMA, generation: 0, active: None }) }
    })
}
fn journal(root: &Path) -> Result<Option<Journal>, String> {
    let a: Option<Journal> = read_slot(root, "switch", 0);
    let b: Option<Journal> = read_slot(root, "switch", 1);
    let valid = [a, b].into_iter().flatten().filter(|j| j.schema == SCHEMA && matches!(j.state.as_str(), "switching" | "complete" | "reverting"))
        .max_by_key(|j| j.generation);
    if valid.is_none() && state_exists(root, "switch") { return Err("client release switch journal is damaged".into()); }
    Ok(valid)
}
fn last_known_good(root: &Path) -> Result<Option<Journal>, String> {
    let a: Option<Journal> = read_slot(root, "last-known-good", 0);
    let b: Option<Journal> = read_slot(root, "last-known-good", 1);
    let valid = [a, b].into_iter().flatten().filter(|j| j.schema == SCHEMA && j.state == "complete")
        .max_by_key(|j| j.generation);
    if valid.is_none() && state_exists(root, "last-known-good") {
        return Err("last-known-good metadata is damaged".into());
    }
    Ok(valid)
}
fn lock(root: &Path) -> Result<fs::File, String> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    safe_dir(&root, &base(&root))?;
    let path = base(&root).join("release.lock");
    file_ownership::ensure_no_symlinks(&root, &path)?;
    let file = fs::OpenOptions::new().read(true).write(true).create(true).open(path).map_err(|e| e.to_string())?;
    file.try_lock_exclusive().map_err(|e| format!("client release is busy (Minecraft may be running): {e}"))?;
    Ok(file)
}
fn eligible(manifest: &Manifest, path: &str) -> bool {
    manifest.files.iter().any(|f| f.path == path && manifest_file_applies(f) && !file_ownership::skip_download(manifest, f))
}
fn validate_release(release: &Release, key: &str) -> Result<(), String> {
    validate_id(&release.id)?;
    verify_manifest_signature(&release.manifest, key)?;
    file_ownership::validate_download_targets(&release.manifest)?;
    let selected=crate::component_catalog_0241::active_files(&release.manifest,release.preset.as_deref())?;
    let mut seen = BTreeSet::new();
    for p in &release.installed {
        if !selected.contains(p) || !eligible(&release.manifest, p) || !seen.insert(p) { return Err(format!("invalid release ownership record: {p}")); }
    }
    if release.manifest.schema_version == "3.0" {
        for file in &release.manifest.files {
            if selected.contains(&file.path) && eligible(&release.manifest, &file.path) && !seen.contains(&file.path) {
                return Err(format!("v3 signed component file not installed: {}",file.path));
            }
        }
    }
    Ok(())
}
fn expected<'a>(release: &'a Release, path: &str) -> Option<(&'a str, u64)> {
    release.manifest.files.iter().find(|f| f.path == path).map(|f| (f.sha256.as_str(), f.size))
}
fn hash(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut digest = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        digest.update(&buf[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
fn matches_digest(path: &Path, digest: &str, length: u64) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink() && m.len() == length)
        && hash(path).is_ok_and(|actual| actual.eq_ignore_ascii_case(digest))
}
async fn matches_digest_async(path: &Path, digest: &str, length: u64) -> bool {
    tokio::fs::symlink_metadata(path).await.is_ok_and(|m| m.is_file() && !m.file_type().is_symlink() && m.len() == length)
        && sha256_file(path).await.is_ok_and(|actual| actual.eq_ignore_ascii_case(digest))
}
fn verify_installed(root: &Path, release: &Release) -> Result<bool, String> {
    for p in &release.installed {
        let path = safe_join(root, p)?;
        file_ownership::ensure_no_symlinks(root, &path)?;
        let (sha, size) = expected(release, p).ok_or("missing signed file in release")?;
        if !matches_digest(&path, sha, size) { return Ok(false); }
    }
    Ok(true)
}
fn verify_journal(root: &Path, j: &Journal, key: &str) -> Result<(), String> {
    validate_release(&j.next, key)?;
    if let Some(ref old) = j.previous { validate_release(old, key)?; }
    validate_id(&j.backup_id)?;
    let old: BTreeSet<_> = j.previous.as_ref().map(|p| p.installed.iter().map(String::as_str).collect()).unwrap_or_default();
    let new: BTreeSet<_> = j.next.installed.iter().map(String::as_str).collect();
    let all: BTreeSet<_> = old.union(&new).copied().collect();
    if j.entries.len() != all.len() { return Err("release journal path count mismatch".into()); }
    for (entry, signed_path) in j.entries.iter().zip(all) {
        if entry.path != signed_path || entry.new_sha256.is_some() != new.contains(signed_path) {
            return Err("release journal contains unsigned paths".into());
        }
        if let Some(ref digest) = entry.old_sha256 {
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid backup digest".into()); }
        }
        if let Some(ref digest) = entry.new_sha256 {
            if expected(&j.next, &entry.path).is_none_or(|(sha, _)| !sha.eq_ignore_ascii_case(digest)) { return Err("journal target digest mismatch".into()); }
        }
        let path = safe_join(root, &entry.path)?;
        file_ownership::ensure_no_symlinks(root, &path)?;
    }
    Ok(())
}
fn backup_dir(root: &Path, id: &str) -> PathBuf { base(root).join("backups").join(id) }
fn copy_durable(src: &Path, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let mut created = false;
    let result = (|| {
        let mut input = fs::File::open(src).map_err(|e| format!("read backup source {}: {e}", src.display()))?;
        // create_new refuses a substituted symlink/existing backup path.
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(dest)
            .map_err(|e| format!("create durable copy {}: {e}", dest.display()))?;
        created = true;
        std::io::copy(&mut input, &mut output).map_err(|e| format!("stream durable copy: {e}"))?;
        output.set_permissions(input.metadata().map_err(|e| e.to_string())?.permissions())
            .map_err(|e| format!("preserve managed file permissions: {e}"))?;
        output.sync_all().map_err(|e| format!("flush durable copy: {e}"))?;
        drop(output);
        if let Some(parent) = dest.parent() { sync_dir(parent)?; }
        Ok(())
    })();
    if result.is_err() && created { let _ = fs::remove_file(dest); }
    result
}
fn switch_file(root: &Path, source: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination.parent().ok_or("target has no parent")?;
    file_ownership::ensure_no_symlinks(root, destination)?;
    safe_dir(root, parent)?;
    platform_fs::replace_file(root, source, destination)
}
fn restore(root: &Path, j: &Journal) -> Result<(), String> {
    let back = backup_dir(root, &j.backup_id);
    // Fail on case aliases, hostile reparse points or denied destinations
    // BEFORE any restoration makes a change to the live tree.
    let destinations: Vec<_> = j.entries.iter().map(|e| safe_join(root, &e.path)).collect::<Result<_, _>>()?;
    platform_fs::preflight_targets(root, &destinations)?;
    // Validate ALL backup bytes before modifying even the first destination.
    for e in &j.entries {
        if let Some(ref digest) = e.old_sha256 {
            let saved = safe_join(&back, &e.path)?;
            file_ownership::ensure_no_symlinks(root, &saved)?;
            if hash(&saved)?.to_ascii_lowercase() != digest.to_ascii_lowercase() {
                return Err(format!("last-known-good backup is damaged: {}", e.path));
            }
        }
    }
    for e in &j.entries {
        let target = safe_join(root, &e.path)?;
        platform_fs::check_target(root, &target)?;
        match &e.old_sha256 {
            Some(_) => {
                let source = safe_join(&back, &e.path)?;
                let tmp = target.with_extension(format!("nl-restore-{:016x}", rand::random::<u64>()));
                copy_durable(&source, &tmp)?;
                switch_file(root, &tmp, &target)?;
            },
            None => {
                match fs::remove_file(&target) {
                    Ok(()) => { if let Some(parent) = target.parent() { sync_dir(parent)?; } },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(format!("remove newly installed file {}: {e}", e.path)),
                }
            }
        }
    }
    let current = pointer(root)?;
    write_slot(root, "active", current.generation + 1,
        &Pointer { schema: SCHEMA, generation: current.generation + 1, active: j.previous.clone() })?;
    Ok(())
}
fn recover_locked(root: &Path, key: &str) -> Result<(), String> {
    let Some(mut j) = journal(root)? else { return Ok(()); };
    if j.state == "complete" {
        if let Some(active) = pointer(root)?.active {
            validate_release(&active,key)?;
            if verify_installed(root,&active)? { release_generations::accept(root,&active.manifest)?; crate::trust_policy::accept(root,&active.manifest,key)?; }
        }
        return Ok(());
    }
    verify_journal(root, &j, key)?;
    let current = pointer(root)?;
    let published = current.active.as_ref().is_some_and(|p| p.id == j.next.id);
    let roll_forward = j.state != "reverting" && published && verify_installed(root, &j.next)?;
    if !roll_forward { restore(root, &j)?; }
    j.state = "complete".into();
    j.generation += 1;
    if roll_forward { write_slot(root, "last-known-good", j.generation, &j)?; }
    write_slot(root, "switch", j.generation, &j)?;
    if let Some(active) = pointer(root)?.active {
        validate_release(&active,key)?;
            if verify_installed(root,&active)? { release_generations::accept(root,&active.manifest)?; crate::trust_policy::accept(root,&active.manifest,key)?; }
    }
    Ok(())
}
/// Called before ANY launch/plan and before staging another release. If a switch
/// was interrupted, restore the complete old set before permitting game launch.
pub async fn recover(root: &Path, key: &str) -> Result<(), String> {
    let root = root.to_path_buf(); let key = key.to_owned();
    tokio::task::spawn_blocking(move || {
        let _guard = lock(&root)?;
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        recover_locked(&root, &key)
    }).await.map_err(|e| e.to_string())?
}
/// Reject launch with an unrelated (even validly signed) manifest when an active
/// release is registered. The caller still performs its full file integrity check.
pub async fn acquire_launch_lease(manifest: &Manifest, root: &Path, key: &str) -> Result<std::sync::Arc<fs::File>, String> {
    verify_manifest_signature(manifest, key)?;
    let root = root.to_path_buf(); let key = key.to_owned(); let signed = manifest.clone();
    tokio::task::spawn_blocking(move || {
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        safe_dir(&root, &base(&root))?;
        let path = base(&root).join("release.lock");
        file_ownership::ensure_no_symlinks(&root, &path)?;
        let file = fs::OpenOptions::new().read(true).write(true).create(true).open(&path).map_err(|e| e.to_string())?;
        // Recover first if there is no running game. If a different game holds
        // a shared lease, the journal must already be complete.
        match file.try_lock_exclusive() {
            Ok(()) => {
                let recovered = recover_locked(&root, &key);
                let _ = FileExt::unlock(&file);
                recovered?;
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(format!("release launch lock: {e}")),
        }
        file.lock_shared().map_err(|e| format!("shared release launch lock: {e}"))?;
        if journal(&root)?.is_some_and(|j| j.state != "complete") {
            return Err("incomplete release transaction: recovery required before launch".into());
        }
        release_generations::check(&root,&signed)?;
        crate::trust_policy::check_launch(&root,&signed,&key)?;
        if let Some(active) = pointer(&root)?.active {
            validate_release(&active, &key)?;
            let new_sig = signed.signature.as_ref().map(|s| (&s.signature, &s.public_key));
            let current_sig = active.manifest.signature.as_ref().map(|s| (&s.signature, &s.public_key));
            if new_sig != current_sig { return Err("launch blocked: requested manifest is not the active client release".into()); }
        }
        Ok(std::sync::Arc::new(file))
    }).await.map_err(|e| e.to_string())?
}

// Compare the requested selection with the active verified release before launch.
// Changing the UI dropdown alone must never silently launch the older preset.
pub async fn ensure_active_preset(manifest:&Manifest,root:&Path,key:&str,preset:Option<&str>)->Result<(),String>{
    verify_manifest_signature(manifest,key)?;
    let wanted=crate::component_catalog_0241::active_files(manifest,preset)?;
    let active=pointer(root)?.active.ok_or("client release is not installed")?;
    validate_release(&active,key)?;
    if active.manifest.signature.as_ref().map(|s|&s.signature)!=manifest.signature.as_ref().map(|s|&s.signature){return Err("active client release does not match signed manifest".into())}
    let actual=crate::component_catalog_0241::active_files(manifest,active.preset.as_deref())?;
    if wanted!=actual {return Err("selected component preset is not installed: install selected preset first".into())}
    // Two selections can contain the same files but different signed launch
    // actions. Never accept a UI-only preset change as an installed selection.
    if manifest.component_catalog.as_ref().is_some_and(|c|c.schema_version=="5.0") {
        let requested=preset.filter(|s|!s.is_empty()).unwrap_or_default();
        let installed=active.preset.as_deref().filter(|s|!s.is_empty()).unwrap_or_default();
        if requested!=installed {
            return Err("selected preset actions differ from installed release: install selected preset first".into())
        }
    }
    Ok(())
}
// v5 actions cannot be applied against a merely downloaded but uncommitted
// manifest. An identical signed active release is required even for default presets.
pub fn require_installed_preset_0245(manifest:&Manifest,root:&Path)->Result<Option<String>,String>{
    let active=pointer(root)?.active.ok_or("signed component actions require installed active release")?;
    let expected=manifest.signature.as_ref().map(|s|(&s.signature,&s.public_key));
    let actual=active.manifest.signature.as_ref().map(|s|(&s.signature,&s.public_key));
    if expected!=actual{return Err("signed component actions do not match installed release".into())}
    Ok(active.preset)
}

// Used for the exact installed selection when verifying files before launch.
pub fn active_preset_for_manifest(manifest:&Manifest,root:&Path)->Option<String>{
    let active=pointer(root).ok()?.active?;
    if active.manifest.signature.as_ref().map(|s|&s.signature)==manifest.signature.as_ref().map(|s|&s.signature){active.preset}else{None}
}

pub async fn ready_for_launch(manifest: &Manifest, root: &Path, key: &str) -> Result<(), String> {
    let _lease = acquire_launch_lease(manifest, root, key).await?;
    Ok(())
}

fn commit(root: &Path, next: Release, key: &str, stage: &Path) -> Result<(), String> {
    let _guard = lock(root)?;
    recover_locked(root, key)?;
    validate_release(&next, key)?;
    release_generations::check(root,&next.manifest)?;
    crate::trust_policy::check(root,&next.manifest,key)?;
    if !verify_installed(stage, &next)? { return Err("staged client files failed pre-commit verification".into()); }
    // Persistence barrier for all verified staged bytes and their directory
    // entries. The journal may be published only after these bytes are durable.
    let mut parents = BTreeSet::new();
    for path in &next.installed {
        let file_path = safe_join(stage, path)?;
        fs::File::open(&file_path).and_then(|f| f.sync_all())
            .map_err(|e| format!("persist staged file {path}: {e}"))?;
        if let Some(parent) = file_path.parent() { parents.insert(parent.to_path_buf()); }
    }
    for parent in parents { sync_dir(&parent)?; }
    let current = pointer(root)?;
    if let Some(ref old) = current.active {
        validate_release(old, key)?;
        // Cross-check the active signed release in addition to the durable
        // watermark: losing one local journal file must never enable a replay.
        if next.manifest.game_release_generation < old.manifest.game_release_generation ||
           (next.manifest.game_release_generation == old.manifest.game_release_generation &&
            next.manifest.signature.as_ref().map(|s| &s.signature) != old.manifest.signature.as_ref().map(|s| &s.signature)) {
            return Err("signed gameReleaseGeneration cannot replace the active release with older/different content".into());
        }
        if !verify_installed(root, old)? && old.manifest.signature.as_ref().map(|s| &s.signature) != next.manifest.signature.as_ref().map(|s| &s.signature) {
            return Err("active release is damaged; recover last-known-good before upgrading to a different release".into());
        }
        if old.manifest.project_id != next.manifest.project_id || old.manifest.profile_id != next.manifest.profile_id {
            return Err("active release belongs to another project/profile".into());
        }
    }
    let previous = current.active;
    let mut all = BTreeSet::new();
    if let Some(ref old) = previous { all.extend(old.installed.iter().cloned()); }
    all.extend(next.installed.iter().cloned());
    let new_paths: BTreeSet<_> = next.installed.iter().map(String::as_str).collect();
    let backup_id = format!("{:032x}", rand::random::<u128>());
    let back = backup_dir(root, &backup_id);
    safe_dir(root, &back)?;
    // Reserve the current bytes plus one potential restore temp per file.
    // If disk capacity is already insufficient, NO live file has changed.
    let mut rollback_bytes = 0u64;
    let all_paths: Vec<_> = all.iter().map(|p| safe_join(root, p)).collect::<Result<_, _>>()?;
    platform_fs::preflight_targets(root, &all_paths)?;
    for p in &all {
        let live = safe_join(root, p)?;
        match fs::symlink_metadata(&live) {
            Ok(meta) => {
                rollback_bytes = platform_fs::checked_add(rollback_bytes, meta.len())?;
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("preflight managed file {p}: {e}")),
        }
    }
    platform_fs::require_free_space(root, rollback_bytes.saturating_mul(2))?;
    let mut entries = Vec::new();
    for p in all {
        let live = safe_join(root, &p)?;
        platform_fs::check_target(root, &live)?;
        // A newly referenced path was not previously managed. A player-owned
        // file at that path must not be silently replaced by the new release.
        let was_managed = previous.as_ref().is_some_and(|old| old.installed.contains(&p));
        if !was_managed && live.exists() {
            let same_as_new = expected(&next, &p).is_some_and(|(sha,len)| matches_digest(&live, sha, len));
            if !same_as_new { return Err(format!("untracked user file conflicts with new managed path: {p}")); }
        }
        let digest = match fs::symlink_metadata(&live) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                let destination = safe_join(&back, &p)?;
                file_ownership::ensure_no_symlinks(root, &destination)?;
                copy_durable(&live, &destination)?;
                let old_hash = hash(&live)?;
                if hash(&destination)? != old_hash { return Err(format!("backup verification failed: {p}")); }
                Some(old_hash)
            },
            Ok(_) => return Err(format!("managed target is not a regular file: {p}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        entries.push(Backup { path: p.clone(), old_sha256: digest,
            new_sha256: if new_paths.contains(p.as_str()) { expected(&next, &p).map(|(sha,_)| sha.to_owned()) } else { None } });
    }
    sync_dir(&back)?;
    if let Some(ref old) = previous {
        let repairing_same_release = old.manifest.signature.as_ref().map(|s| &s.signature) == next.manifest.signature.as_ref().map(|s| &s.signature);
        if !repairing_same_release && !verify_installed(root, old)? { return Err("previous active release changed during backup".into()); }
    }
    let prior_generation = journal(root)?.map_or(0, |j| j.generation);
    let mut j = Journal { schema: SCHEMA, generation: prior_generation + 1, state: "switching".into(),
        previous, next: next.clone(), backup_id, entries };
    verify_journal(root, &j, key)?;
    // Durable write-ahead barrier: no live bytes change before this succeeds.
    write_slot(root, "switch", j.generation, &j)?;
    let result = (|| -> Result<(), String> {
        for e in &j.entries {
            let target = safe_join(root, &e.path)?;
            if e.new_sha256.is_some() {
                let staged = safe_join(stage, &e.path)?;
                switch_file(root, &staged, &target)?;
            } else if target.exists() {
                platform_fs::check_target(root, &target)?;
                fs::remove_file(&target).map_err(|e| format!("remove registered retired file: {e}"))?;
                if let Some(parent) = target.parent() { sync_dir(parent)?; }
            }
        }
        if !verify_installed(root, &next)? { return Err("installed client set failed post-switch verification".into()); }
        let generation = pointer(root)?.generation + 1;
        write_slot(root, "active", generation, &Pointer { schema: SCHEMA, generation, active: Some(next.clone()) })?;
        // The journal, including backups and previous pointer, is the LKG
        // record. It survives a commit; explicit rollback can use it later.
        j.state = "complete".into(); j.generation += 1;
        write_slot(root, "last-known-good", j.generation, &j)?;
        write_slot(root, "switch", j.generation, &j)?;
        release_generations::accept(root,&next.manifest)?;
        crate::trust_policy::accept(root,&next.manifest,key)?;
        Ok(())
    })();
    if let Err(err) = result {
        // If recovery fails (disk full / file locked), leave journal and old
        // backups intact. The next launch retries before any execution.
        match recover_locked(root, key) {
            Ok(()) => Err(format!("client release switch failed and previous installation recovered: {err}")),
            Err(recovery) => Err(format!("client switch failed: {err}; recovery pending: {recovery}")),
        }
    } else { Ok(()) }
}

/// Stage all selected files (including offline cache hits), verify the entire
/// set, and commit only if every required staged file passed SHA-256.
pub async fn install(manifest: &Manifest, root: &Path, key: &str,
    sink: Option<ProgressSink>, operation_id: String, control: watch::Receiver<Directive>, preset:Option<String>) -> Result<DownloadResult, String> {
    verify_manifest_signature(manifest, key)?;
    file_ownership::validate_download_targets(manifest)?;
    let selected=crate::component_catalog_0241::active_files(manifest,preset.as_deref())?;
    recover(root, key).await?;
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    release_generations::check(&root,manifest)?;
    crate::trust_policy::check(&root,manifest,key)?;
    // Operation ID is generated by durable_downloads, but never use its raw
    // input as a filesystem path (durable journals may be user modified).
    let stage_id = hex::encode(Sha256::digest(operation_id.as_bytes()));
    let work = base(&root).join("work").join(&stage_id);
    let stage = work.join("files");
    safe_dir(&root, &stage)?;
    // Verify available capacity BEFORE starting a multi-GB staging operation.
    // Existing verified stage bytes do not need to be reserved twice; the
    // up to six active .part/cache copies may coexist during parallel delivery.
    let mut required_stage = 0u64;
    let mut largest_pending = Vec::new();
    for f in &manifest.files {
        if !selected.contains(&f.path) || !manifest_file_applies(f) || file_ownership::skip_download(manifest, f) { continue; }
        let path = safe_join(&stage, &f.path)?;
        file_ownership::ensure_no_symlinks(&root, &path)?;
        let live = safe_join(&root, &f.path)?;
        file_ownership::ensure_no_symlinks(&root, &live)?;
        if manifest.schema_version == "2.0" && file_ownership::effective_ownership(f) == "optional" &&
            !file_ownership::must_verify(manifest, &f.path) && !path.exists() && !live.exists() {
            continue;
        }
        if !matches_digest_async(&path, &f.sha256, f.size).await {
            required_stage = platform_fs::checked_add(required_stage, f.size)?;
            largest_pending.push(f.size);
        }
    }
    largest_pending.sort_unstable_by(|a,b| b.cmp(a));
    let mut inflight_space = 0u64;
    for size in largest_pending.into_iter().take(DownloadLimits::default().global) {
        inflight_space = platform_fs::checked_add(inflight_space, size)?;
    }
    platform_fs::require_free_space(&root, platform_fs::checked_add(required_stage, inflight_space)?)?;
    // Existing intact files are valid inputs for staging and need no HTTP.
    // Optional files already installed are copied too so the scheduler repairs
    // them; absent optional files remain optional, as in 0.23.4.
    for f in &manifest.files {
        crate::network_resilience::check(&control)?;
        if !selected.contains(&f.path) || !manifest_file_applies(f) || file_ownership::skip_download(manifest, f) { continue; }
        let target = safe_join(&root, &f.path)?;
        let staged = safe_join(&stage, &f.path)?;
        file_ownership::ensure_no_symlinks(&root, &target)?;
        file_ownership::ensure_no_symlinks(&root, &staged)?;
        if matches_digest_async(&target, &f.sha256, f.size).await && !matches_digest_async(&staged, &f.sha256, f.size).await {
            if let Some(parent) = staged.parent() { safe_dir(&root, parent)?; }
            tokio::fs::copy(&target, &staged).await.map_err(|e| format!("stage existing {}: {e}",f.path))?;
        } else if file_ownership::effective_ownership(f) == "optional" && target.exists() && !staged.exists() {
            if let Some(parent) = staged.parent() { safe_dir(&root, parent)?; }
            tokio::fs::copy(&target, &staged).await.map_err(|e| format!("stage optional {}: {e}",f.path))?;
        }
    }
    let result = download_scheduler::run_selected(manifest, &stage, DownloadLimits::default(), sink, operation_id, control.clone(), &selected).await?;
    if *control.borrow() != Directive::Running || result.failed != 0 { return Ok(result); }
    let mut installed = Vec::new();
    for f in &manifest.files {
        if !selected.contains(&f.path) || !manifest_file_applies(f) || file_ownership::skip_download(manifest, f) { continue; }
        let path = safe_join(&stage, &f.path)?;
        let optional_absent = manifest.schema_version == "2.0" && file_ownership::effective_ownership(f) == "optional" && !path.exists() && !file_ownership::must_verify(manifest, &f.path);
        if optional_absent { continue; }
        if !matches_digest_async(&path, &f.sha256, f.size).await { return Err(format!("staged client file failed SHA-256: {}", f.path)); }
        installed.push(f.path.clone());
    }
    if *control.borrow() != Directive::Running { return Ok(result); }
    let next = Release { manifest: manifest.clone(), installed, id: format!("{:032x}", rand::random::<u128>()), preset };
    let key = key.to_owned();
    let restore_root = root.clone(); let restore_key = key.clone();
    tokio::task::spawn_blocking(move || commit(&root, next, &key, &stage))
        .await.map_err(|e| e.to_string())??;
    // Do not leave a newly activated release behind if the user cancelled or
    // paused after the irreversible switch phase began. Switching itself must
    // run to completion, then use the same durable rollback procedure.
    if *control.borrow() != Directive::Running && manifest.game_release_generation == 0 {
        rollback(&restore_root, &restore_key).await?;
    }
    Ok(result)
}

/// Explicit rollback of the most recently committed release. It restores only
/// registered managed paths; non-managed player files are never enumerated.
pub async fn rollback(root: &Path, key: &str) -> Result<(), String> {
    let root = root.to_path_buf(); let key = key.to_owned();
    tokio::task::spawn_blocking(move || {
        let _guard = lock(&root)?;
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        recover_locked(&root, &key)?;
        let mut j = last_known_good(&root)?.ok_or("no last-known-good client release")?;
        verify_journal(&root, &j, &key)?;
        let active = pointer(&root)?.active.ok_or("no active release")?;
        if active.manifest.game_release_generation > 0 { return Err("game rollback requires a NEW signed gameReleaseGeneration; publish the old content as a new release".into()); }
        if active.id != j.next.id { return Err("last-known-good is not the previous active release".into()); }
        if !verify_installed(&root, &active)? { return Err("current release was modified; refusing to overwrite local changes".into()); }
        // Publish switching intent before the first restoration so a power
        // failure during explicit rollback is also recoverable.
        j.state = "reverting".into();
        j.generation = journal(&root)?.map_or(0, |current| current.generation) + 1;
        write_slot(&root, "switch", j.generation, &j)?;
        restore(&root, &j)?;
        j.state = "complete".into(); j.generation += 1;
        write_slot(&root, "switch", j.generation, &j)?;
        Ok(())
    }).await.map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_manifest;
    use serde_json::json;
    fn fixture(root: &Path, v: &str, files: &[(&str, &[u8])]) -> (Manifest, String) {
        let arr: Vec<_> = files.iter().map(|(path, bytes)| json!({"path":path,"size":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes)),
            "url":"http://127.0.0.1:9/never","required":true,"ownership":"managed"})).collect();
        let spec = json!({"projectId":"test","id":"default","name":"Default","description":"","loader":"vanilla","preset":"","isDefault":true});
        let profile_digest = hex::encode(Sha256::digest(b"test\0default\0Default\0\0vanilla\0\0true"));
        let mut m: Manifest = serde_json::from_value(json!({"schemaVersion":"2.0","projectId":"test","profileId":"default","channel":"stable",
            "version":v,"createdAt":"2026-10-19T00:00:00Z","minecraft":{"version":"1.20.4","loader":"vanilla"},
            "runtime":{"java":{"majorVersion":17,"distribution":"temurin"}},"files":arr,
            "profileSnapshot":{"schemaVersion":"2.0","revision":1,"digest":profile_digest,"spec":spec}})).unwrap();
        let key = sign_manifest(&mut m, &"1a".repeat(32), "2026-10-19T00:00:00Z").unwrap();
        fs::create_dir_all(root).unwrap();
        (m,key)
    }
    fn staged(root: &Path, manifest: &Manifest, bytes: &[(&str, &[u8])]) -> PathBuf {
        let dir = base(root).join("test-staging");
        fs::create_dir_all(&dir).unwrap();
        for (path, contents) in bytes {
            let dest = safe_join(&dir,path).unwrap();
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::write(dest, contents).unwrap();
        }
        assert_eq!(manifest.files.len(), bytes.len());
        dir
    }
    #[tokio::test]
    async fn switch_only_registered_paths_and_explicit_rollback_preserve_user_data() {
        let root = std::env::temp_dir().join(format!("nl-txn-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (m1,key) = fixture(&root,"1",&[("mods/a.jar",b"OLD"),("mods/retired.jar",b"RETIRED")]);
        let one = Release { manifest:m1.clone(), installed:m1.files.iter().map(|f|f.path.clone()).collect(), id:format!("{:032x}",1),preset:None };
        commit(&root,one,&key,&staged(&root,&m1,&[("mods/a.jar",b"OLD"),("mods/retired.jar",b"RETIRED")])).unwrap();
        fs::create_dir_all(root.join("saves/world")).unwrap();
        fs::write(root.join("saves/world/level.dat"),b"WORLD").unwrap();
        fs::write(root.join("mods/custom.jar"),b"PLAYER").unwrap();
        let (m2,_) = fixture(&root,"2",&[("mods/a.jar",b"NEW"),("mods/b.jar",b"ADDED")]);
        let next = Release { manifest:m2.clone(), installed:m2.files.iter().map(|f|f.path.clone()).collect(), id:format!("{:032x}",2),preset:None };
        commit(&root,next,&key,&staged(&root,&m2,&[("mods/a.jar",b"NEW"),("mods/b.jar",b"ADDED")])).unwrap();
        assert_eq!(fs::read(root.join("mods/a.jar")).unwrap(),b"NEW");
        assert!(!root.join("mods/retired.jar").exists());
        assert_eq!(fs::read(root.join("mods/custom.jar")).unwrap(),b"PLAYER");
        rollback(&root,&key).await.unwrap();
        assert_eq!(fs::read(root.join("mods/a.jar")).unwrap(),b"OLD");
        assert_eq!(fs::read(root.join("mods/retired.jar")).unwrap(),b"RETIRED");
        assert!(!root.join("mods/b.jar").exists());
        assert_eq!(fs::read(root.join("saves/world/level.dat")).unwrap(),b"WORLD");
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn interrupted_switch_restores_old_set_including_removed_paths() {
        let root = std::env::temp_dir().join(format!("nl-txn-crash-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (m,key) = fixture(&root,"1",&[("libraries/a.jar",b"OLD")]);
        let first = Release { manifest:m.clone(), installed:vec!["libraries/a.jar".into()], id:format!("{:032x}",1),preset:None };
        commit(&root,first,&key,&staged(&root,&m,&[("libraries/a.jar",b"OLD")])).unwrap();
        let (m2,_) = fixture(&root,"2",&[("libraries/a.jar",b"NEW")]);
        let next = Release { manifest:m2, installed:vec!["libraries/a.jar".into()], id:format!("{:032x}",2),preset:None };
        let old = pointer(&root).unwrap().active;
        let back_id = format!("{:032x}",3);
        let back = backup_dir(&root,&back_id);
        fs::create_dir_all(back.join("libraries")).unwrap();
        copy_durable(&root.join("libraries/a.jar"),&back.join("libraries/a.jar")).unwrap();
        let generation = journal(&root).unwrap().unwrap().generation + 1;
        let switching = Journal { schema:SCHEMA, generation, state:"switching".into(), previous:old, next, backup_id:back_id,
            entries:vec![Backup{path:"libraries/a.jar".into(),old_sha256:Some(hex::encode(Sha256::digest(b"OLD"))),
                new_sha256:Some(hex::encode(Sha256::digest(b"NEW")))}] };
        write_slot(&root,"switch",generation,&switching).unwrap();
        fs::write(root.join("libraries/a.jar"),b"NEW").unwrap();
        recover_locked(&root,&key).unwrap();
        assert_eq!(fs::read(root.join("libraries/a.jar")).unwrap(),b"OLD");
        assert_eq!(pointer(&root).unwrap().active.unwrap().manifest.version,"1");
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn failed_precommit_verification_does_not_touch_live_files() {
        let root = std::env::temp_dir().join(format!("nl-txn-bad-stage-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (m,key) = fixture(&root,"1",&[("libraries/a.jar",b"SIGNED")]);
        fs::create_dir_all(root.join("libraries")).unwrap();
        fs::write(root.join("libraries/a.jar"),b"ORIGINAL").unwrap();
        fs::write(root.join("options.txt"),b"PLAYER").unwrap();
        let next = Release { manifest:m.clone(), installed:vec!["libraries/a.jar".into()], id:format!("{:032x}",4),preset:None };
        let broken = staged(&root,&m,&[("libraries/a.jar",b"INJECTED")]);
        assert!(commit(&root,next,&key,&broken).is_err());
        assert_eq!(fs::read(root.join("libraries/a.jar")).unwrap(),b"ORIGINAL");
        assert_eq!(fs::read(root.join("options.txt")).unwrap(),b"PLAYER");
        assert!(pointer(&root).unwrap().active.is_none());
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn rollback_interrupted_after_partial_restore_resumes_reverting() {
        let root = std::env::temp_dir().join(format!("nl-txn-reverting-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (m,key) = fixture(&root,"1",&[("mods/a.jar",b"OLD")]);
        let old = Release { manifest:m.clone(), installed:vec!["mods/a.jar".into()], id:format!("{:032x}",5),preset:None };
        commit(&root,old,&key,&staged(&root,&m,&[("mods/a.jar",b"OLD")])).unwrap();
        let (m2,_) = fixture(&root,"2",&[("mods/a.jar",b"NEW")]);
        let new = Release { manifest:m2.clone(), installed:vec!["mods/a.jar".into()], id:format!("{:032x}",6),preset:None };
        commit(&root,new,&key,&staged(&root,&m2,&[("mods/a.jar",b"NEW")])).unwrap();
        let mut entry = journal(&root).unwrap().unwrap();
        entry.state = "reverting".into(); entry.generation += 1;
        write_slot(&root,"switch",entry.generation,&entry).unwrap();
        // Simulate crash before any old bytes are restored.
        recover_locked(&root,&key).unwrap();
        assert_eq!(fs::read(root.join("mods/a.jar")).unwrap(),b"OLD");
        assert_eq!(pointer(&root).unwrap().active.unwrap().manifest.version,"1");
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn backup_corruption_blocks_destructive_recovery() {
        let root = std::env::temp_dir().join(format!("nl-txn-corrupt-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (m,key) = fixture(&root,"1",&[("mods/a.jar",b"OLD")]);
        let old = Release { manifest:m.clone(), installed:vec!["mods/a.jar".into()], id:format!("{:032x}",7),preset:None };
        commit(&root,old,&key,&staged(&root,&m,&[("mods/a.jar",b"OLD")])).unwrap();
        let (m2,_) = fixture(&root,"2",&[("mods/a.jar",b"NEW")]);
        let new = Release { manifest:m2.clone(), installed:vec!["mods/a.jar".into()], id:format!("{:032x}",8),preset:None };
        commit(&root,new,&key,&staged(&root,&m2,&[("mods/a.jar",b"NEW")])).unwrap();
        let mut entry = journal(&root).unwrap().unwrap();
        fs::write(backup_dir(&root,&entry.backup_id).join("mods/a.jar"),b"TAMPERED").unwrap();
        entry.state = "reverting".into(); entry.generation += 1;
        write_slot(&root,"switch",entry.generation,&entry).unwrap();
        assert!(recover_locked(&root,&key).is_err());
        assert_eq!(fs::read(root.join("mods/a.jar")).unwrap(),b"NEW");
        assert_eq!(journal(&root).unwrap().unwrap().state,"reverting");
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn live_launch_lease_prevents_switching_files_while_game_is_running() {
        let root = std::env::temp_dir().join(format!("nl-txn-lease-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (m1,key) = fixture(&root,"1",&[("libraries/a.jar",b"OLD")]);
        let old = Release { manifest:m1.clone(), installed:vec!["libraries/a.jar".into()], id:format!("{:032x}",9),preset:None };
        commit(&root,old,&key,&staged(&root,&m1,&[("libraries/a.jar",b"OLD")])).unwrap();
        let lease = acquire_launch_lease(&m1,&root,&key).await.unwrap();
        let (m2,_) = fixture(&root,"2",&[("libraries/a.jar",b"NEW")]);
        let new = Release { manifest:m2.clone(), installed:vec!["libraries/a.jar".into()], id:format!("{:032x}",10),preset:None };
        let target = staged(&root,&m2,&[("libraries/a.jar",b"NEW")]);
        assert!(commit(&root,new.clone(),&key,&target).is_err());
        assert_eq!(fs::read(root.join("libraries/a.jar")).unwrap(),b"OLD");
        drop(lease);
        commit(&root,new,&key,&target).unwrap();
        assert_eq!(fs::read(root.join("libraries/a.jar")).unwrap(),b"NEW");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn untracked_custom_mod_is_not_overwritten_by_new_managed_path() {
        let root = std::env::temp_dir().join(format!("nl-user-conflict-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (manifest,key) = fixture(&root,"new",&[("mods/custom.jar",b"PUBLISHED")]);
        fs::create_dir_all(root.join("mods")).unwrap();
        fs::write(root.join("mods/custom.jar"),b"CUSTOM_PLAYER_DATA").unwrap();
        let next = Release { manifest: manifest.clone(), installed:vec!["mods/custom.jar".into()], id:format!("{:032x}",60),preset:None };
        let work = staged(&root,&manifest,&[("mods/custom.jar",b"PUBLISHED")]);
        let error = commit(&root,next,&key,&work).unwrap_err();
        assert!(error.contains("untracked user file"), "{error}");
        assert_eq!(fs::read(root.join("mods/custom.jar")).unwrap(),b"CUSTOM_PLAYER_DATA");
        assert!(pointer(&root).unwrap().active.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn readonly_existing_file_rejects_switch_without_journal_mutation() {
        let root = std::env::temp_dir().join(format!("nl-readonly-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (manifest,key) = fixture(&root,"base",&[("libraries/core.jar",b"OLD")]);
        let old = Release { manifest:manifest.clone(), installed:vec!["libraries/core.jar".into()], id:format!("{:032x}",61),preset:None };
        commit(&root,old,&key,&staged(&root,&manifest,&[("libraries/core.jar",b"OLD")])).unwrap();
        let (new_manifest,_) = fixture(&root,"new",&[("libraries/core.jar",b"NEXT")]);
        let next = Release { manifest:new_manifest.clone(), installed:vec!["libraries/core.jar".into()], id:format!("{:032x}",62),preset:None };
        let dest = root.join("libraries/core.jar");
        let mut permissions = fs::metadata(&dest).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&dest, permissions).unwrap();
        let before = journal(&root).unwrap().unwrap().generation;
        assert!(commit(&root,next,&key,&staged(&root,&new_manifest,&[("libraries/core.jar",b"NEXT")])).is_err());
        assert_eq!(journal(&root).unwrap().unwrap().generation, before);
        assert_eq!(fs::read(&dest).unwrap(),b"OLD");
        assert_eq!(pointer(&root).unwrap().active.unwrap().manifest.version,"base");
        let mut permissions = fs::metadata(&dest).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&dest, permissions).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn insufficient_disk_budget_fails_before_live_mutation() {
        let root = std::env::temp_dir().join(format!("nl-capacity-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (old_manifest,key) = fixture(&root,"base",&[("libraries/a.jar",b"OLD")]);
        let old = Release { manifest:old_manifest.clone(), installed:vec!["libraries/a.jar".into()], id:format!("{:032x}",65),preset:None };
        commit(&root,old,&key,&staged(&root,&old_manifest,&[("libraries/a.jar",b"OLD")])).unwrap();
        let old_generation = pointer(&root).unwrap().generation;
        let mut oversized = old_manifest.clone();
        oversized.version = "oversized".into();
        oversized.files[0].size = u64::MAX / 8;
        sign_manifest(&mut oversized, &"1a".repeat(32), "2026-10-19T00:00:00Z").unwrap();
        let (_tx,control) = watch::channel(Directive::Running);
        let err = install(&oversized,&root,&key,None,format!("budget-{:x}",rand::random::<u64>()),control,None).await.unwrap_err();
        assert!(err.contains("disk") || err.contains("overflow"), "{err}");
        assert_eq!(pointer(&root).unwrap().generation,old_generation);
        assert_eq!(fs::read(root.join("libraries/a.jar")).unwrap(),b"OLD");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_prevents_install_without_modifying_external_file() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("nl-symlink-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let external = std::env::temp_dir().join(format!("nl-symlink-external-{}-{:x}",std::process::id(),rand::random::<u64>()));
        fs::create_dir_all(root.join("mods")).unwrap();
        fs::write(&external,b"USER_SECRET").unwrap();
        symlink(&external,root.join("mods/core.jar")).unwrap();
        let (manifest,key) = fixture(&root,"new",&[("mods/core.jar",b"SIGNED")]);
        let next = Release { manifest:manifest.clone(), installed:vec!["mods/core.jar".into()], id:format!("{:032x}",63),preset:None };
        assert!(commit(&root,next,&key,&staged(&root,&manifest,&[("mods/core.jar",b"SIGNED")])).is_err());
        assert_eq!(fs::read(&external).unwrap(),b"USER_SECRET");
        assert!(fs::symlink_metadata(root.join("mods/core.jar")).unwrap().file_type().is_symlink());
        let _ = fs::remove_dir_all(root); let _ = fs::remove_file(external);
    }

    #[test]
    fn crash_after_first_file_of_two_recovers_complete_old_release() {
        let root = std::env::temp_dir().join(format!("nl-multi-crash-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (old_m,key) = fixture(&root,"old",&[("mods/a.jar",b"OLD_A"),("mods/b.jar",b"OLD_B")]);
        let old = Release { manifest:old_m.clone(), installed:vec!["mods/a.jar".into(),"mods/b.jar".into()], id:format!("{:032x}",71),preset:None };
        commit(&root,old,&key,&staged(&root,&old_m,&[("mods/a.jar",b"OLD_A"),("mods/b.jar",b"OLD_B")])).unwrap();
        let (new_m,_) = fixture(&root,"new",&[("mods/a.jar",b"NEW_A"),("mods/b.jar",b"NEW_B")]);
        let next = Release { manifest:new_m.clone(), installed:vec!["mods/a.jar".into(),"mods/b.jar".into()], id:format!("{:032x}",72),preset:None };
        let backup_id = format!("{:032x}",73);
        let back = backup_dir(&root,&backup_id);
        fs::create_dir_all(back.join("mods")).unwrap();
        let entries = ["mods/a.jar", "mods/b.jar"].iter().map(|p| {
            copy_durable(&root.join(p), &back.join(p)).unwrap();
            Backup { path: (*p).into(), old_sha256:Some(hash(&root.join(p)).unwrap()),
                new_sha256:Some(new_m.files.iter().find(|f|f.path == *p).unwrap().sha256.clone()) }
        }).collect();
        let generation = journal(&root).unwrap().unwrap().generation + 1;
        let j = Journal { schema:SCHEMA, generation, state:"switching".into(), previous:pointer(&root).unwrap().active,
            next, backup_id, entries };
        write_slot(&root,"switch",generation,&j).unwrap();
        fs::write(root.join("mods/a.jar"),b"NEW_A").unwrap();
        // A restart must block launching a mixed set and replay the journal.
        recover_locked(&root,&key).unwrap();
        assert_eq!(fs::read(root.join("mods/a.jar")).unwrap(),b"OLD_A");
        assert_eq!(fs::read(root.join("mods/b.jar")).unwrap(),b"OLD_B");
        assert_eq!(pointer(&root).unwrap().active.unwrap().manifest.version,"old");
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn real_http_download_is_staged_verified_then_published_by_installer() {
        use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
        let root = std::env::temp_dir().join(format!("nl-txn-http-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let payload = format!("REAL_VERIFIED_BYTES_0235_{:016x}", rand::random::<u64>()).into_bytes();
        let serving = payload.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/resource",listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8;4096];
            let _ = conn.read(&mut buf).await.unwrap();
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"release-one\"\r\nConnection: close\r\n\r\n", serving.len());
            conn.write_all(response.as_bytes()).await.unwrap();
            conn.write_all(&serving).await.unwrap();
            let _ = conn.shutdown().await;
        });
        let (mut manifest,key) = fixture(&root,"http",&[("libraries/downloaded.jar",payload.as_slice())]);
        manifest.files[0].url = url;
        sign_manifest(&mut manifest, &"1a".repeat(32), "2026-10-19T00:00:00Z").unwrap();
        let (_tx,control) = watch::channel(Directive::Running);
        let result = install(&manifest,&root,&key,None,format!("http-test-{:x}",rand::random::<u64>()),control,None).await.unwrap();
        assert_eq!(result.failed,0);
        assert_eq!(fs::read(root.join("libraries/downloaded.jar")).unwrap(),payload);
        assert_eq!(pointer(&root).unwrap().active.unwrap().manifest.version,"http");
        server.await.unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn signed_game_rollback_must_use_new_authorized_generation_02311() {
        let root = std::env::temp_dir().join(format!("nl-game-gen-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let (mut one,key)=fixture(&root,"old",&[("mods/main.jar",b"OLD")]);
        one.game_release_generation=10;
        sign_manifest(&mut one,&"1a".repeat(32),"2026-10-19T00:00:00Z").unwrap();
        let original_digest=hex::encode(Sha256::digest(serde_json::to_vec(&one).unwrap()));
        let first=Release{manifest:one.clone(),installed:vec!["mods/main.jar".into()],id:format!("{:032x}",100),preset:None };
        commit(&root,first,&key,&staged(&root,&one,&[("mods/main.jar",b"OLD")])).unwrap();
        let (mut two,_)=fixture(&root,"new",&[("mods/main.jar",b"NEW")]);
        two.game_release_generation=11;
        sign_manifest(&mut two,&"1a".repeat(32),"2026-10-19T00:00:00Z").unwrap();
        let second=Release{manifest:two.clone(),installed:vec!["mods/main.jar".into()],id:format!("{:032x}",101),preset:None };
        commit(&root,second,&key,&staged(&root,&two,&[("mods/main.jar",b"NEW")])).unwrap();
        assert!(rollback(&root,&key).await.is_err(),"unsigned local rollback must not downgrade a protected release");
        assert_eq!(fs::read(root.join("mods/main.jar")).unwrap(),b"NEW");
        let previous=Release{manifest:one.clone(),installed:vec!["mods/main.jar".into()],id:format!("{:032x}",102),preset:None };
        assert!(commit(&root,previous,&key,&staged(&root,&one,&[("mods/main.jar",b"OLD")])).is_err());
        let (mut authorized,_)=fixture(&root,"old-content-authorized-again",&[("mods/main.jar",b"OLD")]);
        authorized.game_release_generation=12;
        authorized.rollback_source=Some(crate::GameRollbackSource02311{
            version:"old".into(),manifest_sha256:original_digest,game_release_generation:10,
        });
        sign_manifest(&mut authorized,&"1a".repeat(32),"2026-10-19T00:00:00Z").unwrap();
        let approved=Release{manifest:authorized.clone(),installed:vec!["mods/main.jar".into()],id:format!("{:032x}",103),preset:None };
        commit(&root,approved,&key,&staged(&root,&authorized,&[("mods/main.jar",b"OLD")])).unwrap();
        assert_eq!(fs::read(root.join("mods/main.jar")).unwrap(),b"OLD");
        assert!(crate::release_generations::check(&root,&two).is_err());
        fs::remove_dir_all(root).unwrap();
    }

}
