//! Filesystem barriers for durable client releases. Never mutate the active tree
//! before verifying targets, capacity, staged bytes and synced rollback copies.
use crate::file_ownership;
use std::{collections::HashMap, ffi::OsString, fs, io, path::{Path, PathBuf}};

const SAFETY_RESERVE: u64 = 16 * 1024 * 1024;

/// This is intentionally conservative: updates need both a backup and enough
/// space to restore old bytes after a partial switch, not merely room for the
/// new downloaded files. Arithmetic errors fail closed.
fn check_capacity(available: u64, required: u64) -> Result<(), String> {
    let need = required.checked_add(SAFETY_RESERVE).ok_or("disk reservation overflow")?;
    if available < need {
        return Err(format!("insufficient free disk space for recoverable client update: need {need} bytes, available {available} bytes"));
    }
    Ok(())
}

pub(crate) fn require_free_space(root: &Path, bytes: u64) -> Result<(), String> {
    let available = fs2::available_space(root)
        .map_err(|e| format!("cannot query free disk space {}: {e}", root.display()))?;
    check_capacity(available, bytes)
}

pub(crate) fn checked_add(total: u64, additional: u64) -> Result<u64, String> {
    total.checked_add(additional).ok_or_else(|| "client release disk requirement overflow".into())
}

/// Never silently replace a player-supplied directory, junction, read-only
/// file or a path with different casing. ACLs remain enforced by the OS; do not
/// automatically escalate privilege or clear read-only bits.
pub(crate) fn check_target(root: &Path, target: &Path) -> Result<(), String> {
    file_ownership::ensure_no_symlinks(root, target)?;
    if !target.starts_with(root) { return Err("target outside client root".into()); }
    let mut parent = target.parent();
    while let Some(dir) = parent {
        if !dir.starts_with(root) { break; }
        match fs::symlink_metadata(dir) {
            // Windows ignores the READONLY directory attribute for write
            // authorization (and Explorer sets it on ordinary directories).
            // ACL access failures are enforced by the actual OS operations.
            Ok(meta) if cfg!(unix) && meta.permissions().readonly() => {
                return Err(format!("managed parent directory is read-only: {}", dir.display()));
            },
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("inspect managed parent directory {}: {e}", dir.display())),
        }
        if dir == root { break; }
        parent = dir.parent();
    }
    match fs::symlink_metadata(target) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() =>
            Err(format!("managed destination is not a regular file: {}", target.display())),
        Ok(meta) if meta.permissions().readonly() =>
            Err(format!("managed destination is read-only: {}", target.display())),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("inspect managed destination {}: {e}", target.display())),
    }
}

/// Batch-scan each parent directory once instead of O(files * siblings) for
/// large Minecraft assets trees. This detects on-disk casing differences
/// before the journal is published, including on case-sensitive CI hosts.
pub(crate) fn preflight_targets(root: &Path, targets: &[PathBuf]) -> Result<(), String> {
    let mut cache: HashMap<PathBuf, HashMap<String, OsString>> = HashMap::new();
    for target in targets {
        check_target(root, target)?;
        let mut cursor = root.to_path_buf();
        let relative = target.strip_prefix(root).map_err(|e| e.to_string())?;
        for part in relative.components() {
            let wanted = part.as_os_str();
            if cursor.is_dir() {
                if !cache.contains_key(&cursor) {
                    let mut entries = HashMap::new();
                    for entry in fs::read_dir(&cursor).map_err(|e| format!("inspect directory casing: {e}"))? {
                        let name = entry.map_err(|e| e.to_string())?.file_name();
                        let lowered = name.to_string_lossy().to_lowercase();
                        if entries.insert(lowered, name.clone()).is_some() {
                            return Err(format!("on-disk case collision in {}", cursor.display()));
                        }
                    }
                    cache.insert(cursor.clone(), entries);
                }
                if let Some(real) = cache[&cursor].get(&wanted.to_string_lossy().to_lowercase()) {
                    if real.as_os_str() != wanted {
                        return Err(format!("case-aliased on-disk path: {}", target.display()));
                    }
                }
            }
            cursor.push(wanted);
        }
    }
    Ok(())
}

fn sync_parent(dest: &Path) -> Result<(), String> {
    #[cfg(unix)] {
        if let Some(parent) = dest.parent() {
            fs::File::open(parent).and_then(|d| d.sync_all())
                .map_err(|e| format!("persist switched directory {}: {e}", parent.display()))?;
        }
    }
    #[cfg(not(unix))] { let _ = dest; }
    Ok(())
}

/// On Windows, ReplaceFileW preserves the replaced file if a running game or
/// antivirus denies FILE_SHARE_DELETE. Unlike rename-old + rename-new there
/// is no gap in which the live executable is missing. On Unix rename() is an
/// atomic same-volume replacement. Staging lives on the installation volume.
pub(crate) fn replace_file(root: &Path, source: &Path, destination: &Path) -> Result<(), String> {
    file_ownership::ensure_no_symlinks(root, source)?;
    check_target(root, destination)?;
    if !source.starts_with(root) { return Err("staged file outside client root".into()); }
    let meta = fs::symlink_metadata(source).map_err(|e| format!("inspect staged file: {e}"))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("staged object is not a regular file: {}", source.display()));
    }
    #[cfg(windows)] {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
        fn wide(path: &Path) -> Vec<u16> {
            path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
        }
        if destination.exists() {
            // Safety: both paths are valid terminated UTF-16 strings held for
            // the entire synchronous call. Null excludes backup and reserved.
            let ok = unsafe { ReplaceFileW(wide(destination).as_ptr(), wide(source).as_ptr(),
                std::ptr::null(), 0, std::ptr::null(), std::ptr::null()) };
            if ok == 0 {
                let err = io::Error::last_os_error();
                return Err(format!("Windows atomic ReplaceFile failed (file may be locked, sharing violation or ACL denied) {}: {err}", destination.display()));
            }
        } else {
            fs::rename(source, destination).map_err(|e| format!("install new managed file {}: {e}", destination.display()))?;
        }
    }
    #[cfg(not(windows))] {
        fs::rename(source, destination).map_err(|e| format!("atomically switch managed file {}: {e}", destination.display()))?;
    }
    #[cfg(windows)] {
        // Flush the winning file contents/metadata after ReplaceFileW succeeds.
        fs::File::open(destination).and_then(|f| f.sync_all())
            .map_err(|e| format!("persist Windows replaced file: {e}"))?;
    }
    sync_parent(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_reservation_rejects_insufficient_space_and_overflow() {
        assert!(check_capacity(SAFETY_RESERVE - 1, 0).is_err());
        assert!(check_capacity(SAFETY_RESERVE + 100, 101).is_err());
        assert!(check_capacity(SAFETY_RESERVE + 100, 100).is_ok());
        assert!(check_capacity(u64::MAX, u64::MAX).is_err());
        assert!(checked_add(u64::MAX, 1).is_err());
    }
    #[test]
    fn read_only_target_and_case_alias_block_before_switch() {
        let root = std::env::temp_dir().join(format!("nl-platform-{}-{:x}", std::process::id(), rand::random::<u64>()));
        fs::create_dir_all(root.join("Mods")).unwrap();
        fs::write(root.join("Mods/a.jar"), b"PLAYER").unwrap();
        assert!(preflight_targets(&root, &[root.join("mods/a.jar")]).is_err());
        let mut permissions = fs::metadata(root.join("Mods/a.jar")).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(root.join("Mods/a.jar"), permissions).unwrap();
        assert!(check_target(&root, &root.join("Mods/a.jar")).is_err());
        // Windows may be unable to delete a readonly file even as its owner.
        let mut permissions = fs::metadata(root.join("Mods/a.jar")).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(root.join("Mods/a.jar"), permissions).unwrap();
        #[cfg(unix)] {
            let mut dir_permissions = fs::metadata(root.join("Mods")).unwrap().permissions();
            dir_permissions.set_readonly(true);
            fs::set_permissions(root.join("Mods"), dir_permissions).unwrap();
            assert!(check_target(&root, &root.join("Mods/a.jar")).is_err());
            let mut dir_permissions = fs::metadata(root.join("Mods")).unwrap().permissions();
            dir_permissions.set_readonly(false);
            fs::set_permissions(root.join("Mods"), dir_permissions).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn sharing_violation_does_not_remove_existing_executable() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = std::env::temp_dir().join(format!("nl-locked-{}-{:x}", std::process::id(), rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let dest = root.join("runtime.exe");
        let next = root.join("staged.exe");
        fs::write(&dest, b"KNOWN_GOOD").unwrap();
        fs::write(&next, b"NEXT").unwrap();
        // No sharing permitted, including FILE_SHARE_DELETE.
        let lock = fs::OpenOptions::new().read(true).share_mode(0).open(&dest).unwrap();
        assert!(replace_file(&root, &next, &dest).is_err());
        drop(lock);
        assert_eq!(fs::read(&dest).unwrap(), b"KNOWN_GOOD");
        replace_file(&root, &next, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"NEXT");
        fs::remove_dir_all(root).unwrap();
    }
}
