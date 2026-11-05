//! Барьеры файловой системы для надёжных выпусков клиента. Не изменяйте активное дерево
//! до проверки целевых путей, объёма, подготовленных байтов и синхронизированных копий отката.
use crate::file_ownership;
use std::{collections::HashMap, ffi::OsString, fs, io, path::{Path, PathBuf}};

const SAFETY_RESERVE: u64 = 16 * 1024 * 1024;

/// Проверка намеренно консервативна: обновлению нужна резервная копия и достаточно
/// места для возврата старых байтов после частичного переключения, а не только объём
/// для новых скачанных файлов. Ошибки арифметики приводят к отказу.
fn check_capacity(available: u64, required: u64) -> Result<(), String> {
    let need = required.checked_add(SAFETY_RESERVE).ok_or("disk reservation overflow")?;
    if available < need {
        return Err(format!("insufficient free disk space for recoverable client update: need {need} bytes, available {available} bytes"));
    }
    Ok(())
}

pub(crate) fn require_free_space(root: &Path, bytes: u64) -> Result<(), String> {
    let available = fs2::available_space(root)
        .map_err(|e| format!("Не удалось запросить «free disk space {}:» {e}", root.display()))?;
    check_capacity(available, bytes)
}

pub(crate) fn checked_add(total: u64, additional: u64) -> Result<u64, String> {
    total.checked_add(additional).ok_or_else(|| "client release disk requirement overflow".into())
}

/// Не заменяйте незаметно каталог, точку соединения, файл только для чтения,
/// предоставленный игроком, или путь с другим регистром. ACL применяются ОС;
/// не повышайте права и не снимайте атрибут только для чтения автоматически.
pub(crate) fn check_target(root: &Path, target: &Path) -> Result<(), String> {
    file_ownership::ensure_no_symlinks(root, target)?;
    if !target.starts_with(root) { return Err("target outside client root".into()); }
    let mut parent = target.parent();
    while let Some(dir) = parent {
        if !dir.starts_with(root) { break; }
        match fs::symlink_metadata(dir) {
            // Windows игнорирует атрибут READONLY каталога при разрешении записи
            // (Проводник выставляет его и обычным каталогам).
            // Нарушения ACL выявляются фактическими файловыми операциями ОС.
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

/// Сканируйте каждый родительский каталог один раз, а не O(файлы × соседи),
/// для больших каталогов ресурсов Minecraft. Это выявляет расхождения регистра
/// на диске до публикации журнала, в том числе на CI с чувствительной ФС.
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

/// В Windows ReplaceFileW сохраняет заменяемый файл, если запущенная игра или
/// антивирус запрещает FILE_SHARE_DELETE. В отличие от двух переименований,
/// нет промежутка с отсутствующим исполняемым файлом. В Unix rename() выполняет
/// атомарную замену в одном томе. Подготовка ведётся на томе установки.
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
            // Безопасность: оба пути — корректные завершённые строки UTF-16, существующие
            // весь синхронный вызов. Null исключает резервное и зарезервированное имена.
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
        // После успешного ReplaceFileW сбросьте содержимое и метаданные файла на диск.
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
        // Windows может не удалить файл только для чтения даже от имени владельца.
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
        // Общий доступ запрещён, включая FILE_SHARE_DELETE.
        let lock = fs::OpenOptions::new().read(true).share_mode(0).open(&dest).unwrap();
        assert!(replace_file(&root, &next, &dest).is_err());
        drop(lock);
        assert_eq!(fs::read(&dest).unwrap(), b"KNOWN_GOOD");
        replace_file(&root, &next, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"NEXT");
        fs::remove_dir_all(root).unwrap();
    }
}
