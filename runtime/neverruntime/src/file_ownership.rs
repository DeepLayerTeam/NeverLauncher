use crate::{Manifest, ManifestFile};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileRule {
    pub pattern: String,
    pub action: String,
    pub ownership: String,
}

pub fn effective_ownership(f: &ManifestFile) -> &str {
    if !f.ownership.is_empty() { &f.ownership } else if f.required { "required" } else { "optional" }
}
fn valid_ownership(s: &str) -> bool {
    matches!(s, "managed" | "required" | "optional" | "user-owned" | "generated")
}
/// Validate names for every supported operating system, regardless of which
/// platform signs the manifest. In particular Linux publishers must not sign
/// Windows device names, ADS paths or names differing only in casing.
fn valid_component(part: &str, pattern: bool) -> bool {
    if part.is_empty() || part == "." || part == ".." ||
        (part.ends_with(' ') || part.ends_with('.')) || part.starts_with(' ') ||
        part.chars().any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '\0')) {
        return false;
    }
    if !pattern && part.chars().any(|c| matches!(c, '*' | '?' | '[' | ']')) { return false; }
    if pattern && part.chars().any(|c| matches!(c, '?' | '[' | ']')) { return false; }
    // Windows treats CON.txt, NUL.jar, COM¹, etc. as devices as well.
    let stem = part.split('.').next().unwrap_or("").to_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return false;
    }
    if stem.starts_with("COM") || stem.starts_with("LPT") {
        let number = stem.chars().nth(3);
        if stem.chars().count() == 4 && matches!(number, Some('1'..='9' | '¹' | '²' | '³')) {
            return false;
        }
    }
    true
}
fn valid_path(p: &str, pattern: bool) -> bool {
    if p.is_empty() || p.starts_with('/') { return false; }
    if pattern {
        if p.contains('*') && (!p.ends_with("/**") || p.matches('*').count() != 2) { return false; }
    } else if p.contains('*') { return false; }
    let prefix = if pattern { p.strip_suffix("/**").unwrap_or(p) } else { p };
    prefix.split('/').all(|component| valid_component(component, false))
}
/// Refuse file-vs-directory collisions and aliases on case-insensitive hosts.
/// This is checked on *all* platforms so signed releases stay portable.
fn validate_name_collisions(paths: impl Iterator<Item = String>) -> Result<(), String> {
    let mut directories: HashMap<String, String> = HashMap::new();
    let mut files: HashSet<String> = HashSet::new();
    for p in paths {
        let parts: Vec<_> = p.split('/').collect();
        let mut normalized = Vec::with_capacity(parts.len());
        let mut original = Vec::with_capacity(parts.len());
        for (i, part) in parts.iter().enumerate() {
            normalized.push(part.to_lowercase());
            original.push(*part);
            let key = normalized.join("/");
            let real = original.join("/");
            if i + 1 < parts.len() {
                if files.contains(&key) { return Err(format!("file/directory collision: {p}")); }
                if let Some(existing) = directories.insert(key, real.clone()) {
                    if existing != real { return Err(format!("case-colliding directory: {p}")); }
                }
            } else {
                if !files.insert(key.clone()) || directories.contains_key(&key) {
                    return Err(format!("duplicate or file/directory collision: {p}"));
                }
            }
        }
    }
    Ok(())
}
fn matches(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix("/**") {
        Some(base) => path == base || path.strip_prefix(base).is_some_and(|rest| rest.starts_with('/')),
        None => path == pattern,
    }
}
fn overlap(a: &str, b: &str) -> bool {
    matches(a, b.strip_suffix("/**").unwrap_or(b)) || matches(b, a.strip_suffix("/**").unwrap_or(a))
}
pub fn protected(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    if matches!(lower.as_str(), "options.txt" | "optionsof.txt" | "servers.dat" | "usercache.json") { return true }
    ["saves", "screenshots", "resourcepacks", "shaderpacks", "config", "logs", "crash-reports", "diagnostics", ".launcher", ".launcher-quarantine"]
        .iter().any(|prefix| lower == *prefix || lower.starts_with(&format!("{prefix}/")))
}

pub fn validate_policy(m: &Manifest) -> Result<(), String> {
    if (m.schema_version != "2.0" && m.schema_version != "3.0") { return Ok(()); }
    validate_name_collisions(m.files.iter().map(|f| f.path.clone()))?;
    let mut seen = HashSet::new();
    for f in &m.files {
        if !valid_path(&f.path, false) || !seen.insert(f.path.to_ascii_lowercase()) { return Err(format!("duplicate/unsafe file path: {}", f.path)) }
        let ownership = effective_ownership(f);
        if !valid_ownership(ownership) { return Err(format!("unknown ownership: {ownership}")) }
        if matches!(ownership, "user-owned" | "generated") && f.required { return Err(format!("user-owned/generated file cannot be required: {}", f.path)) }
        if !f.ownership.is_empty() && ((ownership == "required" && !f.required) || (ownership == "optional" && f.required)) { return Err(format!("conflicting required/ownership: {}",f.path)) }
        if protected(&f.path) && !matches!(ownership, "user-owned" | "generated") { return Err(format!("user data is protected: {}", f.path)) }
    }
    for (i, r) in m.file_rules.iter().enumerate() {
        if !valid_path(&r.pattern, true) || !valid_ownership(&r.ownership) { return Err(format!("invalid file rule {i}")) }
        if !matches!(r.action.as_str(), "include" | "exclude" | "verify") { return Err(format!("unknown file rule action: {}", r.action)) }
        if (r.action == "include" && !matches!(r.ownership.as_str(), "managed" | "required")) ||
           (r.action == "verify" && matches!(r.ownership.as_str(), "user-owned" | "generated")) ||
           (r.action == "exclude" && !matches!(r.ownership.as_str(), "user-owned" | "generated")) { return Err(format!("invalid rule ownership: {}",r.pattern)) }
        if r.action == "include" && protected(r.pattern.strip_suffix("/**").unwrap_or(&r.pattern)) { return Err(format!("protected include rule: {}",r.pattern)) }
        if m.file_rules[..i].iter().any(|prev| overlap(&prev.pattern, &r.pattern)) { return Err(format!("overlapping rules: {}",r.pattern)) }
        for f in &m.files { if matches(&r.pattern,&f.path) {
            if (r.action == "exclude" && !matches!(effective_ownership(f), "user-owned" | "generated")) ||
               (r.action == "include" && matches!(effective_ownership(f), "user-owned" | "generated")) { return Err(format!("file rule conflicts with file: {}",f.path)) }
        } }
    }
    Ok(())
}

pub fn skip_verification(m: &Manifest, f: &ManifestFile) -> bool {
    if protected(&f.path) { return true }
    if m.schema_version == "1.0" { return false }
    matches!(effective_ownership(f), "user-owned" | "generated") ||
        m.file_rules.iter().any(|r| r.action == "exclude" && matches(&r.pattern, &f.path))
}
pub fn skip_download(m: &Manifest, f: &ManifestFile) -> bool {
    skip_verification(m,f)
}
pub fn must_verify(m: &Manifest, path: &str) -> bool {
    (m.schema_version == "2.0" || m.schema_version == "3.0") && m.file_rules.iter().any(|r| r.action == "verify" && matches(&r.pattern,path))
}
pub fn can_quarantine(m: &Manifest, path: &str) -> bool {
    if (m.schema_version != "2.0" && m.schema_version != "3.0") || protected(path) { return false }
    m.file_rules.iter().any(|r| r.action == "include" && matches!(r.ownership.as_str(), "managed" | "required") && matches(&r.pattern,path))
}

// Windows junctions, mount points and arbitrary reparse points can redirect IO
// without having Metadata::file_type().is_symlink() set.
fn is_link_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() { return true; }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 { return true; }
    }
    false
}

// Never read through symlinked parent directories or final targets. This also
// rejects an attacker-created symlink at the destination of an atomic rename.
pub fn ensure_no_symlinks(root: &Path, target: &Path) -> Result<(), String> {
    if !target.starts_with(root) { return Err("file outside of installation root".to_string()) }
    match std::fs::symlink_metadata(root) {
        Ok(meta) if is_link_or_reparse(&meta) => return Err("symlink/reparse installation root".into()),
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(format!("cannot inspect installation root: {e}")),
    }
    let relative = target.strip_prefix(root).map_err(|e| e.to_string())?;
    let mut cur = root.to_path_buf();
    for component in relative.components() {
        cur.push(component.as_os_str());
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if is_link_or_reparse(&meta) => return Err(format!("symlink/reparse point in managed path: {}",cur.display())),
            Ok(meta) if cur != target && !meta.is_dir() => return Err(format!("non-directory managed path parent: {}",cur.display())),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(format!("{}: {e}",cur.display())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patterns_and_defaults() {
        assert!(matches("mods/**","mods/a.jar"));
        assert!(!matches("mods/**","other/a.jar"));
        assert!(overlap("mods/**","mods/extra/**"));
        assert!(protected("Saves/World/level.dat"));
        assert!(!valid_path("../saves",false));
        assert!(!valid_path("mods/../saves",false));
    }
    #[test]
    fn windows_device_names_and_invalid_trailing_characters_rejected_everywhere() {
        for path in ["CON", "con.txt", "mods/NUL.jar", "mods/lpt9.dat", "mods/COM¹.dll",
            "mods/aux", "mods/a:stream", "mods/a.", "mods/a ", "mods/<bad>.jar", "mods/a\\b"] {
            assert!(!valid_path(path, false), "accepted: {path}");
        }
        for path in ["mods/a.jar", "libraries/com10.jar", "mods/compute.jar", "assets/ab/cd.bin"] {
            assert!(valid_path(path, false), "rejected: {path}");
        }
    }
    #[test]
    fn case_aliases_and_file_directory_collisions_are_rejected() {
        for names in [vec!["mods/A.jar", "MODS/a.jar"],
            vec!["mods", "mods/test.jar"],
            vec!["libraries/Foo/a.jar", "libraries/foo/b.jar"]] {
            assert!(validate_name_collisions(names.into_iter().map(str::to_owned)).is_err());
        }
        validate_name_collisions(["mods/a.jar", "mods/b.jar", "libraries/a.jar"].into_iter().map(str::to_owned)).unwrap();
    }
    #[test]
    fn existing_parent_must_be_directory_not_regular_file() {
        let root = std::env::temp_dir().join(format!("nl-parent-{}-{}",std::process::id(),rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("mods"),b"player").unwrap();
        assert!(ensure_no_symlinks(&root,&root.join("mods/client.jar")).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn ntfs_directory_junction_cannot_redirect_managed_files() {
        use std::process::Command;
        let root = std::env::temp_dir().join(format!("nl-junction-{}-{:x}",std::process::id(),rand::random::<u64>()));
        let external = std::env::temp_dir().join(format!("nl-junction-dest-{}-{:x}",std::process::id(),rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        let junction = root.join("mods");
        let output = Command::new("cmd").arg("/C").arg("mklink").arg("/J")
            .arg(&junction).arg(&external).output().unwrap();
        if output.status.success() {
            assert!(ensure_no_symlinks(&root,&junction.join("core.jar")).is_err());
            std::fs::remove_dir(&junction).unwrap();
        } else {
            eprintln!("NTFS junction creation unavailable; explicit Windows E2E required: {}",
                String::from_utf8_lossy(&output.stderr));
        }
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(external).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("nl-file-policy-{}",std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        symlink(std::env::temp_dir(),dir.join("mods")).unwrap();
        assert!(ensure_no_symlinks(&dir,&dir.join("mods/x.jar")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

// Verified by release signing and again before any network/filesystem mutation.
pub fn validate_download_targets(m: &Manifest) -> Result<(), String> {
    validate_name_collisions(m.files.iter().map(|f| f.path.clone()))?;
    for f in &m.files {
        if !valid_path(&f.path, false) { return Err(format!("unsafe managed file path: {}", f.path)); }
        if !matches!(effective_ownership(f), "required" | "managed" | "optional") { continue }
        let decoded = hex::decode(&f.sha256).map_err(|_| format!("invalid SHA-256: {}",f.path))?;
        if decoded.len() != 32 {return Err(format!("invalid SHA-256 length: {}",f.path))}
        let url = reqwest::Url::parse(&f.url).map_err(|e| format!("invalid download URL {}: {e}",f.path))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(format!("unsafe download URL: {}",f.path));
        }
    }
    Ok(())
}
