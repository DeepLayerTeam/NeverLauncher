use crate::{Manifest, ManifestFile};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::collections::HashSet;

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
fn valid_path(p: &str, pattern: bool) -> bool {
    if p.is_empty() || p.starts_with('/') || p.chars().any(|c| matches!(c, '\\' | '\0' | '\r' | '\n' | ':')) { return false }
    if p.split('/').any(|v| v.is_empty() || v == "." || v == "..") { return false; }
    if pattern {
        if p.chars().any(|c| matches!(c, '?' | '[' | ']')) { return false; }
        if p.contains('*') && (!p.ends_with("/**") || p.matches('*').count() != 2) { return false; }
    } else if p.chars().any(|c| matches!(c, '*' | '?' | '[' | ']')) { return false; }
    true
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
    ["saves", "screenshots", "resourcepacks", "shaderpacks", "config", "logs", "crash-reports", "diagnostics", ".neverlauncher", ".neverlauncher-quarantine"]
        .iter().any(|prefix| lower == *prefix || lower.starts_with(&format!("{prefix}/")))
}

pub fn validate_policy(m: &Manifest) -> Result<(), String> {
    if m.schema_version != "2.0" { return Ok(()); }
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
    m.schema_version == "2.0" && m.file_rules.iter().any(|r| r.action == "verify" && matches(&r.pattern,path))
}
pub fn can_quarantine(m: &Manifest, path: &str) -> bool {
    if m.schema_version != "2.0" || protected(path) { return false }
    m.file_rules.iter().any(|r| r.action == "include" && matches!(r.ownership.as_str(), "managed" | "required") && matches(&r.pattern,path))
}

// Never read through symlinked parent directories or final targets. This also
// rejects an attacker-created symlink at the destination of an atomic rename.
pub fn ensure_no_symlinks(root: &Path, target: &Path) -> Result<(), String> {
    if !target.starts_with(root) { return Err("file outside of installation root".to_string()) }
    match std::fs::symlink_metadata(root) {
        Ok(meta) if meta.file_type().is_symlink() => return Err("symlink installation root".into()),
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(format!("cannot inspect installation root: {e}")),
    }
    let relative = target.strip_prefix(root).map_err(|e| e.to_string())?;
    let mut cur = root.to_path_buf();
    for component in relative.components() {
        cur.push(component.as_os_str());
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(format!("symlink in managed path: {}",cur.display())),
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
    if m.schema_version != "2.0" { return Ok(()) }
    for f in &m.files {
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
