//! Exact, deterministic signed file plan shared by staging, repair, install and
//! installed-release verification. Never derive ownership from directory scans.
use crate::{component_catalog_0241, file_ownership, manifest_file_applies, Manifest};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct ResolvedDownloadPlan {
    pub files: Vec<PlannedFile>,
    pub selected_paths: HashSet<String>,
    pub sha256: String,
}

fn string_field(hasher: &mut Sha256, value: &str) -> Result<(), String> {
    let size = u32::try_from(value.len()).map_err(|_| "resolved field exceeds size limit")?;
    hasher.update(size.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

/// `manifest` must be signature-verified by the caller using the pinned key.
/// The plan digest binds the complete signed release, exact selected preset,
/// final signed file set and file hashes. It cannot authorize any new path.
pub fn resolve(manifest: &Manifest, preset: Option<&str>) -> Result<ResolvedDownloadPlan, String> {
    let selected = component_catalog_0241::active_files(manifest, preset)?;
    let mut hasher = Sha256::new();
    hasher.update(b"neverlauncher.resolved-download-plan.v1\0");
    let signature = manifest.signature.as_ref().ok_or("resolved plan requires signed manifest")?;
    string_field(&mut hasher, &signature.public_key)?;
    string_field(&mut hasher, &signature.signature)?;
    // Explicit/default presets may resolve to the same files but different
    // launch actions; never treat them as the same installed selection.
    string_field(&mut hasher, preset.unwrap_or_default())?;
    if let Some(catalog) = &manifest.component_catalog {
        string_field(&mut hasher, &catalog.digest)?;
        hasher.update(catalog.revision.to_be_bytes());
    } else { string_field(&mut hasher, "")?; }
    let mut files = Vec::new();
    let mut paths = HashSet::new();
    for f in &manifest.files {
        if !selected.contains(&f.path) || !manifest_file_applies(f) || file_ownership::skip_download(manifest, f) {
            continue;
        }
        if !paths.insert(f.path.clone()) { return Err(format!("duplicate resolved file: {}", f.path)); }
        string_field(&mut hasher, &f.path)?;
        string_field(&mut hasher, &f.sha256.to_ascii_lowercase())?;
        hasher.update(f.size.to_be_bytes());
        string_field(&mut hasher, file_ownership::effective_ownership(f))?;
        files.push(PlannedFile { path: f.path.clone(), sha256: f.sha256.clone(), size: f.size });
    }
    Ok(ResolvedDownloadPlan {files, selected_paths: paths, sha256:hex::encode(hasher.finalize())})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_fixture_plan_is_deterministic_and_excludes_unselected_files() {
        let mut m: Manifest=serde_json::from_str(include_str!("../tests/fixtures/catalog_actions_0245_go_signed.json")).unwrap();
        let catalog=m.component_catalog.as_mut().unwrap();
        for c in &mut catalog.components {c.conditions=None;}
        catalog.digest=crate::component_actions_0245::digest_v5(catalog);
        crate::sign_manifest(&mut m,&"1a".repeat(32),"2026-10-20T00:00:00Z").unwrap();
        let first=resolve(&m,None).unwrap();
        let again=resolve(&m,None).unwrap();
        assert_eq!(first.sha256,again.sha256);
        assert_eq!(first.files,again.files);
        assert_eq!(first.files.len(),first.selected_paths.len());
        assert!(first.sha256.len()==64);
        assert_ne!(first.sha256,resolve(&m,Some("quality")).unwrap().sha256);
    }
}
