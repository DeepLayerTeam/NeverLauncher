//! Game release anti-rollback: persistent high watermark for SIGNED publish
//! generations, deliberately separate from transaction pointer generations.
//! Only a strictly newer Ed25519-authorized release may restore older content.
use crate::{Manifest, file_ownership, platform_fs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::{Path, PathBuf}};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Watermark { schema: u32, generation: u64, manifest_digest: String }

fn dir(root: &Path) -> PathBuf { root.join(".launcher").join("client-releases") }
fn slot(root: &Path, index: usize) -> PathBuf { dir(root).join(format!("security-generation-{index}.json")) }
fn valid(item: &Watermark) -> bool {
    item.schema == 1 && item.generation > 0 && item.manifest_digest.len() == 64 &&
       item.manifest_digest.bytes().all(|c| c.is_ascii_hexdigit())
}
fn digest(m: &Manifest) -> Result<String,String> {
    let bytes = serde_json::to_vec(m).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
fn read(root: &Path) -> Result<Option<Watermark>, String> {
    let mut best: Option<Watermark> = None;
    let mut exists = false;
    for index in 0..2 {
        let path = slot(root,index);
        file_ownership::ensure_no_symlinks(root, &path)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                exists = true;
                if !meta.is_file() || meta.len() > 4096 {return Err("game generation slot is unsafe".into());}
                let raw=fs::read(&path).map_err(|e|e.to_string())?;
                let candidate=serde_json::from_slice::<Watermark>(&raw)
                    .map_err(|_|"game generation slot is corrupted".to_string())?;
                if !valid(&candidate) {return Err("invalid game generation slot".into());}
                if let Some(ref previous)=best {
                    if previous.generation==candidate.generation && previous.manifest_digest!=candidate.manifest_digest {
                        return Err("conflicting game generation records".into());
                    }
                }
                if best.as_ref().is_none_or(|b|candidate.generation>b.generation) {best=Some(candidate);}

            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.to_string()),
        }
    }
    if exists && best.is_none() { return Err("game anti-rollback records are damaged".into()); }
    Ok(best)
}

pub fn check(root: &Path, manifest: &Manifest) -> Result<(),String> {
    let floor = read(root)?;
    if let Some(ref record) = floor {
        if manifest.game_release_generation < record.generation {
            return Err(format!("game anti-rollback: signed generation {} is below installed generation {}",manifest.game_release_generation,record.generation));
        }
        if manifest.game_release_generation == record.generation && digest(manifest)? != record.manifest_digest {
            return Err("game anti-rollback: same generation signed for different content".into());
        }
    }
    Ok(())
}

/// Called under the same exclusive release.lock held by commit/recovery.
/// No high-watermark mutation is made until the *complete* new release is
/// active and verified. Failed stage/commit does not consume a generation.
pub fn accept(root: &Path, manifest: &Manifest) -> Result<(),String> {
    check(root,manifest)?;
    if manifest.game_release_generation == 0 {return Ok(());}
    let item=Watermark {schema:1,generation:manifest.game_release_generation,manifest_digest:digest(manifest)?};
    if read(root)?.as_ref().is_some_and(|r|r.generation==item.generation) {return Ok(());}
    fs::create_dir_all(dir(root)).map_err(|e|e.to_string())?;
    let target=slot(root,(item.generation%2) as usize);
    file_ownership::ensure_no_symlinks(root, &target)?;
    let temp=dir(root).join(format!("security-{:016x}.tmp",rand::random::<u64>()));
    let result=(|| -> Result<(),String> {
        let mut f=fs::OpenOptions::new().create_new(true).write(true).open(&temp).map_err(|e|e.to_string())?;
        f.write_all(&serde_json::to_vec(&item).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        f.sync_all().map_err(|e|e.to_string())?;
        drop(f);
        platform_fs::replace_file(root,&temp,&target)?;
        #[cfg(unix)] fs::File::open(dir(root)).and_then(|f|f.sync_all()).map_err(|e|e.to_string())?;
        Ok(())
    })();
    if result.is_err() {let _=fs::remove_file(&temp);}
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn older_signed_generation_fails_even_with_same_jar() {
        let root=std::env::temp_dir().join(format!("never-generation-{}",rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let mut m:Manifest=serde_json::from_value(serde_json::json!({"schemaVersion":"1.0","projectId":"p","profileId":"q","channel":"stable","version":"v1","createdAt":"now","minecraft":{"version":"1.20","loader":"vanilla"},"runtime":{"java":{"majorVersion":17,"distribution":"temurin"}},"files":[]})).unwrap();
        m.game_release_generation=5;
        accept(&root,&m).unwrap();
        let mut old=m.clone();old.game_release_generation=4;
        assert!(check(&root,&old).is_err());
        let mut equivocate=m.clone();equivocate.version="changed".into();
        assert!(check(&root,&equivocate).is_err());
        let mut next=m.clone();next.game_release_generation=6;next.version="v2".into();
        accept(&root,&next).unwrap();
        assert!(check(&root,&m).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
