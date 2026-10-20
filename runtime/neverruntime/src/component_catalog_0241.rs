//! Signed, immutable component snapshot consumed by the native installer.
//! Every component file belongs to the manifest signature and is installed in
//! 0.24.1; player selection and dependency resolution are NOT accepted here.
use crate::{Manifest, file_ownership};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::collections::{HashMap,HashSet};

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ComponentCatalog {
    pub schema_version: String,
    pub revision: u64,
    pub digest: String,
    pub components: Vec<CatalogComponent>,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CatalogComponent {
    pub id: String,
    pub name: String,
    pub files: Vec<String>,
}

pub fn digest(components: &[CatalogComponent]) -> String {
    let mut h = Sha256::new();
    h.update(b"neverlauncher.component-catalog.v1\0");
    fn count(h: &mut Sha256,n:usize) {h.update((n as u32).to_be_bytes());}
    fn text(h: &mut Sha256,s:&str) {count(h,s.len());h.update(s.as_bytes());}
    count(&mut h,components.len());
    for c in components {text(&mut h,&c.id);text(&mut h,&c.name);count(&mut h,c.files.len());
        for path in &c.files {text(&mut h,path);}
    }
    hex::encode(h.finalize())
}
fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len()<=128 && !s.contains("..") &&
    s.bytes().next().is_some_and(|c|c.is_ascii_lowercase() || c.is_ascii_digit()) &&
    s.bytes().all(|c|c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c,b'-'|b'_'|b'.'))
}
pub fn validate(m: &Manifest) -> Result<(),String> {
    if m.schema_version!="3.0" {
        if m.component_catalog.is_some() {return Err("componentCatalog requires manifest v3".into());}
        return Ok(());
    }
    let cat=m.component_catalog.as_ref().ok_or("v3 requires signed componentCatalog")?;
    if cat.schema_version!="1.0" || cat.revision==0 || cat.components.len()>4096 ||
       cat.digest.len()!=64 || cat.digest!=digest(&cat.components) {
        return Err("invalid v3 component snapshot/digest".into());
    }
    let files:HashMap<_,_>=m.files.iter().map(|f|(f.path.to_ascii_lowercase(),f)).collect();
    let mut ids=HashSet::new();
    let mut owners=HashSet::new();
    for c in &cat.components {
        if !valid_id(&c.id) || !ids.insert(c.id.as_str()) || c.name.trim().is_empty() ||
           c.name.len()>256 || c.name.chars().any(|ch| matches!(ch, '\0'|'\r'|'\n')) || c.files.is_empty() || c.files.len()>8192 {
            return Err(format!("invalid/duplicate v3 component {}",c.id));
        }
        for path in &c.files {
            let key=path.to_ascii_lowercase();
            let f=files.get(&key).ok_or_else(||format!("undeclared component file: {path}"))?;
            if f.path!=*path || f.required || file_ownership::effective_ownership(f)!="optional" ||
               !owners.insert(key) {return Err(format!("invalid/duplicate component file: {path}"));}
        }
    }
    for f in &m.files {
        if file_ownership::effective_ownership(f)=="optional" && !owners.contains(&f.path.to_ascii_lowercase()) {
            return Err(format!("unowned v3 optional file: {}",f.path));
        }
    }
    Ok(())
}
