//! Portable component preferences and release-to-release migration.
//! Preferences are UNTRUSTED: they never contain paths/actions and can only
//! select component IDs from a pinned, signature-verified target manifest.
use crate::{component_catalog_0241::{self, ComponentCatalog}, Manifest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

const MAX_SELECTION_BYTES: usize = 1024 * 1024;
const MAX_CHOICE_BYTES: usize = 8192;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableSelection02410 {
    pub schema_version: String,
    pub project_id: String,
    pub profile_id: String,
    pub channel: String,
    pub source_version: String,
    pub source_catalog_digest: String,
    pub source_preset: String,
    pub selected_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionMigration02410 {
    pub choice: Option<String>,
    pub source_version: String,
    pub target_version: String,
    pub preserved_ids: Vec<String>,
    pub removed_ids: Vec<String>,
    pub added_ids: Vec<String>,
    pub preset_changed: bool,
    pub blockers: Vec<String>,
}

fn valid_id(value:&str)->bool {
    !value.is_empty() && value.len()<=128 && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
}
fn checked_id(value:&str)->bool{
    valid_id(value) && !value.contains("..") && value.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||matches!(b,b'.'|b'_'|b'-'))
}
fn sorted_ids(values:Vec<String>)->Result<Vec<String>,String>{
    if values.len()>4096 {return Err("too many component IDs in selection".into())}
    let mut unique=BTreeSet::new();
    for id in values {if !checked_id(&id)||!unique.insert(id.clone()){return Err(format!("invalid or duplicate component ID: {id}"))}}
    Ok(unique.into_iter().collect())
}

pub fn export_from_installed_02410(manifest:&Manifest,preset:Option<&str>)->Result<String,String>{
    let cat=manifest.component_catalog.as_ref().ok_or("signed component catalog required for export")?;
    let preview=component_catalog_0241::preview_components_0244(manifest,preset)?;
    let selected_ids=sorted_ids(preview.selected)?;
    let portable=PortableSelection02410{
        schema_version:"1.0".into(),project_id:manifest.project_id.clone(),
        profile_id:manifest.profile_id.clone(),channel:manifest.channel.clone(),
        source_version:manifest.version.clone(),source_catalog_digest:cat.digest.clone(),
        source_preset:preset.unwrap_or_default().to_owned(),selected_ids,
    };
    let exported=serde_json::to_string_pretty(&portable).map_err(|e|e.to_string())?;
    if exported.len()>MAX_SELECTION_BYTES {return Err("exported selection exceeds 1 MiB".into())}
    Ok(exported)
}

pub fn parse_import_02410(data:&str)->Result<PortableSelection02410,String>{
    if data.len()>MAX_SELECTION_BYTES || data.is_empty(){return Err("selection JSON exceeds size limit or is empty".into())}
    let mut portable:PortableSelection02410=serde_json::from_str(data).map_err(|e|format!("invalid selection JSON: {e}"))?;
    if portable.schema_version!="1.0" {return Err("unsupported selection format".into())}
    for s in [&portable.project_id,&portable.profile_id,&portable.channel] {
        if s.is_empty()||s.len()>128||s.bytes().any(|b|b<32||b==127){return Err("invalid selection profile identity".into())}
    }
    if portable.source_version.len()>128||portable.source_catalog_digest.len()!=64||
       !portable.source_catalog_digest.bytes().all(|b|b.is_ascii_hexdigit())||
       portable.source_preset.len()>MAX_CHOICE_BYTES || portable.source_preset.bytes().any(|b|b<32||b==127) {
        return Err("invalid selection provenance".into());
    }
    portable.selected_ids=sorted_ids(portable.selected_ids)?;
    Ok(portable)
}

pub fn migrate_02410(source:&PortableSelection02410,target:&Manifest)->Result<SelectionMigration02410,String>{
    if source.schema_version!="1.0" {return Err("invalid portable selection".into())}
    let canonical=sorted_ids(source.selected_ids.clone())?;
    if (source.project_id.as_str(),source.profile_id.as_str(),source.channel.as_str()) !=
       (target.project_id.as_str(),target.profile_id.as_str(),target.channel.as_str()){
        return Err("selection belongs to a different project/profile/channel".into())
    }
    // The Tauri boundary MUST verify target Ed25519 against the pinned key.
    component_catalog_0241::validate(target)?;
    let cat: &ComponentCatalog=target.component_catalog.as_ref().ok_or("target release has no signed catalog")?;
    if cat.schema_version=="1.0" {return Err("target catalog v1 does not support selection migration".into())}
    let existing:HashMap<&str,_>=cat.components.iter().map(|c|(c.id.as_str(),c)).collect();
    let selected:BTreeSet<&str>=canonical.iter().map(String::as_str).collect();
    let preserved_ids:Vec<_>=canonical.iter().filter(|id|existing.contains_key(id.as_str())).cloned().collect();
    let removed_ids:Vec<_>=canonical.iter().filter(|id|!existing.contains_key(id.as_str())).cloned().collect();
    // Preserve a named preset if it still exists. Otherwise use default as a
    // base and reconcile explicit IDs with overrides.
    let old_base=source.source_preset.strip_prefix("@custom:v1:")
        .and_then(|s|s.split_once(':').map(|x|x.0)).unwrap_or(source.source_preset.as_str());
    let base=if !old_base.is_empty()&&cat.presets.iter().any(|p|p.id==old_base){old_base}else{""};
    let mut needed:BTreeSet<String>=preserved_ids.iter().cloned().collect();
    let mut pending:Vec<String>=preserved_ids.clone();
    let mut dependency_ids=BTreeSet::new();
    for c in &cat.components{if c.required && needed.insert(c.id.clone()){pending.push(c.id.clone())}}
    // New dependencies of retained IDs cannot be explicitly disabled, even
    // when not present in the older signed release.
    while let Some(id)=pending.pop(){
        if let Some(c)=existing.get(id.as_str()){
            for dep in &c.dependencies {
                dependency_ids.insert(dep.id.clone());
                if needed.insert(dep.id.clone()){pending.push(dep.id.clone())}
            }
        }
    }
    let default_ids:BTreeSet<&str>=if !base.is_empty(){
        cat.presets.iter().find(|p|p.id==base).into_iter().flat_map(|p|p.components.iter().map(String::as_str)).collect()
    }else if !cat.default_preset.is_empty(){
        cat.presets.iter().find(|p|p.id==cat.default_preset).into_iter().flat_map(|p|p.components.iter().map(String::as_str)).collect()
    }else{cat.components.iter().filter(|c|c.default).map(|c|c.id.as_str()).collect()};
    let mut changes=Vec::new();let mut blockers=Vec::new();
    for c in &cat.components{
        if c.required {continue}
        if needed.contains(&c.id){
            if !default_ids.contains(c.id.as_str()){
                if (c.visible==Some(false)||c.limited) && !dependency_ids.contains(&c.id) {
                    blockers.push(format!("component {} is now restricted and cannot be enabled manually",c.id));
                } else if c.visible!=Some(false) && !c.limited {changes.push(format!("+{}",c.id));}
            }
        }else if default_ids.contains(c.id.as_str()){
            changes.push(format!("-{}",c.id));
        }
    }
    changes.sort();
    let choice=if changes.is_empty(){base.to_owned()}
       else{format!("@custom:v1:{}:{}",base,changes.join(","))};
    if choice.len()>MAX_CHOICE_BYTES{blockers.push("migrated component choice exceeds 8192 bytes".into())}
    if blockers.is_empty(){
        if let Err(e)=component_catalog_0241::preview_components_0244(target,Some(&choice)) {
            blockers.push(format!("target signed resolver rejected migrated selection: {e}"));
        }
    }
    let added_ids=if blockers.is_empty(){
        let resolved=component_catalog_0241::preview_components_0244(target,Some(&choice))?;
        resolved.selected.into_iter().filter(|id|!selected.contains(id.as_str())).collect()
    }else{Vec::new()};
    Ok(SelectionMigration02410{
        choice:if blockers.is_empty(){Some(choice)}else{None},
        source_version:source.source_version.clone(),target_version:target.version.clone(),
        preserved_ids,removed_ids,added_ids,preset_changed:base!=old_base,blockers,
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn rejects_malformed_and_duplicate_portable_ids(){
        let mut p=PortableSelection02410{schema_version:"1.0".into(),project_id:"p".into(),profile_id:"c".into(),channel:"stable".into(),source_version:"1".into(),source_catalog_digest:"a".repeat(64),source_preset:"".into(),selected_ids:vec!["mod".into(),"mod".into()]};
        assert!(parse_import_02410(&serde_json::to_string(&p).unwrap()).is_err());
        p.selected_ids=vec!["../bad".into()];
        assert!(parse_import_02410(&serde_json::to_string(&p).unwrap()).is_err());
        p.selected_ids=vec!["a..b".into()];
        assert!(parse_import_02410(&serde_json::to_string(&p).unwrap()).is_err());
        p.selected_ids=vec!["ok".into()];
        assert!(parse_import_02410(&serde_json::to_string(&p).unwrap()).is_ok());
        assert!(parse_import_02410(&serde_json::to_string(&p).unwrap().replace("\"selectedIds\"", "\"extra\":true,\"selectedIds\"")).is_err());
    }
    #[test]fn migration_rejects_other_profile(){
        let m:Manifest=serde_json::from_str(include_str!("../tests/fixtures/catalog_actions_0245_go_signed.json")).unwrap();
        let p=PortableSelection02410{schema_version:"1.0".into(),project_id:"different".into(),profile_id:m.profile_id.clone(),channel:m.channel.clone(),source_version:"0.24.9".into(),source_catalog_digest:"a".repeat(64),source_preset:"".into(),selected_ids:vec![]};
        assert!(migrate_02410(&p,&m).unwrap_err().contains("different project"));
    }
}

#[cfg(test)]
mod signed_migration_tests {
    use super::*;
    use crate::{component_actions_0245, sign_manifest};

    fn fixture()->Manifest{
        let mut m:Manifest=serde_json::from_str(include_str!("../tests/fixtures/catalog_actions_0245_go_signed.json")).unwrap();
        let catalog=m.component_catalog.as_mut().unwrap();
        for c in &mut catalog.components {c.conditions=None;}
        catalog.digest=component_actions_0245::digest_v5(catalog);
        sign_manifest(&mut m,&"1a".repeat(32),"2026-10-20T00:00:00Z").unwrap();
        m
    }
    #[test]fn portable_export_and_import_resolve_same_signed_selection(){
        let m=fixture();
        let exported=export_from_installed_02410(&m,Some("optimized")).unwrap();
        let portable=parse_import_02410(&exported).unwrap();
        assert!(portable.selected_ids.contains(&"core".into()));
        assert!(portable.selected_ids.contains(&"performance.sodium".into()));
        let proposal=migrate_02410(&portable,&m).unwrap();
        assert!(proposal.blockers.is_empty(),"{:?}",proposal.blockers);
        let preview=component_catalog_0241::preview_components_0244(&m,proposal.choice.as_deref()).unwrap();
        assert_eq!(sorted_ids(preview.selected).unwrap(),portable.selected_ids);
    }
    #[test]fn renamed_preset_preserves_ids_and_reports_changes(){
        let m=fixture();
        let portable=parse_import_02410(&export_from_installed_02410(&m,Some("optimized")).unwrap()).unwrap();
        let mut next=m;
        next.version="1.1".into();
        let cat=next.component_catalog.as_mut().unwrap();
        cat.presets.retain(|p|p.id!="optimized");
        cat.default_preset="minimal".into();
        cat.digest=component_actions_0245::digest_v5(cat);
        sign_manifest(&mut next,&"1a".repeat(32),"2026-10-20T00:00:00Z").unwrap();
        let migrated=migrate_02410(&portable,&next).unwrap();
        assert!(migrated.preset_changed);
        assert!(migrated.blockers.is_empty(),"{:?}",migrated.blockers);
        assert!(migrated.choice.unwrap().contains("+performance.sodium"));
    }
    #[test]fn absent_component_is_reported_without_inventing_file_operations(){
        let m=fixture();
        let mut portable=parse_import_02410(&export_from_installed_02410(&m,Some("optimized")).unwrap()).unwrap();
        portable.selected_ids.push("deleted.oldmod".into());
        let report=migrate_02410(&portable,&m).unwrap();
        assert_eq!(report.removed_ids,vec!["deleted.oldmod"]);
        assert!(report.choice.is_some());
    }
    #[test]fn imported_identity_cannot_jump_across_profiles(){
        let m=fixture();
        let portable=parse_import_02410(&export_from_installed_02410(&m,None).unwrap()).unwrap();
        let mut next=m;
        next.profile_id="another-profile".into();
        assert!(migrate_02410(&portable,&next).unwrap_err().contains("different project"));
    }
}
