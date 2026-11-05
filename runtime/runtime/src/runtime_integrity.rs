//! Постройте исполняемую опись целостности JVM, закреплённую дайджестом, из уже проверенного
//! Ed25519 манифеста выпуска и независимо проверенной политики Guard. JSON клиента и
//! недоверенное обнаружение Runtime не разрешают никакие файлы.
use crate::{Manifest, LaunchPlan, guard_compatibility_0502::GamePolicy0503};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap,fs::{self,File},io::Read,path::{Component,Path}};

fn pin_file(root:&Path, path:&Path, expected:&str)->Result<(),String>{
    let relative=path.strip_prefix(root).map_err(|_|format!("Guard runtime executable outside installation: {}",path.display()))?;
    if !expected.len().eq(&64) || !expected.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err("Некорректный SHA-256 инвентаризации среды выполнения Guard".into());
    }
    let mut cursor=root.to_path_buf();
    for part in relative.components(){
        if let Component::Normal(segment)=part {cursor.push(segment);} else {return Err("Guard runtime inventory unsafe path".into());}
        if fs::symlink_metadata(&cursor).map_err(|e|e.to_string())?.file_type().is_symlink(){return Err("Символическая ссылка в инвентаризации среды выполнения Guard отклонена".into())}
    }
    let meta=fs::metadata(path).map_err(|e|e.to_string())?;
    if !meta.is_file() || meta.len()>512*1024*1024 {return Err("Guard runtime inventory invalid file".into())}
    let mut f=File::open(path).map_err(|e|e.to_string())?;
    let mut sha=Sha256::new();let mut buf=[0u8;65536];
    loop {let n=f.read(&mut buf).map_err(|e|e.to_string())?;if n==0{break}sha.update(&buf[..n]);}
    if hex::encode(sha.finalize())!=expected{return Err(format!("Изменился SHA-256 инвентаризации среды выполнения Guard: {}",path.display()))}
    Ok(())
}
fn native_file(path:&str)->bool {
    let s=path.to_ascii_lowercase();
    s.ends_with(".dll") || s.ends_with(".so") || s.contains(".so.") || s.ends_with(".dylib") || s.ends_with(".jnilib")
}
fn insert_pin(pins:&mut BTreeMap<String,(String,&'static str)>,root:&Path,path:&Path,hash:&str,kind:&'static str)->Result<(),String>{
    pin_file(root,path,hash)?;
    let key=path.to_string_lossy().to_string();
    if let Some(old)=pins.get(&key) {
        if old.0!=hash || old.1!=kind{return Err(format!("Guard runtime contradictory signed file identity: {key}"))}
    } else {pins.insert(key,(hash.to_owned(),kind));}
    if pins.len()>8192{return Err("Инвентаризация среды выполнения Guard превышает ограничение 8192 файлов".into())}
    Ok(())
}
/// Точные идентичности нативных библиотек для живого Windows Module Guard. Учитываются только
/// подписанные манифестом или отдельно разрешённые Ed25519 артефакты Guard.
pub fn signed_native_pins(manifest:&Manifest,root:&Path)->Result<Option<Vec<(std::path::PathBuf,String)>>,String>{
    let Some(policy)=crate::guard_compatibility_0502::verified_for_game(root,&manifest.project_id,
        &manifest.minecraft.version,&manifest.minecraft.loader)? else{return Ok(None)};
    let canonical=fs::canonicalize(root).map_err(|e|e.to_string())?;
    let root=canonical.as_path();
    let mut pins=BTreeMap::<String,(String,&'static str)>::new();
    let selected=crate::component_catalog_0241::active_files(manifest,
        crate::transactional_release::active_preset_for_manifest(manifest,root).as_deref())?;
    for file in &manifest.files {
        if !super::manifest_file_applies(file) ||
            !(file.required || (manifest.schema_version=="3.0" && selected.contains(file.path.as_str()))) ||
            !native_file(&file.path){continue}
        insert_pin(&mut pins,root,&root.join(&file.path),&file.sha256.to_ascii_lowercase(),"native")?;
    }
    for (path,digest,kind) in policy.runtime_artifacts(root)? {
        if kind=="native-library" {insert_pin(&mut pins,root,&path,&digest,"native")?;}
    }
    Ok(Some(pins.into_iter().map(|(path,(hash,_))|(std::path::PathBuf::from(path),hash)).collect()))
}

/// Вызывается только после verify_manifest_signature и проверки Ed25519 Guard. Охватывает
/// фактические classpath/modulepath, выбранные нативные файлы выпуска и каждый подписанный
/// исполняемый артефакт (моды, агенты, плагины, загрузчик, нативный код). Java premain повторно
/// хеширует их и отслеживает изменения после запуска JVM.
pub fn from_verified_launch(manifest:&Manifest,plan:&LaunchPlan,root:&Path,guard:&GamePolicy0503)->Result<String,String>{
    let canonical=fs::canonicalize(root).map_err(|e|e.to_string())?;
    let root=canonical.as_path();
    let mut pins=BTreeMap::<String,(String,&'static str)>::new();
    let selected=crate::component_catalog_0241::active_files(manifest,
        crate::transactional_release::active_preset_for_manifest(manifest,root).as_deref())?;
    for path in plan.classpath_entries.iter().chain(plan.modulepath_entries.iter()) {
        let absolute=fs::canonicalize(path).map_err(|e|format!("Отсутствует: путь классов среды выполнения Guard: {e}"))?;
        let rel=absolute.strip_prefix(root).map_err(|_|"Guard runtime classpath outside signed root")?;
        let name=rel.to_string_lossy().replace('\\',"/");
        let file=manifest.files.iter().find(|f|f.path.replace('\\',"/")==name && super::manifest_file_applies(f) &&
                (f.required || (manifest.schema_version=="3.0" && selected.contains(name.as_str()))))
            .ok_or_else(||format!("Guard runtime classpath not required in signed release: {name}"))?;
        if !name.to_ascii_lowercase().ends_with(".jar") {return Err("Guard runtime classpath entry is not a signed JAR".into())}
        insert_pin(&mut pins,root,&absolute,&file.sha256.to_ascii_lowercase(),"code")?;
    }
    for file in &manifest.files {
        if !super::manifest_file_applies(file) ||
            !(file.required || (manifest.schema_version=="3.0" && selected.contains(file.path.as_str()))) ||
            !native_file(&file.path){continue}
        let absolute=root.join(&file.path);
        insert_pin(&mut pins,root,&absolute,&file.sha256.to_ascii_lowercase(),"native")?;
    }
    for (path,digest,kind) in guard.runtime_artifacts(root)? {
        let tag=if kind=="native-library" {"native"} else {"code"};
        insert_pin(&mut pins,root,&path,&digest,tag)?;
    }
    if pins.is_empty(){return Err("Не найдено проверенных исполняемых файлов среды выполнения Guard".into())}
    let mut result=format!("integrity.required=true\nintegrity.code.strict=true\nintegrity.root={}\nintegrity.count={}\n",STANDARD.encode(root.to_string_lossy().as_bytes()),pins.len());
    #[cfg(target_os = "linux")]
    {
        result.push_str("integrity.linux.process.required=true\n");
        let external=guard.external_native_modules(root)?;
        result.push_str(&format!("integrity.external.count={}\n",external.len()));
        for (i,(path,hash)) in external.iter().enumerate(){
            result.push_str(&format!("integrity.external.{i}.path={}\nintegrity.external.{i}.sha256={hash}\n",
                STANDARD.encode(path.as_os_str().as_encoded_bytes())));
        }
    }
    for (index,(path,(digest,kind))) in pins.iter().enumerate(){
        result.push_str(&format!("integrity.{index}.path={}\nintegrity.{index}.sha256={digest}\nintegrity.{index}.kind={kind}\n",STANDARD.encode(path.as_bytes())));
    }
    Ok(result)
}

#[cfg(test)] mod tests {
 use super::*;
 #[test] fn pin_rejects_changed_and_symlink_files(){
  let root=std::env::temp_dir().join(format!("nl-0505-pin-{}",std::process::id()));
  let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).unwrap();
  let item=root.join("example.jar");fs::write(&item,b"original").unwrap();
  let hash=hex::encode(Sha256::digest(b"original"));
  assert!(pin_file(&root,&item,&hash).is_ok());
  fs::write(&item,b"modified").unwrap();
  assert!(pin_file(&root,&item,&hash).is_err());
  assert!(pin_file(&root,&item,&"0".repeat(64)).is_err());
  assert!(pin_file(&root,&root.join("../outside"),&hash).is_err());
  let _=fs::remove_dir_all(root);
 }
}
