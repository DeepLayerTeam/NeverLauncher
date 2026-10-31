//! Owner-signed, executable optional actions. No local JSON or process environment
//! is allowed to introduce launch flags, paths or classpath entries.
use crate::{Manifest,LaunchPlan,component_catalog_0241::{ComponentCatalog,CatalogComponent}};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use std::{collections::HashSet,path::Path};

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ComponentAction0245 {
    #[serde(rename="type")]
    pub kind:String,
    #[serde(default,skip_serializing_if="String::is_empty")]
    pub path:String,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub args:Vec<String>,
}
fn count(h:&mut Sha256,n:usize){h.update((n as u32).to_be_bytes())}
fn text(h:&mut Sha256,s:&str){count(h,s.len());h.update(s.as_bytes())}

pub fn digest_v5(cat:&ComponentCatalog)->String {
    let mut h=Sha256::new();h.update(b"launcher.component-catalog.v5\0");
    text(&mut h,&crate::component_catalog_0241::digest_v4(cat));
    count(&mut h,cat.components.len());
    for c in &cat.components {
        count(&mut h,c.actions.len());
        for a in &c.actions {
            text(&mut h,&a.kind);text(&mut h,&a.path);count(&mut h,a.args.len());
            for arg in &a.args{text(&mut h,arg)}
        }
    }
    hex::encode(h.finalize())
}

fn safe_argument(t:&str,arg:&str)->bool {
    if arg.is_empty()||arg.len()>256||arg.bytes().any(|b|b<33||b>126||b"@\\\"'`$;|&<>".contains(&b)){return false}
    if t=="JvmArgs" {
        if matches!(arg,"-ea"|"-da"|"-XX:+UseG1GC"){return true}
        if let Some(n)=arg.strip_prefix("-XX:MaxGCPauseMillis=") {
            return n.parse::<u32>().is_ok_and(|n|n>=1&&n<=10000)&&!n.starts_with('+');
        }
        let Some(prop)=arg.strip_prefix("-D") else {return false};
        let Some((key,value))=prop.split_once('=') else {return false};
        if value.is_empty()||value.len()>128||value.bytes().any(|b|matches!(b,b'/'|b':'|b'=')) {return false}
        if !["launcher.optional.","fabric.","forge.","neoforge.","mixin."].iter().any(|p|key.starts_with(p)){return false}
        return key.bytes().chain(value.bytes()).all(|b|b.is_ascii_alphanumeric()||matches!(b,b'.'|b'_'|b'-'));
    }
    if t=="ClientArgs" {
        for prefix in ["--optional-","--fabric-","--forge-","--neoforge-","--mixin-"] {
            if let Some(rest)=arg.strip_prefix(prefix) {
                return !rest.is_empty()&&rest.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||matches!(b,b'-'|b'_'|b'='|b'.'));
            }
        }
    }
    false
}

pub fn validate_actions(cat:&ComponentCatalog)->Result<(),String> {
    for c in &cat.components {
        if cat.schema_version!="5.0" {
            if !c.actions.is_empty(){return Err(format!("unsigned actions on pre-v5 component {}",c.id))}
            continue;
        }
        if c.actions.len()>64{return Err(format!("too many optional actions in {}",c.id))}
        let owned:HashSet<&str>=c.files.iter().map(String::as_str).collect();
        let mut seen=HashSet::new();
        for a in &c.actions {
            match a.kind.as_str(){
                "File"|"ClassPath"=>{
                    if !a.args.is_empty()||!owned.contains(a.path.as_str())||a.path.is_empty()||
                        a.path.starts_with('/')||a.path.bytes().any(|b|matches!(b,b'\\'|b':'|b'\0'|b'\r'|b'\n'))||
                        a.path.split('/').any(|x|x.is_empty()||x=="."||x=="..")||
                        (a.kind=="ClassPath"&&!a.path.to_ascii_lowercase().ends_with(".jar")) {
                        return Err(format!("{} {} references unsafe/unowned file {}",c.id,a.kind,a.path))
                    }
                    if !seen.insert(format!("{}:{}",a.kind,a.path.to_ascii_lowercase())){
                        return Err(format!("duplicate action on {}",c.id))
                    }
                },
                "JvmArgs"|"ClientArgs"=>{
                    if !a.path.is_empty()||a.args.is_empty()||a.args.len()>32{return Err(format!("invalid {} arguments in {}",a.kind,c.id))}
                    for arg in &a.args {
                        if !safe_argument(&a.kind,arg){return Err(format!("unsafe {} argument in {}: {}",a.kind,c.id,arg))}
                        if !seen.insert(format!("{}:{}",a.kind,arg)){return Err(format!("duplicate {} argument in {}",a.kind,c.id))}
                    }
                },
                _=>return Err(format!("unsupported optional action {} in {}",a.kind,c.id))
            }
        }
    }
    Ok(())
}

/// File actions select the exact signed file subset. In their absence,
/// preserve existing component file semantics. ClassPath always selects its JAR.
pub fn effective_files(c:&CatalogComponent)->Vec<String> {
    if !c.actions.iter().any(|a|a.kind=="File") {return c.files.clone()}
    let names:HashSet<&str>=c.actions.iter().filter(|a|matches!(a.kind.as_str(),"File"|"ClassPath")).map(|a|a.path.as_str()).collect();
    c.files.iter().filter(|path|names.contains(path.as_str())).cloned().collect()
}

/// This is invoked for the actual installed release after signature/preset checks.
/// It never reads actions from launch preferences, nor permits a new JVM entrypoint.
pub fn apply_installed_actions(manifest:&Manifest,root:&Path,plan:&mut LaunchPlan)->Result<(),String> {
    let Some(cat)=manifest.component_catalog.as_ref().filter(|cat|cat.schema_version=="5.0") else {return Ok(())};
    validate_actions(cat)?;
    let installed_preset=crate::transactional_release::require_installed_preset_0245(manifest,root)?;
    let active=crate::component_catalog_0241::active_files(manifest,installed_preset.as_deref())?;
    apply_selected_actions(cat,&active,root,plan)?;
    crate::validate_memory_arguments_0223(&manifest.runtime.memory,&plan.jvm_args)?;
    Ok(())
}

fn apply_selected_actions(cat:&ComponentCatalog,active:&HashSet<String>,root:&Path,plan:&mut LaunchPlan)->Result<(),String>{
    let mut seen_classpath:HashSet<String>=plan.classpath_entries.iter().cloned().collect();
    let mut seen_jvm:HashSet<String>=plan.jvm_args.iter().cloned().collect();
    let mut seen_client:HashSet<String>=plan.game_args.iter().cloned().collect();
    for component in &cat.components {
        let selected_paths=effective_files(component);
        if !selected_paths.iter().any(|p|active.contains(p)){continue}
        for action in &component.actions {
            match action.kind.as_str() {
                "File"=>{ /* the signed file is already staged by active_files */ },
                "ClassPath"=>{
                    if !plan.main_module.is_empty(){return Err(format!("component {} classpath action is incompatible with modular entrypoint",component.id))}
                    if !active.contains(&action.path){return Err(format!("component {} classpath file is not installed: {}",component.id,action.path))}
                    let joined=crate::safe_join(root,&action.path)?.to_string_lossy().to_string();
                    if !seen_classpath.insert(joined.clone()){return Err(format!("duplicate optional classpath entry: {}",action.path))}
                    plan.classpath_entries.push(joined);
                },
                "JvmArgs"=>{
                    for arg in &action.args {
                        if !seen_jvm.insert(arg.clone()){return Err(format!("duplicate optional JVM argument in {}",component.id))}
                        plan.jvm_args.push(arg.clone());
                    }
                },
                "ClientArgs"=>{
                    for arg in &action.args {
                        if !seen_client.insert(arg.clone()){return Err(format!("duplicate optional client argument in {}",component.id))}
                        plan.game_args.push(arg.clone());
                    }
                },
                _=>return Err(format!("unsigned/unknown action in {}",component.id))
            }
        }
    }
    // Re-use the existing signed runtime constraints after adding optional flags.
    Ok(())
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn optional_arguments_cannot_override_runtime_or_authentication(){
        for arg in ["-javaagent:malware.jar","@other.args","-Djava.library.path=/tmp","-Xmx99g","--add-opens=java.base/java.lang=ALL-UNNAMED"]{assert!(!safe_argument("JvmArgs",arg),"{arg}")}
        for arg in ["--accessToken=forged","--gameDir=/tmp","--username=forged","--version=other","-cp","--server=evil"]{assert!(!safe_argument("ClientArgs",arg),"{arg}")}
        assert!(safe_argument("JvmArgs","-Dfabric.log.level=debug"));
        assert!(safe_argument("JvmArgs","-XX:MaxGCPauseMillis=100"));
        assert!(safe_argument("ClientArgs","--optional-debug=1"));
    }
    #[test] fn signed_go_actions_fixture_and_signature(){
        let m:Manifest=serde_json::from_str(include_str!("../tests/fixtures/catalog_actions_0245_go_signed.json")).unwrap();
        let cat=m.component_catalog.as_ref().unwrap();
        assert_eq!(cat.schema_version,"5.0");
        assert_eq!(cat.digest,digest_v5(cat));
        crate::component_catalog_0241::validate(&m).unwrap();
        let public_key=m.signature.as_ref().unwrap().public_key.clone();
        crate::verify_manifest_signature(&m,&public_key).unwrap();
        let mut tampered=m.clone();
        tampered.component_catalog.as_mut().unwrap().components[1].actions[2].args[0]="-Dfabric.log.level=trace".into();
        assert!(crate::verify_manifest_signature(&tampered,&public_key).is_err());
    }
    #[test] fn action_changes_real_launch_plan(){
        let m:Manifest=serde_json::from_str(include_str!("../tests/fixtures/catalog_actions_0245_go_signed.json")).unwrap();
        let cat=m.component_catalog.as_ref().unwrap();
        let mut plan=LaunchPlan{java_executable:"java".into(),working_directory:"/client".into(),main_class:"net.demo.Main".into(),
            classpath_entries:vec!["/client/libraries/core.jar".into()],modulepath_entries:vec![],main_module:String::new(),
            environment_allowlist:vec![],restrict_java_environment:false,jvm_args:vec![],game_args:vec![],
            command_preview:String::new(),deterministic_sha256:String::new()};
        let active=cat.components[1].files.iter().cloned().collect();
        apply_selected_actions(cat,&active,Path::new("/client"),&mut plan).unwrap();
        assert!(plan.classpath_entries.iter().any(|s|s.ends_with("/mods/sodium.jar")));
        assert!(plan.jvm_args.iter().any(|s|s=="-Dfabric.log.level=debug"));
        assert!(plan.game_args.iter().any(|s|s=="--optional-feature=1"));
        let mut baseline=plan.clone();baseline.classpath_entries.clear();baseline.jvm_args.clear();baseline.game_args.clear();
        apply_selected_actions(cat,&HashSet::new(),Path::new("/client"),&mut baseline).unwrap();
        assert!(baseline.classpath_entries.is_empty()&&baseline.jvm_args.is_empty()&&baseline.game_args.is_empty());
    }
    #[test] fn signed_file_action_subset() {
        let c:CatalogComponent=serde_json::from_str(r#"{"id":"x","name":"X","files":["mods/one.jar","mods/two.jar"],"actions":[{"type":"File","path":"mods/two.jar"}]}"#).unwrap();
        assert_eq!(effective_files(&c),vec!["mods/two.jar"]);
    }
}
