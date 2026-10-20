//! Signed catalogs v1-v3; v3 resolves dependency, version and exclusion constraints before IO.
//! Preset resolution returns actual allow-listed manifest file paths, never
//! commands or client-supplied destinations.
use crate::{Manifest,file_ownership};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::collections::{BTreeMap,HashMap,HashSet};

fn empty(s:&String)->bool{s.is_empty()}
fn no(v:&bool)->bool{!*v}
fn map_empty(v:&BTreeMap<String,String>)->bool{v.is_empty()}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ComponentCatalog {
    pub schema_version:String,
    pub revision:u64,
    pub digest:String,
    pub components:Vec<CatalogComponent>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub categories:Vec<CatalogCategory>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub groups:Vec<CatalogGroup>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub presets:Vec<CatalogPreset>,
    #[serde(default,skip_serializing_if="empty")]
    pub default_preset:String,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CatalogComponent {
    pub id:String,
    pub name:String,
    pub files:Vec<String>,
    #[serde(default,skip_serializing_if="empty")]
    pub version:String,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub dependencies:Vec<ComponentRequirement>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub conflicts:Vec<ComponentRequirement>,
    #[serde(default,skip_serializing_if="empty")]
    pub exclusive_group:String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub conditions:Option<ComponentConditions0244>,
    #[serde(default,skip_serializing_if="empty")]
    pub description:String,
    #[serde(default,skip_serializing_if="empty")]
    pub category_id:String,
    #[serde(default,skip_serializing_if="empty")]
    pub group_id:String,
    #[serde(default,skip_serializing_if="no")]
    pub required:bool,
    #[serde(default,skip_serializing_if="no")]
    pub default:bool,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub visible:Option<bool>,
    #[serde(default,skip_serializing_if="no")]
    pub limited:bool,
    #[serde(default,skip_serializing_if="map_empty")]
    pub metadata:BTreeMap<String,String>,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ComponentConditions0244 {
    pub schema_version:String,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub os:Vec<String>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub arch:Vec<String>,
    #[serde(default,skip_serializing_if="is_zero_u32_0244")]
    pub java_major_min:u32,
    #[serde(default,skip_serializing_if="is_zero_u32_0244")]
    pub java_major_max:u32,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub minecraft_versions:Vec<String>,
    #[serde(default,skip_serializing_if="empty")]
    pub minecraft_version_range:String,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub loaders:Vec<String>,
    #[serde(default,skip_serializing_if="empty")]
    pub loader_version_range:String,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub permissions:Vec<String>,
}
fn is_zero_u32_0244(v:&u32)->bool{*v==0}

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct ComponentRequirement {
    pub id:String,
    #[serde(default,skip_serializing_if="empty")]
    pub version_range:String,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CatalogCategory {
    pub id:String,pub name:String,
    #[serde(default,skip_serializing_if="empty")]
    pub description:String,
    #[serde(default,skip_serializing_if="empty")]
    pub parent_id:String,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CatalogGroup {
    pub id:String,pub name:String,
    #[serde(default,skip_serializing_if="empty")]
    pub description:String,
    #[serde(default,skip_serializing_if="empty")]
    pub parent_id:String,
    #[serde(default,skip_serializing_if="empty")]
    pub category_id:String,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CatalogPreset {
    pub id:String,pub name:String,
    #[serde(default,skip_serializing_if="empty")]
    pub description:String,
    pub components:Vec<String>,
}
fn count(h:&mut Sha256,n:usize){h.update((n as u32).to_be_bytes());}
fn str_f(h:&mut Sha256,s:&str){count(h,s.len());h.update(s.as_bytes());}
fn bit(h:&mut Sha256,b:bool){h.update([u8::from(b)]);}
pub fn digest(components:&[CatalogComponent])->String {
    let mut h=Sha256::new();h.update(b"neverlauncher.component-catalog.v1\0");
    count(&mut h,components.len());
    for c in components {str_f(&mut h,&c.id);str_f(&mut h,&c.name);count(&mut h,c.files.len());for p in &c.files{str_f(&mut h,p)}}
    hex::encode(h.finalize())
}
pub fn digest_v2(cat:&ComponentCatalog)->String{
    let mut h=Sha256::new();h.update(b"neverlauncher.component-catalog.v2\0");
    count(&mut h,cat.components.len());
    for c in &cat.components {
        str_f(&mut h,&c.id);str_f(&mut h,&c.name);count(&mut h,c.files.len());for p in &c.files{str_f(&mut h,p)}
        str_f(&mut h,&c.description);str_f(&mut h,&c.category_id);str_f(&mut h,&c.group_id);
        bit(&mut h,c.required);bit(&mut h,c.default);bit(&mut h,c.visible==Some(true));bit(&mut h,c.limited);
        count(&mut h,c.metadata.len());for (k,v) in &c.metadata{str_f(&mut h,k);str_f(&mut h,v)}
    }
    count(&mut h,cat.categories.len());for c in &cat.categories{str_f(&mut h,&c.id);str_f(&mut h,&c.name);str_f(&mut h,&c.description);str_f(&mut h,&c.parent_id)}
    count(&mut h,cat.groups.len());for g in &cat.groups{str_f(&mut h,&g.id);str_f(&mut h,&g.name);str_f(&mut h,&g.description);str_f(&mut h,&g.parent_id);str_f(&mut h,&g.category_id)}
    count(&mut h,cat.presets.len());for p in &cat.presets{str_f(&mut h,&p.id);str_f(&mut h,&p.name);str_f(&mut h,&p.description);count(&mut h,p.components.len());for id in &p.components{str_f(&mut h,id)}}
    str_f(&mut h,&cat.default_preset);
    hex::encode(h.finalize())
}
pub fn digest_v3(cat:&ComponentCatalog)->String{
    let mut h=Sha256::new();h.update(b"neverlauncher.component-catalog.v3\0");
    str_f(&mut h,&digest_v2(cat));count(&mut h,cat.components.len());
    for c in &cat.components {
        str_f(&mut h,&c.version);str_f(&mut h,&c.exclusive_group);
        count(&mut h,c.dependencies.len());for r in &c.dependencies {str_f(&mut h,&r.id);str_f(&mut h,&r.version_range)}
        count(&mut h,c.conflicts.len());for r in &c.conflicts {str_f(&mut h,&r.id);str_f(&mut h,&r.version_range)}
    }
    hex::encode(h.finalize())
}
pub fn digest_v4(cat:&ComponentCatalog)->String{
    let mut h=Sha256::new();h.update(b"neverlauncher.component-catalog.v4\0");
    str_f(&mut h,&digest_v3(cat));count(&mut h,cat.components.len());
    for c in &cat.components {
        if let Some(v)=&c.conditions {
            h.update([1u8]);str_f(&mut h,&v.schema_version);
            for items in [&v.os,&v.arch,&v.minecraft_versions,&v.loaders,&v.permissions]{
                count(&mut h,items.len());for item in items{str_f(&mut h,item)}
            }
            count(&mut h,v.java_major_min as usize);count(&mut h,v.java_major_max as usize);
            str_f(&mut h,&v.minecraft_version_range);str_f(&mut h,&v.loader_version_range);
        }else{h.update([0u8]);}
    }
    hex::encode(h.finalize())
}
fn valid_permission_0244(s:&str)->bool {
    !s.is_empty()&&s.len()<=128&&s.bytes().next().is_some_and(|b|b.is_ascii_lowercase())&&
    s.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||matches!(b,b'_'|b'-'|b'.'|b':'))&&
    !s.contains("..")&&!s.contains("::")
}

fn distinct_conditions_0244(values:&[String],limit:usize,valid:impl Fn(&str)->bool)->Result<(),String>{
    if values.len()>limit {return Err("condition array exceeds limit".into())}
    let mut seen=HashSet::new();
    for v in values{if !valid(v)||!seen.insert(v){return Err(format!("invalid/duplicate condition value {v:?}"))}}
    Ok(())
}
fn validate_conditions_0244(cat:&ComponentCatalog)->Result<(),String>{
    for c in &cat.components {
        let Some(v)=&c.conditions else {continue};
        if cat.schema_version!="4.0" {return Err(format!("component {} has unsigned v4 conditions",c.id))}
        if v.schema_version!="1.0"{return Err(format!("component {} unsupported condition schema {}",c.id,v.schema_version))}
        distinct_conditions_0244(&v.os,8,|s|matches!(s,"windows"|"linux"|"macos"))?;
        distinct_conditions_0244(&v.arch,8,|s|matches!(s,"x86_64"|"aarch64"))?;
        if v.java_major_min>99||v.java_major_max>99||(v.java_major_max!=0&&v.java_major_min>v.java_major_max){return Err(format!("invalid Java condition on {}",c.id))}
        distinct_conditions_0244(&v.minecraft_versions,64,|s|!s.is_empty()&&s.len()<=80&&!s.bytes().any(|b|b.is_ascii_whitespace()||b==0))?;
        distinct_conditions_0244(&v.loaders,12,|s|matches!(s,"vanilla"|"fabric"|"quilt"|"forge"|"neoforge"))?;
        distinct_conditions_0244(&v.permissions,32,|s|valid_permission_0244(s))?;
        for r in [&v.minecraft_version_range,&v.loader_version_range]{if !r.is_empty(){matches_range_0243("1.0.0",r)?;}}
    }
    Ok(())
}
#[derive(Default)]
pub struct ComponentEnvironment0244 {
    pub os:String,pub arch:String,pub java_major:u32,
    pub minecraft_version:String,pub loader:String,pub loader_version:String,
    /// Permissions are never read from process environment or desktop input.
    /// This is empty unless a trusted signed server authorization is verified.
    pub verified_permissions:HashSet<String>,
}
impl ComponentEnvironment0244 {
    fn for_manifest(m:&Manifest)->Self {
        Self{os:match std::env::consts::OS{"macos"=>"macos",other=>other}.into(),
          arch:match std::env::consts::ARCH{"x86_64"=>"x86_64","aarch64"=>"aarch64",other=>other}.into(),
          java_major:m.runtime.java.major_version,
          minecraft_version:m.minecraft.version.clone(),loader:m.minecraft.loader.to_ascii_lowercase(),
          loader_version:m.minecraft.loader_version.clone(),verified_permissions:HashSet::new()}
    }
}
fn condition_unavailable_0244(c:&CatalogComponent,env:&ComponentEnvironment0244)->Result<Option<String>,String>{
    let Some(v)=&c.conditions else{return Ok(None)};
    if !v.os.is_empty()&&!v.os.contains(&env.os){return Ok(Some(format!("OS {} not in {:?}",env.os,v.os)))}
    if !v.arch.is_empty()&&!v.arch.contains(&env.arch){return Ok(Some(format!("arch {} not in {:?}",env.arch,v.arch)))}
    if v.java_major_min!=0&&(env.java_major==0||env.java_major<v.java_major_min){return Ok(Some(format!("Java {} below {}",env.java_major,v.java_major_min)))}
    if v.java_major_max!=0&&(env.java_major==0||env.java_major>v.java_major_max){return Ok(Some(format!("Java {} above {}",env.java_major,v.java_major_max)))}
    if !v.minecraft_versions.is_empty()&&!v.minecraft_versions.contains(&env.minecraft_version){return Ok(Some(format!("Minecraft {} not allowed",env.minecraft_version)))}
    if !v.minecraft_version_range.is_empty() {
        if !matches_range_0243(&env.minecraft_version,&v.minecraft_version_range).unwrap_or(false){return Ok(Some(format!("Minecraft {} outside {}",env.minecraft_version,v.minecraft_version_range)))}
    }
    if !v.loaders.is_empty()&&!v.loaders.contains(&env.loader){return Ok(Some(format!("loader {} not allowed",env.loader)))}
    if !v.loader_version_range.is_empty(){if !matches_range_0243(&env.loader_version,&v.loader_version_range).unwrap_or(false){return Ok(Some(format!("loader version {} outside {}",env.loader_version,v.loader_version_range)))}}
    for name in &v.permissions{if !env.verified_permissions.contains(name){return Ok(Some(format!("missing verified permission: {name}")))}}
    Ok(None)
}
fn resolve_conditional_0244(cat:&ComponentCatalog,preset:&str,env:&ComponentEnvironment0244)->Result<HashSet<String>,String>{
    let mut modified=cat.clone();
    let explicit=!preset.is_empty()||!cat.default_preset.is_empty();
    for c in &mut modified.components {
        if let Some(reason)=condition_unavailable_0244(c,env)? {
            if c.required{return Err(format!("condition_unsatisfied: required component {}: {reason}",c.id))}
            if !explicit{c.default=false;}
        }
    }
    let selected=resolve_graph_v3(&modified,preset)?;
    for c in &cat.components{
        if selected.contains(&c.id){if let Some(why)=condition_unavailable_0244(c,env)? {
            return Err(format!("condition_unsatisfied: selected/dependent component {}: {why}",c.id))
        }}
    }
    Ok(selected)
}

fn valid_id(s:&str)->bool{
    !s.is_empty()&&s.len()<=128&&!s.contains("..")&&s.bytes().next().is_some_and(|b|b.is_ascii_lowercase()||b.is_ascii_digit())&&s.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||matches!(b,b'-'|b'_'|b'.'))
}
fn label(n:&str,d:&str)->bool{!n.trim().is_empty()&&n.len()<=256&&d.len()<=2048&&!format!("{n}{d}").chars().any(|c|matches!(c,'\0'|'\r'))}
fn validate_topology(cat:&ComponentCatalog)->Result<(),String>{
    validate_conditions_0244(cat)?;
    if cat.schema_version=="1.0"{
        if !cat.categories.is_empty()||!cat.groups.is_empty()||!cat.presets.is_empty()||!cat.default_preset.is_empty() {return Err("v1 catalog cannot contain topology".into())}
        for c in &cat.components{if !c.version.is_empty()||!c.dependencies.is_empty()||!c.conflicts.is_empty()||!c.exclusive_group.is_empty()||!c.description.is_empty()||!c.category_id.is_empty()||!c.group_id.is_empty()||c.required||c.default||c.visible.is_some()||c.limited||!c.metadata.is_empty(){return Err(format!("v1 component has topology: {}",c.id))}}
        return Ok(())
    }
    if cat.schema_version=="2.0" {
        for c in &cat.components {
            if !c.version.is_empty()||!c.dependencies.is_empty()||!c.conflicts.is_empty()||!c.exclusive_group.is_empty(){return Err(format!("v2 component {} contains unsigned v3 constraints",c.id))}
        }
    }
    if cat.categories.len()>256||cat.groups.len()>1024||cat.presets.len()>128{return Err("topology size exceeded".into())}
    let mut categories=HashMap::new();
    for c in &cat.categories{if !valid_id(&c.id)||!label(&c.name,&c.description)||categories.insert(c.id.as_str(),c).is_some(){return Err(format!("invalid/duplicate category {}",c.id))}}
    let mut groups=HashMap::new();
    for g in &cat.groups{if !valid_id(&g.id)||!label(&g.name,&g.description)||groups.insert(g.id.as_str(),g).is_some(){return Err(format!("invalid/duplicate group {}",g.id))}}
    for id in categories.keys(){let mut seen=HashSet::new();let mut cur=*id;while !cur.is_empty(){if seen.len()>=9||!seen.insert(cur){return Err(format!("category cycle/depth {id}"))}cur=categories.get(cur).ok_or(format!("missing category {cur}"))?.parent_id.as_str()}}
    for id in groups.keys(){let mut seen=HashSet::new();let mut cur=*id;let mut category="";while !cur.is_empty(){if seen.len()>=9||!seen.insert(cur){return Err(format!("group cycle/depth {id}"))}let g=groups.get(cur).ok_or(format!("missing group {cur}"))?;if !g.category_id.is_empty(){if !categories.contains_key(g.category_id.as_str())||(!category.is_empty()&&category!=g.category_id){return Err(format!("group category mismatch {id}"))}category=&g.category_id}cur=g.parent_id.as_str()}}
    let mut ids=HashSet::new();
    for c in &cat.components{
        if c.visible.is_none()||!label(&c.name,&c.description)||c.metadata.len()>32{return Err(format!("bad metadata/visibility {}",c.id))}
        if !c.category_id.is_empty()&&!categories.contains_key(c.category_id.as_str()){return Err(format!("unknown category {}",c.category_id))}
        if !c.group_id.is_empty(){let g=groups.get(c.group_id.as_str()).ok_or(format!("unknown group {}",c.group_id))?;if !g.category_id.is_empty()&&!c.category_id.is_empty()&&g.category_id!=c.category_id{return Err(format!("component group category mismatch {}",c.id))}}
        for (k,v) in &c.metadata{if !valid_id(k)||k.len()>64||v.len()>1024||v.chars().any(|ch|matches!(ch,'\0'|'\r')){return Err(format!("invalid component metadata {}",c.id))}}
        ids.insert(c.id.as_str());
    }
    let mut preset_ids=HashSet::new();
    for p in &cat.presets{
        if !valid_id(&p.id)||!label(&p.name,&p.description)||!preset_ids.insert(p.id.as_str())||p.components.len()>4096{return Err(format!("bad preset {}",p.id))}
        let mut included=HashSet::new();for id in &p.components{if !ids.contains(id.as_str())||!included.insert(id){return Err(format!("preset {} unknown/duplicate component {}",p.id,id))}}
    }
    if !cat.default_preset.is_empty()&&!preset_ids.contains(cat.default_preset.as_str()){return Err("unknown defaultPreset".into())}
    validate_conditions_0244(cat)?;
    if cat.schema_version=="3.0"||cat.schema_version=="4.0" {validate_rules_v3(cat)?;}
    Ok(())
}
#[derive(Clone,Debug,PartialEq,Eq)]
struct Semver0243 {major:u64,minor:u64,patch:u64,pre:Vec<String>}
fn parse_semver_0243(value:&str)->Result<Semver0243,String>{
    if value.is_empty()||value.len()>128||value.bytes().any(|b|b.is_ascii_whitespace()){return Err(format!("invalid semantic version {value:?}"))}
    let (before_build,build)=value.split_once('+').map_or((value,None),|(a,b)|(a,Some(b)));
    if let Some(build)=build {if !valid_semver_ids_0243(build,false){return Err(format!("invalid build metadata in {value:?}"))}}
    let (base,pre)=before_build.split_once('-').map_or((before_build,None),|(a,b)|(a,Some(b)));
    let pre=if let Some(pre)=pre {if !valid_semver_ids_0243(pre,true){return Err(format!("invalid prerelease in {value:?}"))}pre.split('.').map(str::to_string).collect()} else {Vec::new()};
    let parts:Vec<_>=base.split('.').collect();
    if parts.len()!=3{return Err(format!("semantic version must be MAJOR.MINOR.PATCH: {value:?}"))}
    let mut nums=[0u64;3];
    for (i,v) in parts.iter().enumerate(){
        if v.is_empty()||(v.len()>1&&v.starts_with('0'))||!v.bytes().all(|b|b.is_ascii_digit()){return Err(format!("invalid semantic version {value:?}"))}
        nums[i]=v.parse::<u64>().map_err(|_|format!("invalid semantic version {value:?}"))?;
    }
    Ok(Semver0243{major:nums[0],minor:nums[1],patch:nums[2],pre})
}
fn valid_semver_ids_0243(value:&str,prerelease:bool)->bool{
    if value.is_empty(){return false}
    value.split('.').all(|part|{
        !part.is_empty()&&part.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')&&
        (!prerelease||!part.bytes().all(|b|b.is_ascii_digit())||
           ((part.len()==1||!part.starts_with('0'))&&part.parse::<u64>().is_ok()))
    })
}
fn compare_semver_0243(a:&Semver0243,b:&Semver0243)->std::cmp::Ordering{
    use std::cmp::Ordering;
    for (x,y) in [(a.major,b.major),(a.minor,b.minor),(a.patch,b.patch)]{let o=x.cmp(&y);if o!=Ordering::Equal{return o}}
    if a.pre.is_empty(){return if b.pre.is_empty(){Ordering::Equal}else{Ordering::Greater}}
    if b.pre.is_empty(){return Ordering::Less}
    for (x,y) in a.pre.iter().zip(b.pre.iter()) {
        let a_num=x.parse::<u64>().ok();let b_num=y.parse::<u64>().ok();
        let o=match (a_num,b_num){(Some(x),Some(y))=>x.cmp(&y),(Some(_),None)=>Ordering::Less,(None,Some(_))=>Ordering::Greater,(None,None)=>x.cmp(y)};
        if o!=Ordering::Equal{return o}
    }
    a.pre.len().cmp(&b.pre.len())
}
fn matches_range_0243(actual:&str,expression:&str)->Result<bool,String>{
    use std::cmp::Ordering;
    let a=parse_semver_0243(actual)?;
    let trimmed=expression.trim();
    if trimmed.is_empty()||trimmed=="*" {return Ok(true)}
    if expression.len()>256{return Err("version range exceeds 256 bytes".into())}
    let mut any_matched=false;
    for branch in expression.split("||"){
        let parts:Vec<&str>=branch.split_whitespace().collect();
        if parts.is_empty()||parts.len()>16{return Err(format!("invalid version range {expression:?}"))}
        let mut all=true;
        for token in parts {
            if token=="*"{continue}
            let (op,raw)=[">=","<=",">","<","=","^","~"].iter().find_map(|op|token.strip_prefix(*op).map(|v|(*op,v))).unwrap_or(("=",token));
            let b=parse_semver_0243(raw).map_err(|err|format!("invalid range {expression:?}: {err}"))?;
            let cmp=compare_semver_0243(&a,&b);
            let valid=match op {
                "="=>cmp==Ordering::Equal,">"=>cmp==Ordering::Greater,">="=>cmp!=Ordering::Less,
                "<"=>cmp==Ordering::Less,"<="=>cmp!=Ordering::Greater,
                "^"|"~"=>{
                    let mut upper=b.clone();upper.pre.clear();
                    if op=="~"{upper.minor=upper.minor.checked_add(1).ok_or("version range overflow")?;upper.patch=0;}
                    else if upper.major>0{upper.major=upper.major.checked_add(1).ok_or("version range overflow")?;upper.minor=0;upper.patch=0;}
                    else if upper.minor>0{upper.minor=upper.minor.checked_add(1).ok_or("version range overflow")?;upper.patch=0;}
                    else {upper.patch=upper.patch.checked_add(1).ok_or("version range overflow")?;}
                    cmp!=Ordering::Less&&compare_semver_0243(&a,&upper)==Ordering::Less
                },_=>false
            };
            if !valid{all=false}
        }
        if all{any_matched=true}
    }
    Ok(any_matched)
}
fn validate_rules_v3(cat:&ComponentCatalog)->Result<(),String>{
    let items:HashMap<&str,&CatalogComponent>=cat.components.iter().map(|c|(c.id.as_str(),c)).collect();
    for c in &cat.components {
        parse_semver_0243(&c.version).map_err(|e|format!("invalid_version component {}: {e}",c.id))?;
        if !c.exclusive_group.is_empty()&&!valid_id(&c.exclusive_group){return Err(format!("invalid_group component {}: {}",c.id,c.exclusive_group))}
        if c.dependencies.len()>64||c.conflicts.len()>64{return Err(format!("limit component {}: too many constraints",c.id))}
        for (kind,refs) in [("dependency",&c.dependencies),("conflict",&c.conflicts)] {
            let mut seen=HashSet::new();
            for r in refs {
                let other=items.get(r.id.as_str()).ok_or_else(||format!("invalid_reference {} {}: unknown {}",c.id,kind,r.id))?;
                if r.id==c.id||!seen.insert(r.id.as_str()){return Err(format!("invalid_reference {} {}: duplicate/self {}",c.id,kind,r.id))}
                matches_range_0243(&other.version,&r.version_range).map_err(|e|format!("invalid_range {} {} {}: {e}",c.id,kind,r.id))?;
            }
        }
    }
    fn visit<'a>(id:&'a str,items:&HashMap<&'a str,&'a CatalogComponent>,state:&mut HashMap<&'a str,u8>,stack:&mut Vec<&'a str>)->Result<(),String>{
        if state.get(id)==Some(&2){return Ok(())}
        if state.get(id)==Some(&1){let i=stack.iter().position(|s|*s==id).unwrap_or(0);let mut path=stack[i..].to_vec();path.push(id);return Err(format!("cycle: {}",path.join(" -> ")))}
        state.insert(id,1);stack.push(id);
        let current=*items.get(id).ok_or_else(||format!("missing dependency node {id}"))?;
        for dep in &current.dependencies {visit(dep.id.as_str(),items,state,stack)?}
        stack.pop();state.insert(id,2);Ok(())
    }
    let mut state=HashMap::new();let mut stack=Vec::new();
    for c in &cat.components{visit(c.id.as_str(),&items,&mut state,&mut stack)?}
    if cat.schema_version!="4.0" {
      resolve_graph_v3(cat,"")?;
      for p in &cat.presets{resolve_graph_v3(cat,&p.id).map_err(|e|format!("preset {} invalid: {e}",p.id))?;}
    }
    Ok(())
}
fn resolve_graph_v3(cat:&ComponentCatalog,preset:&str)->Result<HashSet<String>,String>{
    let components:HashMap<&str,&CatalogComponent>=cat.components.iter().map(|c|(c.id.as_str(),c)).collect();
    let chosen=if preset.is_empty(){cat.default_preset.as_str()}else{preset};
    let mut selected:HashSet<String>=if !chosen.is_empty(){
        cat.presets.iter().find(|p|p.id==chosen).ok_or_else(||format!("unknown_preset: unknown signed component preset {chosen}"))?.components.iter().cloned().collect()
    }else{cat.components.iter().filter(|c|c.default).map(|c|c.id.clone()).collect()};
    selected.extend(cat.components.iter().filter(|c|c.required).map(|c|c.id.clone()));
    fn include(id:&str,chain:&[String],components:&HashMap<&str,&CatalogComponent>,selected:&mut HashSet<String>,done:&mut HashSet<String>)->Result<(),String>{
        if done.contains(id){return Ok(())}
        let c=*components.get(id).ok_or_else(||format!("missing_dependency: {id}"))?;
        for dep in &c.dependencies {
            let other=components.get(dep.id.as_str()).ok_or_else(||format!("missing_dependency: {} -> {}",id,dep.id))?;
            if !matches_range_0243(&other.version,&dep.version_range)?{
                let mut path=chain.to_vec();path.push(id.to_string());
                return Err(format!("version_mismatch: {id} requires {} {:?}, available {} (via {})",dep.id,dep.version_range,other.version,path.join(" -> ")))
            }
            selected.insert(dep.id.clone());
            let mut next=chain.to_vec();next.push(id.to_string());include(&dep.id,&next,components,selected,done)?;
        }
        done.insert(id.to_string());Ok(())
    }
    let mut expanded=HashSet::new();
    for c in &cat.components {if selected.contains(&c.id){include(&c.id,&[],&components,&mut selected,&mut expanded)?}}
    let mut groups=HashMap::new();
    for c in &cat.components {
        if !selected.contains(&c.id){continue}
        if !c.exclusive_group.is_empty() {
            if let Some(other)=groups.insert(c.exclusive_group.as_str(),c.id.as_str()){
                return Err(format!("exclusive_group: {other} and {} are mutually exclusive (group {})",c.id,c.exclusive_group))
            }
        }
        for conflict in &c.conflicts {
            if selected.contains(&conflict.id) {
                let other=components[conflict.id.as_str()];
                if matches_range_0243(&other.version,&conflict.version_range)?{
                    return Err(format!("conflict: {} and {} cannot be selected together; {} conflicts with {} version {} (range {:?})",c.id,other.id,c.id,other.id,other.version,conflict.version_range))
                }
            }
        }
    }
    Ok(selected)
}

#[derive(Debug,Serialize)]
#[serde(rename_all="camelCase")]
pub struct ComponentSelectionPreview0244 {
    pub selected:Vec<String>,
    pub unavailable:Vec<UnavailableComponent0244>,
    pub effective_files:Vec<String>,
}
#[derive(Debug,Serialize)]
#[serde(rename_all="camelCase")]
pub struct UnavailableComponent0244 { pub id:String,pub reason:String }

// Desktop receives the same native result that staging and launch use.
// Caller MUST verify the signed manifest first. This API never trusts local
// permissions, operating-system or architecture input.
pub fn preview_components_0244(m:&Manifest,preset:Option<&str>)->Result<ComponentSelectionPreview0244,String>{
    validate(m)?;
    let cat=m.component_catalog.as_ref().ok_or("catalog is missing")?;
    if cat.schema_version!="4.0"{return Err("conditional preview requires schema v4".into())}
    let env=ComponentEnvironment0244::for_manifest(m);
    let selected=resolve_conditional_0244(cat,preset.unwrap_or_default(),&env)?;
    let unavailable=cat.components.iter().filter_map(|c|{
        condition_unavailable_0244(c,&env).ok().flatten().map(|reason|UnavailableComponent0244{id:c.id.clone(),reason})
    }).collect();
    let mut effective_files=Vec::new();
    for c in &cat.components {if selected.contains(&c.id){effective_files.extend(c.files.iter().cloned())}}
    Ok(ComponentSelectionPreview0244{
        selected:cat.components.iter().filter(|c|selected.contains(&c.id)).map(|c|c.id.clone()).collect(),
        unavailable,effective_files,
    })
}

pub fn validate(m:&Manifest)->Result<(),String>{
    if m.schema_version!="3.0"{if m.component_catalog.is_some(){return Err("componentCatalog requires manifest v3".into())}return Ok(())}
    let cat=m.component_catalog.as_ref().ok_or("v3 requires signed componentCatalog")?;
    if !matches!(cat.schema_version.as_str(),"1.0"|"2.0"|"3.0"|"4.0")||cat.revision==0||cat.components.len()>4096||cat.digest.len()!=64||cat.digest!=(if cat.schema_version=="1.0"{digest(&cat.components)}else if cat.schema_version=="2.0"{digest_v2(cat)}else if cat.schema_version=="3.0"{digest_v3(cat)}else{digest_v4(cat)}){return Err("invalid v3 component snapshot/digest".into())}
    validate_topology(cat)?;
    let files:HashMap<_,_>=m.files.iter().map(|f|(f.path.to_ascii_lowercase(),f)).collect();let mut ids=HashSet::new();let mut owners=HashSet::new();
    for c in &cat.components{
        if !valid_id(&c.id)||!ids.insert(c.id.as_str())||c.name.trim().is_empty()||c.name.len()>256||c.name.chars().any(|c|matches!(c,'\0'|'\r'|'\n'))||c.files.is_empty()||c.files.len()>8192{return Err(format!("invalid/duplicate component {}",c.id))}
        for path in &c.files{let key=path.to_ascii_lowercase();let f=files.get(&key).ok_or_else(||format!("undeclared component file: {path}"))?;
            if f.path!=*path||f.required||file_ownership::effective_ownership(f)!="optional"||!owners.insert(key){return Err(format!("invalid/duplicate component file: {path}"))}}
    }
    for f in &m.files{if file_ownership::effective_ownership(f)=="optional"&&!owners.contains(&f.path.to_ascii_lowercase()){return Err(format!("unowned v3 optional file: {}",f.path))}}
    Ok(())
}
/// Signed preset => effective file paths (all non-component files remain active).
/// v1 catalog selects all files, preserving 0.24.1 behavior.
pub fn active_files(m:&Manifest,preset:Option<&str>)->Result<HashSet<String>,String>{
    validate(m)?;
    let mut active:HashSet<String>=m.files.iter().filter(|f|file_ownership::effective_ownership(f)!="optional").map(|f|f.path.clone()).collect();
    if m.schema_version!="3.0" {active.extend(m.files.iter().map(|f|f.path.clone()));return Ok(active)}
    let cat=m.component_catalog.as_ref().ok_or("missing component catalog")?;
    let mut selected=HashSet::new();
    if cat.schema_version=="3.0"||cat.schema_version=="4.0" {
        let resolved=if cat.schema_version=="4.0"{
            resolve_conditional_0244(cat,preset.unwrap_or_default(),&ComponentEnvironment0244::for_manifest(m))?
        }else{resolve_graph_v3(cat,preset.unwrap_or_default())?};
        for c in &cat.components {if resolved.contains(c.id.as_str()) {active.extend(c.files.iter().cloned());}}
        return Ok(active)
    }
    if cat.schema_version=="1.0"{selected.extend(cat.components.iter().map(|c|c.id.as_str()));}
    else {
        let chosen=preset.filter(|p|!p.is_empty()).unwrap_or(cat.default_preset.as_str());
        if chosen.is_empty(){selected.extend(cat.components.iter().filter(|c|c.default).map(|c|c.id.as_str()));}
        else {let preset=cat.presets.iter().find(|p|p.id==chosen).ok_or_else(||format!("unknown signed component preset {chosen}"))?;selected.extend(preset.components.iter().map(String::as_str));}
        selected.extend(cat.components.iter().filter(|c|c.required).map(|c|c.id.as_str()));
    }
    for c in &cat.components{if selected.contains(c.id.as_str()){active.extend(c.files.iter().cloned());}}
    Ok(active)
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test] fn go_v2_digest_and_presets(){
  let cat:ComponentCatalog=serde_json::from_str(include_str!("../tests/fixtures/catalog_topology_0242_go.json")).unwrap();
  assert_eq!(digest_v2(&cat),"97b6cfd2584fbae25545d422cad08c28b30b1de5d8f399e81a0ed7af3535f909");
  validate_topology(&cat).unwrap();
  let mut other=cat.clone();other.groups[0].name="forged".into();assert_ne!(digest_v2(&cat),digest_v2(&other));
  let mut bad=cat.clone();bad.presets[0].components.push("missing".into());assert!(validate_topology(&bad).is_err());
 }
 #[test] fn v2_preset_and_tamper(){
  let json=r#"{"schemaVersion":"2.0","revision":2,"digest":"","components":[{"id":"core","name":"Core","files":["mods/core.jar"],"required":true,"visible":false},{"id":"shaders","name":"Shaders","files":["mods/shaders.jar"],"default":true,"visible":true,"metadata":{"authors":"A"}}],"categories":[{"id":"visual","name":"Visual"}],"presets":[{"id":"minimal","name":"Minimal","components":[]},{"id":"full","name":"Full","components":["shaders"]}],"defaultPreset":"minimal"}"#;
  let cat:ComponentCatalog=serde_json::from_str(json).unwrap();assert!(validate_topology(&cat).is_ok());assert_ne!(digest_v2(&cat),digest(&cat.components));
  let mut tampered=cat.clone();tampered.components[1].metadata.insert("authors".into(),"B".into());assert_ne!(digest_v2(&cat),digest_v2(&tampered));
  let mut cycle=cat.clone();cycle.categories[0].parent_id="visual".into();assert!(validate_topology(&cycle).is_err());
 }
 #[test] fn signed_go_conditions_fixture_0244(){
  let manifest:crate::Manifest=serde_json::from_str(include_str!("../tests/fixtures/catalog_conditions_0244_go_signed.json")).unwrap();
  let cat=manifest.component_catalog.as_ref().unwrap();
  assert_eq!(cat.schema_version,"4.0");
  assert_eq!(cat.digest,digest_v4(cat));
  validate(&manifest).unwrap();
  let key=manifest.signature.as_ref().unwrap().public_key.clone();
  crate::verify_manifest_signature(&manifest,&key).unwrap();
  let env=ComponentEnvironment0244{os:"linux".into(),arch:"x86_64".into(),java_major:21,
    minecraft_version:"1.21.1".into(),loader:"fabric".into(),loader_version:"0.16.2".into(),verified_permissions:HashSet::new()};
  let allowed=resolve_conditional_0244(cat,"quality",&env).unwrap();
  assert!(allowed.contains("performance.sodium")&&allowed.contains("shaders"));
  let mut invalid=env;invalid.os="macos".into();
  assert!(resolve_conditional_0244(cat,"quality",&invalid).unwrap_err().contains("condition_unsatisfied"));
  let mut changed=manifest.clone();
  changed.component_catalog.as_mut().unwrap().components[1].conditions.as_mut().unwrap().java_major_max=17;
  assert!(validate(&changed).is_err());
  assert_ne!(digest_v4(cat),digest_v4(changed.component_catalog.as_ref().unwrap()));
 }

}
