//! Real signed compatibility enforcement shared by the native Runtime/Guard
//! launcher. The operator's Ed25519 public key is pinned outside client root.
//! The trusted JVM premain separately restricts authorized hook callbacks.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::{HashMap,HashSet},fs,io::Read,path::{Path,Component},time::{SystemTime,UNIX_EPOCH}};

const DOMAIN: &[u8] = b"NeverLauncher-Guard-Compatibility-v1\n";
const SCHEMA: &str = "launcher.guard-compatibility.v1";
const POLICY: &str = ".launcher/guard/compatibility.json";
const FLOOR: &str = ".launcher/guard/accepted.json";
const PUBLIC_KEY: &str = "LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE";
const REQUIRED: &str = "LAUNCHER_GUARD_COMPAT_REQUIRED";

#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Envelope { schema_version: String, payload: String, signature: String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Artifact { kind:String,path:String,sha256:String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Transform { id:String,owner_sha256:String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Policy {
 schema_version:String, project_id:String,minecraft:String,loader:String,epoch:u64,
 issued_at:i64,expires_at:i64,artifacts:Vec<Artifact>,transformations:Vec<Transform>,
 revoked_digests:Vec<String>,revoked_transformations:Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Floor { epoch:u64,digest:String,root_sha256:String }
struct Verified { policy:Policy, digest:String }

fn sha(bytes:&[u8])->String{hex::encode(Sha256::digest(bytes))}
fn is_sha(s:&str)->bool{s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase())}
fn relative(rel:&str)->bool {
 !rel.is_empty() && !rel.starts_with('/') && !rel.contains('\\') && !rel.contains(':') && !rel.contains('\0') &&
 !rel.contains('\n') && !rel.contains('\r') && !rel.contains("//") &&
 rel.split('/').all(|s|!s.is_empty() && s!="." && s!="..")
}
fn safe_file(root:&Path,relative_name:&str,max:u64)->Result<Vec<u8>,String>{
 if !relative(relative_name){return Err("Guard compatibility unsafe relative path".into())}
 let mut path=root.to_path_buf();
 for part in relative_name.split('/') {
  path.push(part);
  let meta=fs::symlink_metadata(&path).map_err(|e|format!("Guard compatibility missing {}: {e}",path.display()))?;
  if meta.file_type().is_symlink(){return Err("Guard compatibility symlink refused".into())}
 }
 let meta=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
 if !meta.is_file() || meta.len()>max {return Err("Guard compatibility file type/size invalid".into())}
 fs::read(&path).map_err(|e|e.to_string())
}
fn external_key(root:&Path)->Result<([u8;32],String),String>{
 let key_path=std::env::var(PUBLIC_KEY).map_err(|_|format!("external {PUBLIC_KEY} required"))?;
 let path=Path::new(&key_path);
 let meta=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
 if !meta.is_file() || meta.file_type().is_symlink() || meta.len()>1024 {return Err("Guard compatibility unsafe public key file".into())}
 let root=fs::canonicalize(root).map_err(|e|e.to_string())?;
 let canonical=fs::canonicalize(path).map_err(|e|e.to_string())?;
 if canonical.starts_with(&root){return Err("Guard compatibility key inside client tree".into())}
 let source=fs::read_to_string(path).map_err(|e|e.to_string())?;
 let text=source.trim();
 let raw=hex::decode(text).ok().filter(|b|b.len()==32)
  .or_else(||STANDARD.decode(text).ok().filter(|b|b.len()==32))
  .ok_or("Guard compatibility Ed25519 public key must be 32-byte hex/base64")?;
 let digest=sha(&raw);
 Ok((raw.try_into().map_err(|_|"Guard compatibility key size".to_string())?,digest))
}
fn now()->Result<i64,String>{SystemTime::now().duration_since(UNIX_EPOCH).map(|x|x.as_secs() as i64).map_err(|e|e.to_string())}
fn load(root:&Path)->Result<Option<Verified>,String>{
 let policy_path=root.join(POLICY);
 let installed=match fs::symlink_metadata(&policy_path){
  Ok(_)=>safe_file(root,POLICY,256*1024)?,
  Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{
   if root.join(FLOOR).exists() || std::env::var(REQUIRED).ok().as_deref()==Some("1"){
    return Err("required Guard compatibility policy missing".into());
   }
   return Ok(None)
  },
  Err(e)=>return Err(e.to_string())
 };
 let (root_key,root_digest)=external_key(root)?;
 let env:Envelope=serde_json::from_slice(&installed).map_err(|e|e.to_string())?;
 if env.schema_version!=SCHEMA{return Err("unknown Guard compatibility envelope".into())}
 let payload=STANDARD.decode(&env.payload).map_err(|e|e.to_string())?;
 if payload.is_empty() || payload.len()>192*1024{return Err("Guard compatibility invalid payload size".into())}
 let signature_bytes=hex::decode(&env.signature).map_err(|e|e.to_string())?;
 let sig:[u8;64]=signature_bytes.try_into().map_err(|_|"Guard compatibility invalid signature length".to_string())?;
 let key=VerifyingKey::from_bytes(&root_key).map_err(|e|e.to_string())?;
 let mut signed=DOMAIN.to_vec();signed.extend_from_slice(&payload);
 key.verify(&signed,&Signature::from_bytes(&sig)).map_err(|_|"Guard compatibility signature invalid".to_string())?;
 let p:Policy=serde_json::from_slice(&payload).map_err(|e|e.to_string())?;
 let current=now()?;
 if p.schema_version!=SCHEMA || p.epoch==0 || p.project_id.is_empty() || p.minecraft.is_empty() || p.loader.is_empty() ||
  p.issued_at<=0 || p.issued_at>current+300 || p.expires_at<=current || p.expires_at<=p.issued_at || p.expires_at-p.issued_at>90*86400 ||
  p.artifacts.len()>4096 || p.transformations.len()>4096 || p.revoked_digests.len()>4096 || p.revoked_transformations.len()>4096 {
  return Err("Guard compatibility scope, validity or list limits invalid".into())
 }
 let mut paths=HashSet::new();let mut plugin_digests=HashSet::new();
 for a in &p.artifacts {
  if !["mod","java-agent","java-plugin","native-library"].contains(&a.kind.as_str()) || !relative(&a.path) || !is_sha(&a.sha256) ||
   !paths.insert(format!("{}:{}",a.kind,a.path.to_ascii_lowercase())){return Err("Guard compatibility artifact invalid/duplicate".into())}
  if a.kind=="java-plugin"{plugin_digests.insert(&a.sha256);}
 }
 let mut ids=HashSet::new();
 for t in &p.transformations {
  if t.id.is_empty() || t.id.len()>256 || !is_sha(&t.owner_sha256) || !plugin_digests.contains(&t.owner_sha256) || !ids.insert(&t.id){
   return Err("Guard compatibility transformation invalid/duplicate".into())
  }
 }
 if p.revoked_digests.iter().any(|d|!is_sha(d)) || p.revoked_transformations.iter().any(|t|t.is_empty()) {
  return Err("Guard compatibility invalid revocation".into())
 }
 let floor_path=root.join(FLOOR);
 if !floor_path.exists(){return Err("Guard compatibility accepted epoch state missing".into())}
 if floor_path.exists() {
  let bytes=safe_file(root,FLOOR,4096)?;
  let floor:Floor=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
  if floor.root_sha256!=root_digest || floor.epoch>p.epoch || (floor.epoch==p.epoch && floor.digest!=sha(&payload)) {
   return Err("Guard compatibility root change, rollback or equivocation".into())
  }
 }
 Ok(Some(Verified{policy:p,digest:sha(&payload)}))
}
/// A scoped, verified operator policy exposed only to the native Trusted JVM bridge.
/// Artifacts are SHA-256 checked again immediately before spawn.
pub struct GamePolicy0503 { policy:Policy, digest:String }
impl GamePolicy0503 {
 pub fn digest(&self)->&str { &self.digest }
 pub fn authorize(&self,root:&Path,kind:&str,relative_path:&str,digest:&str)->Result<(),String> {
  let artifact=self.policy.artifacts.iter().find(|a|a.kind==kind && a.path==relative_path && a.sha256==digest)
   .ok_or_else(||format!("Guard compatibility {kind} not signed for this game: {relative_path}"))?;
  if self.policy.revoked_digests.contains(&artifact.sha256){return Err("Guard compatibility trusted code revoked".into())}
  validate_safe_path(root,&artifact.path,512*1024*1024)?;
  if actual_sha(&root.join(&artifact.path))?!=artifact.sha256{return Err("Guard compatibility trusted code digest changed".into())}
  Ok(())
 }
 pub fn transforms(&self,owners:&HashSet<String>)->Result<Vec<(String,String)>,String>{
  let mut allowed=Vec::new();
  for t in &self.policy.transformations {
   if self.policy.revoked_transformations.contains(&t.id) || self.policy.revoked_digests.contains(&t.owner_sha256) || !owners.contains(&t.owner_sha256){
    return Err(format!("Guard compatibility unapproved/revoked trusted transformation: {}",t.id))
   }
   allowed.push((t.id.clone(),t.owner_sha256.clone()));
  }
  Ok(allowed)
 }
}
pub fn verified_for_game(root:&Path,project:&str,minecraft:&str,loader:&str)->Result<Option<GamePolicy0503>,String>{
 let Some(v)=load(root)? else{return Ok(None)};
 if v.policy.project_id!=project || v.policy.minecraft!=minecraft || !v.policy.loader.eq_ignore_ascii_case(loader) {
  return Err("Guard compatibility trusted game scope mismatch".into())
 }
 Ok(Some(GamePolicy0503{policy:v.policy,digest:v.digest}))
}

fn validate_safe_path(root:&Path,rel:&str,max:u64)->Result<(),String>{
 if !relative(rel){return Err("Guard compatibility invalid path".into())}
 let mut path=root.to_path_buf();
 for component in rel.split('/') {
  path.push(component);
  let meta=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
  if meta.file_type().is_symlink(){return Err("Guard compatibility symlink refused".into())}
 }
 let st=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
 if !st.is_file() || st.len()>max{return Err("Guard compatibility unsafe artifact".into())}
 Ok(())
}
fn actual_sha(path:&Path)->Result<String,String>{
 let meta=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
 if !meta.is_file() || meta.file_type().is_symlink() || meta.len()>512*1024*1024 {return Err("Guard compatibility artifact invalid".into())}
 let mut f=fs::File::open(path).map_err(|e|e.to_string())?;
 let mut digest=Sha256::new();
 let mut buf=[0u8;65536];
 loop{let n=f.read(&mut buf).map_err(|e|e.to_string())?;if n==0{break}digest.update(&buf[..n]);}
 Ok(hex::encode(digest.finalize()))
}
fn normalize_relative(root:&Path,path:&Path)->Result<String,String>{
 let canonical_root=fs::canonicalize(root).map_err(|e|e.to_string())?;
 let absolute=if path.is_absolute(){path.to_path_buf()}else{root.join(path)};
 let canonical_path=fs::canonicalize(&absolute).map_err(|e|e.to_string())?;
 let relative_path=canonical_path.strip_prefix(&canonical_root).map_err(|_|"Guard compatibility agent outside client root")?;
 let parts=relative_path.components().map(|c|match c{Component::Normal(s)=>s.to_string_lossy().to_string(),_=>String::new()}).collect::<Vec<_>>();
 let result=parts.join("/");if !relative(&result){return Err("Guard compatibility invalid agent path".into())}Ok(result)
}
fn require_candidates(root:&Path,dir:&Path,kind:&str,extensions:&[&str],approved:&HashMap<String,String>)->Result<(),String>{
 if !dir.exists(){return Ok(())}
 let mut stack=vec![dir.to_path_buf()];
 while let Some(current)=stack.pop(){
  for item in fs::read_dir(&current).map_err(|e|e.to_string())? {
   let item=item.map_err(|e|e.to_string())?;let meta=fs::symlink_metadata(item.path()).map_err(|e|e.to_string())?;
   if meta.file_type().is_symlink(){return Err("Guard compatibility symlink inside executable tree".into())}
   if meta.is_dir(){stack.push(item.path());continue}
   let name=item.file_name().to_string_lossy().to_ascii_lowercase();
   if extensions.iter().any(|ext|name.ends_with(ext)) {
    let rel=normalize_relative(root,&item.path())?;
    if !approved.contains_key(&format!("{}:{}",kind,rel.to_ascii_lowercase())) {
     return Err(format!("Guard compatibility unauthorized {kind} {rel}"))
    }
   }
  }
 }
 Ok(())
}
/// Rejects native certification of an unscoped game in a root where a
/// signed policy is required. Certification has no project manifest to bind.
pub fn refuse_unscoped_launch(root:&Path)->Result<(),String>{
 if root.join(POLICY).exists() || root.join(FLOOR).exists() || std::env::var(REQUIRED).ok().as_deref()==Some("1") {
  return Err("Guard compatibility cannot authorize unscoped native game certification".into())
 }
 Ok(())
}

/// Enforces scope, revocation, exact allowed artifact bytes, and rejects
/// unknown executable files in controlled Minecraft folders.
pub fn enforce_launch(root:&Path,project:&str,minecraft:&str,loader:&str,jvm_args:&[String])->Result<(),String>{
 let Some(v)=load(root)? else{return Ok(())};
 let p=v.policy;
 for name in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"] {
  if let Ok(value)=std::env::var(name) {
   let lower=value.to_ascii_lowercase();
   if ["-javaagent:","-agentpath:","-agentlib:","-xrunjdwp:"].iter().any(|tok|lower.contains(tok)) {
    return Err(format!("Guard compatibility rejected JVM environment instrumentation from {name}"))
   }
  }
 }
 if p.project_id!=project || p.minecraft!=minecraft || !p.loader.eq_ignore_ascii_case(loader){return Err("Guard compatibility launch scope mismatch".into())}
 let mut approved=HashMap::new();
 for a in &p.artifacts {
  if p.revoked_digests.contains(&a.sha256){return Err(format!("Guard compatibility artifact revoked: {}",a.path))}
  let path=root.join(&a.path);
  // Verify every intermediate path as well as the final inode.
  validate_safe_path(root,&a.path,512*1024*1024)?;
  if actual_sha(&path)?!=a.sha256{return Err(format!("Guard compatibility digest mismatch: {}",a.path))}
  approved.insert(format!("{}:{}",a.kind,a.path.to_ascii_lowercase()),a.sha256.clone());
 }
 for tr in &p.transformations {if p.revoked_transformations.contains(&tr.id) || p.revoked_digests.contains(&tr.owner_sha256){return Err("Guard compatibility transformation revoked".into())}}
 require_candidates(root,&root.join("mods"),"mod",&[".jar"],&approved)?;
 require_candidates(root,&root.join("natives"),"native-library",&[".dll",".so",".dylib",".jnilib"],&approved)?;
 for arg in jvm_args {
  let lower=arg.to_ascii_lowercase();
  if ["-agentpath:","-agentlib:","-xrunjdwp:","-xdebug", "-xx:+startattachlistener"].iter().any(|token|lower.starts_with(token)) {
   return Err("Guard compatibility rejected unapproved JVM instrumentation option".into())
  }
  if let Some(agent)=arg.strip_prefix("-javaagent:") {
   let file=agent.split('=').next().ok_or("empty Guard agent path")?;
   let rel=normalize_relative(root,Path::new(file))?;
   if !approved.contains_key(&format!("java-agent:{}",rel.to_ascii_lowercase())){
    return Err("Guard compatibility unauthorized Java agent".into())
   }
  }
 }
 Ok(())
}
/// Called by Windows Guard before allowing -javaagent. A signed policy is
/// required: ordinary JVM option injection stays forbidden.
pub fn authorize_agent(root:&Path,argument:&str)->Result<bool,String>{
 let Some(v)=load(root)? else{return Ok(false)};
 let Some(value)=argument.strip_prefix("-javaagent:") else{return Ok(false)};
 let file=value.split('=').next().ok_or("empty Java agent")?;
 let rel=normalize_relative(root,Path::new(file))?;
 for a in &v.policy.artifacts {
  if a.kind=="java-agent" && a.path.eq_ignore_ascii_case(&rel) && !v.policy.revoked_digests.contains(&a.sha256) {
   validate_safe_path(root,&a.path,512*1024*1024)?;
   return Ok(actual_sha(&root.join(&a.path))?==a.sha256)
  }
 }
 Ok(false)
}

#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn reject_paths(){for p in ["../a","/tmp/a","C:/x","a\\b","a//b","a/./b","a/../b"]{assert!(!relative(p),"{p}")}}
 #[test]fn sha_validation(){assert!(is_sha(&"f".repeat(64)));assert!(!is_sha(&"F".repeat(64)))}
}
