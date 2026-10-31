//! Native verification of the exact owner-signed Prestarter bootstrap bytes.
//! The renderer, localStorage, desktop config and URL parameters are NEVER trust roots.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Envelope {
    schema_version:String, payload:String, signature:String,
    #[serde(default)] key_id:String, #[serde(default)] trust_epoch:u64,
    #[serde(default)] signed_at:String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct PolicyEnvelope { schema_version:String, payload:String, root_signature:String }
#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Policy { schema_version:String,domain:String,epoch:u64,issued_at:String,expires_at:String,keys:Vec<PolicyKey> }
#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct PolicyKey {id:String, role:String, public_key:String, status:String, not_before:String, #[serde(default)]verify_until:String}
#[derive(Debug, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Bootstrap {
    schema_version:String,project_id:String,profile_id:String,channel:String,
    #[serde(default)]backend_url:String,profile_public_key:String,
    #[serde(default)]server_id:String,#[serde(default)]server_host:String,
    #[serde(default)]server_port:u16,#[serde(default)]auto_enter:bool,
    manifest:serde_json::Value,java_manifest:serde_json::Value,targets:serde_json::Value,
    #[serde(default)]branding:Option<Branding>,
    #[serde(default)]installer_targets:Option<serde_json::Value>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct BrandNews0355 {title:String,url:String}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct Branding {display_name:String,publisher:String,#[serde(default)] website_url:String,
    #[serde(default)] accent_color:String, #[serde(default)] background_color:String,
    #[serde(default)] text_color:String, #[serde(default)] logo_png:String,
    #[serde(default)] icon_png:String, #[serde(default)] splash_png:String,
    #[serde(default)] locale:String, #[serde(default)] news:Vec<BrandNews0355>}
fn validate_brand0355(b:&Branding)->Result<(),String>{
    if b.display_name.is_empty()||b.display_name.len()>80||b.publisher.is_empty()||b.publisher.len()>96||
        b.display_name.chars().chain(b.publisher.chars()).any(|c|c.is_control()) ||
        (!b.website_url.is_empty()&&!https_url(&b.website_url)) {return Err("Недопустимое подписанное имя/сайт бренда".into())}
    for c in [&b.accent_color,&b.background_color,&b.text_color]{
        if !c.is_empty() && (c.len()!=7 || !c.starts_with('#')||!c[1..].bytes().all(|v|v.is_ascii_hexdigit())){
            return Err("Неверный подписанный цвет #RRGGBB".into())
        }
    }
    if !b.locale.is_empty()&&b.locale!="ru"&&b.locale!="en" {return Err("Неподдерживаемая локализация бренда".into())}
    for (name,image) in [("logo",&b.logo_png),("icon",&b.icon_png),("splash",&b.splash_png)]{
        if image.is_empty(){continue}
        if image.len()>174_764{return Err("PNG превышает предел".into())}
        let raw=STANDARD.decode(image).map_err(|_|"Некорректный PNG base64")?;
        if raw.len()<24||raw.len()>131_072||!raw.starts_with(b"\x89PNG\r\n\x1a\n")||&raw[12..16]!=b"IHDR"{
            return Err("Изображение должно быть встроенным PNG".into())
        }
        let width=u32::from_be_bytes(raw[16..20].try_into().map_err(|_|"PNG размер")?);
        let height=u32::from_be_bytes(raw[20..24].try_into().map_err(|_|"PNG размер")?);
        let (maxw,maxh)=if name=="splash"{(2048,1200)}else{(1024,1024)};
        if raw[8..12]!=[0,0,0,13]||width==0||height==0||width>maxw||height>maxh{
            return Err("PNG имеет недопустимые размеры".into())
        }
    }
    if b.news.len()>5{return Err("Слишком много новостей".into())}
    for item in &b.news{
        if item.title.is_empty()||item.title.len()>120||item.title.chars().any(|c|c.is_control())||!https_url(&item.url){
            return Err("Недопустимая ссылка подписанной новости".into())
        }
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub struct Provisioning0352 {
    pub backend_url:String,pub project_id:String,pub profile_id:String,pub channel:String,
    pub manifest_url:String,pub pinned_public_key:String,pub display_name:String,
    pub server_id:String,pub server_host:String,pub server_port:u16,pub auto_enter:bool,
    pub digest:String, pub branding:Option<Branding>,
}
fn safe_file(path:&Path,max:u64)->Result<Vec<u8>,String>{
    let meta=fs::symlink_metadata(path).map_err(|e|format!("{}: {e}",path.display()))?;
    if !meta.file_type().is_file() || meta.len()>max {return Err("Недопустимый тип или размер файла signed bootstrap".into())}
    fs::read(path).map_err(|e|e.to_string())
}
fn bytes_hex(value:&str,len:usize)->Result<Vec<u8>,String>{
    let raw=hex::decode(value).map_err(|_|"Некорректный hex в подписи или ключе")?;
    if raw.len()!=len{return Err("Некорректная длина ключа или подписи".into())} Ok(raw)
}
fn verify(payload:&[u8],pubkey:&[u8],sig:&str)->Result<(),String>{
    let raw=bytes_hex(sig,64)?;
    let key=VerifyingKey::from_bytes(&pubkey.try_into().map_err(|_|"Неверная длина Ed25519 ключа")?)
        .map_err(|_|"Недействительный Ed25519 ключ")?;
    let sig=Signature::from_bytes(&raw.try_into().map_err(|_|"Недействительная подпись")?);
    key.verify(payload,&sig).map_err(|_|"Подпись bootstrap не прошла проверку Ed25519".into())
}
fn time_value(s:&str)->Result<OffsetDateTime,String>{
    if s.len()!=20 || !s.ends_with('Z') {return Err("Требуется UTC timestamp RFC3339 без дробной части".into())}
    OffsetDateTime::parse(s,&Rfc3339).map_err(|_|"Некорректное время политики".into())
}
fn identifier(s:&str)->bool{
    !s.is_empty()&&s.len()<=96&&s!="."&&s!=".."&&!s.ends_with('.')&&!s.ends_with(' ')&&
    s.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'_'|b'-'|b'.'))
}
fn https_url(s:&str)->bool {
    // Validated again by native HTTP and signed manifest verification; reject
    // userinfo, fragments, control chars and ambiguous/relative URL forms here.
    if !s.starts_with("https://") || s.len()>2048 || s.bytes().any(|c|c<=32||c==127||c==b'#'||c==b'\\') {return false}
    let authority=s[8..].split('/').next().unwrap_or("");
    !authority.is_empty()&&!authority.contains('@')&&!authority.starts_with(':')
}
fn valid_server_host(host:&str)->bool{
    host.len()<=253 && host.split('.').all(|part|!part.is_empty()&&part.len()<=63&&
        !part.starts_with('-')&&!part.ends_with('-')&&part.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'))
}
fn valid_manifest_artifact(v:&serde_json::Value)->bool{
    v.get("url").and_then(|x|x.as_str()).map(https_url)==Some(true)&&
    v.get("sha256").and_then(|x|x.as_str()).map(|s|bytes_hex(s,32).is_ok())==Some(true)&&
    v.get("size").and_then(|x|x.as_i64()).map(|s|s>0&&s<=16*1024*1024)==Some(true)
}
fn verified_policy(dir:&Path,root:&[u8],now:OffsetDateTime)->Result<Policy,String>{
    let policy_raw=safe_file(&dir.join("trust-policy.signed.json"),128*1024)?;
    let env:PolicyEnvelope=serde_json::from_slice(&policy_raw).map_err(|_|"Некорректный signed trust policy")?;
    if env.schema_version!="1.0"{return Err("Неподдерживаемая версия trust policy".into())}
    let payload=STANDARD.decode(&env.payload).map_err(|_|"Некорректный payload trust policy")?;
    if payload.len()>96*1024{return Err("Trust policy слишком велик".into())}
    let mut msg=b"Launcher-Trust-Policy-v1\n".to_vec();msg.extend_from_slice(&payload);
    verify(&msg,root,&env.root_signature)?;
    let policy:Policy=serde_json::from_slice(&payload).map_err(|_|"Некорректная структура trust policy")?;
    if policy.schema_version!="1.0"||policy.domain!="launcher.trust.v1"||policy.epoch==0||policy.keys.is_empty()||policy.keys.len()>128 {
        return Err("Некорректный домен или epoch trust policy".into())
    }
    let issued=time_value(&policy.issued_at)?;let expires=time_value(&policy.expires_at)?;
    if issued>now+time::Duration::minutes(5)||expires<=now||expires<=issued||expires-issued>time::Duration::days(90){
        return Err("Trust policy истекла или некорректна".into())
    }
    let mut ids=std::collections::HashSet::new();let mut pubs=std::collections::HashSet::new();
    let mut active=0;
    for k in &policy.keys {
        if !identifier(&k.id)||!ids.insert(&k.id)||!pubs.insert(k.public_key.to_lowercase())||bytes_hex(&k.public_key,32).is_err()||
           !matches!(k.role.as_str(),"bootstrap"|"game"|"component"|"release")||
           !matches!(k.status.as_str(),"active"|"verify-only"|"revoked")||time_value(&k.not_before)? > expires {
            return Err("Некорректный набор delegated keys".into())
        }
        if k.status=="active"{active+=1}
        if k.status=="verify-only"{
            let end=time_value(&k.verify_until)?;let begin=time_value(&k.not_before)?;
            if end<=begin||end-begin>time::Duration::days(90)||end>expires{return Err("Недопустимый verify-only overlap".into())}
        }
    }
    if active==0{return Err("Отсутствуют активные ключи".into())}
    Ok(policy)
}
fn verify_signed(raw:&[u8], policy_dir:&Path, root_hex:&str, now:OffsetDateTime)->Result<Provisioning0352,String>{
    if raw.len()>1024*1024{return Err("Bootstrap слишком велик".into())}
    let root=bytes_hex(root_hex,32)?;
    let env:Envelope=serde_json::from_slice(raw).map_err(|_|"Некорректный signed bootstrap envelope")?;
    if env.schema_version!="1.0"&&env.schema_version!="2.0" {return Err("Неизвестная версия bootstrap envelope".into())}
    if env.schema_version=="1.0" && policy_dir.join("trust-policy.signed.json").symlink_metadata().is_ok() {
        return Err("Legacy bootstrap после delegated trust запрещён".into())
    }
    let payload=STANDARD.decode(&env.payload).map_err(|_|"Некорректный base64 bootstrap")?;
    if payload.len()>1024*1024{return Err("Payload слишком велик".into())}
    let mut signing_key=root.clone();
    let mut signed_bytes=payload.clone();
    if env.schema_version=="2.0" {
        let policy=verified_policy(policy_dir,&root,now)?;
        if env.key_id.is_empty()||env.trust_epoch!=policy.epoch{return Err("Bootstrap signer/epoch mismatch".into())}
        let signed_at=time_value(&env.signed_at)?;
        let key=policy.keys.iter().find(|k|k.id==env.key_id&&k.role=="bootstrap"&&k.status=="active")
            .ok_or("Bootstrap signer не активен в root-signed policy")?;
        if signed_at<time_value(&key.not_before)?||signed_at>now+time::Duration::minutes(5){return Err("Bootstrap подписан вне разрешённого интервала".into())}
        signing_key=bytes_hex(&key.public_key,32)?;
        signed_bytes=format!("Launcher-Bootstrap-v2\n{}\n{}\n{}\n",env.key_id,env.trust_epoch,env.signed_at).into_bytes();
        signed_bytes.extend_from_slice(&payload);
    }
    verify(&signed_bytes,&signing_key,&env.signature)?;
    let cfg:Bootstrap=serde_json::from_slice(&payload).map_err(|_|"Неверная структура bootstrap config")?;
    if cfg.schema_version!="1.0"||!identifier(&cfg.project_id)||!identifier(&cfg.profile_id)||!identifier(&cfg.channel)||
       !https_url(&cfg.backend_url)||!valid_manifest_artifact(&cfg.manifest)||!valid_manifest_artifact(&cfg.java_manifest)||
       !cfg.targets.is_array()||cfg.targets.as_array().map(|a|a.is_empty()).unwrap_or(true)||
       bytes_hex(&cfg.profile_public_key,32).is_err()||
       (!cfg.server_id.is_empty()&&!identifier(&cfg.server_id))||
       (cfg.auto_enter&&(cfg.server_id.is_empty()||cfg.server_host.is_empty()||cfg.server_port==0))||
       (!cfg.server_host.is_empty() && !valid_server_host(&cfg.server_host)) {
        return Err("Некорректный signed bootstrap payload".into())
    }
    if env.schema_version=="2.0"&&!cfg.profile_public_key.eq_ignore_ascii_case(root_hex){
        return Err("Delegated bootstrap требует profilePublicKey=root".into())
    }
    // Config is signed by the operator; only its verified fields are authoritative.
    if let Some(ref brand)=cfg.branding {validate_brand0355(brand)?;}
    let display=cfg.branding.as_ref().map(|b|b.display_name.clone()).unwrap_or_else(||"Launcher".into());
    let _=&cfg.installer_targets;
    let digest=hex::encode(Sha256::digest(&payload));
    Ok(Provisioning0352{backend_url:cfg.backend_url,project_id:cfg.project_id,profile_id:cfg.profile_id,
        channel:cfg.channel,manifest_url:cfg.manifest["url"].as_str().unwrap_or_default().into(),
        pinned_public_key:cfg.profile_public_key,display_name:display,digest,branding:cfg.branding,
        server_id:cfg.server_id,server_host:cfg.server_host,server_port:cfg.server_port,auto_enter:cfg.auto_enter})
}

pub fn load(dir:&Path)->Result<Option<Provisioning0352>,String>{
    let file=dir.join("bootstrap.signed.json");
    match fs::symlink_metadata(&file) {
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
        Err(e)=>return Err(e.to_string()),
        Ok(_)=>{},
    }
    // Production root is compiled into the Desktop binary. Never accept a
    // root key supplied by renderer, local config, query string or process env.
    let root=option_env!("NEVERLAUNCHER_BOOTSTRAP_ROOT_KEY").unwrap_or("");
    if root.is_empty(){return Err("Desktop не содержит закреплённый bootstrap Ed25519 root; необходима branded production сборка".into())}
    let raw=safe_file(&file,1024*1024)?;
    let now=OffsetDateTime::from(SystemTime::now());
    verify_signed(&raw,dir,root,now).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer,SigningKey};
    #[test]
    fn verify_owner_signed_real_payload_and_tamper(){
        let key=SigningKey::from_bytes(&[42u8;32]);
        let root=hex::encode(key.verifying_key().to_bytes());
        let artifact=serde_json::json!({"url":"https://example.org/manifest.json","sha256":"ab".repeat(32),"size":120});
        let payload=serde_json::json!({"schemaVersion":"1.0","projectId":"my-project","profileId":"fabric","channel":"stable", "backendUrl":"https://example.org", "profilePublicKey":root,"branding":{"displayName":"My Server","publisher":"Operator","accentColor":"#22c55e","backgroundColor":"#0f172a","textColor":"#ffffff","locale":"ru","news":[{"title":"News","url":"https://example.org/news"}]},"manifest":artifact,"javaManifest":artifact,"targets":[{"os":"linux","arch":"amd64","components":[]}]}).to_string();
        let signature=hex::encode(key.sign(payload.as_bytes()).to_bytes());
        let env=serde_json::json!({"schemaVersion":"1.0","payload":STANDARD.encode(payload.as_bytes()),"signature":signature});
        let raw=serde_json::to_vec(&env).unwrap();
        let trusted=verify_signed(&raw,Path::new("."),&root,OffsetDateTime::now_utc()).unwrap();
        assert_eq!(trusted.project_id,"my-project");
        assert_eq!(trusted.display_name,"My Server");
        assert_eq!(trusted.branding.as_ref().unwrap().news.len(),1);
        let bad_key="cd".repeat(32);
        assert!(verify_signed(&raw,Path::new("."),&bad_key,OffsetDateTime::now_utc()).is_err());
        let mut broken=env.clone();broken["payload"]=serde_json::json!(STANDARD.encode(payload.replace("my-project","other-project")));
        assert!(verify_signed(&serde_json::to_vec(&broken).unwrap(),Path::new("."),&root,OffsetDateTime::now_utc()).is_err());
    }
    #[test]
    fn unsafe_signed_brand_is_rejected(){
        let mut brand=Branding{display_name:"Launcher".into(),publisher:"Publisher".into(),
            website_url:"https://example.org".into(),accent_color:"#11aa33".into(),
            background_color:String::new(),text_color:String::new(),logo_png:String::new(),
            icon_png:String::new(),splash_png:String::new(),locale:"ru".into(),news:vec![]};
        assert!(validate_brand0355(&brand).is_ok());
        brand.accent_color="red;url(https://evil.test)".into();assert!(validate_brand0355(&brand).is_err());
        brand.accent_color="#11aa33".into();brand.logo_png=STANDARD.encode("<svg onload='alert(1)'/>");
        assert!(validate_brand0355(&brand).is_err());
        brand.logo_png.clear();brand.news.push(BrandNews0355{title:"X".into(),url:"javascript:alert(1)".into()});
        assert!(validate_brand0355(&brand).is_err());
    }
    #[test]
    fn reject_unsafe_identity_and_url(){
        assert!(!identifier("../other"));assert!(!identifier(""));assert!(!https_url("http://example.org"));
        assert!(!https_url("https://user:pass@example.org"));assert!(!https_url("https://example.org/#fragment"));
    }
}
