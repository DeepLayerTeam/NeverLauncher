//! Делегированное доверие к игре, подписанное корнем. В отличие от TUF это политика одной
//! роли, не заявляющая ролей timestamp/snapshot или совместимости с TUF.
use crate::{file_ownership, platform_fs, Manifest};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::{Path,PathBuf},time::{SystemTime,UNIX_EPOCH}};

const DOMAIN: &str = "launcher.trust.v1";
const DOMAIN_SEPARATION: &[u8] = b"Launcher-Trust-Policy-v1\n";

#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Envelope { schema_version: String, payload: String, root_signature: String }
#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Policy { schema_version: String, domain: String, epoch: u64, issued_at: String, expires_at: String, keys: Vec<Key> }
#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Key { id: String, role: String, public_key: String, status: String, not_before: String, #[serde(default)] verify_until: String }
#[derive(Serialize,Deserialize,Clone)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Watermark { epoch: u64, digest: String, root_sha256: String }

fn parse_utc(timestamp: &str) -> Result<i64,String> {
    let x=timestamp.as_bytes();
    if x.len()!=20 || x[4]!=b'-' || x[7]!=b'-' || x[10]!=b'T' || x[13]!=b':' || x[16]!=b':' || x[19]!=b'Z' {return Err("Временная метка доверия должна иметь канонический формат YYYY-MM-DDTHH:MM:SSZ".into())}
    let num=|from:usize,to:usize| -> Result<i64,String> {
        let b=&x[from..to];if !b.iter().all(u8::is_ascii_digit) {return Err("Некорректная цифра в отметке времени политики доверия".into())}
        std::str::from_utf8(b).unwrap().parse::<i64>().map_err(|e|e.to_string())
    };
    let (y,m,d,h,min,sec)=(num(0,4)?,num(5,7)?,num(8,10)?,num(11,13)?,num(14,16)?,num(17,19)?);
    if y<1970 || !(1..=12).contains(&m) || h>23 || min>59 || sec>59 {return Err("Некорректные поля отметки времени политики доверия".into())}
    let leap=y%4==0&&(y%100!=0||y%400==0);
    let days=[31,if leap {29}else{28},31,30,31,30,31,31,30,31,30,31];
    if d<1 || d>days[(m-1) as usize] {return Err("Некорректный день в отметке времени политики доверия".into())}
    // Количество дней от гражданской даты по пролептическому григорианскому календарю относительно эпохи Unix.
    let yy=y-i64::from(m<=2);let era=yy.div_euclid(400);let yoe=yy-era*400;
    let mp=m+if m>2 {-3}else{9};let doy=(153*mp+2)/5+d-1;
    let doe=yoe*365+yoe/4-yoe/100+doy;
    Ok((era*146097+doe-719468)*86400+h*3600+min*60+sec)
}
fn now() -> Result<i64,String> {SystemTime::now().duration_since(UNIX_EPOCH).map(|n|n.as_secs() as i64).map_err(|e|e.to_string())}
fn verify_signature(key_hex:&str,payload:&[u8],sig_hex:&str)->Result<(),String>{
    let bytes: [u8;32]=hex::decode(key_hex).map_err(|e|e.to_string())?.try_into().map_err(|_|"Неверная длина открытого ключа Ed25519".to_string())?;
    let signature: [u8;64]=hex::decode(sig_hex).map_err(|e|e.to_string())?.try_into().map_err(|_|"Неверная длина подписи Ed25519".to_string())?;
    let key=VerifyingKey::from_bytes(&bytes).map_err(|e|e.to_string())?;
    key.verify(payload,&Signature::from_bytes(&signature)).map_err(|_|"Некорректная подпись политики доверия корневым ключом".to_string())
}
fn read_policy(root_key:&str)->Result<(Policy,String),String>{
    // Выбор пути не выбирает корень доверия: он выбирает только байты, проверенные
    // отдельным закреплённым корневым ключом вызывающей стороны.
    let path=std::env::var("LAUNCHER_GAME_TRUST_POLICY_FILE").map_err(|_|"Не указан путь к делегированной политике доверия игры".to_string())?;
    let path=Path::new(&path);
    let meta=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len()>128*1024 {return Err("Небезопасный файл политики доверия игры".into())}
    let raw=fs::read(path).map_err(|e|e.to_string())?;
    let env:Envelope=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    if env.schema_version!="1.0" {return Err("Неизвестное значение: конверт политики доверия".into())}
    let payload=STANDARD.decode(&env.payload).map_err(|e|e.to_string())?;
    if payload.len()>96*1024 {return Err("Данные политики доверия превышают допустимый размер".into())}
    let mut signed=DOMAIN_SEPARATION.to_vec();signed.extend_from_slice(&payload);
    verify_signature(root_key,&signed,&env.root_signature)?;
    let p:Policy=serde_json::from_slice(&payload).map_err(|e|e.to_string())?;
    if p.schema_version!="1.0" || p.domain!=DOMAIN || p.epoch==0 || p.keys.is_empty() || p.keys.len()>128 {return Err("Некорректный домен, версия или ключи политики доверия".into())}
    let issued=parse_utc(&p.issued_at)?;let expires=parse_utc(&p.expires_at)?;let current=now()?;
    if issued>current+300 || expires<=current || expires<=issued || expires-issued>90*86400 {return Err("Политика доверия заморожена, просрочена или имеет недопустимый срок действия".into())}
    let mut seen=std::collections::HashSet::new();
    for k in &p.keys {
        if k.id.is_empty() || k.id.len()>100 || !["game","component","bootstrap","release"].contains(&k.role.as_str()) || !["active","verify-only","revoked"].contains(&k.status.as_str()) {return Err("Некорректная роль или состояние ключа доверия".into())}
        if hex::decode(&k.public_key).map_err(|e|e.to_string())?.len()!=32 || !seen.insert(k.public_key.to_ascii_lowercase()) {return Err("Повторяющийся или некорректный ключ доверия".into())}
        let start=parse_utc(&k.not_before)?;if start>expires{return Err("Ключ доверия начинает действовать после истечения срока политики".into())}
        if k.status=="verify-only" {let end=parse_utc(&k.verify_until)?;if end<=start || end>expires || end-start>90*86400 {return Err("Некорректный период одновременного действия ключей".into())}}
    }
    Ok((p,hex::encode(Sha256::digest(&payload))))
}

pub fn verify_manifest(manifest:&Manifest,root_key:&str,signer_hex:&str,signed_at:&str)->Result<(),String>{
    if manifest.trust_epoch==0 {
        if std::env::var_os("LAUNCHER_GAME_TRUST_POLICY_FILE").is_some() {
            return Err("Старый манифест отклонён после настройки политики игры с корневой подписью".into());
        }
        return Ok(())
    }
    let (p,_)=read_policy(root_key)?;
    if manifest.trust_epoch>p.epoch {return Err("Будущая эпоха доверия манифеста игры не разрешена корневым ключом".into())}
    let signed=parse_utc(signed_at)?;let current=now()?;
    if signed>current+300 {return Err("Дата подписи игры находится в будущем".into())}
    for k in &p.keys {
        if k.role!="game" || !k.public_key.eq_ignore_ascii_case(signer_hex) {continue}
        if k.status=="revoked" {return Err("Ключ подписи игры отозван".into())}
        if signed<parse_utc(&k.not_before)? {return Err("Подпись игры создана до делегирования полномочий".into())}
        if k.status=="verify-only" {
            let end=parse_utc(&k.verify_until)?;
            if signed>=end || current>=end {return Err("Истёк период одновременного действия подписывающих ключей игры".into())}
        }
        return Ok(())
    }
    Err("Встроенный корневой ключ не делегировал полномочия подписанту игры".into())
}
fn dir(root:&Path)->PathBuf{root.join(".launcher").join("game-trust")}
fn slot(root:&Path,i:usize)->PathBuf{dir(root).join(format!("epoch-{i}.json"))}
fn floor(root:&Path)->Result<Option<Watermark>,String>{
    let mut best:Option<Watermark>=None;
    for i in 0..2 {
        let f=slot(root,i);file_ownership::ensure_no_symlinks(root,&f)?;
        match fs::symlink_metadata(&f) {
            Ok(m)=>{if !m.is_file() || m.len()>4096 {return Err("Повреждена метка эпохи доверия игры".into())}
                let current:Watermark=serde_json::from_slice(&fs::read(&f).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
                if current.epoch==0 || current.digest.len()!=64 || current.root_sha256.len()!=64 {return Err("Некорректная контрольная отметка доверия игры".into())}
                if let Some(ref prev)=best {if current.epoch==prev.epoch && current.digest!=prev.digest {return Err("Обнаружено противоречие в политике доверия игры".into())}}
                if best.as_ref().is_none_or(|v|current.epoch>v.epoch){best=Some(current)}
            },
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
            Err(e)=>return Err(e.to_string()),
        }
    }
    Ok(best)
}
pub fn check(root:&Path,manifest:&Manifest,root_key:&str)->Result<(),String>{
    let accepted=floor(root)?;
    if manifest.trust_epoch==0 {
        if accepted.is_some(){return Err("Старая подпись игры заблокирована после включения делегированного доверия".into())}
        return Ok(())
    }
    let (policy,digest)=read_policy(root_key)?;
    if policy.epoch!=manifest.trust_epoch {return Err("Новая установка игры должна использовать текущую эпоху доверия с корневой подписью".into())}
    let signer=manifest.signature.as_ref().ok_or("Подпись игры отсутствует")?;
    if !policy.keys.iter().any(|k|k.role=="game" && k.status=="active" && k.public_key.eq_ignore_ascii_case(&signer.public_key)) {
       return Err("Нельзя устанавливать новый релиз с помощью выведенного из эксплуатации или отозванного ключа подписи игры".into());
    }
    if let Some(stored)=accepted {
        if stored.epoch>policy.epoch || (stored.epoch==policy.epoch && stored.digest!=digest) || stored.root_sha256!=hex::encode(Sha256::digest(hex::decode(root_key).map_err(|e|e.to_string())?)) {return Err("Обнаружен откат, конфликт политики доверия или изменение корневого ключа игры".into())}
    }
    Ok(())
}
pub fn check_launch(root:&Path,manifest:&Manifest,root_key:&str)->Result<(),String>{
    let accepted=floor(root)?;
    if manifest.trust_epoch==0 {
        if accepted.is_some(){return Err("Старый релиз игры запрещён после включения делегированного доверия".into())}
        return Ok(())
    }
    let (p,_)=read_policy(root_key)?;
    if manifest.trust_epoch>p.epoch {return Err("Релиз игры ссылается на будущую политику доверия".into())}
    if let Some(stored)=accepted {
       let pubkey=hex::decode(root_key).map_err(|e|e.to_string())?;
       if stored.root_sha256!=hex::encode(Sha256::digest(pubkey)) {return Err("Обнаружено изменение: корневой ключ доверия игры".into())}
    }
    Ok(())
}
pub fn accept(root:&Path,manifest:&Manifest,root_key:&str)->Result<(),String>{
    // Восстановление ранее проверенного установленного выпуска не должно откатывать максимальную
    // отметку доверия; более новая политика всё ещё может разрешить его запуск.
    check_launch(root,manifest,root_key)?;
    if manifest.trust_epoch==0 {return Ok(())}
    if floor(root)?.as_ref().is_some_and(|r|r.epoch>manifest.trust_epoch){return Ok(())}
    check(root,manifest,root_key)?;
    if floor(root)?.as_ref().is_some_and(|r|r.epoch==manifest.trust_epoch){return Ok(())}
    let (_,digest)=read_policy(root_key)?;
    let key=hex::decode(root_key).map_err(|e|e.to_string())?;
    let record=Watermark{epoch:manifest.trust_epoch,digest,root_sha256:hex::encode(Sha256::digest(key))};
    fs::create_dir_all(dir(root)).map_err(|e|e.to_string())?;
    let target=slot(root,(record.epoch%2) as usize);
    file_ownership::ensure_no_symlinks(root,&target)?;
    let temp=dir(root).join(format!("epoch-{:x}.tmp",rand::random::<u64>()));
    let result=(||->Result<(),String>{
        let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&temp).map_err(|e|e.to_string())?;
        f.write_all(&serde_json::to_vec(&record).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        f.sync_all().map_err(|e|e.to_string())?;drop(f);
        platform_fs::replace_file(root,&temp,&target)?;
        #[cfg(unix)] fs::File::open(dir(root)).and_then(|d|d.sync_all()).map_err(|e|e.to_string())?;
        Ok(())
    })();if result.is_err(){let _=fs::remove_file(temp);}result
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn utc_parser_handles_epoch_and_leap_day(){
  assert_eq!(parse_utc("1970-01-01T00:00:00Z").unwrap(),0);
  assert_eq!(parse_utc("2024-03-01T00:00:00Z").unwrap()-parse_utc("2024-02-29T00:00:00Z").unwrap(),86400);
  assert!(parse_utc("2023-02-29T00:00:00Z").is_err());
  assert!(parse_utc("2026-10-19T09:00:00+01:00").is_err());
 }
}
