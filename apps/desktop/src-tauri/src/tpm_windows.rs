//! Windows TPM2_Certify через дескрипторы ключей CNG с поддержкой PCP и интерфейс TBS. Ключ AK должен быть
//! предварительно подготовлен удостоверяющим центром, проверяющим происхождение TPM. Синтетические доказательства
//! и утверждения о доверии только по имени провайдера Windows не возвращаются.
use crate::tpm_wire_0313::{certify_command,parse_certify_response,parse_public_response,read_public_command};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use std::ptr;

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct WindowsTPMEvidence0313 {
    pub tpm2b_public: String,
    pub tpm2b_attest: String,
    pub tpmt_signature: String,
    pub ak_certificate_pem: String,
    pub intermediates_pem: Vec<String>,
}

#[link(name="Ncrypt")]
extern "system" {
    fn NCryptOpenStorageProvider(provider: *mut usize, name: *const u16, flags: u32) -> i32;
    fn NCryptOpenKey(provider: usize, key: *mut usize, name: *const u16, legacy: u32, flags: u32) -> i32;
    fn NCryptGetProperty(handle: usize, property: *const u16, output: *mut u8, output_len: u32, result: *mut u32, flags: u32) -> i32;
    fn NCryptFreeObject(handle: usize) -> i32;
}
#[link(name="Tbs")]
extern "system" {
    fn Tbsip_Submit_Command(context: usize, locality: u32, priority: u32, command: *const u8,
                            command_len: u32, output: *mut u8, result_len: *mut u32) -> u32;
}
const PCP: &str = "Microsoft Platform Crypto Provider";
const PLATFORM_HANDLE: &str = "PCP_PLATFORMHANDLE";
fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

struct OwnedNCrypt(usize);
impl Drop for OwnedNCrypt { fn drop(&mut self) { if self.0 != 0 { unsafe { NCryptFreeObject(self.0); } } } }
fn check(status: i32, where_: &str) -> Result<(),String> {
    if status != 0 { Err(format!("{where_}: NCrypt 0x{:08x}",status as u32)) } else { Ok(()) }
}
fn open_provider() -> Result<OwnedNCrypt,String> {
    let mut handle = 0;
    check(unsafe { NCryptOpenStorageProvider(&mut handle,wide(PCP).as_ptr(),0) },"Провайдер платформы TPM недоступен")?;
    if handle == 0 { return Err("Пустой дескриптор PCP".into()); }
    Ok(OwnedNCrypt(handle))
}
fn open_key(p: &OwnedNCrypt, name: &str, flags: u32) -> Result<OwnedNCrypt,String> {
    if name.is_empty() || name.len() > 250 || name.contains('\0') { return Err("Некорректное имя ключа PCP".into()); }
    let mut handle = 0;
    check(unsafe { NCryptOpenKey(p.0,&mut handle,wide(name).as_ptr(),0,flags) },"Именованный ключ TPM PCP не найден")?;
    if handle == 0 { return Err("Пустой дескриптор ключа PCP".into()); }
    Ok(OwnedNCrypt(handle))
}
fn property(handle: usize, name: &str, limit: usize) -> Result<Vec<u8>,String> {
    let prop = wide(name);
    let mut n: u32 = 0;
    check(unsafe { NCryptGetProperty(handle,prop.as_ptr(),ptr::null_mut(),0,&mut n,0) },"Размер свойства PCP")?;
    if n == 0 || n as usize > limit { return Err("Неожиданное значение: размер свойства PCP".into()); }
    let mut out = vec![0u8;n as usize];
    check(unsafe { NCryptGetProperty(handle,prop.as_ptr(),out.as_mut_ptr(),n,&mut n,0) },"Ошибка чтения свойства PCP")?;
    out.truncate(n as usize);
    Ok(out)
}
fn key_handle(key: &OwnedNCrypt) -> Result<u32,String> {
    let value = property(key.0, PLATFORM_HANDLE, 16)?;
    if value.len() != 4 && value.len() != 8 { return Err("Не поддерживается: кодирование дескриптора ключа TPM PCP".into()); }
    let h = u32::from_le_bytes(value[..4].try_into().map_err(|_|"Некорректное значение: дескриптор ключа")?);
    if !(0x8000_0000..=0x80ff_ffff).contains(&h) { return Err("PCP не вернул загруженный временный объект TPM".into()); }
    Ok(h)
}
fn context_handle(provider: &OwnedNCrypt) -> Result<usize,String> {
    let value = property(provider.0, PLATFORM_HANDLE, 16)?;
    if value.len() != std::mem::size_of::<usize>() { return Err("Неожиданное значение: размер дескриптора контекста TBS".into()); }
    let mut bytes = [0u8;std::mem::size_of::<usize>()]; bytes.copy_from_slice(&value);
    let h = usize::from_ne_bytes(bytes);
    if h == 0 { return Err("Отсутствует: контекст TBS".into()); }
    Ok(h)
}
fn submit(context: usize, bytes: &[u8]) -> Result<Vec<u8>,String> {
    let mut result = vec![0u8;16384];
    let mut length = result.len() as u32;
    let status = unsafe { Tbsip_Submit_Command(context,0,200,bytes.as_ptr(),bytes.len() as u32,result.as_mut_ptr(),&mut length) };
    if status != 0 { return Err(format!("Ошибка: отправка команды через TBS: 0x{status:08x}")); }
    if length < 10 || length as usize > result.len() { return Err("TBS вернул некорректную длину кадра TPM".into()); }
    result.truncate(length as usize);
    Ok(result)
}

pub fn certify(
    device_key_name: &str, registered_sec1: &[u8], extra_b64url: &str,
    ak_key_name: &str, ak_certificate_pem: &str, intermediates_pem: Vec<String>
) -> Result<WindowsTPMEvidence0313,String> {
    let extra = URL_SAFE_NO_PAD.decode(extra_b64url)
        .map_err(|_|"Некорректное значение: проверочные данные TPM от серверной части")?;
    let extra: [u8;32] = extra.try_into().map_err(|_|"Проверочные данные TPM должны содержать 32 байта")?;
    if registered_sec1.len() != 65 || registered_sec1[0] != 4 { return Err("Требуется зарегистрированный ключ устройства P-256".into()); }
    if ak_key_name == device_key_name { return Err("Ключ AK и проверяемый субъект: требуется разные ключи TPM".into()); }
    if ak_certificate_pem.len() > 16384 || !ak_certificate_pem.contains("-----BEGIN CERTIFICATE-----") ||
       !ak_certificate_pem.contains("-----END CERTIFICATE-----") ||
       intermediates_pem.len() > 8 || intermediates_pem.iter().any(|p| p.len() > 16384) {
        return Err("Некорректное значение: материалы инициализации сертификата X.509 для AK".into());
    }
    let provider = open_provider()?;
    let subject = open_key(&provider,device_key_name,0)?;
    // Корпоративные AIK часто регистрируются в пространстве машинных ключей.
    // Выполняйте Certify только с AK, сертифицированным издателем; ни одному
    // пространству нельзя доверять только из-за успеха NCryptOpenKey.
    let ak = open_key(&provider,ak_key_name,0)
        .or_else(|_| open_key(&provider,ak_key_name,0x20))?; // NCRYPT_MACHINE_KEY_FLAG
    let subject_handle = key_handle(&subject)?;
    let ak_handle = key_handle(&ak)?;
    if subject_handle == ak_handle { return Err("Дескрипторы AK и проверяемого объекта TPM совпадают".into()); }
    let tbs = context_handle(&provider)?;
    let pub_response = submit(tbs,&read_public_command(subject_handle))?;
    let (public, actual_sec1) = parse_public_response(&pub_response)?;
    if actual_sec1.as_slice() != registered_sec1 { return Err("объект TPM, управляемый PCP не совпадает с зарегистрированный ключ без подтверждения доверия".into()); }
    let response = submit(tbs,&certify_command(subject_handle,ak_handle,&extra))?;
    let (attest,signature) = parse_certify_response(&response,&extra)?;
    Ok(WindowsTPMEvidence0313 {
        tpm2b_public: URL_SAFE_NO_PAD.encode(public),
        tpm2b_attest: URL_SAFE_NO_PAD.encode(attest),
        tpmt_signature: URL_SAFE_NO_PAD.encode(signature),
        ak_certificate_pem: ak_certificate_pem.to_string(),
        intermediates_pem,
    })
}

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct WindowsTPMQuote0315 {
    pub tpm2b_attest: String,
    pub tpmt_signature: String,
    pub pcr_values: std::collections::BTreeMap<String,String>,
    pub ak_certificate_pem: String,
    pub intermediates_pem: Vec<String>,
}
pub fn quote0315(extra_b64url:&str,selection:&str,ak_key_name:&str,
    ak_certificate_pem:&str,intermediates_pem:Vec<String>) -> Result<WindowsTPMQuote0315,String> {
    let data=URL_SAFE_NO_PAD.decode(extra_b64url).map_err(|_|"Некорректное значение: проверочный параметр TPM Quote")?;
    let extra:[u8;32]=data.try_into().map_err(|_|"Проверочный параметр TPM Quote должен содержать 32 байта")?;
    if ak_certificate_pem.len()>16384 || !ak_certificate_pem.contains("-----BEGIN CERTIFICATE-----") ||
       !ak_certificate_pem.contains("-----END CERTIFICATE-----") || intermediates_pem.len()>8 ||
       intermediates_pem.iter().any(|s|s.len()>16384 || !s.contains("-----BEGIN CERTIFICATE-----")) {
        return Err("Требуется: сертифицированный издателем ключ AK".into());
    }
    let indices=crate::tpm_wire_0313::parse_pcr_selection_0315(selection)?;
    let provider=open_provider()?;
    let ak=open_key(&provider,ak_key_name,0).or_else(|_|open_key(&provider,ak_key_name,0x20))?;
    let ak_handle=key_handle(&ak)?;
    let ctx=context_handle(&provider)?;
    let quote=submit(ctx,&crate::tpm_wire_0313::quote_command_0315(ak_handle,&extra,&indices))?;
    let (attest,signature)=crate::tpm_wire_0313::parse_quote_response_0315(&quote,&extra,&indices)?;
    // Вторая операция TPM считывает значения PCR; Backend выявляет гонку,
    // проверяя их хеш на соответствие дайджесту PCR в подписанном Quote.
    let read=submit(ctx,&crate::tpm_wire_0313::pcr_read_command_0315(&indices))?;
    let values=crate::tpm_wire_0313::parse_pcr_read_response_0315(&read,&indices)?;
    let mut pcr_values=std::collections::BTreeMap::new();
    for (index,value) in indices.iter().zip(values.iter()) {pcr_values.insert(index.to_string(),value.iter().map(|b|format!("{b:02x}")).collect::<String>());}
    Ok(WindowsTPMQuote0315{tpm2b_attest:URL_SAFE_NO_PAD.encode(attest),
        tpmt_signature:URL_SAFE_NO_PAD.encode(signature),pcr_values,
        ak_certificate_pem:ak_certificate_pem.to_string(),intermediates_pem})
}
