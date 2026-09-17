use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use hardware_enclave::{create_signer, AccessPolicy, EnclaveConfig, SignerHandle};
use p256::ecdsa::Signature as P256Signature;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEVICE_KEY_SERVICE: &str = "NeverLauncher Device Keys";
const DEVICE_KEY_SCHEMA_VERSION: &str = "2";
const DEVICE_HARDWARE_APP: &str = "neverlauncher-desktop";

fn default_software_algorithm() -> String { "ed25519".into() }
fn default_software_binding() -> String { "software".into() }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecureDeviceKeyRecord {
    schema_version: String,
    user_id: String,
    public_key: String,
    fingerprint: String,
    #[serde(default)]
    private_seed_hex: String,
    #[serde(default)]
    device_id: Option<String>,
    created_at_unix: u64,
    storage_backend: String,
    #[serde(default = "default_software_algorithm")]
    key_algorithm: String,
    #[serde(default = "default_software_binding")]
    key_binding: String,
    #[serde(default)]
    hardware_provider: String,
    #[serde(default)]
    hardware_label: String,
}

impl Drop for SecureDeviceKeyRecord {
    fn drop(&mut self) {
        self.private_seed_hex.zeroize();
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    pub user_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub device_id: Option<String>,
    pub created_at_unix: u64,
    pub storage_backend: String,
    pub key_algorithm: String,
    pub key_binding: String,
    pub hardware_provider: String,
    pub hardware_bound: bool,
    pub private_key_exposed_to_frontend: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSignatureResult {
    pub fingerprint: String,
    pub public_key: String,
    pub signature: String,
    pub key_algorithm: String,
    pub key_binding: String,
    pub hardware_provider: String,
    pub hardware_bound: bool,
}

fn normalize_backend_url(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('/').to_ascii_lowercase();
    if value.is_empty() {
        return Err("Backend URL обязателен для device key storage".into());
    }
    let secure = value.starts_with("https://");
    let loopback_http = value.strip_prefix("http://").map(|rest| {
        let authority = rest.split('/').next().unwrap_or("");
        if authority.contains('@') { return false; }
        let host = if authority.starts_with('[') {
            authority.split(']').next().map(|v| format!("{}]", v)).unwrap_or_default()
        } else {
            authority.split(':').next().unwrap_or("").to_string()
        };
        matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
    }).unwrap_or(false);
    if !secure && !loopback_http {
        return Err("Device key разрешён только для HTTPS Backend; HTTP допустим только для localhost development".into());
    }
    Ok(value)
}

fn normalize_user_id(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 160 {
        return Err("userId обязателен для device key storage".into());
    }
    Ok(value.to_string())
}

fn device_key_username(backend_url: &str, user_id: &str) -> Result<String, String> {
    let backend = normalize_backend_url(backend_url)?;
    let user = normalize_user_id(user_id)?;
    let mut hasher = Sha256::new();
    hasher.update(b"NeverLauncher Device Key v1\0");
    hasher.update(backend.as_bytes());
    hasher.update(b"\0");
    hasher.update(user.as_bytes());
    Ok(format!("device:{}", hex::encode(hasher.finalize())))
}

fn hardware_key_label(backend_url: &str, user_id: &str) -> Result<String, String> {
    let username = device_key_username(backend_url, user_id)?;
    let digest = Sha256::digest(username.as_bytes());
    Ok(format!("nl-device-{}", &hex::encode(digest)[..32]))
}

fn storage_backend_name() -> &'static str {
    #[cfg(target_os = "windows")]
    { return "windows-credential-manager"; }
    #[cfg(target_os = "macos")]
    { return "macos-keychain"; }
    #[cfg(target_os = "linux")]
    { return "linux-secret-service"; }
    #[allow(unreachable_code)]
    "os-keyring"
}

fn keyring_entry(backend_url: &str, user_id: &str) -> Result<keyring::v1::Entry, String> {
    let username = device_key_username(backend_url, user_id)?;
    keyring::v1::Entry::new(DEVICE_KEY_SERVICE, &username)
        .map_err(|e| format!("OS secure storage для device key недоступен: {e}"))
}

fn record_to_info(record: &SecureDeviceKeyRecord) -> DeviceKeyInfo {
    DeviceKeyInfo {
        user_id: record.user_id.clone(),
        public_key: record.public_key.clone(),
        fingerprint: record.fingerprint.clone(),
        device_id: record.device_id.clone(),
        created_at_unix: record.created_at_unix,
        storage_backend: record.storage_backend.clone(),
        key_algorithm: record.key_algorithm.clone(),
        key_binding: record.key_binding.clone(),
        hardware_provider: record.hardware_provider.clone(),
        hardware_bound: record.key_binding == "hardware",
        private_key_exposed_to_frontend: false,
    }
}

fn validate_software_record(record: &mut SecureDeviceKeyRecord) -> Result<SigningKey, String> {
    if record.key_algorithm != "ed25519" || record.key_binding != "software" {
        return Err("software device key record имеет некорректный algorithm/binding".into());
    }
    let mut seed = hex::decode(record.private_seed_hex.trim())
        .map_err(|_| "device key seed в OS secure storage повреждён".to_string())?;
    if seed.len() != 32 {
        seed.zeroize();
        return Err("device key seed в OS secure storage имеет неверную длину".into());
    }
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed);
    seed.zeroize();
    let signing = SigningKey::from_bytes(&seed_array);
    seed_array.zeroize();
    let public = signing.verifying_key().to_bytes();
    let public_b64 = URL_SAFE_NO_PAD.encode(public);
    let fingerprint = hex::encode(Sha256::digest(public));
    if record.public_key != public_b64 || record.fingerprint != fingerprint {
        return Err("device key record в OS secure storage не проходит self-check".into());
    }
    Ok(signing)
}

fn is_hardware_backend_kind(provider: &str) -> bool {
    let p = provider.to_ascii_lowercase();
    // Fail closed: only known Secure Enclave / TPM / WSL TPM bridge names are
    // accepted. A future/unknown backend must be reviewed before it can be
    // advertised as hardware-bound.
    (p.contains("tpm")
        || p.contains("secureenclave")
        || p.contains("secure_enclave")
        || p.contains("wslbridge")
        || p.contains("wsl_bridge"))
        && !p.contains("keyring")
        && !p.contains("software")
        && !p.contains("test")
}

fn hardware_signer(label: &str) -> Result<(SignerHandle, String), String> {
    let config = EnclaveConfig::new(DEVICE_HARDWARE_APP, label);
    let signer = create_signer(&config).map_err(|e| format!("hardware signer недоступен: {e}"))?;
    let provider = format!("{:?}", signer.backend_kind());
    // Linux keyring and any explicit software/test backend are deliberately not
    // promoted to hardware-bound identity. They remain eligible only for the
    // existing Ed25519 + OS secure storage fallback.
    if !is_hardware_backend_kind(&provider) {
        return Err(format!("platform signer backend {provider} не является hardware-isolated"));
    }
    Ok((signer, provider))
}

fn validate_hardware_record(record: &SecureDeviceKeyRecord) -> Result<(SignerHandle, String), String> {
    if record.key_algorithm != "p256" || record.key_binding != "hardware" || record.hardware_label.is_empty() {
        return Err("hardware device key record имеет некорректный algorithm/binding".into());
    }
    if !record.private_seed_hex.is_empty() {
        return Err("hardware-bound device record не должен содержать private seed".into());
    }
    let (signer, provider) = hardware_signer(&record.hardware_label)?;
    if !record.hardware_provider.is_empty() && provider != record.hardware_provider {
        return Err(format!("hardware provider изменился: saved={} current={provider}", record.hardware_provider));
    }
    let public = signer.public_key(&record.hardware_label)
        .map_err(|e| format!("не удалось получить hardware public key: {e}"))?;
    if public.len() != 65 || public[0] != 0x04 {
        return Err("hardware signer вернул некорректный SEC1 P-256 public key".into());
    }
    let public_b64 = URL_SAFE_NO_PAD.encode(&public);
    let fingerprint = hex::encode(Sha256::digest(&public));
    if record.public_key != public_b64 || record.fingerprint != fingerprint {
        return Err("hardware-bound device key не проходит public-key self-check".into());
    }
    Ok((signer, provider))
}

fn validate_record(record: &mut SecureDeviceKeyRecord) -> Result<(), String> {
    if record.schema_version != "1" && record.schema_version != DEVICE_KEY_SCHEMA_VERSION {
        return Err("device key record имеет неподдерживаемую версию".into());
    }
    if record.schema_version == "1" {
        record.key_algorithm = "ed25519".into();
        record.key_binding = "software".into();
        record.hardware_provider.clear();
        record.hardware_label.clear();
    }
    match record.key_binding.as_str() {
        "hardware" => { let _ = validate_hardware_record(record)?; }
        "software" => { let _ = validate_software_record(record)?; }
        _ => return Err("device key record содержит неизвестный keyBinding".into()),
    }
    Ok(())
}

fn load_record(backend_url: &str, user_id: &str) -> Result<Option<SecureDeviceKeyRecord>, String> {
    let entry = keyring_entry(backend_url, user_id)?;
    match entry.get_password() {
        Ok(mut secret) => {
            let parsed = serde_json::from_str::<SecureDeviceKeyRecord>(&secret)
                .map_err(|e| format!("device key record в OS secure storage повреждён: {e}"));
            secret.zeroize();
            parsed.map(Some)
        }
        Err(keyring::v1::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("не удалось прочитать device key из OS secure storage: {e}")),
    }
}

fn save_record(backend_url: &str, user_id: &str, record: &SecureDeviceKeyRecord) -> Result<(), String> {
    let entry = keyring_entry(backend_url, user_id)?;
    let mut secret = serde_json::to_string(record)
        .map_err(|e| format!("не удалось сериализовать device key record: {e}"))?;
    let result = entry
        .set_password(&secret)
        .map_err(|e| format!("не удалось сохранить device key metadata в OS secure storage: {e}"));
    secret.zeroize();
    result
}

fn new_software_record(user_id: &str) -> SecureDeviceKeyRecord {
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let public = signing.verifying_key().to_bytes();
    let fingerprint = hex::encode(Sha256::digest(public));
    let mut seed_hex = hex::encode(signing.to_bytes());
    let record = SecureDeviceKeyRecord {
        schema_version: DEVICE_KEY_SCHEMA_VERSION.into(),
        user_id: user_id.to_string(),
        public_key: URL_SAFE_NO_PAD.encode(public),
        fingerprint,
        private_seed_hex: seed_hex.clone(),
        device_id: None,
        created_at_unix: now_unix(),
        storage_backend: storage_backend_name().into(),
        key_algorithm: "ed25519".into(),
        key_binding: "software".into(),
        hardware_provider: String::new(),
        hardware_label: String::new(),
    };
    seed_hex.zeroize();
    record
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}

fn try_new_hardware_record(backend_url: &str, user_id: &str) -> Result<SecureDeviceKeyRecord, String> {
    let label = hardware_key_label(backend_url, user_id)?;
    let (signer, provider) = hardware_signer(&label)?;
    if !signer.key_exists(&label).map_err(|e| format!("hardware key lookup failed: {e}"))? {
        signer.generate_key(&label, AccessPolicy::None)
            .map_err(|e| format!("hardware key generation failed: {e}"))?;
    }
    let public = signer.public_key(&label).map_err(|e| format!("hardware public key read failed: {e}"))?;
    if public.len() != 65 || public[0] != 0x04 {
        return Err("hardware signer вернул некорректный SEC1 P-256 public key".into());
    }
    Ok(SecureDeviceKeyRecord {
        schema_version: DEVICE_KEY_SCHEMA_VERSION.into(),
        user_id: user_id.to_string(),
        public_key: URL_SAFE_NO_PAD.encode(&public),
        fingerprint: hex::encode(Sha256::digest(&public)),
        private_seed_hex: String::new(),
        device_id: None,
        created_at_unix: now_unix(),
        storage_backend: "platform-hardware-enclave".into(),
        key_algorithm: "p256".into(),
        key_binding: "hardware".into(),
        hardware_provider: provider,
        hardware_label: label,
    })
}

pub fn ensure_device_key(backend_url: &str, user_id: &str) -> Result<DeviceKeyInfo, String> {
    let user = normalize_user_id(user_id)?;
    if let Some(mut existing) = load_record(backend_url, &user)? {
        validate_record(&mut existing)?;
        if existing.schema_version == "1" {
            existing.schema_version = DEVICE_KEY_SCHEMA_VERSION.into();
            save_record(backend_url, &user, &existing)?;
        }
        return Ok(record_to_info(&existing));
    }
    let mut record = match try_new_hardware_record(backend_url, &user) {
        Ok(record) => record,
        Err(_) => new_software_record(&user),
    };
    validate_record(&mut record)?;
    save_record(backend_url, &user, &record)?;
    Ok(record_to_info(&record))
}

pub fn device_key_status(backend_url: &str, user_id: &str) -> Result<Option<DeviceKeyInfo>, String> {
    let user = normalize_user_id(user_id)?;
    match load_record(backend_url, &user)? {
        Some(mut record) => {
            validate_record(&mut record)?;
            Ok(Some(record_to_info(&record)))
        }
        None => Ok(None),
    }
}

fn validate_device_signing_payload(payload: &str, user_id: &str) -> Result<(), String> {
    if payload.is_empty() || payload.len() > 16 * 1024 {
        return Err("device signing payload имеет недопустимый размер".into());
    }
    let lines = payload.split_terminator('\n').collect::<Vec<_>>();
    if lines.len() != 6 || lines[0] != "NeverLauncher Device Trust v1" {
        return Err("device signing payload не является каноническим NeverLauncher Device Trust v1 payload".into());
    }
    if lines[1] != "purpose=register" && lines[1] != "purpose=session-bind" {
        return Err("device signing purpose не разрешён".into());
    }
    if lines[2].strip_prefix("challenge=").unwrap_or("").is_empty()
        || lines[3] != format!("user={}", user_id)
        || lines[4].strip_prefix("device=").unwrap_or("").is_empty()
        || lines[5].strip_prefix("session=").unwrap_or("").is_empty() {
        return Err("device signing payload не совпадает с ожидаемой canonical identity/session binding".into());
    }
    Ok(())
}

fn validate_device_attestation_payload(payload: &str, user_id: &str, record: &SecureDeviceKeyRecord) -> Result<(), String> {
    if payload.is_empty() || payload.len() > 16 * 1024 {
        return Err("device attestation payload имеет недопустимый размер".into());
    }
    if record.key_binding != "hardware" || record.key_algorithm != "p256" {
        return Err("device attestation требует hardware-bound P-256 key".into());
    }
    let device_id = record.device_id.as_deref().unwrap_or("").trim();
    if device_id.is_empty() {
        return Err("device attestation требует уже зарегистрированный deviceId".into());
    }
    let lines = payload.split_terminator('\n').collect::<Vec<_>>();
    if lines.len() != 13 || lines[0] != "NeverLauncher Device Attestation v1" || lines[1] != "purpose=attest" {
        return Err("device attestation payload не является каноническим NeverLauncher Device Attestation v1 payload".into());
    }
    if lines[2].strip_prefix("challenge=").unwrap_or("").is_empty()
        || lines[3] != format!("user={}", user_id)
        || lines[4] != format!("device={}", device_id)
        || lines[5].strip_prefix("session=").unwrap_or("").is_empty()
        || lines[6] != format!("fingerprint={}", record.fingerprint)
        || lines[7] != "algorithm=p256"
        || lines[8] != "binding=hardware"
        || lines[9] != format!("provider={}", record.hardware_provider)
        || lines[10].strip_prefix("issued-at=").unwrap_or("").is_empty()
        || lines[11].strip_prefix("challenge-expires-at=").unwrap_or("").is_empty()
        || lines[12].strip_prefix("attestation-valid-until=").unwrap_or("").is_empty()
    {
        return Err("device attestation payload не совпадает с зарегистрированной hardware identity/session/freshness binding".into());
    }
    Ok(())
}

fn der_ecdsa_to_p1363(der: &[u8]) -> Result<[u8; 64], String> {
    let sig = P256Signature::from_der(der).map_err(|_| "hardware ECDSA signature DER повреждена".to_string())?;
    let bytes = sig.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn sign_device_payload(backend_url: &str, user_id: &str, payload: &str) -> Result<DeviceSignatureResult, String> {
    let user = normalize_user_id(user_id)?;
    validate_device_signing_payload(payload, &user)?;
    let mut record = load_record(backend_url, &user)?
        .ok_or_else(|| "device key отсутствует".to_string())?;
    validate_record(&mut record)?;
    let signature = if record.key_binding == "hardware" {
        let (signer, _) = validate_hardware_record(&record)?;
        let der = signer.sign(&record.hardware_label, payload.as_bytes())
            .map_err(|e| format!("hardware device signing failed: {e}"))?;
        URL_SAFE_NO_PAD.encode(der_ecdsa_to_p1363(&der)?)
    } else {
        let signing = validate_software_record(&mut record)?;
        URL_SAFE_NO_PAD.encode(signing.sign(payload.as_bytes()).to_bytes())
    };
    Ok(DeviceSignatureResult {
        fingerprint: record.fingerprint,
        public_key: record.public_key,
        signature,
        key_algorithm: record.key_algorithm,
        key_binding: record.key_binding.clone(),
        hardware_provider: record.hardware_provider.clone(),
        hardware_bound: record.key_binding == "hardware",
    })
}

fn session_refresh_payload(user_id: &str, session_id: &str, device_id: &str, binding_epoch: i64, refresh_token: &str) -> Result<String, String> {
    let session_id = session_id.trim();
    let device_id = device_id.trim();
    if session_id.is_empty() || session_id.len() > 256 || device_id.is_empty() || device_id.len() > 160 {
        return Err("session/device binding для refresh недействителен".into());
    }
    if binding_epoch < 1 {
        return Err("bindingEpoch для refresh должен быть >= 1".into());
    }
    if refresh_token.is_empty() || refresh_token.len() > 4096 {
        return Err("refresh token имеет недопустимый размер".into());
    }
    let digest = hex::encode(Sha256::digest(refresh_token.as_bytes()));
    Ok(format!(
        "NeverLauncher Session Device Binding v1\npurpose=refresh\nuser={}\nsession={}\ndevice={}\nbinding-epoch={}\nrefresh-token-sha256={}\n",
        user_id, session_id, device_id, binding_epoch, digest
    ))
}

pub fn sign_session_refresh(
    backend_url: &str,
    user_id: &str,
    session_id: &str,
    device_id: &str,
    binding_epoch: i64,
    refresh_token: &str,
) -> Result<DeviceSignatureResult, String> {
    let user = normalize_user_id(user_id)?;
    let mut record = load_record(backend_url, &user)?
        .ok_or_else(|| "device key отсутствует".to_string())?;
    validate_record(&mut record)?;
    let registered_device = record.device_id.as_deref().unwrap_or("").trim();
    if registered_device.is_empty() || registered_device != device_id.trim() {
        return Err("refresh proof запрошен не для локально зарегистрированного device key".into());
    }
    let payload = session_refresh_payload(&user, session_id, registered_device, binding_epoch, refresh_token)?;
    let signature = if record.key_binding == "hardware" {
        let (signer, _) = validate_hardware_record(&record)?;
        let der = signer.sign(&record.hardware_label, payload.as_bytes())
            .map_err(|e| format!("hardware session refresh signing failed: {e}"))?;
        URL_SAFE_NO_PAD.encode(der_ecdsa_to_p1363(&der)?)
    } else {
        let signing = validate_software_record(&mut record)?;
        URL_SAFE_NO_PAD.encode(signing.sign(payload.as_bytes()).to_bytes())
    };
    Ok(DeviceSignatureResult {
        fingerprint: record.fingerprint,
        public_key: record.public_key,
        signature,
        key_algorithm: record.key_algorithm,
        key_binding: record.key_binding.clone(),
        hardware_provider: record.hardware_provider.clone(),
        hardware_bound: record.key_binding == "hardware",
    })
}

pub fn attest_device_payload(backend_url: &str, user_id: &str, payload: &str) -> Result<DeviceSignatureResult, String> {
    let user = normalize_user_id(user_id)?;
    let mut record = load_record(backend_url, &user)?
        .ok_or_else(|| "device key отсутствует".to_string())?;
    validate_record(&mut record)?;
    validate_device_attestation_payload(payload, &user, &record)?;

    // Attestation intentionally has no software fallback. It is a separate IPC
    // boundary from generic proof-of-possession and can only use the persisted
    // non-exportable hardware key that was previously registered by the server.
    let (signer, _) = validate_hardware_record(&record)?;
    let der = signer.sign(&record.hardware_label, payload.as_bytes())
        .map_err(|e| format!("hardware device attestation signing failed: {e}"))?;
    let signature = URL_SAFE_NO_PAD.encode(der_ecdsa_to_p1363(&der)?);
    Ok(DeviceSignatureResult {
        fingerprint: record.fingerprint,
        public_key: record.public_key,
        signature,
        key_algorithm: record.key_algorithm,
        key_binding: record.key_binding.clone(),
        hardware_provider: record.hardware_provider.clone(),
        hardware_bound: true,
    })
}

pub fn bind_device_key(backend_url: &str, user_id: &str, device_id: &str) -> Result<DeviceKeyInfo, String> {
    let user = normalize_user_id(user_id)?;
    let device_id = device_id.trim();
    if device_id.is_empty() || device_id.len() > 160 {
        return Err("deviceId обязателен".into());
    }
    let mut record = load_record(backend_url, &user)?
        .ok_or_else(|| "device key отсутствует".to_string())?;
    validate_record(&mut record)?;
    record.device_id = Some(device_id.to_string());
    save_record(backend_url, &user, &record)?;
    Ok(record_to_info(&record))
}

pub fn reset_device_key(backend_url: &str, user_id: &str) -> Result<DeviceKeyInfo, String> {
    delete_device_key(backend_url, user_id)?;
    ensure_device_key(backend_url, user_id)
}

pub fn delete_device_key(backend_url: &str, user_id: &str) -> Result<(), String> {
    if let Some(mut record) = load_record(backend_url, user_id)? {
        if record.key_binding == "hardware" && !record.hardware_label.is_empty() {
            if let Ok((signer, _)) = hardware_signer(&record.hardware_label) {
                if signer.key_exists(&record.hardware_label).unwrap_or(false) {
                    signer.delete_key(&record.hardware_label)
                        .map_err(|e| format!("не удалось удалить hardware device key: {e}"))?;
                }
            }
        }
        record.private_seed_hex.zeroize();
    }
    let entry = keyring_entry(backend_url, user_id)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("не удалось удалить device key metadata из OS secure storage: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_username_is_scoped_by_backend_and_user() {
        let a = device_key_username("https://example.test/", "user-a").unwrap();
        let b = device_key_username("https://example.test", "user-b").unwrap();
        let c = device_key_username("https://other.test", "user-a").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("device:"));
    }

    #[test]
    fn hardware_backend_classification_is_fail_closed() {
        assert!(is_hardware_backend_kind("MacOsSecureEnclave"));
        assert!(is_hardware_backend_kind("WindowsTpm"));
        assert!(is_hardware_backend_kind("LinuxTpm"));
        assert!(is_hardware_backend_kind("WslBridge"));
        assert!(!is_hardware_backend_kind("LinuxKeyring"));
        assert!(!is_hardware_backend_kind("Software"));
        assert!(!is_hardware_backend_kind("TestSoftware"));
        assert!(!is_hardware_backend_kind("UnknownFutureBackend"));
    }

    #[test]
    fn hardware_label_is_stable_and_scoped() {
        let a = hardware_key_label("https://example.test", "user-a").unwrap();
        let b = hardware_key_label("https://example.test", "user-b").unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("nl-device-"));
    }

    #[test]
    fn rejects_remote_plain_http_backend() {
        assert!(normalize_backend_url("http://example.test").is_err());
        assert!(normalize_backend_url("http://localhost.evil.test").is_err());
        assert!(normalize_backend_url("http://127.0.0.1.evil.test").is_err());
        assert!(normalize_backend_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn signing_payload_is_scoped_to_device_trust_and_user() {
        let good = "NeverLauncher Device Trust v1\npurpose=register\nchallenge=abc\nuser=user-a\ndevice=dev-1\nsession=sess-1\n";
        assert!(validate_device_signing_payload(good, "user-a").is_ok());
        assert!(validate_device_signing_payload(good, "user-b").is_err());
        assert!(validate_device_signing_payload("arbitrary payload", "user-a").is_err());
    }

    #[test]
    fn refresh_payload_binds_session_device_epoch_and_token_hash_without_token_disclosure() {
        let payload = session_refresh_payload("user-a", "sess-1", "dev-1", 3, "nlr_secret-refresh").unwrap();
        assert!(payload.contains("user=user-a\n"));
        assert!(payload.contains("session=sess-1\n"));
        assert!(payload.contains("device=dev-1\n"));
        assert!(payload.contains("binding-epoch=3\n"));
        assert!(payload.contains("refresh-token-sha256="));
        assert!(!payload.contains("nlr_secret-refresh"));
        assert!(session_refresh_payload("user-a", "sess-1", "dev-1", 0, "x").is_err());
    }

    #[test]
    fn attestation_payload_is_hardware_only_and_identity_bound() {
        let record = SecureDeviceKeyRecord {
            schema_version: DEVICE_KEY_SCHEMA_VERSION.into(),
            user_id: "user-a".into(),
            public_key: "pub".into(),
            fingerprint: "fp123".into(),
            private_seed_hex: String::new(),
            device_id: Some("dev-1".into()),
            created_at_unix: 1,
            storage_backend: "platform-hardware-enclave".into(),
            key_algorithm: "p256".into(),
            key_binding: "hardware".into(),
            hardware_provider: "WindowsTpm".into(),
            hardware_label: "nl-device-test".into(),
        };
        let good = "NeverLauncher Device Attestation v1\npurpose=attest\nchallenge=abc\nuser=user-a\ndevice=dev-1\nsession=sess-1\nfingerprint=fp123\nalgorithm=p256\nbinding=hardware\nprovider=WindowsTpm\nissued-at=2026-09-16T20:00:00Z\nchallenge-expires-at=2026-09-16T20:02:00Z\nattestation-valid-until=2026-09-17T08:00:00Z\n";
        assert!(validate_device_attestation_payload(good, "user-a", &record).is_ok());
        assert!(validate_device_attestation_payload(good, "user-b", &record).is_err());
        assert!(validate_device_attestation_payload(&good.replace("fingerprint=fp123", "fingerprint=other"), "user-a", &record).is_err());

        let mut software = record;
        software.key_algorithm = "ed25519".into();
        software.key_binding = "software".into();
        assert!(validate_device_attestation_payload(good, "user-a", &software).is_err());
    }
}
