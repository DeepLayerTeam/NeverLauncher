use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEVICE_KEY_SERVICE: &str = "NeverLauncher Device Keys";
const DEVICE_KEY_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecureDeviceKeyRecord {
    schema_version: String,
    user_id: String,
    public_key: String,
    fingerprint: String,
    private_seed_hex: String,
    #[serde(default)]
    device_id: Option<String>,
    created_at_unix: u64,
    storage_backend: String,
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
    pub private_key_exposed_to_frontend: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSignatureResult {
    pub fingerprint: String,
    pub public_key: String,
    pub signature: String,
    pub key_algorithm: String,
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
        key_algorithm: "ed25519".into(),
        private_key_exposed_to_frontend: false,
    }
}

fn validate_record(record: &mut SecureDeviceKeyRecord) -> Result<SigningKey, String> {
    if record.schema_version != DEVICE_KEY_SCHEMA_VERSION {
        return Err("device key record имеет неподдерживаемую версию".into());
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
        .map_err(|e| format!("не удалось сохранить device key в OS secure storage: {e}"));
    secret.zeroize();
    result
}

fn new_record(user_id: &str) -> SecureDeviceKeyRecord {
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
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_secs())
            .unwrap_or(0),
        storage_backend: storage_backend_name().into(),
    };
    seed_hex.zeroize();
    record
}

pub fn ensure_device_key(backend_url: &str, user_id: &str) -> Result<DeviceKeyInfo, String> {
    let user = normalize_user_id(user_id)?;
    if let Some(mut existing) = load_record(backend_url, &user)? {
        let _ = validate_record(&mut existing)?;
        return Ok(record_to_info(&existing));
    }
    let mut record = new_record(&user);
    let _ = validate_record(&mut record)?;
    save_record(backend_url, &user, &record)?;
    Ok(record_to_info(&record))
}

pub fn device_key_status(backend_url: &str, user_id: &str) -> Result<Option<DeviceKeyInfo>, String> {
    let user = normalize_user_id(user_id)?;
    match load_record(backend_url, &user)? {
        Some(mut record) => {
            let _ = validate_record(&mut record)?;
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

pub fn sign_device_payload(backend_url: &str, user_id: &str, payload: &str) -> Result<DeviceSignatureResult, String> {
    let user = normalize_user_id(user_id)?;
    validate_device_signing_payload(payload, &user)?;
    let mut record = load_record(backend_url, &user)?
        .ok_or_else(|| "device key отсутствует в OS secure storage".to_string())?;
    let signing = validate_record(&mut record)?;
    let signature = signing.sign(payload.as_bytes());
    Ok(DeviceSignatureResult {
        fingerprint: record.fingerprint,
        public_key: record.public_key,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        key_algorithm: "ed25519".into(),
    })
}

pub fn bind_device_key(backend_url: &str, user_id: &str, device_id: &str) -> Result<DeviceKeyInfo, String> {
    let user = normalize_user_id(user_id)?;
    let device_id = device_id.trim();
    if device_id.is_empty() || device_id.len() > 160 {
        return Err("deviceId обязателен".into());
    }
    let mut record = load_record(backend_url, &user)?
        .ok_or_else(|| "device key отсутствует в OS secure storage".to_string())?;
    let _ = validate_record(&mut record)?;
    record.device_id = Some(device_id.to_string());
    save_record(backend_url, &user, &record)?;
    Ok(record_to_info(&record))
}

pub fn reset_device_key(backend_url: &str, user_id: &str) -> Result<DeviceKeyInfo, String> {
    delete_device_key(backend_url, user_id)?;
    ensure_device_key(backend_url, user_id)
}

pub fn delete_device_key(backend_url: &str, user_id: &str) -> Result<(), String> {
    let entry = keyring_entry(backend_url, user_id)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("не удалось удалить device key из OS secure storage: {e}")),
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
}
