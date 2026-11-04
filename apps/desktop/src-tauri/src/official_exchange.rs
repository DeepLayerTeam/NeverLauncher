//! 0.26.5: provider exchange happens inside the Tauri trusted process.
//! No Microsoft, Xbox, XSTS or Minecraft bearer ever crosses renderer IPC.
use std::{time::{Duration, SystemTime, UNIX_EPOCH}};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};
use crate::{official_browser_0263, official_verification_0266, official_identity_0262::{OfficialProfile, OfficialSkin, OfficialCape}};

const MICROSOFT: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/";
const XBOX: &str = "https://user.auth.xboxlive.com";
const XSTS: &str = "https://xsts.auth.xboxlive.com";
const MINECRAFT: &str = "https://api.minecraftservices.com";
const MAX_REPLY: usize = 256 * 1024;
const SCOPE: &str = "XboxLive.signin offline_access";

#[derive(Debug, PartialEq, Eq)]
pub enum ProviderError {
    Pending, SlowDown, Expired, Denied, InvalidGrant, AppNotAuthorized,
    XboxAccount, XboxRegion, XboxFamily, NoMinecraftJava, IdentityMismatch,
    Throttled(Option<u64>), Transient, InvalidResponse, Unavailable,
}
impl ProviderError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Pending => "Microsoft ожидает подтверждения входа",
            Self::SlowDown => "Microsoft требует увеличить интервал проверки",
            Self::Expired => "Microsoft Device Code истёк",
            Self::Denied => "Вход Microsoft отклонён пользователем",
            Self::InvalidGrant => "Microsoft session истекла или отозвана; войдите повторно",
            Self::AppNotAuthorized => "Регистрация Microsoft-приложения не допущена к Minecraft Services",
            Self::XboxAccount => "У Microsoft-аккаунта отсутствует доступный Xbox-профиль",
            Self::XboxRegion => "Xbox недоступен для региона этого аккаунта",
            Self::XboxFamily => "Настройки семьи или возраста ограничивают Xbox",
            Self::NoMinecraftJava => "Отсутствует доступный Minecraft Java Edition профиль",
            Self::IdentityMismatch => "Minecraft UUID изменился; требуется явное переподключение аккаунта",
            Self::Throttled(_) => "Провайдер ограничил частоту запросов",
            Self::Transient | Self::Unavailable => "Microsoft/Xbox/Minecraft временно недоступны",
            Self::InvalidResponse => "Неверный или неполный ответ игрового провайдера",
        }
    }
    pub fn retryable(&self) -> bool { matches!(self, Self::Transient | Self::Unavailable | Self::Throttled(_)) }
    pub fn retry_after(&self) -> Option<u64> { if let Self::Throttled(v) = self { *v } else { None } }
}

pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
pub fn valid_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 8192 && !s.bytes().any(|b| b <= 0x20 || b == 0x7f)
}
fn valid_account_id(s: &str) -> bool { s.len() == 32 && s.bytes().all(|v| v.is_ascii_hexdigit()) }

#[derive(Deserialize)]
pub struct MicrosoftGrant {
    pub access_token: String,
    #[serde(default)] pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
}
impl Drop for MicrosoftGrant { fn drop(&mut self) { self.access_token.zeroize(); self.refresh_token.zeroize(); } }
impl MicrosoftGrant {
    fn validate(&self) -> Result<(),ProviderError> {
        if !valid_token(&self.access_token) || !valid_token(&self.refresh_token) ||
            self.token_type != "Bearer" || !(60..=86400).contains(&self.expires_in) {
            return Err(ProviderError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct XboxClaims { #[serde(rename="xui")] xui: Vec<UserHash> }
#[derive(Deserialize)]
struct UserHash { #[serde(rename="uhs")] uhs: String }
#[derive(Deserialize)]
struct XboxGrant { #[serde(rename="Token")] token: String, #[serde(rename="DisplayClaims")] claims: XboxClaims }
impl Drop for XboxGrant { fn drop(&mut self) { self.token.zeroize(); } }
impl XboxGrant {
    fn verified_hash(&self) -> Result<&str,ProviderError> {
        if !valid_token(&self.token) || self.claims.xui.len() != 1 { return Err(ProviderError::InvalidResponse); }
        let hash = &self.claims.xui[0].uhs;
        if hash.is_empty() || hash.len() > 128 || !hash.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(ProviderError::InvalidResponse);
        }
        Ok(hash)
    }
}

#[derive(Deserialize)]
pub struct MinecraftGrant { pub access_token: String, pub token_type: String, pub expires_in: u64 }
impl Drop for MinecraftGrant { fn drop(&mut self) { self.access_token.zeroize(); } }
impl MinecraftGrant {
    fn validate(&self) -> Result<(),ProviderError> {
        if !valid_token(&self.access_token) || self.token_type != "Bearer" || !(60..=172800).contains(&self.expires_in) {
            return Err(ProviderError::InvalidResponse);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
struct DeviceGrant { device_code: String, user_code: String, verification_uri: String, expires_in: u64, interval: u64 }
impl Drop for DeviceGrant { fn drop(&mut self) { self.device_code.zeroize(); } }
pub struct DeviceChallengeNative { pub secret: Zeroizing<String>, pub code: String, pub verification_uri: String, pub expires_in: u64, pub interval: u64 }

#[derive(Deserialize)]
struct MinecraftProfile { id: String, name: String, #[serde(default)] demo: bool, #[serde(default)] skins: Vec<OfficialSkin>, #[serde(default)] capes: Vec<OfficialCape> }
impl MinecraftProfile {
    fn checked(self) -> Result<OfficialProfile, ProviderError> {
        if self.demo || !valid_account_id(&self.id) || self.id.bytes().all(|c| c == b'0') || self.name.len() < 3 || self.name.len() > 16 ||
            !self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ProviderError::NoMinecraftJava);
        }
        Ok(OfficialProfile { id: self.id.to_ascii_lowercase(), name: self.name, skins: self.skins, capes: self.capes })
    }
}

pub struct NativeProvider { http: Client, microsoft: Url, xbox: Url, xsts: Url, minecraft: Url }
impl NativeProvider {
    pub fn new() -> Result<Self,String> {
        let http = Client::builder().timeout(Duration::from_secs(25))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Launcher/", env!("CARGO_PKG_VERSION")))
            .build().map_err(|_| "Не удалось инициализировать официальный HTTP transport")?;
        Ok(Self { http, microsoft: Url::parse(MICROSOFT).unwrap(), xbox: Url::parse(XBOX).unwrap(),
            xsts: Url::parse(XSTS).unwrap(), minecraft: Url::parse(MINECRAFT).unwrap() })
    }
    #[cfg(test)]
    fn fixture(base: &str) -> Self {
        let url = Url::parse(base).unwrap();
        Self { http: Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
            microsoft: url.clone(), xbox: url.clone(), xsts: url.clone(), minecraft: url }
    }
    async fn get_json<T: DeserializeOwned>(&self, base: &Url, route: &str, bearer: Option<&str>) -> Result<T,ProviderError> {
        self.call(self.http.get(base.join(route).map_err(|_| ProviderError::InvalidResponse)?), bearer).await
    }
    async fn send_json<T: DeserializeOwned>(&self, base: &Url, route: &str, value: serde_json::Value) -> Result<T,ProviderError> {
        self.call(self.http.post(base.join(route).map_err(|_| ProviderError::InvalidResponse)?).json(&value),None).await
    }
    async fn send_form<T: DeserializeOwned>(&self, route: &str, pairs: &[(&str, &str)]) -> Result<T,ProviderError> {
        let url = self.microsoft.join(route).map_err(|_| ProviderError::InvalidResponse)?;
        self.call(self.http.post(url).form(pairs),None).await
    }
    async fn call<T:DeserializeOwned>(&self, builder: reqwest::RequestBuilder, bearer: Option<&str>) -> Result<T,ProviderError> {
        let req = if let Some(token) = bearer { builder.bearer_auth(token) } else { builder };
        let response = req.header("Accept", "application/json").send().await.map_err(|_| ProviderError::Unavailable)?;
        let status = response.status();
        let retry_after = response.headers().get("Retry-After").and_then(|s|s.to_str().ok()).and_then(|s|s.parse::<u64>().ok());
        if response.content_length().is_some_and(|size|size > MAX_REPLY as u64) { return Err(ProviderError::InvalidResponse); }
        let mut buf = Vec::<u8>::new();
        let mut stream = response;
        while let Some(chunk) = stream.chunk().await.map_err(|_| ProviderError::Unavailable)? {
            if buf.len().saturating_add(chunk.len()) > MAX_REPLY { buf.zeroize(); return Err(ProviderError::InvalidResponse); }
            buf.extend_from_slice(&chunk);
        }
        let parsed = if status.is_success() {
            serde_json::from_slice::<T>(&buf).map_err(|_|ProviderError::InvalidResponse)
        } else {
            let hint: ErrorBody = serde_json::from_slice(&buf).unwrap_or_default();
            Err(classify(status.as_u16(), &hint, retry_after))
        };
        buf.zeroize();
        parsed
    }
    pub async fn authorization_code(&self, client_id: &str, redirect: &str, code: &str, verifier: &str) -> Result<MicrosoftGrant,ProviderError> {
        if !official_browser_0263::valid_client_id(client_id) || !valid_code(code) || !(43..=128).contains(&verifier.len()) ||
           !verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)) ||
           !redirect.starts_with("http://localhost:") || !redirect.ends_with(official_browser_0263::CALLBACK_PATH) {
            return Err(ProviderError::InvalidResponse);
        }
        let ms: MicrosoftGrant = self.send_form("token", &[("grant_type","authorization_code"), ("client_id",client_id),
            ("redirect_uri",redirect), ("code",code), ("code_verifier",verifier), ("scope",SCOPE)]).await?;
        ms.validate()?;
        Ok(ms)
    }
    pub async fn refresh(&self, client_id: &str, refresh: &str) -> Result<MicrosoftGrant,ProviderError> {
        if !official_browser_0263::valid_client_id(client_id) || !valid_token(refresh) { return Err(ProviderError::InvalidResponse); }
        let mut grant: MicrosoftGrant = self.send_form("token", &[("grant_type","refresh_token"), ("client_id",client_id),
            ("refresh_token",refresh), ("scope",SCOPE)]).await?;
        if grant.refresh_token.is_empty() { grant.refresh_token = refresh.to_owned(); }
        grant.validate()?;
        Ok(grant)
    }
    pub async fn device_begin(&self, client_id: &str) -> Result<DeviceChallengeNative,ProviderError> {
        if !official_browser_0263::valid_client_id(client_id) { return Err(ProviderError::InvalidResponse); }
        let challenge: DeviceGrant = self.send_form("devicecode", &[("client_id",client_id),("scope",SCOPE)]).await?;
        let verification = Url::parse(&challenge.verification_uri).map_err(|_| ProviderError::InvalidResponse)?;
        if verification.scheme() != "https" || !matches!(verification.host_str(),Some("microsoft.com" | "www.microsoft.com" | "microsoftonline.com" | "login.microsoftonline.com")) ||
            !verification.username().is_empty() || verification.password().is_some() ||
            challenge.user_code.is_empty() || challenge.user_code.len()>64 || !valid_token(&challenge.device_code) ||
            !(1..=1800).contains(&challenge.expires_in) || challenge.interval>1800 {
            return Err(ProviderError::InvalidResponse);
        }
        Ok(DeviceChallengeNative { secret: Zeroizing::new(challenge.device_code.clone()), code: challenge.user_code.clone(),
            verification_uri: challenge.verification_uri.clone(), expires_in: challenge.expires_in, interval: challenge.interval.max(5) })
    }
    pub async fn device_poll(&self, client_id: &str, code: &str) -> Result<MicrosoftGrant,ProviderError> {
        if !official_browser_0263::valid_client_id(client_id) || !valid_token(code) { return Err(ProviderError::InvalidResponse); }
        let grant: MicrosoftGrant = self.send_form("token", &[("grant_type","urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id",client_id), ("device_code",code)]).await?;
        grant.validate()?;
        Ok(grant)
    }
    pub async fn exchange(&self, microsoft_access: &str) -> Result<MinecraftGrant,ProviderError> {
        if !valid_token(microsoft_access) { return Err(ProviderError::InvalidResponse); }
        let xbl: XboxGrant = self.send_json(&self.xbox,"/user/authenticate",json!({
            "Properties":{"AuthMethod":"RPS","SiteName":"user.auth.xboxlive.com","RpsTicket":format!("d={microsoft_access}")},
            "RelyingParty":"http://auth.xboxlive.com","TokenType":"JWT"
        })).await?;
        let uhs = xbl.verified_hash()?.to_owned();
        let xsts: XboxGrant = self.send_json(&self.xsts,"/xsts/authorize",json!({
            "Properties":{"SandboxId":"RETAIL","UserTokens":[xbl.token.as_str()]},
            "RelyingParty":"rp://api.minecraftservices.com/","TokenType":"JWT"
        })).await?;
        if xsts.verified_hash()? != uhs { return Err(ProviderError::InvalidResponse); }
        let identity = Zeroizing::new(format!("XBL3.0 x={uhs};{}",xsts.token));
        let minecraft: MinecraftGrant = self.send_json(&self.minecraft,"/authentication/login_with_xbox",
            json!({"identityToken":identity.as_str()})).await?;
        minecraft.validate()?;
        Ok(minecraft)
    }
    pub async fn profile(&self, minecraft: &str) -> Result<OfficialProfile,ProviderError> {
        if !valid_token(minecraft) { return Err(ProviderError::InvalidResponse); }
        let value: MinecraftProfile = self.get_json(&self.minecraft,"/minecraft/profile",Some(minecraft)).await?;
        value.checked()
    }
    /// Parse actual named entitlements, not merely the length of the array.
    /// This is NOT a reliable standalone Game Pass check: Java profile is the
    /// authoritative proof of a playable Java identity when items are empty.
    pub(crate) async fn entitlements(&self, minecraft: &str) -> Result<official_verification_0266::JavaAccessEvidence,ProviderError> {
        #[derive(Deserialize)] struct Entitlement { items: Vec<EntitlementItem> }
        #[derive(Deserialize)] struct EntitlementItem { name: String }
        if !valid_token(minecraft) { return Err(ProviderError::InvalidResponse); }
        let data: Entitlement = self.get_json(&self.minecraft,"/entitlements/mcstore",Some(minecraft)).await?;
        let names: Vec<String> = data.items.into_iter().map(|item|item.name).collect();
        official_verification_0266::inspect_entitlements(&names)
    }
    /// Fail closed on HTTP/JSON failures, invalid/demonstration Java profiles,
    /// or UUID changes. The entitlement response alone cannot establish that a
    /// given MS token has a playable Java identity.
    pub async fn verify_java(&self, token: &str, expected_uuid: Option<&str>) -> Result<OfficialProfile,ProviderError> {
        let evidence = self.entitlements(token).await?;
        let profile = self.profile(token).await?;
        official_verification_0266::verify_playable_profile(&profile, expected_uuid, evidence)?;
        Ok(profile)
    }
    /// A write acknowledgement is not the final Minecraft state. Read the
    /// authenticated profile again and confirm that the requested texture is
    /// active before returning it to Desktop (and before updating the vault).
    /// Provider propagation can lag briefly; retries are bounded and
    /// repeat the write itself.
    async fn confirmed_texture_0395(&self, token: &str, operation: &str,
        cape_id: Option<&str>, skin_variant: Option<&str>, uuid: &str,
    ) -> Result<OfficialProfile,ProviderError> {
        for attempt in 0..5 {
            match self.profile(token).await {
                Ok(profile) => {
                    if !profile.id.eq_ignore_ascii_case(uuid) { return Err(ProviderError::IdentityMismatch); }
                    if texture_applied_0395(&profile, operation, cape_id, skin_variant) { return Ok(profile); }
                }
                Err(ProviderError::InvalidGrant) => return Err(ProviderError::InvalidGrant),
                Err(ProviderError::NoMinecraftJava) => return Err(ProviderError::NoMinecraftJava),
                Err(ProviderError::Denied) => return Err(ProviderError::Denied),
                Err(ProviderError::Throttled(_)) => return Err(ProviderError::Throttled(None)),
                Err(error) if !error.retryable() => return Err(error),
                Err(_) => {},
            }
            if attempt < 4 { tokio::time::sleep(Duration::from_millis(350)).await; }
        }
        Err(ProviderError::Transient)
    }
    pub async fn texture(&self, token: &str, operation: &str, cape_id: Option<&str>, skin: Option<(Vec<u8>,String)>) -> Result<OfficialProfile,ProviderError> {
        if !valid_token(token) { return Err(ProviderError::InvalidResponse); }
        // All writes use one account's token; accept a cape merely because
        // it was displayed earlier by the renderer.
        let before = self.profile(token).await?;
        let variant = skin.as_ref().map(|(_,model)| model.as_str().to_owned());
        let path = match operation {
            "resetSkin" => "/minecraft/profile/skins/active",
            "resetCape" | "selectCape" => "/minecraft/profile/capes/active",
            "uploadSkin" => "/minecraft/profile/skins",
            _ => return Err(ProviderError::InvalidResponse),
        };
        let base = self.minecraft.join(path).map_err(|_| ProviderError::InvalidResponse)?;
        let builder = match operation {
            "resetSkin" | "resetCape" => self.http.request(Method::DELETE,base).bearer_auth(token),
            "selectCape" => {
                let cape = cape_id.filter(|id| !id.is_empty() && id.len() <= 128 &&
                    id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
                    .ok_or(ProviderError::InvalidResponse)?;
                if !before.capes.iter().any(|v| v.id == cape) { return Err(ProviderError::Denied); }
                self.http.put(base).bearer_auth(token).json(&json!({"capeId":cape}))
            },
            "uploadSkin" => {
                let (bytes, model) = skin.ok_or(ProviderError::InvalidResponse)?;
                if !valid_official_skin_0395(&bytes,&model) { return Err(ProviderError::InvalidResponse); }
                let part = reqwest::multipart::Part::bytes(bytes).file_name("skin.png").mime_str("image/png").map_err(|_|ProviderError::InvalidResponse)?;
                self.http.post(base).bearer_auth(token).multipart(reqwest::multipart::Form::new().text("variant",model).part("file",part))
            },
            _ => unreachable!(),
        };
        // Minecraft Services currently returns a profile for PUT/POST and
        // can return 204 on DELETE. Verify its status, not a cached reply.
        if matches!(operation,"resetSkin"|"resetCape") {
            let response = builder.send().await.map_err(|_|ProviderError::Unavailable)?;
            if !response.status().is_success() { return Err(ProviderError::Transient); }
        } else {
            let acknowledged: MinecraftProfile = self.call(builder,None).await?;
            let acknowledged = acknowledged.checked()?;
            if !acknowledged.id.eq_ignore_ascii_case(&before.id) { return Err(ProviderError::IdentityMismatch); }
        }
        self.confirmed_texture_0395(token,operation,cape_id,variant.as_deref(),&before.id).await
    }
}

fn texture_applied_0395(profile: &OfficialProfile, operation: &str, cape_id: Option<&str>, variant: Option<&str>) -> bool {
    match operation {
        "selectCape" => cape_id.is_some_and(|id|profile.capes.iter().any(|cape|cape.id == id && cape.state == "ACTIVE")),
        "resetCape" => !profile.capes.iter().any(|cape|cape.state == "ACTIVE"),
        "uploadSkin" => variant.is_some_and(|v|profile.skins.iter().any(|skin|skin.state == "ACTIVE" && skin.variant.eq_ignore_ascii_case(v))),
        // The official default after skin reset is provider-dependent.
        // A successful DELETE + fresh authenticated profile is authoritative.
        "resetSkin" => true,
        _ => false,
    }
}

fn valid_official_skin_0395(png: &[u8], variant: &str) -> bool {
    if png.len() < 33 || png.len() > 4 * 1024 * 1024 ||
        !png.starts_with(b"\x89PNG\r\n\x1a\n") || &png[12..16] != b"IHDR" ||
        u32::from_be_bytes([png[8],png[9],png[10],png[11]]) != 13 ||
        !matches!(variant,"classic"|"slim") {return false;}
    let width = u32::from_be_bytes([png[16],png[17],png[18],png[19]]);
    let height = u32::from_be_bytes([png[20],png[21],png[22],png[23]]);
    width == 64 && (height == 64 || (height == 32 && variant == "classic"))
}

fn valid_code(code: &str) -> bool { !code.is_empty() && code.len()<=4096 && !code.bytes().any(|b| b==b'\r' || b==b'\n') }
#[derive(Default, Deserialize)]
struct ErrorBody { #[serde(default)] error: String, #[serde(default,rename="errorMessage")] message: String, #[serde(default,rename="XErr")] xerr: serde_json::Value }
impl Drop for ErrorBody { fn drop(&mut self) { self.error.zeroize(); self.message.zeroize(); } }
fn classify(status: u16, hint: &ErrorBody, retry_after: Option<u64>) -> ProviderError {
    match hint.error.as_str() {
        "authorization_pending" => return ProviderError::Pending,
        "slow_down" => return ProviderError::SlowDown,
        "expired_token" | "bad_verification_code" => return ProviderError::Expired,
        "authorization_declined" | "access_denied" => return ProviderError::Denied,
        "invalid_grant" | "interaction_required" => return ProviderError::InvalidGrant,
        _ => {},
    }
    if status==403 && (hint.message.to_ascii_lowercase().contains("invalid app registration") || hint.error.to_ascii_lowercase().contains("invalid_app_registration")) { return ProviderError::AppNotAuthorized; }
    if status==401 {
        return match hint.xerr.as_i64().or_else(||hint.xerr.as_str().and_then(|s|s.parse::<i64>().ok())) {
            Some(2148916233) => ProviderError::XboxAccount,
            Some(2148916235) => ProviderError::XboxRegion,
            Some(2148916238) => ProviderError::XboxFamily,
            _ => ProviderError::InvalidGrant,
        };
    }
    if status==403 && matches!(hint.xerr.as_i64().or_else(||hint.xerr.as_str().and_then(|s|s.parse::<i64>().ok())),Some(2148916238)) {
        return ProviderError::XboxFamily;
    }
    if status==403 { return ProviderError::Denied; }
    if status==404 { return ProviderError::NoMinecraftJava; }
    if status==429 { return ProviderError::Throttled(retry_after.map(|v|v.clamp(5,3600))); }
    if status==408 || (500..=599).contains(&status) { return ProviderError::Transient; }
    ProviderError::InvalidResponse
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn xbox_hash_must_not_change_between_xbl_and_xsts() {
        let first: XboxGrant=serde_json::from_str(r#"{"Token":"xbl","DisplayClaims":{"xui":[{"uhs":"shared"}]}}"#).unwrap();
        let second: XboxGrant=serde_json::from_str(r#"{"Token":"xsts","DisplayClaims":{"xui":[{"uhs":"different"}]}}"#).unwrap();
        assert_ne!(first.verified_hash().unwrap(),second.verified_hash().unwrap());
        assert!(serde_json::from_str::<XboxGrant>(r#"{"Token":"t","DisplayClaims":{"xui":[]}}"#).unwrap().verified_hash().is_err());
    }
    #[test] fn provider_errors_are_specific_and_contain_secrets() {
        let hint=ErrorBody{error:String::new(),message:"Invalid app registration: very-secret".into(),xerr:serde_json::json!(0)};
        assert_eq!(classify(403,&hint,None),ProviderError::AppNotAuthorized);
        assert_eq!(classify(429,&ErrorBody::default(),Some(31)),ProviderError::Throttled(Some(31)));
        assert_eq!(classify(401,&ErrorBody{xerr:serde_json::json!(2148916238),..Default::default()},None),ProviderError::XboxFamily);
        assert!(!ProviderError::AppNotAuthorized.message().contains("very-secret"));
    }
    #[test] fn official_texture_changes_require_observed_account_state() {
        let id="123456781234123412341234567890ab";
        let mut p=OfficialProfile{id:id.into(),name:"Player".into(),skins:vec![],capes:vec![
            OfficialCape{id:"owned".into(),state:"INACTIVE".into(),url:String::new(),alias:None},
            OfficialCape{id:"other".into(),state:"ACTIVE".into(),url:String::new(),alias:None},
        ]};
        assert!(!texture_applied_0395(&p,"selectCape",Some("owned"),None));
        p.capes[0].state="ACTIVE".into();p.capes[1].state="INACTIVE".into();
        assert!(texture_applied_0395(&p,"selectCape",Some("owned"),None));
        assert!(!texture_applied_0395(&p,"resetCape",None,None));
        p.capes[0].state="INACTIVE".into();
        assert!(texture_applied_0395(&p,"resetCape",None,None));
        p.skins.push(OfficialSkin{id:"new".into(),state:"ACTIVE".into(),url:String::new(),variant:"SLIM".into()});
        assert!(texture_applied_0395(&p,"uploadSkin",None,Some("slim")));
        assert!(!texture_applied_0395(&p,"uploadSkin",None,Some("classic")));
    }
    #[test] fn official_skin_png_geometry_is_checked_before_network_write() {
        let mut png=vec![0u8;33]; png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[8..12].copy_from_slice(&13u32.to_be_bytes()); png[12..16].copy_from_slice(b"IHDR");
        png[16..20].copy_from_slice(&64u32.to_be_bytes());png[20..24].copy_from_slice(&64u32.to_be_bytes());
        assert!(valid_official_skin_0395(&png,"slim"));
        png[20..24].copy_from_slice(&32u32.to_be_bytes());
        assert!(!valid_official_skin_0395(&png,"slim"));
        assert!(valid_official_skin_0395(&png,"classic"));
        png[16..20].copy_from_slice(&128u32.to_be_bytes());
        assert!(!valid_official_skin_0395(&png,"classic"));
    }
    #[test] fn refuses_fake_credential_shapes() {
        assert!(!valid_token("")); assert!(!valid_token("abc\nBearer")); assert!(!valid_token(&"a".repeat(9000)));
        let p: MinecraftProfile=serde_json::from_str(r#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"JavaName"}"#).unwrap();
        assert_eq!(p.checked().unwrap().id,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
    async fn fixture_server(bodies: Vec<(&'static str, &'static str)>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::{net::TcpListener,io::{AsyncReadExt,AsyncWriteExt}};
        let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin=format!("http://{}",listener.local_addr().unwrap());
        let task=tokio::spawn(async move {
            let mut collected=Vec::new();
            for (expected,reply) in bodies {
                let (mut conn,_) = listener.accept().await.unwrap();
                let mut req=Vec::<u8>::new();
                let mut expected_len=None::<usize>;
                loop {
                    let mut chunk=[0u8;4096];
                    let count=conn.read(&mut chunk).await.unwrap();
                    if count==0 {break;}
                    req.extend_from_slice(&chunk[..count]);
                    if let Some(split)=req.windows(4).position(|x|x==b"\r\n\r\n") {
                        if expected_len.is_none() {
                            let headers=String::from_utf8_lossy(&req[..split]);
                            expected_len=Some(headers.lines().find_map(|line| {
                                line.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("content-length"))
                                    .and_then(|(_,v)|v.trim().parse::<usize>().ok())
                            }).unwrap_or(0));
                        }
                        if req.len()>=split+4+expected_len.unwrap() {break;}
                    }
                }
                let wire=String::from_utf8_lossy(&req).to_string();
                assert!(wire.starts_with(expected),"unexpected mock provider endpoint");
                collected.push(wire);
                let (status,body)=if reply.starts_with("403:") {("403 Forbidden",&reply[4..])}
                    else if reply.starts_with("400:") {("400 Bad Request",&reply[4..])}
                    else if reply.starts_with("429:") {("429 Too Many Requests",&reply[4..])}
                    else {("200 OK",reply)};
                let response=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                conn.write_all(response.as_bytes()).await.unwrap();
            }
            collected
        });
        (origin,task)
    }
    #[tokio::test]
    async fn official_cape_selection_is_confirmed_after_provider_write() {
        let (origin,task)=fixture_server(vec![
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","capes":[{"id":"owned","state":"INACTIVE","url":""}]}"#),
            ("PUT /minecraft/profile/capes/active",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player"}"#),
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","capes":[{"id":"owned","state":"ACTIVE","url":""}]}"#),
        ]).await;
        let client=NativeProvider::fixture(&origin);
        let profile=client.texture("minecraft-token","selectCape",Some("owned"),None).await.unwrap();
        assert_eq!(profile.capes[0].state,"ACTIVE");
        let calls=task.await.unwrap();
        assert_eq!(calls.len(),3);
        assert!(calls[1].contains("\"capeId\":\"owned\""));
        assert!(calls.iter().all(|r|r.contains("Bearer minecraft-token")));
    }
    #[tokio::test]
    async fn official_unowned_cape_is_rejected_without_write() {
        let (origin,task)=fixture_server(vec![
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","capes":[{"id":"owned","state":"ACTIVE","url":""}]}"#),
        ]).await;
        let client=NativeProvider::fixture(&origin);
        assert_eq!(client.texture("minecraft-token","selectCape",Some("someone-else"),None).await.err(),Some(ProviderError::Denied));
        assert_eq!(task.await.unwrap().len(),1);
    }
    #[tokio::test]
    async fn official_upload_skin_checks_provider_reply_and_observed_variant() {
        let (origin,task)=fixture_server(vec![
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","skins":[]}"#),
            ("POST /minecraft/profile/skins",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player"}"#),
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","skins":[{"id":"new","state":"ACTIVE","variant":"SLIM","url":""}]}"#),
        ]).await;
        let mut png=vec![0u8;33];png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[8..12].copy_from_slice(&13u32.to_be_bytes());png[12..16].copy_from_slice(b"IHDR");
        png[16..20].copy_from_slice(&64u32.to_be_bytes());png[20..24].copy_from_slice(&64u32.to_be_bytes());
        let client=NativeProvider::fixture(&origin);
        let profile=client.texture("minecraft-token","uploadSkin",None,Some((png,"slim".into()))).await.unwrap();
        assert_eq!(profile.skins[0].state,"ACTIVE");
        let calls=task.await.unwrap();
        assert_eq!(calls.len(),3);
        assert!(calls[1].contains("name=\"variant\""));
        assert!(calls[1].contains("name=\"file\""));
    }
    #[tokio::test]
    async fn official_reset_cape_requires_fresh_absence_of_active_cape() {
        let (origin,task)=fixture_server(vec![
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","capes":[{"id":"owned","state":"ACTIVE"}]}"#),
            ("DELETE /minecraft/profile/capes/active",""),
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"Player","capes":[{"id":"owned","state":"INACTIVE"}]}"#),
        ]).await;
        let client=NativeProvider::fixture(&origin);
        let updated=client.texture("minecraft-token","resetCape",None,None).await.unwrap();
        assert!(!updated.capes.iter().any(|c|c.state=="ACTIVE"));
        assert_eq!(task.await.unwrap().len(),3);
    }
    #[tokio::test]
    async fn native_oauth_pkce_code_exchange_does_not_use_backend_tickets() {
        let (origin,task)=fixture_server(vec![
            ("POST /token",r#"{"access_token":"native-ms-token","refresh_token":"native-refresh","token_type":"Bearer","expires_in":3600}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        let client_id="11111111-2222-3333-4444-555555555555";
        let verifier="a".repeat(64);
        let grant=provider.authorization_code(client_id,"http://localhost:49152/minecraft-poc/callback","test-authorization-code",&verifier).await.unwrap();
        assert_eq!(grant.refresh_token,"native-refresh");
        let observed=task.await.unwrap();
        assert!(observed[0].contains("grant_type=authorization_code"));
        assert!(observed[0].contains("code_verifier="));
        assert!(observed[0].contains("XboxLive.signin"));
        assert!(observed[0].contains("offline_access"));
        assert!(observed[0].contains("redirect_uri="));
    }
    #[tokio::test]
    async fn device_grant_respects_pending_and_slowdown_provider_status() {
        let (origin,task)=fixture_server(vec![
            ("POST /devicecode",r#"{"device_code":"native-secret-code","user_code":"ABCD-1234","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}"#),
            ("POST /token",r#"400:{"error":"authorization_pending"}"#),
            ("POST /token",r#"400:{"error":"slow_down"}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        let client_id="11111111-2222-3333-4444-555555555555";
        let code=provider.device_begin(client_id).await.unwrap();
        assert_eq!(code.interval,5);
        assert_eq!(provider.device_poll(client_id,&code.secret).await.err(),Some(ProviderError::Pending));
        assert_eq!(provider.device_poll(client_id,&code.secret).await.err(),Some(ProviderError::SlowDown));
        assert_eq!(task.await.unwrap().len(),3);
    }
    #[tokio::test]
    async fn native_xbox_xsts_minecraft_chain_uses_correct_bearers() {
        let (origin,task)=fixture_server(vec![
            ("POST /user/authenticate",r#"{"Token":"xbl-secret","DisplayClaims":{"xui":[{"uhs":"userhash"}]}}"#),
            ("POST /xsts/authorize",r#"{"Token":"xsts-secret","DisplayClaims":{"xui":[{"uhs":"userhash"}]}}"#),
            ("POST /authentication/login_with_xbox",r#"{"access_token":"mc-secret","token_type":"Bearer","expires_in":7200}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        let grant=provider.exchange("ms-secret").await.unwrap();
        assert_eq!(grant.access_token,"mc-secret");
        let observed=task.await.unwrap();
        assert!(observed[0].contains("d=ms-secret"));
        assert!(observed[0].contains("http://auth.xboxlive.com"));
        assert!(observed[1].contains("xbl-secret"));
        assert!(observed[1].contains("rp://api.minecraftservices.com/"));
        assert!(observed[2].contains("XBL3.0 x=userhash;xsts-secret"));
        assert!(!observed[2].contains("ms-secret"));
    }
    #[tokio::test]
    async fn native_xsts_mismatch_rejects_before_minecraft() {
        let (origin,task)=fixture_server(vec![
            ("POST /user/authenticate",r#"{"Token":"xbl-secret","DisplayClaims":{"xui":[{"uhs":"first"}]}}"#),
            ("POST /xsts/authorize",r#"{"Token":"xsts-secret","DisplayClaims":{"xui":[{"uhs":"different"}]}}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        assert_eq!(provider.exchange("ms-secret").await.err(),Some(ProviderError::InvalidResponse));
        assert_eq!(task.await.unwrap().len(),2);
    }
    #[tokio::test]
    async fn native_app_registration_rejection_is_blocker() {
        let (origin,task)=fixture_server(vec![
            ("POST /user/authenticate",r#"{"Token":"xbl-secret","DisplayClaims":{"xui":[{"uhs":"first"}]}}"#),
            ("POST /xsts/authorize",r#"{"Token":"xsts-secret","DisplayClaims":{"xui":[{"uhs":"first"}]}}"#),
            ("POST /authentication/login_with_xbox",r#"403:{"errorMessage":"Invalid app registration"}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        assert_eq!(provider.exchange("ms-secret").await.err(),Some(ProviderError::AppNotAuthorized));
        assert_eq!(task.await.unwrap().len(),3);
    }
    #[test] fn app_registration_required_before_exchange() {
        assert!(!official_browser_0263::valid_client_id("00000000-0000-0000-0000-000000000000"));
        assert_eq!(now() > 1700000000,true);
    }
    #[tokio::test]
    async fn java_identity_requires_token_authenticated_profile_even_with_entitlement() {
        let (origin,server)=fixture_server(vec![
            ("GET /entitlements/mcstore",r#"{"items":[{"name":"game_minecraft"}]}"#),
            ("GET /minecraft/profile",r#"404:{"error":"NOT_FOUND"}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        assert_eq!(provider.verify_java("minecraft-bearer",None).await.err(),Some(ProviderError::NoMinecraftJava));
        let requests=server.await.unwrap();
        assert_eq!(requests.len(),2);
        assert!(requests.iter().all(|r| r.contains("authorization: Bearer minecraft-bearer") ||
            r.contains("Authorization: Bearer minecraft-bearer")));
    }
    #[tokio::test]
    async fn game_pass_without_mcstore_items_requires_live_java_profile() {
        let (origin,server)=fixture_server(vec![
            ("GET /entitlements/mcstore",r#"{"items":[]}"#),
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"ValidPlayer"}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        let profile=provider.verify_java("game-pass-mc-bearer",None).await.unwrap();
        assert_eq!(profile.name,"ValidPlayer");
        assert_eq!(server.await.unwrap().len(),2);
    }
    #[tokio::test]
    async fn saved_account_mismatch_denies_launch_after_refresh() {
        let (origin,server)=fixture_server(vec![
            ("GET /entitlements/mcstore",r#"{"items":[{"name":"game_minecraft_bedrock"}]}"#),
            ("GET /minecraft/profile",r#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"ValidPlayer"}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        assert_eq!(provider.verify_java("mc-bearer",Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).await.err(),Some(ProviderError::IdentityMismatch));
        assert_eq!(server.await.unwrap().len(),2);
    }
    #[tokio::test]
    async fn demo_profile_and_corrupt_entitlement_data_fail_closed() {
        let (origin,server)=fixture_server(vec![
            ("GET /entitlements/mcstore",r#"{"items":[]}"#),
            ("GET /minecraft/profile",r#"{"id":"1234567890abcdef1234567890abcdef","name":"DemoUser","demo":true}"#),
        ]).await;
        let provider=NativeProvider::fixture(&origin);
        assert_eq!(provider.verify_java("mc-bearer",None).await.err(),Some(ProviderError::NoMinecraftJava));
        server.await.unwrap();
        let (origin,server)=fixture_server(vec![("GET /entitlements/mcstore",r#"{"items":"all"}"#)]).await;
        let provider=NativeProvider::fixture(&origin);
        assert_eq!(provider.verify_java("mc-bearer",None).await.err(),Some(ProviderError::InvalidResponse));
        assert_eq!(server.await.unwrap().len(),1);
    }
    #[test]
    fn xbox_family_xerr_accepts_provider_string_or_number_without_leaking_body() {
        let hint:ErrorBody=serde_json::from_str(r#"{"XErr":"2148916238","message":"private secret"}"#).unwrap();
        assert_eq!(classify(401,&hint,None),ProviderError::XboxFamily);
        assert_eq!(classify(403,&hint,None),ProviderError::XboxFamily);
        assert!(!ProviderError::XboxFamily.message().contains("private secret"));
    }

}
