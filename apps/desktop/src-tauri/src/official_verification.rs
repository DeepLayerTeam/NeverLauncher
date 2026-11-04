//! Java Edition admission checks for the native Microsoft/Xbox/Minecraft flow.
//! This is a *game* authorization gate, not an OIDC/Never sign-in gate.
use crate::{official_exchange_0265::ProviderError, official_identity_0262::OfficialProfile};

/// Только внутреннее доказательство; не отправляется в рендерер и не сохраняется как постоянное
/// подтверждение владения, поскольку оно может измениться после отзыва учётной записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JavaAccessEvidence {
    JavaLicense,
    GamePassCandidate,
    ProfileBased,
}

/// Только известные названия продуктов Java Edition подтверждают право на Java.
/// Bedrock, Dungeons и неизвестные продукты сами по себе НЕ разрешают Java.
pub(crate) fn inspect_entitlements(names: &[String]) -> Result<JavaAccessEvidence, ProviderError> {
    if names.len() > 1024 || names.iter().any(|s| s.is_empty() || s.len()>128 ||
        !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')) {
        return Err(ProviderError::InvalidResponse);
    }
    if names.iter().any(|v| matches!(v.as_str(), "game_minecraft" | "product_minecraft")) {
        Ok(JavaAccessEvidence::JavaLicense)
    } else if names.iter().any(|v| matches!(v.as_str(), "product_game_pass_pc" | "game_pass_pc")) {
        // Права Game Pass не всегда заполняются в mcstore.
        Ok(JavaAccessEvidence::GamePassCandidate)
    } else {
        Ok(JavaAccessEvidence::ProfileBased)
    }
}

/// Маршрут Minecraft Services /minecraft/profile аутентифицируется токеном. Пустой
/// список прав, например при Game Pass, допустим только при наличии реального
/// Java-профиля из ТОГО ЖЕ токена. Это не обходит сервер сеансов Minecraft,
/// проверки мультиплеера, приватности или разрешение внешнего приложения.
pub(crate) fn verify_playable_profile(
    profile: &OfficialProfile, expected_uuid: Option<&str>, _evidence: JavaAccessEvidence,
) -> Result<(), ProviderError> {
    if profile.id.len()!=32 || !profile.id.bytes().all(|b|b.is_ascii_hexdigit()) ||
        profile.id.bytes().all(|b|b==b'0') || !(3..=16).contains(&profile.name.len()) ||
        !profile.name.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'_') {
        return Err(ProviderError::NoMinecraftJava);
    }
    if let Some(expected) = expected_uuid {
        // Только проверенный UUID Minecraft идентифицирует сохранённую учётную
        // запись; отображаемое имя меняется и не может разрешать переключение.
        if expected.len()!=32 || !expected.bytes().all(|b|b.is_ascii_hexdigit()) ||
            !expected.eq_ignore_ascii_case(&profile.id) {
            return Err(ProviderError::IdentityMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(id:&str,name:&str)->OfficialProfile {
        OfficialProfile {id:id.into(),name:name.into(),skins:Vec::new(),capes:Vec::new()}
    }
    #[test]
    fn bedrock_or_unknown_entitlements_do_not_claim_java_ownership() {
        assert_eq!(inspect_entitlements(&["game_minecraft_bedrock".into()]).unwrap(),JavaAccessEvidence::ProfileBased);
        assert_eq!(inspect_entitlements(&["game_minecraft".into()]).unwrap(),JavaAccessEvidence::JavaLicense);
        assert_eq!(inspect_entitlements(&["product_game_pass_pc".into()]).unwrap(),JavaAccessEvidence::GamePassCandidate);
        assert_eq!(inspect_entitlements(&[]).unwrap(),JavaAccessEvidence::ProfileBased);
        assert_eq!(inspect_entitlements(&["".into()]),Err(ProviderError::InvalidResponse));
    }
    #[test]
    fn uuid_is_authoritative_and_username_is_only_display_metadata() {
        let id="1234567890abcdef1234567890abcdef";
        assert_eq!(verify_playable_profile(&profile(id,"OldName"),Some(id),JavaAccessEvidence::ProfileBased),Ok(()));
        assert_eq!(verify_playable_profile(&profile(id,"NewName"),Some(&id.to_uppercase()),JavaAccessEvidence::ProfileBased),Ok(()));
        assert_eq!(verify_playable_profile(&profile("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","OldName"),Some(id),JavaAccessEvidence::JavaLicense),Err(ProviderError::IdentityMismatch));
        assert_eq!(verify_playable_profile(&profile("00000000000000000000000000000000","OldName"),None,JavaAccessEvidence::JavaLicense),Err(ProviderError::NoMinecraftJava));
    }
}
