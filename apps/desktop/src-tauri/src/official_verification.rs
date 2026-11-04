//! Java Edition admission checks for the native Microsoft/Xbox/Minecraft flow.
//! This is a *game* authorization gate, not an OIDC/Never sign-in gate.
use crate::{official_exchange_0265::ProviderError, official_identity_0262::OfficialProfile};

/// Internal evidence only; never sent to renderer or persisted as an ownership
/// assertion (ownership can change after account revocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JavaAccessEvidence {
    JavaLicense,
    GamePassCandidate,
    ProfileBased,
}

/// Only known Java Edition product names count as Java ownership.
/// Bedrock/Dungeons/unknown item names MUST NOT authorize Java by themselves.
pub(crate) fn inspect_entitlements(names: &[String]) -> Result<JavaAccessEvidence, ProviderError> {
    if names.len() > 1024 || names.iter().any(|s| s.is_empty() || s.len()>128 ||
        !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')) {
        return Err(ProviderError::InvalidResponse);
    }
    if names.iter().any(|v| matches!(v.as_str(), "game_minecraft" | "product_minecraft")) {
        Ok(JavaAccessEvidence::JavaLicense)
    } else if names.iter().any(|v| matches!(v.as_str(), "product_game_pass_pc" | "game_pass_pc")) {
        // Game Pass entitlements are not always populated in mcstore.
        Ok(JavaAccessEvidence::GamePassCandidate)
    } else {
        Ok(JavaAccessEvidence::ProfileBased)
    }
}

/// Minecraft Services /minecraft/profile is token-authenticated. An empty
/// entitlement list (e.g. Game Pass) is acceptable only with a real Java
/// profile from that SAME token. This never bypasses the Minecraft session
/// server, multiplayer/privacy checks or external application approval.
pub(crate) fn verify_playable_profile(
    profile: &OfficialProfile, expected_uuid: Option<&str>, _evidence: JavaAccessEvidence,
) -> Result<(), ProviderError> {
    if profile.id.len()!=32 || !profile.id.bytes().all(|b|b.is_ascii_hexdigit()) ||
        profile.id.bytes().all(|b|b==b'0') || !(3..=16).contains(&profile.name.len()) ||
        !profile.name.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'_') {
        return Err(ProviderError::NoMinecraftJava);
    }
    if let Some(expected) = expected_uuid {
        // Only the verified Minecraft UUID identifies a persisted account;
        // display name can change and must not be used to authorize a switch.
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
