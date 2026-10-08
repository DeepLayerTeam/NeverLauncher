use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION: u32 = 2;
pub const NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION: u32 = 1;
pub const NEVERGUARD_WINDOWS_PROTECTION_CORE_SCHEMA: &str =
    "neverguard/windows-protection-core/v1";
pub const NEVERGUARD_WINDOWS_PROTECTION_PROFILE_ENV: &str =
    "NEVERGUARD_WINDOWS_PROTECTION_PROFILE";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum WindowsProtectionProfile {
    Audit,
    Compat,
    #[default]
    Aggressive,
}

impl WindowsProtectionProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Compat => "compat",
            Self::Aggressive => "aggressive",
        }
    }

    pub const fn is_remote_attestation_eligible(self) -> bool {
        matches!(self, Self::Aggressive)
    }
}


impl fmt::Display for WindowsProtectionProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for WindowsProtectionProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "audit" => Ok(Self::Audit),
            "compat" => Ok(Self::Compat),
            "aggressive" => Ok(Self::Aggressive),
            other => Err(format!(
                "unsupported NeverGuard Windows protection profile {other:?}; expected audit, compat or aggressive"
            )),
        }
    }
}

pub fn protection_profile_from_environment() -> Result<WindowsProtectionProfile, String> {
    match std::env::var(NEVERGUARD_WINDOWS_PROTECTION_PROFILE_ENV) {
        Ok(value) if !value.trim().is_empty() => value.parse(),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(WindowsProtectionProfile::Aggressive),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{NEVERGUARD_WINDOWS_PROTECTION_PROFILE_ENV} is not valid UTF-8"
        )),
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct WindowsMitigationRequirements {
    pub dynamic_code: u32,
    pub extension_point_disable: u32,
    pub strict_handle_check: u32,
    pub image_load: u32,
    pub child_process: u32,
}

impl WindowsMitigationRequirements {
    pub const fn for_profile(profile: WindowsProtectionProfile) -> Self {
        match profile {
            WindowsProtectionProfile::Audit => Self {
                dynamic_code: 0,
                extension_point_disable: 0,
                strict_handle_check: 0,
                image_load: 0,
                child_process: 0,
            },
            WindowsProtectionProfile::Compat => Self {
                dynamic_code: 0,
                extension_point_disable: 0x0000_0001,
                strict_handle_check: 0x0000_0003,
                image_load: 0x0000_0003,
                child_process: 0x0000_0001,
            },
            WindowsProtectionProfile::Aggressive => Self {
                dynamic_code: 0x0000_0001,
                extension_point_disable: 0x0000_0001,
                strict_handle_check: 0x0000_0003,
                image_load: 0x0000_0007,
                child_process: 0x0000_0001,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsMitigationCapability {
    pub supported: bool,
    pub required_flags: u32,
    pub observed_flags: u32,
    pub satisfied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_error: Option<String>,
}

impl WindowsMitigationCapability {
    pub fn unsupported(required_flags: u32, error: String) -> Self {
        Self {
            supported: false,
            required_flags,
            observed_flags: 0,
            satisfied: required_flags == 0,
            query_error: Some(error),
        }
    }

    pub fn observed(required_flags: u32, observed_flags: u32) -> Self {
        Self {
            supported: true,
            required_flags,
            observed_flags,
            satisfied: observed_flags & required_flags == required_flags,
            query_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProtectionCapabilities {
    pub model_version: u32,
    pub architecture: String,
    pub dynamic_code_policy: WindowsMitigationCapability,
    pub extension_point_disable_policy: WindowsMitigationCapability,
    pub strict_handle_check_policy: WindowsMitigationCapability,
    pub image_load_policy: WindowsMitigationCapability,
    pub child_process_policy: WindowsMitigationCapability,
    pub guard_lifetime_job_bound: bool,
}

impl WindowsProtectionCapabilities {
    pub fn requirements_satisfied(&self) -> bool {
        [
            &self.dynamic_code_policy,
            &self.extension_point_disable_policy,
            &self.strict_handle_check_policy,
            &self.image_load_policy,
            &self.child_process_policy,
        ]
        .into_iter()
        .all(|capability| capability.satisfied)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsGuardPolicyDetails {
    pub core_schema: String,
    pub core_version: u32,
    pub capability_model_version: u32,
    pub profile: WindowsProtectionProfile,
    pub remote_attestation_eligible: bool,
    pub requirements: WindowsMitigationRequirements,
    pub capabilities: WindowsProtectionCapabilities,
    pub requirements_satisfied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProtectionCoreReport<P, H> {
    pub schema: String,
    pub core_version: u32,
    pub profile: WindowsProtectionProfile,
    pub capability_model_version: u32,
    pub process_policy: P,
    pub hardening: H,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_parse_and_default_to_aggressive() {
        assert_eq!("audit".parse(), Ok(WindowsProtectionProfile::Audit));
        assert_eq!("COMPAT".parse(), Ok(WindowsProtectionProfile::Compat));
        assert_eq!(" aggressive ".parse(), Ok(WindowsProtectionProfile::Aggressive));
        assert_eq!(WindowsProtectionProfile::default(), WindowsProtectionProfile::Aggressive);
        assert!("disabled".parse::<WindowsProtectionProfile>().is_err());
    }

    #[test]
    fn profiles_have_real_distinct_mitigation_requirements() {
        let audit = WindowsMitigationRequirements::for_profile(WindowsProtectionProfile::Audit);
        let compat = WindowsMitigationRequirements::for_profile(WindowsProtectionProfile::Compat);
        let aggressive =
            WindowsMitigationRequirements::for_profile(WindowsProtectionProfile::Aggressive);

        assert_eq!(audit, WindowsMitigationRequirements::default());
        assert_eq!(compat.dynamic_code, 0);
        assert_eq!(compat.image_load, 0x3);
        assert_eq!(aggressive.dynamic_code, 0x1);
        assert_eq!(aggressive.image_load, 0x7);
        assert!(WindowsProtectionProfile::Aggressive.is_remote_attestation_eligible());
        assert!(!WindowsProtectionProfile::Compat.is_remote_attestation_eligible());
    }

    #[test]
    fn capability_satisfaction_is_bit_exact() {
        let satisfied = WindowsMitigationCapability::observed(0x3, 0x7);
        let missing = WindowsMitigationCapability::observed(0x3, 0x1);
        let optional_unsupported =
            WindowsMitigationCapability::unsupported(0, "unsupported".to_string());
        assert!(satisfied.satisfied);
        assert!(!missing.satisfied);
        assert!(optional_unsupported.satisfied);
    }
}
