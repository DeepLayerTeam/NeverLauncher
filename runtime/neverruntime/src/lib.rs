pub mod attestation;
pub mod compatibility;
mod deterministic_launch;
mod launch_identity_0269;
pub mod file_ownership;
pub mod component_catalog_0241;
pub mod component_actions_0245;
pub mod component_selection_02410;
pub mod resolved_download_0246;
mod platform_fs;
pub mod download_scheduler;
mod http_resume;
mod content_cache;
mod network_resilience;
pub mod durable_downloads;
pub mod player_migration_0339;
pub mod transactional_release;
mod release_generations;
mod trust_policy;
pub use download_scheduler::{DownloadLimits, DownloadProgress, ProgressSink, DOWNLOAD_PROGRESS_EVENT};
pub mod managed_java;
pub mod guard_ipc;
mod integrity;
pub mod supervisor;
pub mod windows_policy;
pub mod windows_protection;
pub mod windows_sensor;
pub mod windows_module_guard;
pub mod windows_hook_engine;
pub mod windows_memory_integrity;
pub mod windows_thread_process_integrity;
pub mod windows_debug_instrumentation;
pub mod windows_jvm_aware;
pub mod windows_continuous_guard;
pub mod windows_attestation_v2;
pub mod linux_policy;
pub mod macos_policy;
#[cfg(target_os = "linux")]
pub mod linux_guard;
#[cfg(target_os = "macos")]
pub mod macos_guard;
pub use attestation::{GuardAttestationRequest, NeverGuardRemoteAttestation, NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_MACOS_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_REMOTE_ATTESTATION_VERSION};
pub use compatibility::{resolve_compatibility, CompatibilityContext, CompatibilityEnvironment, CompatibilityResolution, ResolvedLibrary, ResolvedNative};
pub use managed_java::{ensure_managed_java, ensure_managed_java_from_distribution, select_java_executable, ManagedJavaResult};
pub use integrity::{
    verify_windows_authenticode_trust, AuthenticodeEvidence, BoundaryEvidence, LinuxProcessSecurityEvidence, MacOSProcessSecurityEvidence, ModuleSetEvidence,
    NeverGuardIntegrityEvidence, ProcessIntegrityEvidence, ProcessMitigationEvidence, NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA,
    NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA, NEVERGUARD_MACOS_INTEGRITY_EVIDENCE_SCHEMA, NEVERGUARD_INTEGRITY_EVIDENCE_VERSION,
};
pub use guard_ipc::{neverguard_executable_name, run_windows_guard_server, validate_neverguard_path, NeverGuardStatus, NEVERGUARD_PROTOCOL_VERSION};
#[cfg(windows)]
pub use guard_ipc::NeverGuardSupervisor;
#[cfg(target_os = "linux")]
pub use linux_guard::{run_linux_guard_server, NeverGuardSupervisor};
#[cfg(target_os = "macos")]
pub use macos_guard::{run_macos_guard_server, NeverGuardSupervisor};
#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub use guard_ipc::NeverGuardSupervisor;
pub use supervisor::{ProcessStatus, ProcessSupervisor};
pub use windows_policy::{
    ensure_guard_process_policy, ensure_guard_process_policy_with_profile,
    ensure_windows_production_hardening, ensure_windows_protection_core,
    ensure_windows_protection_core_with_profile, validate_windows_guard_policy_report,
    GuardProcessPolicyReport, RuntimeProcessPolicyReport, RuntimeProcessPolicyGuard,
    RuntimeProcessTreeSnapshot,
    WindowsProductionHardeningReport, WindowsProtectionCoreReport,
    NEVERGUARD_WINDOWS_HARDENING_VERSION, NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA,
    NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
};
pub use windows_protection::{
    protection_profile_from_environment, WindowsGuardPolicyDetails,
    WindowsMitigationCapability, WindowsMitigationRequirements, WindowsProtectionCapabilities,
    WindowsProtectionProfile, NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
    NEVERGUARD_WINDOWS_PROTECTION_CORE_SCHEMA, NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION,
    NEVERGUARD_WINDOWS_PROTECTION_PROFILE_ENV,
};
pub use windows_sensor::{WindowsSensorBootstrap, WindowsSensorReport, WindowsSensorSession, NEVERGUARD_SENSOR_FILE_NAME, NEVERGUARD_SENSOR_PIPE_ENV, NEVERGUARD_SENSOR_PROTOCOL_VERSION, NEVERGUARD_SENSOR_SECRET_ENV};
pub use windows_module_guard::{WindowsModuleGuardPolicy, WindowsModuleGuardReport, WindowsModuleGuardSession, NEVERGUARD_MODULE_GUARD_VERSION};
pub use windows_hook_engine::{WindowsHookEngineReport, NEVERGUARD_HOOK_ENGINE_VERSION};
pub use windows_memory_integrity::{WindowsMemoryIntegrityReport, NEVERGUARD_MEMORY_INTEGRITY_VERSION};
pub use windows_thread_process_integrity::{
    WindowsThreadProcessIntegrityReport, NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION,
};
pub use windows_debug_instrumentation::{
    WindowsDebugInstrumentationReport, NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION,
};
pub use windows_jvm_aware::{
    WindowsJvmAwareProtectionReport, NEVERGUARD_CERTIFIED_JAVA_MAJORS,
    NEVERGUARD_JVM_AWARE_PROTECTION_VERSION,
};
pub use windows_continuous_guard::{
    WindowsContinuousGuardReport, NEVERGUARD_CONTINUOUS_GUARD_VERSION,
};
pub use windows_attestation_v2::{
    build_windows_attestation_v2, collect_windows_continuous_evidence_v2,
    recompute_continuous_evidence_sha256, recompute_windows_attestation_v2_sha256,
    validate_continuous_evidence_v2, NeverGuardRemoteAttestationV2,
    WindowsContinuousEvidenceV2, NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_SCHEMA,
    NEVERGUARD_WINDOWS_CONTINUOUS_EVIDENCE_VERSION, NEVERGUARD_WINDOWS_REMOTE_ATTESTATION_V2_SCHEMA,
    NEVERGUARD_WINDOWS_REMOTE_ATTESTATION_V2_VERSION,
};
pub use linux_policy::{LinuxGuardPolicyDetails, LinuxProductionHardeningReport, LinuxRuntimeProcessPolicyReport, NEVERGUARD_LINUX_HARDENING_VERSION, NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA, NEVERGUARD_LINUX_PROCESS_POLICY_VERSION};
pub use macos_policy::{MacOSCodeSignatureState, MacOSGuardPolicyDetails, MacOSProductionHardeningReport, MacOSRuntimeProcessPolicyReport, NEVERGUARD_MACOS_HARDENING_VERSION, NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA, NEVERGUARD_MACOS_PROCESS_POLICY_VERSION};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Component, Path, PathBuf},
    process::Stdio,
    io::SeekFrom,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process::Command,
    time::{timeout, Duration},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: String,
    pub project_id: String,
    pub profile_id: String,
    pub channel: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "is_zero_u64_02311")]
    pub game_release_generation: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64_02311")]
    pub trust_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_source: Option<GameRollbackSource02311>,
    pub created_at: String,
    pub minecraft: MinecraftInfo,
    pub runtime: RuntimeInfo,
    #[serde(default)]
    pub directories: Directories,
    pub files: Vec<ManifestFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_rules: Vec<file_ownership::FileRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_snapshot: Option<ProfileSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_catalog: Option<component_catalog_0241::ComponentCatalog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileSpec {
    pub project_id: String,
    pub id: String,
    pub name: String,
    pub description: String,
    pub loader: String,
    pub preset: String,
    pub is_default: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileSnapshot {
    pub schema_version: String,
    pub revision: u64,
    pub digest: String,
    pub spec: ProfileSpec,
}

fn is_zero_u64_02311(value: &u64) -> bool { *value == 0 }

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRollbackSource02311 {
    pub version: String,
    pub manifest_sha256: String,
    pub game_release_generation: u64,
}

fn validate_manifest_schema(manifest: &Manifest) -> Result<(), String> {
    if let Some(ref source) = manifest.rollback_source {
        if manifest.game_release_generation == 0 || source.version.is_empty() ||
           source.game_release_generation >= manifest.game_release_generation ||
           source.manifest_sha256.len() != 64 ||
           !source.manifest_sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid signed game rollback source/generation".into());
        }
    }
    match (manifest.schema_version.as_str(), manifest.profile_snapshot.as_ref()) {
        ("1.0", None) => {component_catalog_0241::validate(manifest)?;Ok(())},
        ("2.0" | "3.0", Some(snapshot)) => {
            if snapshot.schema_version != "2.0" || snapshot.revision == 0 ||
               snapshot.spec.project_id != manifest.project_id || snapshot.spec.id != manifest.profile_id ||
               snapshot.spec.name.is_empty() || snapshot.spec.loader.is_empty() {
                return Err("invalid v2 profile snapshot identity".into());
            }
            use sha2::{Sha256, Digest};
            let sep = "\0";
            let digest_payload = [snapshot.spec.project_id.as_str(), snapshot.spec.id.as_str(),
                snapshot.spec.name.as_str(), snapshot.spec.description.as_str(),
                snapshot.spec.loader.as_str(), snapshot.spec.preset.as_str(),
                if snapshot.spec.is_default {"true"} else {"false"}].join(sep);
            let actual = hex::encode(Sha256::digest(digest_payload.as_bytes()));
            if snapshot.digest != actual {return Err("v2 profile snapshot digest mismatch".into());}
            validate_runtime_constraints_0223(manifest)?;
            file_ownership::validate_policy(manifest)?;
            component_catalog_0241::validate(manifest)?;
            Ok(())
        }
        _ => Err(format!("unsupported manifest schema or missing profileSnapshot: {}", manifest.schema_version)),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftInfo {
    pub version: String,
    pub loader: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub loader_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub game_args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInfo {
    pub java: JavaInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jvm_args: Vec<String>,
    #[serde(default)]
    pub memory: MemoryInfo,
    #[serde(default)]
    pub launch: RuntimeLaunch,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JavaInfo {
    pub major_version: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub minimum_major_version: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub recommended_major_version: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub maximum_major_version: u32,
    pub distribution: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_custom_path: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct MemoryInfo {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub minimum_mb: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub recommended_mb: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub maximum_mb: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLaunch {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main_class: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub classpath_strategy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub natives_directory: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version_metadata_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classpath_entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modulepath_entries: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main_module: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty", serialize_with = "serialize_sorted_features_0227")]
    pub features: HashMap<String, bool>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub offline_mode: bool,
}

// Preserve the existing Go-compatible Manifest v2 signing payload field order.
// Go json.Marshal sorts map keys; Rust HashMap iteration must not introduce
// random signing payloads or intermittent Ed25519 verification failures.
fn serialize_sorted_features_0227<S: serde::Serializer>(value: &HashMap<String, bool>, serializer: S) -> Result<S::Ok, S::Error> {
    let sorted: BTreeMap<&str, &bool> = value.iter().map(|(name, enabled)| (name.as_str(), enabled)).collect();
    sorted.serialize(serializer)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftLaunchCredentials {
    pub username: String,
    pub uuid: String,
    pub access_token: String,
    #[serde(default = "default_minecraft_user_type")]
    pub user_type: String,
    #[serde(default)]
    pub auth_server_base_url: String,
}

fn default_minecraft_user_type() -> String { "mojang".to_string() }

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Directories {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub game: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub assets: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub libraries: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub natives: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub url: String,
    /// Ordered, independently SHA-256 verified fallback sources. Included in the signed manifest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirrors: Vec<String>,
    pub required: bool,
    #[serde(default)]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_os: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ownership: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureCheckResult {
    pub valid: bool,
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileCheckResult {
    pub path: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DownloadResult {
    pub downloaded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub repaired: usize,
    pub bytes_downloaded: u64,
    #[serde(default)]
    pub cache_hits: usize,
    #[serde(default)]
    pub bytes_reused: u64,
    pub failed_files: Vec<String>,
    pub messages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RepairResult {
    pub status: String,
    pub before: Vec<FileCheckResult>,
    pub download: DownloadResult,
    pub after: Vec<FileCheckResult>,
    pub repaired: usize,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CleanUnusedResult {
    pub moved: usize,
    pub preserved: usize,
    pub quarantine_dir: String,
    pub messages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchHistoryEntry {
    pub started_at: String,
    pub project_id: String,
    pub profile_id: String,
    pub version: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub log_path: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JavaInfoResult {
    pub found: bool,
    pub compatible: bool,
    pub required_major_version: u32,
    pub detected_major_version: Option<u32>,
    pub executable: String,
    pub version_output: String,
    pub recommended_memory_mb: Option<u32>,
    pub maximum_memory_mb: Option<u32>,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchPlan {
    pub java_executable: String,
    pub working_directory: String,
    pub main_class: String,
    pub classpath_entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modulepath_entries: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub main_module: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub restrict_java_environment: bool,
    pub jvm_args: Vec<String>,
    pub game_args: Vec<String>,
    pub command_preview: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deterministic_sha256: String,
}

// Local user choices do not change the signed Manifest. They are validated
// against its limits, then applied to the actual Java invocation (not just UI).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchPreferences {
    #[serde(default)] pub memory_mb: Option<u32>,
    #[serde(default)] pub width: Option<u32>,
    #[serde(default)] pub height: Option<u32>,
    #[serde(default)] pub fullscreen: bool,
    #[serde(default)] pub auto_enter: bool,
    #[serde(default)] pub server_host: Option<String>,
    #[serde(default)] pub server_port: Option<u16>,
    #[serde(default)] pub offline: bool,
}

pub fn validate_launch_preferences(manifest: &Manifest, p: &LaunchPreferences, authenticated: bool) -> Result<(), String> {
    if (manifest.schema_version != "2.0" && manifest.schema_version != "3.0") { return Err("Desktop launch preferences require a signed v2/v3 Manifest".into()); }
    if p.offline {
        if authenticated || !manifest.runtime.launch.offline_mode {
            return Err("offline launch is not authorized by the signed profile".into());
        }
        if p.auto_enter { return Err("offline mode cannot auto-enter a protected server".into()); }
    }
    if let Some(memory) = p.memory_mb {
        let policy = &manifest.runtime.memory;
        if memory < policy.minimum_mb.max(512) || memory > (if policy.maximum_mb > 0 { policy.maximum_mb.min(32768) } else { 32768 }) {
            return Err(format!("RAM {memory} MB is outside signed profile limits"));
        }
        if policy.minimum_mb > memory { return Err("RAM lower than minimum memory".into()); }
    }
    if p.width.is_some() != p.height.is_some() { return Err("resolution width and height must be supplied together".into()); }
    if let (Some(width), Some(height)) = (p.width, p.height) {
        if !(640..=7680).contains(&width) || !(480..=4320).contains(&height) {
            return Err("resolution outside supported bounds".into());
        }
    }
    if p.auto_enter {
        let host = p.server_host.as_deref().unwrap_or("");
        if host.is_empty() || host.len() > 253 || host.split('.').any(|label| {
            label.is_empty() || label.len() > 63 ||
            !label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric) ||
            !label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric) ||
            !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) {
            return Err("invalid server address for auto-enter".into());
        }
        if p.server_port.unwrap_or(0) == 0 { return Err("auto-enter requires a valid server port".into()); }
    }
    Ok(())
}

pub fn apply_launch_preferences(manifest: &Manifest, root: &Path, plan: &mut LaunchPlan, preferences: &LaunchPreferences, credentials: Option<&MinecraftLaunchCredentials>) -> Result<(), String> {
    validate_launch_preferences(manifest, preferences, credentials.is_some())?;
    if let Some(memory) = preferences.memory_mb {
        // Never allow unsigned extra JVM flags to override the chosen -Xmx.
        plan.jvm_args.retain(|arg| !arg.starts_with("-Xmx"));
        plan.jvm_args.push(format!("-Xmx{memory}M"));
        // The core planner has already verified and inserted its internal
        // signed authlib agent. That agent is not a user JVM override and
        // must not cause this post-auth heap-only policy check to fail.
        let heap_check_args = plan.jvm_args.iter().filter(|arg| !arg.starts_with("-javaagent:")).cloned().collect::<Vec<_>>();
        validate_memory_arguments_0223(&manifest.runtime.memory, &heap_check_args)?;
    }
    if let (Some(width), Some(height)) = (preferences.width, preferences.height) {
        replace_or_append_arg_pair(&mut plan.game_args, "--width", width.to_string());
        replace_or_append_arg_pair(&mut plan.game_args, "--height", height.to_string());
    }
    plan.game_args.retain(|arg| arg != "--fullscreen");
    if preferences.fullscreen { plan.game_args.push("--fullscreen".into()); }
    if preferences.auto_enter {
        let host = preferences.server_host.as_ref().ok_or("server host missing")?;
        let port = preferences.server_port.ok_or("server port missing")?;
        if minecraft_supports_quick_play_multiplayer(&manifest.minecraft.version) {
            replace_or_append_arg_pair(&mut plan.game_args, "--quickPlayMultiplayer", format!("{host}:{port}"));
        } else {
            replace_or_append_arg_pair(&mut plan.game_args, "--server", host.clone());
            replace_or_append_arg_pair(&mut plan.game_args, "--port", port.to_string());
        }
    }
    // User choices are part of the reproducible plan identity, unlike session
    // tokens and machine-specific installation paths.
    plan.deterministic_sha256 = deterministic_launch::plan_digest(manifest, root, manifest.runtime.java.major_version, plan, credentials)?;
    plan.command_preview = redacted_command_preview119(plan, credentials.map(|c| c.access_token.as_str()));
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchResult {
    pub exit_code: Option<i32>,
    pub success: bool,
    #[serde(default)]
    pub timed_out: bool,
    pub log_path: String,
    pub stdout: String,
    pub stderr: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VanillaCompatibilityProbeResult {
    pub status: String,
    pub minecraft_version: String,
    pub required_java_major: u32,
    pub detected_java_major: u32,
    pub java_executable: String,
    pub main_class: String,
    pub classpath_entries: usize,
    pub natives_directory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_server_port: Option<u16>,
    pub success: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub log_path: String,
    pub runtime_seconds: u64,
    pub message: String,
}

pub async fn load_manifest(url: &str, pinned_public_key: &str) -> Result<Manifest, String> {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|err| format!("не удалось запросить манифест: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("backend вернул статус {}", response.status()));
    }
    let manifest = response
        .json::<Manifest>()
        .await
        .map_err(|err| format!("не удалось разобрать манифест: {err}"))?;
    verify_manifest_signature(&manifest, pinned_public_key)?;
    Ok(manifest)
}

pub fn verify_manifest_signature(manifest: &Manifest, pinned_public_key: &str) -> Result<SignatureCheckResult, String> {
    let pinned = pinned_public_key.trim();
    if pinned.is_empty() {
        return Err("pinned Ed25519 public key обязателен; trust-on-first-use запрещён".to_string());
    }
    let signature_info = manifest
        .signature
        .clone()
        .ok_or_else(|| "в манифесте отсутствует блок signature".to_string())?;
    if signature_info.algorithm != "Ed25519" {
        return Err(format!("неподдерживаемый алгоритм подписи: {}", signature_info.algorithm));
    }
    let public_key_hex = signature_info.public_key.trim().to_string();
    if manifest.trust_epoch == 0 && !pinned.eq_ignore_ascii_case(&public_key_hex) {
        return Err("публичный ключ манифеста не совпадает с закреплённым ключом проекта".to_string());
    }
    let public_key_bytes = hex::decode(&public_key_hex)
        .map_err(|err| format!("публичный ключ не является hex-строкой: {err}"))?;
    let signature_bytes = hex::decode(&signature_info.signature)
        .map_err(|err| format!("подпись не является hex-строкой: {err}"))?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "публичный ключ Ed25519 должен иметь длину 32 байта".to_string())?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "подпись Ed25519 должна иметь длину 64 байта".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|err| format!("публичный ключ Ed25519 некорректен: {err}"))?;
    let signature = Signature::from_bytes(&signature_array);
    validate_manifest_schema(manifest)?;
    let payload = manifest_signing_payload(manifest)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| "подпись манифеста не прошла проверку".to_string())?;
    trust_policy::verify_manifest(manifest, pinned, &public_key_hex, &signature_info.signed_at)?;
    Ok(SignatureCheckResult {
        valid: true,
        public_key: public_key_hex,
        message: "подпись манифеста корректна и соответствует pinned key".to_string(),
    })
}

pub fn sign_manifest(manifest: &mut Manifest, private_key_hex: &str, signed_at: &str) -> Result<String, String> {
    let bytes = hex::decode(private_key_hex.trim()).map_err(|err| format!("private key не является hex: {err}"))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| "Ed25519 private key seed должен быть 32 байта".to_string())?;
    validate_manifest_schema(manifest)?;
    file_ownership::validate_download_targets(manifest)?;
    manifest.signature = None;
    let payload = manifest_signing_payload(manifest)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(&payload);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    manifest.signature = Some(SignatureInfo {
        algorithm: "Ed25519".to_string(),
        public_key: public_key.clone(),
        signature: hex::encode(signature.to_bytes()),
        signed_at: signed_at.to_string(),
    });
    Ok(public_key)
}

fn manifest_signing_payload(manifest: &Manifest) -> Result<Vec<u8>, String> {
    let mut unsigned = manifest.clone();
    unsigned.signature = None;
    // Go encoding/json (the publishing signer) escapes HTML metacharacters
    // and JavaScript line separators. Rust must verify those exact bytes.
    let json = serde_json::to_string(&unsigned).map_err(|err| format!("не удалось сериализовать payload подписи: {err}"))?;
    Ok(json.replace('&', "\\u0026").replace('<', "\\u003c").replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028").replace('\u{2029}', "\\u2029").into_bytes())
}

pub async fn check_files(manifest: &Manifest, root: &Path) -> Result<Vec<FileCheckResult>, String> {
    validate_manifest_schema(manifest)?;
    let preset=transactional_release::active_preset_for_manifest(manifest,root);
    check_files_with_preset(manifest,root,preset.as_deref()).await
}
pub async fn check_files_with_preset(manifest:&Manifest,root:&Path,preset:Option<&str>)->Result<Vec<FileCheckResult>,String>{
    let selected=component_catalog_0241::active_files(manifest,preset)?;
    let mut results = Vec::with_capacity(selected.len());
    for file in &manifest.files {
        if !selected.contains(&file.path){continue;}
        if !manifest_file_applies(file) { continue; }
        if file_ownership::skip_verification(manifest, file) { continue; }
        let local_path = safe_join(root, &file.path)?;
        file_ownership::ensure_no_symlinks(root, &local_path)?;
        match fs::metadata(&local_path).await {
            Ok(metadata) => {
                if metadata.len() != file.size {
                    results.push(FileCheckResult { path: file.path.clone(), status: "invalid".into(), message: "размер файла не совпадает".into() });
                    continue;
                }
                let hash = sha256_file(&local_path).await?;
                if hash.eq_ignore_ascii_case(&file.sha256) {
                    results.push(FileCheckResult { path: file.path.clone(), status: "ok".into(), message: "файл актуален".into() });
                } else {
                    results.push(FileCheckResult { path: file.path.clone(), status: "invalid".into(), message: "SHA-256 не совпадает".into() });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let optional = manifest.schema_version == "2.0" && file_ownership::effective_ownership(file) == "optional" && !file_ownership::must_verify(manifest, &file.path);
                results.push(FileCheckResult { path: file.path.clone(), status: if optional { "optional-missing" } else { "missing" }.into(), message: "файл отсутствует".into() });
            },
            Err(err) => return Err(format!("{}: {err}", local_path.display())),
        }
    }
    Ok(results)
}

pub async fn download_missing_files(manifest: &Manifest, root: &Path, pinned_public_key: &str) -> Result<DownloadResult, String> {
    download_missing_files_with_progress(manifest, root, pinned_public_key, None).await
}

pub async fn download_missing_files_with_progress(manifest: &Manifest, root: &Path, pinned_public_key: &str,
    progress: Option<ProgressSink>) -> Result<DownloadResult, String> {
    download_missing_files_with_preset(manifest,root,pinned_public_key,progress,None).await
}
pub async fn download_missing_files_with_preset(manifest:&Manifest,root:&Path,pinned_public_key:&str,
    progress:Option<ProgressSink>,preset:Option<String>)->Result<DownloadResult,String>{
    verify_manifest_signature(manifest,pinned_public_key)?;
    file_ownership::validate_download_targets(manifest)?;
    durable_downloads::start_with_preset(manifest,root,pinned_public_key,"download",progress,preset).await
}

// On Unix rename replaces the destination atomically. Windows rename does not
// replace an existing file; retain the original until the verified staged bytes
// are installed, and restore it if the replacement fails.
async fn replace_verified_managed_file_0224(part: &Path, target: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    { fs::rename(part,target).await.map_err(|e| format!("managed file switch {}: {e}",target.display())) }
    #[cfg(windows)]
    {
        if !target.exists() { return fs::rename(part,target).await.map_err(|e| format!("managed file switch {}: {e}",target.display())); }
        let name = target.file_name().ok_or("invalid managed filename")?.to_string_lossy();
        let backup = target.with_file_name(format!("{name}.nlbackup-{}-{}",std::process::id(),now_unix()?));
        if std::fs::symlink_metadata(&backup).is_ok() {return Err("managed backup collision".into());}
        fs::rename(target,&backup).await.map_err(|e| format!("managed backup {}: {e}",target.display()))?;
        if let Err(err)=fs::rename(part,target).await {
            fs::rename(&backup,target).await.map_err(|restore|format!("managed replacement failed: {err}; restore failed: {restore}; backup {}",backup.display()))?;
            return Err(format!("managed replacement failed: {err}"));
        }
        fs::remove_file(&backup).await.map_err(|e| format!("managed replacement installed but backup cleanup failed {}: {e}",backup.display()))
    }
}

pub async fn repair_client(manifest: &Manifest, root: &Path, pinned_public_key: &str) -> Result<RepairResult, String> {
    repair_client_with_progress(manifest, root, pinned_public_key, None).await
}

pub async fn repair_client_with_progress(manifest: &Manifest, root: &Path, pinned_public_key: &str,
    progress: Option<ProgressSink>) -> Result<RepairResult, String> {
    repair_client_with_preset(manifest,root,pinned_public_key,progress,None).await
}
pub async fn repair_client_with_preset(manifest:&Manifest,root:&Path,pinned_public_key:&str,
    progress:Option<ProgressSink>,preset:Option<String>)->Result<RepairResult,String>{
    verify_manifest_signature(manifest,pinned_public_key)?;
    let before=check_files_with_preset(manifest,root,preset.as_deref()).await?;
    let download=durable_downloads::start_with_preset(manifest,root,pinned_public_key,"repair",progress,preset.clone()).await?;
    let after=check_files_with_preset(manifest,root,preset.as_deref()).await?;
    let broken_after = after.iter().filter(|item| item.status != "ok" && item.status != "optional-missing").count();
    Ok(RepairResult {
        status: if broken_after == 0 { "ready" } else { "failed" }.to_string(),
        before,
        repaired: download.repaired,
        download,
        after,
        message: if broken_after == 0 { "Repair завершён: клиент соответствует manifest".to_string() } else { format!("Repair завершён, но осталось проблемных файлов: {broken_after}") },
    })
}

pub async fn clean_unused_files(manifest: &Manifest, root: &Path, pinned_public_key: &str) -> Result<CleanUnusedResult, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    file_ownership::ensure_no_symlinks(root, root)?;
    let expected: HashSet<String> = manifest.files.iter().map(|f| f.path.clone()).collect();
    let quarantine = root.join(".neverlauncher-quarantine").join(now_unix()?.to_string());
    let mut result = CleanUnusedResult { moved: 0, preserved: 0, quarantine_dir: quarantine.to_string_lossy().into_owned(), messages: Vec::new() };
    if !root.exists() { return Ok(result); }
    // Unknown files are user-owned by default. Only explicitly signed include
    // rules for managed directories authorize quarantine. Never follow links.
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            let rel = p.strip_prefix(root).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
            if rel == ".neverlauncher-quarantine" || rel.starts_with(".neverlauncher-quarantine/") { continue; }
            let meta = std::fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() { result.preserved += 1; continue; }
            if meta.is_dir() { stack.push(p); continue; }
            if expected.contains(&rel) || !file_ownership::can_quarantine(manifest, &rel) {
                result.preserved += 1;
                continue;
            }
            file_ownership::ensure_no_symlinks(root, &p)?;
            let target = quarantine.join(&rel);
            if let Some(parent) = target.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
            std::fs::rename(&p, &target).map_err(|e| format!("failed to quarantine {rel}: {e}"))?;
            result.moved += 1;
            result.messages.push(format!("{rel} → {}", target.display()));
        }
    }
    Ok(result)
}

pub async fn prepare_profile_directory(base_dir: &Path, project_id: &str, profile_id: &str) -> Result<PathBuf, String> {
    let project = safe_component(project_id)?;
    let profile = safe_component(profile_id)?;
    let path = base_dir.join(project).join(profile);
    fs::create_dir_all(&path).await.map_err(|err| format!("не удалось создать каталог профиля: {err}"))?;
    Ok(path)
}

pub async fn check_java(java_path: Option<String>, required_major_version: Option<u32>) -> Result<JavaInfoResult, String> {
    let executable = java_path.filter(|value| !value.trim().is_empty()).unwrap_or_else(|| "java".to_string());
    let required = required_major_version.unwrap_or(17);
    let output = Command::new(&executable).arg("-version").stderr(Stdio::piped()).stdout(Stdio::piped()).output().await;
    match output {
        Ok(output) => {
            let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            let detected = parse_java_major_version(&text);
            let compatible = detected.map(|major| major >= required).unwrap_or(false);
            let message = match detected { Some(major) if compatible => format!("Java {major} подходит для профиля"), Some(major) => format!("Java {major} найдена, но требуется Java {required}+"), None => "Java найдена, но версию определить не удалось".to_string() };
            Ok(JavaInfoResult { found: output.status.success(), compatible, required_major_version: required, detected_major_version: detected, executable, version_output: text.trim().to_string(), recommended_memory_mb: None, maximum_memory_mb: None, message })
        }
        Err(err) => Ok(JavaInfoResult { found: false, compatible: false, required_major_version: required, detected_major_version: None, executable, version_output: format!("Java не найдена: {err}"), recommended_memory_mb: None, maximum_memory_mb: None, message: "Java не найдена".to_string() }),
    }
}

pub async fn build_launch_plan(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>, pinned_public_key: &str) -> Result<LaunchPlan, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    transactional_release::ready_for_launch(manifest, root, pinned_public_key).await?;
    create_launch_plan(manifest, root, java_path, username).await
}

pub async fn build_authenticated_launch_plan(manifest: &Manifest, root: &Path, java_path: Option<String>, credentials: MinecraftLaunchCredentials, pinned_public_key: &str) -> Result<LaunchPlan, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    transactional_release::ready_for_launch(manifest, root, pinned_public_key).await?;
    create_launch_plan_with_credentials(manifest, root, java_path, Some(credentials.username.clone()), Some(&credentials)).await
}

pub async fn launch(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>, pinned_public_key: &str) -> Result<LaunchResult, String> {
    launch_with_timeout(manifest, root, java_path, username, pinned_public_key, None).await
}

pub async fn certify_vanilla_compatibility(
    root: &Path,
    version: &str,
    java_path: String,
    required_java_major: u32,
    max_runtime_seconds: u64,
    matching_server: Option<String>,
    matching_server_port: Option<u16>,
) -> Result<VanillaCompatibilityProbeResult, String> {
    if required_java_major == 0 {
        return Err("Vanilla certification требует required Java major".to_string());
    }
    if max_runtime_seconds < 5 {
        return Err("Vanilla certification требует max-runtime-seconds >= 5".to_string());
    }
    fs::create_dir_all(root).await.map_err(|err| format!("не удалось открыть client root: {err}"))?;
    let version = safe_component(version)?;
    let natives_base = root.join("natives");
    let natives_dir = platform_natives_directory(&natives_base).await;
    let context = CompatibilityContext {
        username: "NL_Cert_Client".to_string(),
        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
        access_token: "offline".to_string(),
        user_type: "legacy".to_string(),
        launcher_name: "NeverLauncher".to_string(),
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        game_directory: root.to_string_lossy().to_string(),
        assets_directory: root.join("assets").to_string_lossy().to_string(),
        natives_directory: natives_dir.to_string_lossy().to_string(),
        features: HashMap::new(),
    };
    let resolution = resolve_compatibility(root, &version, None, &context).await?;
    if let Some(metadata_java) = resolution.java_major_version {
        if metadata_java != required_java_major {
            return Err(format!(
                "Vanilla {version} Mojang metadata требует Java {metadata_java}, certification target требует Java {required_java_major}"
            ));
        }
    }
    let java_info = check_java(Some(java_path.clone()), Some(required_java_major)).await?;
    if !java_info.found || java_info.detected_major_version != Some(required_java_major) {
        return Err(format!(
            "Vanilla {version} certification Java mismatch: требуется Java {required_java_major}, {}",
            java_info.message
        ));
    }
    let classpath_entries = resolution
        .classpath
        .iter()
        .map(|entry| safe_join(root, entry).map(|path| path.to_string_lossy().to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if classpath_entries.is_empty() {
        return Err(format!("Vanilla {version} certification classpath пуст"));
    }
    let mut game_args = resolution.game_args.clone();
    let normalized_matching_server = matching_server.map(|value| value.trim().to_string()).filter(|value| !value.is_empty());
    if let Some(host) = normalized_matching_server.as_ref() {
        if host.chars().any(|ch| ch.is_whitespace()) {
            return Err("Vanilla certification matching server host содержит пробелы".to_string());
        }
        let port = matching_server_port.ok_or_else(|| "Vanilla certification matching server требует --server-port".to_string())?;
        if port == 0 {
            return Err("Vanilla certification matching server port должен быть > 0".to_string());
        }
        if minecraft_supports_quick_play_for_resolution(&version, &resolution.inheritance_chain) {
            // Minecraft 1.20+ убрал старые параметры подключения --server/--port.
            // Используйте штатный Quick Play для настоящего соединения; проверка
            // соответствия сервера всё равно требует доказательств в серверном журнале.
            replace_or_append_arg_pair(&mut game_args, "--quickPlayMultiplayer", format!("{host}:{port}"));
        } else {
            replace_or_append_arg_pair(&mut game_args, "--server", host.clone());
            replace_or_append_arg_pair(&mut game_args, "--port", port.to_string());
        }
    } else if matching_server_port.is_some() {
        return Err("Vanilla certification --server-port требует --server".to_string());
    }

    let mut jvm_args = resolution.jvm_args.clone();
    if !jvm_args.iter().any(|arg| arg.starts_with("-Xmx")) {
        jvm_args.push("-Xmx1024m".to_string());
    }
    if !jvm_args.iter().any(|arg| arg.starts_with("-Xms")) {
        jvm_args.push("-Xms256m".to_string());
    }
    let plan = LaunchPlan {
        java_executable: java_path.clone(),
        working_directory: root.to_string_lossy().to_string(),
        main_class: resolution.main_class.clone(),
        classpath_entries,
        modulepath_entries: Vec::new(),
        main_module: String::new(),
        environment_allowlist: Vec::new(),
        restrict_java_environment: false,
        jvm_args,
        game_args,
        command_preview: format!("{} ... {}", java_path, resolution.main_class),
        deterministic_sha256: String::new(),
    };

    let logs_dir = root.join("logs");
    fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
    let started_at = now_unix()?;
    let log_path = logs_dir.join(format!("neverruntime-vanilla-certification-{version}-{started_at}.log"));
    let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)
        .map_err(|err| format!("не удалось открыть certification log {}: {err}", log_path.display()))?;
    use std::io::Write as _;
    writeln!(log_file, "NeverRuntime {} Vanilla certification", env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
    writeln!(log_file, "Minecraft: {version}; Java: {required_java_major}; Main: {}", plan.main_class).map_err(|e| e.to_string())?;
    // Записываются только уже разрешённые относительные JAR-пути, без учётных данных или
    // токенов аргументов. Так можно диагностировать отсутствие библиотек в старых версиях.
    writeln!(log_file, "--- verified classpath entries ---").map_err(|e| e.to_string())?;
    for entry in &plan.classpath_entries {
        let relative = Path::new(entry).strip_prefix(root).unwrap_or(Path::new(entry));
        writeln!(log_file, "{}", relative.display()).map_err(|e| e.to_string())?;
    }
    writeln!(log_file, "--- process output ---").map_err(|e| e.to_string())?;
    log_file.flush().map_err(|e| e.to_string())?;
    let stdout_file = log_file.try_clone().map_err(|e| format!("не удалось клонировать certification log handle: {e}"))?;
    let mut command = Command::new(&plan.java_executable);
    command.current_dir(Path::new(&plan.working_directory));
    command.args(&plan.jvm_args);
    #[cfg(windows)]
    let mut sensor_bootstrap = windows_sensor::prepare_sensor_command(&mut command)
        .map_err(|err| format!("Vanilla certification заблокирован NeverGuard Sensor: {err}"))?;
    apply_launch_command_0223(&mut command, &plan);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(log_file));
    windows_policy::prepare_runtime_command(&mut command);
    let mut child = command.spawn().map_err(|err| format!("не удалось запустить Vanilla {version}: {err}"))?;
    let _runtime_policy = windows_policy::enforce_runtime_process(&mut child)
        .map_err(|err| format!("Vanilla certification заблокирован runtime policy: {err}"))?;
    #[cfg(windows)]
    sensor_bootstrap.bind_runtime_policy(&_runtime_policy);
    #[cfg(windows)]
    let _sensor_session = windows_sensor::authenticate_sensor_or_kill(sensor_bootstrap, &mut child)
        .await
        .map_err(|err| format!("Vanilla certification заблокирован NeverGuard Sensor: {err}"))?;
    let (status, timed_out) = match timeout(Duration::from_secs(max_runtime_seconds), child.wait()).await {
        Ok(result) => (Some(result.map_err(|err| format!("не удалось дождаться Vanilla runtime: {err}"))?), false),
        Err(_) => {
            child.kill().await.map_err(|err| format!("Vanilla runtime не удалось остановить после timeout: {err}"))?;
            let _ = child.wait().await;
            (None, true)
        }
    };
    let success = status.as_ref().map(|value| value.success()).unwrap_or(false);
    // При ошибке сохраняйте ограниченный маркер завершения. JVM, завершённая
    // нативным сигналом Unix, часто не оставляет Java stack trace, а status.code()
    // равен None; ранее сбои SDL/GLFW в macOS не давали полезных сведений.
    if !timed_out && !success {
        let mut diagnostics = std::fs::OpenOptions::new().append(true).open(&log_path)
            .map_err(|e| format!("cannot append certification exit diagnostics: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            let signal = status.as_ref().and_then(|value| value.signal());
            writeln!(diagnostics, "--- runtime exit --- code={:?} signal={:?}",
                status.as_ref().and_then(|value| value.code()), signal)
                .map_err(|e| format!("cannot write certification exit diagnostics: {e}"))?;
        }
        #[cfg(not(unix))]
        writeln!(diagnostics, "--- runtime exit --- code={:?}",
            status.as_ref().and_then(|value| value.code()))
            .map_err(|e| format!("cannot write certification exit diagnostics: {e}"))?;
    }
    let exit_code = status.and_then(|value| value.code());
    // 0xE3 — специальный код завершения NeverGuard при строгом отказе.
    // Добавляйте его краткую причину в артефакт сертификации клиента
    // вместо пустого журнала, чтобы ошибки Windows-агента были понятны.
    #[cfg(windows)]
    if exit_code == Some(0xE3) || exit_code == Some(0xC000_0409u32 as i32) {
        // Windows Rust abort() also yields 0xC0000409. Attach authenticated
        // Guard violation details only if one actually arrived; never label
        // an unrelated JVM/graphics fail-fast as a Guard finding.
        let guard = _sensor_session.report().module_guard;
        if !guard.last_violation.is_empty() {
            let bounded = guard.last_violation.chars().take(1024).collect::<String>();
            let mut diagnostics = std::fs::OpenOptions::new().append(true).open(&log_path)
                .map_err(|e| format!("cannot append NeverGuard certification diagnostics: {e}"))?;
            writeln!(diagnostics, "--- NeverGuard fail-closed ---\n{bounded}")
                .map_err(|e| format!("cannot write NeverGuard certification diagnostics: {e}"))?;
        } else if exit_code == Some(0xE3) {
            let mut diagnostics = std::fs::OpenOptions::new().append(true).open(&log_path)
                .map_err(|e| format!("cannot append NeverGuard certification diagnostics: {e}"))?;
            writeln!(diagnostics, "--- NeverGuard fail-closed ---\nGuard terminated the runtime without a recorded violation")
                .map_err(|e| format!("cannot write NeverGuard certification diagnostics: {e}"))?;
        }
    }
    let finished_at = now_unix()?;
    let runtime_seconds = finished_at.saturating_sub(started_at);
    // V03: process lifetime is observational only. No menu/renderer proof is
    // collected by this legacy entrypoint, so it must not certify startup.
    let observed = timed_out || success;
    let message = if timed_out {
        format!("Vanilla {version}: timeout без подтверждения GUI/menu; startup INCONCLUSIVE")
    } else if success {
        format!("Vanilla {version}: JVM завершилась, GUI/menu не подтверждены")
    } else {
        format!("Vanilla {version} завершился с ошибкой до certification timeout")
    };
    Ok(VanillaCompatibilityProbeResult {
        status: if observed { "inconclusive".to_string() } else { "failed".to_string() },
        minecraft_version: version,
        required_java_major,
        detected_java_major: java_info.detected_major_version.unwrap_or_default(),
        java_executable: java_path,
        main_class: plan.main_class,
        classpath_entries: plan.classpath_entries.len(),
        natives_directory: natives_dir.to_string_lossy().to_string(),
        matching_server: normalized_matching_server,
        matching_server_port,
        success,
        timed_out,
        exit_code,
        log_path: log_path.to_string_lossy().to_string(),
        runtime_seconds,
        message,
    })
}

pub async fn launch_with_timeout(
    manifest: &Manifest,
    root: &Path,
    java_path: Option<String>,
    username: Option<String>,
    pinned_public_key: &str,
    max_runtime_seconds: Option<u64>,
) -> Result<LaunchResult, String> {
    launch_with_timeout_matching(manifest, root, java_path, username, pinned_public_key, max_runtime_seconds, None).await
}

/// Only the operator's isolated loopback matching-server is accepted. Launches
/// the very same verified signed installation, with the ordinary launch plan.
pub async fn launch_with_timeout_matching(
    manifest: &Manifest,
    root: &Path,
    java_path: Option<String>,
    username: Option<String>,
    pinned_public_key: &str,
    max_runtime_seconds: Option<u64>,
    matching_server: Option<u16>,
) -> Result<LaunchResult, String> {
    launch_with_timeout_matching_authenticated(manifest, root, java_path, username, pinned_public_key,
        max_runtime_seconds, matching_server, None).await
}

/// Authenticated staged validation uses the exact same guarded Java runtime and
/// immutable release installation as the normal launcher. No extra downloader.
pub async fn launch_with_timeout_matching_authenticated(
    manifest: &Manifest, root: &Path, java_path: Option<String>,
    username: Option<String>, pinned_public_key: &str, max_runtime_seconds: Option<u64>,
    matching_server: Option<u16>, credentials: Option<MinecraftLaunchCredentials>,
) -> Result<LaunchResult, String> {
    verify_manifest_signature(manifest, pinned_public_key)?;
    fs::create_dir_all(root).await.map_err(|err| format!("не удалось создать рабочий каталог: {err}"))?;
    let _client_release_lease = transactional_release::acquire_launch_lease(manifest, root, pinned_public_key).await?;
    let checks = check_files(manifest, root).await?;
    if checks.iter().any(|item| item.status != "ok") {
        return Err("launch заблокирован: client files не прошли integrity check".to_string());
    }
    let mut plan = if let Some(ref credentials) = credentials {
        create_launch_plan_with_credentials(manifest, root, java_path, Some(credentials.username.clone()), Some(credentials)).await?
    } else {
        create_launch_plan(manifest, root, java_path, username).await?
    };
    if let Some(port) = matching_server {
        if port == 0 { return Err("matching server port cannot be zero".into()); }
        let preferences = LaunchPreferences {
            auto_enter: true, server_host: Some("127.0.0.1".into()),
            server_port: Some(port), ..Default::default()
        };
        apply_launch_preferences(manifest, root, &mut plan, &preferences, credentials.as_ref())?;
    }
    let logs_dir = root.join("logs");
    fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
    let started_at = now_unix()?;
    let log_path = logs_dir.join(format!("neverruntime-launch-{started_at}.log"));
    let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)
        .map_err(|err| format!("не удалось открыть runtime log {}: {err}", log_path.display()))?;
    use std::io::Write as _;
    writeln!(log_file, "NeverRuntime {}", env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
    writeln!(log_file, "Команда: {}", plan.command_preview).map_err(|e| e.to_string())?;
    writeln!(log_file, "--- process output ---").map_err(|e| e.to_string())?;
    log_file.flush().map_err(|e| e.to_string())?;
    let stdout_file = log_file.try_clone().map_err(|e| format!("не удалось клонировать runtime log handle: {e}"))?;
    let mut command = Command::new(&plan.java_executable);
    command.current_dir(Path::new(&plan.working_directory));
    command.args(&plan.jvm_args);
    #[cfg(windows)]
    let mut sensor_bootstrap = windows_sensor::prepare_sensor_command(&mut command)
        .map_err(|err| format!("launch заблокирован: NeverGuard Sensor prepare failed: {err}"))?;
    apply_launch_command_0223(&mut command, &plan);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(log_file));
    windows_policy::prepare_runtime_command(&mut command);
    let mut child = command
        .spawn()
        .map_err(|err| format!("не удалось запустить runtime: {err}"))?;
    let _runtime_policy = windows_policy::enforce_runtime_process(&mut child)
        .map_err(|err| format!("launch заблокирован: Windows runtime/process policy enforcement failed: {err}"))?;
    #[cfg(windows)]
    sensor_bootstrap.bind_runtime_policy(&_runtime_policy);
    #[cfg(windows)]
    let _sensor_session = windows_sensor::authenticate_sensor_or_kill(sensor_bootstrap, &mut child)
        .await
        .map_err(|err| format!("launch заблокирован: NeverGuard Sensor authentication failed: {err}"))?;

    let (status, timed_out) = if let Some(seconds) = max_runtime_seconds.filter(|seconds| *seconds > 0) {
        match timeout(Duration::from_secs(seconds), child.wait()).await {
            Ok(result) => (Some(result.map_err(|err| format!("не удалось дождаться runtime: {err}"))?), false),
            Err(_) => {
                child.kill().await.map_err(|err| format!("runtime превысил лимит {seconds}s и не был остановлен: {err}"))?;
                let _ = child.wait().await;
                (None, true)
            }
        }
    } else {
        (Some(child.wait().await.map_err(|err| format!("не удалось дождаться runtime: {err}"))?), false)
    };
    let success = status.as_ref().map(|value| value.success()).unwrap_or(false);
    let exit_code = status.and_then(|value| value.code());
    let stdout = read_log_tail(&log_path, 512 * 1024).await.unwrap_or_default();
    let stderr = String::new();
    let message = if timed_out {
        format!("Runtime остановлен после заданного лимита {}s", max_runtime_seconds.unwrap_or_default())
    } else if success {
        "Runtime завершился успешно".to_string()
    } else {
        "Runtime завершился с ошибкой".to_string()
    };
    let history = LaunchHistoryEntry {
        started_at: started_at.to_string(),
        project_id: manifest.project_id.clone(),
        profile_id: manifest.profile_id.clone(),
        version: manifest.version.clone(),
        success,
        exit_code,
        log_path: log_path.to_string_lossy().to_string(),
        message: message.clone(),
    };
    append_launch_history(root, &history).await?;
    Ok(LaunchResult {
        exit_code,
        success,
        timed_out,
        log_path: log_path.to_string_lossy().to_string(),
        stdout,
        stderr,
        message,
    })
}

pub async fn load_launch_history(root: &Path) -> Result<Vec<LaunchHistoryEntry>, String> {
    let path = root.join("logs").join("launch-history.jsonl");
    if fs::metadata(&path).await.is_err() { return Ok(Vec::new()); }
    let data = fs::read_to_string(&path).await.map_err(|err| format!("не удалось прочитать launch history: {err}"))?;
    Ok(data.lines().filter(|line| !line.trim().is_empty()).filter_map(|line| serde_json::from_str::<LaunchHistoryEntry>(line).ok()).collect())
}

pub(crate) async fn create_launch_plan(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>) -> Result<LaunchPlan, String> {
    create_launch_plan_with_credentials(manifest, root, java_path, username, None).await
}

pub(crate) async fn create_launch_plan_with_credentials(manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>, credentials: Option<&MinecraftLaunchCredentials>) -> Result<LaunchPlan, String> {
    launch_identity_0269::identity(credentials)?;
    let offline_username_0269 = username.clone().unwrap_or_else(|| "Player".into());
    let strategy = manifest.runtime.launch.classpath_strategy.trim().to_ascii_lowercase();
    if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") { validate_runtime_constraints_0223(manifest)?; }
    let mut required_java = manifest.runtime.java.major_version;
    if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") && manifest.runtime.java.recommended_major_version > 0 {
        required_java = manifest.runtime.java.recommended_major_version;
    }
    let mut verified_metadata_paths = Vec::new();
    let mut plan = if strategy == "compatibility" || strategy == "mojang" {
        let game_dir = manifest_directory(root, &manifest.directories.game, ".")?;
        let assets_dir = manifest_directory(root, &manifest.directories.assets, "assets")?;
        let natives_name = if !manifest.runtime.launch.natives_directory.trim().is_empty() {
            manifest.runtime.launch.natives_directory.as_str()
        } else if !manifest.directories.natives.trim().is_empty() {
            manifest.directories.natives.as_str()
        } else {
            "natives"
        };
        let natives_base = manifest_directory(root, natives_name, "natives")?;
        let natives_dir = if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") {
            signed_platform_natives_directory_0227(manifest, root, &natives_base)?
        } else {
            platform_natives_directory(&natives_base).await
        };
        let player_name = credentials.map(|c| c.username.clone()).or(username).unwrap_or_else(|| "Player".to_string());
        let metadata_path = if manifest.runtime.launch.version_metadata_path.trim().is_empty() {
            None
        } else {
            Some(manifest.runtime.launch.version_metadata_path.as_str())
        };
        let context = CompatibilityContext {
            username: player_name,
            uuid: credentials.map(|c| c.uuid.clone()).unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string()),
            access_token: credentials.map(|c| c.access_token.clone()).unwrap_or_else(|| "offline".to_string()),
            user_type: credentials.map(|c| c.user_type.clone()).unwrap_or_else(|| "legacy".to_string()),
            launcher_name: "NeverLauncher".to_string(),
            launcher_version: env!("CARGO_PKG_VERSION").to_string(),
            game_directory: game_dir.to_string_lossy().to_string(),
            assets_directory: assets_dir.to_string_lossy().to_string(),
            natives_directory: natives_dir.to_string_lossy().to_string(),
            features: manifest.runtime.launch.features.clone(),
        };
        let resolution = resolve_compatibility(root, &manifest.minecraft.version, metadata_path, &context).await?;
        if let Some(major) = resolution.java_major_version {
            if required_java > 0 && required_java != major {
                return Err(format!(
                    "manifest требует Java {required_java}, а Mojang metadata требует Java {major}; release должен быть пересобран"
                ));
            }
            required_java = major;
        }
        validate_compatibility_resolution_trust(manifest, &resolution)?;
        verified_metadata_paths = resolution.metadata_paths.clone();
        if !manifest.runtime.launch.main_class.trim().is_empty() && manifest.runtime.launch.main_class != resolution.main_class {
            return Err(format!("manifest mainClass {} расходится с Compatibility Engine mainClass {}", manifest.runtime.launch.main_class, resolution.main_class));
        }
        if !manifest.minecraft.main_class.trim().is_empty() && manifest.minecraft.main_class != resolution.main_class {
            return Err(format!("minecraft.mainClass {} расходится с Compatibility Engine mainClass {}", manifest.minecraft.main_class, resolution.main_class));
        }
        let classpath_entries = resolution.classpath.iter().map(|path| safe_join(root, path).map(|value| value.to_string_lossy().to_string())).collect::<Result<Vec<_>, _>>()?;
        let mut jvm_args = resolution.jvm_args;
        jvm_args.extend(manifest.runtime.jvm_args.clone());
        let mut game_args = resolution.game_args;
        game_args.extend(manifest.minecraft.game_args.clone());
        LaunchPlan {
            java_executable: String::new(),
            working_directory: game_dir.to_string_lossy().to_string(),
            main_class: resolution.main_class,
            classpath_entries,
            modulepath_entries: Vec::new(),
            main_module: String::new(),
            environment_allowlist: Vec::new(),
            restrict_java_environment: false,
            jvm_args,
            game_args,
            command_preview: String::new(),
            deterministic_sha256: String::new(),
        }
    } else {
        create_manifest_launch_plan(manifest, root, "", credentials.map(|c| c.username.clone()).or(username), credentials).await?
    };

    if (manifest.schema_version != "2.0" && manifest.schema_version != "3.0") {
        if let Some(credentials) = credentials {
            apply_minecraft_auth119(manifest, root, credentials, &mut plan)?;
        }
    }

    if required_java == 0 {
        return Err("launch заблокирован: manifest/runtime metadata не задают требуемую major-версию Java".to_string());
    }
    let (java_executable, _managed) = select_java_executable(
        java_path,
        required_java,
        &manifest.runtime.java.distribution,
        manifest.runtime.java.allow_custom_path,
    )
    .await?;
    plan.java_executable = java_executable;
    if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") {
        let java = &manifest.runtime.java;
        if (java.minimum_major_version > 0 && required_java < java.minimum_major_version) ||
           (java.maximum_major_version > 0 && required_java > java.maximum_major_version) {
            return Err("selected Java falls outside profile major version range".into());
        }
    }

    if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") {
        apply_explicit_paths_0223(manifest, root, &mut plan)?;
        component_actions_0245::apply_installed_actions(manifest, root, &mut plan)?;
        verify_launch_inputs_0227(manifest, root, &plan, &verified_metadata_paths).await?;
        plan.environment_allowlist = manifest.runtime.launch.environment_allowlist.clone();
        plan.restrict_java_environment = true;
        validate_memory_arguments_0223(&manifest.runtime.memory, &plan.jvm_args)?;
    }
    apply_memory_policy(&manifest.runtime.memory, &mut plan.jvm_args);
    if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") {
        validate_memory_arguments_0223(&manifest.runtime.memory, &plan.jvm_args)?;
        // Authlib injector is an internal, trusted argument derived only from
        // the pinned, signed manifest artifact; do not treat it as custom args.
        if let Some(credentials) = credentials {
            apply_minecraft_auth119(manifest, root, credentials, &mut plan)?;
        }
    }
    // Manifest JVM args are appended after Mojang resolution. Repin the
    // extraction root here so a later manifest override cannot redirect the
    // LWJGL loader outside the client's NeverGuard-certified native cache.
    #[cfg(windows)]
    if strategy == "compatibility" || strategy == "mojang" {
        compatibility::pin_windows_lwjgl_extract_path(
            &mut plan.jvm_args,
            Path::new(&plan.working_directory),
            "windows",
            std::env::consts::ARCH,
        );
    }
    // Resolved Mojang metadata and signed project arguments must not override
    // the selected account. This is the final authority for game auth args.
    launch_identity_0269::pin_game_identity(&mut plan, &manifest.minecraft.version, credentials, &offline_username_0269)?;
    if credentials.is_none() && launch_identity_0269::forbidden_auth_agent(&plan.jvm_args) {
        return Err("offline game may not load an online authentication injector".into());
    }
    if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") {
        // A reproducible plan identity covers resolved metadata/order/options,
        // but deliberately excludes local installation roots and auth secrets.
        plan.deterministic_sha256 = deterministic_launch::plan_digest(manifest, root, required_java, &plan, credentials)?;
    }
    plan.command_preview = redacted_command_preview119(&plan, credentials.map(|c| c.access_token.as_str()));
    Ok(plan)
}

// For v2, platform native directory selection depends only on signed
// release paths, never on which directories happened to be created locally.
fn signed_platform_natives_directory_0227(manifest: &Manifest, root: &Path, base: &Path) -> Result<PathBuf, String> {
    let prefix = base.strip_prefix(root).map_err(|_| "native directory outside client root")?
        .to_string_lossy().replace('\\', "/");
    let os = match std::env::consts::OS { "macos" => "osx", "windows" => "windows", "linux" => "linux", _ => return Ok(base.to_path_buf()) };
    let arch = match std::env::consts::ARCH { "x86_64" => "x86_64", "aarch64" => "aarch64", "x86" => "x86", "arm" => "arm", _ => "" };
    let contains = |relative_dir: &str| {
        let file_prefix = if prefix.is_empty() { format!("{relative_dir}/") } else { format!("{prefix}/{relative_dir}/") };
        manifest.files.iter().any(|file| file.required && manifest_file_applies(file) && file.path.starts_with(&file_prefix))
    };
    if !arch.is_empty() && contains(&format!("{os}/{arch}")) { return Ok(base.join(os).join(arch)); }
    if contains(os) { return Ok(base.join(os)); }
    Ok(base.to_path_buf())
}

async fn platform_natives_directory(base: &Path) -> PathBuf {
    let platform = match std::env::consts::OS {
        "macos" => "osx",
        "windows" => "windows",
        "linux" => "linux",
        _ => return base.to_path_buf(),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "x86" => "x86",
        "arm" => "arm",
        _ => "",
    };
    if !arch.is_empty() {
        let candidate = base.join(platform).join(arch);
        if fs::metadata(&candidate).await.map(|metadata| metadata.is_dir()).unwrap_or(false) {
            return candidate;
        }
    }
    // Обратно совместимый резервный путь для пакетов, подготовленных до 0.16.9.
    let legacy = base.join(platform);
    if fs::metadata(&legacy).await.map(|metadata| metadata.is_dir()).unwrap_or(false) {
        legacy
    } else {
        base.to_path_buf()
    }
}

async fn create_manifest_launch_plan(manifest: &Manifest, root: &Path, java_executable: &str, username: Option<String>, credentials: Option<&MinecraftLaunchCredentials>) -> Result<LaunchPlan, String> {
    let main_class = if !manifest.runtime.launch.main_class.trim().is_empty() { manifest.runtime.launch.main_class.clone() } else { manifest.minecraft.main_class.clone() };
    if main_class.trim().is_empty() && manifest.runtime.launch.main_module.trim().is_empty() { return Err("в манифесте не указан mainClass или mainModule".to_string()); }
    let mut classpath_entries = Vec::new();
    for file in &manifest.files {
        if !manifest_file_applies(file) { continue; }
        if file.path.ends_with(".jar") && !file.path.contains("/mods/") && !file.path.starts_with("mods/") {
            if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") && (!file.required || matches!(file.ownership.as_str(), "user-owned" | "generated")) {
                continue;
            }
            let normalized = file.path.replace('\\', "/");
            let filename = normalized.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
            if filename.starts_with("authlib-injector") { continue; }
            let local_path = safe_join(root, &file.path)?;
            // v2 uses signed file order, never the mutable set of currently
            // installed JARs. Missing/corrupt inputs fail instead of changing
            // the LaunchPlan between identical releases.
            if (manifest.schema_version == "2.0" || manifest.schema_version == "3.0") || fs::metadata(&local_path).await.is_ok() {
                classpath_entries.push(local_path.to_string_lossy().to_string());
            }
        }
    }
    if classpath_entries.is_empty() && manifest.runtime.launch.modulepath_entries.is_empty() { return Err("classpath/modulepath пуст: JAR-файлы для запуска не найдены".to_string()); }
    let mut jvm_args = manifest.runtime.jvm_args.clone();
    if !jvm_args.iter().any(|arg| arg.starts_with("-Djava.library.path=")) {
        let natives_dir = if manifest.runtime.launch.natives_directory.trim().is_empty() { "natives" } else { manifest.runtime.launch.natives_directory.as_str() };
        jvm_args.push(format!("-Djava.library.path={}", root.join(natives_dir).to_string_lossy()));
    }
    let mut game_args = manifest.minecraft.game_args.clone();
    replace_or_append_arg_pair(&mut game_args, "--username", credentials.map(|c| c.username.clone()).or(username).unwrap_or_else(|| "Player".to_string()));
    if let Some(credentials) = credentials {
        replace_or_append_arg_pair(&mut game_args, "--uuid", credentials.uuid.clone());
        replace_or_append_arg_pair(&mut game_args, "--accessToken", credentials.access_token.clone());
        replace_or_append_arg_pair(&mut game_args, "--userType", credentials.user_type.clone());
    }
    replace_or_append_arg_pair(&mut game_args, "--version", manifest.minecraft.version.clone());
    replace_or_append_arg_pair(&mut game_args, "--gameDir", root.to_string_lossy().to_string());
    replace_or_append_arg_pair(&mut game_args, "--assetsDir", root.join("assets").to_string_lossy().to_string());
    Ok(LaunchPlan { java_executable: java_executable.to_string(), working_directory: root.to_string_lossy().to_string(), main_class, classpath_entries, modulepath_entries: Vec::new(), main_module: String::new(), environment_allowlist: Vec::new(), restrict_java_environment: false, jvm_args, game_args, command_preview: String::new(), deterministic_sha256: String::new() })
}

fn apply_minecraft_auth119(manifest: &Manifest, root: &Path, credentials: &MinecraftLaunchCredentials, plan: &mut LaunchPlan) -> Result<(), String> {
    use launch_identity_0269::{identity,GameIdentity,forbidden_auth_agent};
    match identity(Some(credentials))? {
        GameIdentity::Official => {
            if forbidden_auth_agent(&plan.jvm_args) {
                return Err("Official Minecraft must use Mojang sessionserver; authlib-injector is forbidden".into());
            }
        }
        GameIdentity::Yggdrasil => {
            if forbidden_auth_agent(&plan.jvm_args) {return Err("Yggdrasil auth agent must be supplied exclusively by NeverRuntime".into());}
            let mut injector: Option<PathBuf> = None;
            for file in &manifest.files {
                let normalized = file.path.replace('\\', "/");
                let filename = normalized.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
                if filename.starts_with("authlib-injector") && filename.ends_with(".jar") && file.required && manifest_file_applies(file) &&
                    !matches!(file.ownership.as_str(),"user-owned"|"generated") {
                    if injector.is_some() {return Err("multiple signed authlib-injector agents".into());}
                    injector = Some(safe_join(root, &file.path)?);
                }
            }
            let path=injector.ok_or("Yggdrasil online launch requires a required, signed authlib-injector JAR")?;
            if !tokio_path_exists119(&path) {return Err("signed authlib-injector is missing".into());}
            let base=credentials.auth_server_base_url.trim_end_matches('/');
            plan.jvm_args.push(format!("-javaagent:{}={}",path.to_string_lossy(),base));
        }
        GameIdentity::Offline => return Err("authenticated launch cannot use offline identity".into()),
    }
    Ok(())
}

fn tokio_path_exists119(path: &Path) -> bool { std::fs::metadata(path).is_ok() }

fn redacted_command_preview119(plan: &LaunchPlan, access_token: Option<&str>) -> String {
    let cp = if plan.classpath_entries.is_empty() { String::new() } else { format!("-cp {} ", join_classpath(&plan.classpath_entries)) };
    let entry = if plan.main_module.is_empty() { format!("{}{}", cp, plan.main_class) } else { format!("{}--module-path {} -m {}", cp, join_classpath(&plan.modulepath_entries), plan.main_module) };
    let raw = format!("{} {} {} {}", plan.java_executable, plan.jvm_args.join(" "), entry, plan.game_args.join(" "));
    match access_token.filter(|v| !v.is_empty()) { Some(token) => raw.replace(token, "[REDACTED]"), None => raw }
}

// 0.22.3: runtime constraints are enforced both when verifying v2 signatures
// and again immediately before constructing the OS process.
fn validate_runtime_constraints_0223(m: &Manifest) -> Result<(), String> {
    let j = &m.runtime.java;
    let launch = &m.runtime.launch;
    if j.major_version == 0 && j.distribution.is_empty() && m.runtime.jvm_args.is_empty() &&
        m.runtime.memory.minimum_mb == 0 && m.runtime.memory.recommended_mb == 0 &&
        m.runtime.memory.maximum_mb == 0 && launch.main_class.is_empty() &&
        launch.classpath_strategy.is_empty() && launch.classpath_entries.is_empty() &&
        launch.modulepath_entries.is_empty() && launch.main_module.is_empty() &&
        launch.environment_allowlist.is_empty() {
        // Empty pre-release drafts can still be inspected. Publishing must
        // require a runnable runtime before they can reach a public channel.
        return Ok(());
    }
    if j.major_version == 0 || j.major_version > 255 || j.minimum_major_version > 255 ||
       j.recommended_major_version > 255 || j.maximum_major_version > 255 ||
       (j.minimum_major_version != 0 && j.maximum_major_version != 0 && j.minimum_major_version > j.maximum_major_version) ||
       (j.minimum_major_version != 0 && j.major_version < j.minimum_major_version) ||
       (j.maximum_major_version != 0 && j.major_version > j.maximum_major_version) ||
       (j.recommended_major_version != 0 && j.minimum_major_version != 0 && j.recommended_major_version < j.minimum_major_version) ||
       (j.recommended_major_version != 0 && j.maximum_major_version != 0 && j.recommended_major_version > j.maximum_major_version) {
        return Err("runtime.java major version range is inconsistent".into());
    }
    let mem = &m.runtime.memory;
    if (mem.maximum_mb != 0 && mem.minimum_mb > mem.maximum_mb) ||
       (mem.recommended_mb != 0 && mem.minimum_mb != 0 && mem.recommended_mb < mem.minimum_mb) ||
       (mem.maximum_mb != 0 && mem.recommended_mb > mem.maximum_mb) {
        return Err("runtime.memory minimum/recommended/maximum MB order invalid".into());
    }
    if !matches!(launch.classpath_strategy.trim().to_ascii_lowercase().as_str(), "" | "manifest" | "libraries" | "compatibility" | "mojang") {
        return Err("unsupported runtime.launch.classpathStrategy".into());
    }
    validate_memory_arguments_0223(mem, &m.runtime.jvm_args)?;
    let files: HashSet<&str> = m.files.iter().filter(|f| f.required).map(|f| f.path.as_str()).collect();
    let mut seen = HashSet::new();
    for path in launch.classpath_entries.iter().chain(launch.modulepath_entries.iter()) {
        if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains(':') ||
           path.contains('\0') || path.contains('\r') || path.contains('\n') ||
           path.split('/').any(|part| part.is_empty() || part == "." || part == "..") ||
           !path.to_ascii_lowercase().ends_with(".jar") || !files.contains(path.as_str()) || !seen.insert(path) {
            return Err(format!("invalid/unsigned/duplicate launch JAR path: {path}"));
        }
    }
    if launch.main_module.is_empty() != launch.modulepath_entries.is_empty() {
        return Err("mainModule and modulepathEntries must be set together".into());
    }
    if !launch.main_module.is_empty() {
        let valid = regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_.]*(/[A-Za-z_$][A-Za-z0-9_.$]*)?$").map_err(|e| e.to_string())?;
        if !valid.is_match(&launch.main_module) { return Err("invalid mainModule".into()); }
    }
    let valid_environment = regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").map_err(|e| e.to_string())?;
    let mut env_names = HashSet::new();
    for name in &launch.environment_allowlist {
        let upper = name.to_ascii_uppercase();
        if !valid_environment.is_match(name) || !env_names.insert(upper.clone()) ||
           matches!(upper.as_str(), "JAVA_TOOL_OPTIONS" | "_JAVA_OPTIONS" | "JDK_JAVA_OPTIONS" | "CLASSPATH") {
            return Err(format!("invalid/unsafe/duplicate environment allowlist key {name}"));
        }
    }
    for arg in &m.minecraft.game_args {
        if arg.contains('\0') || arg.contains('\r') || arg.contains('\n') { return Err("invalid game argument".into()); }
    }
    Ok(())
}

fn parse_heap_arg_0223(arg: &str) -> Result<Option<(char, u64)>, String> {
    let lower = arg.to_ascii_lowercase();
    if !(lower.starts_with("-xmx") || lower.starts_with("-xms")) { return Ok(None); }
    let heap_type = lower.as_bytes()[3] as char;
    let payload = &lower[4..];
    let digits = match payload.chars().last() {
        Some('k' | 'm' | 'g') => &payload[..payload.len()-1],
        _ => payload,
    };
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid heap argument {arg}"));
    }
    let value = digits.parse::<u64>().map_err(|_| format!("invalid heap argument {arg}"))?;
    // Convert to MB with checked multiplication and ceiling for k/bytes.
    let mb = match payload.chars().last() {
        Some('k') => value.checked_add(1023).map(|v| v / 1024),
        Some('m') => Some(value),
        Some('g') => value.checked_mul(1024),
        _ => value.checked_add(1048575).map(|v| v / 1048576),
    }.ok_or_else(|| format!("heap argument overflow: {arg}"))?;
    Ok(Some((heap_type, mb)))
}

fn validate_memory_arguments_0223(mem: &MemoryInfo, args: &[String]) -> Result<(), String> {
    let mut xms = None;
    let mut xmx = None;
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if arg.trim().is_empty() || arg.contains('\0') || arg.contains('\r') || arg.contains('\n') {
            return Err("invalid JVM argument".into());
        }
        if matches!(lower.as_str(), "-cp" | "-classpath" | "--class-path" | "--module-path" | "--patch-module" | "--upgrade-module-path" | "-p" | "-m" | "--module" | "-jar") ||
            ["-xbootclasspath", "--class-path=", "--module-path=", "--patch-module", "--upgrade-module-path", "-javaagent:", "-agentpath:", "-agentlib:", "-xx:onerror=", "-xx:onoutofmemoryerror="].iter().any(|v| lower.starts_with(v)) {
            return Err(format!("JVM entrypoint/path/agent override prohibited: {arg}"));
        }
        if let Some((kind, mb)) = parse_heap_arg_0223(arg)? {
            if (mem.minimum_mb > 0 && mb < mem.minimum_mb as u64) ||
               (mem.maximum_mb > 0 && mb > mem.maximum_mb as u64) {
                return Err(format!("heap argument outside profile limits: {arg}"));
            }
            let slot = if kind == 's' { &mut xms } else { &mut xmx };
            if slot.replace(mb).is_some() { return Err(format!("duplicate heap argument: {arg}")); }
        }
    }
    if let (Some(min), Some(max)) = (xms, xmx) {
        if min > max { return Err("-Xms exceeds -Xmx".into()); }
    }
    Ok(())
}

fn apply_explicit_paths_0223(m: &Manifest, root: &Path, plan: &mut LaunchPlan) -> Result<(), String> {
    let launch = &m.runtime.launch;
    for name in launch.classpath_entries.iter().chain(launch.modulepath_entries.iter()) {
        if !m.files.iter().any(|file| file.path == *name && file.required && manifest_file_applies(file)) {
            return Err(format!("signed runtime path not applicable to current platform: {name}"));
        }
    }
    if !launch.classpath_entries.is_empty() {
        plan.classpath_entries = launch.classpath_entries.iter().map(|v| safe_join(root, v).map(|p| p.to_string_lossy().to_string())).collect::<Result<Vec<_>, _>>()?;
    }
    plan.modulepath_entries = launch.modulepath_entries.iter().map(|v| safe_join(root, v).map(|p| p.to_string_lossy().to_string())).collect::<Result<Vec<_>, _>>()?;
    plan.main_module = launch.main_module.clone();
    if !plan.main_module.is_empty() && launch.classpath_entries.is_empty() {
        // Modules must not silently reappear on the legacy classpath.
        plan.classpath_entries.clear();
    }
    if plan.main_module.is_empty() && plan.classpath_entries.is_empty() {
        return Err("launch requires signed classpath entries or mainModule".into());
    }
    Ok(())
}

// Recheck all selected executable inputs against the signed Manifest bytes;
// otherwise edited Mojang metadata or disappearing JARs can silently change
// an otherwise identical plan even though the manifest signature is valid.
async fn verify_launch_inputs_0227(manifest: &Manifest, root: &Path, plan: &LaunchPlan, metadata_paths: &[String]) -> Result<(), String> {
    let canonical_root = root.canonicalize().map_err(|e| format!("client root is unavailable: {e}"))?;
    let mut paths = HashSet::<String>::new();
    for absolute in plan.classpath_entries.iter().chain(plan.modulepath_entries.iter()) {
        let absolute = Path::new(absolute);
        let rel = absolute.strip_prefix(root).or_else(|_| absolute.strip_prefix(&canonical_root))
            .map_err(|_| format!("launch JAR outside client root: {}", absolute.display()))?;
        let rel = rel.to_str().ok_or("non-UTF8 JAR path")?.replace('\\', "/");
        paths.insert(rel);
    }
    // Metadata read by Compatibility Engine must also be exactly the signed
    // bytes. Otherwise local JSON edits could change launch args while keeping
    // the same signed release and profile snapshot.
    let active=component_catalog_0241::active_files(manifest,transactional_release::active_preset_for_manifest(manifest,root).as_deref())?;
    for rel in paths.iter().chain(metadata_paths.iter()) {
        let declared = manifest.files.iter().find(|file| file.path == *rel && manifest_file_applies(file) &&
           (file.required || (manifest.schema_version=="3.0" && active.contains(rel.as_str()))))
            .ok_or_else(|| format!("launch input is not a selected signed artifact: {rel}"))?;
        if metadata_paths.contains(rel) && !declared.required {
            return Err(format!("compatibility metadata cannot be optional: {rel}"));
        }
        let location = safe_join(&canonical_root, rel)?;
        file_ownership::ensure_no_symlinks(&canonical_root, &location)?;
        let metadata = fs::metadata(&location).await.map_err(|e| format!("launch input missing {rel}: {e}"))?;
        if !metadata.is_file() || metadata.len() != declared.size || !sha256_file(&location).await?.eq_ignore_ascii_case(&declared.sha256) {
            return Err(format!("launch input does not match signed size/SHA-256: {rel}"));
        }
    }
    Ok(())
}

pub(crate) fn apply_launch_command_0223(command: &mut Command, plan: &LaunchPlan) {
    if plan.restrict_java_environment {
        let inherited: Vec<(String, String)> = plan.environment_allowlist.iter().filter_map(|key| std::env::var(key).ok().map(|value| (key.clone(), value))).collect();
        command.env_clear();
        for (key, value) in inherited { command.env(key, value); }
        #[cfg(windows)]
        for key in ["SystemRoot", "WINDIR"] {
            if let Ok(value) = std::env::var(key) { command.env(key, value); }
        }
    }
    if plan.restrict_java_environment {
        for forbidden in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"] {
            command.env_remove(forbidden);
        }
    }
    if !plan.classpath_entries.is_empty() {
        command.arg("-cp").arg(join_classpath(&plan.classpath_entries));
    }
    if !plan.modulepath_entries.is_empty() {
        command.arg("--module-path").arg(join_classpath(&plan.modulepath_entries));
    }
    if !plan.main_module.is_empty() { command.arg("-m").arg(&plan.main_module); }
    else { command.arg(&plan.main_class); }
    command.args(&plan.game_args);
}

fn apply_memory_policy(memory: &MemoryInfo, jvm_args: &mut Vec<String>) {
    if memory.minimum_mb > 0 && !jvm_args.iter().any(|arg| arg.starts_with("-Xms")) { jvm_args.push(format!("-Xms{}M", memory.minimum_mb)); }
    if (memory.recommended_mb > 0 || memory.maximum_mb > 0) && !jvm_args.iter().any(|arg| arg.starts_with("-Xmx")) {
        let max = if memory.recommended_mb > 0 { memory.recommended_mb } else { memory.maximum_mb };
        jvm_args.push(format!("-Xmx{}M", max));
    }
}

fn manifest_directory(root: &Path, configured: &str, fallback: &str) -> Result<PathBuf, String> {
    let value = if configured.trim().is_empty() { fallback } else { configured.trim() };
    if value == "." { return Ok(root.to_path_buf()); }
    safe_join(root, value)
}

fn validate_compatibility_resolution_trust(manifest: &Manifest, resolution: &CompatibilityResolution) -> Result<(), String> {
    let trusted = manifest.files.iter().filter(|file| manifest_file_applies(file)).map(|file| file.path.replace('\\', "/")).collect::<HashSet<_>>();
    for path in resolution.metadata_paths.iter().chain(resolution.classpath.iter()).chain(resolution.natives.iter().map(|native| &native.path)) {
        if !trusted.contains(path) {
            return Err(format!("Compatibility Engine отклонил неподписанный release path: {path}"));
        }
    }
    if let Some(path) = resolution.logging_file.as_ref() {
        if !trusted.contains(path) {
            return Err(format!("Compatibility Engine отклонил неподписанный logging config: {path}"));
        }
    }
    Ok(())
}

async fn read_log_tail(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = fs::File::open(path).await.map_err(|err| format!("не удалось открыть runtime log: {err}"))?;
    let len = file.metadata().await.map_err(|err| format!("не удалось получить размер runtime log: {err}"))?.len();
    if len > max_bytes {
        file.seek(SeekFrom::Start(len - max_bytes)).await.map_err(|err| format!("не удалось выполнить seek runtime log: {err}"))?;
    }
    let mut data = Vec::with_capacity(len.min(max_bytes) as usize);
    file.read_to_end(&mut data).await.map_err(|err| format!("не удалось прочитать runtime log: {err}"))?;
    Ok(String::from_utf8_lossy(&data).to_string())
}

async fn append_launch_history(root: &Path, entry: &LaunchHistoryEntry) -> Result<(), String> {
    let logs_dir = root.join("logs");
    fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
    let path = logs_dir.join("launch-history.jsonl");
    let mut line = serde_json::to_string(entry).map_err(|err| format!("не удалось сериализовать launch history: {err}"))?;
    line.push('\n');
    let mut file = fs::OpenOptions::new().create(true).append(true).open(&path).await.map_err(|err| format!("не удалось открыть launch history: {err}"))?;
    file.write_all(line.as_bytes()).await.map_err(|err| format!("не удалось записать launch history: {err}"))
}

async fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).await.map_err(|err| format!("не удалось прочитать {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buffer).await.map_err(|err| format!("не удалось прочитать {}: {err}", path.display()))?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn manifest_file_applies(file: &ManifestFile) -> bool {
    if file.target_os.is_empty() { return true; }
    let current = match std::env::consts::OS {
        "macos" => "osx",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    };
    file.target_os.iter().any(|item| {
        let normalized_item = item.trim().to_ascii_lowercase();
        let normalized = match normalized_item.as_str() {
            "macos" | "darwin" | "osx" => "osx",
            "win" | "windows" => "windows",
            "linux" => "linux",
            other => other,
        };
        normalized == current
    })
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() { return Err(format!("небезопасный путь файла: {relative}")); }
    for component in relative_path.components() { if !matches!(component, Component::Normal(_)) { return Err(format!("небезопасный путь файла: {relative}")); } }
    Ok(root.join(relative_path))
}

fn safe_component(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\\') || trimmed == "." || trimmed == ".." { return Err(format!("небезопасный path component: {value}")); }
    Ok(trimmed.to_string())
}

fn parse_java_major_version(output: &str) -> Option<u32> {
    let marker = "version \"";
    let start = output.find(marker)? + marker.len();
    let rest = &output[start..];
    let end = rest.find('"')?;
    let version = &rest[..end];
    let mut parts = version.split('.');
    let first = parts.next()?.parse::<u32>().ok()?;
    if first == 1 { parts.next()?.parse::<u32>().ok() } else { Some(first) }
}

// Профили с модами используют ID вроде "quilt-loader-0.30.1-1.21.1", а не
// номера релизов Mojang. Определяйте поддержку Quick Play по корневой версии
// Vanilla из проверенной цепочки inheritsFrom, никогда по ID модифицированного
// профиля. Иначе загрузчик 1.21.x незаметно получит удалённые --server/--port,
// останется запущенным и не подключится к настоящему серверу.
fn minecraft_supports_quick_play_for_resolution(version: &str, inheritance_chain: &[String]) -> bool {
    let vanilla_version = inheritance_chain.first().map(String::as_str).unwrap_or(version);
    minecraft_supports_quick_play_multiplayer(vanilla_version)
}

fn minecraft_supports_quick_play_multiplayer(version: &str) -> bool {
    // Выпуски 1.20 и новее, включая годовую схему 26.x, поддерживают
    // --quickPlayMultiplayer host:port. Старые используют --server/--port.
    let mut parts = version.split('.');
    let first = parts.next().and_then(|v| v.parse::<u32>().ok());
    let second = parts.next().and_then(|v| v.parse::<u32>().ok());
    match (first, second) {
        (Some(1), Some(minor)) => minor >= 20,
        (Some(year), _) => year >= 26,
        _ => false,
    }
}

fn replace_or_append_arg_pair(args: &mut Vec<String>, key: &str, value: String) {
    if let Some(index) = args.iter().position(|item| item == key) {
        if index + 1 < args.len() { args[index + 1] = value; } else { args.push(value); }
        return;
    }
    args.push(key.to_string());
    args.push(value);
}

fn join_classpath(entries: &[String]) -> String { entries.join(if cfg!(windows) { ";" } else { ":" }) }
fn is_false(value: &bool) -> bool { !*value }
fn is_zero(value: &u32) -> bool { *value == 0 }
fn now_unix() -> Result<u64, String> { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|err| err.to_string()) }

#[cfg(unix)]
async fn set_executable_if_needed(path: &Path, executable: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !executable { return Ok(()); }
    let meta = fs::metadata(path).await.map_err(|err| format!("permissions {}: {err}", path.display()))?;
    let mut permissions = meta.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(path, permissions).await.map_err(|err| format!("chmod {}: {err}", path.display()))
}

#[cfg(not(unix))]
async fn set_executable_if_needed(_path: &Path, _executable: bool) -> Result<(), String> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_runtime_constraints_enforce_signed_jars_java_heap_and_environment_0223() {
        let mut m = sample_manifest();
        m.schema_version = "2.0".into();
        m.runtime.java.minimum_major_version = 16;
        m.runtime.java.recommended_major_version = 17;
        m.runtime.java.maximum_major_version = 21;
        m.runtime.launch.classpath_entries = vec!["libraries/fixture.jar".into()];
        m.runtime.launch.environment_allowlist = vec!["LANG".into()];
        assert!(validate_runtime_constraints_0223(&m).is_ok());
        m.runtime.jvm_args.push("-Xmx2048M".into());
        assert!(validate_runtime_constraints_0223(&m).is_err(), "duplicate heap override");
        m.runtime.jvm_args.clear();
        m.runtime.jvm_args.push("-Xmx1024M".into());
        assert!(validate_runtime_constraints_0223(&m).is_err(), "heap beyond max");
        m.runtime.jvm_args.clear();
        m.runtime.launch.classpath_entries = vec!["libraries/missing.jar".into()];
        assert!(validate_runtime_constraints_0223(&m).is_err(), "unsigned classpath");
        m.runtime.launch.classpath_entries = vec!["libraries/fixture.jar".into()];
        m.runtime.launch.environment_allowlist = vec!["JAVA_TOOL_OPTIONS".into()];
        assert!(validate_runtime_constraints_0223(&m).is_err(), "Java env injection");
        m.runtime.launch.environment_allowlist.clear();
        m.runtime.java.maximum_major_version = 16;
        assert!(validate_runtime_constraints_0223(&m).is_err(), "Java constraint mismatch");
    }

    #[tokio::test]
    async fn deterministic_0227_rejects_mutated_and_missing_signed_inputs() {
        use sha2::{Digest, Sha256};
        let root = std::env::temp_dir().join(format!("nl-plan-integrity-{}-{}", std::process::id(), now_unix().unwrap()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("libraries")).unwrap();
        std::fs::create_dir_all(root.join("versions/v")).unwrap();
        std::fs::write(root.join("libraries/a.jar"), b"signed-jar").unwrap();
        std::fs::write(root.join("versions/v/v.json"), b"signed-metadata").unwrap();
        let mut manifest = sample_manifest();
        for (path, body) in [("libraries/a.jar", &b"signed-jar"[..]), ("versions/v/v.json", &b"signed-metadata"[..])] {
            manifest.files.push(ManifestFile { path: path.into(), size: body.len() as u64, sha256: hex::encode(Sha256::digest(body)), url: "https://example.test/file".into(), mirrors: vec![], required: true, executable: false, target_os: vec![], ownership: "managed".into() });
        }
        let plan = LaunchPlan {
            java_executable: "java".into(), working_directory: root.to_string_lossy().to_string(),
            main_class: "demo.Main".into(), main_module: "".into(), classpath_entries: vec![root.join("libraries/a.jar").to_string_lossy().to_string()],
            modulepath_entries: vec![], environment_allowlist: vec![], restrict_java_environment: true,
            jvm_args: vec![], game_args: vec![], command_preview: "".into(), deterministic_sha256: "".into(),
        };
        let metadata = vec!["versions/v/v.json".to_string()];
        assert!(verify_launch_inputs_0227(&manifest, &root, &plan, &metadata).await.is_ok());
        std::fs::write(root.join("versions/v/v.json"), b"forged-metadata").unwrap();
        assert!(verify_launch_inputs_0227(&manifest, &root, &plan, &metadata).await.is_err());
        std::fs::write(root.join("versions/v/v.json"), b"signed-metadata").unwrap();
        std::fs::remove_file(root.join("libraries/a.jar")).unwrap();
        assert!(verify_launch_inputs_0227(&manifest, &root, &plan, &metadata).await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deterministic_0227_empty_environment_allowlist_drops_inherited_keys() {
        let mut plan = LaunchPlan {
            java_executable: "java".into(), working_directory: ".".into(), main_class: "Main".into(),
            main_module: "".into(), classpath_entries: vec![], modulepath_entries: vec![],
            environment_allowlist: vec![], restrict_java_environment: true,
            jvm_args: vec![], game_args: vec![], command_preview: "".into(), deterministic_sha256: "".into(),
        };
        let mut process = Command::new("java");
        apply_launch_command_0223(&mut process, &plan);
        assert!(process.as_std().get_envs().any(|(name, value)| name.to_string_lossy() == "JAVA_TOOL_OPTIONS" && value.is_none()));
        plan.environment_allowlist.push("LANG".into());
        let mut another = Command::new("java");
        apply_launch_command_0223(&mut another, &plan);
        assert!(another.as_std().get_args().any(|arg| arg == "Main"));
    }

    #[test]
    fn runtime_0223_launch_command_uses_argument_arrays_for_java_modules() {
        let mut plan = LaunchPlan {
            java_executable: "java".into(), working_directory: ".".into(),
            main_class: "ignored.Main".into(),
            classpath_entries: vec!["lib one.jar".into()], modulepath_entries: vec!["mod one.jar".into()],
            main_module: "example.mod/example.Main".into(), environment_allowlist: vec!["LANG".into()], restrict_java_environment: true,
            jvm_args: vec!["-Xmx1G".into()], game_args: vec!["value with spaces".into()], command_preview: String::new(), deterministic_sha256: String::new(),
        };
        let mut cmd = Command::new("java");
        cmd.args(&plan.jvm_args);
        apply_launch_command_0223(&mut cmd, &plan);
        let args: Vec<String> = cmd.as_std().get_args().map(|v| v.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["-Xmx1G", "-cp", "lib one.jar", "--module-path", "mod one.jar", "-m", "example.mod/example.Main", "value with spaces"]);
        plan.main_module.clear();
        plan.modulepath_entries.clear();
        let mut legacy_cmd = Command::new("java");
        apply_launch_command_0223(&mut legacy_cmd, &plan);
        assert!(legacy_cmd.as_std().get_args().any(|v| v.to_string_lossy() == "ignored.Main"));
    }

    #[test]
    fn modded_profile_uses_root_minecraft_release_for_quick_play() {
        for profile in [
            "fabric-loader-0.19.5-1.21.1",
            "quilt-loader-0.30.1-1.21.1",
            "1.21.1-forge-52.1.0",
            "neoforge-21.1.0-1.21.1",
        ] {
            let chain = vec!["1.21.1".to_string(), profile.to_string()];
            assert!(minecraft_supports_quick_play_for_resolution(profile, &chain), "{profile}");
            if !profile.starts_with("1.") {
                assert!(!minecraft_supports_quick_play_multiplayer(profile), "regression must exercise modded IDs");
            }
        }
        let legacy = vec!["1.16.4".to_string(), "1.16.4-forge-35.1.37".to_string()];
        assert!(!minecraft_supports_quick_play_for_resolution(&legacy[1], &legacy));
        let vanilla = vec!["26.3".to_string()];
        assert!(minecraft_supports_quick_play_for_resolution("26.3", &vanilla));
        // При повреждённой или неполной цепочке наследования нельзя делать вывод
        // о поддержке по похожему на номер версии суффиксу профиля загрузчика.
        assert!(!minecraft_supports_quick_play_for_resolution("quilt-loader-0.30.1-1.21.1", &[]));
    }

    #[test]
    fn desktop_launch_preferences_enforce_signed_profile_policy() {
        let mut manifest = sample_manifest();
        manifest.schema_version = "2.0".into();
        manifest.runtime.launch.offline_mode = true;
        manifest.runtime.memory = MemoryInfo { minimum_mb: 1024, recommended_mb: 2048, maximum_mb: 8192 };
        let mut pref = LaunchPreferences { memory_mb: Some(4096), width: Some(1280), height: Some(720),
            fullscreen: false, auto_enter: false, server_host: None, server_port: None, offline: true };
        assert!(validate_launch_preferences(&manifest, &pref, false).is_ok());
        pref.memory_mb = Some(16384);
        assert!(validate_launch_preferences(&manifest, &pref, false).is_err());
        pref.memory_mb = Some(4096);
        pref.height = None;
        assert!(validate_launch_preferences(&manifest, &pref, false).is_err());
        pref.height = Some(720);
        pref.auto_enter = true;
        assert!(validate_launch_preferences(&manifest, &pref, false).is_err());
        pref.auto_enter = false;
        manifest.runtime.launch.offline_mode = false;
        assert!(validate_launch_preferences(&manifest, &pref, false).is_err());
        pref.offline = false;
        pref.auto_enter = true;
        pref.server_host = Some("mc.example.org".into());
        pref.server_port = Some(25565);
        assert!(validate_launch_preferences(&manifest, &pref, true).is_ok());
        pref.server_host = Some("evil/path".into());
        assert!(validate_launch_preferences(&manifest, &pref, true).is_err());
    }

    #[test]
    fn matching_server_uses_quick_play_only_for_supported_minecraft_versions() {
        for version in ["1.3.1", "1.6.4", "1.12.2", "1.19.4"] {
            assert!(!minecraft_supports_quick_play_multiplayer(version), "{version}");
        }
        for version in ["1.20", "1.20.4", "1.21.10", "26.3"] {
            assert!(minecraft_supports_quick_play_multiplayer(version), "{version}");
        }
    }

    fn sample_manifest() -> Manifest {
        Manifest {
            schema_version: "1.0".to_string(),
            project_id: "demo".to_string(),
            profile_id: "vanilla".to_string(),
            channel: "stable".to_string(),
            version: format!("{}-test", env!("CARGO_PKG_VERSION")),
            trust_epoch: 0,
            game_release_generation: 0,
            rollback_source: None,
            created_at: "2026-09-13T00:00:00Z".to_string(),
            minecraft: MinecraftInfo {
                version: "1.21.1".to_string(),
                loader: "fixture".to_string(),
                loader_version: String::new(),
                main_class: "ru.neverlauncher.e2e.LaunchFixture".to_string(),
                game_args: Vec::new(),
            },
            runtime: RuntimeInfo {
                java: JavaInfo {
                    major_version: 17,
                    minimum_major_version: 0,
                    recommended_major_version: 0,
                    maximum_major_version: 0,
                    distribution: "temurin".to_string(),
                    allow_custom_path: true,
                },
                jvm_args: Vec::new(),
                memory: MemoryInfo {
                    minimum_mb: 64,
                    recommended_mb: 128,
                    maximum_mb: 256,
                },
                launch: RuntimeLaunch {
                    main_class: "ru.neverlauncher.e2e.LaunchFixture".to_string(),
                    classpath_strategy: "manifest".to_string(),
                    natives_directory: "natives".to_string(),
                    version_metadata_path: String::new(),
                    classpath_entries: Vec::new(),
                    modulepath_entries: Vec::new(),
                    main_module: String::new(),
                    environment_allowlist: Vec::new(),
                    features: HashMap::new(),
                    offline_mode: true,
                },
            },
            directories: Directories::default(),
            files: vec![ManifestFile {
                path: "libraries/fixture.jar".to_string(),
                size: 123,
                sha256: "00".repeat(32),
                url: "https://example.invalid/fixture.jar".to_string(),
                mirrors: vec![],
                required: true,
                executable: false,
                target_os: Vec::new(),
                ownership: String::new(),
            }],
            file_rules: Vec::new(),
            profile_snapshot: None,
            component_catalog: None,
            signature: None,
        }
    }

    #[test]
    fn v2_manifest_signed_snapshot_is_verified_and_tamper_protected() {
        use sha2::{Sha256, Digest};
        let mut manifest = sample_manifest();
        manifest.schema_version = "2.0".into();
        let spec = ProfileSpec {
            project_id: "demo".into(), id: "vanilla".into(), name: "Vanilla".into(),
            description: "Signed snapshot".into(), loader: "vanilla".into(),
            preset: "".into(), is_default: true,
        };
        let bytes = ["demo", "vanilla", "Vanilla", "Signed snapshot", "vanilla", "", "true"].join("\0");
        manifest.profile_snapshot = Some(ProfileSnapshot {
            schema_version: "2.0".into(), revision: 4,
            digest: hex::encode(Sha256::digest(bytes.as_bytes())), spec,
        });
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let key = sign_manifest(&mut manifest, seed, "2026-10-18T00:00:00Z").expect("v2 sign");
        verify_manifest_signature(&manifest, &key).expect("v2 verify");
        let mut altered_runtime = manifest.clone();
        altered_runtime.runtime.java.minimum_major_version = 16;
        assert!(verify_manifest_signature(&altered_runtime, &key).is_err(), "Java policy is covered by the Ed25519 signature");
        manifest.profile_snapshot.as_mut().unwrap().spec.name = "Forged".into();
        assert!(verify_manifest_signature(&manifest, &key).is_err());
        manifest.profile_snapshot = None;
        assert!(verify_manifest_signature(&manifest, &key).is_err());
    }

    #[test]
    fn v3_go_publisher_fixture_verifies_in_native_runtime_0241() {
        // Fixture signed with crypto/ed25519 + encoding/json by the Go publisher.
        let json = include_str!("../tests/fixtures/component_catalog_v3_go_signed.json");
        let m: Manifest = serde_json::from_str(json).expect("Go v3 fixture decode");
        let pinned = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
        verify_manifest_signature(&m,pinned).expect("Go-signed v3 catalog must verify in Rust");
        let mut tampered=m.clone();
        tampered.component_catalog.as_mut().unwrap().components[0].files.pop();
        assert!(verify_manifest_signature(&tampered,pinned).is_err());
        let mut forged=m.clone();
        forged.files[0].sha256="00".repeat(32);
        assert!(verify_manifest_signature(&forged,pinned).is_err());
    }

    #[test]
    fn go_signed_v3_catalog_v2_interop_0242() {
        let signed = include_str!("../tests/fixtures/catalog_manifest_v3_go_signed_0242.json");
        let manifest: Manifest = serde_json::from_str(signed).expect("Go signed catalog fixture");
        let key="24a9dcf8fac87bd5cb27d51d09f98188bc1c00b1223f5ccaa26a5736d9a53d78";
        verify_manifest_signature(&manifest,key).expect("Go Ed25519 v3 / catalog v2 signature must verify in Rust");
        let cat=manifest.component_catalog.as_ref().unwrap();
        assert_eq!(crate::component_catalog_0241::digest_v2(cat),cat.digest);
        let minimal=crate::component_catalog_0241::active_files(&manifest,Some("minimal")).unwrap();
        assert!(minimal.contains("mods/core.jar"));
        assert!(!minimal.contains("mods/sodium.jar"));
        let quality=crate::component_catalog_0241::active_files(&manifest,Some("quality")).unwrap();
        assert!(quality.contains("mods/shader.jar"));
        assert!(!quality.contains("mods/indium.jar"));
        let mut changed=manifest.clone();
        changed.component_catalog.as_mut().unwrap().components[0].required=false;
        assert!(verify_manifest_signature(&changed,key).is_err());
        let mut changed=manifest.clone();
        changed.component_catalog.as_mut().unwrap().default_preset="quality".into();
        assert!(verify_manifest_signature(&changed,key).is_err());
    }

    #[test]
    fn signed_go_v3_dependencies_and_conflicts_0243() {
        use crate::component_catalog_0241::{active_files,digest_v3,ComponentRequirement};
        let signed=include_str!("../tests/fixtures/catalog_dependency_0243_go_signed.json");
        let manifest:Manifest=serde_json::from_str(signed).expect("Go-signed v3 resolver fixture must decode");
        let key="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
        verify_manifest_signature(&manifest,key).expect("Go Ed25519 with catalog 3.0 must verify in Rust");
        let cat=manifest.component_catalog.as_ref().unwrap();
        assert_eq!(digest_v3(cat),"53fe27537e66b25479003cdca208f3272091ef78b9278e16009e5097d4281988");
        let minimum=active_files(&manifest,Some("minimal")).unwrap();
        assert!(minimum.contains("mods/core.jar"));
        assert!(!minimum.contains("mods/sodium.jar"));
        let quality=active_files(&manifest,Some("quality")).unwrap();
        assert!(quality.contains("mods/core.jar"));
        assert!(quality.contains("mods/sodium.jar"));
        assert!(quality.contains("mods/indium.jar"));
        assert!(quality.contains("mods/shader.jar"));
        let mut tampered=manifest.clone();
        tampered.component_catalog.as_mut().unwrap().components[2].dependencies[0].version_range="^0.6.0".into();
        assert!(verify_manifest_signature(&tampered,key).is_err());
        let cat=tampered.component_catalog.as_mut().unwrap();cat.digest=digest_v3(cat);
        assert!(active_files(&tampered,Some("quality")).is_err());
        let mut cycle=manifest.clone();
        let cat=cycle.component_catalog.as_mut().unwrap();
        cat.components[0].dependencies.push(ComponentRequirement{id:"shaders".into(),version_range:String::new()});
        cat.digest=digest_v3(cat);
        assert!(active_files(&cycle,Some("minimal")).unwrap_err().contains("cycle"));
        let mut exclusion=manifest.clone();
        let cat=exclusion.component_catalog.as_mut().unwrap();
        cat.components[2].exclusive_group="performance-engine".into();
        cat.digest=digest_v3(cat);
        assert!(active_files(&exclusion,Some("quality")).unwrap_err().contains("exclusive_group"));
    }

    #[test]
    fn v3_catalog_ed25519_sign_verify_and_tamper_0241() {
        use crate::component_catalog_0241::{CatalogComponent,ComponentCatalog,digest};
        use sha2::{Digest,Sha256};
        let mut m=sample_manifest();
        m.schema_version="3.0".into();
        let spec=ProfileSpec{project_id:"demo".into(),id:"vanilla".into(),name:"Vanilla".into(),
            description:String::new(),loader:"vanilla".into(),preset:String::new(),is_default:false};
        let digest_profile=hex::encode(Sha256::digest(["demo","vanilla","Vanilla","","vanilla","","false"].join("\0").as_bytes()));
        m.profile_snapshot=Some(ProfileSnapshot{schema_version:"2.0".into(),revision:1,digest:digest_profile,spec});
        let paths=vec!["mods/sodium.jar".to_string(),"mods/indium.jar".to_string()];
        for path in &paths {
            m.files.push(ManifestFile{path:path.clone(),size:3,sha256:"aa".repeat(32),
                url:"https://example.invalid/file".into(),mirrors:vec![],required:false,
                executable:false,target_os:vec![],ownership:"optional".into()});
        }
        let components=vec![CatalogComponent{id:"performance.sodium".into(),name:"Sodium & friends".into(),files:paths,version:String::new(),dependencies:vec![],conflicts:vec![],exclusive_group:String::new(),conditions:None,actions:vec![],description:String::new(),category_id:String::new(),group_id:String::new(),required:false,default:false,visible:None,limited:false,metadata:Default::default()}];
        assert_eq!(digest(&components),"85f4d294a8028281b667503339bc444bdf5c05ceef31e87fdee87f5cd0c84119");
        m.component_catalog=Some(ComponentCatalog{schema_version:"1.0".into(),revision:1,digest:digest(&components),components,categories:vec![],groups:vec![],presets:vec![],default_preset:String::new()});
        let seed="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let key=sign_manifest(&mut m,seed,"2026-10-20T00:00:00Z").expect("v3 sign");
        verify_manifest_signature(&m,&key).expect("signed v3 catalog");
        assert!(String::from_utf8(manifest_signing_payload(&m).unwrap()).unwrap().contains("Sodium \\u0026 friends"));
        let mut tampered=m.clone();
        tampered.component_catalog.as_mut().unwrap().components[0].name="forged".into();
        assert!(verify_manifest_signature(&tampered,&key).is_err());
        let mut altered=m.clone();
        altered.component_catalog.as_mut().unwrap().revision=2;
        assert!(verify_manifest_signature(&altered,&key).is_err());
        let mut rogue=m.clone();
        rogue.files.push(ManifestFile{path:"mods/unsigned.jar".into(),size:3,sha256:"aa".repeat(32),
            url:"https://example.invalid/file".into(),mirrors:vec![],required:false,executable:false,target_os:vec![],ownership:"optional".into()});
        assert!(verify_manifest_signature(&rogue,&key).is_err());
    }

    #[test]
    fn sign_and_verify_manifest_with_pinned_key() {
        let mut manifest = sample_manifest();
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let public_key = sign_manifest(&mut manifest, seed, "2026-09-13T00:00:00Z").expect("sign");
        let result = verify_manifest_signature(&manifest, &public_key).expect("verify");
        assert!(result.valid);
        assert_eq!(result.public_key, public_key);
    }

    #[test]
    fn signing_payload_preserves_explicit_false_executable_for_go_contract() {
        let manifest = sample_manifest();
        let payload = manifest_signing_payload(&manifest).expect("payload");
        let json = String::from_utf8(payload).expect("utf8");
        assert!(
            json.contains("\"executable\":false"),
            "Go ManifestFile signs executable=false explicitly: {json}"
        );
    }

    #[test]
    fn file_download_rate_limit_retry_budget_remains_bounded() {
        // These are the actual bounded retry settings used by HTTP Resume and
        // the durable download worker, not unused legacy constants.
        assert_eq!(network_resilience::MAX_ATTEMPTS, 7);
        assert_eq!(network_resilience::REQUEST_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn signature_verification_is_fail_closed() {
        let mut manifest = sample_manifest();
        let seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let public_key = sign_manifest(&mut manifest, seed, "2026-09-13T00:00:00Z").expect("sign");
        manifest.version = "tampered".to_string();
        assert!(verify_manifest_signature(&manifest, &public_key).is_err());
        assert!(verify_manifest_signature(&manifest, "").is_err());
    }

    #[tokio::test]
    async fn platform_natives_directory_prefers_os_arch_isolation() {
        let root = std::env::temp_dir().join(format!(
            "neverruntime-natives-{}-{}",
            std::process::id(),
            std::env::consts::ARCH
        ));
        let _ = std::fs::remove_dir_all(&root);
        let platform = match std::env::consts::OS {
            "macos" => "osx",
            "windows" => "windows",
            "linux" => "linux",
            _ => return,
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            "x86" => "x86",
            "arm" => "arm",
            _ => return,
        };
        let legacy = root.join(platform);
        let isolated = legacy.join(arch);
        std::fs::create_dir_all(&isolated).expect("mkdir natives");
        assert_eq!(platform_natives_directory(&root).await, isolated);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn safe_join_rejects_path_traversal() {
        let root = Path::new("/tmp/neverruntime-test");
        assert!(safe_join(root, "libraries/a.jar").is_ok());
        assert!(safe_join(root, "../secret").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
    }

    #[test]
    fn parses_modern_and_legacy_java_versions() {
        assert_eq!(parse_java_major_version("openjdk version \"21.0.4\" 2024-07-16"), Some(21));
        assert_eq!(parse_java_major_version("java version \"1.8.0_402\""), Some(8));
        assert_eq!(parse_java_major_version("unexpected output"), None);
    }
    #[tokio::test]
    async fn signed_file_policy_quarantines_only_explicitly_managed_orphans() {
        use sha2::{Digest, Sha256};
        let root = std::env::temp_dir().join(format!("nl-repair-ownership-{}-{}", std::process::id(), now_unix().unwrap()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("mods")).unwrap();
        std::fs::create_dir_all(root.join("saves/world")).unwrap();
        std::fs::create_dir_all(root.join("resourcepacks")).unwrap();
        std::fs::write(root.join("saves/world/level.dat"), b"world").unwrap();
        std::fs::write(root.join("resourcepacks/custom.zip"), b"custom").unwrap();
        std::fs::write(root.join("options.txt"), b"user settings").unwrap();
        std::fs::write(root.join("mods/stale.jar"), b"stale").unwrap();
        let mut manifest = sample_manifest();
        manifest.schema_version = "2.0".into();
        let spec = ProfileSpec {
            project_id: "demo".into(), id: "vanilla".into(), name: "Vanilla".into(),
            description: "".into(), loader: "vanilla".into(), preset: "".into(), is_default: false,
        };
        let digest = hex::encode(Sha256::digest(["demo","vanilla","Vanilla","","vanilla","","false"].join("\0").as_bytes()));
        manifest.profile_snapshot = Some(ProfileSnapshot{schema_version:"2.0".into(),revision:1,digest,spec});
        manifest.file_rules.push(file_ownership::FileRule {
            pattern:"mods/**".into(),action:"include".into(),ownership:"managed".into(),
        });
        let key=sign_manifest(&mut manifest,"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","2026-10-18T00:00:00Z").unwrap();
        let result=clean_unused_files(&manifest,&root,&key).await.unwrap();
        assert_eq!(result.moved,1);
        assert!(!root.join("mods/stale.jar").exists());
        assert_eq!(std::fs::read(root.join("saves/world/level.dat")).unwrap(),b"world");
        assert_eq!(std::fs::read(root.join("resourcepacks/custom.zip")).unwrap(),b"custom");
        assert_eq!(std::fs::read(root.join("options.txt")).unwrap(),b"user settings");
        let mut modified=manifest.clone();
        modified.file_rules[0].pattern="saves/**".into();
        assert!(clean_unused_files(&modified,&root,&key).await.is_err());
        let _=std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn legacy_repair_does_not_replace_saves_or_settings() {
        let root=std::env::temp_dir().join(format!("nl-v1-ownership-{}-{}",std::process::id(),now_unix().unwrap()));
        let _=std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("options.txt"),b"modified user options").unwrap();
        let mut manifest=sample_manifest();
        manifest.files[0].path="options.txt".into();
        let key=sign_manifest(&mut manifest,"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","2026-10-18T00:00:00Z").unwrap();
        let result=repair_client(&manifest,&root,&key).await.unwrap();
        assert_eq!(result.repaired,0);
        assert_eq!(std::fs::read(root.join("options.txt")).unwrap(),b"modified user options");
        let _=std::fs::remove_dir_all(root);
    }

}
