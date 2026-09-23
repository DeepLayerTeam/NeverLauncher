use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NEVERGUARD_INTEGRITY_EVIDENCE_VERSION: u32 = 1;
pub const NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA: &str = "neverguard/windows-integrity-evidence/v1";
pub const NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA: &str = "neverguard/linux-integrity-evidence/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticodeEvidence {
    pub trusted: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessMitigationEvidence {
    pub dep: Option<u32>,
    pub aslr: Option<u32>,
    pub dynamic_code: Option<u32>,
    pub extension_point_disable: Option<u32>,
    pub control_flow_guard: Option<u32>,
    pub binary_signature: Option<u32>,
    pub image_load: Option<u32>,
    pub child_process: Option<u32>,
    pub user_shadow_stack: Option<u32>,
    pub sehop: Option<u32>,
    pub query_failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModuleSetEvidence {
    pub module_count: u32,
    pub module_set_sha256: String,
    pub non_system_module_names: Vec<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxProcessSecurityEvidence {
    pub uid: u32,
    pub gid: u32,
    pub no_new_privs: bool,
    pub seccomp_mode: u32,
    pub dumpable_disabled: bool,
    pub parent_death_signal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIntegrityEvidence {
    pub pid: u32,
    pub image_path: String,
    pub image_sha256: String,
    pub image_size: u64,
    pub image_modified_unix_ms: u64,
    pub process_created_filetime: u64,
    pub authenticode: AuthenticodeEvidence,
    pub mitigations: ProcessMitigationEvidence,
    pub modules: ModuleSetEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxProcessSecurityEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryEvidence {
    pub expected_parent_pid: u32,
    pub observed_parent_pid: u32,
    pub parent_matches: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NeverGuardIntegrityEvidence {
    pub schema: String,
    pub evidence_version: u32,
    pub evidence_id: String,
    pub collected_at_unix: u64,
    pub boundary: BoundaryEvidence,
    pub guard: ProcessIntegrityEvidence,
    pub launcher: ProcessIntegrityEvidence,
    pub evidence_sha256: String,
    pub session_proof: String,
}

#[cfg(any(windows, target_os = "linux", test))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntegrityEvidenceCore<'a> {
    schema: &'a str,
    evidence_version: u32,
    evidence_id: &'a str,
    collected_at_unix: u64,
    boundary: &'a BoundaryEvidence,
    guard: &'a ProcessIntegrityEvidence,
    launcher: &'a ProcessIntegrityEvidence,
}

#[cfg(any(windows, target_os = "linux", test))]
fn core_bytes(evidence: &NeverGuardIntegrityEvidence) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&IntegrityEvidenceCore {
        schema: &evidence.schema,
        evidence_version: evidence.evidence_version,
        evidence_id: &evidence.evidence_id,
        collected_at_unix: evidence.collected_at_unix,
        boundary: &evidence.boundary,
        guard: &evidence.guard,
        launcher: &evidence.launcher,
    })
    .map_err(|err| format!("NeverGuard integrity evidence serialization failed: {err}"))
}

#[cfg(any(windows, target_os = "linux", test))]
pub(crate) fn recompute_evidence_sha256(
    evidence: &NeverGuardIntegrityEvidence,
) -> Result<[u8; 32], String> {
    let digest = Sha256::digest(core_bytes(evidence)?);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(any(windows, target_os = "linux", test))]
pub(crate) fn validate_evidence_shape(evidence: &NeverGuardIntegrityEvidence) -> Result<(), String> {
    let schema_ok = evidence.schema == NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA
        || evidence.schema == NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA;
    if !schema_ok || evidence.evidence_version != NEVERGUARD_INTEGRITY_EVIDENCE_VERSION {
        return Err("NeverGuard integrity evidence schema/version mismatch".to_string());
    }
    if evidence.evidence_id.len() != 32
        || !evidence.evidence_id.bytes().all(|value| value.is_ascii_hexdigit())
    {
        return Err("NeverGuard integrity evidence id malformed".to_string());
    }
    for (label, value) in [
        ("evidenceSha256", evidence.evidence_sha256.as_str()),
        ("sessionProof", evidence.session_proof.as_str()),
        ("guard.imageSha256", evidence.guard.image_sha256.as_str()),
        ("launcher.imageSha256", evidence.launcher.image_sha256.as_str()),
        (
            "guard.modules.moduleSetSha256",
            evidence.guard.modules.module_set_sha256.as_str(),
        ),
        (
            "launcher.modules.moduleSetSha256",
            evidence.launcher.modules.module_set_sha256.as_str(),
        ),
    ] {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("NeverGuard integrity evidence {label} malformed"));
        }
    }
    if evidence.guard.pid == 0 || evidence.launcher.pid == 0 {
        return Err("NeverGuard integrity evidence contains zero PID".to_string());
    }
    if !evidence.boundary.parent_matches
        || evidence.boundary.expected_parent_pid != evidence.boundary.observed_parent_pid
        || evidence.launcher.pid != evidence.boundary.expected_parent_pid
    {
        return Err("NeverGuard integrity evidence process boundary mismatch".to_string());
    }
    if evidence.schema == NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA {
        let guard = evidence.guard.linux.as_ref().ok_or_else(|| "Linux integrity evidence missing guard security state".to_string())?;
        let launcher = evidence.launcher.linux.as_ref().ok_or_else(|| "Linux integrity evidence missing launcher security state".to_string())?;
        if !guard.no_new_privs || !guard.dumpable_disabled || !guard.parent_death_signal {
            return Err("Linux NeverGuard security state is not enforced".to_string());
        }
        if guard.uid != launcher.uid || guard.gid != launcher.gid {
            return Err("Linux NeverGuard/launcher uid/gid boundary mismatch".to_string());
        }
    }
    Ok(())
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::{
        ffi::{c_void, OsString},
        fs::File,
        io::{BufReader, Read},
        mem::size_of,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
        ptr::null_mut,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
        Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
            WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
            WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
                Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
                TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetProcessMitigationPolicy, GetProcessTimes, OpenProcess,
                QueryFullProcessImageNameW, ProcessASLRPolicy, ProcessChildProcessPolicy,
                ProcessControlFlowGuardPolicy, ProcessDEPPolicy, ProcessDynamicCodePolicy,
                ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSEHOPPolicy,
                ProcessSignaturePolicy, ProcessUserShadowStackPolicy, PROCESS_MITIGATION_POLICY,
                PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    const MAX_PROCESS_PATH_CHARS: usize = 32768;
    const MAX_REPORTED_NON_SYSTEM_MODULES: usize = 32;

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn open_process(pid: u32) -> Result<Self, String> {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            if handle.is_null() {
                return Err(format!(
                    "NeverGuard cannot open process {pid}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn observed_parent_pid(process_id: u32) -> Result<u32, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "NeverGuard process snapshot failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let snapshot = OwnedHandle(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut has_entry = unsafe { Process32FirstW(snapshot.raw(), &mut entry) } != 0;
        while has_entry {
            if entry.th32ProcessID == process_id {
                return Ok(entry.th32ParentProcessID);
            }
            has_entry = unsafe { Process32NextW(snapshot.raw(), &mut entry) } != 0;
        }
        Err(format!(
            "NeverGuard process {process_id} not found in process snapshot"
        ))
    }

    pub(super) fn collect(
        expected_parent_pid: u32,
    ) -> Result<NeverGuardIntegrityEvidence, String> {
        let guard_pid = std::process::id();
        let observed_parent_pid = observed_parent_pid(guard_pid)?;
        if observed_parent_pid != expected_parent_pid {
            return Err(format!(
                "NeverGuard actual parent PID mismatch: expected {expected_parent_pid}, observed {observed_parent_pid}"
            ));
        }

        let guard = collect_process(guard_pid)?;
        let launcher = collect_process(expected_parent_pid)?;
        let collected_at_unix = now_unix()?;
        let mut evidence_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut evidence_id_bytes);

        let mut evidence = NeverGuardIntegrityEvidence {
            schema: NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA.to_string(),
            evidence_version: NEVERGUARD_INTEGRITY_EVIDENCE_VERSION,
            evidence_id: hex::encode(evidence_id_bytes),
            collected_at_unix,
            boundary: BoundaryEvidence {
                expected_parent_pid,
                observed_parent_pid,
                parent_matches: true,
            },
            guard,
            launcher,
            evidence_sha256: String::new(),
            session_proof: String::new(),
        };
        evidence.evidence_sha256 = hex::encode(recompute_evidence_sha256(&evidence)?);
        Ok(evidence)
    }

    fn collect_process(pid: u32) -> Result<ProcessIntegrityEvidence, String> {
        let process = OwnedHandle::open_process(pid)?;
        let image_path = process_image_path(process.raw())?;
        let metadata = std::fs::metadata(&image_path).map_err(|err| {
            format!(
                "NeverGuard cannot stat process image {}: {err}",
                image_path.display()
            )
        })?;
        let modified_ms = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);

        Ok(ProcessIntegrityEvidence {
            pid,
            image_path: image_path.to_string_lossy().to_string(),
            image_sha256: sha256_file(&image_path)?,
            image_size: metadata.len(),
            image_modified_unix_ms: modified_ms,
            process_created_filetime: process_creation_filetime(process.raw())?,
            authenticode: verify_authenticode(&image_path),
            mitigations: process_mitigations(process.raw()),
            modules: module_set(pid, &image_path)?,
            linux: None,
        })
    }

    fn process_image_path(handle: HANDLE) -> Result<PathBuf, String> {
        let mut buffer = vec![0u16; MAX_PROCESS_PATH_CHARS];
        let mut size = buffer.len() as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
        };
        if ok == 0 || size == 0 {
            return Err(format!(
                "NeverGuard QueryFullProcessImageNameW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        buffer.truncate(size as usize);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    fn process_creation_filetime(handle: HANDLE) -> Result<u64, String> {
        let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let ok = unsafe {
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
        };
        if ok == 0 {
            return Err(format!(
                "NeverGuard GetProcessTimes failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }

    fn query_mitigation(
        handle: HANDLE,
        name: &str,
        policy: PROCESS_MITIGATION_POLICY,
        failures: &mut Vec<String>,
    ) -> Option<u32> {
        let mut flags = 0u32;
        let ok = unsafe {
            GetProcessMitigationPolicy(
                handle,
                policy,
                &mut flags as *mut u32 as *mut c_void,
                size_of::<u32>(),
            )
        };
        if ok == 0 {
            failures.push(format!("{name}:{}", std::io::Error::last_os_error()));
            None
        } else {
            Some(flags)
        }
    }

    fn process_mitigations(handle: HANDLE) -> ProcessMitigationEvidence {
        let mut failures = Vec::new();
        let dep = query_mitigation(handle, "DEP", ProcessDEPPolicy, &mut failures);
        let aslr = query_mitigation(handle, "ASLR", ProcessASLRPolicy, &mut failures);
        let dynamic_code = query_mitigation(
            handle,
            "DynamicCode",
            ProcessDynamicCodePolicy,
            &mut failures,
        );
        let extension_point_disable = query_mitigation(
            handle,
            "ExtensionPointDisable",
            ProcessExtensionPointDisablePolicy,
            &mut failures,
        );
        let control_flow_guard = query_mitigation(
            handle,
            "ControlFlowGuard",
            ProcessControlFlowGuardPolicy,
            &mut failures,
        );
        let binary_signature = query_mitigation(
            handle,
            "BinarySignature",
            ProcessSignaturePolicy,
            &mut failures,
        );
        let image_load = query_mitigation(
            handle,
            "ImageLoad",
            ProcessImageLoadPolicy,
            &mut failures,
        );
        let child_process = query_mitigation(
            handle,
            "ChildProcess",
            ProcessChildProcessPolicy,
            &mut failures,
        );
        let user_shadow_stack = query_mitigation(
            handle,
            "UserShadowStack",
            ProcessUserShadowStackPolicy,
            &mut failures,
        );
        let sehop = query_mitigation(handle, "SEHOP", ProcessSEHOPPolicy, &mut failures);

        ProcessMitigationEvidence {
            dep,
            aslr,
            dynamic_code,
            extension_point_disable,
            control_flow_guard,
            binary_signature,
            image_load,
            child_process,
            user_shadow_stack,
            sehop,
            query_failures: failures,
        }
    }

    fn module_set(pid: u32, primary_image: &Path) -> Result<ModuleSetEvidence, String> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "NeverGuard module snapshot failed for PID {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let snapshot = OwnedHandle(snapshot);
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        let mut has_entry = unsafe { Module32FirstW(snapshot.raw(), &mut entry) } != 0;
        if !has_entry {
            return Err(format!(
                "NeverGuard module enumeration failed for PID {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }

        let primary_dir = primary_image.parent().map(normalize_path);
        let primary_normalized = normalize_path(primary_image);
        let mut records = Vec::new();
        let mut non_system = Vec::new();
        while has_entry {
            let module_path = wide_z_to_path(&entry.szExePath);
            if let Some(path) = module_path {
                let normalized = normalize_path(&path);
                let metadata = std::fs::metadata(&path).map_err(|err| {
                    format!(
                        "NeverGuard cannot stat loaded module {} for PID {pid}: {err}",
                        path.display()
                    )
                })?;
                let modified_ms = metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
                    .unwrap_or(0);
                let module_sha256 = sha256_file(&path)?;
                records.push(format!(
                    "{normalized}\0{}\0{modified_ms}\0{module_sha256}",
                    metadata.len()
                ));

                let is_primary = normalized == primary_normalized;
                let is_windows = normalized.contains("\\windows\\") || normalized.contains("/windows/");
                let is_same_dir = primary_dir
                    .as_deref()
                    .is_some_and(|dir| normalized.starts_with(dir));
                if !is_primary && !is_windows && !is_same_dir && non_system.len() < MAX_REPORTED_NON_SYSTEM_MODULES {
                    if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                        non_system.push(name.to_string());
                    }
                }
            }
            has_entry = unsafe { Module32NextW(snapshot.raw(), &mut entry) } != 0;
        }
        records.sort_unstable();
        non_system.sort_unstable_by_key(|value| value.to_ascii_lowercase());
        non_system.dedup_by(|left, right| left.eq_ignore_ascii_case(right));

        let mut digest = Sha256::new();
        digest.update(b"NeverLauncher NeverGuard module-set v1\0");
        for record in &records {
            digest.update((record.len() as u32).to_le_bytes());
            digest.update(record.as_bytes());
        }
        Ok(ModuleSetEvidence {
            module_count: records.len().min(u32::MAX as usize) as u32,
            module_set_sha256: hex::encode(digest.finalize()),
            non_system_module_names: non_system,
        })
    }

    fn wide_z_to_path(value: &[u16]) -> Option<PathBuf> {
        let len = value.iter().position(|ch| *ch == 0).unwrap_or(value.len());
        if len == 0 {
            return None;
        }
        Some(PathBuf::from(OsString::from_wide(&value[..len])))
    }

    fn normalize_path(path: &Path) -> String {
        path.to_string_lossy().replace('/', "\\").to_ascii_lowercase()
    }

    fn sha256_file(path: &Path) -> Result<String, String> {
        let file = File::open(path)
            .map_err(|err| format!("NeverGuard cannot open {} for hashing: {err}", path.display()))?;
        let mut reader = BufReader::with_capacity(128 * 1024, file);
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|err| format!("NeverGuard cannot hash {}: {err}", path.display()))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(hex::encode(digest.finalize()))
    }

    pub(super) fn verify_authenticode(path: &Path) -> AuthenticodeEvidence {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<u16>>();
        wide.push(0);
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: null_mut(),
            pgKnownSubject: null_mut(),
        };
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.pPolicyCallbackData = null_mut();
        data.pSIPClientData = null_mut();
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 {
            pFile: &mut file_info,
        };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.hWVTStateData = null_mut();
        data.pwszURLReference = null_mut();
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        data.dwUIContext = WTD_UICONTEXT_EXECUTE;
        data.pSignatureSettings = null_mut();

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut action,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            )
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            let _ = WinVerifyTrust(
                null_mut(),
                &mut action,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            );
        }

        AuthenticodeEvidence {
            trusted: status == 0,
            status: format!("0x{:08X}", status as u32),
        }
    }

    fn now_unix() -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|err| format!("system clock error: {err}"))
    }
}

#[cfg(windows)]
pub fn verify_windows_authenticode_trust(path: &std::path::Path) -> Result<(), String> {
    let result = windows_impl::verify_authenticode(path);
    if result.trusted {
        Ok(())
    } else {
        Err(format!(
            "Authenticode trust verification failed for {}: {}",
            path.display(),
            result.status
        ))
    }
}

#[cfg(not(windows))]
pub fn verify_windows_authenticode_trust(_path: &std::path::Path) -> Result<(), String> {
    Err("Authenticode trust verification доступен только на Windows".to_string())
}

#[cfg(windows)]
pub(crate) fn collect_windows_integrity_evidence(
    expected_parent_pid: u32,
) -> Result<NeverGuardIntegrityEvidence, String> {
    windows_impl::collect(expected_parent_pid)
}

#[cfg(windows)]
pub(crate) fn observed_windows_parent_pid(process_id: u32) -> Result<u32, String> {
    windows_impl::observed_parent_pid(process_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_process(pid: u32, name: &str) -> ProcessIntegrityEvidence {
        ProcessIntegrityEvidence {
            pid,
            image_path: format!(r"C:\NeverLauncher\{name}.exe"),
            image_sha256: "11".repeat(32),
            image_size: 123,
            image_modified_unix_ms: 456,
            process_created_filetime: 789,
            authenticode: AuthenticodeEvidence {
                trusted: false,
                status: "0x800B0100".to_string(),
            },
            mitigations: ProcessMitigationEvidence {
                dep: Some(1),
                aslr: Some(3),
                dynamic_code: Some(0),
                extension_point_disable: Some(0),
                control_flow_guard: Some(1),
                binary_signature: Some(0),
                image_load: Some(0),
                child_process: Some(0),
                user_shadow_stack: None,
                sehop: Some(1),
                query_failures: vec!["UserShadowStack:unsupported".to_string()],
            },
            modules: ModuleSetEvidence {
                module_count: 2,
                module_set_sha256: "22".repeat(32),
                non_system_module_names: vec![],
            },
            linux: None,
        }
    }

    fn sample_evidence() -> NeverGuardIntegrityEvidence {
        let mut evidence = NeverGuardIntegrityEvidence {
            schema: NEVERGUARD_INTEGRITY_EVIDENCE_SCHEMA.to_string(),
            evidence_version: NEVERGUARD_INTEGRITY_EVIDENCE_VERSION,
            evidence_id: "33".repeat(16),
            collected_at_unix: 1000,
            boundary: BoundaryEvidence {
                expected_parent_pid: 10,
                observed_parent_pid: 10,
                parent_matches: true,
            },
            guard: sample_process(11, "neverguard"),
            launcher: sample_process(10, "neverlauncher-desktop"),
            evidence_sha256: String::new(),
            session_proof: "44".repeat(32),
        };
        evidence.evidence_sha256 = hex::encode(recompute_evidence_sha256(&evidence).expect("digest"));
        evidence
    }

    #[test]
    fn evidence_digest_changes_when_process_image_changes() {
        let evidence = sample_evidence();
        let original = evidence.evidence_sha256.clone();
        let mut changed = evidence.clone();
        changed.guard.image_sha256 = "aa".repeat(32);
        assert_ne!(hex::encode(recompute_evidence_sha256(&changed).expect("digest")), original);
    }

    #[test]
    fn evidence_shape_rejects_parent_mismatch() {
        let mut evidence = sample_evidence();
        assert!(validate_evidence_shape(&evidence).is_ok());
        evidence.boundary.observed_parent_pid = 999;
        evidence.boundary.parent_matches = false;
        assert!(validate_evidence_shape(&evidence).is_err());
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::{collections::BTreeMap, fs::File, io::{BufReader, Read}, os::unix::fs::MetadataExt, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

    const MAX_REPORTED_NON_SYSTEM_MODULES: usize = 64;

    fn sha256_file(path: &Path) -> Result<String, String> {
        let file = File::open(path).map_err(|e| format!("open {} failed: {e}", path.display()))?;
        let mut reader = BufReader::new(file); let mut hasher = Sha256::new(); let mut buf=[0u8;64*1024];
        loop { let n=reader.read(&mut buf).map_err(|e| format!("read {} failed: {e}", path.display()))?; if n==0 { break; } hasher.update(&buf[..n]); }
        Ok(hex::encode(hasher.finalize()))
    }

    fn proc_status(pid: u32) -> Result<String, String> {
        std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| format!("read /proc/{pid}/status failed: {e}"))
    }
    fn status_u32(status: &str, key: &str) -> Option<u32> {
        status.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse().ok())
    }
    fn observed_parent_pid(pid: u32) -> Result<u32, String> { status_u32(&proc_status(pid)?, "PPid:").ok_or_else(|| "PPid missing in /proc status".into()) }
    fn process_start_ticks(pid: u32) -> Result<u64, String> {
        let stat=std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| format!("read /proc/{pid}/stat failed: {e}"))?;
        let end=stat.rfind(')').ok_or_else(|| "malformed /proc stat".to_string())?;
        let rest=stat.get(end+2..).ok_or_else(|| "malformed /proc stat".to_string())?;
        rest.split_whitespace().nth(19).ok_or_else(|| "starttime missing".to_string())?.parse().map_err(|_| "invalid process starttime".to_string())
    }
    fn pdeathsig(pid: u32) -> bool {
        if pid != std::process::id() {
            return false;
        }
        let mut sig = 0;
        unsafe {
            libc::prctl(
                libc::PR_GET_PDEATHSIG,
                &mut sig as *mut libc::c_int,
            ) == 0 && sig == libc::SIGKILL
        }
    }
    fn security(pid: u32) -> Result<LinuxProcessSecurityEvidence, String> {
        let status=proc_status(pid)?;
        Ok(LinuxProcessSecurityEvidence {
            uid: status_u32(&status,"Uid:").ok_or_else(|| "Uid missing".to_string())?,
            gid: status_u32(&status,"Gid:").ok_or_else(|| "Gid missing".to_string())?,
            no_new_privs: status_u32(&status,"NoNewPrivs:")==Some(1),
            seccomp_mode: status_u32(&status,"Seccomp:").unwrap_or(0),
            dumpable_disabled: if pid==std::process::id() { unsafe { libc::prctl(libc::PR_GET_DUMPABLE,0,0,0,0)==0 } } else { true },
            parent_death_signal: pdeathsig(pid),
        })
    }
    fn modules(pid: u32, primary: &Path) -> Result<ModuleSetEvidence,String> {
        let maps=std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| format!("read maps failed: {e}"))?;
        let mut files=BTreeMap::<String,String>::new();
        for line in maps.lines() {
            let Some(raw)=line.split_whitespace().last() else { continue; };
            if !raw.starts_with('/') { continue; }
            let path=raw.strip_suffix(" (deleted)").unwrap_or(raw);
            if files.contains_key(path) { continue; }
            if let Ok(hash)=sha256_file(Path::new(path)) { files.insert(path.to_string(),hash); }
        }
        let mut h=Sha256::new(); let mut non_system=Vec::new();
        for (path,hash) in &files { h.update((path.len() as u64).to_le_bytes()); h.update(path.as_bytes()); h.update(hex::decode(hash).unwrap_or_default());
            let system=path.starts_with("/usr/lib/")||path.starts_with("/lib/")||path.starts_with("/lib64/")||Path::new(path)==primary;
            if !system && non_system.len()<MAX_REPORTED_NON_SYSTEM_MODULES { non_system.push(path.clone()); }
        }
        Ok(ModuleSetEvidence { module_count: files.len() as u32, module_set_sha256: hex::encode(h.finalize()), non_system_module_names: non_system })
    }
    fn process(pid:u32)->Result<ProcessIntegrityEvidence,String>{
        let image=std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e|format!("read exe link failed: {e}"))?;
        let meta=std::fs::metadata(&image).map_err(|e|format!("metadata {} failed: {e}",image.display()))?;
        let modified=meta.modified().ok().and_then(|v|v.duration_since(UNIX_EPOCH).ok()).map(|d|d.as_millis() as u64).unwrap_or(0);
        Ok(ProcessIntegrityEvidence{ pid, image_path:image.to_string_lossy().into_owned(), image_sha256:sha256_file(&image)?, image_size:meta.len(), image_modified_unix_ms:modified, process_created_filetime:process_start_ticks(pid)?, authenticode:AuthenticodeEvidence{trusted:false,status:"not-applicable-linux".into()}, mitigations:ProcessMitigationEvidence{dep:None,aslr:None,dynamic_code:None,extension_point_disable:None,control_flow_guard:None,binary_signature:None,image_load:None,child_process:None,user_shadow_stack:None,sehop:None,query_failures:vec![]}, modules:modules(pid,&image)?, linux:Some(security(pid)?), })
    }
    pub fn collect(expected_parent_pid:u32)->Result<NeverGuardIntegrityEvidence,String>{
        let guard_pid=std::process::id(); let observed=observed_parent_pid(guard_pid)?; if observed!=expected_parent_pid { return Err(format!("Linux NeverGuard parent mismatch: expected {expected_parent_pid}, observed {observed}")); }
        let mut id=[0u8;16]; OsRng.fill_bytes(&mut id);
        let collected=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs();
        let mut evidence=NeverGuardIntegrityEvidence{ schema:NEVERGUARD_LINUX_INTEGRITY_EVIDENCE_SCHEMA.into(), evidence_version:1, evidence_id:hex::encode(id), collected_at_unix:collected, boundary:BoundaryEvidence{expected_parent_pid,observed_parent_pid:observed,parent_matches:true}, guard:process(guard_pid)?, launcher:process(expected_parent_pid)?, evidence_sha256:String::new(), session_proof:String::new() };
        evidence.evidence_sha256=hex::encode(recompute_evidence_sha256(&evidence)?); validate_evidence_shape(&evidence)?; Ok(evidence)
    }
    pub fn parent(pid:u32)->Result<u32,String>{ observed_parent_pid(pid) }
}

#[cfg(target_os = "linux")]
pub(crate) fn collect_linux_integrity_evidence(expected_parent_pid:u32)->Result<NeverGuardIntegrityEvidence,String>{ linux_impl::collect(expected_parent_pid) }
#[cfg(target_os = "linux")]
pub(crate) fn observed_linux_parent_pid(pid:u32)->Result<u32,String>{ linux_impl::parent(pid) }
