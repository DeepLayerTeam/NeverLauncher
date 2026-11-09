use serde::{Deserialize, Serialize};
use crate::{
    linux_policy::LinuxGuardPolicyDetails,
    macos_policy::MacOSGuardPolicyDetails,
    windows_protection::{
        WindowsGuardPolicyDetails, WindowsMitigationRequirements,
        WindowsProtectionCoreReport as GenericWindowsProtectionCoreReport,
        WindowsProtectionProfile, GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
        GUARD_WINDOWS_PROTECTION_CORE_SCHEMA, GUARD_WINDOWS_PROTECTION_CORE_VERSION,
    },
};

pub const GUARD_WINDOWS_PROCESS_POLICY_VERSION: u32 = 1;
pub const GUARD_WINDOWS_HARDENING_VERSION: u32 = 1;
pub const GUARD_WINDOWS_PROCESS_POLICY_SCHEMA: &str =
    "guard/windows-runtime-process-policy/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GuardProcessPolicyReport {
    pub schema: String,
    pub policy_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub dynamic_code_prohibited: bool,
    pub extension_points_disabled: bool,
    pub strict_handle_checks: bool,
    pub remote_images_blocked: bool,
    pub low_mandatory_label_images_blocked: bool,
    pub prefer_system32_images: bool,
    pub child_process_creation_blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxGuardPolicyDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<MacOSGuardPolicyDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsGuardPolicyDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProductionHardeningReport {
    pub hardening_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub heap_terminate_on_corruption: bool,
    pub current_directory_removed_from_dll_search: bool,
    pub restricted_default_dll_directories: bool,
}

pub type WindowsProtectionCoreReport =
    GenericWindowsProtectionCoreReport<GuardProcessPolicyReport, WindowsProductionHardeningReport>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProcessTreeSnapshot {
    pub root_pid: u32,
    pub process_count: u32,
    pub descendant_count: u32,
    pub job_bound: bool,
    pub process_tree_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProcessPolicyReport {
    pub schema: String,
    pub policy_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub created_suspended: bool,
    pub assigned_to_job: bool,
    pub kill_on_job_close: bool,
    pub die_on_unhandled_exception: bool,
    pub breakaway_allowed: bool,
    pub primary_thread_resumed: bool,
}


pub fn validate_windows_guard_policy_report(
    policy: &GuardProcessPolicyReport,
    expected_profile: WindowsProtectionProfile,
) -> Result<(), String> {
    if policy.schema != GUARD_WINDOWS_PROCESS_POLICY_SCHEMA
        || policy.policy_version != GUARD_WINDOWS_PROCESS_POLICY_VERSION
        || !policy.enforced
    {
        return Err("Не совпадает схема, версия или состояние применения политики процессов Guard в Windows".to_string());
    }
    let details = policy
        .windows
        .as_ref()
        .ok_or_else(|| "В политике процессов Guard для Windows отсутствуют сведения Protection Core".to_string())?;
    if details.core_schema != GUARD_WINDOWS_PROTECTION_CORE_SCHEMA
        || details.core_version != GUARD_WINDOWS_PROTECTION_CORE_VERSION
        || details.capability_model_version != GUARD_WINDOWS_CAPABILITY_MODEL_VERSION
        || details.capabilities.model_version != GUARD_WINDOWS_CAPABILITY_MODEL_VERSION
        || details.profile != expected_profile
        || details.remote_attestation_eligible != expected_profile.is_remote_attestation_eligible()
        || details.requirements != WindowsMitigationRequirements::for_profile(expected_profile)
        || !details.requirements_satisfied
        || !details.capabilities.requirements_satisfied()
    {
        return Err("Ошибка: «проверка профиля и возможностей Windows Protection Core»".to_string());
    }

    let requirements = details.requirements;
    let direct_dynamic = u32::from(policy.dynamic_code_prohibited);
    let direct_extension = u32::from(policy.extension_points_disabled);
    let direct_strict = if policy.strict_handle_checks { 0x3 } else { 0 };
    let direct_image = u32::from(policy.remote_images_blocked)
        | (u32::from(policy.low_mandatory_label_images_blocked) << 1)
        | (u32::from(policy.prefer_system32_images) << 2);
    let direct_child = u32::from(policy.child_process_creation_blocked);
    for (name, actual, required) in [
        ("DynamicCode", direct_dynamic, requirements.dynamic_code),
        ("ExtensionPointDisable", direct_extension, requirements.extension_point_disable),
        ("StrictHandleCheck", direct_strict, requirements.strict_handle_check),
        ("ImageLoad", direct_image, requirements.image_load),
        ("ChildProcess", direct_child, requirements.child_process),
    ] {
        if actual & required != required {
            return Err(format!(
                "Guard: политика Windows {name} не соответствует профилю {expected_profile}: required=0x{required:08x}, actual=0x{actual:08x}"
            ));
        }
    }

    let capabilities = &details.capabilities;
    for (name, capability, required) in [
        ("DynamicCode", &capabilities.dynamic_code_policy, requirements.dynamic_code),
        (
            "ExtensionPointDisable",
            &capabilities.extension_point_disable_policy,
            requirements.extension_point_disable,
        ),
        (
            "StrictHandleCheck",
            &capabilities.strict_handle_check_policy,
            requirements.strict_handle_check,
        ),
        ("ImageLoad", &capabilities.image_load_policy, requirements.image_load),
        ("ChildProcess", &capabilities.child_process_policy, requirements.child_process),
    ] {
        if capability.required_flags != required
            || (required != 0 && !capability.supported)
            || !capability.satisfied
        {
            return Err(format!(
                "Guard: возможность Windows {name} не соответствует профилю {expected_profile}"
            ));
        }
    }
    if !capabilities.guard_lifetime_job_bound || capabilities.architecture.trim().is_empty() {
        return Err("Модель возможностей Guard в Windows заполнена не полностью".to_string());
    }
    Ok(())
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use crate::windows_protection::{
        protection_profile_from_environment, WindowsMitigationCapability,
        WindowsProtectionCapabilities,
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        ffi::c_void,
        mem::{size_of, zeroed},
        ptr::{null, null_mut},
        sync::{Arc, OnceLock},
    };
    use tokio::process::{Child, Command};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First,
                Thread32Next, PROCESSENTRY32W, THREADENTRY32, TH32CS_SNAPPROCESS,
                TH32CS_SNAPTHREAD,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
                QueryInformationJobObject, SetInformationJobObject,
                JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            LibraryLoader::{
                SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            },
            Memory::{HeapSetInformation, HeapEnableTerminationOnCorruption},
            Threading::{
                GetExitCodeProcess, GetProcessMitigationPolicy, OpenProcess, OpenThread, ResumeThread,
                SetProcessMitigationPolicy, ProcessChildProcessPolicy, ProcessDynamicCodePolicy,
                ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
                ProcessStrictHandleCheckPolicy, CREATE_SUSPENDED, PROCESS_MITIGATION_POLICY,
                PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
            },
        },
    };

    const JOB_LIMITS_REQUIRED: u32 =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    const MAX_JOB_PROCESS_IDS: usize = 4096;

    static GUARD_POLICY: OnceLock<Result<GuardProcessPolicyReport, String>> = OnceLock::new();
    static PROCESS_HARDENING: OnceLock<Result<WindowsProductionHardeningReport, String>> = OnceLock::new();

    #[derive(Debug)]
    struct OwnedJob(usize);

    impl OwnedJob {
        fn raw(&self) -> HANDLE {
            self.0 as HANDLE
        }
    }

    impl Drop for OwnedJob {
        fn drop(&mut self) {
            let handle = self.raw();
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct GuardLifetimeJob {
        _job: Arc<OwnedJob>,
    }

    #[derive(Debug, Clone)]
    pub struct RuntimeProcessPolicyGuard {
        report: RuntimeProcessPolicyReport,
        _job: Arc<OwnedJob>,
    }

    impl RuntimeProcessPolicyGuard {
        pub fn report(&self) -> &RuntimeProcessPolicyReport {
            &self.report
        }

        pub fn verify_process_tree(&self, root_pid: u32) -> Result<RuntimeProcessTreeSnapshot, String> {
            if root_pid != self.report.pid {
                return Err(format!(
                    "Guard: корень дерева процессов не соответствует политике: policy={}, requested={root_pid}",
                    self.report.pid
                ));
            }
            if self.report.breakaway_allowed || !self.report.assigned_to_job {
                return Err("Guard: для проверки дерева процессов необходим Job Object с запретом выхода процессов из группы".to_string());
            }
            verify_process_tree_for_job(self._job.raw(), root_pid)
        }
    }

    pub fn ensure_guard_process_policy() -> Result<GuardProcessPolicyReport, String> {
        if let Some(cached) = GUARD_POLICY.get() {
            return cached.clone();
        }
        let profile = protection_profile_from_environment()?;
        ensure_guard_process_policy_with_profile(profile)
    }

    pub fn ensure_guard_process_policy_with_profile(
        profile: WindowsProtectionProfile,
    ) -> Result<GuardProcessPolicyReport, String> {
        let report = GUARD_POLICY
            .get_or_init(|| apply_guard_process_policy(profile))
            .clone()?;
        let actual_profile = report
            .windows
            .as_ref()
            .map(|details| details.profile)
            .ok_or_else(|| "В политике Guard для Windows отсутствуют сведения о ядре защиты".to_string())?;
        if actual_profile != profile {
            return Err(format!(
                "Guard: ядро защиты Windows уже инициализировано с профилем {actual_profile}, запрошен {profile}"
            ));
        }
        Ok(report)
    }

    pub fn ensure_windows_production_hardening() -> Result<WindowsProductionHardeningReport, String> {
        PROCESS_HARDENING
            .get_or_init(apply_windows_production_hardening)
            .clone()
    }

    pub fn ensure_windows_protection_core() -> Result<WindowsProtectionCoreReport, String> {
        if let Some(cached) = GUARD_POLICY.get() {
            let process_policy = cached.clone()?;
            let profile = process_policy
                .windows
                .as_ref()
                .map(|details| details.profile)
                .ok_or_else(|| "В политике Guard для Windows отсутствуют сведения о ядре защиты".to_string())?;
            let hardening = ensure_windows_production_hardening()?;
            return Ok(build_core_report(profile, process_policy, hardening));
        }
        let profile = protection_profile_from_environment()?;
        ensure_windows_protection_core_with_profile(profile)
    }

    pub fn ensure_windows_protection_core_with_profile(
        profile: WindowsProtectionProfile,
    ) -> Result<WindowsProtectionCoreReport, String> {
        // Применяйте глобальную защиту heap и DLL до профильных ограничений
        // и создания Tokio runtime процессом guard.exe. Это сохраняет
        // производственный порядок и учитывает требования каждого профиля.
        let hardening = ensure_windows_production_hardening()?;
        let process_policy = ensure_guard_process_policy_with_profile(profile)?;
        Ok(build_core_report(profile, process_policy, hardening))
    }

    fn build_core_report(
        profile: WindowsProtectionProfile,
        process_policy: GuardProcessPolicyReport,
        hardening: WindowsProductionHardeningReport,
    ) -> WindowsProtectionCoreReport {
        WindowsProtectionCoreReport {
            schema: GUARD_WINDOWS_PROTECTION_CORE_SCHEMA.to_string(),
            core_version: GUARD_WINDOWS_PROTECTION_CORE_VERSION,
            profile,
            capability_model_version: GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
            process_policy,
            hardening,
        }
    }

    fn apply_windows_production_hardening() -> Result<WindowsProductionHardeningReport, String> {
        let heap_ok = unsafe {
            HeapSetInformation(
                std::ptr::null_mut(),
                HeapEnableTerminationOnCorruption,
                std::ptr::null(),
                0,
            )
        };
        if heap_ok == 0 {
            return Err(format!(
                "Не удалось включить завершение процесса при повреждении кучи Windows: {}",
                std::io::Error::last_os_error()
            ));
        }

        let empty = [0u16];
        let dll_dir_ok = unsafe { SetDllDirectoryW(empty.as_ptr()) };
        if dll_dir_ok == 0 {
            return Err(format!(
                "Не удалось исключить текущий каталог из поиска DLL Windows: {}",
                std::io::Error::last_os_error()
            ));
        }

        let search_flags = LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
        let default_dirs_ok = unsafe { SetDefaultDllDirectories(search_flags) };
        if default_dirs_ok == 0 {
            return Err(format!(
                "Не удалось ограничить стандартные каталоги поиска DLL Windows: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(WindowsProductionHardeningReport {
            hardening_version: GUARD_WINDOWS_HARDENING_VERSION,
            pid: std::process::id(),
            enforced: true,
            heap_terminate_on_corruption: true,
            current_directory_removed_from_dll_search: true,
            restricted_default_dll_directories: true,
        })
    }

    pub fn prepare_guard_command(command: &mut Command) {
        command.creation_flags(CREATE_SUSPENDED);
    }

    pub fn bind_guard_to_launcher_job(child: &mut Child) -> Result<GuardLifetimeJob, String> {
        let pid = child
            .id()
            .ok_or_else(|| "PID процесса Guard недоступен для контроля времени жизни при приостановленном запуске".to_string())?;
        let process_handle = child
            .raw_handle()
            .ok_or_else(|| "Дескриптор процесса Guard недоступен для задания контроля времени жизни".to_string())?
            as HANDLE;
        let job_handle = unsafe { CreateJobObjectW(null(), null()) };
        if job_handle.is_null() {
            return Err(format!(
                "Guard: не удалось создать Job Object для времени жизни процесса: {}",
                std::io::Error::last_os_error()
            ));
        }
        let job = Arc::new(OwnedJob(job_handle as usize));
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let set_ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set_ok == 0 {
            return Err(format!(
                "Guard: не удалось настроить политику Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        let assign_ok = unsafe { AssignProcessToJobObject(job.raw(), process_handle) };
        if assign_ok == 0 {
            return Err(format!(
                "Guard: не удалось привязать процесс к Job Object жизненного цикла лаунчера: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut in_job = 0i32;
        let membership_ok = unsafe { IsProcessInJob(process_handle, job.raw(), &mut in_job) };
        if membership_ok == 0 || in_job == 0 {
            return Err(format!(
                "Guard: не удалось проверить Job Object лаунчера: {}",
                std::io::Error::last_os_error()
            ));
        }
        resume_primary_thread(pid)?;
        Ok(GuardLifetimeJob { _job: job })
    }

    fn apply_guard_process_policy(
        profile: WindowsProtectionProfile,
    ) -> Result<GuardProcessPolicyReport, String> {
        let requirements = WindowsMitigationRequirements::for_profile(profile);

        apply_policy_if_required("DynamicCode", ProcessDynamicCodePolicy, requirements.dynamic_code)?;
        apply_policy_if_required(
            "ExtensionPointDisable",
            ProcessExtensionPointDisablePolicy,
            requirements.extension_point_disable,
        )?;
        apply_policy_if_required(
            "StrictHandleCheck",
            ProcessStrictHandleCheckPolicy,
            requirements.strict_handle_check,
        )?;
        apply_policy_if_required("ImageLoad", ProcessImageLoadPolicy, requirements.image_load)?;
        apply_policy_if_required(
            "ChildProcess",
            ProcessChildProcessPolicy,
            requirements.child_process,
        )?;

        let capabilities = WindowsProtectionCapabilities {
            model_version: GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
            architecture: std::env::consts::ARCH.to_string(),
            dynamic_code_policy: mitigation_capability(
                "DynamicCode",
                ProcessDynamicCodePolicy,
                requirements.dynamic_code,
            ),
            extension_point_disable_policy: mitigation_capability(
                "ExtensionPointDisable",
                ProcessExtensionPointDisablePolicy,
                requirements.extension_point_disable,
            ),
            strict_handle_check_policy: mitigation_capability(
                "StrictHandleCheck",
                ProcessStrictHandleCheckPolicy,
                requirements.strict_handle_check,
            ),
            image_load_policy: mitigation_capability(
                "ImageLoad",
                ProcessImageLoadPolicy,
                requirements.image_load,
            ),
            child_process_policy: mitigation_capability(
                "ChildProcess",
                ProcessChildProcessPolicy,
                requirements.child_process,
            ),
            guard_lifetime_job_bound: current_process_is_job_bound()?,
        };

        if !capabilities.requirements_satisfied() {
            return Err(format!(
                "Guard: набор возможностей системы не позволяет обеспечить профиль защиты Windows {profile}"
            ));
        }

        let dynamic_code = capabilities.dynamic_code_policy.observed_flags;
        let extension_points = capabilities.extension_point_disable_policy.observed_flags;
        let strict_handle = capabilities.strict_handle_check_policy.observed_flags;
        let image_load = capabilities.image_load_policy.observed_flags;
        let child_process = capabilities.child_process_policy.observed_flags;

        let windows = WindowsGuardPolicyDetails {
            core_schema: GUARD_WINDOWS_PROTECTION_CORE_SCHEMA.to_string(),
            core_version: GUARD_WINDOWS_PROTECTION_CORE_VERSION,
            capability_model_version: GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
            profile,
            remote_attestation_eligible: profile.is_remote_attestation_eligible(),
            requirements,
            requirements_satisfied: true,
            capabilities,
        };

        Ok(GuardProcessPolicyReport {
            schema: GUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: GUARD_WINDOWS_PROCESS_POLICY_VERSION,
            pid: std::process::id(),
            enforced: true,
            dynamic_code_prohibited: dynamic_code & 0x1 != 0,
            extension_points_disabled: extension_points & 0x1 != 0,
            strict_handle_checks: strict_handle & 0x3 == 0x3,
            remote_images_blocked: image_load & 0x1 != 0,
            low_mandatory_label_images_blocked: image_load & 0x2 != 0,
            prefer_system32_images: image_load & 0x4 != 0,
            child_process_creation_blocked: child_process & 0x1 != 0,
            linux: None,
            macos: None,
            windows: Some(windows),
        })
    }

    fn apply_policy_if_required(
        name: &str,
        policy: PROCESS_MITIGATION_POLICY,
        flags: u32,
    ) -> Result<(), String> {
        if flags == 0 {
            return Ok(());
        }
        set_policy(name, policy, flags)
    }

    fn set_policy(
        name: &str,
        policy: PROCESS_MITIGATION_POLICY,
        flags: u32,
    ) -> Result<(), String> {
        let ok = unsafe {
            SetProcessMitigationPolicy(
                policy,
                &flags as *const u32 as *const c_void,
                size_of::<u32>(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "Guard: не удалось применить политику процессов Windows {name}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn mitigation_capability(
        name: &str,
        policy: PROCESS_MITIGATION_POLICY,
        required_flags: u32,
    ) -> WindowsMitigationCapability {
        match query_policy(name, policy) {
            Ok(observed_flags) => {
                WindowsMitigationCapability::observed(required_flags, observed_flags)
            }
            Err(error) => WindowsMitigationCapability::unsupported(required_flags, error),
        }
    }

    fn query_policy(name: &str, policy: PROCESS_MITIGATION_POLICY) -> Result<u32, String> {
        let mut flags = 0u32;
        let ok = unsafe {
            GetProcessMitigationPolicy(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                policy,
                &mut flags as *mut u32 as *mut c_void,
                size_of::<u32>(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "Guard: не удалось запросить политику процессов Windows {name}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(flags)
    }

    fn current_process_is_job_bound() -> Result<bool, String> {
        let mut in_job = 0i32;
        let ok = unsafe {
            IsProcessInJob(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                null_mut(),
                &mut in_job,
            )
        };
        if ok == 0 {
            return Err(format!(
                "Guard: не удалось проверить принадлежность текущего процесса к Job Object Windows: {}",
                std::io::Error::last_os_error()
            ));
        }
        if in_job == 0 {
            return Err("Guard Windows Protection Core: требуется «привязка жизненного цикла лаунчера к Job Object»".to_string());
        }
        Ok(true)
    }

    fn job_process_ids(job: HANDLE) -> Result<HashSet<u32>, String> {
        let mut buffer = vec![0u8; 8 + MAX_JOB_PROCESS_IDS * size_of::<usize>()];
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len().min(u32::MAX as usize) as u32,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "Guard: не удалось получить список участников Job Object Runtime: {}",
                std::io::Error::last_os_error()
            ));
        }
        let assigned = u32::from_ne_bytes(buffer[0..4].try_into().expect("получить заголовок фиксированной длины")) as usize;
        let listed = u32::from_ne_bytes(buffer[4..8].try_into().expect("получить заголовок фиксированной длины")) as usize;
        if assigned > listed || listed > MAX_JOB_PROCESS_IDS {
            return Err(format!(
                "Guard: список процессов Job Object неполон: assigned={assigned}, listed={listed}"
            ));
        }
        let required = 8usize
            .checked_add(listed.saturating_mul(size_of::<usize>()))
            .ok_or_else(|| "Guard: переполнение размера списка процессов Job Object".to_string())?;
        if required > buffer.len() {
            return Err("Список процессов Job Object в Guard превышает размер буфера проверки".to_string());
        }
        let mut result = HashSet::with_capacity(listed);
        for index in 0..listed {
            let offset = 8 + index * size_of::<usize>();
            let raw = unsafe {
                std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const usize)
            };
            let pid = u32::try_from(raw)
                .map_err(|_| format!("Guard: PID Job Object не помещается в u32: {raw}"))?;
            if pid == 0 || !result.insert(pid) {
                return Err(format!("Список процессов объекта заданий Guard содержит некорректный или повторяющийся PID {pid}"));
            }
        }
        Ok(result)
    }

    fn verify_process_tree_for_job(job: HANDLE, root_pid: u32) -> Result<RuntimeProcessTreeSnapshot, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "Guard: не удалось получить снимок дерева процессов: {}",
                std::io::Error::last_os_error()
            ));
        }
        struct Snapshot(HANDLE);
        impl Drop for Snapshot {
            fn drop(&mut self) {
                if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                    unsafe { let _ = CloseHandle(self.0); }
                }
            }
        }
        let snapshot = Snapshot(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut parent_by_pid = HashMap::<u32, u32>::new();
        let mut has_entry = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        while has_entry {
            parent_by_pid.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            has_entry = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        if !parent_by_pid.contains_key(&root_pid) {
            return Err(format!("Корневой PID Runtime Guard {root_pid} отсутствует в снимке процессов"));
        }
        let job_members = job_process_ids(job)?;
        if !job_members.contains(&root_pid) {
            return Err(format!(
                "Guard: нарушена целостность дерева процессов — корневой PID Runtime {root_pid} отсутствует в Job Object"
            ));
        }

        let mut descendants = HashSet::new();
        let mut queue = VecDeque::from([root_pid]);
        while let Some(parent) = queue.pop_front() {
            for (&pid, &observed_parent) in &parent_by_pid {
                if pid != root_pid && observed_parent == parent && descendants.insert(pid) {
                    queue.push_back(pid);
                }
            }
        }

        // Снимки процессов ToolHelp и PID внутри Job Object независимы.
        // Потомок может возникнуть между чтениями, поэтому его отсутствие
        // в раннем списке ещё не означает выход из задания. Проверяйте
        // всех живых потомков через IsProcessInJob; этот системный запрос
        // определяющий и строго блокирует настоящий побег.

        for pid in std::iter::once(root_pid).chain(descendants.iter().copied()) {
            let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if process.is_null() {
                if pid == root_pid {
                    return Err(format!(
                        "Guard: не удалось открыть корневой процесс Runtime с PID {pid} для проверки Job Object: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                // Кратковременный дочерний процесс может завершиться после снимка.
                // Он больше не входит в живое дерево и не нарушает текущую границу.
                continue;
            }
            // ToolHelp может показать недавно завершённый дочерний
            // процесс, чей объект ещё открыт. Windows удаляет завершённые
            // процессы из Job Object, даже если OpenProcess ещё успешен.
            // Проверка их членства даст ложное сообщение о побеге.
            const STILL_ACTIVE_EXIT_CODE: u32 = 259;
            let mut exit_code = 0u32;
            let exit_ok = unsafe { GetExitCodeProcess(process, &mut exit_code) };
            if exit_ok == 0 {
                let error = std::io::Error::last_os_error();
                unsafe { let _ = CloseHandle(process); }
                return Err(format!(
                    "Guard: не удалось проверить активность процесса PID {pid}: {error}"
                ));
            }
            if exit_code != STILL_ACTIVE_EXIT_CODE {
                unsafe { let _ = CloseHandle(process); }
                if pid == root_pid {
                    return Err(format!("Корневой PID Runtime Guard {pid} завершился во время проверки Job Object"));
                }
                continue;
            }
            let mut in_job = 0i32;
            let ok = unsafe { IsProcessInJob(process, job, &mut in_job) };
            if ok == 0 {
                let error = std::io::Error::last_os_error();
                unsafe { let _ = CloseHandle(process); }
                return Err(format!(
                    "Guard: не удалось проверить принадлежность PID {pid} к Job Object: {error}"
                ));
            }
            if in_job == 0 {
                // Дочерний процесс может завершиться между двумя запросами ОС. Перед объявлением
                // побега перепроверьте тот же дескриптор, а не повторно используемый PID.
                let mut final_exit_code = 0u32;
                let final_ok = unsafe { GetExitCodeProcess(process, &mut final_exit_code) };
                if final_ok == 0 {
                    let error = std::io::Error::last_os_error();
                    unsafe { let _ = CloseHandle(process); }
                    return Err(format!(
                        "Guard: повторная проверка активности процесса PID {pid} завершилась ошибкой: {error}"
                    ));
                }
                unsafe { let _ = CloseHandle(process); }
                if pid != root_pid && final_exit_code != STILL_ACTIVE_EXIT_CODE {
                    continue;
                }
                return Err(format!(
                    "Guard: нарушена целостность дерева процессов — дочерний PID {pid} вышел из Job Object Runtime"
                ));
            }
            unsafe { let _ = CloseHandle(process); }
        }

        let mut records = Vec::with_capacity(job_members.len());
        for pid in &job_members {
            records.push((*pid, *parent_by_pid.get(pid).unwrap_or(&0)));
        }
        records.sort_unstable();
        let mut digest = Sha256::new();
        digest.update(b"Launcher Thread & Process Integrity process-tree v1\0");
        for (pid, parent) in records {
            digest.update(pid.to_le_bytes());
            digest.update(parent.to_le_bytes());
        }
        Ok(RuntimeProcessTreeSnapshot {
            root_pid,
            process_count: job_members.len().min(u32::MAX as usize) as u32,
            descendant_count: job_members.len().saturating_sub(1).min(u32::MAX as usize) as u32,
            job_bound: true,
            process_tree_sha256: hex::encode(digest.finalize()),
        })
    }

    pub fn prepare_runtime_command(command: &mut Command) {
        command.creation_flags(CREATE_SUSPENDED);
    }

    pub fn enforce_runtime_process(
        child: &mut Child,
    ) -> Result<RuntimeProcessPolicyGuard, String> {
        match enforce_runtime_process_inner(child) {
            Ok(value) => Ok(value),
            Err(err) => {
                let _ = child.start_kill();
                Err(err)
            }
        }
    }

    fn enforce_runtime_process_inner(
        child: &mut Child,
    ) -> Result<RuntimeProcessPolicyGuard, String> {
        let pid = child
            .id()
            .ok_or_else(|| "PID среды выполнения Windows недоступен до применения политики".to_string())?;
        let process_handle = child
            .raw_handle()
            .ok_or_else(|| "Дескриптор процесса среды выполнения Windows недоступен до применения политики".to_string())?
            as HANDLE;

        let job_handle = unsafe { CreateJobObjectW(null(), null()) };
        if job_handle.is_null() {
            return Err(format!(
                "Не удалось создать Job Object для Runtime Windows: {}",
                std::io::Error::last_os_error()
            ));
        }
        let job = Arc::new(OwnedJob(job_handle as usize));

        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_LIMITS_REQUIRED;
        let set_ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set_ok == 0 {
            return Err(format!(
                "Не удалось настроить политику Job Object Runtime Windows: {}",
                std::io::Error::last_os_error()
            ));
        }

        let assign_ok = unsafe { AssignProcessToJobObject(job.raw(), process_handle) };
        if assign_ok == 0 {
            return Err(format!(
                "Runtime Windows: не удалось назначить процесс в Guard Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut in_job = 0i32;
        let membership_ok = unsafe { IsProcessInJob(process_handle, job.raw(), &mut in_job) };
        if membership_ok == 0 || in_job == 0 {
            return Err(format!(
                "Не удалось проверить принадлежность процесса Runtime к Job Object Windows: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut observed: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        let query_ok = unsafe {
            QueryInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &mut observed as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *mut c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            )
        };
        if query_ok == 0 {
            return Err(format!(
                "Не удалось проверить политику Job Object Runtime Windows: {}",
                std::io::Error::last_os_error()
            ));
        }
        let actual_limits = observed.BasicLimitInformation.LimitFlags;
        if actual_limits & JOB_LIMITS_REQUIRED != JOB_LIMITS_REQUIRED {
            return Err(format!(
                "Runtime Windows: ограничения Job Object заданы не полностью: required=0x{JOB_LIMITS_REQUIRED:08x}, actual=0x{actual_limits:08x}"
            ));
        }
        if actual_limits
            & (windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_BREAKAWAY_OK
                | windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            != 0
        {
            return Err("Job Object в Windows Runtime неожиданно допускает выход процессов из группы".to_string());
        }

        resume_primary_thread(pid)?;

        let report = RuntimeProcessPolicyReport {
            schema: GUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: GUARD_WINDOWS_PROCESS_POLICY_VERSION,
            pid,
            enforced: true,
            created_suspended: true,
            assigned_to_job: true,
            kill_on_job_close: actual_limits & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0,
            die_on_unhandled_exception: actual_limits
                & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                != 0,
            breakaway_allowed: false,
            primary_thread_resumed: true,
        };

        Ok(RuntimeProcessPolicyGuard { report, _job: job })
    }

    fn resume_primary_thread(pid: u32) -> Result<(), String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "Не удалось получить снимок потоков Runtime Windows для PID {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        struct Snapshot(HANDLE);
        impl Drop for Snapshot {
            fn drop(&mut self) {
                if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                    unsafe {
                        let _ = CloseHandle(self.0);
                    }
                }
            }
        }
        let snapshot = Snapshot(snapshot);
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut has_entry = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
        while has_entry {
            if entry.th32OwnerProcessID == pid {
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if !thread.is_null() {
                    let previous_suspend_count = unsafe { ResumeThread(thread) };
                    unsafe {
                        let _ = CloseHandle(thread);
                    }
                    if previous_suspend_count == u32::MAX {
                        return Err(format!(
                            "Не удалось возобновить основной поток Runtime Windows для PID {pid}: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if previous_suspend_count == 0 {
                        return Err(format!(
                            "Runtime Windows: процесс {pid} не был приостановлен при назначении политики"
                        ));
                    }
                    return Ok(());
                }
            }
            has_entry = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
        }
        Err(format!(
            "Runtime Windows: основной поток не найден при приостановленном процессе {pid}"
        ))
    }
}

#[cfg(windows)]
pub use windows_impl::{
    bind_guard_to_launcher_job, enforce_runtime_process, ensure_guard_process_policy,
    ensure_guard_process_policy_with_profile, ensure_windows_production_hardening,
    ensure_windows_protection_core, ensure_windows_protection_core_with_profile,
    prepare_guard_command, prepare_runtime_command, GuardLifetimeJob, RuntimeProcessPolicyGuard,
};

#[cfg(not(windows))]
#[derive(Debug, Clone, Default)]
pub struct GuardLifetimeJob;

#[cfg(not(windows))]
#[derive(Debug, Clone, Default)]
pub struct RuntimeProcessPolicyGuard;

#[cfg(not(windows))]
impl RuntimeProcessPolicyGuard {
    pub fn report(&self) -> &RuntimeProcessPolicyReport {
        unreachable!("Политика процессов Windows Runtime доступна только в Windows")
    }
}

#[cfg(not(windows))]
pub fn ensure_guard_process_policy() -> Result<GuardProcessPolicyReport, String> {
    Err("Применение политики процессов Windows в Guard 0.13.4 доступно только в Windows".to_string())
}

#[cfg(not(windows))]
pub fn ensure_windows_production_hardening() -> Result<WindowsProductionHardeningReport, String> {
    Err("Промышленные механизмы защиты Windows в Guard 0.13.6 доступны только в Windows".to_string())
}

#[cfg(not(windows))]
pub fn ensure_guard_process_policy_with_profile(
    _profile: WindowsProtectionProfile,
) -> Result<GuardProcessPolicyReport, String> {
    Err("Guard Windows Protection Core доступен только для Windows".to_string())
}

#[cfg(not(windows))]
pub fn ensure_windows_protection_core() -> Result<WindowsProtectionCoreReport, String> {
    Err("Guard Windows Protection Core доступен только для Windows".to_string())
}

#[cfg(not(windows))]
pub fn ensure_windows_protection_core_with_profile(
    _profile: WindowsProtectionProfile,
) -> Result<WindowsProtectionCoreReport, String> {
    Err("Guard Windows Protection Core доступен только для Windows".to_string())
}

#[cfg(not(windows))]
pub fn prepare_guard_command(_command: &mut tokio::process::Command) {}

#[cfg(not(windows))]
pub fn bind_guard_to_launcher_job(
    _child: &mut tokio::process::Child,
) -> Result<GuardLifetimeJob, String> {
    Err("Управление временем жизни лаунчера через Job Object в Guard 0.13.6 доступно только в Windows".to_string())
}

#[cfg(not(windows))]
pub fn prepare_runtime_command(_command: &mut tokio::process::Command) {}

#[cfg(not(windows))]
pub fn enforce_runtime_process(
    _child: &mut tokio::process::Child,
) -> Result<RuntimeProcessPolicyGuard, String> {
    Ok(RuntimeProcessPolicyGuard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_schema_and_version_are_stable() {
        assert_eq!(GUARD_WINDOWS_PROCESS_POLICY_VERSION, 1);
        assert_eq!(
            GUARD_WINDOWS_PROCESS_POLICY_SCHEMA,
            "guard/windows-runtime-process-policy/v1"
        );
    }

    #[test]
    fn runtime_report_serializes_enforcement_state() {
        let report = RuntimeProcessPolicyReport {
            schema: GUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: GUARD_WINDOWS_PROCESS_POLICY_VERSION,
            pid: 42,
            enforced: true,
            created_suspended: true,
            assigned_to_job: true,
            kill_on_job_close: true,
            die_on_unhandled_exception: true,
            breakaway_allowed: false,
            primary_thread_resumed: true,
        };
        let json = serde_json::to_value(&report).expect("Сериализация отчёта о политике");
        assert_eq!(json["pid"], 42);
        assert_eq!(json["assignedToJob"], true);
        assert_eq!(json["breakawayAllowed"], false);
    }
    #[test]
    fn hardening_report_serializes_enforcement_state() {
        let report = WindowsProductionHardeningReport {
            hardening_version: GUARD_WINDOWS_HARDENING_VERSION,
            pid: 42,
            enforced: true,
            heap_terminate_on_corruption: true,
            current_directory_removed_from_dll_search: true,
            restricted_default_dll_directories: true,
        };
        let json = serde_json::to_value(&report).expect("Сериализация отчёта об усилении защиты");
        assert_eq!(json["hardeningVersion"], GUARD_WINDOWS_HARDENING_VERSION);
        assert_eq!(json["enforced"], true);
        assert_eq!(json["restrictedDefaultDllDirectories"], true);
    }


    fn sample_windows_policy(profile: WindowsProtectionProfile) -> GuardProcessPolicyReport {
        use crate::windows_protection::{
            WindowsMitigationCapability, WindowsProtectionCapabilities,
        };

        let requirements = WindowsMitigationRequirements::for_profile(profile);
        let capability = |required_flags| {
            WindowsMitigationCapability::observed(required_flags, required_flags)
        };
        let capabilities = WindowsProtectionCapabilities {
            model_version: GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
            architecture: "x86_64".to_string(),
            dynamic_code_policy: capability(requirements.dynamic_code),
            extension_point_disable_policy: capability(requirements.extension_point_disable),
            strict_handle_check_policy: capability(requirements.strict_handle_check),
            image_load_policy: capability(requirements.image_load),
            child_process_policy: capability(requirements.child_process),
            guard_lifetime_job_bound: true,
        };
        GuardProcessPolicyReport {
            schema: GUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: GUARD_WINDOWS_PROCESS_POLICY_VERSION,
            pid: 42,
            enforced: true,
            dynamic_code_prohibited: requirements.dynamic_code & 0x1 != 0,
            extension_points_disabled: requirements.extension_point_disable & 0x1 != 0,
            strict_handle_checks: requirements.strict_handle_check & 0x3 == 0x3,
            remote_images_blocked: requirements.image_load & 0x1 != 0,
            low_mandatory_label_images_blocked: requirements.image_load & 0x2 != 0,
            prefer_system32_images: requirements.image_load & 0x4 != 0,
            child_process_creation_blocked: requirements.child_process & 0x1 != 0,
            linux: None,
            macos: None,
            windows: Some(WindowsGuardPolicyDetails {
                core_schema: GUARD_WINDOWS_PROTECTION_CORE_SCHEMA.to_string(),
                core_version: GUARD_WINDOWS_PROTECTION_CORE_VERSION,
                capability_model_version: GUARD_WINDOWS_CAPABILITY_MODEL_VERSION,
                profile,
                remote_attestation_eligible: profile.is_remote_attestation_eligible(),
                requirements,
                capabilities,
                requirements_satisfied: true,
            }),
        }
    }

    #[test]
    fn protection_profiles_validate_against_runtime_capabilities() {
        for profile in [
            WindowsProtectionProfile::Audit,
            WindowsProtectionProfile::Compat,
            WindowsProtectionProfile::Aggressive,
        ] {
            let report = sample_windows_policy(profile);
            validate_windows_guard_policy_report(&report, profile)
                .expect("Действительный отчёт о возможностях профиля");
        }
    }

    #[test]
    fn protection_core_rejects_capability_drift() {
        let mut report = sample_windows_policy(WindowsProtectionProfile::Aggressive);
        let details = report.windows.as_mut().expect("Сведения Windows");
        details.capabilities.image_load_policy.observed_flags = 0x3;
        details.capabilities.image_load_policy.satisfied = false;
        assert!(validate_windows_guard_policy_report(
            &report,
            WindowsProtectionProfile::Aggressive
        )
        .is_err());
    }

    #[test]
    fn protection_core_rejects_profile_substitution() {
        let report = sample_windows_policy(WindowsProtectionProfile::Compat);
        assert!(validate_windows_guard_policy_report(
            &report,
            WindowsProtectionProfile::Aggressive
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn process_hardening_is_enforced_for_current_test_process() {
        let report = ensure_windows_production_hardening().expect("Усиление защиты Windows в промышленной среде");
        assert_eq!(report.pid, std::process::id());
        assert!(report.enforced);
        assert!(report.heap_terminate_on_corruption);
        assert!(report.current_directory_removed_from_dll_search);
        assert!(report.restricted_default_dll_directories);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn runtime_process_is_suspended_assigned_and_resumed() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("cmd.exe");
        command
            .args(["/D", "/C", "exit", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        prepare_runtime_command(&mut command);
        let mut child = command.spawn().expect("Создание приостановленного дочернего процесса Windows");
        let guard = enforce_runtime_process(&mut child).expect("Применение политики процессов среды выполнения");
        let report = guard.report();
        assert!(report.enforced);
        assert!(report.created_suspended);
        assert!(report.assigned_to_job);
        assert!(report.kill_on_job_close);
        assert!(report.die_on_unhandled_exception);
        assert!(!report.breakaway_allowed);
        assert!(report.primary_thread_resumed);
        let status = child.wait().await.expect("Ожидание дочернего процесса с применённой политикой");
        assert!(status.success());
    }

}
