use serde::{Deserialize, Serialize};
use crate::{linux_policy::LinuxGuardPolicyDetails, macos_policy::MacOSGuardPolicyDetails};

pub const NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION: u32 = 1;
pub const NEVERGUARD_WINDOWS_HARDENING_VERSION: u32 = 1;
pub const NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA: &str =
    "neverguard/windows-runtime-process-policy/v1";

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

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::{
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
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
                TH32CS_SNAPTHREAD,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
                QueryInformationJobObject, SetInformationJobObject,
                JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            LibraryLoader::{
                SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            },
            Memory::{HeapSetInformation, HeapEnableTerminationOnCorruption},
            Threading::{
                GetProcessMitigationPolicy, OpenThread, ResumeThread,
                SetProcessMitigationPolicy, ProcessChildProcessPolicy, ProcessDynamicCodePolicy,
                ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
                ProcessStrictHandleCheckPolicy, CREATE_SUSPENDED, PROCESS_MITIGATION_POLICY,
                THREAD_SUSPEND_RESUME,
            },
        },
    };

    const DYNAMIC_CODE_REQUIRED: u32 = 0x0000_0001;
    const EXTENSION_POINT_REQUIRED: u32 = 0x0000_0001;
    const STRICT_HANDLE_REQUIRED: u32 = 0x0000_0003;
    const IMAGE_LOAD_REQUIRED: u32 = 0x0000_0007;
    const CHILD_PROCESS_REQUIRED: u32 = 0x0000_0001;
    const JOB_LIMITS_REQUIRED: u32 =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

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
    }

    pub fn ensure_guard_process_policy() -> Result<GuardProcessPolicyReport, String> {
        GUARD_POLICY
            .get_or_init(apply_guard_process_policy)
            .clone()
    }

    pub fn ensure_windows_production_hardening() -> Result<WindowsProductionHardeningReport, String> {
        PROCESS_HARDENING
            .get_or_init(apply_windows_production_hardening)
            .clone()
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
                "Windows heap terminate-on-corruption hardening failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let empty = [0u16];
        let dll_dir_ok = unsafe { SetDllDirectoryW(empty.as_ptr()) };
        if dll_dir_ok == 0 {
            return Err(format!(
                "Windows DLL search hardening failed to remove current directory: {}",
                std::io::Error::last_os_error()
            ));
        }

        let search_flags = LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
        let default_dirs_ok = unsafe { SetDefaultDllDirectories(search_flags) };
        if default_dirs_ok == 0 {
            return Err(format!(
                "Windows DLL search hardening failed to restrict default directories: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(WindowsProductionHardeningReport {
            hardening_version: NEVERGUARD_WINDOWS_HARDENING_VERSION,
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
            .ok_or_else(|| "NeverGuard PID unavailable for suspended lifetime boundary".to_string())?;
        let process_handle = child
            .raw_handle()
            .ok_or_else(|| "NeverGuard process handle unavailable for lifetime job".to_string())?
            as HANDLE;
        let job_handle = unsafe { CreateJobObjectW(null(), null()) };
        if job_handle.is_null() {
            return Err(format!(
                "NeverGuard lifetime Job Object creation failed: {}",
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
                "NeverGuard lifetime Job Object policy setup failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let assign_ok = unsafe { AssignProcessToJobObject(job.raw(), process_handle) };
        if assign_ok == 0 {
            return Err(format!(
                "NeverGuard process cannot be assigned to launcher lifetime Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut in_job = 0i32;
        let membership_ok = unsafe { IsProcessInJob(process_handle, job.raw(), &mut in_job) };
        if membership_ok == 0 || in_job == 0 {
            return Err(format!(
                "NeverGuard launcher lifetime Job Object verification failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        resume_primary_thread(pid)?;
        Ok(GuardLifetimeJob { _job: job })
    }

    fn apply_guard_process_policy() -> Result<GuardProcessPolicyReport, String> {
        set_policy(
            "DynamicCode",
            ProcessDynamicCodePolicy,
            DYNAMIC_CODE_REQUIRED,
        )?;
        set_policy(
            "ExtensionPointDisable",
            ProcessExtensionPointDisablePolicy,
            EXTENSION_POINT_REQUIRED,
        )?;
        set_policy(
            "StrictHandleCheck",
            ProcessStrictHandleCheckPolicy,
            STRICT_HANDLE_REQUIRED,
        )?;
        set_policy("ImageLoad", ProcessImageLoadPolicy, IMAGE_LOAD_REQUIRED)?;
        set_policy(
            "ChildProcess",
            ProcessChildProcessPolicy,
            CHILD_PROCESS_REQUIRED,
        )?;

        let dynamic_code = query_policy("DynamicCode", ProcessDynamicCodePolicy)?;
        let extension_points = query_policy(
            "ExtensionPointDisable",
            ProcessExtensionPointDisablePolicy,
        )?;
        let strict_handle = query_policy("StrictHandleCheck", ProcessStrictHandleCheckPolicy)?;
        let image_load = query_policy("ImageLoad", ProcessImageLoadPolicy)?;
        let child_process = query_policy("ChildProcess", ProcessChildProcessPolicy)?;

        require_bits("DynamicCode", dynamic_code, DYNAMIC_CODE_REQUIRED)?;
        require_bits(
            "ExtensionPointDisable",
            extension_points,
            EXTENSION_POINT_REQUIRED,
        )?;
        require_bits("StrictHandleCheck", strict_handle, STRICT_HANDLE_REQUIRED)?;
        require_bits("ImageLoad", image_load, IMAGE_LOAD_REQUIRED)?;
        require_bits("ChildProcess", child_process, CHILD_PROCESS_REQUIRED)?;

        Ok(GuardProcessPolicyReport {
            schema: NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
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
        })
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
                "NeverGuard failed to enforce Windows {name} process policy: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
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
                "NeverGuard failed to verify Windows {name} process policy: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(flags)
    }

    fn require_bits(name: &str, actual: u32, required: u32) -> Result<(), String> {
        if actual & required != required {
            return Err(format!(
                "NeverGuard Windows {name} process policy is not enforced: required=0x{required:08x}, actual=0x{actual:08x}"
            ));
        }
        Ok(())
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
            .ok_or_else(|| "Windows runtime PID unavailable before policy enforcement".to_string())?;
        let process_handle = child
            .raw_handle()
            .ok_or_else(|| "Windows runtime process handle unavailable before policy enforcement".to_string())?
            as HANDLE;

        let job_handle = unsafe { CreateJobObjectW(null(), null()) };
        if job_handle.is_null() {
            return Err(format!(
                "Windows runtime Job Object creation failed: {}",
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
                "Windows runtime Job Object policy setup failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let assign_ok = unsafe { AssignProcessToJobObject(job.raw(), process_handle) };
        if assign_ok == 0 {
            return Err(format!(
                "Windows runtime process cannot be assigned to NeverGuard Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut in_job = 0i32;
        let membership_ok = unsafe { IsProcessInJob(process_handle, job.raw(), &mut in_job) };
        if membership_ok == 0 || in_job == 0 {
            return Err(format!(
                "Windows runtime Job Object membership verification failed: {}",
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
                "Windows runtime Job Object policy verification failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let actual_limits = observed.BasicLimitInformation.LimitFlags;
        if actual_limits & JOB_LIMITS_REQUIRED != JOB_LIMITS_REQUIRED {
            return Err(format!(
                "Windows runtime Job Object limits are incomplete: required=0x{JOB_LIMITS_REQUIRED:08x}, actual=0x{actual_limits:08x}"
            ));
        }
        if actual_limits
            & (windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_BREAKAWAY_OK
                | windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            != 0
        {
            return Err("Windows runtime Job Object unexpectedly permits process breakaway".to_string());
        }

        resume_primary_thread(pid)?;

        let report = RuntimeProcessPolicyReport {
            schema: NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
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
                "Windows runtime thread snapshot failed for PID {pid}: {}",
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
                            "Windows runtime primary thread resume failed for PID {pid}: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if previous_suspend_count == 0 {
                        return Err(format!(
                            "Windows runtime process {pid} was not suspended during policy assignment"
                        ));
                    }
                    return Ok(());
                }
            }
            has_entry = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
        }
        Err(format!(
            "Windows runtime primary thread not found while process {pid} is suspended"
        ))
    }
}

#[cfg(windows)]
pub use windows_impl::{
    bind_guard_to_launcher_job, enforce_runtime_process, ensure_guard_process_policy,
    ensure_windows_production_hardening, prepare_guard_command, prepare_runtime_command,
    GuardLifetimeJob,
    RuntimeProcessPolicyGuard,
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
        unreachable!("Windows runtime process policy is only available on Windows")
    }
}

#[cfg(not(windows))]
pub fn ensure_guard_process_policy() -> Result<GuardProcessPolicyReport, String> {
    Err("NeverGuard 0.13.4 Windows process policy enforcement доступен только для Windows".to_string())
}

#[cfg(not(windows))]
pub fn ensure_windows_production_hardening() -> Result<WindowsProductionHardeningReport, String> {
    Err("NeverGuard 0.13.6 Windows production hardening доступен только для Windows".to_string())
}

#[cfg(not(windows))]
pub fn prepare_guard_command(_command: &mut tokio::process::Command) {}

#[cfg(not(windows))]
pub fn bind_guard_to_launcher_job(
    _child: &mut tokio::process::Child,
) -> Result<GuardLifetimeJob, String> {
    Err("NeverGuard 0.13.6 launcher lifetime Job Object доступен только для Windows".to_string())
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
        assert_eq!(NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION, 1);
        assert_eq!(
            NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA,
            "neverguard/windows-runtime-process-policy/v1"
        );
    }

    #[test]
    fn runtime_report_serializes_enforcement_state() {
        let report = RuntimeProcessPolicyReport {
            schema: NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA.to_string(),
            policy_version: NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
            pid: 42,
            enforced: true,
            created_suspended: true,
            assigned_to_job: true,
            kill_on_job_close: true,
            die_on_unhandled_exception: true,
            breakaway_allowed: false,
            primary_thread_resumed: true,
        };
        let json = serde_json::to_value(&report).expect("policy report serializes");
        assert_eq!(json["pid"], 42);
        assert_eq!(json["assignedToJob"], true);
        assert_eq!(json["breakawayAllowed"], false);
    }
    #[test]
    fn hardening_report_serializes_enforcement_state() {
        let report = WindowsProductionHardeningReport {
            hardening_version: NEVERGUARD_WINDOWS_HARDENING_VERSION,
            pid: 42,
            enforced: true,
            heap_terminate_on_corruption: true,
            current_directory_removed_from_dll_search: true,
            restricted_default_dll_directories: true,
        };
        let json = serde_json::to_value(&report).expect("hardening report serializes");
        assert_eq!(json["hardeningVersion"], NEVERGUARD_WINDOWS_HARDENING_VERSION);
        assert_eq!(json["enforced"], true);
        assert_eq!(json["restrictedDefaultDllDirectories"], true);
    }

    #[cfg(windows)]
    #[test]
    fn process_hardening_is_enforced_for_current_test_process() {
        let report = ensure_windows_production_hardening().expect("Windows production hardening");
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
        let mut child = command.spawn().expect("spawn suspended Windows child");
        let guard = enforce_runtime_process(&mut child).expect("enforce runtime process policy");
        let report = guard.report();
        assert!(report.enforced);
        assert!(report.created_suspended);
        assert!(report.assigned_to_job);
        assert!(report.kill_on_job_close);
        assert!(report.die_on_unhandled_exception);
        assert!(!report.breakaway_allowed);
        assert!(report.primary_thread_resumed);
        let status = child.wait().await.expect("wait for policy-bound child");
        assert!(status.success());
    }

}
