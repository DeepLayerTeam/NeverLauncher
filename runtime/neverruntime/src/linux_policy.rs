use serde::{Deserialize, Serialize};

pub const NEVERGUARD_LINUX_PROCESS_POLICY_VERSION: u32 = 1;
pub const NEVERGUARD_LINUX_HARDENING_VERSION: u32 = 1;
pub const NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA: &str = "neverguard/linux-runtime-process-policy/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxGuardPolicyDetails {
    pub no_new_privs: bool,
    pub dumpable_disabled: bool,
    pub core_dumps_disabled: bool,
    pub ptrace_restricted: bool,
    pub parent_death_signal: bool,
    pub private_umask: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxProductionHardeningReport {
    pub hardening_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub no_new_privs: bool,
    pub dumpable_disabled: bool,
    pub core_dumps_disabled: bool,
    pub ptrace_restricted: bool,
    pub private_umask: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxRuntimeProcessPolicyReport {
    pub schema: String,
    pub policy_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub no_new_privs: bool,
    pub parent_death_signal: bool,
    pub own_process_group: bool,
    pub core_dumps_disabled: bool,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::{io, os::unix::process::CommandExt, sync::OnceLock};
    use tokio::process::{Child, Command};

    const PR_SET_PTRACER: libc::c_int = 0x59616d61;
    static HARDENING: OnceLock<Result<LinuxProductionHardeningReport, String>> = OnceLock::new();

    fn os_err(label: &str) -> String { format!("{label}: {}", io::Error::last_os_error()) }

    unsafe fn set_no_new_privs() -> Result<(), String> {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 { return Err(os_err("Linux PR_SET_NO_NEW_PRIVS failed")); }
        Ok(())
    }
    unsafe fn disable_dumpable() -> Result<(), String> {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 { return Err(os_err("Linux PR_SET_DUMPABLE failed")); }
        Ok(())
    }
    unsafe fn disable_core_dumps() -> Result<(), String> {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 { return Err(os_err("Linux setrlimit(RLIMIT_CORE) failed")); }
        Ok(())
    }
    unsafe fn restrict_ptrace() -> Result<(), String> {
        if libc::prctl(PR_SET_PTRACER, 0, 0, 0, 0) != 0 {
            return Err(os_err("Linux PR_SET_PTRACER failed"));
        }
        Ok(())
    }

    pub fn ensure_linux_production_hardening() -> Result<LinuxProductionHardeningReport, String> {
        HARDENING.get_or_init(|| {
            unsafe {
                set_no_new_privs()?;
                disable_dumpable()?;
                disable_core_dumps()?;
                restrict_ptrace()?;
                libc::umask(0o077);
            }
            let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
            let dumpable_disabled = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
            if !no_new_privs || !dumpable_disabled { return Err("Linux production hardening verification failed".into()); }
            Ok(LinuxProductionHardeningReport {
                hardening_version: NEVERGUARD_LINUX_HARDENING_VERSION,
                pid: std::process::id(), enforced: true, no_new_privs, dumpable_disabled,
                core_dumps_disabled: true, ptrace_restricted: true, private_umask: true,
            })
        }).clone()
    }

    pub fn guard_policy_report() -> Result<LinuxGuardPolicyDetails, String> {
        let hardening = ensure_linux_production_hardening()?;
        let mut sig = 0;
        if unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut sig as *mut libc::c_int) } != 0 {
            return Err(os_err("Linux PR_GET_PDEATHSIG failed"));
        }
        Ok(LinuxGuardPolicyDetails {
            no_new_privs: hardening.no_new_privs,
            dumpable_disabled: hardening.dumpable_disabled,
            core_dumps_disabled: hardening.core_dumps_disabled,
            ptrace_restricted: hardening.ptrace_restricted,
            parent_death_signal: sig == libc::SIGKILL,
            private_umask: hardening.private_umask,
        })
    }

    fn configure_child() -> io::Result<()> {
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 { return Err(io::Error::last_os_error()); }
            if libc::getppid() == 1 { return Err(io::Error::other("launcher parent already exited")); }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 { return Err(io::Error::last_os_error()); }
            let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 { return Err(io::Error::last_os_error()); }
            if libc::setpgid(0, 0) != 0 { return Err(io::Error::last_os_error()); }
        }
        Ok(())
    }

    pub fn prepare_guard_command(command: &mut Command) {
        unsafe { command.as_std_mut().pre_exec(configure_child); }
    }
    pub fn prepare_runtime_command(command: &mut Command) {
        unsafe { command.as_std_mut().pre_exec(configure_child); }
    }


    pub fn terminate_runtime_process_group(pid: u32) -> Result<(), String> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err("Linux runtime process group PID is invalid".to_string());
        }
        let rc = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(format!("Linux kill process group {pid} failed: {err}"))
    }

    pub fn runtime_policy(child: &mut Child) -> Result<LinuxRuntimeProcessPolicyReport, String> {
        let pid = child.id().ok_or_else(|| "Linux runtime PID unavailable".to_string())?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| format!("read /proc/{pid}/status failed: {e}"))?;
        let no_new_privs = status.lines().find_map(|l| l.strip_prefix("NoNewPrivs:\t")).map(str::trim) == Some("1");
        let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        if pgid < 0 { return Err(os_err("Linux getpgid failed")); }
        let own_process_group = pgid as u32 == pid;
        if !no_new_privs || !own_process_group { return Err("Linux runtime process policy verification failed".into()); }
        Ok(LinuxRuntimeProcessPolicyReport {
            schema: "neverruntime/linux-process-policy/v1".into(), policy_version: 1, pid,
            enforced: true, no_new_privs, parent_death_signal: true, own_process_group,
            core_dumps_disabled: true,
        })
    }
}

#[cfg(target_os = "linux")]
pub use imp::{ensure_linux_production_hardening, guard_policy_report, prepare_guard_command, prepare_runtime_command, runtime_policy, terminate_runtime_process_group};

#[cfg(not(target_os = "linux"))]
pub fn ensure_linux_production_hardening() -> Result<LinuxProductionHardeningReport, String> { Err("Linux hardening is only available on Linux".into()) }
#[cfg(not(target_os = "linux"))]
pub fn guard_policy_report() -> Result<LinuxGuardPolicyDetails, String> { Err("Linux policy is only available on Linux".into()) }
#[cfg(not(target_os = "linux"))]
pub fn prepare_guard_command(_command: &mut tokio::process::Command) {}
#[cfg(not(target_os = "linux"))]
pub fn prepare_runtime_command(_command: &mut tokio::process::Command) {}
#[cfg(not(target_os = "linux"))]
pub fn runtime_policy(_child: &mut tokio::process::Child) -> Result<LinuxRuntimeProcessPolicyReport, String> { Err("Linux runtime policy is only available on Linux".into()) }
#[cfg(not(target_os = "linux"))]
pub fn terminate_runtime_process_group(_pid: u32) -> Result<(), String> { Err("Linux runtime process groups are only available on Linux".into()) }
