use serde::{Deserialize, Serialize};
use std::path::Path;

pub const NEVERGUARD_MACOS_PROCESS_POLICY_VERSION: u32 = 1;
pub const NEVERGUARD_MACOS_HARDENING_VERSION: u32 = 1;
pub const NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA: &str = "neverguard/macos-runtime-process-policy/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacOSGuardPolicyDetails {
    pub core_dumps_disabled: bool,
    pub debugger_attach_denied: bool,
    pub code_signature_valid: bool,
    pub hardened_runtime: bool,
    pub library_validation: bool,
    pub dyld_environment_sanitized: bool,
    pub parent_exit_watch: bool,
    pub private_umask: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacOSProductionHardeningReport {
    pub hardening_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub core_dumps_disabled: bool,
    pub debugger_attach_denied: bool,
    pub code_signature_valid: bool,
    pub hardened_runtime: bool,
    pub library_validation: bool,
    pub dyld_environment_sanitized: bool,
    pub private_umask: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacOSRuntimeProcessPolicyReport {
    pub schema: String,
    pub policy_version: u32,
    pub pid: u32,
    pub enforced: bool,
    pub own_process_group: bool,
    pub core_dumps_disabled: bool,
    pub dyld_environment_sanitized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOSCodeSignatureState {
    pub valid: bool,
    pub hardened_runtime: bool,
    pub library_validation: bool,
    pub team_identifier: Option<String>,
    pub identifier: Option<String>,
    pub detail: String,
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::{
        io,
        os::unix::process::CommandExt,
        process::Command as StdCommand,
        sync::OnceLock,
    };
    use tokio::process::{Child, Command};

    const PT_DENY_ATTACH: libc::c_int = 31;
    static HARDENING: OnceLock<Result<MacOSProductionHardeningReport, String>> = OnceLock::new();

    fn os_err(label: &str) -> String {
        format!("{label}: {}", io::Error::last_os_error())
    }

    fn entitlement_true(text: &str, key: &str) -> bool {
        let needle = format!("<key>{key}</key>");
        let Some(index) = text.find(&needle) else { return false; };
        let tail = &text[index + needle.len()..];
        tail.find("<true/>").is_some_and(|true_index| {
            tail.find("<key>").is_none_or(|next_key| true_index < next_key)
        })
    }

    fn field(text: &str, prefix: &str) -> Option<String> {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(prefix))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    pub fn verify_macos_code_signature(path: &Path) -> Result<MacOSCodeSignatureState, String> {
        let verify = StdCommand::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "--verbose=2"])
            .arg(path)
            .output()
            .map_err(|err| format!("failed to execute codesign verify for {}: {err}", path.display()))?;
        if !verify.status.success() {
            return Err(format!(
                "macOS code signature verification failed for {}: {}",
                path.display(),
                String::from_utf8_lossy(&verify.stderr).trim()
            ));
        }

        let display = StdCommand::new("/usr/bin/codesign")
            .args(["-d", "--verbose=4", "--entitlements", ":-"])
            .arg(path)
            .output()
            .map_err(|err| format!("failed to inspect code signature for {}: {err}", path.display()))?;
        if !display.status.success() {
            return Err(format!(
                "macOS code signature inspection failed for {}: {}",
                path.display(),
                String::from_utf8_lossy(&display.stderr).trim()
            ));
        }
        let mut details = String::from_utf8_lossy(&display.stderr).into_owned();
        details.push_str(&String::from_utf8_lossy(&display.stdout));
        let flags_line = details.lines().find(|line| line.trim_start().starts_with("CodeDirectory") || line.contains("flags=")).unwrap_or("");
        let hardened_runtime = flags_line.contains("runtime") || details.contains("flags=0x10000(runtime)");
        let library_validation = !entitlement_true(&details, "com.apple.security.cs.disable-library-validation")
            && !entitlement_true(&details, "com.apple.security.get-task-allow");
        Ok(MacOSCodeSignatureState {
            valid: true,
            hardened_runtime,
            library_validation,
            team_identifier: field(&details, "TeamIdentifier="),
            identifier: field(&details, "Identifier="),
            detail: details,
        })
    }

    fn scrub_dyld_environment() {
        let keys = std::env::vars_os()
            .filter_map(|(key, _)| {
                let key_string = key.to_string_lossy();
                (key_string.starts_with("DYLD_") || key_string.starts_with("__XPC_DYLD_")).then_some(key)
            })
            .collect::<Vec<_>>();
        for key in keys {
            std::env::remove_var(key);
        }
    }

    fn command_scrub_dyld(command: &mut Command) {
        const KEYS: &[&str] = &[
            "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_IMAGE_SUFFIX",
            "DYLD_ROOT_PATH", "DYLD_SHARED_REGION", "DYLD_PRINT_TO_FILE",
            "__XPC_DYLD_FRAMEWORK_PATH", "__XPC_DYLD_LIBRARY_PATH", "__XPC_DYLD_INSERT_LIBRARIES",
        ];
        for key in KEYS { command.env_remove(key); }
    }

    unsafe fn disable_core_dumps() -> Result<(), String> {
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err(os_err("macOS setrlimit(RLIMIT_CORE) failed"));
        }
        Ok(())
    }

    unsafe fn deny_debugger_attach() -> Result<(), String> {
        if libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) != 0 {
            return Err(os_err("macOS PT_DENY_ATTACH failed"));
        }
        Ok(())
    }

    pub fn ensure_macos_production_hardening() -> Result<MacOSProductionHardeningReport, String> {
        HARDENING.get_or_init(|| {
            scrub_dyld_environment();
            unsafe {
                disable_core_dumps()?;
                deny_debugger_attach()?;
                libc::umask(0o077);
            }
            let executable = std::env::current_exe().map_err(|err| format!("resolve current executable failed: {err}"))?;
            let signature = verify_macos_code_signature(&executable)?;
            if !signature.valid || !signature.hardened_runtime || !signature.library_validation {
                return Err("macOS production hardening requires a valid Hardened Runtime signature with library validation".to_string());
            }
            Ok(MacOSProductionHardeningReport {
                hardening_version: NEVERGUARD_MACOS_HARDENING_VERSION,
                pid: std::process::id(),
                enforced: true,
                core_dumps_disabled: true,
                debugger_attach_denied: true,
                code_signature_valid: signature.valid,
                hardened_runtime: signature.hardened_runtime,
                library_validation: signature.library_validation,
                dyld_environment_sanitized: true,
                private_umask: true,
            })
        }).clone()
    }

    pub fn guard_policy_report(parent_exit_watch: bool) -> Result<MacOSGuardPolicyDetails, String> {
        let hardening = ensure_macos_production_hardening()?;
        Ok(MacOSGuardPolicyDetails {
            core_dumps_disabled: hardening.core_dumps_disabled,
            debugger_attach_denied: hardening.debugger_attach_denied,
            code_signature_valid: hardening.code_signature_valid,
            hardened_runtime: hardening.hardened_runtime,
            library_validation: hardening.library_validation,
            dyld_environment_sanitized: hardening.dyld_environment_sanitized,
            parent_exit_watch,
            private_umask: hardening.private_umask,
        })
    }

    pub fn install_parent_exit_watch(parent_pid: u32) -> Result<(), String> {
        if parent_pid == 0 || parent_pid > i32::MAX as u32 {
            return Err("macOS parent PID is invalid".to_string());
        }
        let current_parent = unsafe { libc::getppid() };
        if current_parent != parent_pid as libc::pid_t {
            return Err(format!("macOS parent PID mismatch: expected {parent_pid}, observed {current_parent}"));
        }
        let kq = unsafe { libc::kqueue() };
        if kq < 0 { return Err(os_err("macOS kqueue failed")); }
        let mut change: libc::kevent = unsafe { std::mem::zeroed() };
        change.ident = parent_pid as libc::uintptr_t;
        change.filter = libc::EVFILT_PROC;
        change.flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR;
        change.fflags = libc::NOTE_EXIT;
        let rc = unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if rc < 0 {
            let err = os_err("macOS parent kqueue registration failed");
            unsafe { libc::close(kq); }
            return Err(err);
        }
        std::thread::Builder::new().name("neverguard-parent-watch".into()).spawn(move || {
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            loop {
                let rc = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, std::ptr::null()) };
                if rc > 0 && event.filter == libc::EVFILT_PROC && (event.fflags & libc::NOTE_EXIT) != 0 {
                    unsafe { libc::close(kq); libc::_exit(70); }
                }
                if rc < 0 {
                    unsafe { libc::close(kq); libc::_exit(71); }
                }
            }
        }).map_err(|err| {
            unsafe { libc::close(kq); }
            format!("macOS parent watcher thread failed: {err}")
        })?;
        Ok(())
    }

    fn configure_child() -> io::Result<()> {
        unsafe {
            let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 { return Err(io::Error::last_os_error()); }
            if libc::setpgid(0, 0) != 0 { return Err(io::Error::last_os_error()); }
        }
        Ok(())
    }

    pub fn prepare_guard_command(command: &mut Command) {
        command_scrub_dyld(command);
        unsafe { command.as_std_mut().pre_exec(configure_child); }
    }

    pub fn prepare_runtime_command(command: &mut Command) {
        command_scrub_dyld(command);
        unsafe { command.as_std_mut().pre_exec(configure_child); }
    }

    pub fn runtime_policy(child: &mut Child) -> Result<MacOSRuntimeProcessPolicyReport, String> {
        let pid = child.id().ok_or_else(|| "macOS runtime PID unavailable".to_string())?;
        let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        if pgid < 0 { return Err(os_err("macOS getpgid failed")); }
        let own_process_group = pgid as u32 == pid;
        if !own_process_group { return Err("macOS runtime process group policy verification failed".to_string()); }
        Ok(MacOSRuntimeProcessPolicyReport {
            schema: "neverruntime/macos-process-policy/v1".to_string(),
            policy_version: 1,
            pid,
            enforced: true,
            own_process_group,
            core_dumps_disabled: true,
            dyld_environment_sanitized: true,
        })
    }

    pub fn terminate_runtime_process_group(pid: u32) -> Result<(), String> {
        if pid == 0 || pid > i32::MAX as u32 { return Err("macOS runtime process group PID is invalid".to_string()); }
        let rc = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        if rc == 0 { return Ok(()); }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) { return Ok(()); }
        Err(format!("macOS kill process group {pid} failed: {err}"))
    }
}

#[cfg(target_os = "macos")]
pub use imp::{
    ensure_macos_production_hardening, guard_policy_report, install_parent_exit_watch,
    prepare_guard_command, prepare_runtime_command, runtime_policy, terminate_runtime_process_group,
    verify_macos_code_signature,
};

#[cfg(not(target_os = "macos"))]
pub fn ensure_macos_production_hardening() -> Result<MacOSProductionHardeningReport, String> { Err("macOS hardening is only available on macOS".into()) }
#[cfg(not(target_os = "macos"))]
pub fn guard_policy_report(_parent_exit_watch: bool) -> Result<MacOSGuardPolicyDetails, String> { Err("macOS policy is only available on macOS".into()) }
#[cfg(not(target_os = "macos"))]
pub fn install_parent_exit_watch(_parent_pid: u32) -> Result<(), String> { Err("macOS parent watcher is only available on macOS".into()) }
#[cfg(not(target_os = "macos"))]
pub fn prepare_guard_command(_command: &mut tokio::process::Command) {}
#[cfg(not(target_os = "macos"))]
pub fn prepare_runtime_command(_command: &mut tokio::process::Command) {}
#[cfg(not(target_os = "macos"))]
pub fn runtime_policy(_child: &mut tokio::process::Child) -> Result<MacOSRuntimeProcessPolicyReport, String> { Err("macOS runtime policy is only available on macOS".into()) }
#[cfg(not(target_os = "macos"))]
pub fn terminate_runtime_process_group(_pid: u32) -> Result<(), String> { Err("macOS runtime process groups are only available on macOS".into()) }
#[cfg(not(target_os = "macos"))]
pub fn verify_macos_code_signature(_path: &Path) -> Result<MacOSCodeSignatureState, String> { Err("macOS code signature verification is only available on macOS".into()) }
