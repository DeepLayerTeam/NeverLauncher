#[cfg(windows)]
use neverruntime::{
    ensure_windows_protection_core_with_profile, protection_profile_from_environment,
    run_windows_guard_server, WindowsProtectionProfile,
};
#[cfg(target_os = "linux")]
use neverruntime::{linux_policy::ensure_linux_production_hardening, run_linux_guard_server};
#[cfg(target_os = "macos")]
use neverruntime::{macos_policy::ensure_macos_production_hardening, run_macos_guard_server};
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let show_help = args.iter().any(|arg| arg == "--help" || arg == "-h");

    #[cfg(windows)]
    if !show_help {
        let profile = match windows_protection_profile(&args) {
            Ok(profile) => profile,
            Err(err) => {
                eprintln!("neverguard: {err}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(err) = ensure_windows_protection_core_with_profile(profile) {
            eprintln!("neverguard: {err}");
            return ExitCode::FAILURE;
        }
    }
    #[cfg(target_os = "linux")]
    if !show_help {
        if let Err(err) = ensure_linux_production_hardening() {
            eprintln!("neverguard: {err}");
            return ExitCode::FAILURE;
        }
    }
    #[cfg(target_os = "macos")]
    if !show_help {
        if let Err(err) = ensure_macos_production_hardening() {
            eprintln!("neverguard: {err}");
            return ExitCode::FAILURE;
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("neverguard: failed to initialize async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("neverguard: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        #[cfg(windows)]
        println!(
            "NeverGuard {}\nUsage: neverguard --pipe <local named pipe> --parent-pid <pid> [--protection-profile audit|compat|aggressive]\nBootstrap secret: exactly 32 raw bytes on stdin.",
            env!("CARGO_PKG_VERSION")
        );
        #[cfg(target_os = "linux")]
        println!(
            "NeverGuard {}\nUsage: neverguard --socket <private unix socket> --parent-pid <pid>\nBootstrap secret: exactly 32 raw bytes on stdin.",
            env!("CARGO_PKG_VERSION")
        );
        #[cfg(target_os = "macos")]
        println!(
            "NeverGuard {}\nUsage: neverguard --socket <private unix socket> --parent-pid <pid>\nBootstrap secret: exactly 32 raw bytes on stdin.",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    let parent_pid = required_flag(&args, "--parent-pid")?
        .parse::<u32>()
        .map_err(|_| "--parent-pid must be a positive u32".to_string())?;
    if parent_pid == 0 {
        return Err("--parent-pid must be a positive u32".to_string());
    }
    #[cfg(windows)]
    {
        run_windows_guard_server(required_flag(&args, "--pipe")?, parent_pid).await
    }
    #[cfg(target_os = "linux")]
    {
        run_linux_guard_server(
            std::path::PathBuf::from(required_flag(&args, "--socket")?),
            parent_pid,
        )
        .await
    }
    #[cfg(target_os = "macos")]
    {
        run_macos_guard_server(
            std::path::PathBuf::from(required_flag(&args, "--socket")?),
            parent_pid,
        )
        .await
    }
    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    {
        let _ = parent_pid;
        Err("NeverGuard production implementation is available on Windows, Linux and macOS".into())
    }
}

#[cfg(windows)]
fn windows_protection_profile(args: &[String]) -> Result<WindowsProtectionProfile, String> {
    match optional_flag(args, "--protection-profile")? {
        Some(value) => value.parse(),
        None => protection_profile_from_environment(),
    }
}

fn required_flag(args: &[String], name: &str) -> Result<String, String> {
    optional_flag(args, name)?.ok_or_else(|| format!("required argument {name} is missing"))
}

fn optional_flag(args: &[String], name: &str) -> Result<Option<String>, String> {
    let mut found = None;
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == name {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("argument {name} requires a value"))?;
            if found.replace(value.clone()).is_some() {
                return Err(format!("argument {name} must be specified only once"));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(found)
}
