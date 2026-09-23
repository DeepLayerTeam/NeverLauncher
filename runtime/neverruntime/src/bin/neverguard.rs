#[cfg(windows)]
use neverruntime::{ensure_guard_process_policy, ensure_windows_production_hardening, run_windows_guard_server};
#[cfg(target_os = "linux")]
use neverruntime::{linux_policy::ensure_linux_production_hardening, run_linux_guard_server};
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    #[cfg(windows)]
    if let Err(err) = ensure_windows_production_hardening().and_then(|_| ensure_guard_process_policy().map(|_| ())) {
        eprintln!("neverguard: {err}"); return ExitCode::FAILURE;
    }
    #[cfg(target_os = "linux")]
    if let Err(err) = ensure_linux_production_hardening() { eprintln!("neverguard: {err}"); return ExitCode::FAILURE; }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => { eprintln!("neverguard: failed to initialize async runtime: {err}"); return ExitCode::FAILURE; }
    };
    match runtime.block_on(run()) { Ok(()) => ExitCode::SUCCESS, Err(err) => { eprintln!("neverguard: {err}"); ExitCode::FAILURE } }
}

async fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        #[cfg(windows)] println!("NeverGuard {}\nUsage: neverguard --pipe <local named pipe> --parent-pid <pid>\nBootstrap secret: exactly 32 raw bytes on stdin.", env!("CARGO_PKG_VERSION"));
        #[cfg(target_os = "linux")] println!("NeverGuard {}\nUsage: neverguard --socket <private unix socket> --parent-pid <pid>\nBootstrap secret: exactly 32 raw bytes on stdin.", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let parent_pid = required_flag(&args, "--parent-pid")?.parse::<u32>().map_err(|_| "--parent-pid must be a positive u32".to_string())?;
    #[cfg(windows)] { return run_windows_guard_server(required_flag(&args, "--pipe")?, parent_pid).await; }
    #[cfg(target_os = "linux")] { return run_linux_guard_server(std::path::PathBuf::from(required_flag(&args, "--socket")?), parent_pid).await; }
    #[cfg(all(not(windows), not(target_os = "linux")))] { let _=parent_pid; Err("NeverGuard production implementation is available on Windows and Linux".into()) }
}
fn required_flag(args:&[String],name:&str)->Result<String,String>{args.windows(2).find(|p|p[0]==name).map(|p|p[1].clone()).ok_or_else(||format!("required argument {name} is missing"))}
