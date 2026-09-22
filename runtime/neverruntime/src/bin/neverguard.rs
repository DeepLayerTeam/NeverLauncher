#[cfg(windows)]
use neverruntime::{ensure_guard_process_policy, run_windows_guard_server};
#[cfg(windows)]
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    if let Err(err) = ensure_guard_process_policy() {
        eprintln!("neverguard: {err}");
        return ExitCode::FAILURE;
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

    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("neverguard: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    #[cfg(not(windows))]
    {
        return Err("NeverGuard is Windows-only; Linux/macOS implementations are planned later".to_string());
    }

    #[cfg(windows)]
    {
        let args = env::args().skip(1).collect::<Vec<_>>();
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            println!(
                "NeverGuard {}\nUsage: neverguard --pipe <local named pipe> --parent-pid <pid>\nBootstrap secret: exactly 32 raw bytes on stdin.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        let endpoint = required_flag(&args, "--pipe")?;
        let parent_pid = required_flag(&args, "--parent-pid")?
            .parse::<u32>()
            .map_err(|_| "--parent-pid должен быть положительным u32".to_string())?;
        run_windows_guard_server(endpoint, parent_pid).await
    }
}

#[cfg(windows)]
fn required_flag(args: &[String], name: &str) -> Result<String, String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("обязательный аргумент {name} не указан"))
}
