use neverruntime::{
    build_launch_plan, check_files, download_missing_files, ensure_managed_java, launch_with_timeout, load_manifest,
    resolve_compatibility, verify_manifest_signature, CompatibilityContext, Manifest,
};
use serde_json::json;
use std::{collections::HashMap, env, path::{Path, PathBuf}, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(value) => {
            match serde_json::to_string_pretty(&value) {
                Ok(text) => println!("{text}"),
                Err(err) => {
                    eprintln!("neverruntime: JSON output error: {err}");
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("neverruntime: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<serde_json::Value, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest = if args.len() > 1 { &args[1..] } else { &[] };
    match command {
        "verify" => command_verify(rest).await,
        "sync" => command_sync(rest).await,
        "launch" => command_launch(rest).await,
        "plan" => command_plan(rest).await,
        "compatibility" => command_compatibility(rest).await,
        "java" => command_java(rest).await,
        "help" | "--help" | "-h" => Ok(json!({
            "status": "ready",
            "version": env!("CARGO_PKG_VERSION"),
            "commands": ["verify", "sync", "launch", "plan", "compatibility", "java ensure"]
        })),
        other => Err(format!("неизвестная команда: {other}")),
    }
}

async fn command_verify(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest = read_manifest_required(args)?;
    let pinned = required_flag(args, "--pinned-public-key")?;
    let signature = verify_manifest_signature(&manifest, &pinned)?;
    let root = optional_flag(args, "--root");
    let files = if let Some(root) = root {
        check_files(&manifest, Path::new(&root)).await?
    } else {
        Vec::new()
    };
    let ready = files.is_empty() || files.iter().all(|file| file.status == "ok");
    Ok(json!({"status": if ready {"ready"} else {"invalid"}, "signature": signature, "files": files}))
}

async fn command_sync(args: &[String]) -> Result<serde_json::Value, String> {
    let url = required_flag(args, "--manifest-url")?;
    let pinned = required_flag(args, "--pinned-public-key")?;
    let root = PathBuf::from(required_flag(args, "--root")?);
    let manifest = load_manifest(&url, &pinned).await?;
    let download = download_missing_files(&manifest, &root, &pinned).await?;
    let files = check_files(&manifest, &root).await?;
    let ready = download.failed == 0 && files.iter().all(|file| file.status == "ok");
    if !ready {
        return Err(format!(
            "sync не завершён: failed={}, broken={}",
            download.failed,
            files.iter().filter(|file| file.status != "ok").count()
        ));
    }
    Ok(json!({"status":"ready","download":download,"files":files,"manifest":{"projectId":manifest.project_id,"profileId":manifest.profile_id,"version":manifest.version}}))
}

async fn command_launch(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest = read_manifest_required(args)?;
    let pinned = required_flag(args, "--pinned-public-key")?;
    let root = PathBuf::from(required_flag(args, "--root")?);
    let max_runtime_seconds = optional_flag(args, "--max-runtime-seconds")
        .map(|value| value.parse::<u64>().map_err(|_| "--max-runtime-seconds должен быть целым числом секунд".to_string()))
        .transpose()?;
    let result = launch_with_timeout(
        &manifest,
        &root,
        optional_flag(args, "--java"),
        optional_flag(args, "--username"),
        &pinned,
        max_runtime_seconds,
    )
    .await?;
    serde_json::to_value(result).map_err(|err| err.to_string())
}

async fn command_plan(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest = read_manifest_required(args)?;
    let pinned = required_flag(args, "--pinned-public-key")?;
    let root = PathBuf::from(required_flag(args, "--root")?);
    let plan = build_launch_plan(
        &manifest,
        &root,
        optional_flag(args, "--java"),
        optional_flag(args, "--username"),
        &pinned,
    )
    .await?;
    serde_json::to_value(plan).map_err(|err| err.to_string())
}

async fn command_compatibility(args: &[String]) -> Result<serde_json::Value, String> {
    let root = PathBuf::from(required_flag(args, "--root")?);
    let version = required_flag(args, "--version")?;
    let game = optional_flag(args, "--game-directory").unwrap_or_else(|| root.to_string_lossy().to_string());
    let assets = optional_flag(args, "--assets-directory").unwrap_or_else(|| root.join("assets").to_string_lossy().to_string());
    let natives = optional_flag(args, "--natives-directory").unwrap_or_else(|| root.join("natives").to_string_lossy().to_string());
    let context = CompatibilityContext {
        username: optional_flag(args, "--username").unwrap_or_else(|| "Player".to_string()),
        uuid: optional_flag(args, "--uuid").unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string()),
        access_token: optional_flag(args, "--access-token").unwrap_or_else(|| "offline".to_string()),
        user_type: optional_flag(args, "--user-type").unwrap_or_else(|| "legacy".to_string()),
        launcher_name: "NeverLauncher".to_string(),
        launcher_version: env!("CARGO_PKG_VERSION").to_string(),
        game_directory: game,
        assets_directory: assets,
        natives_directory: natives,
        features: HashMap::new(),
    };
    let metadata = optional_flag(args, "--metadata");
    let result = resolve_compatibility(&root, &version, metadata.as_deref(), &context).await?;
    serde_json::to_value(result).map_err(|err| err.to_string())
}

async fn command_java(args: &[String]) -> Result<serde_json::Value, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("");
    if subcommand != "ensure" {
        return Err("использование: neverruntime java ensure --major <8|17|21|25> [--distribution temurin] [--runtime-root PATH]".to_string());
    }
    let rest = &args[1..];
    let major = required_flag(rest, "--major")?
        .parse::<u32>()
        .map_err(|_| "--major должен быть числом".to_string())?;
    let distribution = optional_flag(rest, "--distribution").unwrap_or_else(|| "temurin".to_string());
    let runtime_root = optional_flag(rest, "--runtime-root").map(PathBuf::from);
    let result = ensure_managed_java(major, &distribution, runtime_root.as_deref()).await?;
    serde_json::to_value(result).map_err(|err| err.to_string())
}

fn read_manifest_required(args: &[String]) -> Result<Manifest, String> {
    let path = PathBuf::from(required_flag(args, "--manifest")?);
    let bytes = std::fs::read(&path).map_err(|err| format!("не удалось прочитать manifest {}: {err}", path.display()))?;
    serde_json::from_slice::<Manifest>(&bytes).map_err(|err| format!("manifest {} повреждён: {err}", path.display()))
}

fn required_flag(args: &[String], name: &str) -> Result<String, String> {
    optional_flag(args, name).ok_or_else(|| format!("обязательный аргумент {name} не указан"))
}

fn optional_flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1].clone())
}
