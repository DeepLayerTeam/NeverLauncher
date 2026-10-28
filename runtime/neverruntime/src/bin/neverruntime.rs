use neverruntime::{
    build_launch_plan, certify_vanilla_compatibility, check_files, check_files_with_preset, download_missing_files_with_preset, ensure_managed_java, ensure_managed_java_from_distribution, launch_with_timeout, launch_with_timeout_matching, launch_with_timeout_matching_authenticated, load_manifest,
    resolve_compatibility, verify_manifest_signature, CompatibilityContext, Manifest, MinecraftLaunchCredentials,
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
        "sync-local" => command_sync_local(rest).await,
        "adopt-staged" => command_adopt_staged(rest).await,
        "rollback-release" => command_rollback_release(rest).await,
        "recover-release" => command_recover_release(rest).await,
        "launch" => command_launch(rest).await,
        "plan" => command_plan(rest).await,
        "compatibility" => command_compatibility(rest).await,
        "certify-vanilla" => command_certify_vanilla(rest).await,
        "java" => command_java(rest).await,
        "help" | "--help" | "-h" => Ok(json!({
            "status": "ready",
            "version": env!("CARGO_PKG_VERSION"),
            "commands": ["verify", "sync", "sync-local", "adopt-staged", "rollback-release", "recover-release", "launch", "plan", "compatibility", "certify-vanilla", "java ensure"]
        })),
        other => Err(format!("неизвестная команда: {other}")),
    }
}

async fn command_verify(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest = read_manifest_required(args)?;
    let pinned = required_flag(args, "--pinned-public-key")?;
    let signature = verify_manifest_signature(&manifest, &pinned)?;
    let root = optional_flag(args, "--root");
    let selection = optional_flag(args, "--preset");
    // Explicit selection is resolved by the same native graph used for installation;
    // it must never be interpreted as a modified or unsigned manifest.
    let files = if let Some(root) = root {
        if selection.is_some() {check_files_with_preset(&manifest, Path::new(&root), selection.as_deref()).await?}
        else {check_files(&manifest, Path::new(&root)).await?}
    } else {
        if selection.is_some() {return Err("--preset requires --root for file verification".into());}
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
    let selection = optional_flag(args, "--preset");
    let download = download_missing_files_with_preset(&manifest, &root, &pinned, None, selection.clone()).await?;
    let files = check_files_with_preset(&manifest, &root, selection.as_deref()).await?;
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

/// Bootstrap offline/verified-manifest path: never fetch an unauthenticated
/// second manifest after Prestarter verified and cached this signed release.
/// The same transactional download scheduler, cache, recovery and SHA-256
/// checks used by Desktop/Repair run here; only manifest transport differs.
async fn command_sync_local(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest = read_manifest_required(args)?;
    let key = required_flag(args, "--pinned-public-key")?;
    let root = PathBuf::from(required_flag(args, "--root")?);
    verify_manifest_signature(&manifest, &key)?;
    let selection = optional_flag(args, "--preset");
    let downloaded = download_missing_files_with_preset(&manifest, &root, &key, None, selection.clone()).await?;
    let files = check_files_with_preset(&manifest, &root, selection.as_deref()).await?;
    let ready = downloaded.failed == 0 && files.iter().all(|file| file.status == "ok" || file.status == "optional-missing");
    if !ready {
        return Err(format!("sync-local: download failed={}, invalid={}", downloaded.failed,
            files.iter().filter(|f| f.status != "ok" && f.status != "optional-missing").count()));
    }
    Ok(json!({"status":"ready", "download":downloaded, "manifest":{
        "projectId": manifest.project_id, "profileId": manifest.profile_id, "version": manifest.version}}))
}

async fn command_adopt_staged(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest=read_manifest_required(args)?;
    let pinned=required_flag(args,"--pinned-public-key")?;
    let source=PathBuf::from(required_flag(args,"--source")?);
    let root=PathBuf::from(required_flag(args,"--root")?);
    let preset=optional_flag(args,"--preset");
    let (imported,digest)=neverruntime::transactional_release::adopt_verified_staged(
        &manifest,&source,&root,&pinned,preset).await?;
    Ok(json!({"status":"ready","importedFiles":imported,"networkDownloads":0,
             "planSha256":digest}))
}

async fn command_rollback_release(args: &[String]) -> Result<serde_json::Value, String> {
    let root = PathBuf::from(required_flag(args, "--root")?);
    let key = required_flag(args, "--pinned-public-key")?;
    neverruntime::transactional_release::rollback(&root, &key).await?;
    Ok(json!({"status":"rolled-back"}))
}
async fn command_recover_release(args: &[String]) -> Result<serde_json::Value, String> {
    let root = PathBuf::from(required_flag(args, "--root")?);
    let key = required_flag(args, "--pinned-public-key")?;
    neverruntime::transactional_release::recover(&root, &key).await?;
    Ok(json!({"status":"recovered"}))
}

async fn command_launch(args: &[String]) -> Result<serde_json::Value, String> {
    let manifest = read_manifest_required(args)?;
    let pinned = required_flag(args, "--pinned-public-key")?;
    let root = PathBuf::from(required_flag(args, "--root")?);
    let max_runtime_seconds = optional_flag(args, "--max-runtime-seconds")
        .map(|value| value.parse::<u64>().map_err(|_| "--max-runtime-seconds должен быть целым числом секунд".to_string()))
        .transpose()?;
    let server_port = optional_flag(args, "--matching-server-port")
        .map(|value| value.parse::<u16>().map_err(|_| "invalid matching server port".to_string()))
        .transpose()?;
    // Runtime validation must execute exactly the installed signed preset,
    // not whichever selection a previous launch happened to leave active.
    if let Some(preset) = optional_flag(args, "--preset") {
        neverruntime::transactional_release::ensure_active_preset(
            &manifest, &root, &pinned, Some(&preset)).await?;
    }
    // Credentials arrive only through a rootless-container read-only 0600
    // secret file; command line arguments never carry the token.
    let creds = if let Some(path) = optional_flag(args, "--credentials-file") {
        let path = PathBuf::from(path);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "authentication credential file unavailable")?;
        if !meta.file_type().is_file() || meta.len() > 16 * 1024 {
            return Err("invalid authentication credential file".into());
        }
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("authentication credential file must be 0600".into());
            }
        }
        let raw = std::fs::read(&path).map_err(|_| "credential file unreadable")?;
        Some(serde_json::from_slice::<MinecraftLaunchCredentials>(&raw)
             .map_err(|_| "invalid Minecraft credential identity")?)
    } else { None };
    if creds.is_some() && server_port.is_none() {
        return Err("authenticated validation requires a matching server".into());
    }
    let mut result = launch_with_timeout_matching_authenticated(
        &manifest, &root, optional_flag(args, "--java"), optional_flag(args, "--username"),
        &pinned, max_runtime_seconds, server_port, creds.clone(),
    ).await?;
    // Never disclose an account token in diagnostic output/structured JSON.
    if let Some(c) = creds {
        result.stdout = result.stdout.replace(&c.access_token, "[REDACTED]");
        result.stderr = result.stderr.replace(&c.access_token, "[REDACTED]");
    }
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

async fn command_certify_vanilla(args: &[String]) -> Result<serde_json::Value, String> {
    let root = PathBuf::from(required_flag(args, "--root")?);
    let version = required_flag(args, "--version")?;
    let java = required_flag(args, "--java")?;
    let required_java_major = required_flag(args, "--required-java-major")?
        .parse::<u32>()
        .map_err(|_| "--required-java-major должен быть целым числом".to_string())?;
    let max_runtime_seconds = optional_flag(args, "--max-runtime-seconds")
        .unwrap_or_else(|| "30".to_string())
        .parse::<u64>()
        .map_err(|_| "--max-runtime-seconds должен быть целым числом секунд".to_string())?;
    let matching_server = optional_flag(args, "--server");
    let matching_server_port = optional_flag(args, "--server-port")
        .map(|value| value.parse::<u16>().map_err(|_| "--server-port должен быть TCP port 1..65535".to_string()))
        .transpose()?;
    let result = certify_vanilla_compatibility(
        &root,
        &version,
        java,
        required_java_major,
        max_runtime_seconds,
        matching_server,
        matching_server_port,
    )
    .await?;
    serde_json::to_value(result).map_err(|err| err.to_string())
}

async fn command_java(args: &[String]) -> Result<serde_json::Value, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("");
    if subcommand != "ensure" {
        return Err("использование: neverruntime java ensure --major <8|16|17|21|25> [--distribution temurin] [--runtime-root PATH] [--manifest PATH|HTTPS_URL --manifest-sha256 SHA256]".to_string());
    }
    let rest = &args[1..];
    let major = required_flag(rest, "--major")?
        .parse::<u32>()
        .map_err(|_| "--major должен быть числом".to_string())?;
    let distribution = optional_flag(rest, "--distribution").unwrap_or_else(|| "temurin".to_string());
    let runtime_root = optional_flag(rest, "--runtime-root").map(PathBuf::from);
    let manifest_sha256 = optional_flag(rest, "--manifest-sha256");
    let result = if let Some(manifest) = optional_flag(rest, "--manifest") {
        ensure_managed_java_from_distribution(
            major,
            &distribution,
            runtime_root.as_deref(),
            &manifest,
            manifest_sha256.as_deref(),
        )
        .await?
    } else {
        ensure_managed_java(major, &distribution, runtime_root.as_deref()).await?
    };
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
