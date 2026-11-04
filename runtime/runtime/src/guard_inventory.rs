//! Active, local Guard inventory. This is diagnostic observation, not remote attestation
//! of a Minecraft game, a certification receipt, or a permission to join a server.
use crate::GuardSupervisor;
use serde::Serialize;
use std::{path::{Path, PathBuf}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{process::Command, time::timeout};

pub const INVENTORY_SCHEMA_0501: &str = "guard/local-inventory/v1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardInventoryCheck0501 {
    pub id: String,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardInventory0501 {
    pub schema: &'static str,
    pub product_version: &'static str,
    pub collected_at_unix: u64,
    pub os: String,
    pub architecture: String,
    pub java_major: Option<u32>,
    pub minecraft_version: Option<String>,
    pub loader: Option<String>,
    pub checks: Vec<GuardInventoryCheck0501>,
    pub status: &'static str,
}

fn check(id: &str, status: &'static str, detail: impl Into<String>) -> GuardInventoryCheck0501 {
    GuardInventoryCheck0501 { id: id.into(), status, detail: detail.into() }
}

fn java_major(value: &str) -> Option<u32> {
    // java.version выводится параметром -XshowSettings:properties в поддерживаемых
    // JVM. Учитывайте старый формат 1.8 и версии с суффиксами патча/сборки.
    let version = value.lines().find_map(|line| {
        line.trim().strip_prefix("java.version =").map(str::trim)
    })?;
    let version = version.trim_matches('"');
    let first = version.split(|c: char| !c.is_ascii_digit()).next()?;
    let major = first.parse::<u32>().ok()?;
    if major == 1 {
        version.strip_prefix("1.")?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    } else if (8..=100).contains(&major) { Some(major) } else { None }
}

async fn probe_java(java: &Path) -> Result<u32, String> {
    let mut cmd = Command::new(java);
    cmd.args(["-XshowSettings:properties", "-version"])
        .env_remove("JAVA_TOOL_OPTIONS")
        .env_remove("_JAVA_OPTIONS")
        .env_remove("JDK_JAVA_OPTIONS")
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(8), cmd.output()).await
        .map_err(|_| "Java version probe exceeded 8 seconds".to_string())?
        .map_err(|err| format!("Java process failed to start: {err}"))?;
    if !output.status.success() { return Err(format!("Java version probe exited with {}", output.status)); }
    let text = String::from_utf8_lossy(&output.stderr);
    java_major(&text).ok_or_else(|| "Java did not return a recognizable java.version property".into())
}

fn validate_version_id(version: &str) -> Result<(), String> {
    if version.is_empty() || version.len() > 160 ||
       !version.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+')) ||
       version == "." || version == ".." || version.starts_with('.') {
        return Err("Minecraft version must be a single safe version ID".into());
    }
    Ok(())
}

fn inspect_installed_version(root: &Path, version: &str) -> Result<String, String> {
    validate_version_id(version)?;
    let base = root.canonicalize().map_err(|err| format!("Minecraft root unavailable: {err}"))?;
    let metadata = base.join("versions").join(version).join(format!("{version}.json"));
    let resolved = metadata.canonicalize().map_err(|err| format!("Minecraft version JSON unavailable: {err}"))?;
    if !resolved.starts_with(base.join("versions")) {
        return Err("Minecraft metadata escapes game root".into());
    }
    let file = std::fs::File::open(&resolved).map_err(|err| err.to_string())?;
    if file.metadata().map_err(|err| err.to_string())?.len() > 2 * 1024 * 1024 {
        return Err("Minecraft version JSON exceeds 2 MiB".into());
    }
    let metadata: serde_json::Value = serde_json::from_reader(file)
        .map_err(|err| format!("Minecraft metadata invalid: {err}"))?;
    let main = metadata.get("mainClass").and_then(|v| v.as_str())
        .ok_or("Minecraft metadata missing mainClass")?;
    // Имя загрузчика здесь обозначает только установленные метаданные, а НЕ
    // успешный запуск или совместимость инструментации Runtime/Guard.
    let lower = main.to_ascii_lowercase();
    let loader = if lower.contains("quiltmc") { "quilt" }
        else if lower.contains("fabricmc") { "fabric" }
        else if lower.contains("neoforged") { "neoforge" }
        else if lower.contains("minecraftforge") || lower.contains("forge") { "forge" }
        else if main == "net.minecraft.client.main.Main" { "vanilla" }
        else { "unknown" };
    Ok(loader.to_string())
}

/// Проверяет настоящий аутентифицированный IPC Guard и проверенные отчёты. Никакого фиктивного
/// PASS и предположения о включении внутрипроцессного датчика Windows без запуска игры.
pub async fn collect_guard_inventory_0501(
    guard_executable: Option<PathBuf>, java: Option<PathBuf>,
    game_root: Option<PathBuf>, minecraft_version: Option<String>,
) -> GuardInventory0501 {
    let mut checks = Vec::new();
    let java = java.unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "java.exe" } else { "java" }));
    let java_major = match probe_java(&java).await {
        Ok(major) => {
            checks.push(check("java.execution", "PASS", format!("Java process executed and reported major {major}")));
            Some(major)
        }
        Err(err) => { checks.push(check("java.execution", "BLOCKED", err)); None }
    };
    let mut loader = None;
    match (game_root.as_deref(), minecraft_version.as_deref()) {
        (Some(root), Some(version)) => match inspect_installed_version(root, version) {
            Ok(found) => { loader = Some(found.clone()); checks.push(check("minecraft.loader.metadata", "PASS", format!("Parsed installed version metadata; mainClass identifies {found}; no game was launched"))); },
            Err(err) => checks.push(check("minecraft.loader.metadata", "BLOCKED", err)),
        },
        (None, None) => checks.push(check("minecraft.loader.metadata", "BLOCKED", "Supply --game-root and --minecraft-version for installed loader inspection")),
        _ => checks.push(check("minecraft.loader.metadata", "BLOCKED", "Both --game-root and --minecraft-version are required")),
    }
    let supervisor = guard_executable.map(GuardSupervisor::with_executable).unwrap_or_default();
    match supervisor.ensure_started().await {
        Err(err) => {
            checks.push(check("guard.authenticated-ipc", "BLOCKED", err));
            checks.push(check("guard.process-policy", "BLOCKED", "Guard IPC not established"));
            checks.push(check("guard.integrity-evidence", "BLOCKED", "Guard IPC not established"));
            checks.push(check("guard.remote-attestation", "BLOCKED", "Guard IPC not established"));
            checks.push(check("guard.release-package", "BLOCKED", "Guard executable identity not verified"));
        }
        Ok(status) => {
            let authenticated = status.authenticated && status.secure_pipe_acl &&
                status.lifetime_job_enforced && status.process_policy_enforced && status.hardening_enforced;
            checks.push(check("guard.authenticated-ipc", if authenticated { "PASS" } else { "BLOCKED" },
                format!("Guard PID {}; authenticated={}, processPolicy={}, hardening={}, boundToParent={}",
                    status.pid, status.authenticated, status.process_policy_enforced, status.hardening_enforced, status.lifetime_job_enforced)));
            checks.push(check("guard.release-package", if status.package_manifest_verified { "PASS" } else { "BLOCKED" },
                if status.package_manifest_verified { "Release package manifest verified" } else { "Release package verification not demonstrated (debug or unverified package)" }));
            match supervisor.process_policy().await {
                Ok(policy) if policy.enforced && policy.pid == status.pid =>
                    checks.push(check("guard.process-policy", "PASS", format!("Guard enforced {} on PID {}", policy.schema, policy.pid))),
                Ok(_) => checks.push(check("guard.process-policy", "BLOCKED", "Policy absent, unenforced or PID mismatch")),
                Err(err) => checks.push(check("guard.process-policy", "BLOCKED", err)),
            }
            match supervisor.integrity_evidence().await {
                Ok(evidence) if evidence.guard.pid == status.pid && evidence.boundary.parent_matches =>
                    checks.push(check("guard.integrity-evidence", "PASS", format!("Validated {} for PID {}", evidence.schema, evidence.guard.pid))),
                Ok(_) => checks.push(check("guard.integrity-evidence", "BLOCKED", "Integrity evidence PID or process boundary mismatch")),
                Err(err) => checks.push(check("guard.integrity-evidence", "BLOCKED", err)),
            }
            let nonce: [u8; 16] = rand::random();
            let id = format!("inventory-{}", hex::encode(nonce));
            let challenge = hex::encode(rand::random::<[u8; 32]>());
            match supervisor.remote_attestation(&id, &challenge).await {
                Ok(attestation) if attestation.challenge_id == id =>
                    checks.push(check("guard.remote-attestation", "PASS", "Fresh challenge validated by authenticated Guard IPC; not server/game attestation")),
                Ok(_) => checks.push(check("guard.remote-attestation", "BLOCKED", "Remote attestation challenge mismatch")),
                Err(err) => checks.push(check("guard.remote-attestation", "BLOCKED", err)),
            }
        }
    }
    if let Err(err) = supervisor.shutdown().await {
        checks.push(check("guard.shutdown", "BLOCKED", format!("Guard could not stop cleanly: {err}")));
    }
    // Для этого требуется НАСТОЯЩИЙ процесс Minecraft и сертифицированный нативный исполнитель.
    // Локальный список никогда не повышает статус до PASS только из-за наличия библиотек.
    if cfg!(windows) {
        checks.push(check("sensor.windows.in-process", "BLOCKED", "Requires real game startup and authenticated pre-main sensor report"));
        checks.push(check("sensor.jvm-awareness", "BLOCKED", "Requires live JVM and native sensor reports"));
        checks.push(check("sensor.continuous", "BLOCKED", "Requires game-lifetime watchdog observations"));
    } else {
        checks.push(check("sensor.windows.in-process", "UNSUPPORTED", "Windows-only native in-process Guard Sensor"));
        checks.push(check("sensor.jvm-awareness", "UNSUPPORTED", "Windows-only native JVM-aware Guard Sensor in 0.50.1"));
        checks.push(check("sensor.continuous", "UNSUPPORTED", "Windows-only native continuous Guard Sensor in 0.50.1"));
    }
    for name in ["vanilla", "fabric", "quilt", "forge", "neoforge"] {
        checks.push(check(&format!("loader.runtime.{name}"), "BLOCKED",
            if loader.as_deref() == Some(name) { "Installed metadata detected; no native Minecraft launch/join certificate supplied" }
            else { "No real runtime/game launch evidence for this loader" }));
    }
    checks.push(check("minecraft.real-join", "BLOCKED", "Requires external real Minecraft launch/join evidence; metadata and Java detection are insufficient"));
    checks.push(check("minecraft.authorized-javaagent", "BLOCKED", "Trusted Java Agent + Guard compatibility not demonstrated by inventory; planned for 0.50.3"));
    let status = if checks.iter().any(|c| c.status == "BLOCKED") { "BLOCKED" } else { "PASS" };
    GuardInventory0501 {
        schema: INVENTORY_SCHEMA_0501,
        product_version: env!("CARGO_PKG_VERSION"),
        collected_at_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        java_major, minecraft_version, loader, checks, status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn java_version_parsing_is_strict() {
        assert_eq!(java_major("Property settings:\n java.version = 21.0.5+11\n"), Some(21));
        assert_eq!(java_major(" java.version = 1.8.0_372\n"), Some(8));
        assert_eq!(java_major("java.version = unknown"), None);
    }
    #[test]
    fn loader_metadata_never_certifies_game() {
        let root = std::env::temp_dir().join(format!("guard-inventory-{}", std::process::id()));
        let path = root.join("versions").join("fabric-test");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("fabric-test.json"), br#"{"mainClass":"net.fabricmc.loader.impl.launch.knot.KnotClient"}"#).unwrap();
        assert_eq!(inspect_installed_version(&root, "fabric-test").unwrap(), "fabric");
        assert!(inspect_installed_version(&root, "../secrets").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
