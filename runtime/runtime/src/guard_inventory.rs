//! Актуальная локальная опись Guard. Это диагностическое наблюдение, а не удалённая аттестация
//! Minecraft, квитанция сертификации или разрешение на вход на сервер.
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
        .map_err(|_| "Проверка версии Java превысила 8 секунд".to_string())?
        .map_err(|err| format!("Не удалось запустить процесс Java: {err}"))?;
    if !output.status.success() { return Err(format!("Проверка версии Java завершилась с кодом {}", output.status)); }
    let text = String::from_utf8_lossy(&output.stderr);
    java_major(&text).ok_or_else(|| "Java не вернула распознаваемое свойство java.version".into())
}

fn validate_version_id(version: &str) -> Result<(), String> {
    if version.is_empty() || version.len() > 160 ||
       !version.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+')) ||
       version == "." || version == ".." || version.starts_with('.') {
        return Err("Для Minecraft требуется безопасный идентификатор версии без пробелов и специальных путей".into());
    }
    Ok(())
}

fn inspect_installed_version(root: &Path, version: &str) -> Result<String, String> {
    validate_version_id(version)?;
    let base = root.canonicalize().map_err(|err| format!("Недоступно: корневой каталог Minecraft: {err}"))?;
    let metadata = base.join("versions").join(version).join(format!("{version}.json"));
    let resolved = metadata.canonicalize().map_err(|err| format!("Недоступно: JSON-файл версии Minecraft: {err}"))?;
    if !resolved.starts_with(base.join("versions")) {
        return Err("Путь к метаданным Minecraft выходит за пределы каталога игры".into());
    }
    let file = std::fs::File::open(&resolved).map_err(|err| err.to_string())?;
    if file.metadata().map_err(|err| err.to_string())?.len() > 2 * 1024 * 1024 {
        return Err("JSON-файл версии Minecraft превышает 2 МиБ".into());
    }
    let metadata: serde_json::Value = serde_json::from_reader(file)
        .map_err(|err| format!("Некорректное значение: метаданные Minecraft: {err}"))?;
    let main = metadata.get("mainClass").and_then(|v| v.as_str())
        .ok_or("В метаданных Minecraft отсутствует mainClass")?;
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
            checks.push(check("java.execution", "PASS", format!("Java успешно запущена; основная версия: {major}")));
            Some(major)
        }
        Err(err) => { checks.push(check("java.execution", "BLOCKED", err)); None }
    };
    let mut loader = None;
    match (game_root.as_deref(), minecraft_version.as_deref()) {
        (Some(root), Some(version)) => match inspect_installed_version(root, version) {
            Ok(found) => { loader = Some(found.clone()); checks.push(check("minecraft.loader.metadata", "PASS", format!("Метаданные установленной версии прочитаны; mainClass указывает на {found}; игра не запускалась"))); },
            Err(err) => checks.push(check("minecraft.loader.metadata", "BLOCKED", err)),
        },
        (None, None) => checks.push(check("minecraft.loader.metadata", "BLOCKED", "Для проверки установленного загрузчика укажите --game-root и --minecraft-version")),
        _ => checks.push(check("minecraft.loader.metadata", "BLOCKED", "Необходимо одновременно указать --game-root и --minecraft-version")),
    }
    let supervisor = guard_executable.map(GuardSupervisor::with_executable).unwrap_or_default();
    match supervisor.ensure_started().await {
        Err(err) => {
            checks.push(check("guard.authenticated-ipc", "BLOCKED", err));
            checks.push(check("guard.process-policy", "BLOCKED", "IPC-соединение с Guard не установлено"));
            checks.push(check("guard.integrity-evidence", "BLOCKED", "IPC-соединение с Guard не установлено"));
            checks.push(check("guard.remote-attestation", "BLOCKED", "IPC-соединение с Guard не установлено"));
            checks.push(check("guard.release-package", "BLOCKED", "Идентичность исполняемого файла Guard не подтверждена"));
        }
        Ok(status) => {
            let authenticated = status.authenticated && status.secure_pipe_acl &&
                status.lifetime_job_enforced && status.process_policy_enforced && status.hardening_enforced;
            checks.push(check("guard.authenticated-ipc", if authenticated { "PASS" } else { "BLOCKED" },
                format!("PID Guard {}; авторизован={}, политика процесса={}, усиленная защита={}, привязка к родителю={}",
                    status.pid, status.authenticated, status.process_policy_enforced, status.hardening_enforced, status.lifetime_job_enforced)));
            checks.push(check("guard.release-package", if status.package_manifest_verified { "PASS" } else { "BLOCKED" },
                if status.package_manifest_verified { "Манифест релизного пакета успешно проверен" } else { "Проверка релизного пакета не подтверждена (отладочный или непроверенный пакет)" }));
            match supervisor.process_policy().await {
                Ok(policy) if policy.enforced && policy.pid == status.pid =>
                    checks.push(check("guard.process-policy", "PASS", format!("Guard применил {} к PID {}", policy.schema, policy.pid))),
                Ok(_) => checks.push(check("guard.process-policy", "BLOCKED", "Политика отсутствует, не применяется или PID не совпадает")),
                Err(err) => checks.push(check("guard.process-policy", "BLOCKED", err)),
            }
            match supervisor.integrity_evidence().await {
                Ok(evidence) if evidence.guard.pid == status.pid && evidence.boundary.parent_matches =>
                    checks.push(check("guard.integrity-evidence", "PASS", format!("Проверено {} для PID {}", evidence.schema, evidence.guard.pid))),
                Ok(_) => checks.push(check("guard.integrity-evidence", "BLOCKED", "Не совпадает PID или граница процесса в подтверждении целостности")),
                Err(err) => checks.push(check("guard.integrity-evidence", "BLOCKED", err)),
            }
            let nonce: [u8; 16] = rand::random();
            let id = format!("inventory-{}", hex::encode(nonce));
            let challenge = hex::encode(rand::random::<[u8; 32]>());
            match supervisor.remote_attestation(&id, &challenge).await {
                Ok(attestation) if attestation.challenge_id == id =>
                    checks.push(check("guard.remote-attestation", "PASS", "Одноразовый запрос проверен через аутентифицированный IPC Guard; это не аттестация сервера или игры")),
                Ok(_) => checks.push(check("guard.remote-attestation", "BLOCKED", "Проверочный запрос удалённого подтверждения не совпадает")),
                Err(err) => checks.push(check("guard.remote-attestation", "BLOCKED", err)),
            }
        }
    }
    if let Err(err) = supervisor.shutdown().await {
        checks.push(check("guard.shutdown", "BLOCKED", format!("Guard не удалось корректно остановить: {err}")));
    }
    // Для этого требуется НАСТОЯЩИЙ процесс Minecraft и сертифицированный нативный исполнитель.
    // Локальный список никогда не повышает статус до PASS только из-за наличия библиотек.
    if cfg!(windows) {
        checks.push(check("sensor.windows.in-process", "BLOCKED", "Требуются реальный запуск игры и аутентифицированный отчёт датчика до выполнения main"));
        checks.push(check("sensor.jvm-awareness", "BLOCKED", "Требуются отчёты работающей JVM и нативного датчика"));
        checks.push(check("sensor.continuous", "BLOCKED", "Требуются наблюдения сторожевого процесса на протяжении игрового сеанса"));
    } else {
        checks.push(check("sensor.windows.in-process", "UNSUPPORTED", "Нативный внутрипроцессный датчик Guard доступен только в Windows"));
        checks.push(check("sensor.jvm-awareness", "UNSUPPORTED", "Нативный датчик Guard с контролем JVM в версии 0.50.1 доступен только в Windows"));
        checks.push(check("sensor.continuous", "UNSUPPORTED", "Нативный датчик непрерывного контроля Guard в версии 0.50.1 доступен только в Windows"));
    }
    for name in ["vanilla", "fabric", "quilt", "forge", "neoforge"] {
        checks.push(check(&format!("loader.runtime.{name}"), "BLOCKED",
            if loader.as_deref() == Some(name) { "Найдены метаданные установки, но нет свидетельства нативного запуска Minecraft или подключения к серверу" }
            else { "Для этого загрузчика отсутствует подтверждение реального запуска среды выполнения или игры" }));
    }
    checks.push(check("minecraft.real-join", "BLOCKED", "Требуются внешние доказательства реального запуска Minecraft и подключения к серверу; одних метаданных и обнаружения Java недостаточно"));
    checks.push(check("minecraft.authorized-javaagent", "BLOCKED", "Инвентаризация не подтверждает совместимость доверенного Java Agent и Guard; запланировано для 0.50.3"));
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
