//! Нативный мост Minecraft Runtime для уже установленного подписанного пакета Trusted JVM.
//! Независимо подписанная оператором политика Guard разрешает только точные байты агентов и
//! плагинов; этот модуль не считает изменяемый active.json корнем доверия.
use crate::guard_compatibility_0502;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

const ACTIVE: &str = ".launcher/trusted-jvm/active.json";
const ROOT: &str = ".launcher/trusted-jvm";
const WRAPPER: &str = "ru.launcher.trusted.MinecraftMain";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Active {
    schema_version: String,
    package_sha256: String,
    agent_sha256: String,
    approved_access: String,
    plugins: Vec<ActivePlugin>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivePlugin { name: String, sha256: String }

pub struct GuardedTrustedLaunch0503 {
    config: PathBuf,
    pub agent_arg: String,
    pub main_class: String,
    pub policy_digest: String,
}
impl Drop for GuardedTrustedLaunch0503 {
    fn drop(&mut self) { let _ = fs::remove_file(&self.config); }
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.as_bytes().iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn plugin_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 180 && s.ends_with(".jar") &&
        !s.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\r' | '\n' | '\0')) && s != ".jar"
}
fn check_package(root: &Path, release: &str, digest: &str) -> Result<(), String> {
    // Нативный Runtime не принимает изменяемый active.json за подписанный
    // манифест расширения: байты установленного .nlext проверяются независимо.
    // Разрешением на запуск JAR остаётся внешняя политика Guard.
    let mut current = root.to_path_buf();
    for part in format!("{release}/signed.nlext").split('/') {
        current.push(part);
        let md = fs::symlink_metadata(&current).map_err(|e| format!("Не найден пакет доверенной JVM Guard: {e}"))?;
        if md.file_type().is_symlink() { return Err("Символическая ссылка в пути к пакету доверенной JVM для Guard".into()) }
    }
    let md = fs::metadata(&current).map_err(|e| e.to_string())?;
    if !md.is_file() || md.len() == 0 || md.len() > 256 * 1024 * 1024 { return Err("Некорректный размер или тип подписанного пакета доверенной JVM Guard".into()) }
    let mut src = File::open(&current).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = src.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break }
        hasher.update(&buf[..n]);
    }
    if hex::encode(hasher.finalize()) != digest { return Err("SHA-256 подписанного пакета доверенной JVM Guard отличается от активного идентификатора".into()) }
    Ok(())
}
fn config_text(main: &str, plugins: &[(PathBuf, String)], transforms: &[(String, String)], loader: &str, libraries: &[(PathBuf, String)], class_bytes: &[(String,String)]) -> Result<String, String> {
    if !main.contains('.') || !main.split('.').all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')) {
        return Err("Guard Trusted JVM: некорректный главный класс Minecraft".into());
    }
    if plugins.len() > 32 || transforms.len() > 4096 { return Err("Превышен лимит плагинов или преобразований доверенной JVM для Guard".into()) }
    let mut text = format!("main={}\nguard.policy.active=true\ntransform.count={}\n", STANDARD.encode(main), transforms.len());
    for (i, (class, owner)) in transforms.iter().enumerate() {
        if !is_digest(owner) { return Err("Некорректная контрольная сумма владельца преобразования доверенной JVM Guard".into()) }
        text.push_str(&format!("transform.{i}.owner={owner}\ntransform.{i}.class={}\n", STANDARD.encode(class)));
    }
    if !["vanilla","fabric","quilt","forge","neoforge","neo-forge","neo_forge"].contains(&loader.to_ascii_lowercase().as_str()) {
        return Err("Guard Trusted JVM: некорректный идентификатор загрузчика".into());
    }
    if libraries.len()>128 {return Err("Превышен лимит библиотек загрузчика доверенной JVM для Guard".into())}
    text.push_str(&format!("loader.id={}\nloader.count={}\n", loader.to_ascii_lowercase().replace('-', "").replace('_', ""), libraries.len()));
    for (i, (path,digest)) in libraries.iter().enumerate() {
        if !is_digest(digest) {return Err("Некорректное значение: хеш библиотеки загрузчика Guard".into())}
        text.push_str(&format!("loader.{i}.path={}\nloader.{i}.sha256={digest}\n", STANDARD.encode(path.to_string_lossy().as_bytes())));
    }
    if class_bytes.len()>4096 {return Err("Слишком много контрольных сумм классов загрузчика Guard".into())}
    text.push_str(&format!("loader.class.count={}\n", class_bytes.len()));
    for (i,(name,digest)) in class_bytes.iter().enumerate() {
        if !is_digest(digest) || name.len()>256 || !name.contains('.') {return Err("Guard: некорректная привязка SHA-256 класса".into())}
        text.push_str(&format!("loader.class.{i}.name={}\nloader.class.{i}.sha256={digest}\n",STANDARD.encode(name)));
    }
    text.push_str(&format!("count={}\n", plugins.len()));
    for (i, (path, digest)) in plugins.iter().enumerate() {
        if !is_digest(digest) { return Err("Некорректная контрольная сумма плагина доверенной JVM Guard".into()) }
        text.push_str(&format!("plugin.{i}={}\nplugin.{i}.sha256={digest}\n", STANDARD.encode(path.to_string_lossy().as_bytes())));
    }
    Ok(text)
}

/// Если установлен доверенный пакет JVM, требуйте полную подписанную политику Guard и
/// привязывайте её агент, плагины, преобразования и область игры до создания
/// Java-процесса. Без пакета обычный запуск vanilla и загрузчиков остаётся прежним.
pub fn prepare_verified(root: &Path, project: &str, minecraft: &str, loader: &str, original_main: &str,
    manifest:&crate::Manifest, plan:&crate::LaunchPlan) -> Result<Option<GuardedTrustedLaunch0503>, String> {
    prepare_inner(root,project,minecraft,loader,original_main,Some((manifest,plan)))
}
#[cfg(test)]
fn prepare(root: &Path, project: &str, minecraft: &str, loader: &str, original_main: &str) -> Result<Option<GuardedTrustedLaunch0503>, String> {
    prepare_inner(root,project,minecraft,loader,original_main,None)
}
fn prepare_inner(root: &Path, project: &str, minecraft: &str, loader: &str, original_main: &str,
   launch:Option<(&crate::Manifest,&crate::LaunchPlan)>) -> Result<Option<GuardedTrustedLaunch0503>, String> {
    let canonical_root = fs::canonicalize(root).map_err(|e| format!("Guard Trusted JVM: ошибка корневого каталога клиента: {e}"))?;
    let root = canonical_root.as_path();
    let active = root.join(ACTIVE);
    let meta = match fs::symlink_metadata(&active) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Ошибка записи активной доверенной JVM для Guard: {e}")),
    };
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8192 {
        return Err("Guard Trusted JVM: активная запись не является обычным файлом допустимого размера".into());
    }
    let rec: Active = serde_json::from_slice(&fs::read(&active).map_err(|e| e.to_string())?).map_err(|e| format!("Некорректная запись об активной доверенной JVM Guard: {e}"))?;
    if rec.schema_version != "launcher.trusted-jvm.v1" || rec.approved_access != "full-minecraft-jvm" ||
        !is_digest(&rec.package_sha256) || !is_digest(&rec.agent_sha256) || rec.plugins.len() > 16 {
        return Err("Guard Trusted JVM: в активной записи некорректный идентификатор или разрешение".into());
    }
    let signed = guard_compatibility_0502::verified_for_game(root, project, minecraft, loader)?
        .ok_or("Guard Trusted JVM установлен без обязательной подписанной политики совместимости")?;
    let release = format!("{ROOT}/releases/{}", rec.package_sha256);
    check_package(root, &release, &rec.package_sha256)?;
    let agent_rel = format!("{release}/agent.jar");
    signed.authorize(root, "java-agent", &agent_rel, &rec.agent_sha256)?;
    let mut plugins = Vec::new();
    let mut approved_plugins = HashSet::new();
    for plugin in rec.plugins {
        if !plugin_name(&plugin.name) || !is_digest(&plugin.sha256) || !approved_plugins.insert(plugin.sha256.clone()) {
            return Err("Guard Trusted JVM: повторяющийся или недопустимый плагин".into());
        }
        let rel = format!("{release}/plugins/{}", plugin.name);
        signed.authorize(root, "java-plugin", &rel, &plugin.sha256)?;
        let absolute = root.join(&rel).canonicalize().map_err(|e| e.to_string())?;
        plugins.push((absolute, plugin.sha256));
    }
    // Каждое преобразование должно принадлежать установленному и разрешённому плагину.
    let transforms = signed.transforms(&approved_plugins)?;
    // Перед подготовкой JVM повторно проверяйте ВСЕ артефакты политики, не только
    // доверенные. Финальный нативный барьер Guard до запуска повторяет эти проверки.
    guard_compatibility_0502::enforce_launch(root, project, minecraft, loader, &[])?;
    let libraries = signed.loader_libraries(root, loader)?;
    let mut config = config_text(original_main, &plugins, &transforms, loader, &libraries, &signed.loader_class_bytes())?;
    if let Some((manifest,plan))=launch {
        config.push_str(&crate::runtime_integrity_0505::from_verified_launch(manifest,plan,root,&signed)?);
    }
    let dir = root.join(ROOT);
    let mut random = [0u8; 16]; OsRng.fill_bytes(&mut random);
    let name = dir.join(format!(".guard-launch-{}.properties", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(&name).map_err(|e| format!("Guard Trusted JVM: не удалось создать конфигурацию запуска: {e}"))?;
    if let Err(e) = file.write_all(config.as_bytes()).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&name);
        return Err(format!("Не удалось записать конфигурацию запуска доверенной JVM для Guard: {e}"));
    }
    drop(file);
    let agent = root.join(&agent_rel).canonicalize().map_err(|e| { let _ = fs::remove_file(&name); e.to_string() })?;
    Ok(Some(GuardedTrustedLaunch0503 {
        config: name.clone(),
        agent_arg: format!("-javaagent:{}={}", agent.display(), name.display()),
        main_class: WRAPPER.into(),
        policy_digest: signed.digest().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_bad_names_and_identity() {
        for s in ["../hook.jar", "other\\hook.jar", "nojar", "x.jar\nX=1", ".jar"] { assert!(!plugin_name(s)); }
        assert!(plugin_name("trusted-hook.jar"));
        assert!(config_text("com.example.Client", &[], &[], "vanilla", &[], &[]).unwrap().contains("guard.policy.active=true"));
        assert!(config_text("bad class", &[], &[], "vanilla", &[], &[]).is_err());
        assert!(config_text("Main", &[], &[], "vanilla", &[], &[]).is_err());
    }
}

#[cfg(test)]
mod signed_launch_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
    fn create(root: &Path, path: &str, bytes: &[u8]) {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    fn policy_fixture(root: &Path, anchor: &Path, revoked: bool) -> String {
        let key = SigningKey::from_bytes(&[17u8; 32]);
        fs::write(anchor, hex::encode(key.verifying_key().to_bytes())).unwrap();
        let package_hash = sha(b"trusted-package");
        let agent = b"agent-JAR-fixed-contents";
        let plugin = b"plugin-JAR-fixed-contents";
        create(root, &format!("{ROOT}/releases/{package_hash}/signed.nlext"), b"trusted-package");
        let agent_path = format!("{ROOT}/releases/{package_hash}/agent.jar");
        let plugin_path = format!("{ROOT}/releases/{package_hash}/plugins/hook.jar");
        create(root, &agent_path, agent);
        create(root, &plugin_path, plugin);
        create(root, "mods/approved.jar", b"approved-mod");
        create(root, "libraries/fabric-loader.jar", b"approved-loader");
        create(root, ACTIVE, serde_json::to_string(&json!({
            "schemaVersion":"launcher.trusted-jvm.v1",
            "packageSha256":package_hash,
            "agentSha256":sha(agent),
            "approvedAccess":"full-minecraft-jvm",
            "plugins":[{"name":"hook.jar","sha256":sha(plugin)}]
        })).unwrap().as_bytes());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let payload = serde_json::to_vec(&json!({
            "schemaVersion":"launcher.guard-compatibility.v1", "projectId":"project-1", "minecraft":"1.20.1", "loader":"fabric",
            "epoch":2, "issuedAt":now-60, "expiresAt":now+3600,
            "artifacts":[
                {"kind":"java-agent","path":agent_path,"sha256":sha(agent)},
                {"kind":"java-plugin","path":plugin_path,"sha256":sha(plugin)},
                {"kind":"mod","path":"mods/approved.jar","sha256":sha(b"approved-mod")},
                {"kind":"loader-library","path":"libraries/fabric-loader.jar","sha256":sha(b"approved-loader")}
            ],
            "transformations":[{"id":"net.minecraft.client.Minecraft","ownerSha256":sha(plugin)}],
            "loaderClassBytes":[{"class":"net.minecraft.client.Minecraft","sha256":sha(b"game-class-expected")}],
            "revokedDigests":if revoked { vec![sha(agent)] } else { vec![] },
            "revokedTransformations":[]
        })).unwrap();
        let mut message = b"Launcher-Guard-Compatibility-v1\n".to_vec();
        message.extend_from_slice(&payload);
        create(root, ".launcher/guard/compatibility.json", serde_json::to_string(&json!({
            "schemaVersion":"launcher.guard-compatibility.v1", "payload":STANDARD.encode(&payload),
            "signature":hex::encode(key.sign(&message).to_bytes())
        })).unwrap().as_bytes());
        create(root, ".launcher/guard/accepted.json", serde_json::to_string(&json!({
            "epoch":2, "digest":sha(&payload), "rootSha256":sha(&key.verifying_key().to_bytes())
        })).unwrap().as_bytes());
        agent_path
    }
    #[test]
    fn native_modded_agent_prepare_enforces_real_signed_policy() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let mut random = [0u8; 16]; OsRng.fill_bytes(&mut random);
        let base = std::env::temp_dir().join(format!("nl-0503-test-{}", hex::encode(random)));
        let root = base.join("game");
        fs::create_dir_all(&root).unwrap();
        let key = base.join("public.hex");
        let agent_rel = policy_fixture(&root, &key, false);
        let old = std::env::var_os("LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE");
        std::env::set_var("LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE", &key);
        let accepted = prepare(&root, "project-1", "1.20.1", "fabric", "net.minecraft.client.main.Main").unwrap().unwrap();
        let file = accepted.agent_arg.split_once('=').unwrap().1.to_string();
        let props = fs::read_to_string(&file).unwrap();
        assert!(props.contains("transform.count=1"));
        assert!(props.contains("loader.id=fabric"));
        assert!(props.contains("loader.count=1"));
        assert!(props.contains("loader.class.count=1"));
        assert!(props.contains("plugin.0.sha256="));
        assert!(accepted.agent_arg.contains("agent.jar"));
        assert_eq!(accepted.main_class, WRAPPER);
        drop(accepted);
        assert!(!Path::new(&file).exists());
        assert!(prepare(&root, "project-2", "1.20.1", "fabric", "com.example.Game").is_err());
        create(&root, "mods/injected.jar", b"unexpected mod");
        assert!(prepare(&root, "project-1", "1.20.1", "fabric", "com.example.Game").is_err());
        fs::remove_file(root.join("mods/injected.jar")).unwrap();
        create(&root, &agent_rel, b"tampered");
        assert!(prepare(&root, "project-1", "1.20.1", "fabric", "com.example.Game").is_err());
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        policy_fixture(&root, &key, true);
        assert!(prepare(&root, "project-1", "1.20.1", "fabric", "com.example.Game").is_err());
        match old { Some(v) => std::env::set_var("LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE", v), None => std::env::remove_var("LAUNCHER_GUARD_COMPAT_PUBLIC_KEY_FILE") }
        let _ = fs::remove_dir_all(&base);
    }
}
