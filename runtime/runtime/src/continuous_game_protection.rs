//! Активные проверки с отказом при ошибке на протяжении всей жизни JVM
//! Minecraft.
//! Проверка независима от наблюдателя файлов внутри Java-процесса.
//! Она не подтверждает отсутствие всех изменений классов в памяти
//! и не заменяет серверную античит-защиту.
use crate::{Manifest, LaunchPlan};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{self, File}, io::Read, path::{Component, Path, PathBuf}};
use tokio::{process::Child, time::{timeout, Duration, Instant}};

const LIMIT: usize = 8192;
const PERIOD: Duration = Duration::from_secs(5);
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone)]
pub struct LiveGameGuard0506 {
    root: PathBuf,
    project: String,
    minecraft: String,
    loader: String,
    policy_digest: Option<String>,
    pinned: BTreeMap<PathBuf, String>,
    jvm_args: Vec<String>,
    #[cfg(target_os = "linux")]
    linux_external: BTreeMap<PathBuf,String>,
    #[cfg(target_os = "linux")]
    linux_process: Option<crate::linux_runtime_guard_0508::LinuxRuntimeGuard0508>,
    #[cfg(target_os = "linux")]
    linux_daemon: Option<crate::linux_guard::GuardSupervisor>,
    #[cfg(target_os = "macos")]
    macos_process: Option<crate::macos_runtime_guard_0509::MacOSRuntimeGuard0509>,
    #[cfg(target_os = "macos")]
    macos_daemon: Option<crate::macos_guard::GuardSupervisor>,
}

fn is_executable(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".jar") || n.ends_with(".dll") || n.ends_with(".dylib") ||
        n.ends_with(".jnilib") || n.ends_with(".so") || n.contains(".so.")
}

fn digest_file(root: &Path, candidate: &Path) -> Result<String, String> {
    let rel = candidate.strip_prefix(root).map_err(|_| "Файл работающего Guard вышел за пределы корня установки")?;
    let mut path = root.to_path_buf();
    for component in rel.components() {
        let Component::Normal(name) = component else {return Err("Небезопасный путь к файлу Runtime при активном Guard".into())};
        path.push(name);
        if fs::symlink_metadata(&path).map_err(|e| format!("Файл работающего Guard отсутствует {}: {e}", path.display()))?.file_type().is_symlink() {
            return Err(format!("Символическая ссылка в пути к исполняемому файлу при активном Guard: {}", path.display()));
        }
    }
    let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {return Err("Некорректный исполняемый файл при активном Guard".into())}
    let mut f = File::open(&path).map_err(|e| e.to_string())?;
    let mut sha = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {let read = f.read(&mut buf).map_err(|e| e.to_string())?; if read == 0 {break} sha.update(&buf[..read]);}
    Ok(hex::encode(sha.finalize()))
}

impl LiveGameGuard0506 {
    pub fn new(manifest: &Manifest, plan: &LaunchPlan, root: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let signed = crate::guard_compatibility_0502::verified_for_game(&root,
            &manifest.project_id, &manifest.minecraft.version, &manifest.minecraft.loader)?;
        crate::guard_compatibility_0502::enforce_launch(&root, &manifest.project_id,
            &manifest.minecraft.version, &manifest.minecraft.loader, &plan.jvm_args)?;
        let selected = crate::component_catalog_0241::active_files(manifest,
            crate::transactional_release::active_preset_for_manifest(manifest, &root).as_deref())?;
        let mut pinned = BTreeMap::new();
        for f in &manifest.files {
            if !crate::manifest_file_applies(f) || !selected.contains(&f.path) || !is_executable(&f.path) {continue}
            let absolute = root.join(&f.path);
            let actual = digest_file(&root, &absolute)?;
            if !actual.eq_ignore_ascii_case(&f.sha256) {return Err(format!("Не совпадает исходная контрольная сумма при активном Guard: {}", f.path))}
            if pinned.insert(absolute, f.sha256.to_ascii_lowercase()).is_some() {return Err("Повторяющийся подписанный файл при активном Guard".into())}
        }
        if let Some(ref policy) = signed {
            for (path, digest, _) in policy.runtime_artifacts(&root)? {
                match pinned.insert(path.clone(), digest.clone()) {
                    Some(old) if old != digest => return Err(format!("Конфликт артефактов при активном Guard: {}",path.display())),
                    _ => (),
                }
            }
        }
        // Артефакты точки входа JVM, созданные Launcher, должны входить
// в подписанную инвентаризацию.
        for entry in plan.classpath_entries.iter().chain(plan.modulepath_entries.iter()) {
            let canonical = fs::canonicalize(entry).map_err(|e| format!("Не удалось найти путь к классам действующего Guard: {e}"))?;
            if !pinned.contains_key(&canonical) {
                return Err(format!("Неподписанный путь к классам Java при активном Guard: {}",canonical.display()));
            }
        }
        if pinned.is_empty() {return Err("Список контролируемых исполняемых файлов действующего Guard пуст".into())}
        if pinned.len() > LIMIT {return Err("Превышен лимит проверки файлов при активном Guard".into())}
        #[cfg(target_os = "linux")]
        let linux_external = match signed.as_ref() {
            Some(policy) => policy.external_native_modules(&root)?,
            None => BTreeMap::new(),
        };
        let guard = Self {
            root, project:manifest.project_id.clone(), minecraft:manifest.minecraft.version.clone(),
            loader:manifest.minecraft.loader.clone(), policy_digest:signed.as_ref().map(|p|p.digest().to_string()),
            pinned, jvm_args:plan.jvm_args.clone(),
            #[cfg(target_os = "linux")]
            linux_external,
            #[cfg(target_os = "linux")]
            linux_process: None,
            #[cfg(target_os = "linux")]
            linux_daemon: None,
            #[cfg(target_os = "macos")]
            macos_process: None,
            #[cfg(target_os = "macos")]
            macos_daemon: None,
        };
        guard.verify()?;
        Ok(guard)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn linux_root(&self) -> &Path { &self.root }

    #[cfg(target_os = "linux")]
    pub(crate) fn linux_signed_artifacts(&self) -> &BTreeMap<PathBuf, String> { &self.pinned }
    #[cfg(target_os = "linux")]
    pub(crate) fn linux_external_modules(&self) -> &BTreeMap<PathBuf,String> { &self.linux_external }

    #[cfg(target_os = "linux")]
    pub(crate) fn linux_jvm_args(&self) -> &[String] { &self.jvm_args }

    #[cfg(target_os = "linux")]
    pub fn bind_linux_process(&mut self, pid: u32, java: &Path) -> Result<(), String> {
        if self.linux_process.is_some() { return Err("JVM уже привязана к Linux Guard".into()); }
        self.linux_process = Some(crate::linux_runtime_guard_0508::LinuxRuntimeGuard0508::attach(pid, java, self)?);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn bind_linux_guard_daemon(&mut self, daemon: crate::linux_guard::GuardSupervisor) -> Result<(),String> {
        if self.linux_daemon.is_some(){return Err("Демон уже привязан к Linux Guard".into());}
        self.linux_daemon = Some(daemon);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub async fn verify_linux_daemon(&self) -> Result<(),String> {
        self.linux_daemon.as_ref().ok_or("Демон Linux Guard не привязан")?.ping_running().await
    }

    #[cfg(target_os = "macos")]
    pub fn bind_macos_process(&mut self, pid: u32, java: &Path) -> Result<(), String> {
        if self.macos_process.is_some() { return Err("JVM уже привязана к macOS Guard".into()); }
        self.macos_process = Some(crate::macos_runtime_guard_0509::MacOSRuntimeGuard0509::attach(pid, java)?);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn bind_macos_guard_daemon(&mut self, daemon: crate::macos_guard::GuardSupervisor) -> Result<(), String> {
        if self.macos_daemon.is_some() { return Err("Демон уже привязан к macOS Guard".into()); }
        self.macos_daemon = Some(daemon);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub async fn verify_macos_daemon(&self) -> Result<(), String> {
        self.macos_daemon.as_ref().ok_or("Демон macOS Guard не привязан")?.ping_running().await
    }

    /// Вызывается в блокирующем обработчике; хеширование никогда не выполняется
// в потоке асинхронного исполнителя.
    pub fn verify(&self) -> Result<(), String> {
        let current = crate::guard_compatibility_0502::verified_for_game(&self.root,
            &self.project, &self.minecraft, &self.loader)?;
        if current.as_ref().map(|p|p.digest()) != self.policy_digest.as_deref() {
            return Err("Политика активного Guard заменена или отозвана во время игры".into());
        }
        crate::guard_compatibility_0502::enforce_launch(&self.root, &self.project,
            &self.minecraft, &self.loader, &self.jvm_args)?;
        #[cfg(target_os = "linux")]
        for (path,expected) in &self.linux_external {
            if &crate::guard_compatibility_0502::verified_external_native_hash(path)?!=expected {
                return Err(format!("Внешний оверлей изменился во время игры при активном Guard: {}",path.display()));
            }
        }
        for (path, expected) in &self.pinned {
            if &digest_file(&self.root, path)? != expected {
                return Err(format!("Исполняемый файл изменился во время игры при активном Guard: {}", path.display()));
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(process) = &self.linux_process { process.verify()?; }
        #[cfg(target_os = "macos")]
        if let Some(process) = &self.macos_process { process.verify()?; }
        Ok(())
    }
}

/// Нативная точка входа: наблюдайте до фактического завершения дочернего
/// процесса, изменения подписанного файла/политики или истечения общего
/// лимита времени. При нарушении завершайте процесс; такой исход
/// нельзя считать успешным завершением игры.
pub struct ProtectedExit0506 {
    pub status: Option<std::process::ExitStatus>,
    pub timed_out: bool,
    pub violation: Option<String>,
}

pub async fn wait_protected(child: &mut Child, guard: LiveGameGuard0506,
    max_seconds: Option<u64>) -> Result<ProtectedExit0506, String> {
    let deadline = max_seconds.filter(|v|*v>0).map(|seconds| Instant::now()+Duration::from_secs(seconds));
    loop {
        let wait_for = deadline.map(|d|d.saturating_duration_since(Instant::now()).min(PERIOD)).unwrap_or(PERIOD);
        if wait_for.is_zero() {
            #[cfg(target_os = "macos")]
            if let Some(pid) = child.id() { let _ = crate::macos_policy::terminate_runtime_process_group(pid); }
            child.kill().await.map_err(|e|format!("Принудительное завершение Runtime по тайм-ауту: {e}"))?;
            let _=child.wait().await;
            return Ok(ProtectedExit0506{status:None,timed_out:true,violation:None});
        }
        match timeout(wait_for, child.wait()).await {
            Ok(result) => return Ok(ProtectedExit0506{status:Some(result.map_err(|e|e.to_string())?),timed_out:false,violation:None}),
            Err(_) => (),
        }
        if deadline.map(|d|Instant::now()>=d).unwrap_or(false) {continue}
        let check = tokio::task::spawn_blocking({let guard=guard.clone(); move ||guard.verify()}).await
            .map_err(|e|format!("Ошибка наблюдателя за действующим Guard: {e}"))?;
        #[cfg(target_os = "linux")]
        let check = match check { Ok(()) => guard.verify_linux_daemon().await, err => err };
        #[cfg(target_os = "macos")]
        let check = match check { Ok(()) => guard.verify_macos_daemon().await, err => err };
        if let Err(reason)=check {
            #[cfg(target_os = "macos")]
            if let Some(pid) = child.id() { let _ = crate::macos_policy::terminate_runtime_process_group(pid); }
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Ok(ProtectedExit0506{status:None,timed_out:false,violation:Some(reason)});
        }
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn live_digest_rejects_mutation_and_symlinks() {
        let root=std::env::temp_dir().join(format!("nl-0506-file-{}",std::process::id()));
        let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).unwrap();
        let jar=root.join("test.jar");fs::write(&jar,b"original").unwrap();
        let expected=hex::encode(Sha256::digest(b"original"));
        assert_eq!(digest_file(&root,&jar).unwrap(),expected);
        fs::write(&jar,b"changed").unwrap();
        assert_ne!(digest_file(&root,&jar).unwrap(),expected);
        assert!(digest_file(&root,&root.join("../escape.jar")).is_err());
        #[cfg(unix)] {
            use std::os::unix::fs::symlink;
            let link=root.join("linked.jar");symlink(&jar,&link).unwrap();
            assert!(digest_file(&root,&link).is_err());
        }
        let _=fs::remove_dir_all(root);
    }
    #[test] fn runtime_parent_detects_modified_pinned_bytes() {
        let root=std::env::temp_dir().join(format!("nl-0506-live-{}", std::process::id()));
        let _=fs::remove_dir_all(&root); fs::create_dir_all(&root).unwrap();
        let jar=root.join("game.jar"); fs::write(&jar,b"signed-game").unwrap();
        let sha=hex::encode(Sha256::digest(b"signed-game"));
        let mut pins=BTreeMap::new(); pins.insert(jar.clone(),sha);
        let live=LiveGameGuard0506{root:root.clone(),project:"p".into(),minecraft:"1.20.1".into(),
            loader:"vanilla".into(),policy_digest:None,pinned:pins,jvm_args:vec![],
            #[cfg(target_os = "linux")] linux_external:BTreeMap::new(),
            #[cfg(target_os = "linux")] linux_process:None,
            #[cfg(target_os = "linux")] linux_daemon:None,
            #[cfg(target_os = "macos")] macos_process:None,
            #[cfg(target_os = "macos")] macos_daemon:None};
        assert!(live.verify().is_ok());
        fs::write(&jar,b"different game").unwrap();
        assert!(live.verify().unwrap_err().contains("Исполняемый файл изменился во время игры"));
        let _=fs::remove_dir_all(root);
    }
    #[cfg(unix)]
    #[tokio::test] async fn native_watchdog_kills_real_long_running_process_on_file_change() {
        let root=std::env::temp_dir().join(format!("nl-0506-child-{}",std::process::id()));
        let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).unwrap();
        let file=root.join("game.jar");fs::write(&file,b"trusted").unwrap();
        let mut pinned=BTreeMap::new();pinned.insert(file.clone(),hex::encode(Sha256::digest(b"trusted")));
        let guard=LiveGameGuard0506{root:root.clone(),project:"p".into(),minecraft:"1.20.1".into(),
            loader:"vanilla".into(),policy_digest:None,pinned,jvm_args:vec![],
            #[cfg(target_os = "linux")] linux_external:BTreeMap::new(),
            #[cfg(target_os = "linux")] linux_process:None,
            #[cfg(target_os = "linux")] linux_daemon:None,
            #[cfg(target_os = "macos")] macos_process:None,
            #[cfg(target_os = "macos")] macos_daemon:None};
        let mut child=tokio::process::Command::new("sleep").arg("12").spawn().unwrap();
        let handle=tokio::spawn(async move {wait_protected(&mut child,guard,Some(10)).await.unwrap()});
        tokio::time::sleep(Duration::from_millis(700)).await;
        fs::write(&file,b"injected").unwrap();
        let exited=handle.await.unwrap();
        assert!(!exited.timed_out);
        assert!(exited.violation.unwrap_or_default().contains("Исполняемый файл изменился во время игры"));
        assert!(exited.status.is_none());
        let _=fs::remove_dir_all(root);
    }

}
