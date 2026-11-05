//! Linux-мониторинг действующей игровой JVM. До создания этого монитора
//! LiveGameGuard0506 проверяет манифест и политику совместимости Guard.
//! /proc — источник наблюдений, а не доверия.
#![cfg(target_os = "linux")]

use crate::continuous_game_protection_0506::LiveGameGuard0506;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const MAX_PROC_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MAPPINGS: usize = 65_536;
const MAX_FDS: usize = 16_384;
const MAX_JRE_FILES: usize = 4_096;
const MAX_HASH_FILE: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LinuxRuntimeGuard0508 {
    pid: u32,
    start_ticks: u64,
    java_device: u64,
    java_inode: u64,
    java_sha256: String,
    root: PathBuf,
    java_home: PathBuf,
    java_executable: PathBuf,
    signed: BTreeMap<PathBuf, String>,
    external: BTreeMap<PathBuf, String>,
    java_native_baseline: BTreeMap<PathBuf, String>,
    expected_jvm_args: Vec<String>,
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("Guard для Linux: не удалось получить сведения о файле {}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE {
        return Err(format!("Guard Linux: недопустимый исполняемый файл {}", path.display()));
    }
    let mut hasher = Sha256::new();
    let mut f = File::open(path).map_err(|e| format!("Guard для Linux: не удалось открыть {}: {e}", path.display()))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn read_proc(pid: u32, file: &str) -> Result<String, String> {
    let path = format!("/proc/{pid}/{file}");
    let meta = fs::metadata(&path).map_err(|e| format!("Guard для Linux: не удалось прочитать сведения о файле {path}: {e}"))?;
    if meta.len() > MAX_PROC_BYTES { return Err(format!("Linux Guard: превышен допустимый размер файла {path}")); }
    let bytes = fs::read(&path).map_err(|e| format!("Guard для Linux: не удалось прочитать {path}: {e}"))?;
    if bytes.len() as u64 > MAX_PROC_BYTES { return Err(format!("Linux Guard: превышен допустимый размер файла {path}")); }
    String::from_utf8(bytes).map_err(|e| format!("Linux Guard invalid {path}: {e}"))
}

fn start_ticks_from_stat(stat: &str) -> Result<u64, String> {
    // Поле comm (второе) само может содержать пробелы и скобки.
    let end = stat.rfind(") ").ok_or("Linux Guard invalid /proc stat comm")?;
    let tail = &stat[end + 2..];
    let ticks = tail.split_whitespace().nth(19)
        .ok_or("Linux Guard missing process starttime")?
        .parse::<u64>().map_err(|_| "Linux Guard invalid process starttime")?;
    if ticks == 0 { return Err("Guard Linux: время запуска процесса равно нулю".into()); }
    Ok(ticks)
}

fn status_value<'a>(status: &'a str, field: &str) -> Result<&'a str, String> {
    status.lines().find_map(|line| line.strip_prefix(field)).map(str::trim)
        .ok_or_else(|| format!("Linux Guard missing process status field {field}"))
}

fn native_name(path: &Path) -> bool {
    let name = path.file_name().map(|v| v.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    name.ends_with(".so") || name.contains(".so.") || name.ends_with(".jnilib")
}
fn game_code_name(path: &Path) -> bool {
    path.file_name().map(|v| v.to_string_lossy().to_ascii_lowercase()).unwrap_or_default().ends_with(".jar") || native_name(path)
}

fn collect_java_natives(home: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let mut result = BTreeMap::new();
    let mut pending = vec![home.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| format!("Linux Guard JRE inventory {}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            visited += 1;
            if visited > MAX_FDS { return Err("Guard Linux: превышен лимит обхода файлов JRE".into()); }
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            if ty.is_symlink() && native_name(&entry.path()) {
                let destination = fs::canonicalize(entry.path()).map_err(|e|e.to_string())?;
                if !destination.starts_with(home) || !destination.is_file() {
                    return Err("Guard Linux: нативный псевдоним JRE находится вне доверенного домашнего каталога Java".into());
                }
                result.insert(entry.path(), sha256_file(&destination)?);
            }
            if ty.is_dir() { pending.push(entry.path()); }
            else if ty.is_file() && native_name(&entry.path()) {
                if result.len() >= MAX_JRE_FILES { return Err("Превышен лимит проверки нативных файлов JRE в Linux Guard".into()); }
                result.insert(entry.path(), sha256_file(&entry.path())?);
            }
        }
    }
    Ok(result)
}

fn trusted_system_library(path:&Path)->Result<bool,String> {
 // Внешний путь может быть каноническим файлом /usr/lib или ссылкой дистрибутива /lib → /usr/lib.
 // Доверие к системной библиотеке получают только неизменяемая цель с владельцем root и её цепочка
 // каталогов; пользовательские оверлеи требуют закреплённого подписанного дайджеста.
 let original=path.to_string_lossy();
 if !["/usr/lib/","/usr/lib64/","/lib/","/lib64/"].iter().any(|r|original.starts_with(r)) {return Ok(false)}
 let resolved=match fs::canonicalize(path) {Ok(p)=>p,Err(_)=>return Ok(false)};
 let resolved_name=resolved.to_string_lossy();
 if !["/usr/lib/","/usr/lib64/"].iter().any(|r|resolved_name.starts_with(r)) {return Ok(false)}
 let mut current=PathBuf::from("/");
 for component in resolved.components().skip(1) {
  let std::path::Component::Normal(part)=component else{return Ok(false)};
  current.push(part);
  let meta=fs::symlink_metadata(&current).map_err(|e|e.to_string())?;
  if meta.file_type().is_symlink() || meta.uid()!=0 || meta.mode() & 0o022 != 0 {return Ok(false)}
 }
 Ok(fs::metadata(&resolved).map_err(|e|e.to_string())?.is_file())
}
fn check_process(pid: u32, start: u64) -> Result<(), String> {
    if start_ticks_from_stat(&read_proc(pid, "stat")?)? != start {
        return Err("Изменилась идентичность игрового процесса Linux Guard (PID использован повторно)".into());
    }
    let status = read_proc(pid, "status")?;
    if status_value(&status, "PPid:")? != std::process::id().to_string() {
        return Err("Обнаружено изменение: родительский процесс JVM Guard в Linux".into());
    }
    if status_value(&status, "TracerPid:")? != "0" {
        return Err("Обнаружена трассировка JVM в Linux Guard".into());
    }
    if status_value(&status, "NoNewPrivs:")? != "1" {
        return Err("Для JVM Linux Guard отключён режим no-new-privs".into());
    }
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    if pgid < 0 || pgid as u32 != pid {
        return Err("Обнаружено изменение: группа процессов JVM Guard в Linux".into());
    }
    Ok(())
}

// Проверяйте также inode открытого объекта: процесс может продолжать держать заменённый
// или удалённый JAR через дескриптор, хотя файл по пути уже имеет одобренный хеш.
fn verify_inode(path: &Path, proc_object: &Path) -> Result<(), String> {
    let on_disk = fs::metadata(path).map_err(|e| e.to_string())?;
    let opened = match fs::metadata(proc_object) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    if on_disk.dev() != opened.dev() || on_disk.ino() != opened.ino() {
        return Err(format!("Подменён открытый объект Linux Guard: {}", path.display()));
    }
    Ok(())
}

impl LinuxRuntimeGuard0508 {
    pub fn attach(pid: u32, java: &Path, verified: &LiveGameGuard0506) -> Result<Self, String> {
        if pid == 0 { return Err("Отсутствует: PID процесса JVM Guard в Linux".into()); }
        let java = fs::canonicalize(java).map_err(|e| format!("Linux Guard Java executable: {e}"))?;
        let java_home = java.parent().and_then(Path::parent)
            .ok_or("Linux Guard Java home unavailable")?.to_path_buf();
        let expected = fs::metadata(&java).map_err(|e| e.to_string())?;
        if !expected.is_file() { return Err("Исполняемый файл Java для Linux Guard не является обычным файлом".into()); }
        let root = verified.linux_root().to_path_buf();
        let signed = verified.linux_signed_artifacts().clone();
        let java_native_baseline = if java_home.starts_with(&root) {
            collect_java_natives(&java_home)?
        } else { BTreeMap::new() };
        let guard = Self { pid, start_ticks: start_ticks_from_stat(&read_proc(pid, "stat")?)?,
            java_device: expected.dev(), java_inode: expected.ino(), java_sha256: sha256_file(&java)?,
            root, java_home, java_executable:java, signed,
            external:verified.linux_external_modules().clone(), java_native_baseline,
            expected_jvm_args: verified.linux_jvm_args().to_vec() };
        guard.verify()?;
        Ok(guard)
    }

    pub fn verify(&self) -> Result<(), String> {
        check_process(self.pid, self.start_ticks)?;
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", self.pid));
        let running = fs::metadata(&proc_exe).map_err(|e| format!("Guard для Linux: не удалось прочитать сведения об образе JVM: {e}"))?;
        if running.dev() != self.java_device || running.ino() != self.java_inode ||
            sha256_file(&proc_exe)? != self.java_sha256 {
            return Err("Обнаружено изменение: фактический исполняемый файл JVM Guard в Linux".into());
        }
        self.verify_jvm_args()?;
        self.verify_maps()?;
        self.verify_fds()?;
        Ok(())
    }

    fn verify_jvm_args(&self) -> Result<(), String> {
        let file = format!("/proc/{}/cmdline", self.pid);
        let bytes = fs::read(&file).map_err(|e| format!("Недоступно: аргументы запуска JVM Guard в Linux: {e}"))?;
        if bytes.is_empty() || bytes.len() > MAX_PROC_BYTES || bytes.last() != Some(&0) {
            return Err("Неполный список аргументов JVM в Linux Guard".into());
        }
        let argv = bytes.split(|c| *c == 0).filter(|a| !a.is_empty()).collect::<Vec<_>>();
        if argv.len() < 1 + self.expected_jvm_args.len() {
            return Err("Обрезан список аргументов JVM в Linux Guard".into());
        }
        for (actual, expected) in argv.iter().skip(1).zip(&self.expected_jvm_args) {
            if *actual != expected.as_bytes() {
                return Err("Обнаружено изменение: фактические параметры запуска JVM Guard в Linux".into());
            }
        }
        Ok(())
    }

    fn verify_mapped_file(&self, path: &Path, proc_object: Option<&Path>, executable: bool) -> Result<(), String> {
        if path.starts_with(&self.java_home) {
            if path.starts_with(&self.root) && executable && path != self.java_executable && !native_name(path) {
                return Err(format!("Неизвестный исполняемый файл в каталоге Java для Linux Guard: {}", path.display()));
            }
            if path.starts_with(&self.root) && native_name(path) {
                let expected = self.java_native_baseline.get(path)
                    .ok_or_else(|| format!("Linux Guard unapproved Java native module: {}", path.display()))?;
                if &sha256_file(path)? != expected {
                    return Err(format!("Изменён нативный модуль Java в Linux Guard: {}", path.display()));
                }
            }
            if let Some(fd) = proc_object { verify_inode(path, fd)?; }
            return Ok(());
        }
        if !path.starts_with(&self.root) {
            if !executable && !native_name(path) {return Ok(())}
            if trusted_system_library(path)? {return Ok(())}
            let expected=self.external.get(path).ok_or_else(||format!(
                "Linux Guard external native module not approved: {}",path.display()))?;
            if &crate::guard_compatibility_0502::verified_external_native_hash(path)?!=expected {
                return Err(format!("Изменён внешний оверлей Linux Guard: {}",path.display()));
            }
            if let Some(fd)=proc_object {verify_inode(path,fd)?;}
            return Ok(())
        }
        if !executable && !game_code_name(path) { return Ok(()); } // data files / non-executable fd
        let expected = self.signed.get(path)
            .ok_or_else(|| format!("Linux Guard unauthorized game module: {}", path.display()))?;
        if fs::symlink_metadata(path).map_err(|e| e.to_string())?.file_type().is_symlink() {
            return Err(format!("Обнаружена символическая ссылка на игровой модуль Linux Guard: {}", path.display()));
        }
        if &sha256_file(path)? != expected {
            return Err(format!("Изменён игровой модуль Linux Guard: {}", path.display()));
        }
        if let Some(fd) = proc_object { verify_inode(path, fd)?; }
        Ok(())
    }

    fn verify_maps(&self) -> Result<(), String> {
        let maps = File::open(format!("/proc/{}/maps", self.pid)).map_err(|e| format!("Недоступно: карта памяти процесса Guard в Linux: {e}"))?;
        let mut lines = 0usize;
        for line in BufReader::new(maps).lines() {
            lines += 1;
            if lines > MAX_MAPPINGS { return Err("Превышен лимит отображений памяти Linux Guard".into()); }
            let line = line.map_err(|e| e.to_string())?;
            let mut fields = line.split_whitespace();
            let _address = fields.next();
            let permissions = fields.next().unwrap_or("");
            let _offset = fields.next(); let _device = fields.next(); let inode = fields.next().unwrap_or("0");
            if !permissions.contains('x') { continue; }
            let filename = fields.collect::<Vec<_>>().join(" ");
            if !filename.starts_with('/') { continue; }
            let deleted = filename.ends_with(" (deleted)");
            let original = if deleted { &filename[..filename.len()-10] } else { &filename };
            let path = Path::new(original);
            if deleted && (path.starts_with(&self.root) || path.starts_with(&self.java_home)) {
                return Err(format!("Удалён исполняемый файл, отображённый в память Linux Guard: {}", path.display()));
            }
            // Любое исполняемое отображение файла из игрового корня считается
            // кодом независимо от расширения; .dat не служит обходом.
            self.verify_mapped_file(path, None, true)?;
            if self.external.contains_key(path) {
                let mapped_inode=inode.parse::<u64>().map_err(|_|"Linux Guard bad overlay mapping inode")?;
                let actual_inode=fs::metadata(path).map_err(|e|format!("Linux Guard overlay map vanished: {e}"))?.ino();
                if mapped_inode==0 || mapped_inode!=actual_inode {
                    return Err(format!("Заменён inode внешнего оверлея Linux Guard: {}",path.display()));
                }
            }
        }
        Ok(())
    }

    fn verify_fds(&self) -> Result<(), String> {
        let dir = format!("/proc/{}/fd", self.pid);
        let entries = fs::read_dir(&dir).map_err(|e| format!("Недоступно: список файловых дескрипторов Guard в Linux: {e}"))?;
        for (i, entry) in entries.enumerate() {
            if i >= MAX_FDS { return Err("Превышен лимит открытых дескрипторов Linux Guard".into()); }
            let entry = entry.map_err(|e| e.to_string())?;
            let opened = match fs::read_link(entry.path()) {
                Ok(path) => path,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // fd closed during iteration
                Err(e) => return Err(format!("Guard для Linux: не удалось проверить открытый файловый дескриптор: {e}")),
            };
            let displayed = opened.to_string_lossy();
            let deleted = displayed.ends_with(" (deleted)");
            let name = if deleted { &displayed[..displayed.len()-10] } else { &displayed };
            let path = Path::new(name);
            if !path.is_absolute() { continue; } // pipe/socket/anon_inode
            if deleted && (path.starts_with(&self.root) || path.starts_with(&self.java_home)) && game_code_name(path) {
                return Err(format!("Удалён открытый файл игры или JRE в Linux Guard: {}", path.display()));
            }
            if !game_code_name(path) { continue; }
            if path.starts_with(&self.root) || path.starts_with(&self.java_home) {
                self.verify_mapped_file(path, Some(&entry.path()), false)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_vendor_modules_are_not_implicitly_approved() {
        let temp=std::env::temp_dir().join(format!("nl-05010-vendor-{}",std::process::id()));
        let _=fs::remove_dir_all(&temp);fs::create_dir_all(&temp).unwrap();
        let overlay=temp.join("libcapture.so");fs::write(&overlay,b"signed test payload").unwrap();
        assert!(!trusted_system_library(&overlay).unwrap());
        let _=fs::remove_dir_all(temp);
    }
    #[test]
    fn parses_real_linux_stat_with_weird_comm() {
        let sample = "424 (hello (other) game) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 12345 20 21 22";
        assert_eq!(start_ticks_from_stat(sample).unwrap(), 12345);
        assert!(start_ticks_from_stat("bad stat").is_err());
    }
    #[test]
    fn detects_real_process_identity_and_tracing_flags() {
        let pid = std::process::id();
        assert!(start_ticks_from_stat(&read_proc(pid, "stat").unwrap()).unwrap() > 0);
        let status = read_proc(pid, "status").unwrap();
        assert_eq!(status_value(&status, "TracerPid:").unwrap(), "0");
        assert!(status_value(&status, "NoNewPrivs:").is_ok());
    }
    // Это настоящий дочерний процесс с теми же ограничениями prctl и
    // группы процессов, что у игрового лаунчера, а не имитация /proc.
    #[tokio::test]
    async fn live_child_process_flags_and_argv_are_enforced() {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("8");
        crate::linux_policy::prepare_runtime_command(&mut cmd);
        let mut child = cmd.spawn().expect("start Linux restricted child");
        let pid = child.id().expect("child pid");
        let exe = fs::read_link(format!("/proc/{pid}/exe")).expect("resolve child executable");
        let meta = fs::metadata(&exe).unwrap();
        let mut guard = LinuxRuntimeGuard0508 {
            pid, start_ticks:start_ticks_from_stat(&read_proc(pid,"stat").unwrap()).unwrap(),
            java_device:meta.dev(), java_inode:meta.ino(), java_sha256:sha256_file(&exe).unwrap(),
            root:std::env::temp_dir().join(format!("nl-0508-empty-{}",pid)),
            java_home:exe.parent().unwrap().parent().unwrap().to_path_buf(),
            java_executable:exe.clone(),
            signed:BTreeMap::new(), external:BTreeMap::new(), java_native_baseline:BTreeMap::new(),
            expected_jvm_args:vec!["8".into()],
        };
        assert!(guard.verify().is_ok(), "actual hardened child should pass");
        guard.expected_jvm_args = vec!["-javaagent:/injected.jar".into()];
        assert!(guard.verify().unwrap_err().contains("Обнаружено изменение: параметры запуска"));
        guard.expected_jvm_args = vec!["8".into()];
        guard.start_ticks += 1;
        assert!(guard.verify().unwrap_err().contains("PID reuse"));
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    #[tokio::test]
    async fn loaded_unsigned_elf_under_game_root_is_rejected() {
        let root = std::env::temp_dir().join(format!("nl-0508-unsigned-{}",std::process::id()));
        let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).unwrap();
        let source = root.join("probe.c");
        fs::write(&source, b"int guard_probe(void) { return 10; }\n").unwrap();
        let native = root.join("unapproved.so");
        let compiler = std::process::Command::new("cc").args(["-shared","-fPIC","-o"])
            .arg(&native).arg(&source).status().expect("C compiler for real ELF probe");
        assert!(compiler.success());
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("8").env("LD_PRELOAD", &native);
        crate::linux_policy::prepare_runtime_command(&mut cmd);
        let mut child = cmd.spawn().expect("run game-like process with injected ELF");
        let pid = child.id().unwrap();
        let exe = fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let meta = fs::metadata(&exe).unwrap();
        let guard = LinuxRuntimeGuard0508 {
            pid, start_ticks:start_ticks_from_stat(&read_proc(pid,"stat").unwrap()).unwrap(),
            java_device:meta.dev(), java_inode:meta.ino(), java_sha256:sha256_file(&exe).unwrap(),
            root:root.clone(), java_home:PathBuf::from("/not-a-java-home"),
            java_executable:exe.clone(),
            signed:BTreeMap::new(), external:BTreeMap::new(), java_native_baseline:BTreeMap::new(),
            expected_jvm_args:vec!["8".into()],
        };
        let result=guard.verify();
        assert!(result.unwrap_err().contains("unauthorized game module"));
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn catches_opened_inode_replacement() {
        let root = std::env::temp_dir().join(format!("guard-0508-inode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root); fs::create_dir_all(&root).unwrap();
        let original = root.join("module.jar"); fs::write(&original, b"first").unwrap();
        let held = File::open(&original).unwrap();
        let moved = root.join("old.jar"); fs::rename(&original, &moved).unwrap();
        fs::write(&original, b"second").unwrap();
        let handle = PathBuf::from(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&held)));
        assert!(verify_inode(&original, &handle).is_err());
        drop(held); let _ = fs::remove_dir_all(root);
    }
}
