//! Мониторинг JVM на macOS в пользовательском режиме. Намеренно не использует task_for_pid и
//! расширения ядра, не заявляет перечисление защищённых SIP/AMFI отображений памяти. За
//! файлами Minecraft также следят LiveGameGuard и Java-агент.
#![cfg(target_os = "macos")]

use crate::macos_policy::verify_macos_code_signature;
use sha2::{Digest, Sha256};
use std::{fs::{self, File}, io::Read, mem, os::unix::fs::MetadataExt, path::{Path, PathBuf}};

const PROC_PIDTBSDINFO: libc::c_int = 3;
const PROC_FLAG_TRACED: u32 = 0x2;
const MAX_EXEC_PATH: usize = 4096;
const MAX_JVM_BYTES: u64 = 512 * 1024 * 1024;

#[link(name = "proc")]
extern "C" {
    fn proc_pidinfo(pid: libc::c_int, flavor: libc::c_int, arg: u64,
                    buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void,
                    buffersize: u32) -> libc::c_int;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    pid: u32,
    parent: u32,
    owner: u32,
    group: u32,
    started_seconds: u64,
    started_microseconds: u64,
    traced: bool,
}

fn process_identity(pid: u32) -> Result<Identity, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("Некорректный PID процесса JVM в macOS Guard".into());
    }
    // proc_bsdinfo — документированная структура Darwin из <sys/proc_info.h>. Проверяйте
    // возвращённый размер; неполная или запрещённая инспекция никогда не проходит.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    let result = unsafe { proc_pidinfo(pid as libc::c_int, PROC_PIDTBSDINFO, 0,
        (&mut info as *mut libc::proc_bsdinfo).cast(),
        mem::size_of::<libc::proc_bsdinfo>() as libc::c_int) };
    if result != mem::size_of::<libc::proc_bsdinfo>() as libc::c_int {
        return Err(format!("Guard для macOS: не удалось проверить процесс JVM {}: {}", pid,
            std::io::Error::last_os_error()));
    }
    if info.pbi_pid != pid || info.pbi_start_tvsec == 0 {
        return Err("Некорректное значение: идентичность JVM Guard в macOS отсутствует или".into());
    }
    Ok(Identity {
        pid, parent: info.pbi_ppid, owner: info.pbi_uid,
        group: info.pbi_pgid, started_seconds: info.pbi_start_tvsec,
        started_microseconds: info.pbi_start_tvusec,
        traced: info.pbi_flags & PROC_FLAG_TRACED != 0,
    })
}

fn actual_executable(pid: u32) -> Result<PathBuf, String> {
    let mut buffer = [0u8; MAX_EXEC_PATH];
    let count = unsafe { proc_pidpath(pid as libc::c_int, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if count <= 0 || count as usize >= buffer.len() {
        return Err(format!("Guard для macOS: не удалось определить исполняемый файл JVM: {}", std::io::Error::last_os_error()));
    }
    if buffer[..count as usize].contains(&0) {
        return Err("Некорректный путь к исполняемому файлу JVM в macOS Guard".into());
    }
    let path = std::str::from_utf8(&buffer[..count as usize])
        .map_err(|_| "Путь к исполняемому файлу JVM для macOS Guard не соответствует UTF-8")?;
    fs::canonicalize(path).map_err(|e| format!("Исполняемый файл JVM для macOS Guard исчез: {e}"))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("Ошибка: получение сведений об исполняемом файле JVM Guard в macOS: {e}"))?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_JVM_BYTES {
        return Err("Некорректное значение: размер или тип исполняемого файла JVM Guard в macOS".into());
    }
    let mut file = File::open(path).map_err(|e| format!("Ошибка: открытие исполняемого файла JVM Guard в macOS: {e}"))?;
    let mut digest = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("Ошибка: чтение исполняемого файла JVM Guard в macOS: {e}"))?;
        if n == 0 { break; }
        digest.update(&buf[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn check_identity(current: Identity, original: Identity) -> Result<(), String> {
    if current.pid != original.pid || current.started_seconds != original.started_seconds ||
       current.started_microseconds != original.started_microseconds {
        return Err("PID процесса JVM в macOS Guard использован повторно".into());
    }
    if current.parent != original.parent || current.owner != original.owner ||
       current.group != original.group || current.group != current.pid {
        return Err("Обнаружено изменение: родительский процесс, владелец или группа процессов JVM Guard в macOS".into());
    }
    if current.traced { return Err("Обнаружена трассировка JVM в macOS Guard".into()); }
    Ok(())
}

#[derive(Clone)]
pub struct MacOSRuntimeGuard0509 {
    identity: Identity,
    executable: PathBuf,
    device: u64,
    inode: u64,
    digest: String,
    signing_team: String,
    signing_identifier: String,
}

impl MacOSRuntimeGuard0509 {
    pub fn attach(pid: u32, java: &Path) -> Result<Self, String> {
        let expected = fs::canonicalize(java).map_err(|e|format!("Отсутствует: настроенная Java для Guard в macOS: {e}"))?;
        let actual = actual_executable(pid)?;
        if expected != actual { return Err(format!("Неожиданный исполняемый файл JVM в macOS Guard: {}",actual.display())); }
        let identity = process_identity(pid)?;
        if identity.parent != std::process::id() || identity.owner != unsafe { libc::geteuid() } ||
            identity.group != pid || identity.traced {
            return Err("JVM не соответствует политике родителя, владельца, группы или трассировки macOS Guard".into());
        }
        let meta = fs::metadata(&actual).map_err(|e| e.to_string())?;
        let signature = verify_macos_code_signature(&actual)?;
        if !signature.valid { return Err("Некорректное значение: подпись JVM Guard в macOS".into()); }
        // Java требует JIT и может использовать JNI-агенты. Нельзя ошибочно требовать
        // для отдельного исполняемого Java разрешения Hardened Runtime/проверки
        // библиотек демона Guard. Вместо этого на всю игровую сессию закрепляются
        // фактическая идентичность, SHA-256 бинарника и идентичность подписи.
        let signing_team = signature.team_identifier
            .filter(|s| !s.trim().is_empty() && s != "not set")
            .ok_or("JVM macOS Guard должна иметь TeamIdentifier подписи, отличной от ad-hoc")?;
        let signing_identifier = signature.identifier
            .filter(|s| !s.trim().is_empty())
            .ok_or("Недоступен идентификатор подписи JVM macOS Guard")?;
        let guard = Self { identity, executable: actual, device: meta.dev(), inode: meta.ino(),
            digest: sha256_file(&expected)?, signing_team, signing_identifier };
        guard.verify()?;
        Ok(guard)
    }

    pub fn verify(&self) -> Result<(), String> {
        check_identity(process_identity(self.identity.pid)?, self.identity)?;
        let actual = actual_executable(self.identity.pid)?;
        if actual != self.executable { return Err("Обнаружено изменение: образ запущенной JVM Guard в macOS".into()); }
        let meta = fs::metadata(&actual).map_err(|e| e.to_string())?;
        if meta.dev() != self.device || meta.ino() != self.inode || sha256_file(&actual)? != self.digest {
            return Err("Исполняемый файл JVM в macOS Guard подменён или изменён".into());
        }
        let sig = verify_macos_code_signature(&actual)?;
        if !sig.valid || sig.team_identifier.as_deref() != Some(self.signing_team.as_str()) ||
            sig.identifier.as_deref() != Some(self.signing_identifier.as_str()) {
            return Err("Обнаружено изменение: идентичность кодовой подписи JVM Guard в macOS".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_pid_reuse_and_tracing() {
        let original = Identity { pid: 42, parent: 1, owner: 501, group: 42,
            started_seconds: 1_700_000_000, started_microseconds: 111, traced: false };
        assert!(check_identity(original, original).is_ok());
        assert!(check_identity(Identity{traced:true,..original},original).is_err());
        assert!(check_identity(Identity{started_microseconds:112,..original},original).is_err());
        assert!(check_identity(Identity{parent:55,..original},original).is_err());
        assert!(check_identity(Identity{group:1,..original},original).is_err());
    }
    #[test]
    fn checks_real_signed_jvm_child() {
        use std::{os::unix::process::CommandExt, process::{Command, Stdio}, time::Duration};
        let home = std::env::var("JAVA_HOME").expect("Интеграция Guard в macOS требует подписанного JAVA_HOME");
        let java = PathBuf::from(&home).join("bin/java");
        let javac = PathBuf::from(&home).join("bin/javac");
        let fixture = std::env::temp_dir().join(format!("nl-0509-mac-java-{}",std::process::id()));
        let _ = fs::remove_dir_all(&fixture);
        fs::create_dir_all(&fixture).unwrap();
        fs::write(fixture.join("GuardHold.java"),
            "public final class GuardHold {public static void main(String[] a) throws Exception {Thread.sleep(20000);}}")
            .unwrap();
        let compiled = Command::new(javac).arg(fixture.join("GuardHold.java"))
            .status().expect("javac spawn");
        assert!(compiled.success(), "javac fixture failed");
        let mut command = Command::new(&java);
        command.args(["-cp",fixture.to_str().unwrap(),"GuardHold"]);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        // Runtime использует ту же политику setpgid перед exec.
        unsafe { command.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {return Err(std::io::Error::last_os_error())}
            Ok(())
        }); }
        let mut child = command.spawn().expect("signed game JVM must launch");
        std::thread::sleep(Duration::from_millis(700));
        let pid = child.id();
        let attached = MacOSRuntimeGuard0509::attach(pid,&java).expect("signed JDK process must be verifiable");
        attached.verify().expect("macOS process signature and identity still valid");
        assert!(MacOSRuntimeGuard0509::attach(pid,Path::new("/usr/bin/false")).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(attached.verify().is_err(),"«dead JVM»: запрещено сохранять действительные свидетельства Guard");
        let _ = fs::remove_dir_all(fixture);
    }
    #[test]
    fn inspects_current_real_process() {
        let pid = std::process::id();
        let i = process_identity(pid).expect("macOS libproc must inspect own process");
        assert_eq!(i.pid,pid);
        assert_eq!(i.owner, unsafe{libc::geteuid()});
        assert!(actual_executable(pid).unwrap().is_file());
    }
}
