use crate::{
    append_launch_history, check_files, create_launch_plan, join_classpath, now_unix,
    verify_manifest_signature, LaunchHistoryEntry, Manifest,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::{process::Child, sync::Mutex, time::{sleep, Duration}};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProcessStatus {
    pub id: String,
    pub pid: Option<u32>,
    pub state: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub exit_code: Option<i32>,
    pub success: Option<bool>,
    pub log_path: String,
    pub message: String,
}

#[derive(Clone)]
struct ManagedProcess {
    status: ProcessStatus,
    child: Arc<Mutex<Option<Child>>>,
}

#[derive(Clone, Default)]
pub struct ProcessSupervisor {
    processes: Arc<Mutex<HashMap<String, ManagedProcess>>>,
}

impl ProcessSupervisor {
    pub fn new() -> Self { Self::default() }

    pub async fn start(
        &self,
        manifest: &Manifest,
        root: &Path,
        java_path: Option<String>,
        username: Option<String>,
        pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        verify_manifest_signature(manifest, pinned_public_key)?;
        tokio::fs::create_dir_all(root).await.map_err(|err| format!("не удалось создать рабочий каталог: {err}"))?;
        let checks = check_files(manifest, root).await?;
        if checks.iter().any(|item| item.status != "ok") {
            return Err("launch заблокирован: client files не прошли integrity check".to_string());
        }

        let plan = create_launch_plan(manifest, root, java_path, username).await?;
        let logs_dir = root.join("logs");
        tokio::fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
        let started_at = now_unix()?;
        let log_path = logs_dir.join(format!("neverruntime-launch-{started_at}.log"));

        let mut log_file = OpenOptions::new().create(true).append(true).open(&log_path)
            .map_err(|err| format!("не удалось открыть runtime log {}: {err}", log_path.display()))?;
        writeln!(log_file, "NeverRuntime {}", env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
        writeln!(log_file, "Команда: {}", plan.command_preview).map_err(|e| e.to_string())?;
        writeln!(log_file, "--- process output ---").map_err(|e| e.to_string())?;
        log_file.flush().map_err(|e| e.to_string())?;
        let stdout_file = log_file.try_clone().map_err(|e| format!("не удалось клонировать runtime log handle: {e}"))?;

        let mut child = tokio::process::Command::new(&plan.java_executable)
            .args(&plan.jvm_args)
            .arg("-cp")
            .arg(join_classpath(&plan.classpath_entries))
            .arg(&plan.main_class)
            .args(&plan.game_args)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(log_file))
            .spawn()
            .map_err(|err| format!("не удалось запустить runtime: {err}"))?;

        let pid = child.id();
        let id = format!("runtime-{started_at}-{}", pid.unwrap_or(0));
        let status = ProcessStatus {
            id: id.clone(), pid, state: "running".to_string(), started_at: started_at.to_string(),
            finished_at: None, exit_code: None, success: None,
            log_path: log_path.to_string_lossy().to_string(), message: "Runtime запущен под supervision".to_string(),
        };
        let child = Arc::new(Mutex::new(Some(child)));
        self.processes.lock().await.insert(id.clone(), ManagedProcess { status: status.clone(), child: child.clone() });

        let processes = self.processes.clone();
        let root = PathBuf::from(root);
        let project_id = manifest.project_id.clone();
        let profile_id = manifest.profile_id.clone();
        let version = manifest.version.clone();
        let log_path_string = log_path.to_string_lossy().to_string();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(500)).await;
                let exit = {
                    let mut guard = child.lock().await;
                    match guard.as_mut() {
                        Some(process) => match process.try_wait() {
                            Ok(Some(status)) => { *guard = None; Some(Ok(status)) }
                            Ok(None) => None,
                            Err(err) => { *guard = None; Some(Err(err)) },
                        },
                        None => return,
                    }
                };
                let Some(exit) = exit else { continue; };
                let finished_at = now_unix().unwrap_or_default().to_string();
                let (exit_code, success, message) = match exit {
                    Ok(status) => (status.code(), status.success(), if status.success() { "Runtime завершился успешно".to_string() } else { "Runtime завершился с ошибкой".to_string() }),
                    Err(err) => (None, false, format!("Не удалось получить статус runtime: {err}")),
                };
                {
                    let mut map = processes.lock().await;
                    if let Some(process) = map.get_mut(&id) {
                        process.status.state = "exited".to_string();
                        process.status.finished_at = Some(finished_at.clone());
                        process.status.exit_code = exit_code;
                        process.status.success = Some(success);
                        process.status.message = message.clone();
                    }
                }
                let history = LaunchHistoryEntry {
                    started_at: started_at.to_string(), project_id, profile_id, version, success,
                    exit_code, log_path: log_path_string, message,
                };
                let _ = append_launch_history(&root, &history).await;
                return;
            }
        });

        Ok(status)
    }

    pub async fn status(&self, id: &str) -> Result<ProcessStatus, String> {
        self.processes.lock().await.get(id).map(|p| p.status.clone())
            .ok_or_else(|| format!("runtime process {id} не найден"))
    }

    pub async fn list(&self) -> Vec<ProcessStatus> {
        let mut items = self.processes.lock().await.values().map(|p| p.status.clone()).collect::<Vec<_>>();
        items.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        items
    }

    pub async fn stop(&self, id: &str) -> Result<ProcessStatus, String> {
        let child = {
            let map = self.processes.lock().await;
            map.get(id).map(|p| p.child.clone()).ok_or_else(|| format!("runtime process {id} не найден"))?
        };
        {
            let mut guard = child.lock().await;
            let process = guard.as_mut().ok_or_else(|| format!("runtime process {id} уже завершён"))?;
            process.start_kill().map_err(|err| format!("не удалось остановить runtime process {id}: {err}"))?;
        }
        let mut map = self.processes.lock().await;
        let process = map.get_mut(id).ok_or_else(|| format!("runtime process {id} не найден"))?;
        process.status.state = "stopping".to_string();
        process.status.message = "Отправлен сигнал остановки runtime".to_string();
        Ok(process.status.clone())
    }
}
