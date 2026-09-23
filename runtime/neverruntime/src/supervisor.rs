use crate::{
    append_launch_history, check_files, create_launch_plan, create_launch_plan_with_credentials, join_classpath, now_unix,
    verify_manifest_signature, LaunchHistoryEntry, Manifest, MinecraftLaunchCredentials,
    RuntimeProcessPolicyReport,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_process_policy: Option<RuntimeProcessPolicyReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux_process_policy: Option<crate::LinuxRuntimeProcessPolicyReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_process_policy: Option<crate::MacOSRuntimeProcessPolicyReport>,
}

#[derive(Clone)]
struct ManagedProcess {
    status: ProcessStatus,
    child: Arc<Mutex<Option<Child>>>,
    #[cfg(windows)]
    runtime_policy: Option<crate::RuntimeProcessPolicyGuard>,
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
        self.start_inner(manifest, root, java_path, username, None, pinned_public_key).await
    }

    pub async fn start_authenticated(
        &self,
        manifest: &Manifest,
        root: &Path,
        java_path: Option<String>,
        credentials: MinecraftLaunchCredentials,
        pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        self.start_inner(manifest, root, java_path, Some(credentials.username.clone()), Some(credentials), pinned_public_key).await
    }

    async fn start_inner(
        &self,
        manifest: &Manifest,
        root: &Path,
        java_path: Option<String>,
        username: Option<String>,
        credentials: Option<MinecraftLaunchCredentials>,
        pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        verify_manifest_signature(manifest, pinned_public_key)?;
        tokio::fs::create_dir_all(root).await.map_err(|err| format!("не удалось создать рабочий каталог: {err}"))?;
        let checks = check_files(manifest, root).await?;
        if checks.iter().any(|item| item.status != "ok") {
            return Err("launch заблокирован: client files не прошли integrity check".to_string());
        }

        let plan = if let Some(credentials) = credentials.as_ref() {
            create_launch_plan_with_credentials(manifest, root, java_path, username, Some(credentials)).await?
        } else {
            create_launch_plan(manifest, root, java_path, username).await?
        };
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

        let mut command = tokio::process::Command::new(&plan.java_executable);
        command
            .args(&plan.jvm_args)
            .arg("-cp")
            .arg(join_classpath(&plan.classpath_entries))
            .arg(&plan.main_class)
            .args(&plan.game_args)
            .current_dir(Path::new(&plan.working_directory))
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(log_file));
        #[cfg(windows)]
        crate::windows_policy::prepare_runtime_command(&mut command);
        #[cfg(target_os = "linux")]
        crate::linux_policy::prepare_runtime_command(&mut command);
        #[cfg(target_os = "macos")]
        crate::macos_policy::prepare_runtime_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|err| format!("не удалось запустить runtime: {err}"))?;
        #[cfg(windows)]
        let runtime_policy = crate::windows_policy::enforce_runtime_process(&mut child)
            .map_err(|err| format!("launch заблокирован: Windows runtime/process policy enforcement failed: {err}"))?;
        #[cfg(target_os = "linux")]
        let linux_runtime_policy = crate::linux_policy::runtime_policy(&mut child)
            .map_err(|err| format!("launch заблокирован: Linux runtime/process policy enforcement failed: {err}"))?;
        #[cfg(target_os = "macos")]
        let macos_runtime_policy = crate::macos_policy::runtime_policy(&mut child)
            .map_err(|err| format!("launch заблокирован: macOS runtime/process policy enforcement failed: {err}"))?;

        let pid = child.id();
        #[cfg(windows)]
        let windows_process_policy = Some(runtime_policy.report().clone());
        #[cfg(not(windows))]
        let windows_process_policy = None;
        #[cfg(target_os = "linux")]
        let linux_process_policy = Some(linux_runtime_policy);
        #[cfg(not(target_os = "linux"))]
        let linux_process_policy = None;
        #[cfg(target_os = "macos")]
        let macos_process_policy = Some(macos_runtime_policy);
        #[cfg(not(target_os = "macos"))]
        let macos_process_policy = None;
        #[cfg(windows)]
        let launch_message = "Runtime запущен под supervision с Windows process policy enforcement";
        #[cfg(target_os = "linux")]
        let launch_message = "Runtime запущен под supervision с Linux process policy enforcement";
        #[cfg(target_os = "macos")]
        let launch_message = "Runtime запущен под supervision с macOS process policy enforcement";
        #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
        let launch_message = "Runtime запущен под supervision";
        let id = format!("runtime-{started_at}-{}", pid.unwrap_or(0));
        let status = ProcessStatus {
            id: id.clone(), pid, state: "running".to_string(), started_at: started_at.to_string(),
            finished_at: None, exit_code: None, success: None,
            log_path: log_path.to_string_lossy().to_string(), message: launch_message.to_string(),
            windows_process_policy,
            linux_process_policy,
            macos_process_policy,
        };
        let child = Arc::new(Mutex::new(Some(child)));
        self.processes.lock().await.insert(id.clone(), ManagedProcess {
            status: status.clone(),
            child: child.clone(),
            #[cfg(windows)]
            runtime_policy: Some(runtime_policy),
        });

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
                #[cfg(target_os = "linux")]
                if let Some(process_group) = pid {
                    let _ = crate::linux_policy::terminate_runtime_process_group(process_group);
                }
                #[cfg(target_os = "macos")]
                if let Some(process_group) = pid {
                    let _ = crate::macos_policy::terminate_runtime_process_group(process_group);
                }
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
                        #[cfg(windows)]
                        {
                            process.runtime_policy = None;
                        }
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
            #[cfg(target_os = "linux")]
            {
                let pid = process.id().ok_or_else(|| format!("runtime process {id} PID недоступен"))?;
                crate::linux_policy::terminate_runtime_process_group(pid)?;
            }
            #[cfg(target_os = "macos")]
            {
                let pid = process.id().ok_or_else(|| format!("runtime process {id} PID недоступен"))?;
                crate::macos_policy::terminate_runtime_process_group(pid)?;
            }
            #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
            process.start_kill().map_err(|err| format!("не удалось остановить runtime process {id}: {err}"))?;
        }
        let mut map = self.processes.lock().await;
        let process = map.get_mut(id).ok_or_else(|| format!("runtime process {id} не найден"))?;
        process.status.state = "stopping".to_string();
        process.status.message = "Отправлен сигнал остановки runtime".to_string();
        Ok(process.status.clone())
    }
}
