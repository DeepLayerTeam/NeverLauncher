use crate::{
    append_launch_history, check_files, create_launch_plan, create_launch_plan_with_credentials, join_classpath, now_unix,
    verify_manifest_signature, LaunchHistoryEntry, Manifest, MinecraftLaunchCredentials, LaunchPreferences, apply_launch_preferences,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_sensor: Option<crate::WindowsSensorReport>,
}

#[derive(Clone)]
struct ManagedProcess {
    status: ProcessStatus,
    child: Arc<Mutex<Option<Child>>>,
    client_release_lease: Option<Arc<std::fs::File>>,
    trusted_launch: Option<Arc<crate::guarded_trusted_launch_0503::GuardedTrustedLaunch0503>>,
    guard_violation: Option<String>,
    #[cfg(windows)]
    runtime_policy: Option<crate::RuntimeProcessPolicyGuard>,
    #[cfg(windows)]
    sensor_session: Option<crate::WindowsSensorSession>,
}

#[derive(Clone, Default)]
pub struct ProcessSupervisor {
    processes: Arc<Mutex<HashMap<String, ManagedProcess>>>,
}

#[cfg(windows)]
fn process_status_snapshot(process: &ManagedProcess) -> ProcessStatus {
    let mut status = process.status.clone();
    if let Some(session) = process.sensor_session.as_ref() {
        status.windows_sensor = Some(session.report());
    }
    status
}

#[cfg(not(windows))]
fn process_status_snapshot(process: &ManagedProcess) -> ProcessStatus {
    process.status.clone()
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
        self.start_inner(manifest, root, java_path, username, None, None, pinned_public_key).await
    }

    pub async fn start_authenticated(
        &self,
        manifest: &Manifest,
        root: &Path,
        java_path: Option<String>,
        credentials: MinecraftLaunchCredentials,
        pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        self.start_inner(manifest, root, java_path, Some(credentials.username.clone()), Some(credentials), None, pinned_public_key).await
    }

    pub async fn start_with_preferences(
        &self, manifest: &Manifest, root: &Path, java_path: Option<String>, username: Option<String>,
        preferences: LaunchPreferences, pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        self.start_inner(manifest, root, java_path, username, None, Some(preferences), pinned_public_key).await
    }

    pub async fn start_authenticated_with_preferences(
        &self, manifest: &Manifest, root: &Path, java_path: Option<String>, credentials: MinecraftLaunchCredentials,
        preferences: LaunchPreferences, pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        self.start_inner(manifest, root, java_path, Some(credentials.username.clone()), Some(credentials), Some(preferences), pinned_public_key).await
    }

    async fn start_inner(
        &self,
        manifest: &Manifest,
        root: &Path,
        java_path: Option<String>,
        username: Option<String>,
        credentials: Option<MinecraftLaunchCredentials>,
        preferences: Option<LaunchPreferences>,
        pinned_public_key: &str,
    ) -> Result<ProcessStatus, String> {
        verify_manifest_signature(manifest, pinned_public_key)?;
        if let Some(p) = preferences.as_ref() {
            if !p.offline && credentials.is_none() { return Err("Для запуска в сети требуется действующий сеанс Minecraft".into()); }
        }
        tokio::fs::create_dir_all(root).await.map_err(|err| format!("не удалось создать рабочий каталог: {err}"))?;
        let client_release_lease = crate::transactional_release::acquire_launch_lease(manifest, root, pinned_public_key).await?;
        let checks = check_files(manifest, root).await?;
        if checks.iter().any(|item| item.status != "ok") {
            return Err("Запуск заблокирован: файлы клиента не прошли проверку целостности".to_string());
        }

        let mut plan = if let Some(credentials) = credentials.as_ref() {
            create_launch_plan_with_credentials(manifest, root, java_path, username, Some(credentials)).await?
        } else {
            create_launch_plan(manifest, root, java_path, username).await?
        };
        if let Some(preferences) = preferences.as_ref() {
            apply_launch_preferences(manifest, root, &mut plan, preferences, credentials.as_ref())?;
            if preferences.offline {
                crate::offline_policy_0358::reject_offline_server_autojoin_0358(&plan)?;
            }
        }
        crate::managed_java::revalidate_managed_java_before_spawn(&plan.java_executable).await?;
        if !plan.main_module.is_empty() && root.join(".launcher/trusted-jvm/active.json").exists() {
            return Err("Для доверенной JVM Guard требуется главный класс Minecraft, указанный в classpath".into());
        }
        let trusted = crate::guarded_trusted_launch_0503::prepare_verified(
            root, &manifest.project_id, &manifest.minecraft.version,
            &manifest.minecraft.loader, &plan.main_class, manifest, &plan)?;
        if let Some(ref agent) = trusted {
            plan.jvm_args.push(agent.agent_arg.clone());
            plan.main_class = agent.main_class.clone();
        }
        let trusted = trusted.map(Arc::new);
        crate::guard_compatibility_0502::enforce_launch(root,
            &manifest.project_id, &manifest.minecraft.version, &manifest.minecraft.loader, &plan.jvm_args)?;
        let mut live_guard = crate::continuous_game_protection_0506::LiveGameGuard0506::new(manifest, &plan, root)?;
        #[cfg(target_os = "linux")]
        {
            let daemon = crate::linux_guard::GuardSupervisor::new();
            daemon.ensure_started().await.map_err(|e|format!("Ошибка запуска Guard в Linux: {e}"))?;
            daemon.ping_running().await?;
            live_guard.bind_linux_guard_daemon(daemon)?;
        }
        #[cfg(target_os = "macos")]
        {
            let daemon = crate::macos_guard::GuardSupervisor::new();
            daemon.ensure_started().await.map_err(|e|format!("Ошибка запуска Guard в macOS: {e}"))?;
            daemon.ping_running().await?;
            live_guard.bind_macos_guard_daemon(daemon)?;
        }
        let logs_dir = root.join("logs");
        tokio::fs::create_dir_all(&logs_dir).await.map_err(|err| format!("не удалось создать каталог логов: {err}"))?;
        let started_at = now_unix()?;
        let log_path = logs_dir.join(format!("runtime-launch-{started_at}.log"));

        let mut log_file = OpenOptions::new().create(true).append(true).open(&log_path)
            .map_err(|err| format!("не удалось открыть журнал среды выполнения {}: {err}", log_path.display()))?;
        writeln!(log_file, "Runtime {}", env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
        writeln!(log_file, "Команда: {}", plan.command_preview).map_err(|e| e.to_string())?;
        writeln!(log_file, "--- вывод процесса ---").map_err(|e| e.to_string())?;
        log_file.flush().map_err(|e| e.to_string())?;
        let stdout_file = log_file.try_clone().map_err(|e| format!("Не удалось продублировать дескриптор журнала Runtime: {e}"))?;

        let mut command = tokio::process::Command::new(&plan.java_executable);
        command.current_dir(Path::new(&plan.working_directory));
        command.args(&plan.jvm_args);
        crate::apply_launch_command_0223(&mut command, &plan);
        #[cfg(windows)]
        let mut sensor_bootstrap = crate::windows_sensor::prepare_sensor_command_for_game(&mut command, root, manifest)
            .map_err(|err| format!("Запуск заблокирован: ошибка подготовки датчика Guard: {err}"))?;
        command
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
            .map_err(|err| format!("Запуск заблокирован: не удалось применить политику Runtime и процессов Windows: {err}"))?;
        #[cfg(windows)]
        sensor_bootstrap.bind_runtime_policy(&runtime_policy);
        #[cfg(windows)]
        let windows_sensor_session = Some(
            crate::windows_sensor::authenticate_sensor_or_kill(sensor_bootstrap, &mut child)
                .await
                .map_err(|err| format!("Запуск заблокирован: ошибка аутентификации датчика Guard или Module Guard: {err}"))?,
        );
        #[cfg(windows)]
        let windows_sensor = windows_sensor_session.as_ref().map(|session| session.report());
        #[cfg(not(windows))]
        let windows_sensor = None;
        #[cfg(target_os = "linux")]
        let linux_runtime_policy = match crate::linux_policy::runtime_policy(&mut child) {
            Ok(policy) => policy,
            Err(err) => {
                if let Some(pid) = child.id() { let _ = crate::linux_policy::terminate_runtime_process_group(pid); }
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(format!("Ошибка применения политик Runtime и процессов в Linux: {err}"));
            }
        };
        #[cfg(target_os = "macos")]
        let macos_runtime_policy = match crate::macos_policy::runtime_policy(&mut child) {
            Ok(policy) => policy,
            Err(err) => {
                if let Some(pid) = child.id() { let _ = crate::macos_policy::terminate_runtime_process_group(pid); }
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(format!("Ошибка применения политик Runtime и процессов в macOS: {err}"));
            }
        };

        #[cfg(target_os = "linux")]
        if let Err(reason) = live_guard.bind_linux_process(
            child.id().ok_or("Linux Guard: PID процесса JVM недоступен")?,
            Path::new(&plan.java_executable),
        ) {
            if let Some(pid) = child.id() { let _ = crate::linux_policy::terminate_runtime_process_group(pid); }
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!("Ошибка проверки игрового процесса Guard в Linux: {reason}"));
        }

        #[cfg(target_os = "macos")]
        if let Err(reason) = live_guard.bind_macos_process(
            child.id().ok_or("macOS Guard: PID процесса JVM недоступен")?,
            Path::new(&plan.java_executable),
        ) {
            if let Some(pid) = child.id() { let _ = crate::macos_policy::terminate_runtime_process_group(pid); }
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!("Ошибка проверки игрового процесса Guard в macOS: {reason}"));
        }

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
        let launch_message = "Runtime запущен под наблюдением с применением политики процессов Windows";
        #[cfg(target_os = "linux")]
        let launch_message = "Runtime запущен под наблюдением с применением политики процессов Linux";
        #[cfg(target_os = "macos")]
        let launch_message = "Runtime запущен под наблюдением с применением политики процессов macOS";
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
            windows_sensor,
        };
        let child = Arc::new(Mutex::new(Some(child)));
        self.processes.lock().await.insert(id.clone(), ManagedProcess {
            status: status.clone(),
            child: child.clone(),
            client_release_lease: Some(client_release_lease),
            trusted_launch: trusted,
            guard_violation: None,
            #[cfg(windows)]
            runtime_policy: Some(runtime_policy),
            #[cfg(windows)]
            sensor_session: windows_sensor_session,
        });

        // Независимая проверка на стороне Rust действует на протяжении всего времени работы
        // каждой управляемой JVM. Она также обнаруживает отзыв политики Guard, пока
        // встроенный Java-наблюдатель остановлен или отключён.
        let watcher = self.clone();
        let watched_id = id.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;
                let current = watcher.status(&watched_id).await;
                match current {
                    Ok(status) if status.state == "running" => (),
                    _ => return,
                }
                let guard = live_guard.clone();
                let result = tokio::task::spawn_blocking(move || guard.verify()).await;
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e),
                    Err(e) => Some(format!("Ошибка нативного наблюдателя Guard за работающей игрой: {e}")),
                };
                #[cfg(target_os = "linux")]
                let failure = if failure.is_none() {
                    live_guard.verify_linux_daemon().await.err()
                } else { failure };
                #[cfg(target_os = "macos")]
                let failure = if failure.is_none() {
                    live_guard.verify_macos_daemon().await.err()
                } else { failure };
                if let Some(reason) = failure {
                    let _ = watcher.stop_for_guard_violation_0438(&watched_id, &reason).await;
                    return;
                }
            }
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
                let (exit_code, mut success, mut message) = match exit {
                    Ok(status) => (status.code(), status.success(), if status.success() { "Runtime завершился успешно".to_string() } else { "Runtime завершился с ошибкой".to_string() }),
                    Err(err) => (None, false, format!("Не удалось получить статус runtime: {err}")),
                };
                {
                    let mut map = processes.lock().await;
                    if let Some(process) = map.get_mut(&id) {
                        // Дочерний процесс, завершившийся с кодом ноль после принудительной остановки Guard,
                        // всё равно считается отказом безопасности, а не успехом.
                        if let Some(reason) = process.guard_violation.as_ref() {
                            success = false;
                            message = format!("Доверие к NeverGuard отозвано во время игры: {reason}");
                        }
                        process.status.state = "exited".to_string();
                        process.status.finished_at = Some(finished_at.clone());
                        process.status.exit_code = exit_code;
                        process.status.success = Some(success);
                        process.status.message = message.clone();
                        process.client_release_lease = None;
                        process.trusted_launch = None;
                        #[cfg(windows)]
                        {
                            if let Some(session) = process.sensor_session.as_ref() {
                                process.status.windows_sensor = Some(session.report());
                            }
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
        let map = self.processes.lock().await;
        map.get(id)
            .map(process_status_snapshot)
            .ok_or_else(|| format!("Процесс среды выполнения {id} не найден"))
    }

    pub async fn list(&self) -> Vec<ProcessStatus> {
        let map = self.processes.lock().await;
        let mut items = map.values().map(process_status_snapshot).collect::<Vec<_>>();
        items.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        items
    }

    /// Останавливайте работающую игру, когда её исходный Guard теряет целостность или
    /// доверие. Сохраните отказ до сигнала дочернему процессу, чтобы наблюдатель
    /// завершения случайно не записал штатный успешный выход.
    pub async fn stop_for_guard_violation_0438(
        &self, id: &str, reason: &str,
    ) -> Result<ProcessStatus, String> {
        let reason = reason.chars().take(300).collect::<String>();
        let child = {
            let mut processes = self.processes.lock().await;
            let managed = processes.get_mut(id).ok_or_else(|| format!("Процесс среды выполнения {id} не найден"))?;
            if managed.status.state != "running" {
                return Ok(process_status_snapshot(managed));
            }
            managed.guard_violation = Some(reason.clone());
            managed.status.state = "trust-blocked".to_string();
            managed.status.success = Some(false);
            managed.status.message = format!("Доверие к NeverGuard отозвано во время игры: {reason}");
            managed.child.clone()
        };
        let mut process = child.lock().await;
        if let Some(process) = process.as_mut() {
            #[cfg(target_os = "linux")]
            {
                let pid = process.id().ok_or("PID процесса Runtime отсутствует")?;
                if crate::linux_policy::terminate_runtime_process_group(pid).is_err() {
                    process.start_kill().map_err(|err| format!("Ошибка: завершение среды выполнения: {err}"))?;
                }
            }
            #[cfg(target_os = "macos")]
            {
                let pid = process.id().ok_or("PID процесса Runtime отсутствует")?;
                if crate::macos_policy::terminate_runtime_process_group(pid).is_err() {
                    process.start_kill().map_err(|err| format!("Ошибка: завершение среды выполнения: {err}"))?;
                }
            }
            #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
            process.start_kill().map_err(|err| format!("Ошибка: завершение среды выполнения: {err}"))?;
        }
        drop(process);
        self.status(id).await
    }

    pub async fn stop(&self, id: &str) -> Result<ProcessStatus, String> {
        let child = {
            let map = self.processes.lock().await;
            map.get(id).map(|p| p.child.clone()).ok_or_else(|| format!("Процесс среды выполнения {id} не найден"))?
        };
        {
            let mut guard = child.lock().await;
            let process = guard.as_mut().ok_or_else(|| format!("процесс среды выполнения {id} уже завершён"))?;
            #[cfg(target_os = "linux")]
            {
                let pid = process.id().ok_or_else(|| format!("процесс среды выполнения {id} PID недоступен"))?;
                crate::linux_policy::terminate_runtime_process_group(pid)?;
            }
            #[cfg(target_os = "macos")]
            {
                let pid = process.id().ok_or_else(|| format!("процесс среды выполнения {id} PID недоступен"))?;
                crate::macos_policy::terminate_runtime_process_group(pid)?;
            }
            #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
            process.start_kill().map_err(|err| format!("не удалось остановить процесс среды выполнения {id}: {err}"))?;
        }
        let mut map = self.processes.lock().await;
        let process = map.get_mut(id).ok_or_else(|| format!("Процесс среды выполнения {id} не найден"))?;
        process.status.state = "stopping".to_string();
        process.status.message = "Отправлен сигнал остановки runtime".to_string();
        Ok(process.status.clone())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod game_guard_lifetime_0438_tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn guard_loss_terminates_real_child_and_marks_failure_0438() {
        let supervisor = ProcessSupervisor::new();
        let mut command = tokio::process::Command::new("sleep");
        command.arg("30");
        crate::linux_policy::prepare_runtime_command(&mut command);
        let child = command.spawn().expect("Запуск настоящего процесса в отдельной группе");
        let pid = child.id().expect("PID дочернего процесса");
        let id = format!("guard-0438-{pid}");
        let status = ProcessStatus {
            id: id.clone(), pid: Some(pid), state: "running".into(),
            started_at: "1".into(), finished_at: None,
            exit_code: None, success: None, log_path: String::new(),
            message: "test game".into(), windows_process_policy: None,
            linux_process_policy: None, macos_process_policy: None, windows_sensor: None,
        };
        let child = Arc::new(Mutex::new(Some(child)));
        supervisor.processes.lock().await.insert(id.clone(), ManagedProcess {
            status,
            child: child.clone(),
            client_release_lease: None,
            guard_violation: None,
        });
        let result = supervisor.stop_for_guard_violation_0438(&id, "Связь с аутентифицированным Guard потеряна")
            .await.expect("При потере Guard игра должна завершаться");
        assert_eq!(result.state, "trust-blocked");
        assert_eq!(result.success, Some(false));
        assert!(result.message.contains("Связь с аутентифицированным Guard потеряна"));
        let mut locked = child.lock().await;
        let exit = timeout(Duration::from_secs(3), locked.as_mut().unwrap().wait())
            .await.expect("Превышено время ожидания завершения дочернего процесса").expect("Не удалось дождаться завершения дочернего процесса");
        assert!(!exit.success(), "При потере Guard игра должна принудительно завершаться");
    }
}
