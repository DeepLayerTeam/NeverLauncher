//! Проверка NeverGuard на протяжении всей игры. Аттестация при запуске не выдаёт разрешения на
//! всё время работы: тот же аутентифицированный Guard должен работать до завершения дочернего
//! процесса, а проверенные образ и политика процесса не должны меняться. Отсутствующий или
//! противоречивый образец приводит к завершению игры.
use runtime::{GuardIntegrityEvidence, GuardProcessPolicyReport, GuardStatus, GuardSupervisor, ProcessStatus, ProcessSupervisor};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};

const INTERVAL: Duration = Duration::from_secs(2);
const PROBE_DEADLINE: Duration = Duration::from_secs(8);
const MAX_EVIDENCE_AGE: u64 = 15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuardIdentity0438 {
    pid: u32,
    started_at_unix: u64,
    guard_image_sha256: String,
    launcher_image_sha256: String,
}

fn validate_guard_identity_0438(
    status: &GuardStatus,
    policy: &GuardProcessPolicyReport,
    evidence: &GuardIntegrityEvidence,
    previous: Option<&GuardIdentity0438>,
    now: u64,
) -> Result<GuardIdentity0438, String> {
    if !status.authenticated || status.state != "ready"
        || !status.process_policy_enforced || !status.hardening_enforced
        || !status.secure_pipe_acl || !status.lifetime_job_enforced
        || (!cfg!(debug_assertions) && !status.package_manifest_verified)
        || status.pid == 0 || status.parent_pid != std::process::id()
        || status.started_at_unix == 0 || status.started_at_unix > now.saturating_add(5)
    {
        return Err("Guard не аутентифицирован, не защищён или не привязан к лаунчеру".into());
    }
    if !policy.enforced || policy.pid != status.pid || policy.policy_version != status.process_policy_version {
        return Err("Политика работающего процесса Guard изменилась или была отключена".into());
    }
    #[cfg(windows)]
    if status.process_policy_version != runtime::GUARD_WINDOWS_PROCESS_POLICY_VERSION
        || status.hardening_version != runtime::GUARD_WINDOWS_HARDENING_VERSION
        || policy.windows.is_none() {
        return Err("Некорректное значение: политика защиты процесса Guard в Windows".into());
    }
    #[cfg(target_os = "linux")]
    if status.process_policy_version != runtime::GUARD_LINUX_PROCESS_POLICY_VERSION
        || status.hardening_version != runtime::GUARD_LINUX_HARDENING_VERSION
        || policy.linux.is_none() {
        return Err("Некорректное значение: политика защиты процесса Guard в Linux".into());
    }
    #[cfg(target_os = "macos")]
    if status.process_policy_version != runtime::GUARD_MACOS_PROCESS_POLICY_VERSION
        || status.hardening_version != runtime::GUARD_MACOS_HARDENING_VERSION
        || policy.macos.is_none() {
        return Err("Некорректное значение: политика защиты процесса Guard в macOS".into());
    }
    if !evidence.boundary.parent_matches
        || evidence.boundary.expected_parent_pid != status.parent_pid
        || evidence.boundary.observed_parent_pid != status.parent_pid
        || evidence.guard.pid != status.pid
        || evidence.launcher.pid != std::process::id()
        || !evidence_fresh_0438(now, evidence.collected_at_unix)
    {
        return Err("Данные Guard устарели или не привязаны к работающему лаунчеру".into());
    }
    let identity = GuardIdentity0438 {
        pid: status.pid,
        started_at_unix: status.started_at_unix,
        guard_image_sha256: evidence.guard.image_sha256.clone(),
        launcher_image_sha256: evidence.launcher.image_sha256.clone(),
    };
    if previous.is_some_and(|baseline| baseline != &identity) {
        return Err("Процесс Guard перезапустился либо его подписанный образ изменился во время игры".into());
    }
    Ok(identity)
}

fn evidence_fresh_0438(now: u64, observed: u64) -> bool {
    observed <= now.saturating_add(5) && now.saturating_sub(observed) <= MAX_EVIDENCE_AGE
}

fn now_secs() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs()).map_err(|_| "Системное время раньше начала эпохи Unix".into())
}

async fn collect_guard_identity_0438(
    guard: &GuardSupervisor,
    previous: Option<&GuardIdentity0438>,
) -> Result<GuardIdentity0438, String> {
    // Клиентский IPC Guard аутентифицирует каждый ответ, проверяет дайджест
    // доказательства целостности и последовательность протокола. Не принимайте
    // вновь запущенный Guard за продолжение уже начатой игровой сессии.
    let status = guard.status().await?;
    guard.ping().await?;
    let policy = guard.process_policy().await?;
    let evidence = guard.integrity_evidence().await?;
    let identity = validate_guard_identity_0438(&status, &policy, &evidence, previous, now_secs()?)?;
    let after = guard.status().await?;
    if after.pid != identity.pid || after.started_at_unix != identity.started_at_unix {
        return Err("Идентичность Guard изменилась при проверке работающей игры".into());
    }
    Ok(identity)
}

pub(crate) async fn baseline_guard_0438(guard: &GuardSupervisor) -> Result<GuardIdentity0438, String> {
    timeout(PROBE_DEADLINE, collect_guard_identity_0438(guard, None))
        .await.map_err(|_| "Превышено время проверки Guard перед запуском".to_string())?
}

#[cfg(windows)]
fn check_windows_game_sensor_0438(status: &ProcessStatus) -> Result<(), String> {
    let sensor = status.windows_sensor.as_ref().ok_or("Отсутствует отчёт игрового датчика")?;
    if !sensor.authenticated || !sensor.loaded_before_main || Some(sensor.pid) != status.pid {
        return Err("Игровой датчик утратил аутентификацию или привязку к процессу".into());
    }
    let module = &sensor.module_guard;
    if !module.active || !module.healthy || module.violation_count != 0 || module.dropped_event_count != 0 {
        return Err("Защита игровых модулей обнаружила нарушение целостности".into());
    }
    let now_ms = now_secs()?.saturating_mul(1000);
    if module.heartbeat_count == 0 || module.last_heartbeat_unix_ms == 0
        || module.last_heartbeat_unix_ms > now_ms.saturating_add(2_000)
        || now_ms.saturating_sub(module.last_heartbeat_unix_ms) > 10_000
    {
        return Err("Сигнал активности защиты игровых модулей отсутствует или устарел".into());
    }
    if module.continuous_guard.active && !module.continuous_guard.healthy {
        return Err("Датчик непрерывной защиты Guard работает некорректно".into());
    }
    Ok(())
}

async fn probe_live_game_0438(
    guard: &GuardSupervisor,
    supervisor: &ProcessSupervisor,
    game_id: &str,
    previous: &GuardIdentity0438,
) -> Result<(), String> {
    let before = supervisor.status(game_id).await?;
    if before.state != "running" {
        return Ok(());
    }
    collect_guard_identity_0438(guard, Some(previous)).await?;
    let after = supervisor.status(game_id).await?;
    if after.state != "running" {
        return Ok(());
    }
    if after.pid != before.pid || after.started_at != before.started_at {
        return Err("Обнаружено изменение: идентичность игрового процесса".into());
    }
    #[cfg(windows)]
    check_windows_game_sensor_0438(&after)?;
    Ok(())
}

pub(crate) fn start_game_watchdog_0438(
    guard: GuardSupervisor,
    supervisor: ProcessSupervisor,
    game: ProcessStatus,
    baseline: GuardIdentity0438,
) {
    tokio::spawn(async move {
        loop {
            sleep(INTERVAL).await;
            match supervisor.status(&game.id).await {
                Ok(current) if current.state == "running" && current.pid == game.pid => {},
                Ok(current) if current.state == "running" => {
                    let _ = supervisor.stop_for_guard_violation_0438(
                        &game.id, "Game PID replaced while Guard was active",
                    ).await;
                    break;
                },
                _ => break,
            }
            let result = timeout(PROBE_DEADLINE, probe_live_game_0438(&guard, &supervisor, &game.id, &baseline)).await;
            let failure = match result {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => error,
                Err(_) => "Превышено время проверки среды выполнения Guard".into(),
            };
            // Никаких повторов или льготного периода с разрешением по умолчанию: устаревшие или
            // недоступные доказательства Guard не позволяют продолжать активную игровую сессию.
            let _ = supervisor.stop_for_guard_violation_0438(&game.id, &failure).await;
            break;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn game_guard_rejects_stale_and_future_proof_0438() {
        assert!(evidence_fresh_0438(1_000, 985));
        assert!(!evidence_fresh_0438(1_000, 984));
        assert!(evidence_fresh_0438(1_000, 1_005));
        assert!(!evidence_fresh_0438(1_000, 1_006));
    }

    #[test]
    fn game_guard_rejects_process_replacement_0438() {
        let before = GuardIdentity0438 { pid: 100, started_at_unix: 123,
            guard_image_sha256: "a".repeat(64), launcher_image_sha256: "b".repeat(64) };
        assert_ne!(before, GuardIdentity0438 { pid: 101, ..before.clone() });
        assert_ne!(before, GuardIdentity0438 { started_at_unix: 124, ..before.clone() });
        assert_ne!(before, GuardIdentity0438 { guard_image_sha256: "c".repeat(64), ..before.clone() });
    }
}
