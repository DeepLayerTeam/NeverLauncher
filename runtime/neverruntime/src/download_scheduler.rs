//! Bounded, host-aware streaming downloads for signed client manifests.
//! Each queued file owns one worker slot; a host permit is acquired before spawning.
//! HTTP bodies are never collected in memory and disk writes exert natural backpressure.
use crate::{file_ownership, get_release_file_with_rate_limit_retry, manifest_file_applies,
    replace_verified_managed_file_0224, safe_join, set_executable_if_needed, sha256_file,
    DownloadResult, Manifest, ManifestFile};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, VecDeque}, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, Weak},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering}, time::{Duration, Instant}};
use tokio::{fs, io::AsyncWriteExt, sync::{OwnedSemaphorePermit, Semaphore}, task::JoinSet};

pub const DOWNLOAD_PROGRESS_EVENT: &str = "neverlauncher-download-progress";
// Cap aggregate transfers across concurrent Desktop/Repair invocations in this process.
// The per-run scheduler may request stricter limits but cannot exceed these ceilings.
const PROCESS_GLOBAL_LIMIT: usize = 6;
const PROCESS_HOST_LIMIT: usize = 3;
static PROCESS_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static PROCESS_HOST_SLOTS: OnceLock<Mutex<HashMap<String, Weak<Semaphore>>>> = OnceLock::new();

fn process_host_permit_map(hosts: impl Iterator<Item = String>) -> HashMap<String, Arc<Semaphore>> {
    let mut guard = PROCESS_HOST_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
        .lock().expect("process host limit lock poisoned");
    guard.retain(|_, gate| gate.strong_count() != 0);
    let mut entries = HashMap::new();
    for host in hosts {
        let gate = guard.get(&host).and_then(Weak::upgrade).unwrap_or_else(|| {
            let gate = Arc::new(Semaphore::new(PROCESS_HOST_LIMIT));
            guard.insert(host.clone(), Arc::downgrade(&gate));
            gate
        });
        entries.insert(host, gate);
    }
    entries
}
pub type ProgressSink = Arc<dyn Fn(DownloadProgress) + Send + Sync + 'static>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadProgress {
    pub operation_id: String,
    pub phase: String,
    pub total_files: usize,
    pub queued: usize,
    pub active: usize,
    pub completed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub bytes_expected: u64,
    /// Wire bytes consumed, including invalid responses (not verified bytes).
    pub bytes_transferred: u64,
    pub current_file: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct DownloadLimits {
    pub global: usize,
    pub per_host: usize,
}

impl Default for DownloadLimits {
    fn default() -> Self { Self { global: 6, per_host: 3 } }
}

impl DownloadLimits {
    fn validate(self) -> Result<Self, String> {
        if self.global == 0 || self.global > 32 || self.per_host == 0 || self.per_host > self.global {
            return Err("invalid download concurrency limits (global 1..=32, per_host 1..=global)".into());
        }
        Ok(self)
    }
}

struct Job {
    file: ManifestFile,
    target: PathBuf,
    host: String,
    priority: u8,
    order: usize,
}

// Critical Minecraft metadata and executable dependencies should complete before bulk assets.
// Stable within a priority band: manifest order is preserved.
fn priority(file: &ManifestFile) -> u8 {
    if file.executable || file.path.starts_with("versions/") { 0 }
    else if file.path.starts_with("libraries/") || file.path.starts_with("natives/") { 1 }
    else if file.path.starts_with("assets/") { 3 }
    else { 2 }
}

struct Statistics {
    total: usize,
    skipped: AtomicUsize,
    completed: AtomicUsize,
    failed: AtomicUsize,
    active: AtomicUsize,
    queued: AtomicUsize,
    transferred: AtomicU64,
    expected: u64,
    last_emit: Mutex<Instant>,
    operation_id: String,
    sink: Option<ProgressSink>,
}

impl Statistics {
    fn emit(&self, phase: &str, path: Option<&str>, force: bool) {
        let Some(sink) = &self.sink else { return };
        // Avoid emitting one Tauri event for every small network packet.
        let Ok(mut last) = self.last_emit.try_lock() else { return };
        if !force && last.elapsed() < Duration::from_millis(100) { return }
        *last = Instant::now();
        let snapshot = DownloadProgress {
            operation_id: self.operation_id.clone(), phase: phase.to_string(),
            total_files: self.total,
            queued: self.queued.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            bytes_expected: self.expected,
            bytes_transferred: self.transferred.load(Ordering::Relaxed),
            current_file: path.map(ToOwned::to_owned),
        };
        // Do not hold the mutex while notifying clients.
        drop(last);
        sink(snapshot);
    }
}

fn file_host(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid download URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() ||
        !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("unsafe download URL".into());
    }
    Ok(format!("{}://{}:{}", parsed.scheme(), parsed.host_str().unwrap_or_default(),
        parsed.port_or_known_default().unwrap_or(0)))
}

async fn fetch_one(client: &reqwest::Client, root: &Path, job: &Job, stats: &Statistics) -> Result<(), String> {
    let file = &job.file;
    let target = &job.target;
    file_ownership::ensure_no_symlinks(root, target)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await.map_err(|e| format!("{}: create directory: {e}", file.path))?;
    }
    file_ownership::ensure_no_symlinks(root, target)?;

    let mut response = get_release_file_with_rate_limit_retry(client, &file.url).await
        .map_err(|e| format!("{}: request failed: {e}", file.path))?;
    if !response.status().is_success() {
        return Err(format!("{}: HTTP {}", file.path, response.status()));
    }
    if response.content_length().is_some_and(|len| len != file.size) {
        return Err(format!("{}: response length differs from signed manifest", file.path));
    }

    // Per-attempt random file names prevent collisions with parallel launches.
    let filename = target.file_name().ok_or("invalid managed filename")?.to_string_lossy();
    let part = target.with_file_name(format!("{filename}.nlpart-{}-{:016x}",
        std::process::id(), rand::random::<u64>()));
    let transfer = async {
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&part).await
            .map_err(|e| format!("{}: create temporary file: {e}", file.path))?;
        let mut digest = Sha256::new();
        let mut written = 0u64;
        while let Some(chunk) = response.chunk().await
            .map_err(|e| format!("{}: read response: {e}", file.path))? {
            // Reject oversized responses before writing them to the installation.
            stats.transferred.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            if chunk.len() as u64 > file.size.saturating_sub(written) {
                return Err(format!("{}: response exceeds signed size", file.path));
            }
            // One outstanding HTTP chunk per active worker. Await each disk write
            // before asking reqwest for the next chunk (network/disk backpressure).
            for piece in chunk.chunks(64 * 1024) {
                output.write_all(piece).await.map_err(|e| format!("{}: write: {e}", file.path))?;
                digest.update(piece);
                written += piece.len() as u64;
                stats.emit("downloading", Some(&file.path), false);
            }
        }
        output.flush().await.map_err(|e| format!("{}: flush: {e}", file.path))?;
        output.sync_all().await.map_err(|e| format!("{}: fsync: {e}", file.path))?;
        drop(output);
        if written != file.size || !hex::encode(digest.finalize()).eq_ignore_ascii_case(&file.sha256) {
            return Err(format!("{}: size/SHA-256 verification failed", file.path));
        }
        file_ownership::ensure_no_symlinks(root, target)?;
        replace_verified_managed_file_0224(&part, target).await?;
        set_executable_if_needed(target, file.executable).await?;
        Ok(())
    }.await;
    if transfer.is_err() { let _ = fs::remove_file(&part).await; }
    transfer
}

/// Stream only the missing/mismatched files using bounded workers. Errors are
/// collected per file; an unhealthy mirror/file never cancels unrelated jobs.
/// This is also the engine used by repair_client, not a separate downloader.
pub(crate) async fn run(manifest: &Manifest, root: &Path, limits: DownloadLimits,
                 sink: Option<ProgressSink>) -> Result<DownloadResult, String> {
    let limits = limits.validate()?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        // Redirects could move a request to a different host after admitting a
        // per-host slot. Never follow redirects implicitly.
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(limits.per_host)
        .build().map_err(|e| format!("download HTTP client: {e}"))?;
    let mut result = DownloadResult { downloaded: 0, skipped: 0, failed: 0, repaired: 0,
        bytes_downloaded: 0, failed_files: Vec::new(), messages: Vec::new() };
    let mut jobs = Vec::new();
    for (order, file) in manifest.files.iter().enumerate() {
        if !manifest_file_applies(file) || file_ownership::skip_download(manifest, file) {
            result.skipped += 1;
            continue;
        }
        let target = safe_join(root, &file.path)?;
        file_ownership::ensure_no_symlinks(root, &target)?;
        if manifest.schema_version == "2.0" && file_ownership::effective_ownership(file) == "optional"
            && !file_ownership::must_verify(manifest, &file.path) && !target.exists() {
            result.skipped += 1;
            continue;
        }
        let actual = match fs::metadata(&target).await {
            Ok(meta) if meta.len() == file.size => sha256_file(&target).await
                .map(|digest| digest.eq_ignore_ascii_case(&file.sha256)).unwrap_or(false),
            _ => false,
        };
        if actual { result.skipped += 1; continue; }
        match file_host(&file.url) {
            Ok(host) => jobs.push(Job { file: file.clone(), target, host,
                priority: priority(file), order }),
            Err(e) => {
                result.failed += 1;
                result.failed_files.push(file.path.clone());
                result.messages.push(format!("{}: {e}", file.path));
            }
        }
    }
    jobs.sort_by_key(|job| (job.priority, job.order));
    let expected: u64 = jobs.iter().map(|job| job.file.size).sum();
    let stats = Arc::new(Statistics {
        total: manifest.files.len(), skipped: AtomicUsize::new(result.skipped),
        completed: AtomicUsize::new(0), failed: AtomicUsize::new(result.failed),
        active: AtomicUsize::new(0), queued: AtomicUsize::new(jobs.len()),
        transferred: AtomicU64::new(0), expected,
        last_emit: Mutex::new(Instant::now() - Duration::from_secs(1)),
        operation_id: format!("{}-{:016x}", std::process::id(), rand::random::<u64>()), sink,
    });
    stats.emit("starting", None, true);
    let mut pending: VecDeque<Job> = jobs.into();
    let mut host_limits: HashMap<String, Arc<Semaphore>> = HashMap::new();
    for job in &pending {
        host_limits.entry(job.host.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(limits.per_host)));
    }
    let process_slots = Arc::clone(PROCESS_SLOTS.get_or_init(||
        Arc::new(Semaphore::new(PROCESS_GLOBAL_LIMIT))));
    let process_hosts = process_host_permit_map(pending.iter().map(|j| j.host.clone()));
    let root = root.to_path_buf();
    let mut workers: JoinSet<(String, Result<(), String>)> = JoinSet::new();
    while !pending.is_empty() || !workers.is_empty() {
        while workers.len() < limits.global && !pending.is_empty() {
            // Do not block on the first saturated host while another host can run.
            let mut chosen: Option<(usize, OwnedSemaphorePermit, OwnedSemaphorePermit, OwnedSemaphorePermit)> = None;
            for (idx, job) in pending.iter().enumerate() {
                let Some(local) = host_limits.get(&job.host) else { continue };
                let Some(shared) = process_hosts.get(&job.host) else { continue };
                if let Ok(local_permit) = Arc::clone(local).try_acquire_owned() {
                    if let Ok(host_permit) = Arc::clone(shared).try_acquire_owned() {
                        if let Ok(global_permit) = Arc::clone(&process_slots).try_acquire_owned() {
                            chosen = Some((idx, local_permit, host_permit, global_permit));
                            break;
                        }
                    }
                }
            }
            let Some((idx, local_permit, host_permit, global_permit)) = chosen else { break };
            let job = pending.remove(idx).expect("position was present");
            let client = client.clone();
            let root = root.clone();
            let stats = Arc::clone(&stats);
            stats.queued.fetch_sub(1, Ordering::Relaxed);
            stats.active.fetch_add(1, Ordering::Relaxed);
            workers.spawn(async move {
                let _permits = (local_permit, host_permit, global_permit);
                let outcome = fetch_one(&client, &root, &job, &stats).await;
                (job.file.path, outcome)
            });
        }
        if workers.is_empty() && !pending.is_empty() {
            // A different download invocation may currently hold all process-wide
            // permits. Yield instead of hot-spinning with an empty JoinSet.
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        if let Some(outcome) = workers.join_next().await {
            stats.active.fetch_sub(1, Ordering::Relaxed);
            match outcome {
                Ok((path, Ok(()))) => {
                    result.downloaded += 1;
                    result.repaired += 1;
                    stats.completed.fetch_add(1, Ordering::Relaxed);
                    stats.emit("verified", Some(&path), true);
                },
                Ok((path, Err(e))) => {
                    result.failed += 1;
                    result.failed_files.push(path.clone());
                    result.messages.push(e);
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    stats.emit("failed-file", Some(&path), true);
                },
                Err(e) => {
                    result.failed += 1;
                    result.messages.push(format!("download worker panicked: {e}"));
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    stats.emit("failed-file", None, true);
                },
            }
        }
    }
    result.bytes_downloaded = stats.transferred.load(Ordering::Relaxed);
    stats.emit("finished", None, true);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::Ordering;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

    struct TestHttp {
        base: String,
        max_active: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn test_http(global_active: Arc<AtomicUsize>, global_max: Arc<AtomicUsize>) -> TestHttp {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let own_active = Arc::clone(&active);
        let own_max = Arc::clone(&max_active);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                let active = Arc::clone(&own_active);
                let max_active = Arc::clone(&own_max);
                let global_active = Arc::clone(&global_active);
                let global_max = Arc::clone(&global_max);
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let count = match socket.read(&mut request).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let line = String::from_utf8_lossy(&request[..count]);
                    let path = line.split_whitespace().nth(1).unwrap_or("/missing");
                    let body = format!("file:{path}");
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(now, Ordering::SeqCst);
                    let all = global_active.fetch_add(1, Ordering::SeqCst) + 1;
                    global_max.fetch_max(all, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(90)).await;
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    global_active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        TestHttp { base, max_active, task }
    }

    #[test]
    fn prioritizes_critical_files_before_bulk_assets() {
        let mut f = ManifestFile {
            path: "assets/objects/a".into(), size: 1, sha256: "00".repeat(32),
            url: "https://example.com/a".into(), required: true, executable: false,
            target_os: Vec::new(), ownership: "required".into(),
        };
        assert_eq!(priority(&f), 3);
        f.path = "libraries/a.jar".into();
        assert_eq!(priority(&f), 1);
        f.executable = true;
        assert_eq!(priority(&f), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_parallel_downloads_isolate_failures_and_report_progress() {
        let global_active = Arc::new(AtomicUsize::new(0));
        let global_max = Arc::new(AtomicUsize::new(0));
        let a = test_http(Arc::clone(&global_active), Arc::clone(&global_max)).await;
        let b = test_http(Arc::clone(&global_active), Arc::clone(&global_max)).await;
        let mut entries = Vec::new();
        for i in 0..8 {
            let path = if i == 7 { "/bad".into() } else { format!("/{i}") };
            let body = format!("file:{path}");
            let host = if i == 6 { &b.base } else { &a.base };
            entries.push(json!({
                "path": format!("libraries/{i}.jar"),
                "size": body.len(),
                "sha256": if i == 7 { hex::encode(Sha256::digest(b"not the downloaded content")) }
                           else { hex::encode(Sha256::digest(body.as_bytes())) },
                "url": format!("{host}{path}"), "required": true,
                "ownership": "required"
            }));
        }
        let manifest: Manifest = serde_json::from_value(json!({
            "schemaVersion": "1.0", "projectId": "test", "profileId": "test",
            "channel": "test", "version": "1", "createdAt": "test",
            "minecraft": { "version": "1.21.1", "loader": "vanilla" },
            "runtime": { "java": { "majorVersion": 21, "distribution": "temurin" } },
            "files": entries,
        })).unwrap();
        let root = std::env::temp_dir().join(format!("neverruntime-parallel-test-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&root).await.unwrap();
        let events = Arc::new(Mutex::new(Vec::<DownloadProgress>::new()));
        let observed = Arc::clone(&events);
        let sink: ProgressSink = Arc::new(move |p| observed.lock().unwrap().push(p));
        let result = run(&manifest, &root, DownloadLimits { global: 3, per_host: 2 }, Some(sink)).await.unwrap();
        assert_eq!(result.downloaded, 7, "{:?}", result.messages);
        assert_eq!(result.failed, 1, "{:?}", result.messages);
        assert_eq!(result.failed_files, vec!["libraries/7.jar"]);
        assert!(a.max_active.load(Ordering::SeqCst) >= 2, "no parallel downloads on first host");
        assert!(a.max_active.load(Ordering::SeqCst) <= 2, "exceeded per-host limit");
        assert!(global_max.load(Ordering::SeqCst) >= 2, "downloads were sequential");
        assert!(global_max.load(Ordering::SeqCst) <= 3, "exceeded global limit");
        assert!(b.max_active.load(Ordering::SeqCst) <= 2);
        for i in 0..7 {
            assert_eq!(fs::read_to_string(root.join(format!("libraries/{i}.jar"))).await.unwrap(),
                format!("file:/{i}"));
        }
        assert!(!root.join("libraries/7.jar").exists());
        let events = events.lock().unwrap();
        assert!(events.iter().any(|p| p.phase == "downloading"));
        let final_event = events.last().unwrap();
        assert_eq!(final_event.phase, "finished");
        assert_eq!(final_event.completed, 7);
        assert_eq!(final_event.failed, 1);
        assert_eq!(final_event.active, 0);
        assert_eq!(final_event.queued, 0);
        assert_eq!(final_event.bytes_transferred, result.bytes_downloaded);
        drop(events);
        a.task.abort();
        b.task.abort();
        fs::remove_dir_all(&root).await.unwrap();
    }
}

#[cfg(test)]
mod concurrent_operations_tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::Ordering;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn separate_repair_downloads_share_process_host_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let active_server = Arc::clone(&active);
        let peak_server = Arc::clone(&peak);
        let server = tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let active = Arc::clone(&active_server);
                let peak = Arc::clone(&peak_server);
                tokio::spawn(async move {
                    let mut incoming = [0u8; 1024];
                    if conn.read(&mut incoming).await.is_err() { return }
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(70)).await;
                    let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").await;
                    let _ = conn.shutdown().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        let entries: Vec<_> = (0..8).map(|i| json!({
            "path": format!("libraries/{i}.jar"), "size": 1,
            "sha256": hex::encode(Sha256::digest(b"x")),
            "url": format!("{base}/{i}"), "required": true
        })).collect();
        let manifest: Manifest = serde_json::from_value(json!({
            "schemaVersion": "1.0", "projectId": "test", "profileId": "test",
            "channel": "test", "version": "1", "createdAt": "test",
            "minecraft": { "version": "1.21.1", "loader": "vanilla" },
            "runtime": { "java": { "majorVersion": 21, "distribution": "temurin" } },
            "files": entries
        })).unwrap();
        let first = std::env::temp_dir().join(format!("nl-a-{:016x}", rand::random::<u64>()));
        let second = std::env::temp_dir().join(format!("nl-b-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&first).await.unwrap();
        fs::create_dir_all(&second).await.unwrap();
        let (left, right) = tokio::join!(
            run(&manifest, &first, DownloadLimits::default(), None),
            run(&manifest, &second, DownloadLimits::default(), None)
        );
        assert_eq!(left.unwrap().downloaded, 8);
        assert_eq!(right.unwrap().downloaded, 8);
        assert!(peak.load(Ordering::SeqCst) >= 2);
        assert!(peak.load(Ordering::SeqCst) <= PROCESS_HOST_LIMIT,
            "independent operations exceeded the process-wide host budget");
        server.abort();
        fs::remove_dir_all(first).await.unwrap();
        fs::remove_dir_all(second).await.unwrap();
    }
}
