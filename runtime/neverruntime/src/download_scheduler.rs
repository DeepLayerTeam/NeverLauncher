//! Bounded, host-aware streaming downloads for signed client manifests.
//! Each queued file owns one worker slot; a host permit is acquired before spawning.
//! HTTP bodies are never collected in memory and disk writes exert natural backpressure.
use crate::{file_ownership, manifest_file_applies, safe_join, sha256_file, network_resilience::{self, Directive},
    DownloadResult, Manifest, ManifestFile};
use serde::Serialize;
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, VecDeque}, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, Weak},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering}, time::{Duration, Instant}};
use tokio::{fs, sync::{OwnedSemaphorePermit, Semaphore, watch}, task::JoinSet};

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

async fn fetch_one(client: &reqwest::Client, root: &Path, job: &Job, stats: &Statistics,
                   mut control: watch::Receiver<Directive>) -> Result<(), String> {
    for attempt in 0..network_resilience::MAX_ATTEMPTS {
        network_resilience::check(&control)?;
        let outcome = crate::http_resume::download_verified_controlled(client, root, &job.file,
            &job.target, |bytes| {
                stats.transferred.fetch_add(bytes, Ordering::Relaxed);
                stats.emit("downloading", Some(&job.file.path), false);
            }, control.clone()).await;
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) => {
                network_resilience::check(&control)?;
                if attempt + 1 == network_resilience::MAX_ATTEMPTS { return Err(error); }
                let Some(delay) = network_resilience::retry_delay(&error, attempt) else { return Err(error); };
                stats.emit("retrying", Some(&job.file.path), true);
                network_resilience::wait(delay, &mut control).await?;
            }
        }
    }
    Err(format!("{}: retry budget exhausted", job.file.path))
}

/// Stream only the missing/mismatched files using bounded workers. Errors are
/// collected per file; an unhealthy mirror/file never cancels unrelated jobs.
/// This is also the engine used by repair_client, not a separate downloader.
pub(crate) async fn run(manifest: &Manifest, root: &Path, limits: DownloadLimits,
                 sink: Option<ProgressSink>, operation_id: String, control: watch::Receiver<Directive>) -> Result<DownloadResult, String> {
    let limits = limits.validate()?;
    let client = reqwest::Client::builder()
        .connect_timeout(network_resilience::CONNECT_TIMEOUT)
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
        operation_id, sink,
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
        if *control.borrow() != Directive::Running && workers.is_empty() { break; }
        while *control.borrow() == Directive::Running && workers.len() < limits.global && !pending.is_empty() {
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
            let control = control.clone();
            stats.queued.fetch_sub(1, Ordering::Relaxed);
            stats.active.fetch_add(1, Ordering::Relaxed);
            workers.spawn(async move {
                let _permits = (local_permit, host_permit, global_permit);
                let outcome = fetch_one(&client, &root, &job, &stats, control).await;
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
                Ok((_path, Err(e))) if e == "download paused" || e == "download cancelled" => {
                    // The durable journal and all verified partials remain available.
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
    stats.emit(match *control.borrow() { Directive::Running => "finished", Directive::Paused => "paused", Directive::Cancelled => "cancelled" }, None, true);
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
        let result = run(&manifest, &root, DownloadLimits { global: 3, per_host: 2 }, Some(sink), "test-scheduler".into(), watch::channel(Directive::Running).1).await.unwrap();
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
            run(&manifest, &first, DownloadLimits::default(), None, "test-one".into(), watch::channel(Directive::Running).1),
            run(&manifest, &second, DownloadLimits::default(), None, "test-two".into(), watch::channel(Directive::Running).1)
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
    #[tokio::test]
    async fn retries_503_then_truncated_body_by_range_without_repeating_prefix() {
        let bytes = b"0123456789ABCDEFGHIJ";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let observed = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            for step in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                }
                observed.lock().unwrap().push(String::from_utf8(request).unwrap());
                let response = match step {
                    0 => b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nRetry-After: 0\r\nConnection: close\r\n\r\n".to_vec(),
                    1 => [b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nETag: \"stable\"\r\nConnection: close\r\n\r\n".as_slice(), &bytes[..8]].concat(),
                    _ => [b"HTTP/1.1 206 Partial Content\r\nContent-Length: 12\r\nContent-Range: bytes 8-19/20\r\nETag: \"stable\"\r\nConnection: close\r\n\r\n".as_slice(), &bytes[8..]].concat(),
                };
                stream.write_all(&response).await.unwrap();
                let _ = stream.shutdown().await;
            }
        });
        let manifest: Manifest = serde_json::from_value(json!({
            "schemaVersion": "1.0", "projectId": "test", "profileId": "test", "channel": "stable",
            "version": "test", "createdAt": "test", "minecraft": { "version": "1.21.1", "loader": "vanilla" },
            "runtime": { "java": { "majorVersion": 21, "distribution": "temurin" } },
            "files": [{"path": "libraries/retry.jar", "url": url, "size": bytes.len(),
                "sha256": hex::encode(Sha256::digest(bytes)), "required": true, "executable": false }]
        })).unwrap();
        let root = std::env::temp_dir().join(format!("nl-retry-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&root).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(12), run(&manifest, &root,
            DownloadLimits::default(), None, "retry-test".into(), watch::channel(Directive::Running).1))
            .await.unwrap().unwrap();
        assert_eq!(result.downloaded, 1, "{:?}", result.messages);
        assert_eq!(result.failed, 0);
        assert_eq!(result.bytes_downloaded, 20, "only the missing suffix crossed the wire after failure");
        assert_eq!(fs::read(root.join("libraries/retry.jar")).await.unwrap(), bytes);
        server.await.unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[2].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(requests[2].to_ascii_lowercase().contains("if-range: \"stable\""));
        drop(requests);
        fs::remove_dir_all(root).await.unwrap();
    }

}
