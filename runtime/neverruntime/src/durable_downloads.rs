//! Durable signed download operations. The journal persists the *signed* manifest
//! (not trusted paths) and the pinned public key. Partials remain in http_resume.
//! Two alternating generations survive an interrupted journal rewrite, including
//! Windows, where rename-over-existing is not available.
use crate::{file_ownership, network_resilience::Directive,
    verify_manifest_signature, DownloadResult, Manifest, ProgressSink};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Mutex, OnceLock}};
use tokio::{fs, io::AsyncWriteExt, sync::watch};

const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedJob {
    pub schema_version: u32,
    pub generation: u64,
    pub operation_id: String,
    pub mode: String,
    pub status: String,
    pub pinned_public_key: String,
    pub manifest: Manifest,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub preset: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDownload {
    pub operation_id: String,
    pub mode: String,
    pub status: String,
    pub project_id: String,
    pub profile_id: String,
    pub version: String,
    pub total_files: usize,
}

static ACTIVE: OnceLock<Mutex<HashMap<PathBuf, watch::Sender<Directive>>>> = OnceLock::new();
fn active() -> &'static Mutex<HashMap<PathBuf, watch::Sender<Directive>>> {
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct ActiveGuard(PathBuf);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = active().lock() { guard.remove(&self.0); }
    }
}

async fn normalized(root: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(root).await.map_err(|e| format!("create install root: {e}"))?;
    let resolved = fs::canonicalize(root).await.map_err(|e| format!("resolve install root: {e}"))?;
    file_ownership::ensure_no_symlinks(&resolved, &resolved.join(".neverlauncher"))?;
    Ok(resolved)
}

fn journal_path(root: &Path, slot: usize) -> PathBuf {
    root.join(".neverlauncher").join(format!("download-job-{slot}.json"))
}

async fn read_slot(root: &Path, slot: usize) -> Option<SavedJob> {
    let path = journal_path(root, slot);
    if fs::symlink_metadata(&path).await.ok()?.file_type().is_symlink() { return None; }
    if fs::metadata(&path).await.ok()?.len() > MAX_JOURNAL_BYTES { return None; }
    let job: SavedJob = serde_json::from_slice(&fs::read(path).await.ok()?).ok()?;
    (job.schema_version == SCHEMA && (job.mode == "download" || job.mode == "repair") &&
        matches!(job.status.as_str(), "running" | "paused" | "pending") &&
        job.operation_id.len() <= 128).then_some(job)
}

async fn read(root: &Path) -> Option<SavedJob> {
    let first = read_slot(root, 0).await;
    let second = read_slot(root, 1).await;
    match (first, second) {
        (Some(a), Some(b)) => Some(if a.generation >= b.generation { a } else { b }),
        (Some(a), None) | (None, Some(a)) => Some(a),
        _ => None,
    }
}

async fn write(root: &Path, job: &SavedJob) -> Result<(), String> {
    let dir = root.join(".neverlauncher");
    fs::create_dir_all(&dir).await.map_err(|e| format!("create journal directory: {e}"))?;
    crate::file_ownership::ensure_no_symlinks(root, &dir)?;
    let bytes = serde_json::to_vec(job).map_err(|e| format!("serialize job: {e}"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES { return Err("download journal exceeds size limit".into()); }
    let target = journal_path(root, (job.generation % 2) as usize);
    let tmp = dir.join(format!("download-job-{:016x}.tmp", rand::random::<u64>()));
    let outcome = async {
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).await.map_err(|e| e.to_string())?;
        output.write_all(&bytes).await.map_err(|e| e.to_string())?;
        output.sync_all().await.map_err(|e| e.to_string())?;
        drop(output);
        if fs::try_exists(&target).await.map_err(|e| e.to_string())? {
            // The other generation always remains intact until this slot is published.
            fs::remove_file(&target).await.map_err(|e| e.to_string())?;
        }
        fs::rename(&tmp, target).await.map_err(|e| e.to_string())
    }.await;
    if outcome.is_err() { let _ = fs::remove_file(&tmp).await; }
    outcome
}

async fn erase(root: &Path) {
    for slot in 0..2 {
        let _ = fs::remove_file(journal_path(root, slot)).await;
    }
}

fn register(root: &Path) -> Result<(ActiveGuard, watch::Receiver<Directive>), String> {
    let mut guard = active().lock().map_err(|_| "active download registry poisoned")?;
    if guard.contains_key(root) { return Err("a download or repair operation is already active for this install directory".into()); }
    let (sender, receiver) = watch::channel(Directive::Running);
    guard.insert(root.to_path_buf(), sender);
    Ok((ActiveGuard(root.to_path_buf()), receiver))
}

async fn perform(root: &Path, job: SavedJob, sink: Option<ProgressSink>,
    rx: watch::Receiver<Directive>) -> Result<DownloadResult, String> {
    verify_manifest_signature(&job.manifest, &job.pinned_public_key)?;
    file_ownership::validate_download_targets(&job.manifest)?;
    let outcome = crate::transactional_release::install(&job.manifest, root, &job.pinned_public_key, sink,
        job.operation_id.clone(), rx.clone(), job.preset.clone()).await;
    let stopped = *rx.borrow();
    if stopped == Directive::Cancelled { erase(root).await; }
    else if stopped == Directive::Paused {
        if let Some(mut saved) = read(root).await {
            saved.status = "paused".into(); saved.generation += 1;
            write(root, &saved).await?;
        }
    } else if let Ok(ref result) = outcome {
        if result.failed == 0 { erase(root).await; }
        else if let Some(mut saved) = read(root).await {
            saved.status = "pending".into(); saved.generation += 1;
            write(root, &saved).await?;
        }
    }
    outcome
}

pub async fn start(manifest:&Manifest,root:&Path,key:&str,mode:&str,sink:Option<ProgressSink>)->Result<DownloadResult,String>{
    start_with_preset(manifest,root,key,mode,sink,None).await
}
pub async fn start_with_preset(manifest: &Manifest, root: &Path, key: &str, mode: &str,
    sink: Option<ProgressSink>, preset:Option<String>) -> Result<DownloadResult, String> {
    if !matches!(mode, "download" | "repair") { return Err("invalid operation mode".into()); }
    verify_manifest_signature(manifest, key)?;
    file_ownership::validate_download_targets(manifest)?;
    crate::component_catalog_0241::active_files(manifest,preset.as_deref())?;
    let root = normalized(root).await?;
    let (_guard, rx) = register(&root)?;
    let prev_generation = read(&root).await.map_or(0, |job| job.generation);
    let job = SavedJob {
        schema_version: SCHEMA, generation: prev_generation + 1,
        operation_id: format!("{}-{:016x}", std::process::id(), rand::random::<u64>()),
        mode: mode.into(), status: "running".into(), pinned_public_key: key.into(), manifest: manifest.clone(), preset,
    };
    write(&root, &job).await?;
    perform(&root, job, sink, rx).await
}

pub async fn pending(root: &Path, expected_pinned_key: &str) -> Result<Option<PendingDownload>, String> {
    if !fs::try_exists(root).await.map_err(|e| e.to_string())? { return Ok(None); }
    let root = normalized(root).await?;
    let Some(job) = read(&root).await else { return Ok(None); };
    // The journal is user-writable: it MUST NOT set its own trust root.
    if expected_pinned_key.trim().is_empty() || !job.pinned_public_key.eq_ignore_ascii_case(expected_pinned_key.trim()) {
        return Err("saved download public key differs from Desktop pinned trust key".into());
    }
    verify_manifest_signature(&job.manifest, expected_pinned_key)?;
    Ok(Some(PendingDownload { operation_id: job.operation_id, mode: job.mode, status: job.status,
        project_id: job.manifest.project_id, profile_id: job.manifest.profile_id,
        version: job.manifest.version, total_files: job.manifest.files.len() }))
}

pub async fn resume(root: &Path, expected_pinned_key: &str, sink: Option<ProgressSink>) -> Result<DownloadResult, String> {
    let root = normalized(root).await?;
    let (_guard, rx) = register(&root)?;
    let mut job = read(&root).await.ok_or("no durable download job to resume")?;
    if expected_pinned_key.trim().is_empty() || !job.pinned_public_key.eq_ignore_ascii_case(expected_pinned_key.trim()) {
        return Err("saved download public key differs from Desktop pinned trust key".into());
    }
    verify_manifest_signature(&job.manifest, expected_pinned_key)?;
    file_ownership::validate_download_targets(&job.manifest)?;
    job.generation += 1;
    job.status = "running".into();
    write(&root, &job).await?;
    perform(&root, job, sink, rx).await
}

pub async fn control(root: &Path, action: &str) -> Result<(), String> {
    if !matches!(action, "pause" | "cancel") { return Err("invalid download control action".into()); }
    let root = normalized(root).await?;
    let sender = active().lock().map_err(|_| "active download registry poisoned")?
        .get(&root).cloned();
    let directive = if action == "pause" { Directive::Paused } else { Directive::Cancelled };
    if let Some(sender) = sender {
        // Stop network waits immediately; persist the requested intent before
        // acknowledging it, so Desktop termination right after the click is safe.
        sender.send_replace(directive);
    }
    if action == "cancel" {
        erase(&root).await;
    } else {
        let mut job = read(&root).await.ok_or("no durable job to pause")?;
        job.generation += 1;
        job.status = "paused".into();
        write(&root, &job).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_manifest;
    use sha2::{Digest, Sha256};
    use serde_json::json;
    use std::{sync::{Arc, Mutex}, time::Duration};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, sync::oneshot};

    async fn read_headers(stream: &mut tokio::net::TcpStream) -> String {
        let mut data = Vec::new();
        let mut bytes = [0u8; 1024];
        loop {
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(n > 0);
            data.extend_from_slice(&bytes[..n]);
            if data.windows(4).any(|chunk| chunk == b"\r\n\r\n") { break; }
        }
        String::from_utf8(data).unwrap()
    }

    #[tokio::test]
    async fn paused_signed_job_is_persisted_and_resumes_only_suffix_after_restarting_runtime() {
        let payload = b"0123456789ABCDEFGHIJ";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let (sent, received) = oneshot::channel();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let first_headers = read_headers(&mut first).await;
            observed.lock().unwrap().push(first_headers);
            first.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n01234567").await.unwrap();
            let _ = sent.send(());
            // The first response remains open until the caller explicitly pauses.
            let (mut second, _) = listener.accept().await.unwrap();
            let second_headers = read_headers(&mut second).await;
            observed.lock().unwrap().push(second_headers);
            second.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 12\r\nContent-Range: bytes 8-19/20\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n89ABCDEFGHIJ").await.unwrap();
            let _ = second.shutdown().await;
        });
        let mut manifest: Manifest = serde_json::from_value(json!({
            "schemaVersion": "1.0", "projectId": "test", "profileId": "test", "channel": "stable",
            "version": "1", "createdAt": "test", "minecraft": { "version": "1.21.1", "loader": "vanilla" },
            "runtime": { "java": { "majorVersion": 21, "distribution": "temurin" } },
            "files": [{ "path": "libraries/large.jar", "url": url, "size": payload.len(),
                "sha256": hex::encode(Sha256::digest(payload)), "required": true, "executable": false }]
        })).unwrap();
        let key = sign_manifest(&mut manifest, &hex::encode([1u8; 32]), "2026-10-19T00:00:00Z").unwrap();
        let root = std::env::temp_dir().join(format!("nl-durable-{:016x}", rand::random::<u64>()));
        let root2 = root.clone();
        let trust_key = key.clone();
        let worker = tokio::spawn(async move { start(&manifest, &root2, &key, "repair", None).await });
        received.await.unwrap();
        // Allow the first chunk to reach the filesystem before the pause signal.
        tokio::time::sleep(Duration::from_millis(100)).await;
        control(&root, "pause").await.unwrap();
        let paused = tokio::time::timeout(Duration::from_secs(4), worker).await.unwrap().unwrap().unwrap();
        assert_eq!(paused.downloaded, 0);
        assert_eq!(pending(&root, &trust_key).await.unwrap().unwrap().status, "paused");
        assert_eq!(pending(&root, &trust_key).await.unwrap().unwrap().mode, "repair");
        assert!(pending(&root, &hex::encode([2u8; 32])).await.is_err());
        // A new invocation (and HTTP client) only depends on durable on-disk state.
        let restored = tokio::time::timeout(Duration::from_secs(5), resume(&root, &trust_key, None)).await.unwrap().unwrap();
        assert_eq!(restored.downloaded, 1, "{:?}", restored.messages);
        assert_eq!(restored.bytes_downloaded, 12);
        assert_eq!(fs::read(root.join("libraries/large.jar")).await.unwrap(), payload);
        assert!(pending(&root, &trust_key).await.unwrap().is_none());
        server.await.unwrap();
        let requests = requests.lock().unwrap();
        assert!(requests[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(requests[1].to_ascii_lowercase().contains("if-range: \"v1\""));
        drop(requests);
        fs::remove_dir_all(root).await.unwrap();
    }
}
