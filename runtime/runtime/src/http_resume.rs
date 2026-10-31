//! Restart-safe HTTP file transfer for signed manifests.
//!
//! Partial bytes are never trusted by themselves: a strong HTTP validator gates
//! Range reuse and the signed SHA-256 authenticates the complete staged file
//! before it is switched into the client installation.
use crate::{file_ownership, network_resilience::{self, Directive},
    replace_verified_managed_file_0224, set_executable_if_needed, ManifestFile};
use reqwest::{header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, ETAG, RANGE, IF_RANGE, ACCEPT_ENCODING}, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, Weak}};
use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}, sync::{Mutex as AsyncMutex, watch}};

const PARTIAL_SCHEMA: u32 = 1;
const META_MAX_SIZE: u64 = 8192;
// A CDN may cap each 206 response below the requested end. Continue fetching
// subsequent ranges without consuming the retry budget for healthy responses.
const MAX_RANGE_SEGMENTS: usize = 256;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartialMetadata {
    schema_version: u32,
    url: String,
    expected_sha256: String,
    expected_size: u64,
    /// Only strong entity tags can be sent in If-Range.
    etag: Option<String>,
}

impl PartialMetadata {
    fn matches(&self, file: &ManifestFile) -> bool {
        self.schema_version == PARTIAL_SCHEMA &&
        self.expected_size == file.size &&
        self.expected_sha256.eq_ignore_ascii_case(&file.sha256) &&
        self.etag.as_deref().map_or(true, strong_etag)
    }
}

static FILE_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<AsyncMutex<()>>>>> = OnceLock::new();

fn file_mutex(path: &Path) -> Arc<AsyncMutex<()>> {
    let mut locks = FILE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
        .lock().expect("partial transfer lock poisoned");
    locks.retain(|_, lock| lock.strong_count() > 0);
    let key = path.to_path_buf();
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) { return lock }
    let lock = Arc::new(AsyncMutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn partial_paths(root: &Path, target: &Path) -> Result<(PathBuf, PathBuf), String> {
    // Keep internal state out of user-owned directories, where a user might
    // legitimately have a file called *.part or *.json.
    let relative = target.strip_prefix(root).map_err(|_| "target outside install root")?;
    let id = hex::encode(Sha256::digest(relative.to_string_lossy().as_bytes()));
    let directory = root.join(".launcher").join("downloads").join(&id[..2]);
    Ok((directory.join(format!("{id}.part")), directory.join(format!("{id}.part.json"))))
}

fn strong_etag(etag: &str) -> bool {
    // ETag is an opaque, quoted, strong validator (RFC 9110 section 8.8.3).
    // Never use weak validators or strings containing CR/LF in HTTP headers.
    etag.len() >= 2 && etag.starts_with('"') && etag.ends_with('"') &&
        !etag.as_bytes()[1..etag.len()-1].iter().any(|b| *b < 0x21 || *b == b'"' || *b == 0x7f)
}

fn response_etag(response: &reqwest::Response) -> Option<String> {
    response.headers().get(ETAG).and_then(|value| value.to_str().ok())
        .filter(|value| strong_etag(value)).map(ToOwned::to_owned)
}

fn check_identity_encoding(response: &reqwest::Response) -> Result<(), String> {
    if let Some(encoding) = response.headers().get(CONTENT_ENCODING) {
        if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
            return Err("non-identity Content-Encoding is forbidden for signed files".into());
        }
    }
    Ok(())
}

fn content_length(response: &reqwest::Response) -> Result<Option<u64>, String> {
    response.headers().get(CONTENT_LENGTH).map(|value| {
        value.to_str().map_err(|_| "non-UTF8 Content-Length".to_string())?
            .parse::<u64>().map_err(|_| "invalid Content-Length".to_string())
    }).transpose()
}

fn expected_range(response: &reqwest::Response, start: u64, total: u64) -> Result<u64, String> {
    // Strict single-range parsing. No wildcard totals, multipart or unsatisfied ranges.
    let value = response.headers().get(CONTENT_RANGE)
        .ok_or("206 response without Content-Range")?
        .to_str().map_err(|_| "invalid Content-Range encoding")?;
    let range = value.strip_prefix("bytes ").ok_or("invalid Content-Range unit")?;
    let (bounds, total_str) = range.split_once('/').ok_or("invalid Content-Range")?;
    let (low, high) = bounds.split_once('-').ok_or("invalid Content-Range bounds")?;
    let first = low.parse::<u64>().map_err(|_| "invalid Content-Range start")?;
    let last = high.parse::<u64>().map_err(|_| "invalid Content-Range end")?;
    let complete = total_str.parse::<u64>().map_err(|_| "invalid Content-Range total")?;
    if first != start || last < first || complete != total || last >= total {
        return Err(format!("unsafe Content-Range: {value}, requested {start}-/{total}"));
    }
    let length = last - first + 1;
    if content_length(response)?.is_some_and(|reported| reported != length) {
        return Err("Content-Length does not match Content-Range".into());
    }
    Ok(length)
}

fn check_full_response(response: &reqwest::Response, size: u64) -> Result<(), String> {
    if response.status() != StatusCode::OK { return Err(format!("expected HTTP 200, got {}", response.status())) }
    if response.headers().contains_key(CONTENT_RANGE) {
        return Err("HTTP 200 unexpectedly includes Content-Range".into());
    }
    if content_length(response)?.is_some_and(|len| len != size) {
        return Err("Content-Length differs from signed manifest".into());
    }
    check_identity_encoding(response)
}

async fn remove_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove partial {}: {err}", path.display())),
    }
}

async fn discard(part: &Path, meta: &Path) -> Result<(), String> {
    remove_if_present(part).await?;
    remove_if_present(meta).await
}

async fn read_metadata(path: &Path) -> Option<PartialMetadata> {
    if fs::metadata(path).await.ok()?.len() > META_MAX_SIZE { return None }
    serde_json::from_slice(&fs::read(path).await.ok()?).ok()
}

async fn store_metadata(root: &Path, meta_path: &Path, data: &PartialMetadata) -> Result<(), String> {
    let payload = serde_json::to_vec(data).map_err(|e| e.to_string())?;
    let name = meta_path.file_name().ok_or("invalid metadata name")?.to_string_lossy();
    let tmp = meta_path.with_file_name(format!("{name}.tmp-{:016x}", rand::random::<u64>()));
    let outcome = async {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).await
            .map_err(|e| format!("create partial metadata: {e}"))?;
        file.write_all(&payload).await.map_err(|e| format!("write partial metadata: {e}"))?;
        file.sync_all().await.map_err(|e| format!("fsync partial metadata: {e}"))?;
        drop(file);
        // A mirror switch must persist the new source identity before appending.
        // Replace atomically on Windows too; never expose a missing validator.
        crate::platform_fs::replace_file(root, &tmp, meta_path)
            .map_err(|e| format!("publish partial metadata: {e}"))
    }.await;
    if outcome.is_err() { let _ = fs::remove_file(&tmp).await; }
    outcome
}

async fn digest_existing(path: &Path) -> Result<(u64, Sha256), String> {
    let mut input = fs::File::open(path).await.map_err(|e| format!("open partial for hashing: {e}"))?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).await.map_err(|e| format!("hash partial: {e}"))?;
        if count == 0 { break }
        size = size.checked_add(count as u64).ok_or("partial length overflow")?;
        digest.update(&buffer[..count]);
    }
    Ok((size, digest))
}

async fn install_verified(root: &Path, file: &ManifestFile, target: &Path, part: &Path, meta: &Path) -> Result<(), String> {
    file_ownership::ensure_no_symlinks(root, target)?;
    replace_verified_managed_file_0224(part, target).await?;
    set_executable_if_needed(target, file.executable).await?;
    remove_if_present(meta).await
}

fn request_error(path: &str, error: String) -> String {
    if error.starts_with("[retry:") || error == "download paused" || error == "download cancelled" {
        error
    } else { format!("{path}: HTTP request: {error}") }
}

async fn request_with_control(client: &reqwest::Client, url: &str,
    range: Option<(u64, Option<&str>)>, control: &mut watch::Receiver<Directive>) -> Result<reqwest::Response, String> {
    network_resilience::check(control)?;
    let mut request = client.get(url).header(ACCEPT_ENCODING, "identity");
    if let Some((start, validator)) = range {
        request = request.header(RANGE, format!("bytes={start}-"));
        // Validators are scoped to a single origin. Across signed mirrors,
        // Range is only a bandwidth optimization: the full digest is authority.
        if let Some(validator) = validator { request = request.header(IF_RANGE, validator); }
    }
    let response = tokio::select! {
        result = tokio::time::timeout(network_resilience::REQUEST_TIMEOUT, request.send()) => {
            match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(network_resilience::transient(format!("HTTP connect/request: {error}"), None)),
                Err(_) => return Err(network_resilience::transient("HTTP request timed out", None)),
            }
        },
        state = network_resilience::interrupted(control) => return Err(state.error().into()),
    };
    if network_resilience::retryable_status(response.status()) {
        let wait = network_resilience::retry_after(&response);
        return Err(network_resilience::transient(format!("transient HTTP {}", response.status()), wait));
    }
    Ok(response)
}

/// Resume a verified-manifest file, optionally using a persistent partial from
/// an interrupted prior invocation. `transferred` accounts for *wire* body bytes.
/// Both Desktop downloads and Repair call this via download_scheduler::run.
pub(crate) async fn download_verified(
    client: &reqwest::Client, root: &Path, file: &ManifestFile, target: &Path,
    transferred: impl Fn(u64),
) -> Result<(), String> {
    let (_sender, receiver) = watch::channel(Directive::Running);
    download_verified_controlled(client, root, file, target, transferred, receiver).await
}

pub(crate) async fn download_verified_controlled(
    client: &reqwest::Client, root: &Path, file: &ManifestFile, target: &Path,
    transferred: impl Fn(u64), control: watch::Receiver<Directive>,
) -> Result<(), String> {
    let lock = file_mutex(target);
    let _guard = lock.lock().await;
    for _ in 0..MAX_RANGE_SEGMENTS {
        if download_verified_segment(client, root, file, target, &transferred, control.clone()).await? {
            return Ok(());
        }
    }
    Err(network_resilience::transient(
        "server supplied too many bounded HTTP ranges; partial retained", None))
}

/// A single full response or a bounded range. Returns false only when the
/// server supplied a verified-length prefix and another range is required.
async fn download_verified_segment(
    client: &reqwest::Client, root: &Path, file: &ManifestFile, target: &Path,
    transferred: impl Fn(u64), mut control: watch::Receiver<Directive>,
) -> Result<bool, String> {
    network_resilience::check(&control)?;
    file_ownership::ensure_no_symlinks(root, target)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await.map_err(|e| format!("{}: mkdir: {e}", file.path))?;
    }
    let (part, meta) = partial_paths(root, target)?;
    file_ownership::ensure_no_symlinks(root, &part)?;
    file_ownership::ensure_no_symlinks(root, &meta)?;
    fs::create_dir_all(part.parent().ok_or("invalid partial directory")?).await
        .map_err(|e| format!("{}: create partial storage: {e}", file.path))?;
    file_ownership::ensure_no_symlinks(root, &part)?;
    file_ownership::ensure_no_symlinks(root, &meta)?;

    let exists_part = fs::try_exists(&part).await.map_err(|e| e.to_string())?;
    let exists_meta = fs::try_exists(&meta).await.map_err(|e| e.to_string())?;
    let previous = if exists_part && exists_meta { read_metadata(&meta).await } else { None };
    // Reuse an existing prefix on the same origin only with its strong ETag.
    // A different signed mirror may serve the remaining suffix without an
    // origin-specific If-Range; final SHA-256 authenticates the combined file.
    let mut resume = None;
    if let Some(state) = previous.filter(|m| m.matches(file)) {
        let len = fs::metadata(&part).await.map_err(|e| e.to_string())?.len();
        if len == file.size {
            let (actual_len, hash) = digest_existing(&part).await?;
            if actual_len == file.size && hex::encode(hash.finalize()).eq_ignore_ascii_case(&file.sha256) {
                network_resilience::check(&control)?;
                install_verified(root, file, target, &part, &meta).await?;
                return Ok(true);
            }
        }
        if len > 0 && len < file.size {
            if state.url == file.url {
                if let Some(etag) = state.etag { resume = Some((len, Some(etag))); }
            } else {
                resume = Some((len, None));
            }
        }
    }
    if resume.is_none() { discard(&part, &meta).await?; }

    let mut response = request_with_control(client, &file.url,
        resume.as_ref().map(|(start, etag)| (*start, etag.as_deref())), &mut control).await
        .map_err(|e| request_error(&file.path, e))?;
    let mut append = false;
    let mut prefix_len = 0u64;
    let mut allowed_body_len = file.size;
    if let Some((start, expected_etag)) = &resume {
        match response.status() {
            StatusCode::PARTIAL_CONTENT => {
                let valid = check_identity_encoding(&response)
                    .and_then(|_| expected_range(&response, *start, file.size))
                    .and_then(|length| {
                        if expected_etag.as_deref().is_some_and(|expected|
                            response_etag(&response).as_deref() != Some(expected)) {
                            return Err("206 response lacks the original strong ETag".into());
                        }
                        Ok(length)
                    });
                match valid {
                    Ok(length) => {
                        if expected_etag.is_none() {
                            // Persist new mirror identity atomically before writing
                            // any mixed-origin bytes. A later retry must not send
                            // the former origin's validator to this mirror.
                            store_metadata(root, &meta, &PartialMetadata {
                                schema_version: PARTIAL_SCHEMA, url: file.url.clone(),
                                expected_sha256: file.sha256.clone(), expected_size: file.size,
                                etag: response_etag(&response),
                            }).await?;
                        }
                        append = true;
                        prefix_len = *start;
                        allowed_body_len = length;
                    }
                    Err(_) => {
                        // Malformed/mismatched 206 can never be appended. Discard
                        // this response and fetch a clean 200 (not a second Range).
                        drop(response);
                        discard(&part, &meta).await?;
                        response = request_with_control(client, &file.url, None, &mut control).await
                            .map_err(|e| request_error(&file.path, e))?;
                    }
                }
            }
            StatusCode::OK => {
                // If-Range validator changed or server ignored Range. This is
                // a complete representation; never concatenate with old bytes.
                discard(&part, &meta).await?;
            }
            StatusCode::RANGE_NOT_SATISFIABLE => {
                // A 416 can mean the remote object shrank or the Range was
                // rejected. The local prefix has no authority over the server.
                drop(response);
                discard(&part, &meta).await?;
                response = request_with_control(client, &file.url, None, &mut control).await
                    .map_err(|e| request_error(&file.path, e))?;
            }
            status => return Err(format!("{}: resume HTTP {status}", file.path)),
        }
    }
    if append {
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(format!("{}: expected HTTP 206", file.path));
        }
    } else {
        check_full_response(&response, file.size).map_err(|e| format!("{}: {e}", file.path))?;
        // Note: a failed initial full response leaves any previous partial
        // untouched only when it is still eligible for a subsequent safe resume.
        discard(&part, &meta).await?;
        let state = PartialMetadata { schema_version: PARTIAL_SCHEMA, url: file.url.clone(),
            expected_sha256: file.sha256.clone(), expected_size: file.size,
            etag: response_etag(&response) };
        store_metadata(root, &meta, &state).await?;
    }

    let mut digest = Sha256::new();
    if append {
        let (len, prefix_hash) = digest_existing(&part).await?;
        if len != prefix_len { return Err(format!("{}: partial modified concurrently", file.path)) }
        digest = prefix_hash;
    }
    let mut output = fs::OpenOptions::new().write(true).create(!append).append(append)
        .truncate(!append).open(&part).await
        .map_err(|e| format!("{}: open partial: {e}", file.path))?;
    let mut body_len = 0u64;
    loop {
        let packet = tokio::select! {
            result = tokio::time::timeout(network_resilience::READ_TIMEOUT, response.chunk()) => result,
            state = network_resilience::interrupted(&mut control) => {
                output.flush().await.map_err(|e| format!("flush partial on pause/cancel: {e}"))?;
                output.sync_all().await.map_err(|e| format!("fsync partial on pause/cancel: {e}"))?;
                return Err(state.error().into());
            }
        };
        let chunk = match packet {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                output.flush().await.map_err(|io| format!("{}: flush partial: {io}", file.path))?;
                output.sync_all().await.map_err(|io| format!("{}: fsync partial: {io}", file.path))?;
                return Err(network_resilience::transient(format!("{}: interrupted HTTP body: {error}", file.path), None));
            },
            Err(_) => {
                output.flush().await.map_err(|io| format!("{}: flush partial: {io}", file.path))?;
                output.sync_all().await.map_err(|io| format!("{}: fsync partial: {io}", file.path))?;
                return Err(network_resilience::transient(format!("{}: read timeout", file.path), None));
            }
        };
        transferred(chunk.len() as u64);
        if chunk.len() as u64 > allowed_body_len.saturating_sub(body_len) {
            drop(output);
            discard(&part, &meta).await?;
            return Err(format!("{}: HTTP body exceeds declared/signed size", file.path));
        }
        for piece in chunk.chunks(64 * 1024) {
            output.write_all(piece).await.map_err(|e| format!("{}: write partial: {e}", file.path))?;
            digest.update(piece);
            body_len += piece.len() as u64;
        }
    }
    output.flush().await.map_err(|e| format!("{}: flush partial: {e}", file.path))?;
    output.sync_all().await.map_err(|e| format!("{}: fsync partial: {e}", file.path))?;
    drop(output);
    if body_len != allowed_body_len {
        // A short, well-formed HTTP body is still a resumable interruption
        // when the strong ETag remains pinned; never activate it.
        return Err(network_resilience::transient(format!("{}: truncated HTTP body ({body_len}/{allowed_body_len})", file.path), None));
    }
    if prefix_len + body_len != file.size {
        // A valid but capped 206 response is not a failure. Its strong ETag
        // remains pinned for the next Range within this same operation.
        return Ok(false);
    }
    if !hex::encode(digest.finalize()).eq_ignore_ascii_case(&file.sha256) {
        discard(&part, &meta).await?;
        if append {
            // Prefix corruption or divergent mirror bytes must never activate.
            // Retry this source from byte zero before giving up or falling back.
            return Err(network_resilience::transient(
                format!("{}: resumed SHA-256 mismatch; retrying full file", file.path), None));
        }
        return Err(format!("{}: complete SHA-256 verification failed", file.path));
    }
    network_resilience::check(&control)?;
    install_verified(root, file, target, &part, &meta).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

    struct Reply {
        status: &'static str,
        headers: Vec<(String, String)>,
        bytes: Vec<u8>,
    }
    fn response(status: &'static str, etag: Option<&str>, data: &[u8], declared: u64) -> Reply {
        let mut headers = vec![("Content-Length".into(), declared.to_string())];
        if let Some(tag) = etag { headers.push(("ETag".into(), tag.into())); }
        Reply { status, headers, bytes: data.to_vec() }
    }

    async fn mock_http(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/file", server.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = server.accept().await.unwrap();
                let mut header = Vec::new();
                let mut buf = [0u8; 1024];
                while !header.ends_with(b"\r\n\r\n") {
                    let count = stream.read(&mut buf).await.unwrap();
                    if count == 0 { return }
                    header.extend_from_slice(&buf[..count]);
                    if header.len() > 16384 { panic!("oversized HTTP request") }
                    if header.windows(4).any(|w| w == b"\r\n\r\n") { break }
                }
                observed.lock().unwrap().push(String::from_utf8(header).unwrap());
                let mut payload = format!("HTTP/1.1 {}\r\nConnection: close\r\n", reply.status);
                for (name, value) in reply.headers { payload.push_str(&format!("{name}: {value}\r\n")); }
                payload.push_str("\r\n");
                stream.write_all(payload.as_bytes()).await.unwrap();
                stream.write_all(&reply.bytes).await.unwrap();
                let _ = stream.shutdown().await;
            }
        });
        (url, requests, task)
    }

    fn file(url: String, data: &[u8]) -> ManifestFile {
        ManifestFile { path: "libraries/data.jar".into(), url, size: data.len() as u64,
            sha256: hex::encode(Sha256::digest(data)), mirrors: vec![], required: true, executable: false,
            target_os: vec![], ownership: "required".into() }
    }

    async fn workspace() -> PathBuf {
        let root = std::env::temp_dir().join(format!("nl-http-resume-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(root.join("libraries")).await.unwrap();
        root
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .build().unwrap()
    }

    #[tokio::test]
    async fn interrupted_transfer_persists_validator_and_sends_if_range_after_restart() {
        let data = b"0123456789ABCDEFGHIJ";
        let first = response("200 OK", Some("\"v1\""), &data[..8], data.len() as u64);
        let mut second = response("206 Partial Content", Some("\"v1\""), &data[8..], 12);
        second.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let (url, requests, server) = mock_http(vec![first, second]).await;
        let f = file(url, data);
        let root = workspace().await;
        let target = root.join(&f.path);
        let transferred = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let result = download_verified(&client(), &root, &f, &target, |n| {
            transferred.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }).await;
        assert!(result.is_err(), "truncated response was accepted");
        let (part, metadata) = partial_paths(&root, &target).unwrap();
        assert_eq!(fs::read(&part).await.unwrap(), &data[..8]);
        assert_eq!(read_metadata(&metadata).await.unwrap().etag.as_deref(), Some("\"v1\""));
        // New HTTP client and invocation model process restart semantics.
        download_verified(&client(), &root, &f, &target, |n| {
            transferred.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        assert!(!fs::try_exists(&part).await.unwrap());
        assert!(!fs::try_exists(&metadata).await.unwrap());
        assert_eq!(transferred.load(std::sync::atomic::Ordering::Relaxed), 20);
        server.await.unwrap();
        let history = requests.lock().unwrap();
        assert_eq!(history.len(), 2);
        assert!(!history[0].to_ascii_lowercase().contains("range: bytes="));
        assert!(history[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(history[1].to_ascii_lowercase().contains("if-range: \"v1\""));
        drop(history);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn changed_etag_and_http_200_never_append_old_content() {
        let old = b"OOOOOOOOOOabcdefghij";
        let new = b"NNNNNNNNNNabcdefghij";
        let replies = vec![
            response("200 OK", Some("\"old\""), &old[..10], 20),
            response("200 OK", Some("\"new\""), new, 20),
        ];
        let (url, history, server) = mock_http(replies).await;
        let root = workspace().await;
        let f = file(url, new);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(target).await.unwrap(), new);
        server.await.unwrap();
        assert!(history.lock().unwrap()[1].to_ascii_lowercase().contains("if-range: \"old\""));
        fs::remove_dir_all(root).await.unwrap();
    }

    async fn corrupted_resume_response_is_restarted(invalid: Reply) {
        let data = b"0123456789ABCDEFGHIJ";
        let replies = vec![
            response("200 OK", Some("\"fixed\""), &data[..8], 20),
            invalid,
            response("200 OK", Some("\"fixed\""), data, 20),
        ];
        let (url, requests, server) = mock_http(replies).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(target).await.unwrap(), data);
        server.await.unwrap();
        let history = requests.lock().unwrap();
        assert_eq!(history.len(), 3);
        assert!(history[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(!history[2].to_ascii_lowercase().contains("range: bytes="));
        drop(history);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn malformed_content_range_must_fallback_to_fresh_get() {
        let mut invalid = response("206 Partial Content", Some("\"fixed\""), b"garbage", 7);
        invalid.headers.push(("Content-Range".into(), "bytes 9-15/20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn response_etag_mismatch_on_206_forces_fresh_get() {
        let mut invalid = response("206 Partial Content", Some("\"changed\""), b"garbage", 7);
        invalid.headers.push(("Content-Range".into(), "bytes 8-14/20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn range_not_satisfiable_forces_fresh_get() {
        let mut invalid = response("416 Range Not Satisfiable", Some("\"fixed\""), b"", 0);
        invalid.headers.push(("Content-Range".into(), "bytes */20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn incorrect_partial_content_length_forces_fresh_get() {
        let mut invalid = response("206 Partial Content", Some("\"fixed\""), b"garbage", 7);
        invalid.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        corrupted_resume_response_is_restarted(invalid).await;
    }

    #[tokio::test]
    async fn wrong_hash_discards_partial_and_preserves_previous_target() {
        let correct = b"expected";
        let (url, _, server) = mock_http(vec![response("200 OK", Some("\"t1\""), b"BAD_DATA", 8)]).await;
        let root = workspace().await;
        let f = file(url, correct);
        let target = root.join(&f.path);
        fs::write(&target, b"original client data").await.unwrap();
        let result = download_verified(&client(), &root, &f, &target, |_| {}).await;
        assert!(result.unwrap_err().contains("SHA-256"));
        assert_eq!(fs::read(&target).await.unwrap(), b"original client data");
        let (part, meta) = partial_paths(&root, &target).unwrap();
        assert!(!fs::try_exists(part).await.unwrap());
        assert!(!fs::try_exists(meta).await.unwrap());
        server.await.unwrap();
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn weak_or_missing_validator_never_triggers_range_reuse() {
        let data = b"0123456789ABCDEFGHIJ";
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("W/\"weak\""), &data[..7], 20),
            response("200 OK", Some("\"strong\""), data, 20),
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(target).await.unwrap(), data);
        server.await.unwrap();
        let observed = history.lock().unwrap();
        assert!(!observed[1].to_ascii_lowercase().contains("range: bytes="));
        drop(observed);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn stale_signed_identity_or_corrupt_metadata_is_not_reused() {
        let data = b"0123456789ABCDEFGHIJ";
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("\"v3\""), data, 20),
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        let (part, meta) = partial_paths(&root, &target).unwrap();
        fs::create_dir_all(part.parent().unwrap()).await.unwrap();
        fs::write(&part, b"old bytes").await.unwrap();
        fs::write(&meta, b"{broken metadata").await.unwrap();
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        assert!(!fs::try_exists(&part).await.unwrap());
        server.await.unwrap();
        assert!(!history.lock().unwrap()[0].to_ascii_lowercase().contains("range: bytes="));
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn completed_partial_from_prior_process_installs_without_network() {
        let data = b"complete signed artifact";
        // Deliberately unreachable URL: no request should be issued.
        let root = workspace().await;
        let f = file("http://127.0.0.1:1/unreachable".into(), data);
        let target = root.join(&f.path);
        let (part, meta) = partial_paths(&root, &target).unwrap();
        fs::create_dir_all(part.parent().unwrap()).await.unwrap();
        fs::write(&part, data).await.unwrap();
        store_metadata(&root, &meta, &PartialMetadata {
            schema_version: PARTIAL_SCHEMA, url: f.url.clone(),
            expected_sha256: f.sha256.clone(), expected_size: f.size,
            etag: Some("\"cached\"".into()),
        }).await.unwrap();
        download_verified(&client(), &root, &f, &target, |_| panic!("network body consumed"))
            .await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        assert!(!fs::try_exists(part).await.unwrap());
        assert!(!fs::try_exists(meta).await.unwrap());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn bounded_206_ranges_continue_without_restarting_or_consuming_retry_budget() {
        let data = b"0123456789ABCDEFGHIJ";
        let mut middle = response("206 Partial Content", Some("\"stable\""), &data[8..14], 6);
        middle.headers.push(("Content-Range".into(), "bytes 8-13/20".into()));
        let mut tail = response("206 Partial Content", Some("\"stable\""), &data[14..], 6);
        tail.headers.push(("Content-Range".into(), "bytes 14-19/20".into()));
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("\"stable\""), &data[..8], 20),
            middle, tail,
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        // One invocation chains both valid bounded responses, without throwing
        // away the first eight bytes or requiring an application-level retry.
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        server.await.unwrap();
        let h = history.lock().unwrap();
        assert_eq!(h.len(), 3);
        assert!(h[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(h[2].to_ascii_lowercase().contains("range: bytes=14-"));
        assert!(h[2].to_ascii_lowercase().contains("if-range: \"stable\""));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn failed_primary_mirror_resumes_suffix_without_leaking_origin_etag() {
        let data = b"0123456789ABCDEFGHIJ";
        let (primary, primary_history, primary_server) = mock_http(vec![
            response("200 OK", Some("\"primary\""), &data[..8], 20),
        ]).await;
        let mut suffix = response("206 Partial Content", Some("\"mirror\""), &data[8..], 12);
        suffix.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let (mirror, mirror_history, mirror_server) = mock_http(vec![suffix]).await;
        let root = workspace().await;
        let f = file(primary, data);
        let target = root.join(&f.path);
        fs::write(&target, b"previous client").await.unwrap();
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        assert_eq!(fs::read(&target).await.unwrap(), b"previous client");
        let mut alternate = f.clone();
        alternate.url = mirror;
        download_verified(&client(), &root, &alternate, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        primary_server.await.unwrap();
        mirror_server.await.unwrap();
        assert_eq!(primary_history.lock().unwrap().len(), 1);
        let h = mirror_history.lock().unwrap();
        assert_eq!(h.len(), 1);
        assert!(h[0].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(!h[0].to_ascii_lowercase().contains("if-range:"));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn interrupted_mirror_transfer_pins_new_origin_etag_before_resuming() {
        let data = b"0123456789ABCDEFGHIJ";
        let (primary, _, first_server) = mock_http(vec![
            response("200 OK", Some("\"origin-a\""), &data[..8], 20),
        ]).await;
        let mut interrupted = response("206 Partial Content", Some("\"origin-b\""), &data[8..13], 12);
        interrupted.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let mut finished = response("206 Partial Content", Some("\"origin-b\""), &data[13..], 7);
        finished.headers.push(("Content-Range".into(), "bytes 13-19/20".into()));
        let (mirror, requests, second_server) = mock_http(vec![interrupted, finished]).await;
        let root = workspace().await;
        let original = file(primary, data);
        let target = root.join(&original.path);
        assert!(download_verified(&client(), &root, &original, &target, |_| {}).await.is_err());
        let mut fallback = original.clone();
        fallback.url = mirror.clone();
        assert!(download_verified(&client(), &root, &fallback, &target, |_| {}).await.is_err());
        let (part, meta) = partial_paths(&root, &target).unwrap();
        assert_eq!(fs::read(&part).await.unwrap(), &data[..13]);
        let state = read_metadata(&meta).await.unwrap();
        assert_eq!(state.url, mirror);
        assert_eq!(state.etag.as_deref(), Some("\"origin-b\""));
        // Fresh invocation models a restarted Desktop after another outage.
        download_verified(&client(), &root, &fallback, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        first_server.await.unwrap();
        second_server.await.unwrap();
        let h = requests.lock().unwrap();
        assert_eq!(h.len(), 2);
        assert!(!h[0].to_ascii_lowercase().contains("if-range:"));
        assert!(h[1].to_ascii_lowercase().contains("range: bytes=13-"));
        assert!(h[1].to_ascii_lowercase().contains("if-range: \"origin-b\""));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn poisoned_partial_is_discarded_and_retry_from_zero_repairs_automatically() {
        let data = b"0123456789ABCDEFGHIJ";
        let mut resumed = response("206 Partial Content", Some("\"stable\""), &data[8..], 12);
        resumed.headers.push(("Content-Range".into(), "bytes 8-19/20".into()));
        let (url, history, server) = mock_http(vec![
            response("200 OK", Some("\"stable\""), &data[..8], 20),
            resumed,
            response("200 OK", Some("\"stable\""), data, 20),
        ]).await;
        let root = workspace().await;
        let f = file(url, data);
        let target = root.join(&f.path);
        fs::write(&target, b"previous working client").await.unwrap();
        assert!(download_verified(&client(), &root, &f, &target, |_| {}).await.is_err());
        let (part, meta) = partial_paths(&root, &target).unwrap();
        fs::write(&part, b"XXXXXXXX").await.unwrap();
        let error = download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap_err();
        assert!(network_resilience::retry_delay(&error, 0).is_some());
        assert!(!fs::try_exists(&part).await.unwrap());
        assert!(!fs::try_exists(&meta).await.unwrap());
        assert_eq!(fs::read(&target).await.unwrap(), b"previous working client");
        download_verified(&client(), &root, &f, &target, |_| {}).await.unwrap();
        assert_eq!(fs::read(&target).await.unwrap(), data);
        server.await.unwrap();
        let h = history.lock().unwrap();
        assert_eq!(h.len(), 3);
        assert!(h[1].to_ascii_lowercase().contains("range: bytes=8-"));
        assert!(!h[2].to_ascii_lowercase().contains("range: bytes="));
        drop(h);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn strict_http_range_parsing_and_weak_validator_rejection() {
        assert!(strong_etag("\"abc\""));
        assert!(!strong_etag("W/\"abc\""));
        assert!(!strong_etag("\"abc\r\n\""));
        assert!(!strong_etag("1234"));
    }
}
