//! Shared SHA-256 object store for verified client files. Objects are copied,
//! never hardlinked, into installations (players may subsequently modify them).
//! An in-process mutex and an OS file lock cover the entire check/fetch/publish
//! sequence so simultaneous profiles/processes fetch each object only once.
use crate::{file_ownership, replace_verified_managed_file_0224, set_executable_if_needed, ManifestFile};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock, Weak}};
use tokio::{fs, io::{AsyncReadExt, AsyncWriteExt}, sync::{Mutex as AsyncMutex, OwnedMutexGuard}};

static OBJECT_LOCKS: OnceLock<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>> = OnceLock::new();

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn lock_for(digest: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = OBJECT_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
        .lock().expect("object cache mutex map poisoned");
    locks.retain(|_, value| value.strong_count() > 0);
    if let Some(existing) = locks.get(digest).and_then(Weak::upgrade) { return existing; }
    let lock = Arc::new(AsyncMutex::new(()));
    locks.insert(digest.into(), Arc::downgrade(&lock));
    lock
}

fn user_cache_root() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let path = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join("AppData/Local")));
    #[cfg(target_os = "macos")]
    let path = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Caches"));
    #[cfg(not(any(windows, target_os = "macos")))]
    let path = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")));
    let base = path.ok_or("no user cache directory (HOME/LOCALAPPDATA missing)")?;
    if !base.is_absolute() { return Err("cache base must be absolute".into()); }
    Ok(base.join("NeverLauncher").join("content-v1"))
}

async fn directory(path: &Path) -> Result<(), String> {
    // Reject symlinks in the store's own directory tree, including the final
    // object directory. No symlink is ever followed when publishing an object.
    fs::create_dir_all(path).await.map_err(|e| format!("create content cache {}: {e}", path.display()))?;
    if fs::symlink_metadata(path).await.map_err(|e| e.to_string())?.file_type().is_symlink() {
        return Err(format!("cache directory is a symlink: {}", path.display()));
    }
    Ok(())
}

async fn existing_verified(path: &Path, file: &ManifestFile) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path).await {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("cache object metadata: {e}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != file.size {
        return Ok(false);
    }
    let mut reader = fs::File::open(path).await.map_err(|e| format!("open cache object: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = reader.read(&mut buffer).await.map_err(|e| format!("read cache object: {e}"))?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
        count += n as u64;
    }
    Ok(count == file.size && hex::encode(hasher.finalize()).eq_ignore_ascii_case(&file.sha256))
}

pub(crate) struct CacheStore { root: PathBuf }

impl CacheStore {
    pub(crate) fn standard() -> Result<Self, String> {
        Ok(Self { root: user_cache_root()? })
    }

    #[cfg(test)]
    pub(crate) fn at(root: PathBuf) -> Self { Self { root } }

    pub(crate) async fn lock(&self, file: &ManifestFile) -> Result<CacheLease, String> {
        if !valid_digest(&file.sha256) { return Err(format!("{}: malformed SHA-256", file.path)); }
        let digest = file.sha256.to_ascii_lowercase();
        let local = lock_for(&format!("{}:{digest}", self.root.display()));
        let guard = local.lock_owned().await;
        directory(&self.root).await?;
        let locks = self.root.join("locks");
        directory(&locks).await?;
        let lockdir = locks.join(&digest[..2]);
        directory(&lockdir).await?;
        let objects = self.root.join("sha256");
        directory(&objects).await?;
        let objdir = objects.join(&digest[..2]);
        directory(&objdir).await?;
        let lockpath = lockdir.join(format!("{digest}.lock"));
        if fs::symlink_metadata(&lockpath).await.is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("content cache lock path is a symlink".into());
        }
        // The blocking lock is acquired off the async executor. File locks are
        // OS-wide and automatically released if this process is killed.
        let handle = tokio::task::spawn_blocking(move || -> Result<std::fs::File, String> {
            let handle = std::fs::OpenOptions::new().read(true).write(true).create(true)
                .open(&lockpath).map_err(|e| format!("open cache lock: {e}"))?;
            handle.lock_exclusive().map_err(|e| format!("lock cache object: {e}"))?;
            Ok(handle)
        }).await.map_err(|e| format!("cache lock task: {e}"))??;
        Ok(CacheLease { path: objdir.join(digest), _local: guard, _handle: handle })
    }
}

pub(crate) struct CacheLease {
    path: PathBuf,
    _local: OwnedMutexGuard<()>,
    _handle: std::fs::File,
}

impl CacheLease {
    pub(crate) async fn restore(&self, root: &Path, file: &ManifestFile, target: &Path) -> Result<bool, String> {
        if !existing_verified(&self.path, file).await? {
            // Corruption, wrong size and symlink replacement all invalidate the object.
            if fs::symlink_metadata(&self.path).await.is_ok() {
                fs::remove_file(&self.path).await.map_err(|e| format!("invalidate cache object: {e}"))?;
            }
            return Ok(false);
        }
        file_ownership::ensure_no_symlinks(root, target)?;
        let parent = target.parent().ok_or("invalid destination")?;
        fs::create_dir_all(parent).await.map_err(|e| format!("create destination: {e}"))?;
        file_ownership::ensure_no_symlinks(root, target)?;
        let staging = parent.join(format!(".nl-cache-{:016x}.tmp", rand::random::<u64>()));
        let outcome = async {
            let mut input = fs::File::open(&self.path).await.map_err(|e| e.to_string())?;
            let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&staging).await.map_err(|e| e.to_string())?;
            tokio::io::copy(&mut input, &mut output).await.map_err(|e| e.to_string())?;
            output.sync_all().await.map_err(|e| e.to_string())?;
            drop(output);
            if !existing_verified(&staging, file).await? {
                return Err("cache copy integrity changed during installation".into());
            }
            file_ownership::ensure_no_symlinks(root, target)?;
            replace_verified_managed_file_0224(&staging, target).await?;
            set_executable_if_needed(target, file.executable).await?;
            Ok(())
        }.await;
        if outcome.is_err() { let _ = fs::remove_file(&staging).await; }
        outcome.map(|_| true)
    }

    pub(crate) async fn publish(&self, file: &ManifestFile, verified_source: &Path) -> Result<(), String> {
        if existing_verified(&self.path, file).await? { return Ok(()); }
        let parent = self.path.parent().ok_or("invalid cache object directory")?;
        let staging = parent.join(format!(".nl-object-{:016x}.tmp", rand::random::<u64>()));
        let outcome = async {
            let mut source = fs::File::open(verified_source).await.map_err(|e| e.to_string())?;
            let mut destination = fs::OpenOptions::new().write(true).create_new(true).open(&staging).await.map_err(|e| e.to_string())?;
            tokio::io::copy(&mut source, &mut destination).await.map_err(|e| e.to_string())?;
            destination.sync_all().await.map_err(|e| e.to_string())?;
            drop(destination);
            if !existing_verified(&staging, file).await? { return Err("refusing to cache invalid content".into()); }
            // Windows cannot rename over an existing file. The object lock
            // serializes readers/writers, so removal is safe here.
            if fs::symlink_metadata(&self.path).await.is_ok() {
                fs::remove_file(&self.path).await.map_err(|e| e.to_string())?;
            }
            fs::rename(&staging, &self.path).await.map_err(|e| format!("publish cache object: {e}"))
        }.await;
        if outcome.is_err() { let _ = fs::remove_file(&staging).await; }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn file(data: &[u8]) -> ManifestFile {
        ManifestFile { path: "libraries/shared.jar".into(), size: data.len() as u64,
            sha256: hex::encode(Sha256::digest(data)), url: "https://unreachable.invalid/file".into(),
            mirrors: vec![], required: true, executable: false, target_os: vec![], ownership: "required".into() }
    }

    #[tokio::test]
    async fn caches_across_separate_roots_without_hardlinks_and_detects_corruption() {
        let root = std::env::temp_dir().join(format!("nl-cache-unit-{:016x}", rand::random::<u64>()));
        let cache = CacheStore::at(root.join("cache"));
        let body = b"identical, signed Minecraft library";
        let f = file(body);
        let source = root.join("source");
        fs::create_dir_all(&root).await.unwrap();
        fs::write(&source, body).await.unwrap();
        let lease = cache.lock(&f).await.unwrap();
        lease.publish(&f, &source).await.unwrap();
        for profile in ["alice", "bob"] {
            let install = root.join(profile);
            fs::create_dir_all(&install).await.unwrap();
            let target = install.join(&f.path);
            assert!(lease.restore(&install, &f, &target).await.unwrap());
            assert_eq!(fs::read(&target).await.unwrap(), body);
        }
        fs::write(root.join("alice").join(&f.path), b"changed by user").await.unwrap();
        assert_eq!(fs::read(root.join("bob").join(&f.path)).await.unwrap(), body);
        fs::write(&lease.path, b"corrupt object").await.unwrap();
        assert!(!lease.restore(&root, &f, &root.join("third.jar")).await.unwrap());
        assert!(!fs::try_exists(&lease.path).await.unwrap());
        drop(lease);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test(flavor="multi_thread", worker_threads=4)]
    async fn concurrent_requests_for_identical_digest_serialize_publish() {
        let root = std::env::temp_dir().join(format!("nl-cache-parallel-{:016x}", rand::random::<u64>()));
        fs::create_dir_all(&root).await.unwrap();
        let cache = Arc::new(CacheStore::at(root.join("cache")));
        let f = file(b"same contents");
        let requests = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let requests = Arc::clone(&requests);
            let f = f.clone();
            let root = root.clone();
            tasks.push(tokio::spawn(async move {
                let lease = cache.lock(&f).await.unwrap();
                let target = root.join(format!("t-{}", rand::random::<u64>()));
                if lease.restore(&root, &f, &target).await.unwrap() { return; }
                requests.fetch_add(1, Ordering::SeqCst);
                let source = root.join(format!("src-{}", rand::random::<u64>()));
                fs::write(&source, b"same contents").await.unwrap();
                lease.publish(&f, &source).await.unwrap();
                fs::remove_file(&source).await.unwrap();
            }));
        }
        for task in tasks { task.await.unwrap(); }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).await.unwrap();
    }
}
