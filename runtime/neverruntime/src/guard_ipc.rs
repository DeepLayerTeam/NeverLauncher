#[cfg(windows)]
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use serde::de::DeserializeOwned;
#[cfg(windows)]
use serde_json::{json, Value};
#[cfg(any(windows, test))]
use hmac::{Hmac, Mac};
#[cfg(any(windows, test))]
use sha2::Sha256;
#[cfg(windows)]
use sha2::Digest;
#[cfg(any(windows, test))]
use subtle::ConstantTimeEq;
use std::path::{Path, PathBuf};
use crate::attestation::{GuardAttestationRequest, NeverGuardRemoteAttestation};
use crate::integrity::NeverGuardIntegrityEvidence;
use crate::windows_policy::GuardProcessPolicyReport;
#[cfg(windows)]
use crate::attestation::{challenge_sha256, recompute_attestation_sha256, validate_attestation_shape, NEVERGUARD_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_REMOTE_ATTESTATION_VERSION};
#[cfg(windows)]
use crate::integrity::{
    collect_windows_integrity_evidence, observed_windows_parent_pid, recompute_evidence_sha256,
    validate_evidence_shape, verify_windows_authenticode_trust,
};
#[cfg(windows)]
use crate::windows_policy::{
    bind_guard_to_launcher_job, ensure_guard_process_policy, ensure_windows_production_hardening,
    prepare_guard_command, GuardLifetimeJob, WindowsProductionHardeningReport, NEVERGUARD_WINDOWS_HARDENING_VERSION,
    NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA, NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION,
};
#[cfg(windows)]
use std::{ffi::c_void, fs::File, io::{BufReader, Read}, mem::size_of, ptr::null_mut, time::{SystemTime, UNIX_EPOCH}};
#[cfg(windows)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(windows)]
use zeroize::Zeroize;

#[cfg(windows)]
use std::{process::Stdio, sync::Arc};
#[cfg(windows)]
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout, Duration, Instant},
};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW},
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub const NEVERGUARD_PROTOCOL_VERSION: u32 = 4;
#[cfg(any(windows, test))]
const NEVERGUARD_PIPE_PREFIX: &str = r"\\.\pipe\NeverLauncher.Guard.";
#[cfg(windows)]
const BOOTSTRAP_SECRET_LEN: usize = 32;
#[cfg(windows)]
const MAX_FRAME_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const IPC_CONNECT_TIMEOUT_SECS: u64 = 8;
#[cfg(windows)]
const IPC_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
#[cfg(windows)]
const IPC_COMMAND_TIMEOUT_SECS: u64 = 3;
#[cfg(windows)]
const IPC_STARTUP_AUTH_WINDOW_SECS: u64 = 12;
#[cfg(windows)]
const WINDOWS_PACKAGE_MANIFEST: &str = "WINDOWS_PACKAGE_MANIFEST.json";

#[cfg(windows)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WindowsPackageManifest {
    schema_version: String,
    product_version: String,
    platform: String,
    never_guard_protocol_version: u32,
    #[serde(default)]
    authenticode_required: bool,
    artifacts: Vec<WindowsPackageArtifact>,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct WindowsPackageArtifact {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NeverGuardStatus {
    pub state: String,
    pub pid: u32,
    pub parent_pid: u32,
    pub protocol_version: u32,
    pub authenticated: bool,
    pub process_policy_version: u32,
    pub process_policy_enforced: bool,
    pub hardening_version: u32,
    pub hardening_enforced: bool,
    pub secure_pipe_acl: bool,
    pub lifetime_job_enforced: bool,
    pub package_manifest_verified: bool,
    pub started_at_unix: u64,
    pub message: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientHello {
    kind: String,
    protocol_version: u32,
    client_pid: u32,
    client_nonce: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerChallenge {
    kind: String,
    protocol_version: u32,
    guard_pid: u32,
    started_at_unix: u64,
    server_nonce: String,
    server_proof: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientAuthentication {
    kind: String,
    client_proof: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerReady {
    kind: String,
    protocol_version: u32,
    guard_pid: u32,
    started_at_unix: u64,
    process_policy_version: u32,
    process_policy_enforced: bool,
    hardening_version: u32,
    hardening_enforced: bool,
    secure_pipe_acl: bool,
    ready_proof: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestEnvelope {
    protocol_version: u32,
    sequence: u64,
    request_id: String,
    command: String,
    payload: String,
    mac: String,
}

#[cfg(windows)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseEnvelope {
    protocol_version: u32,
    sequence: u64,
    request_id: String,
    ok: bool,
    payload: String,
    mac: String,
}

#[cfg(windows)]
struct GuardHandle {
    child: Child,
    pipe: NamedPipeClient,
    session_key: [u8; 32],
    next_sequence: u64,
    _lifetime_job: GuardLifetimeJob,
    package_manifest_verified: bool,
}

#[cfg(windows)]
impl Drop for GuardHandle {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

#[cfg(windows)]
#[derive(Clone)]
pub struct NeverGuardSupervisor {
    inner: Arc<Mutex<Option<GuardHandle>>>,
    executable: Option<PathBuf>,
    require_package_manifest: bool,
}

#[cfg(windows)]
impl Default for NeverGuardSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(windows))]
#[derive(Clone, Default)]
pub struct NeverGuardSupervisor;

impl NeverGuardSupervisor {
    #[cfg(windows)]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            executable: None,
            require_package_manifest: !cfg!(debug_assertions),
        }
    }

    #[cfg(not(windows))]
    pub fn new() -> Self {
        Self
    }

    #[cfg(windows)]
    pub fn with_executable(executable: PathBuf) -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            executable: Some(executable),
            require_package_manifest: false,
        }
    }

    #[cfg(not(windows))]
    pub fn with_executable(_executable: PathBuf) -> Self {
        Self
    }

    #[cfg(windows)]
    pub async fn ensure_started(&self) -> Result<NeverGuardStatus, String> {
        let mut state = self.inner.lock().await;

        if let Some(handle) = state.as_mut() {
            let running = handle
                .child
                .try_wait()
                .map_err(|err| format!("не удалось проверить NeverGuard process: {err}"))?
                .is_none();
            if running {
                if let Ok(status) = send_command(handle, "status").await {
                    let mut status = parse_status(status)?;
                    status.lifetime_job_enforced = true;
                    status.package_manifest_verified = handle.package_manifest_verified;
                    return Ok(status);
                }
            }
        }

        if let Some(mut stale) = state.take() {
            let _ = stale.child.kill().await;
        }

        let executable = match self.executable.as_ref() {
            Some(path) => path.clone(),
            None => resolve_neverguard_executable()?,
        };
        validate_neverguard_path(&executable)?;
        if !executable.is_file() {
            return Err(format!(
                "NeverGuard executable отсутствует рядом с Desktop: {}",
                executable.display()
            ));
        }
        let package_manifest_verified = if self.require_package_manifest {
            verify_windows_package_manifest(&executable)?;
            true
        } else {
            false
        };

        let parent_pid = std::process::id();
        let endpoint = make_pipe_endpoint(parent_pid);
        let mut bootstrap_secret = random_bytes_32();
        let mut command = Command::new(&executable);
        command
            .arg("--pipe")
            .arg(&endpoint)
            .arg("--parent-pid")
            .arg(parent_pid.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        prepare_guard_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|err| format!("не удалось запустить NeverGuard {}: {err}", executable.display()))?;
        let lifetime_job = match bind_guard_to_launcher_job(&mut child) {
            Ok(job) => job,
            Err(err) => {
                let _ = child.kill().await;
                return Err(format!("launch заблокирован: NeverGuard lifetime boundary failed: {err}"));
            }
        };

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "NeverGuard bootstrap stdin недоступен".to_string())?;
        if let Err(err) = stdin.write_all(&bootstrap_secret).await {
            bootstrap_secret.zeroize();
            let _ = child.kill().await;
            return Err(format!("не удалось передать NeverGuard bootstrap secret: {err}"));
        }
        if let Err(err) = stdin.shutdown().await {
            bootstrap_secret.zeroize();
            let _ = child.kill().await;
            return Err(format!("не удалось закрыть NeverGuard bootstrap channel: {err}"));
        }

        let pipe = match connect_client_pipe(&endpoint).await {
            Ok(pipe) => pipe,
            Err(err) => {
                bootstrap_secret.zeroize();
                let _ = child.kill().await;
                return Err(err);
            }
        };
        let (pipe, session_key, status) = match timeout(
            Duration::from_secs(IPC_HANDSHAKE_TIMEOUT_SECS),
            client_authenticate(pipe, &endpoint, parent_pid, &bootstrap_secret),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                bootstrap_secret.zeroize();
                let _ = child.kill().await;
                return Err(err);
            }
            Err(_) => {
                bootstrap_secret.zeroize();
                let _ = child.kill().await;
                return Err("NeverGuard authenticated IPC handshake превысил timeout".to_string());
            }
        };
        bootstrap_secret.zeroize();

        let mut status = status;
        status.lifetime_job_enforced = true;
        status.package_manifest_verified = package_manifest_verified;
        *state = Some(GuardHandle {
            child,
            pipe,
            session_key,
            next_sequence: 1,
            _lifetime_job: lifetime_job,
            package_manifest_verified,
        });
        Ok(status)
    }

    #[cfg(not(windows))]
    pub async fn ensure_started(&self) -> Result<NeverGuardStatus, String> {
        Err("NeverGuard 0.13.4 Windows policy boundary реализован только для Windows".to_string())
    }

    #[cfg(windows)]
    pub async fn status(&self) -> Result<NeverGuardStatus, String> {
        self.ensure_started().await
    }

    #[cfg(not(windows))]
    pub async fn status(&self) -> Result<NeverGuardStatus, String> {
        self.ensure_started().await
    }

    #[cfg(windows)]
    pub async fn ping(&self) -> Result<(), String> {
        self.ensure_started().await?;
        let mut state = self.inner.lock().await;
        let handle = state
            .as_mut()
            .ok_or_else(|| "NeverGuard process boundary не инициализирован".to_string())?;
        let payload = send_command(handle, "ping").await?;
        if payload.get("pong").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err("NeverGuard вернул некорректный ping response".to_string())
        }
    }

    #[cfg(not(windows))]
    pub async fn ping(&self) -> Result<(), String> {
        Err("NeverGuard 0.13.4 Windows policy boundary реализован только для Windows".to_string())
    }

    #[cfg(windows)]
    pub async fn integrity_evidence(&self) -> Result<NeverGuardIntegrityEvidence, String> {
        self.ensure_started().await?;
        let mut state = self.inner.lock().await;
        let handle = state
            .as_mut()
            .ok_or_else(|| "NeverGuard process boundary не инициализирован".to_string())?;
        let payload = send_command(handle, "integrity-evidence").await?;
        let evidence: NeverGuardIntegrityEvidence = serde_json::from_value(payload)
            .map_err(|err| format!("NeverGuard integrity evidence payload повреждён: {err}"))?;
        validate_integrity_evidence(handle, &evidence)?;
        Ok(evidence)
    }

    #[cfg(not(windows))]
    pub async fn integrity_evidence(&self) -> Result<NeverGuardIntegrityEvidence, String> {
        Err("NeverGuard 0.13.4 Windows integrity evidence доступен только для Windows".to_string())
    }

    #[cfg(windows)]
    pub async fn process_policy(&self) -> Result<GuardProcessPolicyReport, String> {
        self.ensure_started().await?;
        let mut state = self.inner.lock().await;
        let handle = state
            .as_mut()
            .ok_or_else(|| "NeverGuard process boundary не инициализирован".to_string())?;
        let payload = send_command(handle, "process-policy").await?;
        let policy: GuardProcessPolicyReport = serde_json::from_value(payload)
            .map_err(|err| format!("NeverGuard process policy payload повреждён: {err}"))?;
        validate_guard_process_policy(handle, &policy)?;
        Ok(policy)
    }

    #[cfg(not(windows))]
    pub async fn process_policy(&self) -> Result<GuardProcessPolicyReport, String> {
        Err("NeverGuard 0.13.4 Windows process policy доступен только для Windows".to_string())
    }

    #[cfg(windows)]
    pub async fn remote_attestation(
        &self,
        challenge_id: &str,
        challenge: &str,
    ) -> Result<NeverGuardRemoteAttestation, String> {
        self.ensure_started().await?;
        if challenge_id.trim().is_empty() || challenge_id.len() > 160 {
            return Err("NeverGuard attestation challengeId malformed".to_string());
        }
        if challenge.is_empty() || challenge.len() > 4096 {
            return Err("NeverGuard attestation challenge malformed".to_string());
        }
        let request = GuardAttestationRequest {
            challenge_id: challenge_id.to_string(),
            challenge: challenge.to_string(),
        };
        let request_payload = serde_json::to_string(&request)
            .map_err(|err| format!("NeverGuard attestation request serialization failed: {err}"))?;
        let mut state = self.inner.lock().await;
        let handle = state
            .as_mut()
            .ok_or_else(|| "NeverGuard process boundary не инициализирован".to_string())?;
        let payload = send_command_with_payload(handle, "guard-attestation", &request_payload).await?;
        let attestation: NeverGuardRemoteAttestation = serde_json::from_value(payload)
            .map_err(|err| format!("NeverGuard remote attestation payload повреждён: {err}"))?;
        validate_remote_attestation(handle, challenge_id, challenge, &attestation)?;
        Ok(attestation)
    }

    #[cfg(not(windows))]
    pub async fn remote_attestation(
        &self,
        _challenge_id: &str,
        _challenge: &str,
    ) -> Result<NeverGuardRemoteAttestation, String> {
        Err("NeverGuard 0.13.4 Guard Attestation доступен только для Windows".to_string())
    }

    #[cfg(windows)]
    pub async fn shutdown(&self) -> Result<(), String> {
        let mut state = self.inner.lock().await;
        let Some(mut handle) = state.take() else {
            return Ok(());
        };
        let _ = send_command(&mut handle, "shutdown").await;
        match timeout(Duration::from_secs(2), handle.child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(format!("не удалось дождаться NeverGuard shutdown: {err}")),
            Err(_) => {
                handle
                    .child
                    .kill()
                    .await
                    .map_err(|err| format!("не удалось принудительно завершить NeverGuard: {err}"))?;
                Ok(())
            }
        }
    }

    #[cfg(not(windows))]
    pub async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(windows)]
fn verify_windows_package_manifest(guard_executable: &Path) -> Result<(), String> {
    let current_exe = std::env::current_exe()
        .map_err(|err| format!("не удалось определить Desktop executable для package verification: {err}"))?;
    let current_dir = current_exe
        .parent()
        .ok_or_else(|| "Desktop executable не имеет parent directory".to_string())?;
    let guard_dir = guard_executable
        .parent()
        .ok_or_else(|| "NeverGuard executable не имеет parent directory".to_string())?;
    let current_dir = std::fs::canonicalize(current_dir)
        .map_err(|err| format!("не удалось canonicalize Desktop directory: {err}"))?;
    let guard_dir = std::fs::canonicalize(guard_dir)
        .map_err(|err| format!("не удалось canonicalize NeverGuard directory: {err}"))?;
    if current_dir != guard_dir {
        return Err("NeverGuard package verification failed: Guard is not adjacent to Desktop".to_string());
    }
    for path in [&current_exe, guard_executable] {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|err| format!("не удалось stat package artifact {}: {err}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "NeverGuard package verification rejected non-regular/symlink artifact: {}",
                path.display()
            ));
        }
    }

    let manifest_path = current_dir.join(WINDOWS_PACKAGE_MANIFEST);
    let manifest_link_metadata = std::fs::symlink_metadata(&manifest_path).map_err(|err| {
        format!(
            "production Windows package manifest отсутствует {}: {err}",
            manifest_path.display()
        )
    })?;
    if manifest_link_metadata.file_type().is_symlink() || !manifest_link_metadata.is_file() {
        return Err("Windows package manifest must be a regular non-symlink file".to_string());
    }
    let metadata = std::fs::metadata(&manifest_path).map_err(|err| {
        format!(
            "production Windows package manifest отсутствует {}: {err}",
            manifest_path.display()
        )
    })?;
    if metadata.len() == 0 || metadata.len() > 256 * 1024 {
        return Err("Windows package manifest size is invalid".to_string());
    }
    let raw = std::fs::read(&manifest_path)
        .map_err(|err| format!("не удалось прочитать Windows package manifest: {err}"))?;
    let manifest: WindowsPackageManifest = serde_json::from_slice(&raw)
        .map_err(|err| format!("Windows package manifest повреждён: {err}"))?;
    if manifest.schema_version != "1.0"
        || manifest.product_version != env!("CARGO_PKG_VERSION")
        || manifest.platform != "windows-amd64"
        || manifest.never_guard_protocol_version != NEVERGUARD_PROTOCOL_VERSION
    {
        return Err("Windows package manifest version/platform/protocol mismatch".to_string());
    }

    if !manifest.authenticode_required {
        return Err(
            "production Windows package manifest must require Authenticode; unsigned release packages are rejected"
                .to_string(),
        );
    }
    verify_package_artifact(&manifest, &current_exe)?;
    verify_package_artifact(&manifest, guard_executable)?;
    verify_windows_authenticode_trust(&current_exe)?;
    verify_windows_authenticode_trust(guard_executable)?;
    Ok(())
}

#[cfg(windows)]
fn verify_package_artifact(manifest: &WindowsPackageManifest, path: &Path) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "Windows package artifact filename is not UTF-8".to_string())?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| format!("Windows package manifest does not contain artifact {name}"))?;
    let metadata = std::fs::metadata(path)
        .map_err(|err| format!("не удалось stat package artifact {}: {err}", path.display()))?;
    if metadata.len() != artifact.size {
        return Err(format!("Windows package artifact size mismatch: {name}"));
    }
    let actual = sha256_file(path)?;
    if artifact.sha256.len() != 64
        || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || !actual.eq_ignore_ascii_case(&artifact.sha256)
    {
        return Err(format!("Windows package artifact SHA-256 mismatch: {name}"));
    }
    Ok(())
}

#[cfg(windows)]
fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|err| format!("не удалось открыть {} для SHA-256: {err}", path.display()))?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| format!("не удалось вычислить SHA-256 {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(windows)]
fn resolve_neverguard_executable() -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|err| format!("не удалось определить путь NeverLauncher Desktop: {err}"))?;
    let parent = current
        .parent()
        .ok_or_else(|| "не удалось определить каталог NeverLauncher Desktop".to_string())?;
    Ok(parent.join("neverguard.exe"))
}

#[cfg(windows)]
fn make_pipe_endpoint(parent_pid: u32) -> String {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    format!("{NEVERGUARD_PIPE_PREFIX}{parent_pid}.{}", hex::encode(nonce))
}

#[cfg(windows)]
async fn connect_client_pipe(endpoint: &str) -> Result<NamedPipeClient, String> {
    let deadline = Instant::now() + Duration::from_secs(IPC_CONNECT_TIMEOUT_SECS);
    loop {
        match ClientOptions::new().open(endpoint) {
            Ok(pipe) => return Ok(pipe),
            Err(err) if Instant::now() < deadline => {
                if !matches!(err.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::WouldBlock) {
                    // ERROR_PIPE_BUSY is reported as a platform-specific Other error on some toolchains.
                    if err.raw_os_error() != Some(231) {
                        return Err(format!("не удалось подключиться к NeverGuard IPC {endpoint}: {err}"));
                    }
                }
                sleep(Duration::from_millis(40)).await;
            }
            Err(err) => {
                return Err(format!(
                    "NeverGuard IPC не появился за {IPC_CONNECT_TIMEOUT_SECS}s ({endpoint}): {err}"
                ));
            }
        }
    }
}

#[cfg(windows)]
async fn client_authenticate(
    mut pipe: NamedPipeClient,
    endpoint: &str,
    client_pid: u32,
    bootstrap_secret: &[u8; 32],
) -> Result<(NamedPipeClient, [u8; 32], NeverGuardStatus), String> {
    let client_nonce = random_bytes_32();
    let hello = ClientHello {
        kind: "hello".to_string(),
        protocol_version: NEVERGUARD_PROTOCOL_VERSION,
        client_pid,
        client_nonce: hex::encode(client_nonce),
    };
    write_frame(&mut pipe, &hello).await?;

    let challenge: ServerChallenge = read_frame(&mut pipe).await?;
    if challenge.kind != "challenge" || challenge.protocol_version != NEVERGUARD_PROTOCOL_VERSION {
        return Err("NeverGuard IPC protocol mismatch на server challenge".to_string());
    }
    let server_nonce = decode_hex_32(&challenge.server_nonce, "serverNonce")?;
    let expected_server_proof = handshake_proof(
        bootstrap_secret,
        b"server",
        endpoint,
        client_pid,
        challenge.guard_pid,
        challenge.started_at_unix,
        &client_nonce,
        &server_nonce,
    );
    let actual_server_proof = decode_hex_32(&challenge.server_proof, "serverProof")?;
    if !constant_time_eq(&expected_server_proof, &actual_server_proof) {
        return Err("NeverGuard server authentication failed".to_string());
    }

    let client_proof = handshake_proof(
        bootstrap_secret,
        b"client",
        endpoint,
        client_pid,
        challenge.guard_pid,
        challenge.started_at_unix,
        &client_nonce,
        &server_nonce,
    );
    write_frame(
        &mut pipe,
        &ClientAuthentication {
            kind: "authenticate".to_string(),
            client_proof: hex::encode(client_proof),
        },
    )
    .await?;

    let session_key = derive_session_key(
        bootstrap_secret,
        endpoint,
        client_pid,
        challenge.guard_pid,
        challenge.started_at_unix,
        &client_nonce,
        &server_nonce,
    );
    let ready: ServerReady = read_frame(&mut pipe).await?;
    if ready.kind != "ready"
        || ready.protocol_version != NEVERGUARD_PROTOCOL_VERSION
        || ready.guard_pid != challenge.guard_pid
        || ready.started_at_unix != challenge.started_at_unix
        || ready.process_policy_version != NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION
        || !ready.process_policy_enforced
        || ready.hardening_version != NEVERGUARD_WINDOWS_HARDENING_VERSION
        || !ready.hardening_enforced
        || !ready.secure_pipe_acl
    {
        return Err("NeverGuard IPC ready response не соответствует handshake/policy/hardening".to_string());
    }
    let expected_ready = ready_proof(
        &session_key,
        ready.guard_pid,
        ready.started_at_unix,
        ready.process_policy_version,
        ready.process_policy_enforced,
        ready.hardening_version,
        ready.hardening_enforced,
        ready.secure_pipe_acl,
    );
    let actual_ready = decode_hex_32(&ready.ready_proof, "readyProof")?;
    if !constant_time_eq(&expected_ready, &actual_ready) {
        return Err("NeverGuard ready authentication failed".to_string());
    }

    let status = NeverGuardStatus {
        state: "ready".to_string(),
        pid: challenge.guard_pid,
        parent_pid: client_pid,
        protocol_version: NEVERGUARD_PROTOCOL_VERSION,
        authenticated: true,
        process_policy_version: ready.process_policy_version,
        process_policy_enforced: ready.process_policy_enforced,
        hardening_version: ready.hardening_version,
        hardening_enforced: ready.hardening_enforced,
        secure_pipe_acl: ready.secure_pipe_acl,
        lifetime_job_enforced: false,
        package_manifest_verified: false,
        started_at_unix: challenge.started_at_unix,
        message: "NeverGuard Windows process boundary authenticated; process policy and production hardening enforced".to_string(),
    };
    Ok((pipe, session_key, status))
}

#[cfg(windows)]
async fn send_command(handle: &mut GuardHandle, command: &str) -> Result<Value, String> {
    send_command_with_payload(handle, command, "").await
}

#[cfg(windows)]
async fn send_command_with_payload(
    handle: &mut GuardHandle,
    command: &str,
    payload: &str,
) -> Result<Value, String> {
    match timeout(
        Duration::from_secs(IPC_COMMAND_TIMEOUT_SECS),
        send_command_inner(handle, command, payload),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "NeverGuard IPC command {command} превысил timeout"
        )),
    }
}

#[cfg(windows)]
async fn send_command_inner(
    handle: &mut GuardHandle,
    command: &str,
    payload: &str,
) -> Result<Value, String> {
    if payload.len() > 32 * 1024 {
        return Err("NeverGuard IPC request payload exceeds 32 KiB".to_string());
    }
    let sequence = handle.next_sequence;
    let request_id = random_id();
    let mac = request_mac(&handle.session_key, sequence, &request_id, command, payload);
    let request = RequestEnvelope {
        protocol_version: NEVERGUARD_PROTOCOL_VERSION,
        sequence,
        request_id: request_id.clone(),
        command: command.to_string(),
        payload: payload.to_string(),
        mac: hex::encode(mac),
    };
    write_frame(&mut handle.pipe, &request).await?;
    let response: ResponseEnvelope = read_frame(&mut handle.pipe).await?;
    if response.protocol_version != NEVERGUARD_PROTOCOL_VERSION
        || response.sequence != sequence
        || response.request_id != request_id
    {
        return Err("NeverGuard IPC response sequence/requestId mismatch".to_string());
    }
    let expected = response_mac(
        &handle.session_key,
        response.sequence,
        &response.request_id,
        response.ok,
        &response.payload,
    );
    let actual = decode_hex_32(&response.mac, "responseMac")?;
    if !constant_time_eq(&expected, &actual) {
        return Err("NeverGuard IPC response MAC verification failed".to_string());
    }
    handle.next_sequence = handle
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| "NeverGuard IPC sequence exhausted".to_string())?;
    let payload: Value = serde_json::from_str(&response.payload)
        .map_err(|err| format!("NeverGuard IPC response payload повреждён: {err}"))?;
    if response.ok {
        Ok(payload)
    } else {
        Err(payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("NeverGuard отклонил IPC command")
            .to_string())
    }
}

#[cfg(windows)]
fn parse_status(value: Value) -> Result<NeverGuardStatus, String> {
    serde_json::from_value(value).map_err(|err| format!("NeverGuard status payload повреждён: {err}"))
}

#[cfg(windows)]
fn validate_integrity_evidence(
    handle: &GuardHandle,
    evidence: &NeverGuardIntegrityEvidence,
) -> Result<(), String> {
    validate_evidence_shape(evidence)?;
    let guard_pid = handle
        .child
        .id()
        .ok_or_else(|| "NeverGuard child PID unavailable during evidence validation".to_string())?;
    let launcher_pid = std::process::id();
    if evidence.guard.pid != guard_pid
        || evidence.launcher.pid != launcher_pid
        || evidence.boundary.expected_parent_pid != launcher_pid
        || evidence.boundary.observed_parent_pid != launcher_pid
    {
        return Err("NeverGuard integrity evidence PID binding mismatch".to_string());
    }

    let expected_digest = recompute_evidence_sha256(evidence)?;
    let actual_digest = decode_hex_32(&evidence.evidence_sha256, "evidenceSha256")?;
    if !constant_time_eq(&expected_digest, &actual_digest) {
        return Err("NeverGuard integrity evidence digest verification failed".to_string());
    }
    let expected_proof = integrity_session_proof(&handle.session_key, &actual_digest);
    let actual_proof = decode_hex_32(&evidence.session_proof, "integritySessionProof")?;
    if !constant_time_eq(&expected_proof, &actual_proof) {
        return Err("NeverGuard integrity evidence session proof verification failed".to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn validate_remote_attestation(
    handle: &GuardHandle,
    challenge_id: &str,
    challenge: &str,
    attestation: &NeverGuardRemoteAttestation,
) -> Result<(), String> {
    validate_attestation_shape(attestation)?;
    if attestation.challenge_id != challenge_id
        || attestation.challenge_sha256 != challenge_sha256(challenge)
    {
        return Err("NeverGuard remote attestation challenge binding mismatch".to_string());
    }
    validate_integrity_evidence(handle, &attestation.evidence)?;
    validate_guard_process_policy(handle, &attestation.process_policy)?;
    let expected_digest = recompute_attestation_sha256(attestation)?;
    let actual_digest = decode_hex_32(&attestation.attestation_sha256, "attestationSha256")?;
    if !constant_time_eq(&expected_digest, &actual_digest) {
        return Err("NeverGuard remote attestation digest verification failed".to_string());
    }
    let expected_proof = attestation_session_proof(&handle.session_key, &actual_digest);
    let actual_proof = decode_hex_32(&attestation.session_proof, "attestationSessionProof")?;
    if !constant_time_eq(&expected_proof, &actual_proof) {
        return Err("NeverGuard remote attestation session proof verification failed".to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn validate_guard_process_policy(
    handle: &GuardHandle,
    policy: &GuardProcessPolicyReport,
) -> Result<(), String> {
    let guard_pid = handle
        .child
        .id()
        .ok_or_else(|| "NeverGuard child PID unavailable during policy validation".to_string())?;
    if policy.schema != NEVERGUARD_WINDOWS_PROCESS_POLICY_SCHEMA
        || policy.policy_version != NEVERGUARD_WINDOWS_PROCESS_POLICY_VERSION
        || policy.pid != guard_pid
        || !policy.enforced
        || !policy.dynamic_code_prohibited
        || !policy.extension_points_disabled
        || !policy.strict_handle_checks
        || !policy.remote_images_blocked
        || !policy.low_mandatory_label_images_blocked
        || !policy.prefer_system32_images
        || !policy.child_process_creation_blocked
    {
        return Err("NeverGuard Windows process policy verification failed".to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_user_sid_string() -> Result<String, String> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "NeverGuard cannot open current process token for pipe ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
    let token = TokenHandle(token);

    let mut needed = 0u32;
    unsafe {
        let _ = GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 4096 {
        return Err("NeverGuard TokenUser size is invalid while building pipe ACL".to_string());
    }
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(format!(
            "NeverGuard cannot read current user SID for pipe ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    if token_user.User.Sid.is_null() {
        return Err("NeverGuard current user SID is null".to_string());
    }

    let mut sid_text: *mut u16 = null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) } == 0
        || sid_text.is_null()
    {
        return Err(format!(
            "NeverGuard cannot convert current user SID for pipe ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut len = 0usize;
    unsafe {
        while *sid_text.add(len) != 0 {
            len += 1;
            if len > 256 {
                let _ = LocalFree(sid_text as *mut c_void);
                return Err("NeverGuard current user SID text exceeds limit".to_string());
            }
        }
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, len) })
        .map_err(|_| "NeverGuard current user SID is not valid UTF-16".to_string());
    unsafe {
        let _ = LocalFree(sid_text as *mut c_void);
    }
    sid
}

#[cfg(windows)]
fn create_secure_pipe_server(endpoint: &str) -> Result<NamedPipeServer, String> {
    // Protected DACL: only LocalSystem and the exact launcher account receive access.
    // Authentication still happens at the HMAC layer, so the ACL is defense in depth.
    let user_sid = current_windows_user_sid_string()?;
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut security_descriptor,
            null_mut(),
        )
    };
    if converted == 0 || security_descriptor.is_null() {
        return Err(format!(
            "NeverGuard named pipe security descriptor creation failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor as *mut c_void,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .max_instances(1)
            .create_with_security_attributes_raw(
                endpoint,
                &mut attributes as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
    };
    unsafe {
        let _ = LocalFree(security_descriptor as *mut c_void);
    }
    result.map_err(|err| format!("не удалось создать hardened NeverGuard named pipe {endpoint}: {err}"))
}

#[cfg(windows)]
pub async fn run_windows_guard_server(endpoint: String, parent_pid: u32) -> Result<(), String> {
    validate_pipe_endpoint(&endpoint)?;
    if parent_pid == 0 {
        return Err("NeverGuard parent PID должен быть > 0".to_string());
    }
    let guard_pid = std::process::id();
    let hardening = ensure_windows_production_hardening()?;
    if hardening.pid != guard_pid
        || hardening.hardening_version != NEVERGUARD_WINDOWS_HARDENING_VERSION
        || !hardening.enforced
        || !hardening.heap_terminate_on_corruption
        || !hardening.current_directory_removed_from_dll_search
        || !hardening.restricted_default_dll_directories
    {
        return Err("NeverGuard Windows production hardening did not bind to guard PID".to_string());
    }
    let process_policy = ensure_guard_process_policy()?;
    if process_policy.pid != guard_pid || !process_policy.enforced {
        return Err("NeverGuard Windows process policy did not bind to guard PID".to_string());
    }
    let observed_parent_pid = observed_windows_parent_pid(guard_pid)?;
    if observed_parent_pid != parent_pid {
        return Err(format!(
            "NeverGuard actual parent PID mismatch: expected {parent_pid}, observed {observed_parent_pid}"
        ));
    }

    let mut bootstrap_secret = [0u8; BOOTSTRAP_SECRET_LEN];
    let mut bootstrap_stdin = std::io::stdin();
    std::io::Read::read_exact(&mut bootstrap_stdin, &mut bootstrap_secret)
        .map_err(|err| format!("NeverGuard bootstrap secret не получен: {err}"))?;
    drop(bootstrap_stdin);

    let started_at_unix = now_unix()?;
    let mut server = create_secure_pipe_server(&endpoint)?;

    let auth_deadline = Instant::now() + Duration::from_secs(IPC_STARTUP_AUTH_WINDOW_SECS);
    let mut last_auth_error: Option<String> = None;
    let mut session_key = loop {
        let remaining = auth_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bootstrap_secret.zeroize();
            let detail = last_auth_error
                .as_deref()
                .unwrap_or("no authenticated client connected");
            return Err(format!(
                "NeverGuard IPC authentication window expired: {detail}"
            ));
        }

        match timeout(remaining, server.connect()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                bootstrap_secret.zeroize();
                return Err(format!("NeverGuard IPC connect failed: {err}"));
            }
            Err(_) => {
                bootstrap_secret.zeroize();
                return Err("NeverGuard IPC client не подключился до timeout".to_string());
            }
        }

        let handshake_budget = auth_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(IPC_HANDSHAKE_TIMEOUT_SECS));
        let auth = timeout(
            handshake_budget,
            server_authenticate(
                &mut server,
                &endpoint,
                parent_pid,
                guard_pid,
                started_at_unix,
                &bootstrap_secret,
                &process_policy,
                &hardening,
            ),
        )
        .await;
        match auth {
            Ok(Ok(key)) => break key,
            Ok(Err(err)) => last_auth_error = Some(err),
            Err(_) => {
                last_auth_error = Some(
                    "authenticated IPC handshake превысил per-client timeout".to_string(),
                );
            }
        }

        if let Err(err) = server.disconnect() {
            bootstrap_secret.zeroize();
            return Err(format!(
                "NeverGuard IPC failed to reset after rejected client: {err}"
            ));
        }
        sleep(Duration::from_millis(10)).await;
    };
    bootstrap_secret.zeroize();

    let result = serve_authenticated_session(
        &mut server,
        parent_pid,
        guard_pid,
        started_at_unix,
        &session_key,
        &process_policy,
        &hardening,
    )
    .await;
    session_key.zeroize();
    result
}

#[cfg(not(windows))]
pub async fn run_windows_guard_server(_endpoint: String, _parent_pid: u32) -> Result<(), String> {
    Err("NeverGuard 0.13.4 Windows policy boundary реализован только для Windows".to_string())
}

#[cfg(windows)]
async fn server_authenticate(
    server: &mut NamedPipeServer,
    endpoint: &str,
    expected_parent_pid: u32,
    guard_pid: u32,
    started_at_unix: u64,
    bootstrap_secret: &[u8; 32],
    process_policy: &GuardProcessPolicyReport,
    hardening: &WindowsProductionHardeningReport,
) -> Result<[u8; 32], String> {
    let hello: ClientHello = read_frame(server).await?;
    if hello.kind != "hello"
        || hello.protocol_version != NEVERGUARD_PROTOCOL_VERSION
        || hello.client_pid != expected_parent_pid
    {
        return Err("NeverGuard client identity/protocol rejected".to_string());
    }
    let client_nonce = decode_hex_32(&hello.client_nonce, "clientNonce")?;
    let server_nonce = random_bytes_32();
    let server_proof = handshake_proof(
        bootstrap_secret,
        b"server",
        endpoint,
        hello.client_pid,
        guard_pid,
        started_at_unix,
        &client_nonce,
        &server_nonce,
    );
    write_frame(
        server,
        &ServerChallenge {
            kind: "challenge".to_string(),
            protocol_version: NEVERGUARD_PROTOCOL_VERSION,
            guard_pid,
            started_at_unix,
            server_nonce: hex::encode(server_nonce),
            server_proof: hex::encode(server_proof),
        },
    )
    .await?;

    let authentication: ClientAuthentication = read_frame(server).await?;
    if authentication.kind != "authenticate" {
        return Err("NeverGuard client authentication message rejected".to_string());
    }
    let expected_client_proof = handshake_proof(
        bootstrap_secret,
        b"client",
        endpoint,
        hello.client_pid,
        guard_pid,
        started_at_unix,
        &client_nonce,
        &server_nonce,
    );
    let actual_client_proof = decode_hex_32(&authentication.client_proof, "clientProof")?;
    if !constant_time_eq(&expected_client_proof, &actual_client_proof) {
        return Err("NeverGuard client authentication failed".to_string());
    }

    let session_key = derive_session_key(
        bootstrap_secret,
        endpoint,
        hello.client_pid,
        guard_pid,
        started_at_unix,
        &client_nonce,
        &server_nonce,
    );
    write_frame(
        server,
        &ServerReady {
            kind: "ready".to_string(),
            protocol_version: NEVERGUARD_PROTOCOL_VERSION,
            guard_pid,
            started_at_unix,
            process_policy_version: process_policy.policy_version,
            process_policy_enforced: process_policy.enforced,
            hardening_version: hardening.hardening_version,
            hardening_enforced: hardening.enforced,
            secure_pipe_acl: true,
            ready_proof: hex::encode(ready_proof(
                &session_key,
                guard_pid,
                started_at_unix,
                process_policy.policy_version,
                process_policy.enforced,
                hardening.hardening_version,
                hardening.enforced,
                true,
            )),
        },
    )
    .await?;
    Ok(session_key)
}

#[cfg(windows)]
async fn serve_authenticated_session(
    server: &mut NamedPipeServer,
    parent_pid: u32,
    guard_pid: u32,
    started_at_unix: u64,
    session_key: &[u8; 32],
    process_policy: &GuardProcessPolicyReport,
    hardening: &WindowsProductionHardeningReport,
) -> Result<(), String> {
    let mut expected_sequence = 1u64;
    loop {
        let request: RequestEnvelope = match read_frame(server).await {
            Ok(value) => value,
            Err(err) if err == "NeverGuard IPC peer closed connection" => return Ok(()),
            Err(err) => return Err(err),
        };
        if request.protocol_version != NEVERGUARD_PROTOCOL_VERSION {
            return Err("NeverGuard IPC request protocol mismatch".to_string());
        }
        if request.sequence != expected_sequence {
            return Err(format!(
                "NeverGuard IPC replay/out-of-order request rejected: expected {expected_sequence}, got {}",
                request.sequence
            ));
        }
        if request.request_id.len() != 32 || !request.request_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("NeverGuard IPC requestId malformed".to_string());
        }
        let expected_mac = request_mac(
            session_key,
            request.sequence,
            &request.request_id,
            &request.command,
            &request.payload,
        );
        let actual_mac = decode_hex_32(&request.mac, "requestMac")?;
        if !constant_time_eq(&expected_mac, &actual_mac) {
            return Err("NeverGuard IPC request MAC verification failed".to_string());
        }

        let (ok, payload, shutdown) = match request.command.as_str() {
            "ping" => (true, json!({"pong": true}), false),
            "status" => (
                true,
                serde_json::to_value(NeverGuardStatus {
                    state: "ready".to_string(),
                    pid: guard_pid,
                    parent_pid,
                    protocol_version: NEVERGUARD_PROTOCOL_VERSION,
                    authenticated: true,
                    process_policy_version: process_policy.policy_version,
                    process_policy_enforced: process_policy.enforced,
                    hardening_version: hardening.hardening_version,
                    hardening_enforced: hardening.enforced,
                    secure_pipe_acl: true,
                    lifetime_job_enforced: false,
                    package_manifest_verified: false,
                    started_at_unix,
                    message: "NeverGuard Windows process boundary authenticated; process policy and production hardening enforced".to_string(),
                })
                .map_err(|err| format!("NeverGuard status serialization failed: {err}"))?,
                false,
            ),
            "process-policy" => (
                true,
                serde_json::to_value(process_policy).map_err(|err| {
                    format!("NeverGuard process policy serialization failed: {err}")
                })?,
                false,
            ),
            "integrity-evidence" => {
                let mut evidence = tokio::task::spawn_blocking(move || {
                    collect_windows_integrity_evidence(parent_pid)
                })
                .await
                .map_err(|err| format!("NeverGuard integrity evidence worker failed: {err}"))??;
                let digest = decode_hex_32(&evidence.evidence_sha256, "evidenceSha256")?;
                evidence.session_proof = hex::encode(integrity_session_proof(session_key, &digest));
                (
                    true,
                    serde_json::to_value(evidence).map_err(|err| {
                        format!("NeverGuard integrity evidence serialization failed: {err}")
                    })?,
                    false,
                )
            }
            "guard-attestation" => {
                let request: GuardAttestationRequest = serde_json::from_str(&request.payload)
                    .map_err(|err| format!("NeverGuard attestation request payload повреждён: {err}"))?;
                if request.challenge_id.trim().is_empty()
                    || request.challenge_id.len() > 160
                    || request.challenge.is_empty()
                    || request.challenge.len() > 4096
                {
                    return Err("NeverGuard attestation request is malformed".to_string());
                }
                let mut evidence = tokio::task::spawn_blocking(move || {
                    collect_windows_integrity_evidence(parent_pid)
                })
                .await
                .map_err(|err| format!("NeverGuard remote attestation evidence worker failed: {err}"))??;
                let evidence_digest = decode_hex_32(&evidence.evidence_sha256, "evidenceSha256")?;
                evidence.session_proof = hex::encode(integrity_session_proof(session_key, &evidence_digest));
                let mut attestation = NeverGuardRemoteAttestation {
                    schema: NEVERGUARD_REMOTE_ATTESTATION_SCHEMA.to_string(),
                    attestation_version: NEVERGUARD_REMOTE_ATTESTATION_VERSION,
                    challenge_id: request.challenge_id,
                    challenge_sha256: challenge_sha256(&request.challenge),
                    collected_at_unix: evidence.collected_at_unix,
                    evidence,
                    process_policy: process_policy.clone(),
                    attestation_sha256: String::new(),
                    session_proof: String::new(),
                };
                let digest = recompute_attestation_sha256(&attestation)?;
                attestation.attestation_sha256 = hex::encode(digest);
                attestation.session_proof = hex::encode(attestation_session_proof(session_key, &digest));
                (
                    true,
                    serde_json::to_value(attestation).map_err(|err| {
                        format!("NeverGuard remote attestation serialization failed: {err}")
                    })?,
                    false,
                )
            }
            "shutdown" => (true, json!({"shutdown": true}), true),
            other => (
                false,
                json!({"error": format!("unsupported NeverGuard command: {other}")}),
                false,
            ),
        };
        let payload = serde_json::to_string(&payload)
            .map_err(|err| format!("NeverGuard response serialization failed: {err}"))?;
        let response = ResponseEnvelope {
            protocol_version: NEVERGUARD_PROTOCOL_VERSION,
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            ok,
            mac: hex::encode(response_mac(
                session_key,
                request.sequence,
                &request.request_id,
                ok,
                &payload,
            )),
            payload,
        };
        write_frame(server, &response).await?;
        if shutdown {
            return Ok(());
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| "NeverGuard IPC sequence exhausted".to_string())?;
    }
}

#[cfg(any(windows, test))]
fn validate_pipe_endpoint(endpoint: &str) -> Result<(), String> {
    if !endpoint.starts_with(NEVERGUARD_PIPE_PREFIX) {
        return Err("NeverGuard IPC endpoint имеет запрещённый namespace".to_string());
    }
    let suffix = &endpoint[NEVERGUARD_PIPE_PREFIX.len()..];
    if suffix.is_empty()
        || suffix.len() > 96
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err("NeverGuard IPC endpoint malformed".to_string());
    }
    Ok(())
}

#[cfg(windows)]
async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = serde_json::to_vec(value)
        .map_err(|err| format!("NeverGuard IPC serialization failed: {err}"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("NeverGuard IPC frame exceeds limit".to_string());
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|err| format!("NeverGuard IPC write failed: {err}"))?;
    writer
        .flush()
        .await
        .map_err(|err| format!("NeverGuard IPC flush failed: {err}"))
}

#[cfg(windows)]
async fn read_frame<R, T>(reader: &mut R) -> Result<T, String>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut bytes = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        let read = reader
            .read(&mut one)
            .await
            .map_err(|err| format!("NeverGuard IPC read failed: {err}"))?;
        if read == 0 {
            return Err("NeverGuard IPC peer closed connection".to_string());
        }
        if one[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_FRAME_BYTES {
            return Err("NeverGuard IPC frame exceeds limit".to_string());
        }
        bytes.push(one[0]);
    }
    if bytes.is_empty() {
        return Err("NeverGuard IPC empty frame rejected".to_string());
    }
    serde_json::from_slice(&bytes).map_err(|err| format!("NeverGuard IPC JSON rejected: {err}"))
}

#[cfg(windows)]
fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(windows)]
fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(windows)]
fn decode_hex_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(value).map_err(|_| format!("NeverGuard IPC {field} is not valid hex"))?;
    if raw.len() != 32 {
        return Err(format!("NeverGuard IPC {field} must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(any(windows, test))]
fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(any(windows, test))]
fn handshake_transcript(
    label: &[u8],
    endpoint: &str,
    client_pid: u32,
    guard_pid: u32,
    started_at_unix: u64,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(192);
    data.extend_from_slice(b"NeverLauncher NeverGuard IPC v4\0");
    append_len_prefixed(&mut data, label);
    append_len_prefixed(&mut data, endpoint.as_bytes());
    data.extend_from_slice(&client_pid.to_le_bytes());
    data.extend_from_slice(&guard_pid.to_le_bytes());
    data.extend_from_slice(&started_at_unix.to_le_bytes());
    data.extend_from_slice(client_nonce);
    data.extend_from_slice(server_nonce);
    data
}

#[cfg(any(windows, test))]
fn handshake_proof(
    secret: &[u8; 32],
    label: &[u8],
    endpoint: &str,
    client_pid: u32,
    guard_pid: u32,
    started_at_unix: u64,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    hmac_sha256(
        secret,
        &handshake_transcript(
            label,
            endpoint,
            client_pid,
            guard_pid,
            started_at_unix,
            client_nonce,
            server_nonce,
        ),
    )
}

#[cfg(any(windows, test))]
fn derive_session_key(
    secret: &[u8; 32],
    endpoint: &str,
    client_pid: u32,
    guard_pid: u32,
    started_at_unix: u64,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    hmac_sha256(
        secret,
        &handshake_transcript(
            b"session-key",
            endpoint,
            client_pid,
            guard_pid,
            started_at_unix,
            client_nonce,
            server_nonce,
        ),
    )
}

#[cfg(any(windows, test))]
fn ready_proof(
    session_key: &[u8; 32],
    guard_pid: u32,
    started_at_unix: u64,
    process_policy_version: u32,
    process_policy_enforced: bool,
    hardening_version: u32,
    hardening_enforced: bool,
    secure_pipe_acl: bool,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(b"NeverLauncher NeverGuard IPC ready v4\0");
    data.extend_from_slice(&guard_pid.to_le_bytes());
    data.extend_from_slice(&started_at_unix.to_le_bytes());
    data.extend_from_slice(&process_policy_version.to_le_bytes());
    data.push(u8::from(process_policy_enforced));
    data.extend_from_slice(&hardening_version.to_le_bytes());
    data.push(u8::from(hardening_enforced));
    data.push(u8::from(secure_pipe_acl));
    hmac_sha256(session_key, &data)
}

#[cfg(any(windows, test))]
fn request_mac(
    session_key: &[u8; 32],
    sequence: u64,
    request_id: &str,
    command: &str,
    payload: &str,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(payload.len() + 112);
    data.extend_from_slice(b"NeverLauncher NeverGuard IPC request v4\0");
    data.extend_from_slice(&sequence.to_le_bytes());
    append_len_prefixed(&mut data, request_id.as_bytes());
    append_len_prefixed(&mut data, command.as_bytes());
    append_len_prefixed(&mut data, payload.as_bytes());
    hmac_sha256(session_key, &data)
}

#[cfg(any(windows, test))]
fn response_mac(
    session_key: &[u8; 32],
    sequence: u64,
    request_id: &str,
    ok: bool,
    payload: &str,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(payload.len() + 96);
    data.extend_from_slice(b"NeverLauncher NeverGuard IPC response v4\0");
    data.extend_from_slice(&sequence.to_le_bytes());
    append_len_prefixed(&mut data, request_id.as_bytes());
    data.push(u8::from(ok));
    append_len_prefixed(&mut data, payload.as_bytes());
    hmac_sha256(session_key, &data)
}

#[cfg(any(windows, test))]
fn integrity_session_proof(session_key: &[u8; 32], evidence_digest: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(b"NeverLauncher NeverGuard integrity evidence session v1\0");
    data.extend_from_slice(evidence_digest);
    hmac_sha256(session_key, &data)
}

#[cfg(any(windows, test))]
fn attestation_session_proof(session_key: &[u8; 32], attestation_digest: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(b"NeverLauncher NeverGuard remote attestation session v1\0");
    data.extend_from_slice(attestation_digest);
    hmac_sha256(session_key, &data)
}

#[cfg(any(windows, test))]
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA-256 accepts arbitrary key length");
    mac.update(message);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(any(windows, test))]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(windows)]
fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("system clock error: {err}"))
}

pub fn neverguard_executable_name() -> &'static str {
    if cfg!(windows) {
        "neverguard.exe"
    } else {
        "neverguard"
    }
}

pub fn validate_neverguard_path(path: &Path) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "NeverGuard executable path не содержит file name".to_string())?;
    if !name.eq_ignore_ascii_case(neverguard_executable_name()) {
        return Err(format!(
            "NeverGuard executable должен называться {}, получено {name}",
            neverguard_executable_name()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn handshake_is_bound_to_endpoint_and_processes() {
        let secret = [7u8; 32];
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];
        let a = handshake_proof(
            &secret,
            b"server",
            r"\\.\pipe\NeverLauncher.Guard.10.aaa",
            10,
            20,
            30,
            &client_nonce,
            &server_nonce,
        );
        let b = handshake_proof(
            &secret,
            b"server",
            r"\\.\pipe\NeverLauncher.Guard.11.aaa",
            10,
            20,
            30,
            &client_nonce,
            &server_nonce,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn session_key_and_ready_proof_are_domain_separated() {
        let secret = [3u8; 32];
        let client_nonce = [4u8; 32];
        let server_nonce = [5u8; 32];
        let session = derive_session_key(
            &secret,
            r"\\.\pipe\NeverLauncher.Guard.42.abcdef",
            42,
            43,
            44,
            &client_nonce,
            &server_nonce,
        );
        let server = handshake_proof(
            &secret,
            b"server",
            r"\\.\pipe\NeverLauncher.Guard.42.abcdef",
            42,
            43,
            44,
            &client_nonce,
            &server_nonce,
        );
        assert_ne!(session, server);
        assert_ne!(ready_proof(&session, 43, 44, 1, true, 1, true, true), session);
    }

    #[test]
    fn ready_proof_is_bound_to_process_policy_state() {
        let key = [6u8; 32];
        let enforced = ready_proof(&key, 43, 44, 1, true, 1, true, true);
        let not_enforced = ready_proof(&key, 43, 44, 1, false, 1, true, true);
        let next_version = ready_proof(&key, 43, 44, 2, true, 1, true, true);
        let no_hardening = ready_proof(&key, 43, 44, 1, true, 1, false, true);
        let insecure_acl = ready_proof(&key, 43, 44, 1, true, 1, true, false);
        assert_ne!(enforced, not_enforced);
        assert_ne!(enforced, next_version);
        assert_ne!(enforced, no_hardening);
        assert_ne!(enforced, insecure_acl);
    }

    #[test]
    fn integrity_evidence_proof_is_session_and_digest_bound() {
        let digest = [0x5au8; 32];
        let first = integrity_session_proof(&[1u8; 32], &digest);
        let second = integrity_session_proof(&[2u8; 32], &digest);
        let mut changed_digest = digest;
        changed_digest[0] ^= 0xff;
        let changed = integrity_session_proof(&[1u8; 32], &changed_digest);
        assert_ne!(first, second);
        assert_ne!(first, changed);
    }

    #[test]
    fn request_mac_changes_with_sequence_and_direction() {
        let key = [9u8; 32];
        let first = request_mac(&key, 1, "00112233445566778899aabbccddeeff", "status", "");
        let replay = request_mac(&key, 2, "00112233445566778899aabbccddeeff", "status", "");
        let response = response_mac(
            &key,
            1,
            "00112233445566778899aabbccddeeff",
            true,
            "{}",
        );
        assert_ne!(first, replay);
        assert_ne!(first, response);
    }

    #[test]
    fn constant_time_comparison_rejects_mismatch() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 0]));
    }

    #[test]
    fn endpoint_namespace_is_fail_closed() {
        assert!(validate_pipe_endpoint(r"\\.\pipe\NeverLauncher.Guard.100.abcdef").is_ok());
        assert!(validate_pipe_endpoint(r"\\.\pipe\Other.100.abcdef").is_err());
        assert!(validate_pipe_endpoint(r"\\.\pipe\NeverLauncher.Guard..\\evil").is_err());
    }
}
