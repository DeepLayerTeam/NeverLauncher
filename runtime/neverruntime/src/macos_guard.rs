#![cfg(target_os = "macos")]

use crate::{
    attestation::{challenge_sha256, recompute_attestation_sha256, validate_attestation_shape, GuardAttestationRequest, NeverGuardRemoteAttestation, NEVERGUARD_MACOS_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_REMOTE_ATTESTATION_VERSION},
    guard_ipc::{NeverGuardStatus, NEVERGUARD_PROTOCOL_VERSION},
    integrity::{collect_macos_integrity_evidence, recompute_evidence_sha256, validate_evidence_shape, NeverGuardIntegrityEvidence},
    macos_policy::{ensure_macos_production_hardening, guard_policy_report, install_parent_exit_watch, prepare_guard_command, verify_macos_code_signature, MacOSProductionHardeningReport, NEVERGUARD_MACOS_HARDENING_VERSION, NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA, NEVERGUARD_MACOS_PROCESS_POLICY_VERSION},
    windows_policy::GuardProcessPolicyReport,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout, Duration, Instant},
};
use zeroize::Zeroize;

const SECRET_LEN: usize = 32;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT_SECS: u64 = 8;
const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const COMMAND_TIMEOUT_SECS: u64 = 3;
const EVIDENCE_COMMAND_TIMEOUT_SECS: u64 = 20;
const STARTUP_AUTH_WINDOW_SECS: u64 = 12;
const PACKAGE_MANIFEST: &str = "MACOS_PACKAGE_MANIFEST.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacOSPackageManifest {
    schema_version: String,
    product_version: String,
    platform: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    never_guard_protocol_version: u32,
    #[serde(default)]
    authenticated_ipc: String,
    #[serde(default)]
    macos_production_hardening_version: u32,
    bundle_identifier: String,
    #[serde(default)]
    signing_team_id: String,
    #[serde(default)]
    desktop_sha256: String,
    #[serde(default)]
    desktop_size: u64,
    #[serde(default)]
    guard_sha256: String,
    #[serde(default)]
    guard_size: u64,
    #[serde(default)]
    developer_id_required: bool,
    #[serde(default)]
    notarization_required: bool,
    #[serde(default)]
    artifacts: Vec<MacOSPackageArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacOSPackageArtifact {
    bundle_path: String,
    component: String,
    sha256: String,
    size: u64,
    #[serde(default)]
    team_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientHello { kind: String, protocol_version: u32, client_pid: u32, client_nonce: String }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerChallenge { kind: String, protocol_version: u32, guard_pid: u32, started_at_unix: u64, server_nonce: String, server_proof: String }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientAuthentication { kind: String, client_proof: String }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerReady { kind: String, protocol_version: u32, guard_pid: u32, started_at_unix: u64, process_policy_version: u32, process_policy_enforced: bool, hardening_version: u32, hardening_enforced: bool, secure_pipe_acl: bool, ready_proof: String }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestEnvelope { protocol_version: u32, sequence: u64, request_id: String, command: String, payload: String, mac: String }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseEnvelope { protocol_version: u32, sequence: u64, request_id: String, ok: bool, payload: String, mac: String }

struct GuardHandle { child: Child, stream: UnixStream, session_key: [u8;32], next_sequence: u64, package_manifest_verified: bool, socket_path: PathBuf }
impl Drop for GuardHandle { fn drop(&mut self){ self.session_key.zeroize(); let _=std::fs::remove_file(&self.socket_path); } }

#[derive(Clone)]
pub struct NeverGuardSupervisor { inner: Arc<Mutex<Option<GuardHandle>>>, executable: Option<PathBuf>, require_package_manifest: bool }
impl Default for NeverGuardSupervisor { fn default()->Self{Self::new()} }
impl NeverGuardSupervisor {
    pub fn new()->Self { Self{inner:Arc::new(Mutex::new(None)),executable:None,require_package_manifest:!cfg!(debug_assertions)} }
    pub fn with_executable(executable:PathBuf)->Self { Self{inner:Arc::new(Mutex::new(None)),executable:Some(executable),require_package_manifest:false} }

    pub async fn ensure_started(&self)->Result<NeverGuardStatus,String>{
        let mut state=self.inner.lock().await;
        if let Some(handle)=state.as_mut(){
            if handle.child.try_wait().map_err(|e|format!("NeverGuard process check failed: {e}"))?.is_none(){
                if let Ok(value)=send_command(handle,"status","").await { let mut s=parse_status(value)?; s.lifetime_job_enforced=true; s.package_manifest_verified=handle.package_manifest_verified; return Ok(s); }
            }
        }
        if let Some(mut stale)=state.take(){ let _=stale.child.kill().await; }
        let executable=self.executable.clone().unwrap_or(resolve_guard_executable()?);
        crate::guard_ipc::validate_neverguard_path(&executable)?;
        validate_secure_file(&executable, true)?;
        let manifest_ok=if self.require_package_manifest { verify_macos_package_manifest(&executable)?; true } else { false };
        let parent_pid=std::process::id(); let endpoint=make_endpoint(parent_pid)?; let mut secret=random32();
        let mut command=Command::new(&executable);
        command.arg("--socket").arg(&endpoint).arg("--parent-pid").arg(parent_pid.to_string()).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        prepare_guard_command(&mut command);
        let mut child=command.spawn().map_err(|e|format!("failed to spawn NeverGuard {}: {e}",executable.display()))?;
        let guard_pid=child.id().ok_or_else(||"NeverGuard PID unavailable".to_string())?;
        let mut stdin=child.stdin.take().ok_or_else(||"NeverGuard bootstrap stdin unavailable".to_string())?;
        if let Err(e)=stdin.write_all(&secret).await { secret.zeroize(); let _=child.kill().await; return Err(format!("NeverGuard bootstrap write failed: {e}")); }
        let _=stdin.shutdown().await;
        let stream=match connect_socket(&endpoint,guard_pid).await {Ok(v)=>v,Err(e)=>{secret.zeroize();let _=child.kill().await;return Err(e)}};
        let (stream,session_key,_handshake_status)=match timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),client_authenticate(stream,&endpoint,parent_pid,guard_pid,&secret)).await {
            Ok(Ok(v))=>v, Ok(Err(e))=>{secret.zeroize();let _=child.kill().await;return Err(e)}, Err(_)=>{secret.zeroize();let _=child.kill().await;return Err("NeverGuard macOS authenticated IPC handshake timeout".into())}
        };
        secret.zeroize();
        let mut handle=GuardHandle{child,stream,session_key,next_sequence:1,package_manifest_verified:manifest_ok,socket_path:endpoint};
        let status_value=send_command(&mut handle,"status","").await.map_err(|e|format!("NeverGuard release identity query failed: {e}"))?;
        let mut status=parse_status(status_value)?; status.lifetime_job_enforced=true; status.package_manifest_verified=manifest_ok;
        *state=Some(handle); Ok(status)
    }
    pub async fn status(&self)->Result<NeverGuardStatus,String>{self.ensure_started().await}
    pub async fn ping(&self)->Result<(),String>{ self.ensure_started().await?; let mut s=self.inner.lock().await; let h=s.as_mut().ok_or("NeverGuard missing")?; let v=send_command(h,"ping","").await?; if v.get("pong").and_then(Value::as_bool)==Some(true){Ok(())}else{Err("invalid NeverGuard ping".into())} }
    pub async fn process_policy(&self)->Result<GuardProcessPolicyReport,String>{ self.ensure_started().await?; let mut s=self.inner.lock().await; let h=s.as_mut().ok_or("NeverGuard missing")?; let v=send_command(h,"process-policy","").await?; let p:GuardProcessPolicyReport=serde_json::from_value(v).map_err(|e|e.to_string())?; validate_policy(&p)?; Ok(p) }
    pub async fn integrity_evidence(&self)->Result<NeverGuardIntegrityEvidence,String>{ self.ensure_started().await?; let mut s=self.inner.lock().await; let h=s.as_mut().ok_or("NeverGuard missing")?; let v=send_command(h,"integrity-evidence","").await?; let e:NeverGuardIntegrityEvidence=serde_json::from_value(v).map_err(|e|e.to_string())?; validate_evidence(h,&e)?; Ok(e) }
    pub async fn remote_attestation(&self,challenge_id:&str,challenge:&str)->Result<NeverGuardRemoteAttestation,String>{
        if challenge_id.trim().is_empty()||challenge_id.len()>160||challenge.is_empty()||challenge.len()>4096{return Err("NeverGuard attestation challenge malformed".into())}
        self.ensure_started().await?; let payload=serde_json::to_string(&GuardAttestationRequest{challenge_id:challenge_id.into(),challenge:challenge.into()}).map_err(|e|e.to_string())?;
        let mut s=self.inner.lock().await; let h=s.as_mut().ok_or("NeverGuard missing")?; let v=send_command(h,"guard-attestation",&payload).await?;
        let a:NeverGuardRemoteAttestation=serde_json::from_value(v).map_err(|e|e.to_string())?; validate_attestation(h,challenge_id,challenge,&a)?; Ok(a)
    }
    pub async fn shutdown(&self)->Result<(),String>{ let mut s=self.inner.lock().await; let Some(mut h)=s.take() else{return Ok(())}; let _=send_command(&mut h,"shutdown","").await; match timeout(Duration::from_secs(2),h.child.wait()).await{Ok(Ok(_))=>Ok(()),_=>{h.child.kill().await.map_err(|e|e.to_string())?;Ok(())}} }
}

fn current_uid()->u32{unsafe{libc::geteuid()}}
fn runtime_dir()->Result<PathBuf,String>{
    let uid=current_uid();
    let base=std::env::temp_dir();
    let meta=std::fs::metadata(&base).map_err(|e|format!("stat macOS temp directory {} failed: {e}",base.display()))?;
    if !meta.is_dir()||meta.uid()!=uid||(meta.mode()&0o077)!=0{return Err("macOS temp runtime directory must be private and owned by current uid".into())}
    let dir=base.join(format!("neverlauncher-{uid}"));
    std::fs::create_dir_all(&dir).map_err(|e|format!("create macOS runtime dir failed: {e}"))?;
    std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;
    let dm=std::fs::metadata(&dir).map_err(|e|e.to_string())?;
    if dm.uid()!=uid||(dm.mode()&0o077)!=0{return Err("macOS NeverLauncher runtime directory permissions are unsafe".into())}
    Ok(dir)
}
fn make_endpoint(pid:u32)->Result<PathBuf,String>{
    let mut r=[0u8;8];OsRng.fill_bytes(&mut r);
    let endpoint=runtime_dir()?.join(format!("guard-{pid}-{}.sock",hex::encode(r)));
    if endpoint.as_os_str().len()>100{return Err("macOS NeverGuard Unix socket path exceeds sockaddr_un limit".into())}
    Ok(endpoint)
}
fn validate_endpoint(path:&Path)->Result<(),String>{
    let base=runtime_dir()?.canonicalize().map_err(|e|e.to_string())?;
    let parent=path.parent().ok_or("socket parent missing")?.canonicalize().map_err(|e|e.to_string())?;
    if parent!=base{return Err("NeverGuard socket outside private macOS runtime directory".into())}
    let name=path.file_name().and_then(|v|v.to_str()).ok_or("socket filename invalid")?;
    if !name.starts_with("guard-")||!name.ends_with(".sock")||name.len()>96{return Err("NeverGuard socket name malformed".into())}
    Ok(())
}
fn validate_secure_file(path:&Path,executable:bool)->Result<(),String>{
    let sm=std::fs::symlink_metadata(path).map_err(|e|format!("stat {} failed: {e}",path.display()))?;
    if sm.file_type().is_symlink()||!sm.file_type().is_file(){return Err(format!("{} must be a regular non-symlink file",path.display()))}
    let owner=sm.uid(); if owner!=current_uid()&&owner!=0{return Err(format!("{} must be owned by the current uid or root",path.display()))}
    if sm.mode()&0o022!=0{return Err(format!("{} must not be group/world writable",path.display()))}
    if executable&&sm.mode()&0o111==0{return Err(format!("{} is not executable",path.display()))}
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|err| format!("open {} failed: {err}", path.display()))?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|err| format!("read {} failed: {err}", path.display()))?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn bundle_root(desktop:&Path)->Result<PathBuf,String>{
    let macos=desktop.parent().ok_or("desktop MacOS directory missing")?;
    if macos.file_name().and_then(|v|v.to_str())!=Some("MacOS"){return Err("Desktop must run from a signed .app/Contents/MacOS bundle".into())}
    let contents=macos.parent().ok_or("app Contents directory missing")?;
    if contents.file_name().and_then(|v|v.to_str())!=Some("Contents"){return Err("Desktop must run from a signed .app Contents directory".into())}
    contents.parent().map(Path::to_path_buf).ok_or_else(||"app bundle root missing".to_string())
}
fn verify_macos_package_manifest(guard:&Path)->Result<(),String>{
    let desktop=std::env::current_exe().map_err(|e|e.to_string())?; validate_secure_file(&desktop,true)?; validate_secure_file(guard,true)?;
    let desktop_dir=desktop.parent().ok_or("desktop parent missing")?.canonicalize().map_err(|e|e.to_string())?;
    let guard_dir=guard.parent().ok_or("guard parent missing")?.canonicalize().map_err(|e|e.to_string())?;
    if desktop_dir!=guard_dir{return Err("Desktop and NeverGuard must be in the same app bundle MacOS directory".into())}
    let app=bundle_root(&desktop)?;
    let manifest_path=app.join("Contents/Resources").join(PACKAGE_MANIFEST);
    validate_secure_file(&manifest_path,false)?;
    let manifest:MacOSPackageManifest=serde_json::from_slice(&std::fs::read(&manifest_path).map_err(|e|e.to_string())?).map_err(|e|format!("macOS package manifest JSON invalid: {e}"))?;
    let canonical_arch=if cfg!(target_arch="aarch64"){"arm64"}else{"x64"};
    let legacy=manifest.schema_version=="1.0"&&manifest.platform=="macos-universal"&&manifest.never_guard_protocol_version==NEVERGUARD_PROTOCOL_VERSION&&manifest.authenticated_ipc=="unix-domain-socket+0600+peer-credentials+hmac-sha256-v4"&&manifest.macos_production_hardening_version==NEVERGUARD_MACOS_HARDENING_VERSION&&manifest.developer_id_required&&manifest.notarization_required;
    let canonical=manifest.schema_version=="1.0"&&manifest.platform=="macos"&&manifest.architecture==canonical_arch&&!manifest.artifacts.is_empty();
    if manifest.product_version!=env!("CARGO_PKG_VERSION")||manifest.bundle_identifier!="ru.skif4er.neverlauncher"||(!legacy&&!canonical){return Err("macOS package manifest identity/hardening mismatch".into())}
    let mut signing_team=manifest.signing_team_id.clone();
    if canonical {
        for (component,path) in [("desktop-launcher",desktop.as_path()),("guard",guard)] {
            let artifact=manifest.artifacts.iter().find(|a|a.component==component).ok_or_else(||format!("macOS package artifact missing: {component}"))?;
            let expected_bundle_path=format!("NeverLauncher.app/Contents/MacOS/{}",path.file_name().and_then(|v|v.to_str()).ok_or("macOS artifact filename invalid")?);
            if artifact.bundle_path!=expected_bundle_path{return Err(format!("macOS package bundle path mismatch for {component}"))}
            let metadata=std::fs::metadata(path).map_err(|e|format!("metadata {} failed: {e}",path.display()))?;
            if metadata.len()!=artifact.size||!sha256_file(path)?.eq_ignore_ascii_case(&artifact.sha256){return Err(format!("macOS package artifact verification failed: {component}"))}
            if signing_team.is_empty(){signing_team=artifact.team_id.clone()} else if !artifact.team_id.is_empty()&&!artifact.team_id.eq_ignore_ascii_case(&signing_team){return Err("macOS package signing team is inconsistent".into())}
        }
    } else {
        for (path, expected_size, expected_sha256) in [(desktop.as_path(), manifest.desktop_size, manifest.desktop_sha256.as_str()), (guard, manifest.guard_size, manifest.guard_sha256.as_str())] {
            let metadata=std::fs::metadata(path).map_err(|e|format!("metadata {} failed: {e}",path.display()))?;
            if metadata.len()!=expected_size{return Err(format!("macOS package size mismatch for {}",path.display()))}
            let actual=sha256_file(path)?;
            if !actual.eq_ignore_ascii_case(expected_sha256){return Err(format!("macOS package SHA-256 mismatch for {}",path.display()))}
        }
    }
    if signing_team.is_empty(){return Err("macOS package signing Team ID is missing".into())}
    for (path, expected_identifier) in [(desktop.as_path(), "ru.skif4er.neverlauncher"), (guard, "ru.skif4er.neverlauncher.guard")] {
        let sig=verify_macos_code_signature(path)?;
        if !sig.valid||!sig.hardened_runtime||!sig.library_validation{return Err(format!("macOS Hardened Runtime verification failed: {}",path.display()))}
        if sig.team_identifier.as_deref()!=Some(signing_team.as_str()){return Err(format!("macOS signing team mismatch: {}",path.display()))}
        if sig.identifier.as_deref()!=Some(expected_identifier){return Err(format!("macOS code-signing identifier mismatch for {}: expected {expected_identifier}, got {:?}",path.display(),sig.identifier))}
    }
    let app_verify=std::process::Command::new("/usr/bin/codesign").args(["--verify","--deep","--strict","--verbose=2"]).arg(&app).output().map_err(|e|format!("codesign app verify failed: {e}"))?;
    if !app_verify.status.success(){return Err(format!("macOS app bundle signature invalid: {}",String::from_utf8_lossy(&app_verify.stderr).trim()))}
    let gatekeeper=std::process::Command::new("/usr/sbin/spctl").args(["--assess","--type","execute","--verbose=2"]).arg(&app).output().map_err(|e|format!("spctl assessment failed: {e}"))?;
    if !gatekeeper.status.success(){return Err(format!("macOS Gatekeeper/notarization assessment failed: {}",String::from_utf8_lossy(&gatekeeper.stderr).trim()))}
    Ok(())
}
fn resolve_guard_executable()->Result<PathBuf,String>{let exe=std::env::current_exe().map_err(|e|e.to_string())?;Ok(exe.parent().ok_or("desktop parent missing")?.join("neverguard"))}

async fn connect_socket(path:&Path,guard_pid:u32)->Result<UnixStream,String>{
    let deadline=Instant::now()+Duration::from_secs(CONNECT_TIMEOUT_SECS); loop{match UnixStream::connect(path).await{Ok(s)=>{verify_peer(&s,guard_pid,current_uid())?;return Ok(s)},Err(e)=>{if Instant::now()>=deadline{return Err(format!("NeverGuard Unix socket connect failed: {e}"))}sleep(Duration::from_millis(40)).await}}
    }
}
fn verify_peer(stream:&UnixStream,expected_pid:u32,expected_uid:u32)->Result<(),String>{
    let cred=stream.peer_cred().map_err(|e|format!("macOS Unix peer credential query failed: {e}"))?;
    let pid=cred.pid().ok_or_else(||"macOS Unix peer PID unavailable".to_string())?;
    if pid as u32!=expected_pid||cred.uid()!=expected_uid{return Err(format!("NeverGuard peer credential mismatch pid={pid} uid={}",cred.uid()))}
    Ok(())
}

async fn client_authenticate(mut s:UnixStream,endpoint:&Path,client_pid:u32,guard_pid:u32,secret:&[u8;32])->Result<(UnixStream,[u8;32],NeverGuardStatus),String>{
    let cn=random32(); write_frame(&mut s,&ClientHello{kind:"client-hello".into(),protocol_version:NEVERGUARD_PROTOCOL_VERSION,client_pid,client_nonce:hex::encode(cn)}).await?;
    let ch:ServerChallenge=read_frame(&mut s).await?; if ch.kind!="server-challenge"||ch.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||ch.guard_pid!=guard_pid{return Err("NeverGuard server challenge mismatch".into())}
    let sn=decode32(&ch.server_nonce,"serverNonce")?; let ep=endpoint.to_string_lossy(); let handshake=HandshakeContext{endpoint:&ep,client_pid,guard_pid,started:ch.started_at_unix,client_nonce:&cn,server_nonce:&sn}; let expected=proof(secret,b"server-proof",&handshake); if !ct_eq(&expected,&hex::decode(&ch.server_proof).map_err(|_|"invalid server proof")?){return Err("NeverGuard server authentication failed".into())}
    let cp=proof(secret,b"client-proof",&handshake); write_frame(&mut s,&ClientAuthentication{kind:"client-auth".into(),client_proof:hex::encode(cp)}).await?;
    let key=session_key(secret,&handshake); let ready:ServerReady=read_frame(&mut s).await?; if ready.kind!="ready"||ready.protocol_version!=NEVERGUARD_PROTOCOL_VERSION{return Err("NeverGuard ready mismatch".into())}
    let expected=ready_proof(&key,ReadyProofState{pid:ready.guard_pid,started:ready.started_at_unix,policy_version:ready.process_policy_version,policy_enforced:ready.process_policy_enforced,hardening_version:ready.hardening_version,hardening_enforced:ready.hardening_enforced,secure_acl:ready.secure_pipe_acl}); if !ct_eq(&expected,&hex::decode(&ready.ready_proof).map_err(|_|"invalid ready proof")?){return Err("NeverGuard ready proof invalid".into())}
    if ready.process_policy_version!=NEVERGUARD_MACOS_PROCESS_POLICY_VERSION||!ready.process_policy_enforced||ready.hardening_version!=NEVERGUARD_MACOS_HARDENING_VERSION||!ready.hardening_enforced||!ready.secure_pipe_acl{return Err("NeverGuard macOS policy/hardening not enforced".into())}
    Ok((s,key,NeverGuardStatus{state:"ready".into(),product_version:env!("CARGO_PKG_VERSION").into(),platform:"macos-universal".into(),pid:guard_pid,parent_pid:client_pid,protocol_version:NEVERGUARD_PROTOCOL_VERSION,authenticated:true,process_policy_version:ready.process_policy_version,process_policy_enforced:true,hardening_version:ready.hardening_version,hardening_enforced:true,secure_pipe_acl:true,lifetime_job_enforced:true,package_manifest_verified:false,started_at_unix:ch.started_at_unix,message:"NeverGuard macOS authenticated Unix IPC ready".into()}))
}

async fn send_command(h:&mut GuardHandle,command:&str,payload:&str)->Result<Value,String>{
    let seq=h.next_sequence; let id=random_id(); let mac=request_mac(&h.session_key,seq,&id,command,payload); let req=RequestEnvelope{protocol_version:NEVERGUARD_PROTOCOL_VERSION,sequence:seq,request_id:id.clone(),command:command.into(),payload:payload.into(),mac:hex::encode(mac)};
    timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS),write_frame(&mut h.stream,&req)).await.map_err(|_|"NeverGuard IPC write timeout".to_string())??;
    let response_timeout = if matches!(command, "integrity-evidence" | "guard-attestation") { EVIDENCE_COMMAND_TIMEOUT_SECS } else { COMMAND_TIMEOUT_SECS };
    let resp:ResponseEnvelope=timeout(Duration::from_secs(response_timeout),read_frame(&mut h.stream)).await.map_err(|_|format!("NeverGuard IPC read timeout for {command}"))??;
    if resp.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||resp.sequence!=seq||resp.request_id!=id{return Err("NeverGuard response binding mismatch".into())}; let expected=response_mac(&h.session_key,seq,&id,resp.ok,&resp.payload); if !ct_eq(&expected,&hex::decode(&resp.mac).map_err(|_|"invalid response mac")?){return Err("NeverGuard response MAC invalid".into())}; h.next_sequence=h.next_sequence.checked_add(1).ok_or("IPC sequence exhausted")?; if !resp.ok{return Err(resp.payload)}; serde_json::from_str(&resp.payload).map_err(|e|format!("NeverGuard response JSON invalid: {e}"))
}
fn parse_status(v:Value)->Result<NeverGuardStatus,String>{let s:NeverGuardStatus=serde_json::from_value(v).map_err(|e|format!("NeverGuard status invalid: {e}"))?;validate_release_identity(&s)?;Ok(s)}
fn validate_release_identity(s:&NeverGuardStatus)->Result<(),String>{if s.product_version!=env!("CARGO_PKG_VERSION"){return Err(format!("NeverGuard release version mismatch: Desktop={} Guard={}",env!("CARGO_PKG_VERSION"),s.product_version))}if s.platform!="macos-universal"{return Err(format!("NeverGuard platform mismatch: expected macos-universal, got {}",s.platform))}if s.protocol_version!=NEVERGUARD_PROTOCOL_VERSION{return Err(format!("NeverGuard protocol mismatch: Desktop={} Guard={}",NEVERGUARD_PROTOCOL_VERSION,s.protocol_version))}Ok(())}
fn validate_policy(p:&GuardProcessPolicyReport)->Result<(),String>{let m=p.macos.as_ref().ok_or("macOS process policy details missing")?;if p.schema!=NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA||p.policy_version!=1||!p.enforced||!m.core_dumps_disabled||!m.debugger_attach_denied||!m.code_signature_valid||!m.hardened_runtime||!m.library_validation||!m.dyld_environment_sanitized||!m.parent_exit_watch||!m.private_umask{return Err("NeverGuard macOS process policy rejected".into())}Ok(())}
fn validate_evidence(h:&GuardHandle,e:&NeverGuardIntegrityEvidence)->Result<(),String>{validate_evidence_shape(e)?;let d=recompute_evidence_sha256(e)?;if !ct_eq(&d,&hex::decode(&e.evidence_sha256).map_err(|_|"invalid evidence digest")?){return Err("evidence digest mismatch".into())};let p=integrity_proof(&h.session_key,&d);if !ct_eq(&p,&hex::decode(&e.session_proof).map_err(|_|"invalid evidence proof")?){return Err("evidence session proof mismatch".into())}Ok(())}
fn validate_attestation(h:&GuardHandle,id:&str,challenge:&str,a:&NeverGuardRemoteAttestation)->Result<(),String>{validate_attestation_shape(a)?;if a.schema!=NEVERGUARD_MACOS_REMOTE_ATTESTATION_SCHEMA||a.challenge_id!=id||a.challenge_sha256!=challenge_sha256(challenge){return Err("macOS Guard Attestation binding mismatch".into())};validate_evidence(h,&a.evidence)?;validate_policy(&a.process_policy)?;let d=recompute_attestation_sha256(a)?;if !ct_eq(&d,&hex::decode(&a.attestation_sha256).map_err(|_|"invalid attestation digest")?){return Err("attestation digest mismatch".into())};let p=attestation_proof(&h.session_key,&d);if !ct_eq(&p,&hex::decode(&a.session_proof).map_err(|_|"invalid attestation proof")?){return Err("attestation session proof mismatch".into())}Ok(())}

pub async fn run_macos_guard_server(endpoint:PathBuf,parent_pid:u32)->Result<(),String>{
    validate_endpoint(&endpoint)?; let hard=ensure_macos_production_hardening()?; let observed=crate::integrity::observed_macos_parent_pid(std::process::id())?; if observed!=parent_pid{return Err(format!("NeverGuard macOS parent mismatch expected={parent_pid} observed={observed}"));} install_parent_exit_watch(parent_pid)?; let policy=policy_report()?;
    let mut secret=[0u8;SECRET_LEN]; { let mut bootstrap_stdin=std::io::stdin(); std::io::Read::read_exact(&mut bootstrap_stdin,&mut secret).map_err(|e|format!("bootstrap secret read failed: {e}"))?; }
    if endpoint.exists(){return Err("NeverGuard Unix socket already exists".into())} let listener=UnixListener::bind(&endpoint).map_err(|e|format!("bind {} failed: {e}",endpoint.display()))?; std::fs::set_permissions(&endpoint,std::fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;
    let m=std::fs::symlink_metadata(&endpoint).map_err(|e|e.to_string())?; if !m.file_type().is_socket()||m.uid()!=current_uid()||(m.mode()&0o077)!=0{return Err("NeverGuard Unix socket ACL verification failed".into())}
    let started=now_unix()?; let deadline=Instant::now()+Duration::from_secs(STARTUP_AUTH_WINDOW_SECS);
    loop { let remaining=deadline.saturating_duration_since(Instant::now()); if remaining.is_zero(){secret.zeroize();return Err("NeverGuard startup authentication window expired".into())}; let (stream,_)=timeout(remaining,listener.accept()).await.map_err(|_|"NeverGuard accept timeout".to_string())?.map_err(|e|e.to_string())?;
        if verify_peer(&stream,parent_pid,current_uid()).is_err(){continue}
        match server_authenticate(stream,&endpoint,parent_pid,started,&secret,&policy,&hard).await {Ok((stream,key))=>{secret.zeroize();let r=serve_commands(stream,key,parent_pid,started,policy,hard).await;let _=std::fs::remove_file(&endpoint);return r},Err(_)=>continue}
    }
}
fn policy_report()->Result<GuardProcessPolicyReport,String>{let l=guard_policy_report(true)?;Ok(GuardProcessPolicyReport{schema:NEVERGUARD_MACOS_PROCESS_POLICY_SCHEMA.into(),policy_version:1,pid:std::process::id(),enforced:true,dynamic_code_prohibited:false,extension_points_disabled:false,strict_handle_checks:false,remote_images_blocked:false,low_mandatory_label_images_blocked:false,prefer_system32_images:false,child_process_creation_blocked:false,linux:None,macos:Some(l)})}
async fn server_authenticate(mut s:UnixStream,endpoint:&Path,parent_pid:u32,started:u64,secret:&[u8;32],policy:&GuardProcessPolicyReport,hard:&MacOSProductionHardeningReport)->Result<(UnixStream,[u8;32]),String>{
    let hello:ClientHello=timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),read_frame(&mut s)).await.map_err(|_|"client hello timeout".to_string())??; if hello.kind!="client-hello"||hello.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||hello.client_pid!=parent_pid{return Err("client hello mismatch".into())}; let cn=decode32(&hello.client_nonce,"clientNonce")?;let sn=random32();let pid=std::process::id();let ep=endpoint.to_string_lossy();let handshake=HandshakeContext{endpoint:&ep,client_pid:parent_pid,guard_pid:pid,started,client_nonce:&cn,server_nonce:&sn};let sp=proof(secret,b"server-proof",&handshake);write_frame(&mut s,&ServerChallenge{kind:"server-challenge".into(),protocol_version:NEVERGUARD_PROTOCOL_VERSION,guard_pid:pid,started_at_unix:started,server_nonce:hex::encode(sn),server_proof:hex::encode(sp)}).await?;let auth:ClientAuthentication=read_frame(&mut s).await?;let expected=proof(secret,b"client-proof",&handshake);if auth.kind!="client-auth"||!ct_eq(&expected,&hex::decode(auth.client_proof).map_err(|_|"invalid client proof")?){return Err("client authentication failed".into())};let key=session_key(secret,&handshake);let rp=ready_proof(&key,ReadyProofState{pid,started,policy_version:policy.policy_version,policy_enforced:policy.enforced,hardening_version:hard.hardening_version,hardening_enforced:hard.enforced,secure_acl:true});write_frame(&mut s,&ServerReady{kind:"ready".into(),protocol_version:NEVERGUARD_PROTOCOL_VERSION,guard_pid:pid,started_at_unix:started,process_policy_version:policy.policy_version,process_policy_enforced:policy.enforced,hardening_version:hard.hardening_version,hardening_enforced:hard.enforced,secure_pipe_acl:true,ready_proof:hex::encode(rp)}).await?;Ok((s,key))
}
async fn serve_commands(mut s:UnixStream,key:[u8;32],parent_pid:u32,started:u64,policy:GuardProcessPolicyReport,hard:MacOSProductionHardeningReport)->Result<(),String>{let mut seq=1u64;loop{let req:RequestEnvelope=read_frame(&mut s).await?;if req.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||req.sequence!=seq{return Err("request sequence mismatch".into())};let expected=request_mac(&key,seq,&req.request_id,&req.command,&req.payload);if !ct_eq(&expected,&hex::decode(&req.mac).map_err(|_|"invalid request mac")?){return Err("request MAC invalid".into())};let (ok,payload,shutdown)=match req.command.as_str(){"ping"=>(true,json!({"pong":true}).to_string(),false),"status"=>(true,serde_json::to_string(&NeverGuardStatus{state:"ready".into(),product_version:env!("CARGO_PKG_VERSION").into(),platform:"macos-universal".into(),pid:std::process::id(),parent_pid,protocol_version:NEVERGUARD_PROTOCOL_VERSION,authenticated:true,process_policy_version:1,process_policy_enforced:true,hardening_version:hard.hardening_version,hardening_enforced:true,secure_pipe_acl:true,lifetime_job_enforced:true,package_manifest_verified:false,started_at_unix:started,message:"NeverGuard macOS production boundary ready".into()}).unwrap(),false),"process-policy"=>(true,serde_json::to_string(&policy).unwrap(),false),"integrity-evidence"=>{let mut e=tokio::task::spawn_blocking(move || collect_macos_integrity_evidence(parent_pid)).await.map_err(|e|format!("NeverGuard integrity worker failed: {e}"))??;let d=recompute_evidence_sha256(&e)?;e.session_proof=hex::encode(integrity_proof(&key,&d));(true,serde_json::to_string(&e).unwrap(),false)},"guard-attestation"=>{let r:GuardAttestationRequest=serde_json::from_str(&req.payload).map_err(|e|format!("attestation request invalid: {e}"))?;let mut e=tokio::task::spawn_blocking(move || collect_macos_integrity_evidence(parent_pid)).await.map_err(|e|format!("NeverGuard attestation integrity worker failed: {e}"))??;let ed=recompute_evidence_sha256(&e)?;e.session_proof=hex::encode(integrity_proof(&key,&ed));let mut a=NeverGuardRemoteAttestation{schema:NEVERGUARD_MACOS_REMOTE_ATTESTATION_SCHEMA.into(),attestation_version:NEVERGUARD_REMOTE_ATTESTATION_VERSION,challenge_id:r.challenge_id,challenge_sha256:challenge_sha256(&r.challenge),collected_at_unix:e.collected_at_unix,evidence:e,process_policy:policy.clone(),attestation_sha256:String::new(),session_proof:String::new()};let ad=recompute_attestation_sha256(&a)?;a.attestation_sha256=hex::encode(ad);a.session_proof=hex::encode(attestation_proof(&key,&ad));(true,serde_json::to_string(&a).unwrap(),false)},"shutdown"=>(true,json!({"shutdown":true}).to_string(),true),_=>(false,"unsupported command".into(),false)};let mac=response_mac(&key,seq,&req.request_id,ok,&payload);write_frame(&mut s,&ResponseEnvelope{protocol_version:NEVERGUARD_PROTOCOL_VERSION,sequence:seq,request_id:req.request_id,ok,payload,mac:hex::encode(mac)}).await?;if shutdown{return Ok(())}seq=seq.checked_add(1).ok_or("sequence exhausted")?}}

async fn write_frame<W:AsyncWrite+Unpin,T:Serialize>(w:&mut W,v:&T)->Result<(),String>{let mut b=serde_json::to_vec(v).map_err(|e|e.to_string())?;if b.len()>MAX_FRAME_BYTES{return Err("IPC frame too large".into())}b.push(b'\n');w.write_all(&b).await.map_err(|e|e.to_string())?;w.flush().await.map_err(|e|e.to_string())}
async fn read_frame<R:AsyncRead+Unpin,T:DeserializeOwned>(r:&mut R)->Result<T,String>{let mut b=Vec::new();let mut one=[0u8;1];loop{let n=r.read(&mut one).await.map_err(|e|e.to_string())?;if n==0{return Err("IPC peer closed".into())}if one[0]==b'\n'{break}if b.len()>=MAX_FRAME_BYTES{return Err("IPC frame too large".into())}b.push(one[0]);}if b.is_empty(){return Err("empty IPC frame".into())}serde_json::from_slice(&b).map_err(|e|e.to_string())}
fn random32()->[u8;32]{let mut b=[0u8;32];OsRng.fill_bytes(&mut b);b}fn random_id()->String{let mut b=[0u8;16];OsRng.fill_bytes(&mut b);hex::encode(b)}fn decode32(v:&str,n:&str)->Result<[u8;32],String>{let b=hex::decode(v).map_err(|_|format!("{n} invalid hex"))?;if b.len()!=32{return Err(format!("{n} invalid length"))}let mut o=[0u8;32];o.copy_from_slice(&b);Ok(o)}
#[derive(Clone, Copy)]
struct HandshakeContext<'a>{endpoint:&'a str,client_pid:u32,guard_pid:u32,started:u64,client_nonce:&'a [u8;32],server_nonce:&'a [u8;32]}
#[derive(Clone, Copy)]
struct ReadyProofState{pid:u32,started:u64,policy_version:u32,policy_enforced:bool,hardening_version:u32,hardening_enforced:bool,secure_acl:bool}
fn prefix(o:&mut Vec<u8>,v:&[u8]){o.extend_from_slice(&(v.len() as u32).to_le_bytes());o.extend_from_slice(v)}
fn transcript(label:&[u8],c:&HandshakeContext<'_>)->Vec<u8>{let mut d=Vec::new();d.extend_from_slice(b"NeverLauncher NeverGuard IPC v4\0");prefix(&mut d,label);prefix(&mut d,c.endpoint.as_bytes());d.extend_from_slice(&c.client_pid.to_le_bytes());d.extend_from_slice(&c.guard_pid.to_le_bytes());d.extend_from_slice(&c.started.to_le_bytes());d.extend_from_slice(c.client_nonce);d.extend_from_slice(c.server_nonce);d}
fn hmac(key:&[u8],msg:&[u8])->[u8;32]{let mut m=Hmac::<Sha256>::new_from_slice(key).unwrap();m.update(msg);let x=m.finalize().into_bytes();let mut o=[0u8;32];o.copy_from_slice(&x);o}
fn proof(k:&[u8;32],l:&[u8],c:&HandshakeContext<'_>)->[u8;32]{hmac(k,&transcript(l,c))}fn session_key(k:&[u8;32],c:&HandshakeContext<'_>)->[u8;32]{proof(k,b"session-key",c)}
fn ready_proof(k:&[u8;32],s:ReadyProofState)->[u8;32]{let mut d=Vec::new();d.extend_from_slice(b"NeverLauncher NeverGuard IPC ready v4\0");d.extend_from_slice(&s.pid.to_le_bytes());d.extend_from_slice(&s.started.to_le_bytes());d.extend_from_slice(&s.policy_version.to_le_bytes());d.push(u8::from(s.policy_enforced));d.extend_from_slice(&s.hardening_version.to_le_bytes());d.push(u8::from(s.hardening_enforced));d.push(u8::from(s.secure_acl));hmac(k,&d)}
fn request_mac(k:&[u8;32],seq:u64,id:&str,c:&str,p:&str)->[u8;32]{let mut d=Vec::new();d.extend_from_slice(b"NeverLauncher NeverGuard IPC request v4\0");d.extend_from_slice(&seq.to_le_bytes());prefix(&mut d,id.as_bytes());prefix(&mut d,c.as_bytes());prefix(&mut d,p.as_bytes());hmac(k,&d)}fn response_mac(k:&[u8;32],seq:u64,id:&str,ok:bool,p:&str)->[u8;32]{let mut d=Vec::new();d.extend_from_slice(b"NeverLauncher NeverGuard IPC response v4\0");d.extend_from_slice(&seq.to_le_bytes());prefix(&mut d,id.as_bytes());d.push(u8::from(ok));prefix(&mut d,p.as_bytes());hmac(k,&d)}fn integrity_proof(k:&[u8;32],d:&[u8;32])->[u8;32]{let mut x=b"NeverLauncher NeverGuard integrity evidence session v1\0".to_vec();x.extend_from_slice(d);hmac(k,&x)}fn attestation_proof(k:&[u8;32],d:&[u8;32])->[u8;32]{let mut x=b"NeverLauncher NeverGuard remote attestation session v1\0".to_vec();x.extend_from_slice(d);hmac(k,&x)}fn ct_eq(a:&[u8],b:&[u8])->bool{a.len()==b.len()&&bool::from(a.ct_eq(b))}fn now_unix()->Result<u64,String>{SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).map_err(|e|e.to_string())}
