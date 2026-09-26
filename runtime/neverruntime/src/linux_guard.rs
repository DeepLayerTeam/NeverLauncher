#![cfg(target_os = "linux")]

use crate::{
    attestation::{challenge_sha256, recompute_attestation_sha256, validate_attestation_shape, GuardAttestationRequest, NeverGuardRemoteAttestation, NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA, NEVERGUARD_REMOTE_ATTESTATION_VERSION},
    guard_ipc::{NeverGuardStatus, NEVERGUARD_PROTOCOL_VERSION},
    integrity::{collect_linux_integrity_evidence, recompute_evidence_sha256, validate_evidence_shape, NeverGuardIntegrityEvidence},
    linux_policy::{ensure_linux_production_hardening, guard_policy_report, prepare_guard_command, NEVERGUARD_LINUX_HARDENING_VERSION, NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA, NEVERGUARD_LINUX_PROCESS_POLICY_VERSION},
    windows_policy::GuardProcessPolicyReport,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
    os::unix::{fs::{FileTypeExt, MetadataExt, PermissionsExt}, io::AsRawFd},
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
const PACKAGE_MANIFEST: &str = "LINUX_PACKAGE_MANIFEST.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinuxPackageManifest {
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
    linux_production_hardening_version: u32,
    artifacts: Vec<LinuxPackageArtifact>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinuxPackageArtifact {
    name: String,
    #[serde(default)]
    package_path: String,
    size: u64,
    sha256: String,
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
        let manifest_ok=if self.require_package_manifest { verify_linux_package_manifest(&executable)?; true } else { false };
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
            Ok(Ok(v))=>v, Ok(Err(e))=>{secret.zeroize();let _=child.kill().await;return Err(e)}, Err(_)=>{secret.zeroize();let _=child.kill().await;return Err("NeverGuard Linux authenticated IPC handshake timeout".into())}
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
    let uid = current_uid();
    let p = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    let m=std::fs::metadata(&p).map_err(|e|format!("stat Linux runtime directory {} failed: {e}",p.display()))?;
    if !m.is_dir()||m.uid()!=uid||(m.mode()&0o077)!=0{return Err("Linux runtime directory must be owned by current uid with no group/world access".into())}
    let d=p.join("neverlauncher"); std::fs::create_dir_all(&d).map_err(|e|format!("create runtime dir failed: {e}"))?; std::fs::set_permissions(&d,std::fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?; Ok(d)
}
fn make_endpoint(pid:u32)->Result<PathBuf,String>{ let mut r=[0u8;8];OsRng.fill_bytes(&mut r);Ok(runtime_dir()?.join(format!("guard-{pid}-{}.sock",hex::encode(r)))) }
fn validate_endpoint(path:&Path)->Result<(),String>{ let base=runtime_dir()?.canonicalize().map_err(|e|e.to_string())?; let parent=path.parent().ok_or("socket parent missing")?.canonicalize().map_err(|e|e.to_string())?; if parent!=base{return Err("NeverGuard socket outside private runtime directory".into())}; let name=path.file_name().and_then(|v|v.to_str()).ok_or("socket filename invalid")?; if !name.starts_with("guard-")||!name.ends_with(".sock")||name.len()>96{return Err("NeverGuard socket name malformed".into())} Ok(()) }
fn validate_secure_file(path:&Path,executable:bool)->Result<(),String>{ let sm=std::fs::symlink_metadata(path).map_err(|e|format!("stat {} failed: {e}",path.display()))?; if sm.file_type().is_symlink()||!sm.file_type().is_file(){return Err(format!("{} must be a regular non-symlink file",path.display()))}; let owner=sm.uid(); if owner!=current_uid()&&owner!=0{return Err(format!("{} must be owned by the current uid or root",path.display()))}; if sm.mode()&0o022!=0{return Err(format!("{} must not be group/world writable",path.display()))}; if executable&&sm.mode()&0o111==0{return Err(format!("{} is not executable",path.display()))}; Ok(()) }
fn sha256_file(path:&Path)->Result<String,String>{let f=File::open(path).map_err(|e|e.to_string())?;let mut r=BufReader::new(f);let mut h=Sha256::new();let mut b=[0u8;65536];loop{let n=r.read(&mut b).map_err(|e|e.to_string())?;if n==0{break}h.update(&b[..n]);}Ok(hex::encode(h.finalize()))}
fn verify_linux_package_manifest(guard:&Path)->Result<(),String>{
    let desktop=std::env::current_exe().map_err(|e|e.to_string())?; validate_secure_file(&desktop,true)?; validate_secure_file(guard,true)?;
    let dd=desktop.parent().ok_or("desktop parent missing")?.canonicalize().map_err(|e|e.to_string())?; let gd=guard.parent().ok_or("guard parent missing")?.canonicalize().map_err(|e|e.to_string())?; if dd!=gd{return Err("Desktop and NeverGuard must be in same package directory".into())}
    let mp=dd.join(PACKAGE_MANIFEST); validate_secure_file(&mp,false)?; let raw=std::fs::read(&mp).map_err(|e|e.to_string())?; let m:LinuxPackageManifest=serde_json::from_slice(&raw).map_err(|e|format!("Linux package manifest JSON invalid: {e}"))?;
    let canonical_arch=if cfg!(target_arch="aarch64"){"arm64"}else{"x64"};
    let legacy=m.schema_version=="1.0"&&m.platform=="linux-amd64"&&m.never_guard_protocol_version==NEVERGUARD_PROTOCOL_VERSION&&m.authenticated_ipc=="unix-domain-socket+0600+so-peercred+hmac-sha256-v4"&&m.linux_production_hardening_version==NEVERGUARD_LINUX_HARDENING_VERSION;
    let canonical=m.schema_version=="1.0"&&m.platform=="linux"&&m.architecture==canonical_arch;
    if m.product_version!=env!("CARGO_PKG_VERSION")||(!legacy&&!canonical){return Err("Linux package manifest identity/hardening mismatch".into())}
    for path in [&desktop,guard]{
        let name=path.file_name().and_then(|v|v.to_str()).ok_or("artifact name invalid")?;
        let a=m.artifacts.iter().find(|a|{
            if canonical&&!a.package_path.is_empty(){Path::new(&a.package_path).file_name().and_then(|v|v.to_str())==Some(name)}else{a.name==name}
        }).ok_or_else(||format!("artifact {name} missing from Linux package manifest"))?;
        let meta=std::fs::metadata(path).map_err(|e|e.to_string())?;
        if meta.len()!=a.size||!ct_eq(sha256_file(path)?.as_bytes(),a.sha256.to_lowercase().as_bytes()){return Err(format!("Linux package artifact verification failed: {name}"))}
    }
    Ok(())
}
fn resolve_guard_executable()->Result<PathBuf,String>{let exe=std::env::current_exe().map_err(|e|e.to_string())?;Ok(exe.parent().ok_or("desktop parent missing")?.join("neverguard"))}

async fn connect_socket(path:&Path,guard_pid:u32)->Result<UnixStream,String>{
    let deadline=Instant::now()+Duration::from_secs(CONNECT_TIMEOUT_SECS); loop{match UnixStream::connect(path).await{Ok(s)=>{verify_peer(&s,guard_pid,current_uid())?;return Ok(s)},Err(e)=>{if Instant::now()>=deadline{return Err(format!("NeverGuard Unix socket connect failed: {e}"))}sleep(Duration::from_millis(40)).await}}
    }
}
fn verify_peer(stream:&UnixStream,expected_pid:u32,expected_uid:u32)->Result<(),String>{
    let fd=stream.as_raw_fd(); let mut cred=libc::ucred{pid:0,uid:0,gid:0}; let mut len=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc=unsafe{libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_PEERCRED,&mut cred as *mut _ as *mut libc::c_void,&mut len)};
    if rc!=0{return Err(format!("SO_PEERCRED failed: {}",std::io::Error::last_os_error()))} if cred.pid as u32!=expected_pid||cred.uid!=expected_uid{return Err(format!("NeverGuard peer credential mismatch pid={} uid={}",cred.pid,cred.uid))} Ok(())
}

async fn client_authenticate(mut s:UnixStream,endpoint:&Path,client_pid:u32,guard_pid:u32,secret:&[u8;32])->Result<(UnixStream,[u8;32],NeverGuardStatus),String>{
    let cn=random32(); write_frame(&mut s,&ClientHello{kind:"client-hello".into(),protocol_version:NEVERGUARD_PROTOCOL_VERSION,client_pid,client_nonce:hex::encode(cn)}).await?;
    let ch:ServerChallenge=read_frame(&mut s).await?; if ch.kind!="server-challenge"||ch.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||ch.guard_pid!=guard_pid{return Err("NeverGuard server challenge mismatch".into())}
    let sn=decode32(&ch.server_nonce,"serverNonce")?; let ep=endpoint.to_string_lossy(); let handshake=HandshakeContext{endpoint:&ep,client_pid,guard_pid,started:ch.started_at_unix,client_nonce:&cn,server_nonce:&sn}; let expected=proof(secret,b"server-proof",&handshake); if !ct_eq(&expected,&hex::decode(&ch.server_proof).map_err(|_|"invalid server proof")?){return Err("NeverGuard server authentication failed".into())}
    let cp=proof(secret,b"client-proof",&handshake); write_frame(&mut s,&ClientAuthentication{kind:"client-auth".into(),client_proof:hex::encode(cp)}).await?;
    let key=session_key(secret,&handshake); let ready:ServerReady=read_frame(&mut s).await?; if ready.kind!="ready"||ready.protocol_version!=NEVERGUARD_PROTOCOL_VERSION{return Err("NeverGuard ready mismatch".into())}
    let expected=ready_proof(&key,ReadyProofState{pid:ready.guard_pid,started:ready.started_at_unix,policy_version:ready.process_policy_version,policy_enforced:ready.process_policy_enforced,hardening_version:ready.hardening_version,hardening_enforced:ready.hardening_enforced,secure_acl:ready.secure_pipe_acl}); if !ct_eq(&expected,&hex::decode(&ready.ready_proof).map_err(|_|"invalid ready proof")?){return Err("NeverGuard ready proof invalid".into())}
    if ready.process_policy_version!=NEVERGUARD_LINUX_PROCESS_POLICY_VERSION||!ready.process_policy_enforced||ready.hardening_version!=NEVERGUARD_LINUX_HARDENING_VERSION||!ready.hardening_enforced||!ready.secure_pipe_acl{return Err("NeverGuard Linux policy/hardening not enforced".into())}
    Ok((s,key,NeverGuardStatus{state:"ready".into(),product_version:env!("CARGO_PKG_VERSION").into(),platform:"linux-amd64".into(),pid:guard_pid,parent_pid:client_pid,protocol_version:NEVERGUARD_PROTOCOL_VERSION,authenticated:true,process_policy_version:ready.process_policy_version,process_policy_enforced:true,hardening_version:ready.hardening_version,hardening_enforced:true,secure_pipe_acl:true,lifetime_job_enforced:true,package_manifest_verified:false,started_at_unix:ch.started_at_unix,message:"NeverGuard Linux authenticated Unix IPC ready".into()}))
}

async fn send_command(h:&mut GuardHandle,command:&str,payload:&str)->Result<Value,String>{
    let seq=h.next_sequence; let id=random_id(); let mac=request_mac(&h.session_key,seq,&id,command,payload); let req=RequestEnvelope{protocol_version:NEVERGUARD_PROTOCOL_VERSION,sequence:seq,request_id:id.clone(),command:command.into(),payload:payload.into(),mac:hex::encode(mac)};
    timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS),write_frame(&mut h.stream,&req)).await.map_err(|_|"NeverGuard IPC write timeout".to_string())??;
    let response_timeout = if matches!(command, "integrity-evidence" | "guard-attestation") { EVIDENCE_COMMAND_TIMEOUT_SECS } else { COMMAND_TIMEOUT_SECS };
    let resp:ResponseEnvelope=timeout(Duration::from_secs(response_timeout),read_frame(&mut h.stream)).await.map_err(|_|format!("NeverGuard IPC read timeout for {command}"))??;
    if resp.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||resp.sequence!=seq||resp.request_id!=id{return Err("NeverGuard response binding mismatch".into())}; let expected=response_mac(&h.session_key,seq,&id,resp.ok,&resp.payload); if !ct_eq(&expected,&hex::decode(&resp.mac).map_err(|_|"invalid response mac")?){return Err("NeverGuard response MAC invalid".into())}; h.next_sequence=h.next_sequence.checked_add(1).ok_or("IPC sequence exhausted")?; if !resp.ok{return Err(resp.payload)}; serde_json::from_str(&resp.payload).map_err(|e|format!("NeverGuard response JSON invalid: {e}"))
}
fn parse_status(v:Value)->Result<NeverGuardStatus,String>{let s:NeverGuardStatus=serde_json::from_value(v).map_err(|e|format!("NeverGuard status invalid: {e}"))?;validate_release_identity(&s)?;Ok(s)}
fn validate_release_identity(s:&NeverGuardStatus)->Result<(),String>{if s.product_version!=env!("CARGO_PKG_VERSION"){return Err(format!("NeverGuard release version mismatch: Desktop={} Guard={}",env!("CARGO_PKG_VERSION"),s.product_version))}if s.platform!="linux-amd64"{return Err(format!("NeverGuard platform mismatch: expected linux-amd64, got {}",s.platform))}if s.protocol_version!=NEVERGUARD_PROTOCOL_VERSION{return Err(format!("NeverGuard protocol mismatch: Desktop={} Guard={}",NEVERGUARD_PROTOCOL_VERSION,s.protocol_version))}Ok(())}
fn validate_policy(p:&GuardProcessPolicyReport)->Result<(),String>{let l=p.linux.as_ref().ok_or("Linux process policy details missing")?;if p.schema!=NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA||p.policy_version!=1||!p.enforced||!l.no_new_privs||!l.dumpable_disabled||!l.core_dumps_disabled||!l.ptrace_restricted||!l.parent_death_signal||!l.private_umask{return Err("NeverGuard Linux process policy rejected".into())}Ok(())}
fn validate_evidence(h:&GuardHandle,e:&NeverGuardIntegrityEvidence)->Result<(),String>{validate_evidence_shape(e)?;let d=recompute_evidence_sha256(e)?;if !ct_eq(&d,&hex::decode(&e.evidence_sha256).map_err(|_|"invalid evidence digest")?){return Err("evidence digest mismatch".into())};let p=integrity_proof(&h.session_key,&d);if !ct_eq(&p,&hex::decode(&e.session_proof).map_err(|_|"invalid evidence proof")?){return Err("evidence session proof mismatch".into())}Ok(())}
fn validate_attestation(h:&GuardHandle,id:&str,challenge:&str,a:&NeverGuardRemoteAttestation)->Result<(),String>{validate_attestation_shape(a)?;if a.schema!=NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA||a.challenge_id!=id||a.challenge_sha256!=challenge_sha256(challenge){return Err("Linux Guard Attestation binding mismatch".into())};validate_evidence(h,&a.evidence)?;validate_policy(&a.process_policy)?;let d=recompute_attestation_sha256(a)?;if !ct_eq(&d,&hex::decode(&a.attestation_sha256).map_err(|_|"invalid attestation digest")?){return Err("attestation digest mismatch".into())};let p=attestation_proof(&h.session_key,&d);if !ct_eq(&p,&hex::decode(&a.session_proof).map_err(|_|"invalid attestation proof")?){return Err("attestation session proof mismatch".into())}Ok(())}

pub async fn run_linux_guard_server(endpoint:PathBuf,parent_pid:u32)->Result<(),String>{
    validate_endpoint(&endpoint)?; let hard=ensure_linux_production_hardening()?; let policy=policy_report()?; let observed=crate::integrity::observed_linux_parent_pid(std::process::id())?; if observed!=parent_pid{return Err(format!("NeverGuard Linux parent mismatch expected={parent_pid} observed={observed}"))}
    let mut secret=[0u8;SECRET_LEN]; { let mut bootstrap_stdin=std::io::stdin(); std::io::Read::read_exact(&mut bootstrap_stdin,&mut secret).map_err(|e|format!("bootstrap secret read failed: {e}"))?; }
    if endpoint.exists(){return Err("NeverGuard Unix socket already exists".into())} let listener=UnixListener::bind(&endpoint).map_err(|e|format!("bind {} failed: {e}",endpoint.display()))?; std::fs::set_permissions(&endpoint,std::fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;
    let m=std::fs::symlink_metadata(&endpoint).map_err(|e|e.to_string())?; if !m.file_type().is_socket()||m.uid()!=current_uid()||(m.mode()&0o077)!=0{return Err("NeverGuard Unix socket ACL verification failed".into())}
    let started=now_unix()?; let deadline=Instant::now()+Duration::from_secs(STARTUP_AUTH_WINDOW_SECS);
    loop { let remaining=deadline.saturating_duration_since(Instant::now()); if remaining.is_zero(){secret.zeroize();return Err("NeverGuard startup authentication window expired".into())}; let (stream,_)=timeout(remaining,listener.accept()).await.map_err(|_|"NeverGuard accept timeout".to_string())?.map_err(|e|e.to_string())?;
        if verify_peer(&stream,parent_pid,current_uid()).is_err(){continue}
        match server_authenticate(stream,&endpoint,parent_pid,started,&secret,&policy,&hard).await {Ok((stream,key))=>{secret.zeroize();let r=serve_commands(stream,key,parent_pid,started,policy,hard).await;let _=std::fs::remove_file(&endpoint);return r},Err(_)=>continue}
    }
}
fn policy_report()->Result<GuardProcessPolicyReport,String>{let l=guard_policy_report()?;Ok(GuardProcessPolicyReport{schema:NEVERGUARD_LINUX_PROCESS_POLICY_SCHEMA.into(),policy_version:1,pid:std::process::id(),enforced:true,dynamic_code_prohibited:false,extension_points_disabled:false,strict_handle_checks:false,remote_images_blocked:false,low_mandatory_label_images_blocked:false,prefer_system32_images:false,child_process_creation_blocked:false,linux:Some(l),macos:None})}
async fn server_authenticate(mut s:UnixStream,endpoint:&Path,parent_pid:u32,started:u64,secret:&[u8;32],policy:&GuardProcessPolicyReport,hard:&crate::linux_policy::LinuxProductionHardeningReport)->Result<(UnixStream,[u8;32]),String>{
    let hello:ClientHello=timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),read_frame(&mut s)).await.map_err(|_|"client hello timeout".to_string())??; if hello.kind!="client-hello"||hello.protocol_version!=NEVERGUARD_PROTOCOL_VERSION||hello.client_pid!=parent_pid{return Err("client hello mismatch".into())}; let cn=decode32(&hello.client_nonce,"clientNonce")?;let sn=random32();let pid=std::process::id();let ep=endpoint.to_string_lossy();let handshake=HandshakeContext{endpoint:&ep,client_pid:parent_pid,guard_pid:pid,started,client_nonce:&cn,server_nonce:&sn};let sp=proof(secret,b"server-proof",&handshake);write_frame(&mut s,&ServerChallenge{kind:"server-challenge".into(),protocol_version:NEVERGUARD_PROTOCOL_VERSION,guard_pid:pid,started_at_unix:started,server_nonce:hex::encode(sn),server_proof:hex::encode(sp)}).await?;let auth:ClientAuthentication=read_frame(&mut s).await?;let expected=proof(secret,b"client-proof",&handshake);if auth.kind!="client-auth"||!ct_eq(&expected,&hex::decode(auth.client_proof).map_err(|_|"invalid client proof")?){return Err("client authentication failed".into())};let key=session_key(secret,&handshake);let rp=ready_proof(&key,ReadyProofState{pid,started,policy_version:policy.policy_version,policy_enforced:policy.enforced,hardening_version:hard.hardening_version,hardening_enforced:hard.enforced,secure_acl:true});write_frame(&mut s,&ServerReady{kind:"ready".into(),protocol_version:NEVERGUARD_PROTOCOL_VERSION,guard_pid:pid,started_at_unix:started,process_policy_version:policy.policy_version,process_policy_enforced:policy.enforced,hardening_version:hard.hardening_version,hardening_enforced:hard.enforced,secure_pipe_acl:true,ready_proof:hex::encode(rp)}).await?;Ok((s,key))
}
async fn build_integrity_evidence(
    parent_pid: u32,
    key: &[u8; 32],
    policy: &GuardProcessPolicyReport,
) -> Result<NeverGuardIntegrityEvidence, String> {
    validate_policy(policy)?;
    let verified_guard = policy
        .linux
        .clone()
        .ok_or_else(|| "Linux process policy details missing".to_string())?;
    let mut evidence = tokio::task::spawn_blocking(move || collect_linux_integrity_evidence(parent_pid))
        .await
        .map_err(|err| format!("NeverGuard integrity worker failed: {err}"))??;

    // PR_GET_PDEATHSIG is task/thread-local on Linux. The policy report is captured
    // on NeverGuard's original task before heavy evidence collection is moved to a
    // blocking worker. Re-bind those already verified hardening facts here instead
    // of treating the worker thread's task-local state as the Guard process state.
    let guard_security = evidence
        .guard
        .linux
        .as_mut()
        .ok_or_else(|| "Linux integrity evidence missing guard security state".to_string())?;
    guard_security.no_new_privs = verified_guard.no_new_privs;
    guard_security.dumpable_disabled = verified_guard.dumpable_disabled;
    guard_security.parent_death_signal = verified_guard.parent_death_signal;

    let digest = recompute_evidence_sha256(&evidence)?;
    evidence.evidence_sha256 = hex::encode(digest);
    evidence.session_proof = hex::encode(integrity_proof(key, &digest));
    validate_evidence_shape(&evidence)?;
    Ok(evidence)
}

async fn build_guard_attestation(
    parent_pid: u32,
    key: &[u8; 32],
    policy: &GuardProcessPolicyReport,
    payload: &str,
) -> Result<NeverGuardRemoteAttestation, String> {
    let request: GuardAttestationRequest = serde_json::from_str(payload)
        .map_err(|err| format!("attestation request invalid: {err}"))?;
    let evidence = build_integrity_evidence(parent_pid, key, policy).await?;
    let mut attestation = NeverGuardRemoteAttestation {
        schema: NEVERGUARD_LINUX_REMOTE_ATTESTATION_SCHEMA.into(),
        attestation_version: NEVERGUARD_REMOTE_ATTESTATION_VERSION,
        challenge_id: request.challenge_id,
        challenge_sha256: challenge_sha256(&request.challenge),
        collected_at_unix: evidence.collected_at_unix,
        evidence,
        process_policy: policy.clone(),
        attestation_sha256: String::new(),
        session_proof: String::new(),
    };
    let digest = recompute_attestation_sha256(&attestation)?;
    attestation.attestation_sha256 = hex::encode(digest);
    attestation.session_proof = hex::encode(attestation_proof(key, &digest));
    validate_attestation_shape(&attestation)?;
    Ok(attestation)
}

async fn serve_commands(
    mut stream: UnixStream,
    key: [u8; 32],
    parent_pid: u32,
    started: u64,
    policy: GuardProcessPolicyReport,
    hardening: crate::linux_policy::LinuxProductionHardeningReport,
) -> Result<(), String> {
    let mut sequence = 1u64;
    loop {
        let request: RequestEnvelope = read_frame(&mut stream).await?;
        if request.protocol_version != NEVERGUARD_PROTOCOL_VERSION || request.sequence != sequence {
            return Err("request sequence mismatch".into());
        }
        let expected = request_mac(
            &key,
            sequence,
            &request.request_id,
            &request.command,
            &request.payload,
        );
        if !ct_eq(
            &expected,
            &hex::decode(&request.mac).map_err(|_| "invalid request mac")?,
        ) {
            return Err("request MAC invalid".into());
        }

        let (ok, payload, shutdown) = match request.command.as_str() {
            "ping" => (true, json!({"pong": true}).to_string(), false),
            "status" => (
                true,
                serde_json::to_string(&NeverGuardStatus {
                    state: "ready".into(),
                    product_version: env!("CARGO_PKG_VERSION").into(),
                    platform: "linux-amd64".into(),
                    pid: std::process::id(),
                    parent_pid,
                    protocol_version: NEVERGUARD_PROTOCOL_VERSION,
                    authenticated: true,
                    process_policy_version: 1,
                    process_policy_enforced: true,
                    hardening_version: hardening.hardening_version,
                    hardening_enforced: true,
                    secure_pipe_acl: true,
                    lifetime_job_enforced: true,
                    package_manifest_verified: false,
                    started_at_unix: started,
                    message: "NeverGuard Linux production boundary ready".into(),
                })
                .map_err(|err| format!("NeverGuard status serialization failed: {err}"))?,
                false,
            ),
            "process-policy" => (
                true,
                serde_json::to_string(&policy)
                    .map_err(|err| format!("NeverGuard process policy serialization failed: {err}"))?,
                false,
            ),
            "integrity-evidence" => match build_integrity_evidence(parent_pid, &key, &policy).await {
                Ok(evidence) => (
                    true,
                    serde_json::to_string(&evidence)
                        .map_err(|err| format!("NeverGuard integrity serialization failed: {err}"))?,
                    false,
                ),
                Err(err) => (false, format!("NeverGuard integrity evidence failed: {err}"), false),
            },
            "guard-attestation" => {
                match build_guard_attestation(parent_pid, &key, &policy, &request.payload).await {
                    Ok(attestation) => (
                        true,
                        serde_json::to_string(&attestation).map_err(|err| {
                            format!("NeverGuard attestation serialization failed: {err}")
                        })?,
                        false,
                    ),
                    Err(err) => (false, format!("NeverGuard attestation failed: {err}"), false),
                }
            }
            "shutdown" => (true, json!({"shutdown": true}).to_string(), true),
            _ => (false, "unsupported command".into(), false),
        };

        let mac = response_mac(&key, sequence, &request.request_id, ok, &payload);
        write_frame(
            &mut stream,
            &ResponseEnvelope {
                protocol_version: NEVERGUARD_PROTOCOL_VERSION,
                sequence,
                request_id: request.request_id,
                ok,
                payload,
                mac: hex::encode(mac),
            },
        )
        .await?;
        if shutdown {
            return Ok(());
        }
        sequence = sequence.checked_add(1).ok_or("sequence exhausted")?;
    }
}

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
