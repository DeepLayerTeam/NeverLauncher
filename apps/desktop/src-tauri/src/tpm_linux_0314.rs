//! Linux TPM2 Certify evidence for the *existing* hardware-enclave device key.
//!
//! hardware-enclave 0.2.10 stores the Linux child as a TPM-wrapped TPMT_PUBLIC
//! and raw TPM2B_PRIVATE.buffer, under a deterministic owner-hierarchy ECC SRK.
//! tpm2-tools 5.x is used to reconstruct/load that exact child, without exporting
//! a private key or allocating a second device identity. All evidence is independently
//! verified by the NeverLauncher backend. No software-key fallback is allowed.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::{fs::{self, OpenOptions}, io::Write, os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
          path::{Path,PathBuf}, process::{Command,Stdio}, thread, time::{Duration,Instant}};

const MAX_BLOB: usize = 4096;
const MAX_CERT: usize = 16384;
const MAX_TOOL_SECONDS: u64 = 20;

#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub struct LinuxTPMEvidence0314 {
    pub tpm2b_public: String,
    pub tpm2b_attest: String,
    pub tpmt_signature: String,
    pub ak_certificate_pem: String,
    pub intermediates_pem: Vec<String>,
}

fn parse_ak_handle(input: &str) -> Result<String, String> {
    let s = input.trim();
    // No filesystem AK contexts, no options and no TCTI/authorization argument
    // may enter a subprocess through IPC. An administrator provisions the AK
    // into a persistent handle (0x81xxxxxx), with a CA-issued leaf certificate.
    if s.len()!=10 || !s.starts_with("0x") ||
       !s[2..].bytes().all(|b| b.is_ascii_hexdigit()) ||
       !s[2..4].eq_ignore_ascii_case("81") {
        return Err("Linux AK must be a provisioned TPM persistent 0x81xxxxxx handle".into());
    }
    let n=u32::from_str_radix(&s[2..],16).map_err(|_|"invalid AK handle")?;
    Ok(format!("0x{n:08x}"))
}

// NeverLauncher hardware-enclave config uses app_name=neverlauncher-desktop.
// 0.2.10 adds -unsigned for unsigned developer binaries. Only the normal
// XDG application directories are eligible; never accept a frontend path.
fn device_blobs(label: &str) -> Result<(Vec<u8>,Vec<u8>),String> {
    if label.len()<10 || label.len()>96 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b=='-') {
        return Err("invalid hardware-enclave TPM label".into());
    }
    let home=std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    let config=std::env::var_os("XDG_CONFIG_HOME").filter(|v| Path::new(v).is_absolute())
        .map(PathBuf::from).unwrap_or_else(|| PathBuf::from(home).join(".config"));
    let mut found=None;
    for app in ["neverlauncher-desktop", "neverlauncher-desktop-unsigned"] {
        let dir=config.join(app).join("keys");
        let public=dir.join(format!("{label}.tpm_pub"));
        let private=dir.join(format!("{label}.tpm_priv"));
        if !public.exists() && !private.exists() { continue; }
        if found.is_some() { return Err("ambiguous TPM key directory (signed and unsigned)".into()); }
        let p=read_bounded_regular(&public,MAX_BLOB)?;
        let s=read_bounded_regular(&private,MAX_BLOB)?;
        found=Some((p,s));
    }
    found.ok_or_else(||"Linux TPM-wrapped device blobs not found; software/keyring identity cannot be certified".into())
}

fn read_bounded_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    // No symlinks. A different UID's blobs cannot be silently used.
    let md=fs::symlink_metadata(path).map_err(|e|format!("TPM device blob missing: {e}"))?;
    if !md.file_type().is_file() || md.uid() != unsafe { libc::geteuid() } || md.len()==0 || md.len() as usize>maximum ||
       md.mode() & 0o022 != 0 {
        return Err("TPM key blob must be an owned, non-group/world-writable regular file".into());
    }
    // The regular-file check prevents naive symlink following; Linux O_NOFOLLOW
    // closes the rename-to-symlink race between stat and open.
    let mut opts=OpenOptions::new();
    opts.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut f=opts.open(path).map_err(|e|format!("cannot open TPM key blob: {e}"))?;
    let fdmd=f.metadata().map_err(|e|e.to_string())?;
    if !fdmd.is_file() || fdmd.uid()!=md.uid() || fdmd.ino()!=md.ino() || fdmd.len()!=md.len() {
        return Err("TPM key blob changed while opening".into());
    }
    use std::io::Read;
    let mut bytes=Vec::new();
    f.take((maximum+1) as u64).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
    if bytes.is_empty() || bytes.len()>maximum { return Err("TPM key blob size invalid".into()); }
    Ok(bytes)
}

struct TempTPMDir(PathBuf);
impl TempTPMDir {
    fn new() -> Result<Self,String> {
        // Fixed per-user base dir avoids placing secrets in untrusted work dirs.
        for _ in 0..6 {
            let mut salt=[0u8;16]; OsRng.fill_bytes(&mut salt);
            let path=std::env::temp_dir().join(format!("nl-tpm0314-{}",hex::encode(salt)));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;
                    return Ok(Self(path));
                },
                Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => continue,
                Err(e)=>return Err(format!("cannot create TPM workspace: {e}")),
            }
        }
        Err("cannot allocate unique TPM workspace".into())
    }
    fn file(&self, name: &str) -> PathBuf { self.0.join(name) }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf,String> {
        let path=self.file(name);
        let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
            .map_err(|e|format!("cannot create temporary TPM input: {e}"))?;
        f.write_all(bytes).map_err(|e|e.to_string())?;
        Ok(path)
    }
}
impl Drop for TempTPMDir { fn drop(&mut self){ let _=fs::remove_dir_all(&self.0); } }

fn tool(program: &str, args: &[String]) -> Result<(),String> {
    const NAMES: &[&str]=&["tpm2_createprimary","tpm2_load","tpm2_readpublic","tpm2_certify"];
    if !NAMES.contains(&program) { return Err("unknown TPM command".into()); }
    // Absolute fixed executable path: no PATH search, no shell expansion.
    let path=Path::new("/usr/bin").join(program);
    let mut child=Command::new(path).args(args).env_remove("TPM2TOOLS_TCTI")
        .env("TPM2TOOLS_TCTI","device:/dev/tpmrm0")
        .env_remove("LD_PRELOAD").env_remove("LD_LIBRARY_PATH")
        .env_remove("TSS2_TCTI")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|e|format!("{program} unavailable: {e}"))?;
    let began=Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(format!("{program} returned {status} (TPM/authorization/firmware failure)")),
            Ok(None) if began.elapsed() < Duration::from_secs(MAX_TOOL_SECONDS) => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _=child.kill(); let _=child.wait();
                return Err(format!("{program} timed out"));
            },
            Err(e) => { let _=child.kill();let _=child.wait();return Err(format!("{program} wait failed: {e}")); }
        }
    }
}
fn arglist(parts: &[&str]) -> Vec<String> { parts.iter().map(|s|s.to_string()).collect() }
fn bytes_from(path: &Path, cap: usize) -> Result<Vec<u8>,String> {
    read_bounded_regular(path,cap).map_err(|e|format!("TPM output unreadable: {e}"))
}
fn to_tpm2b(bytes: &[u8], limit: usize) -> Result<Vec<u8>,String> {
    if bytes.is_empty() || bytes.len()>limit || bytes.len()>u16::MAX as usize {return Err("invalid TPM blob length".into());}
    let mut out=(bytes.len() as u16).to_be_bytes().to_vec();out.extend_from_slice(bytes);Ok(out)
}

fn attestation_with_size(input: Vec<u8>) -> Result<Vec<u8>,String> {
    if input.len()>=8 && input[..4]==0xff544347u32.to_be_bytes() {return to_tpm2b(&input,4096);}
    if input.len()>=10 && input[2..6]==0xff544347u32.to_be_bytes() &&
        u16::from_be_bytes([input[0],input[1]]) as usize==input.len()-2 {return Ok(input);}
    Err("tpm2_certify did not return a TPM_ST_ATTEST payload".into())
}
fn validate_outputs(public: &[u8], att: &[u8], sig: &[u8], registered: &[u8], extra: &[u8;32]) -> Result<(),String> {
    // Reuse strict wire checks from Windows TPM, including fixed TPM,
    // P-256, signed certify tag, nonce and signature shape.
    let mut read_frame=Vec::new();
    let mut read_params=public.to_vec();read_params.extend_from_slice(&[0,0,0,0]);
    read_frame.extend_from_slice(&0x8001u16.to_be_bytes());
    read_frame.extend_from_slice(&((10+read_params.len()) as u32).to_be_bytes());
    read_frame.extend_from_slice(&[0;4]);read_frame.extend_from_slice(&read_params);
    let (pub_checked,point)=crate::tpm_wire_0313::parse_public_response(&read_frame)?;
    if pub_checked!=public || point.as_slice()!=registered {
        return Err("TPM identity public key differs from registered key".into());
    }
    let mut params=att.to_vec();params.extend_from_slice(sig);
    let mut response=Vec::new();response.extend_from_slice(&0x8002u16.to_be_bytes());
    response.extend_from_slice(&((14+params.len()) as u32).to_be_bytes());
    response.extend_from_slice(&[0;4]);response.extend_from_slice(&(params.len() as u32).to_be_bytes());
    response.extend_from_slice(&params);
    let (a,s)=crate::tpm_wire_0313::parse_certify_response(&response,extra)?;
    if a!=att || s!=sig {return Err("TPM result canonicalization mismatch".into());}
    Ok(())
}

pub fn certify(
    device_label: &str, registered_sec1: &[u8], extra_b64url: &str,
    ak_handle: &str, ak_certificate_pem: &str, intermediates_pem: Vec<String>,
) -> Result<LinuxTPMEvidence0314,String> {
    if !Path::new("/dev/tpmrm0").exists() {return Err("Linux TPM resource manager /dev/tpmrm0 unavailable".into());}
    if registered_sec1.len()!=65 || registered_sec1[0]!=4 {return Err("registered P-256 public key required".into());}
    let extra=URL_SAFE_NO_PAD.decode(extra_b64url).map_err(|_|"invalid server TPM qualifier")?;
    let extra: [u8;32]=extra.try_into().map_err(|_|"TPM qualifier must be SHA-256 (32 bytes)")?;
    let ak=parse_ak_handle(ak_handle)?;
    if ak_certificate_pem.len()>MAX_CERT || !ak_certificate_pem.contains("-----BEGIN CERTIFICATE-----") ||
       !ak_certificate_pem.contains("-----END CERTIFICATE-----") || intermediates_pem.len()>8 ||
       intermediates_pem.iter().any(|p|p.len()>MAX_CERT || !p.contains("-----BEGIN CERTIFICATE-----")) {
        return Err("issuer-certified AK X.509 PEM required".into());
    }
    let (pub_blob,priv_blob)=device_blobs(device_label)?;
    // Public is TPMT_PUBLIC (not TPM2B_PUBLIC) from hardware-enclave.
    // Wrapped private is raw TPM2B_PRIVATE.buffer, so add TPM2B length.
    let public=to_tpm2b(&pub_blob,MAX_BLOB)?;
    // Check the local public blob *before* touching TPM operations.
    let mut read_frame=Vec::new();let mut public_params=public.clone();public_params.extend_from_slice(&[0,0,0,0]);
    read_frame.extend_from_slice(&0x8001u16.to_be_bytes());
    read_frame.extend_from_slice(&((10+public_params.len()) as u32).to_be_bytes());
    read_frame.extend_from_slice(&[0;4]);read_frame.extend_from_slice(&public_params);
    let (_,point)=crate::tpm_wire_0313::parse_public_response(&read_frame)?;
    if point.as_slice()!=registered_sec1 {return Err("TPM wrapped identity does not match registered public key".into());}
    let tmp=TempTPMDir::new()?;
    let pub_path=tmp.write("device.pub",&public)?;
    let private_path=tmp.write("device.priv",&to_tpm2b(&priv_blob,MAX_BLOB)?)?;
    let nonce=tmp.write("qualifier.bin",&extra)?;
    let parent=tmp.file("parent.ctx");let subject=tmp.file("subject.ctx");
    let read_pub=tmp.file("subject-read.pub");let att_file=tmp.file("certify.att");let sig_file=tmp.file("certify.sig");
    let path=|p: &Path| p.to_string_lossy().into_owned();
    // Matching hardware-enclave 0.2.10 owner ECC P-256 restricted storage
    // parent template: fixedTPM/parent, sensitiveDataOrigin, userWithAuth,
    // restricted decrypt, AES-128 CFB, SHA-256, null ECC scheme and KDF.
    tool("tpm2_createprimary", &arglist(&["-Q","-C","o","-g","sha256","-G","ecc256:aes128cfb",
        "-a","fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt", "-c",&path(&parent)]))?;
    tool("tpm2_load", &arglist(&["-Q","-C",&path(&parent),"-u",&path(&pub_path),"-r",&path(&private_path),"-c",&path(&subject)]))?;
    tool("tpm2_readpublic", &arglist(&["-Q","-c",&path(&subject),"-f","tss","-o",&path(&read_pub)]))?;
    let loaded_public=bytes_from(&read_pub,MAX_BLOB+2)?;
    if loaded_public!=public {return Err("loaded TPM object public area differs from sealed identity".into());}
    // The AK is a distinct persistent TPM object enrolled under a TPM-aware
    // issuer CA. Certify's own TPM signature and AK chain are verified remotely.
    tool("tpm2_certify", &arglist(&["-Q","-c",&path(&subject),"-C",&ak,"-g","sha256",
        "-q",&path(&nonce),"-f","tss","-o",&path(&att_file),"-s",&path(&sig_file)]))?;
    let attest=attestation_with_size(bytes_from(&att_file,4098)?)?;
    let signature=bytes_from(&sig_file,1024)?;
    validate_outputs(&public,&attest,&signature,registered_sec1,&extra)?;
    Ok(LinuxTPMEvidence0314 {
        tpm2b_public: URL_SAFE_NO_PAD.encode(public),
        tpm2b_attest: URL_SAFE_NO_PAD.encode(attest),
        tpmt_signature: URL_SAFE_NO_PAD.encode(signature),
        ak_certificate_pem: ak_certificate_pem.to_string(), intermediates_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn ak_handles_are_fixed_persistent_numeric_handles() {
        assert_eq!(parse_ak_handle("0x81010001").unwrap(),"0x81010001");
        for s in ["", "0x80000001", "0x8101", "-Q", "../../file.ctx", "0x81010001 extra", "0x82010001"] {
            assert!(parse_ak_handle(s).is_err(),"{s}");
        }
    }
    #[test] fn malformed_tpm_bytes_fail_closed() {
        assert!(attestation_with_size(vec![0;14]).is_err());
        assert!(to_tpm2b(&[],4096).is_err());
        assert!(validate_outputs(&[0;3],&[0;9],&[0;4],&[4;65],&[0;32]).is_err());
        let mut v=0xff544347u32.to_be_bytes().to_vec();v.extend_from_slice(&[0;10]);
        let a=attestation_with_size(v).unwrap();
        assert_eq!(&a[2..6],&0xff544347u32.to_be_bytes());
    }
}
