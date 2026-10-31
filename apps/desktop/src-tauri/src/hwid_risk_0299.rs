// Voluntary, untrusted host-continuity hint. Not a serial number collector or
// identity attestation. No raw values leave this function (or the device).
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
fn host_parts() -> Vec<String> {
    ["/sys/class/dmi/id/product_uuid", "/etc/machine-id"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && !s.chars().all(|c| c == '0' || c == '-'))
        .collect()
}

#[cfg(target_os = "windows")]
fn host_parts() -> Vec<String> {
    use std::process::Command;
    let out = Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .output();
    out.ok().filter(|o| o.status.success()).map(|o| {
        String::from_utf8_lossy(&o.stdout).lines()
            .filter(|s| s.contains("MachineGuid"))
            .filter_map(|line| line.split("REG_SZ").nth(1))
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty()).collect()
    }).unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn host_parts() -> Vec<String> {
    use std::process::Command;
    let out = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output();
    out.ok().filter(|o| o.status.success()).map(|o| {
        String::from_utf8_lossy(&o.stdout).lines()
            .filter(|s| s.contains("IOPlatformUUID"))
            .filter_map(|s| s.split('=').nth(1))
            .map(|s| s.trim().trim_matches('"').to_ascii_lowercase())
            .filter(|s| !s.is_empty()).collect()
    }).unwrap_or_default()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn host_parts() -> Vec<String> { Vec::new() }

#[tauri::command]
pub(crate) fn hardware_risk_signal_0299() -> Result<String, String> {
    let parts = host_parts();
    if parts.is_empty() { return Err("OS не предоставила разрешённый machine-continuity signal".into()); }
    let mut sha = Sha256::new();
    sha.update(b"Launcher voluntary host continuity v1\0");
    for part in parts {
        // No hostname, user name, MAC addresses, disks or serial-number list.
        sha.update((part.len() as u32).to_be_bytes());
        sha.update(part.as_bytes());
    }
    Ok(hex::encode(sha.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hint_is_a_digest_not_a_host_id() {
        if let Ok(signal) = hardware_risk_signal_0299() {
            assert_eq!(signal.len(),64);
            assert!(signal.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(signal, hardware_risk_signal_0299().unwrap());
        }
    }
}
