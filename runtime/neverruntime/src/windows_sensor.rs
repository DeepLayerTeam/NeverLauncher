use serde::{Deserialize, Serialize};

pub const NEVERGUARD_SENSOR_PROTOCOL_VERSION: u32 = 1;
pub const NEVERGUARD_SENSOR_FILE_NAME: &str = "neverguard-sensor.dll";
pub const NEVERGUARD_SENSOR_PIPE_ENV: &str = "NEVERGUARD_SENSOR_PIPE";
pub const NEVERGUARD_SENSOR_SECRET_ENV: &str = "NEVERGUARD_SENSOR_SECRET";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsSensorReport {
    pub protocol_version: u32,
    pub pid: u32,
    pub sensor_path: String,
    pub authenticated: bool,
    pub loaded_before_main: bool,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::guard_ipc::create_secure_pipe_server;
    #[cfg(not(debug_assertions))]
    use crate::verify_windows_authenticode_trust;
    use hmac::{Hmac, Mac};
    use rand::{rngs::OsRng, RngCore};
    use sha2::Sha256;
    use std::{ffi::OsString, path::PathBuf};
    use subtle::ConstantTimeEq;
    use tokio::{
        io::AsyncReadExt,
        net::windows::named_pipe::NamedPipeServer,
        process::Command,
        time::{timeout, Duration},
    };
    use zeroize::Zeroize;

    type HmacSha256 = Hmac<Sha256>;
    const SENSOR_MAGIC: &[u8; 8] = b"NGSENS02";
    const SENSOR_DOMAIN: &[u8] = b"neverguard-sensor-startup-v1";
    const SENSOR_PIPE_PREFIX: &str = r"\\.\pipe\NeverLauncher.Guard.Sensor.";
    const SENSOR_STARTUP_TIMEOUT_SECS: u64 = 12;

    pub struct WindowsSensorBootstrap {
        server: NamedPipeServer,
        secret: [u8; 32],
        sensor_path: PathBuf,
    }

    impl Drop for WindowsSensorBootstrap {
        fn drop(&mut self) {
            self.secret.zeroize();
        }
    }

    fn resolve_sensor_path() -> Result<PathBuf, String> {
        let current = std::env::current_exe()
            .map_err(|err| format!("не удалось определить executable для NeverGuard Sensor: {err}"))?;
        let parent = current
            .parent()
            .ok_or_else(|| "NeverGuard Sensor: executable не имеет parent directory".to_string())?;
        let path = parent.join(NEVERGUARD_SENSOR_FILE_NAME);
        let metadata = std::fs::symlink_metadata(&path).map_err(|err| {
            format!("NeverGuard Sensor отсутствует рядом с launcher/runtime {}: {err}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err("NeverGuard Sensor должен быть непустым regular non-symlink DLL".to_string());
        }
        Ok(path)
    }

    fn sensor_endpoint() -> String {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        format!("{SENSOR_PIPE_PREFIX}{}.{}", std::process::id(), hex::encode(nonce))
    }

    fn prepare_sensor_command_for_path(
        command: &mut Command,
        sensor_path: PathBuf,
    ) -> Result<WindowsSensorBootstrap, String> {
        let metadata = std::fs::symlink_metadata(&sensor_path).map_err(|err| {
            format!("NeverGuard Sensor DLL is unavailable {}: {err}", sensor_path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err("NeverGuard Sensor должен быть непустым regular non-symlink DLL".to_string());
        }
        #[cfg(not(debug_assertions))]
        verify_windows_authenticode_trust(&sensor_path)
            .map_err(|err| format!("NeverGuard Sensor Authenticode verification failed: {err}"))?;

        let endpoint = sensor_endpoint();
        let server = create_secure_pipe_server(&endpoint)
            .map_err(|err| format!("NeverGuard Sensor startup pipe creation failed: {err}"))?;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);

        let mut agent_arg = OsString::from("-agentpath:");
        agent_arg.push(sensor_path.as_os_str());
        command.arg(agent_arg);
        command.env(NEVERGUARD_SENSOR_PIPE_ENV, &endpoint);
        command.env(NEVERGUARD_SENSOR_SECRET_ENV, hex::encode(secret));

        Ok(WindowsSensorBootstrap { server, secret, sensor_path })
    }

    pub fn prepare_sensor_command(command: &mut Command) -> Result<WindowsSensorBootstrap, String> {
        prepare_sensor_command_for_path(command, resolve_sensor_path()?)
    }

    pub fn prepare_sensor_command_with_path(
        command: &mut Command,
        sensor_path: PathBuf,
    ) -> Result<WindowsSensorBootstrap, String> {
        prepare_sensor_command_for_path(command, sensor_path)
    }

    impl WindowsSensorBootstrap {
        pub async fn authenticate(mut self, expected_pid: u32) -> Result<WindowsSensorReport, String> {
            timeout(Duration::from_secs(SENSOR_STARTUP_TIMEOUT_SECS), self.server.connect())
                .await
                .map_err(|_| "NeverGuard Sensor did not load before JVM startup timeout".to_string())?
                .map_err(|err| format!("NeverGuard Sensor startup pipe connect failed: {err}"))?;

            let mut packet = [0u8; 48];
            timeout(Duration::from_secs(3), self.server.read_exact(&mut packet))
                .await
                .map_err(|_| "NeverGuard Sensor startup authentication timed out".to_string())?
                .map_err(|err| format!("NeverGuard Sensor startup packet read failed: {err}"))?;

            if &packet[..8] != SENSOR_MAGIC {
                packet.zeroize();
                return Err("NeverGuard Sensor startup packet magic mismatch".to_string());
            }
            let protocol = u32::from_le_bytes(packet[8..12].try_into().expect("slice length"));
            let pid = u32::from_le_bytes(packet[12..16].try_into().expect("slice length"));
            if protocol != NEVERGUARD_SENSOR_PROTOCOL_VERSION || pid != expected_pid {
                packet.zeroize();
                return Err("NeverGuard Sensor startup packet protocol/PID mismatch".to_string());
            }

            let mut mac = HmacSha256::new_from_slice(&self.secret)
                .map_err(|_| "NeverGuard Sensor HMAC initialization failed".to_string())?;
            mac.update(SENSOR_DOMAIN);
            mac.update(&protocol.to_le_bytes());
            mac.update(&pid.to_le_bytes());
            let expected = mac.finalize().into_bytes();
            let authenticated = expected[..].ct_eq(&packet[16..]).into();
            packet.zeroize();
            self.secret.zeroize();
            if !authenticated {
                return Err("NeverGuard Sensor startup authentication failed".to_string());
            }

            Ok(WindowsSensorReport {
                protocol_version: protocol,
                pid,
                sensor_path: self.sensor_path.to_string_lossy().to_string(),
                authenticated: true,
                loaded_before_main: true,
            })
        }
    }

    /// Authenticates the early JVM sensor and terminates the JVM if the startup
    /// proof is missing or invalid. This keeps sensor enforcement fail-closed
    /// even when the parent-side verification fails after the VM has resumed.
    pub async fn authenticate_sensor_or_kill(
        bootstrap: WindowsSensorBootstrap,
        child: &mut tokio::process::Child,
    ) -> Result<WindowsSensorReport, String> {
        let pid = match child.id() {
            Some(pid) => pid,
            None => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(3), child.wait()).await;
                return Err("runtime PID недоступен для NeverGuard Sensor".to_string());
            }
        };
        match bootstrap.authenticate(pid).await {
            Ok(report) => Ok(report),
            Err(err) => {
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(3), child.wait()).await;
                Err(err)
            }
        }
    }
}

#[cfg(windows)]
pub use imp::{
    authenticate_sensor_or_kill, prepare_sensor_command, prepare_sensor_command_with_path,
    WindowsSensorBootstrap,
};

#[cfg(not(windows))]
#[derive(Debug, Clone, Default)]
pub struct WindowsSensorBootstrap;
