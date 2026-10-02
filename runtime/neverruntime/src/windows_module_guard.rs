use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub const NEVERGUARD_MODULE_GUARD_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsModuleGuardReport {
    pub version: u32,
    pub active: bool,
    pub healthy: bool,
    pub baseline_module_count: u32,
    pub current_module_count: u32,
    pub event_count: u64,
    pub load_events: u64,
    pub unload_events: u64,
    pub heartbeat_count: u64,
    pub last_sequence: u64,
    pub dropped_event_count: u64,
    pub violation_count: u32,
    pub event_chain_sha256: String,
    pub module_set_sha256: String,
    pub last_heartbeat_unix_ms: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_violation: String,
}

impl Default for WindowsModuleGuardReport {
    fn default() -> Self {
        Self {
            version: NEVERGUARD_MODULE_GUARD_VERSION,
            active: false,
            healthy: false,
            baseline_module_count: 0,
            current_module_count: 0,
            event_count: 0,
            load_events: 0,
            unload_events: 0,
            heartbeat_count: 0,
            last_sequence: 0,
            dropped_event_count: 0,
            violation_count: 0,
            event_chain_sha256: String::new(),
            module_set_sha256: String::new(),
            last_heartbeat_unix_ms: 0,
            last_violation: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct WindowsModuleGuardSession {
    state: Arc<Mutex<WindowsModuleGuardReport>>,
}

impl std::fmt::Debug for WindowsModuleGuardSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsModuleGuardSession")
            .field("report", &self.report())
            .finish()
    }
}

impl WindowsModuleGuardSession {
    pub fn report(&self) -> WindowsModuleGuardReport {
        match self.state.lock() {
            Ok(report) => report.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::verify_windows_authenticode_trust;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashMap,
        ffi::OsString,
        fs::File,
        io::{BufReader, Read},
        mem::size_of,
        os::windows::ffi::OsStringExt,
        path::{Path, PathBuf},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use subtle::ConstantTimeEq;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::NamedPipeServer,
        process::Command,
        time::timeout,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
            },
            Threading::{
                GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_TERMINATE,
            },
        },
    };
    use zeroize::Zeroize;

    type HmacSha256 = Hmac<Sha256>;

    const SENSOR_PROTOCOL_VERSION: u32 = 2;
    const MODULE_GUARD_ARM_MAGIC: &[u8; 8] = b"NGARM003";
    const MODULE_GUARD_ARM_DOMAIN: &[u8] = b"neverguard-module-guard-arm-v1";
    const MODULE_EVENT_MAGIC: &[u8; 8] = b"NGMOD003";
    const MODULE_EVENT_DOMAIN: &[u8] = b"neverguard-module-event-v1";
    const MODULE_EVENT_REASON_LOADED: u32 = 1;
    const MODULE_EVENT_REASON_UNLOADED: u32 = 2;
    const MODULE_EVENT_REASON_HEARTBEAT: u32 = 3;
    const MODULE_EVENT_REASON_OVERFLOW: u32 = 4;
    const MODULE_EVENT_REASON_SHUTDOWN: u32 = 5;
    const MODULE_EVENT_FLAG_PATH_TRUNCATED: u32 = 1;
    const MODULE_PATH_WCHARS: usize = 2048;
    const MODULE_EVENT_PREFIX_LEN: usize = 48 + MODULE_PATH_WCHARS * 2;
    const MODULE_EVENT_PACKET_LEN: usize = MODULE_EVENT_PREFIX_LEN + 32;
    const MODULE_STREAM_TIMEOUT: Duration = Duration::from_secs(7);
    const RECONCILE_GRACE: Duration = Duration::from_millis(350);
    const STILL_ACTIVE_EXIT_CODE: u32 = 259;

    #[derive(Clone, Debug)]
    pub struct WindowsModuleGuardPolicy {
        trusted_roots: Vec<String>,
    }

    #[derive(Clone, Debug)]
    struct LoadedModule {
        base_address: u64,
        size_of_image: u32,
        path: PathBuf,
        normalized_path: String,
    }

    #[derive(Debug)]
    struct ParsedEvent {
        sequence: u64,
        reason: u32,
        flags: u32,
        base_address: u64,
        size_of_image: u32,
        path: PathBuf,
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    impl WindowsModuleGuardPolicy {
        pub fn for_command(command: &Command, sensor_path: &Path) -> Result<Self, String> {
            let current_dir = command
                .as_std()
                .get_current_dir()
                .map(PathBuf::from)
                .or_else(|| std::env::current_dir().ok())
                .ok_or_else(|| "NeverGuard Module Guard cannot resolve JVM working directory".to_string())?;

            let java_executable = resolve_program_path(command.as_std().get_program(), &current_dir);

            let mut roots = Vec::new();
            roots.push(current_dir);
            if let Some(sensor_dir) = sensor_path.parent() {
                roots.push(sensor_dir.to_path_buf());
            }
            if let Some(java_bin) = java_executable.parent() {
                roots.push(java_bin.to_path_buf());
                if let Some(java_home) = java_bin.parent() {
                    roots.push(java_home.to_path_buf());
                }
            }
            if let Some(system_root) = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("WINDIR")) {
                roots.push(PathBuf::from(system_root));
            }

            let mut trusted_roots = Vec::new();
            for root in roots {
                let normalized = normalize_path(&canonical_or_absolute(&root)?);
                if !trusted_roots.iter().any(|existing: &String| existing.eq_ignore_ascii_case(&normalized)) {
                    trusted_roots.push(normalized);
                }
            }
            if trusted_roots.is_empty() {
                return Err("NeverGuard Module Guard trusted root set is empty".to_string());
            }
            Ok(Self { trusted_roots })
        }

        fn is_trusted_root_path(&self, normalized_path: &str) -> bool {
            self.trusted_roots.iter().any(|root| path_within(normalized_path, root))
        }

        fn validate_loaded_module(&self, path: &Path) -> Result<(String, String), String> {
            let metadata = std::fs::symlink_metadata(path).map_err(|err| {
                format!("Module Guard cannot stat loaded module {}: {err}", path.display())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                return Err(format!(
                    "Module Guard rejected non-regular/symlink module {}",
                    path.display()
                ));
            }
            let canonical = canonical_or_absolute(path)?;
            let normalized = normalize_path(&canonical);
            if !self.is_trusted_root_path(&normalized) {
                verify_windows_authenticode_trust(&canonical).map_err(|err| {
                    format!(
                        "Module Guard rejected module outside trusted roots {}: {err}",
                        canonical.display()
                    )
                })?;
            }
            let sha256 = sha256_file(&canonical)?;
            Ok((normalized, sha256))
        }
    }

    pub fn policy_for_command(command: &Command, sensor_path: &Path) -> Result<WindowsModuleGuardPolicy, String> {
        WindowsModuleGuardPolicy::for_command(command, sensor_path)
    }

    pub async fn arm_module_guard(
        mut server: NamedPipeServer,
        mut secret: [u8; 32],
        pid: u32,
        policy: WindowsModuleGuardPolicy,
    ) -> Result<WindowsModuleGuardSession, String> {
        let baseline = module_snapshot(pid)?;
        let mut baseline_hashes = Vec::with_capacity(baseline.len());
        for module in &baseline {
            let (normalized, sha256) = policy.validate_loaded_module(&module.path)?;
            if !normalized.eq_ignore_ascii_case(&module.normalized_path) {
                return Err(format!(
                    "Module Guard baseline canonical path drift for {}",
                    module.path.display()
                ));
            }
            baseline_hashes.push((module.base_address, sha256));
        }
        baseline_hashes.sort_unstable_by_key(|(base, _)| *base);

        let module_set_sha256 = module_set_sha256(&baseline);
        let mut event_chain = Sha256::new();
        event_chain.update(b"NeverLauncher Module Guard event-chain v1\0");
        event_chain.update(module_set_sha256.as_bytes());
        for (base, sha256) in &baseline_hashes {
            event_chain.update(base.to_le_bytes());
            event_chain.update(sha256.as_bytes());
        }
        let initial_chain = hex::encode(event_chain.finalize());
        let report = WindowsModuleGuardReport {
            version: NEVERGUARD_MODULE_GUARD_VERSION,
            active: true,
            healthy: true,
            baseline_module_count: baseline.len().min(u32::MAX as usize) as u32,
            current_module_count: baseline.len().min(u32::MAX as usize) as u32,
            event_chain_sha256: initial_chain,
            module_set_sha256,
            last_heartbeat_unix_ms: now_unix_ms(),
            ..WindowsModuleGuardReport::default()
        };
        let state = Arc::new(Mutex::new(report));

        let mut ack = [0u8; 48];
        ack[..8].copy_from_slice(MODULE_GUARD_ARM_MAGIC);
        ack[8..12].copy_from_slice(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
        ack[12..16].copy_from_slice(&pid.to_le_bytes());
        let mut mac = HmacSha256::new_from_slice(&secret)
            .map_err(|_| "Module Guard arm HMAC initialization failed".to_string())?;
        mac.update(MODULE_GUARD_ARM_DOMAIN);
        mac.update(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
        mac.update(&pid.to_le_bytes());
        ack[16..].copy_from_slice(&mac.finalize().into_bytes());
        server
            .write_all(&ack)
            .await
            .map_err(|err| format!("Module Guard arm acknowledgement write failed: {err}"))?;
        server
            .flush()
            .await
            .map_err(|err| format!("Module Guard arm acknowledgement flush failed: {err}"))?;
        ack.zeroize();

        let expected = baseline
            .into_iter()
            .map(|module| (module.base_address, module.normalized_path))
            .collect::<HashMap<_, _>>();
        let task_state = state.clone();
        tokio::spawn(async move {
            monitor_loop(&mut server, &mut secret, pid, policy, expected, task_state).await;
            secret.zeroize();
        });

        Ok(WindowsModuleGuardSession { state })
    }

    async fn monitor_loop(
        server: &mut NamedPipeServer,
        secret: &mut [u8; 32],
        pid: u32,
        policy: WindowsModuleGuardPolicy,
        mut expected: HashMap<u64, String>,
        state: Arc<Mutex<WindowsModuleGuardReport>>,
    ) {
        let mut packet = [0u8; MODULE_EVENT_PACKET_LEN];
        let mut expected_sequence = 1u64;
        let mut last_module_event = Instant::now() - RECONCILE_GRACE;
        let mut event_chain = {
            let report = lock_report(&state);
            let mut decoded = [0u8; 32];
            if let Ok(bytes) = hex::decode(&report.event_chain_sha256) {
                if bytes.len() == decoded.len() {
                    decoded.copy_from_slice(&bytes);
                }
            }
            decoded
        };

        loop {
            packet.fill(0);
            let read = timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut packet)).await;
            match read {
                Err(_) => {
                    if process_alive(pid) {
                        fail_closed(&state, pid, "Module Guard heartbeat timeout", 0);
                    } else {
                        mark_stopped(&state);
                    }
                    return;
                }
                Ok(Err(err)) => {
                    if process_alive(pid) {
                        fail_closed(
                            &state,
                            pid,
                            &format!("Module Guard event stream disconnected: {err}"),
                            0,
                        );
                    } else {
                        mark_stopped(&state);
                    }
                    return;
                }
                Ok(Ok(_)) => {}
            }

            let event = match parse_event_packet(&packet, secret, pid, expected_sequence) {
                Ok(event) => event,
                Err(err) => {
                    fail_closed(&state, pid, &err, 0);
                    return;
                }
            };
            expected_sequence = expected_sequence.saturating_add(1);

            let mut module_hash = String::new();
            let event_result = match event.reason {
                MODULE_EVENT_REASON_LOADED => {
                    last_module_event = Instant::now();
                    if event.flags & MODULE_EVENT_FLAG_PATH_TRUNCATED != 0 {
                        Err("Module Guard received truncated DLL path".to_string())
                    } else if event.base_address == 0
                        || event.size_of_image == 0
                        || event.path.as_os_str().is_empty()
                    {
                        Err("Module Guard received malformed DLL load event".to_string())
                    } else {
                        match policy.validate_loaded_module(&event.path) {
                            Ok((normalized, sha256)) => {
                                module_hash = sha256;
                                expected.insert(event.base_address, normalized);
                                update_counter(&state, |report| report.load_events += 1);
                                Ok(())
                            }
                            Err(err) => Err(err),
                        }
                    }
                }
                MODULE_EVENT_REASON_UNLOADED => {
                    last_module_event = Instant::now();
                    if event.base_address == 0 {
                        Err("Module Guard received malformed DLL unload event".to_string())
                    } else if expected.remove(&event.base_address).is_none() {
                        Err(format!(
                            "Module Guard observed unload for unknown module base 0x{:X}",
                            event.base_address
                        ))
                    } else {
                        update_counter(&state, |report| report.unload_events += 1);
                        Ok(())
                    }
                }
                MODULE_EVENT_REASON_HEARTBEAT => {
                    update_counter(&state, |report| {
                        report.heartbeat_count += 1;
                        report.last_heartbeat_unix_ms = now_unix_ms();
                    });
                    if last_module_event.elapsed() >= RECONCILE_GRACE {
                        reconcile_snapshot(pid, &expected, &state)
                    } else {
                        Ok(())
                    }
                }
                MODULE_EVENT_REASON_OVERFLOW => {
                    let dropped = event.base_address.max(event.flags as u64);
                    Err(format!("Module Guard Sensor ring overflow: dropped {dropped} events"))
                }
                MODULE_EVENT_REASON_SHUTDOWN => Ok(()),
                other => Err(format!("Module Guard received unsupported event reason {other}")),
            };

            if let Err(err) = event_result {
                let dropped = if event.reason == MODULE_EVENT_REASON_OVERFLOW {
                    event.base_address.max(event.flags as u64)
                } else {
                    0
                };
                fail_closed(&state, pid, &err, dropped);
                return;
            }

            event_chain = advance_event_chain(event_chain, &packet, &module_hash);
            update_counter(&state, |report| {
                report.event_count += 1;
                report.last_sequence = event.sequence;
                report.event_chain_sha256 = hex::encode(event_chain);
            });
            if event.reason == MODULE_EVENT_REASON_SHUTDOWN {
                mark_stopped(&state);
                return;
            }
        }
    }

    fn parse_event_packet(
        packet: &[u8; MODULE_EVENT_PACKET_LEN],
        secret: &[u8; 32],
        expected_pid: u32,
        expected_sequence: u64,
    ) -> Result<ParsedEvent, String> {
        if &packet[..8] != MODULE_EVENT_MAGIC {
            return Err("Module Guard event magic mismatch".to_string());
        }
        let protocol = u32::from_le_bytes(packet[8..12].try_into().expect("fixed packet"));
        let pid = u32::from_le_bytes(packet[12..16].try_into().expect("fixed packet"));
        let sequence = u64::from_le_bytes(packet[16..24].try_into().expect("fixed packet"));
        if protocol != SENSOR_PROTOCOL_VERSION || pid != expected_pid {
            return Err("Module Guard event protocol/PID mismatch".to_string());
        }
        if sequence != expected_sequence {
            return Err(format!(
                "Module Guard event sequence mismatch: expected {expected_sequence}, got {sequence}"
            ));
        }
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|_| "Module Guard event HMAC initialization failed".to_string())?;
        mac.update(MODULE_EVENT_DOMAIN);
        mac.update(&packet[..MODULE_EVENT_PREFIX_LEN]);
        let expected = mac.finalize().into_bytes();
        if !bool::from(expected[..].ct_eq(&packet[MODULE_EVENT_PREFIX_LEN..])) {
            return Err("Module Guard event HMAC mismatch".to_string());
        }

        if packet[46] != 0 || packet[47] != 0 {
            return Err("Module Guard event reserved bytes are non-zero".to_string());
        }
        let reason = u32::from_le_bytes(packet[24..28].try_into().expect("fixed packet"));
        let flags = u32::from_le_bytes(packet[28..32].try_into().expect("fixed packet"));
        let base_address = u64::from_le_bytes(packet[32..40].try_into().expect("fixed packet"));
        let size_of_image = u32::from_le_bytes(packet[40..44].try_into().expect("fixed packet"));
        let path_len = u16::from_le_bytes(packet[44..46].try_into().expect("fixed packet")) as usize;
        if path_len > MODULE_PATH_WCHARS {
            return Err("Module Guard event path length exceeds protocol maximum".to_string());
        }
        let mut wide = Vec::with_capacity(path_len);
        for index in 0..path_len {
            let offset = 48 + index * 2;
            wide.push(u16::from_le_bytes(
                packet[offset..offset + 2].try_into().expect("fixed packet"),
            ));
        }
        let path = if wide.is_empty() {
            PathBuf::new()
        } else {
            PathBuf::from(OsString::from_wide(&wide))
        };
        Ok(ParsedEvent {
            sequence,
            reason,
            flags,
            base_address,
            size_of_image,
            path,
        })
    }

    fn reconcile_snapshot(
        pid: u32,
        expected: &HashMap<u64, String>,
        state: &Arc<Mutex<WindowsModuleGuardReport>>,
    ) -> Result<(), String> {
        let observed = module_snapshot(pid)?;
        let observed_map = observed
            .iter()
            .map(|module| (module.base_address, module.normalized_path.as_str()))
            .collect::<HashMap<_, _>>();
        if observed_map.len() != expected.len() {
            return Err(format!(
                "Module Guard external snapshot drift: expected {} modules, observed {}",
                expected.len(),
                observed_map.len()
            ));
        }
        for (base, expected_path) in expected {
            let Some(observed_path) = observed_map.get(base) else {
                return Err(format!(
                    "Module Guard external snapshot missing module base 0x{base:X}"
                ));
            };
            if !observed_path.eq_ignore_ascii_case(expected_path) {
                return Err(format!(
                    "Module Guard module path drift at base 0x{base:X}: expected {expected_path}, observed {observed_path}"
                ));
            }
        }
        let set_hash = module_set_sha256(&observed);
        update_counter(state, |report| {
            report.current_module_count = observed.len().min(u32::MAX as usize) as u32;
            report.module_set_sha256 = set_hash;
        });
        Ok(())
    }

    fn module_snapshot(pid: u32) -> Result<Vec<LoadedModule>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "Module Guard snapshot failed for PID {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let snapshot = OwnedHandle(snapshot);
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        if unsafe { Module32FirstW(snapshot.raw(), &mut entry) } == 0 {
            return Err(format!(
                "Module Guard module enumeration failed for PID {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut modules = Vec::new();
        loop {
            let path = wide_z_to_path(&entry.szExePath).ok_or_else(|| {
                format!("Module Guard encountered module without a path in PID {pid}")
            })?;
            let normalized_path = normalize_path(&canonical_or_absolute(&path)?);
            modules.push(LoadedModule {
                base_address: entry.modBaseAddr as usize as u64,
                size_of_image: entry.modBaseSize,
                path,
                normalized_path,
            });
            if unsafe { Module32NextW(snapshot.raw(), &mut entry) } == 0 {
                break;
            }
        }
        Ok(modules)
    }

    fn module_set_sha256(modules: &[LoadedModule]) -> String {
        let mut records = modules
            .iter()
            .map(|module| {
                format!(
                    "{:016x}\0{}\0{}\0{}",
                    module.base_address,
                    module.size_of_image,
                    module.normalized_path,
                    module.path.to_string_lossy()
                )
            })
            .collect::<Vec<_>>();
        records.sort_unstable();
        let mut digest = Sha256::new();
        digest.update(b"NeverLauncher Module Guard module-set v1\0");
        for record in records {
            digest.update((record.len() as u32).to_le_bytes());
            digest.update(record.as_bytes());
        }
        hex::encode(digest.finalize())
    }

    fn advance_event_chain(previous: [u8; 32], packet: &[u8], module_hash: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"NeverLauncher Module Guard event-chain v1\0");
        digest.update(previous);
        digest.update(packet);
        digest.update((module_hash.len() as u32).to_le_bytes());
        digest.update(module_hash.as_bytes());
        let output = digest.finalize();
        let mut next = [0u8; 32];
        next.copy_from_slice(&output);
        next
    }

    fn fail_closed(
        state: &Arc<Mutex<WindowsModuleGuardReport>>,
        pid: u32,
        reason: &str,
        dropped: u64,
    ) {
        update_counter(state, |report| {
            report.active = false;
            report.healthy = false;
            report.violation_count = report.violation_count.saturating_add(1);
            report.dropped_event_count = report.dropped_event_count.saturating_add(dropped);
            report.last_violation = reason.to_string();
        });
        terminate_runtime(pid);
    }

    fn mark_stopped(state: &Arc<Mutex<WindowsModuleGuardReport>>) {
        update_counter(state, |report| report.active = false);
    }

    fn update_counter(
        state: &Arc<Mutex<WindowsModuleGuardReport>>,
        update: impl FnOnce(&mut WindowsModuleGuardReport),
    ) {
        match state.lock() {
            Ok(mut report) => update(&mut report),
            Err(poisoned) => update(&mut poisoned.into_inner()),
        }
    }

    fn lock_report(state: &Arc<Mutex<WindowsModuleGuardReport>>) -> WindowsModuleGuardReport {
        match state.lock() {
            Ok(report) => report.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn process_alive(pid: u32) -> bool {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let handle = OwnedHandle(handle);
        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(handle.raw(), &mut exit_code) != 0 && exit_code == STILL_ACTIVE_EXIT_CODE }
    }

    fn terminate_runtime(pid: u32) {
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return;
        }
        let handle = OwnedHandle(handle);
        unsafe {
            let _ = TerminateProcess(handle.raw(), 0xE3);
        }
    }

    fn sha256_file(path: &Path) -> Result<String, String> {
        let file = File::open(path)
            .map_err(|err| format!("Module Guard cannot open {} for hashing: {err}", path.display()))?;
        let mut reader = BufReader::with_capacity(128 * 1024, file);
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|err| format!("Module Guard cannot hash {}: {err}", path.display()))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(hex::encode(digest.finalize()))
    }

    fn resolve_program_path(program: &std::ffi::OsStr, current_dir: &Path) -> PathBuf {
        let candidate = PathBuf::from(program);
        if candidate.is_absolute() {
            return candidate;
        }
        if candidate.components().count() > 1 {
            return current_dir.join(candidate);
        }
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                let joined = directory.join(&candidate);
                if joined.is_file() {
                    return joined;
                }
            }
        }
        current_dir.join(candidate)
    }

    fn canonical_or_absolute(path: &Path) -> Result<PathBuf, String> {
        let loader_path = resolve_loader_path(path);
        if let Ok(canonical) = std::fs::canonicalize(&loader_path) {
            return Ok(canonical);
        }
        if loader_path.is_absolute() {
            return Ok(loader_path);
        }
        std::env::current_dir()
            .map(|current| current.join(&loader_path))
            .map_err(|err| format!("Module Guard cannot resolve {}: {err}", path.display()))
    }

    fn resolve_loader_path(path: &Path) -> PathBuf {
        let value = path.to_string_lossy();
        if let Some(stripped) = value.strip_prefix(r"\??\") {
            return PathBuf::from(stripped);
        }
        if let Some(stripped) = value.strip_prefix(r"\SystemRoot\") {
            if let Some(system_root) = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("WINDIR")) {
                return PathBuf::from(system_root).join(stripped);
            }
        }
        path.to_path_buf()
    }

    fn normalize_path(path: &Path) -> String {
        let mut value = path.to_string_lossy().replace('/', "\\");
        if let Some(stripped) = value.strip_prefix(r"\\?\UNC\") {
            value = format!(r"\\{stripped}");
        } else if let Some(stripped) = value.strip_prefix(r"\\?\") {
            value = stripped.to_string();
        }
        value.trim_end_matches('\\').to_ascii_lowercase()
    }

    fn path_within(path: &str, root: &str) -> bool {
        if path.eq_ignore_ascii_case(root) {
            return true;
        }
        path.strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
    }

    fn wide_z_to_path(value: &[u16]) -> Option<PathBuf> {
        let len = value.iter().position(|ch| *ch == 0).unwrap_or(value.len());
        if len == 0 {
            None
        } else {
            Some(PathBuf::from(OsString::from_wide(&value[..len])))
        }
    }

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }
}

#[cfg(windows)]
pub use imp::{arm_module_guard, policy_for_command, WindowsModuleGuardPolicy};

#[cfg(not(windows))]
#[derive(Clone, Debug, Default)]
pub struct WindowsModuleGuardPolicy;
