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
    pub hook_engine: crate::WindowsHookEngineReport,
    pub memory_integrity: crate::WindowsMemoryIntegrityReport,
    #[serde(default)]
    pub thread_process_integrity: crate::WindowsThreadProcessIntegrityReport,
    #[serde(default)]
    pub debug_instrumentation: crate::WindowsDebugInstrumentationReport,
    #[serde(default)]
    pub jvm_aware: crate::WindowsJvmAwareProtectionReport,
    #[serde(default)]
    pub continuous_guard: crate::WindowsContinuousGuardReport,
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
            hook_engine: crate::WindowsHookEngineReport::default(),
            memory_integrity: crate::WindowsMemoryIntegrityReport::default(),
            thread_process_integrity: crate::WindowsThreadProcessIntegrityReport::default(),
            debug_instrumentation: crate::WindowsDebugInstrumentationReport::default(),
            jvm_aware: crate::WindowsJvmAwareProtectionReport::default(),
            continuous_guard: crate::WindowsContinuousGuardReport::default(),
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

    const SENSOR_PROTOCOL_VERSION: u32 = 3;
    const MODULE_GUARD_ARM_MAGIC: &[u8; 8] = b"NGARM004";
    const MODULE_GUARD_ARM_DOMAIN: &[u8] = b"neverguard-module-guard-arm-v2";
    const MODULE_EVENT_MAGIC: &[u8; 8] = b"NGMOD004";
    const MODULE_EVENT_DOMAIN: &[u8] = b"neverguard-module-event-v2";
    const MODULE_EVENT_REASON_LOADED: u32 = 1;
    const MODULE_EVENT_REASON_UNLOADED: u32 = 2;
    const MODULE_EVENT_REASON_HEARTBEAT: u32 = 3;
    const MODULE_EVENT_REASON_OVERFLOW: u32 = 4;
    const MODULE_EVENT_REASON_SHUTDOWN: u32 = 5;
    const MODULE_EVENT_REASON_HOOK_READY: u32 = 6;
    const MODULE_EVENT_REASON_HOOK_HEARTBEAT: u32 = 7;
    const MODULE_EVENT_REASON_HOOK_TAMPER: u32 = 8;
    const MODULE_EVENT_REASON_MEMORY_READY: u32 = 9;
    const MODULE_EVENT_REASON_MEMORY_HEARTBEAT: u32 = 10;
    const MODULE_EVENT_REASON_MEMORY_TAMPER: u32 = 11;
    const MODULE_EVENT_REASON_THREAD_PROCESS_READY: u32 = 12;
    const MODULE_EVENT_REASON_THREAD_PROCESS_HEARTBEAT: u32 = 13;
    const MODULE_EVENT_REASON_THREAD_PROCESS_TAMPER: u32 = 14;
    const MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_READY: u32 = 15;
    const MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_HEARTBEAT: u32 = 16;
    const MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_TAMPER: u32 = 17;
    const MODULE_EVENT_REASON_JVM_AWARE_READY: u32 = 18;
    const MODULE_EVENT_REASON_JVM_AWARE_HEARTBEAT: u32 = 19;
    const MODULE_EVENT_REASON_JVM_AWARE_TAMPER: u32 = 20;
    const MODULE_EVENT_REASON_CONTINUOUS_READY: u32 = 21;
    const MODULE_EVENT_REASON_CONTINUOUS_HEARTBEAT: u32 = 22;
    const MODULE_EVENT_REASON_CONTINUOUS_TAMPER: u32 = 23;
    const CONTINUOUS_GUARD_VERSION: u32 = 1;
    const CONTINUOUS_GUARD_ACK_MAGIC: &[u8; 8] = b"NGCGAK01";
    const CONTINUOUS_GUARD_ACK_DOMAIN: &[u8] = b"neverguard-continuous-guard-ack-v1";
    const CONTINUOUS_GUARD_ACK_PREFIX_LEN: usize = 64;
    const CONTINUOUS_GUARD_ACK_PACKET_LEN: usize = 96;
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
        runtime_policy: crate::RuntimeProcessPolicyGuard,
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
            event_chain_sha256: initial_chain.clone(),
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

        // Agent_OnLoad is not allowed to return until the in-process aggressive
        // hook engine proves that it is armed. The first authenticated stream
        // packet is therefore a mandatory HOOK_READY record.
        let mut ready_packet = [0u8; MODULE_EVENT_PACKET_LEN];
        timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut ready_packet))
            .await
            .map_err(|_| "NeverGuard Hook Engine ready proof timed out".to_string())?
            .map_err(|err| format!("NeverGuard Hook Engine ready proof read failed: {err}"))?;
        let ready_event = parse_event_packet(&ready_packet, &secret, pid, 1)?;
        if ready_event.reason != MODULE_EVENT_REASON_HOOK_READY {
            return Err(format!(
                "NeverGuard Hook Engine expected HOOK_READY as first event, got {}",
                ready_event.reason
            ));
        }
        let hook_digest = hook_digest_from_event(&ready_event)?;
        if ready_event.flags == 0 || ready_event.size_of_image == 0 {
            return Err("NeverGuard Hook Engine armed with zero hooked modules/slots".to_string());
        }
        let mut ready_chain = [0u8; 32];
        if let Ok(bytes) = hex::decode(&initial_chain) {
            if bytes.len() == ready_chain.len() {
                ready_chain.copy_from_slice(&bytes);
            }
        }
        let mut continuous_chain = [0u8; 32];
        continuous_chain = advance_continuous_event_chain(continuous_chain, &ready_packet);
        ready_chain = advance_event_chain(ready_chain, &ready_packet, &hook_digest);
        update_counter(&state, |report| {
            report.event_count = 1;
            report.last_sequence = 1;
            report.event_chain_sha256 = hex::encode(ready_chain);
            report.hook_engine.active = true;
            report.hook_engine.healthy = true;
            report.hook_engine.hooked_module_count = ready_event.flags;
            report.hook_engine.hooked_slot_count = ready_event.size_of_image;
            report.hook_engine.intercepted_call_count = ready_event.base_address;
            report.hook_engine.integrity_check_count = 1;
            report.hook_engine.hook_set_sha256 = hook_digest;
        });
        ready_packet.zeroize();

        // Memory Integrity must also be armed before Agent_OnLoad returns. The
        // second authenticated stream packet is a mandatory MEMORY_READY proof.
        let mut memory_ready_packet = [0u8; MODULE_EVENT_PACKET_LEN];
        timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut memory_ready_packet))
            .await
            .map_err(|_| "NeverGuard Memory Integrity ready proof timed out".to_string())?
            .map_err(|err| format!("NeverGuard Memory Integrity ready proof read failed: {err}"))?;
        let memory_ready_event = parse_event_packet(&memory_ready_packet, &secret, pid, 2)?;
        if memory_ready_event.reason != MODULE_EVENT_REASON_MEMORY_READY {
            return Err(format!(
                "NeverGuard Memory Integrity expected MEMORY_READY as second event, got {}",
                memory_ready_event.reason
            ));
        }
        let memory_ready = memory_report_from_event(&memory_ready_event)?;
        if memory_ready.executable_region_count == 0 || memory_ready.image_code_region_count == 0 {
            return Err("NeverGuard Memory Integrity armed with zero executable/image code coverage".to_string());
        }
        continuous_chain = advance_continuous_event_chain(continuous_chain, &memory_ready_packet);
        ready_chain = advance_event_chain(
            ready_chain,
            &memory_ready_packet,
            &memory_ready.code_set_sha256,
        );
        update_counter(&state, |report| {
            report.event_count = 2;
            report.last_sequence = 2;
            report.event_chain_sha256 = hex::encode(ready_chain);
            report.memory_integrity = memory_ready;
        });
        memory_ready_packet.zeroize();

        // Thread & Process Integrity is the third mandatory startup proof. The
        // Sensor validates thread origins in-process while the parent validates
        // the complete descendant tree against the non-breakaway Job Object.
        let mut thread_ready_packet = [0u8; MODULE_EVENT_PACKET_LEN];
        timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut thread_ready_packet))
            .await
            .map_err(|_| "NeverGuard Thread & Process Integrity ready proof timed out".to_string())?
            .map_err(|err| format!("NeverGuard Thread & Process Integrity ready proof read failed: {err}"))?;
        let thread_ready_event = parse_event_packet(&thread_ready_packet, &secret, pid, 3)?;
        if thread_ready_event.reason != MODULE_EVENT_REASON_THREAD_PROCESS_READY {
            return Err(format!(
                "NeverGuard Thread & Process Integrity expected THREAD_PROCESS_READY as third event, got {}",
                thread_ready_event.reason
            ));
        }
        let process_tree = runtime_policy.verify_process_tree(pid)?;
        let mut thread_ready = thread_process_report_from_event(&thread_ready_event)?;
        if thread_ready.current_thread_count == 0 || thread_ready.baseline_thread_count == 0 {
            return Err("NeverGuard Thread & Process Integrity armed with zero thread coverage".to_string());
        }
        thread_ready.active = true;
        thread_ready.healthy = true;
        thread_ready.baseline_process_count = process_tree.process_count;
        thread_ready.current_process_count = process_tree.process_count;
        thread_ready.descendant_process_count = process_tree.descendant_count;
        thread_ready.descendant_process_peak = process_tree.descendant_count;
        thread_ready.job_bound = process_tree.job_bound;
        thread_ready.breakaway_allowed = runtime_policy.report().breakaway_allowed;
        thread_ready.process_tree_sha256 = process_tree.process_tree_sha256.clone();
        continuous_chain = advance_continuous_event_chain(continuous_chain, &thread_ready_packet);
        ready_chain = advance_event_chain(
            ready_chain,
            &thread_ready_packet,
            &thread_ready.thread_set_sha256,
        );
        update_counter(&state, |report| {
            report.event_count = 3;
            report.last_sequence = 3;
            report.event_chain_sha256 = hex::encode(ready_chain);
            report.thread_process_integrity = thread_ready;
        });
        thread_ready_packet.zeroize();

        // Debug & Instrumentation Guard is the fourth mandatory startup proof.
        // Agent_OnLoad cannot return until the Sensor proves that no debugger is
        // attached and the JVM attach mechanism is disabled by the launcher.
        let mut debug_ready_packet = [0u8; MODULE_EVENT_PACKET_LEN];
        timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut debug_ready_packet))
            .await
            .map_err(|_| "NeverGuard Debug & Instrumentation Guard ready proof timed out".to_string())?
            .map_err(|err| format!("NeverGuard Debug & Instrumentation Guard ready proof read failed: {err}"))?;
        let debug_ready_event = parse_event_packet(&debug_ready_packet, &secret, pid, 4)?;
        if debug_ready_event.reason != MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_READY {
            return Err(format!(
                "NeverGuard Debug & Instrumentation Guard expected DEBUG_INSTRUMENTATION_READY as fourth event, got {}",
                debug_ready_event.reason
            ));
        }
        let debug_ready = debug_instrumentation_report_from_event(&debug_ready_event)?;
        if debug_ready.debugger_present
            || debug_ready.remote_debugger_present
            || debug_ready.debug_port_present
            || debug_ready.debug_object_present
            || !debug_ready.debug_flags_no_debug_inherit
        {
            return Err("NeverGuard Debug & Instrumentation Guard armed with active debugger state".to_string());
        }
        continuous_chain = advance_continuous_event_chain(continuous_chain, &debug_ready_packet);
        ready_chain = advance_event_chain(
            ready_chain,
            &debug_ready_packet,
            &debug_ready.state_sha256,
        );
        update_counter(&state, |report| {
            report.event_count = 4;
            report.last_sequence = 4;
            report.event_chain_sha256 = hex::encode(ready_chain);
            report.debug_instrumentation = debug_ready;
        });
        debug_ready_packet.zeroize();

        // JVM-Aware Protection is the fifth mandatory startup proof. The Sensor
        // has already resolved the loaded jvm.dll identity and certified Java
        // major before the hook engine is armed, so post-start executable
        // MEM_PRIVATE transitions can be attributed to HotSpot rather than merely
        // accepted because VirtualAlloc/VirtualProtect was observed.
        let mut jvm_ready_packet = [0u8; MODULE_EVENT_PACKET_LEN];
        timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut jvm_ready_packet))
            .await
            .map_err(|_| "NeverGuard JVM-Aware Protection ready proof timed out".to_string())?
            .map_err(|err| format!("NeverGuard JVM-Aware Protection ready proof read failed: {err}"))?;
        let jvm_ready_event = parse_event_packet(&jvm_ready_packet, &secret, pid, 5)?;
        if jvm_ready_event.reason != MODULE_EVENT_REASON_JVM_AWARE_READY {
            return Err(format!(
                "NeverGuard JVM-Aware Protection expected JVM_AWARE_READY as fifth event, got {}",
                jvm_ready_event.reason
            ));
        }
        let jvm_ready = jvm_aware_report_from_event(&jvm_ready_event)?;
        if !jvm_ready.certified_major || !crate::NEVERGUARD_CERTIFIED_JAVA_MAJORS.contains(&jvm_ready.java_major) {
            return Err(format!(
                "NeverGuard JVM-Aware Protection rejected uncertified Java major {}",
                jvm_ready.java_major
            ));
        }
        continuous_chain = advance_continuous_event_chain(continuous_chain, &jvm_ready_packet);
        ready_chain = advance_event_chain(
            ready_chain,
            &jvm_ready_packet,
            &jvm_ready.state_sha256,
        );
        update_counter(&state, |report| {
            report.event_count = 5;
            report.last_sequence = 5;
            report.event_chain_sha256 = hex::encode(ready_chain);
            report.jvm_aware = jvm_ready;
        });
        jvm_ready_packet.zeroize();

        // Continuous Guard is the sixth mandatory startup proof. It carries the
        // Sensor's independently maintained digest of every authenticated packet
        // emitted so far. The parent must see the exact same chain and return a
        // signed ACK before Agent_OnLoad is allowed to complete.
        let mut continuous_ready_packet = [0u8; MODULE_EVENT_PACKET_LEN];
        timeout(MODULE_STREAM_TIMEOUT, server.read_exact(&mut continuous_ready_packet))
            .await
            .map_err(|_| "NeverGuard Continuous Guard ready proof timed out".to_string())?
            .map_err(|err| format!("NeverGuard Continuous Guard ready proof read failed: {err}"))?;
        let continuous_ready_event = parse_event_packet(&continuous_ready_packet, &secret, pid, 6)?;
        if continuous_ready_event.reason != MODULE_EVENT_REASON_CONTINUOUS_READY {
            return Err(format!(
                "NeverGuard Continuous Guard expected CONTINUOUS_READY as sixth event, got {}",
                continuous_ready_event.reason
            ));
        }
        if continuous_ready_event.flags != CONTINUOUS_GUARD_VERSION
            || continuous_ready_event.base_address != 0
            || continuous_ready_event.size_of_image != 0
        {
            return Err("NeverGuard Continuous Guard ready metadata mismatch".to_string());
        }
        let continuous_pre_digest = continuous_digest_from_event(&continuous_ready_event)?;
        if continuous_pre_digest != hex::encode(continuous_chain) {
            return Err("NeverGuard Continuous Guard startup event-chain mismatch".to_string());
        }
        continuous_chain = advance_continuous_event_chain(continuous_chain, &continuous_ready_packet);
        ready_chain = advance_event_chain(
            ready_chain,
            &continuous_ready_packet,
            &continuous_pre_digest,
        );
        let guard_sequence = 1u64;
        write_continuous_guard_ack(
            &mut server,
            &secret,
            pid,
            guard_sequence,
            continuous_ready_event.sequence,
            continuous_chain,
        )
        .await?;
        let continuous_now = now_unix_ms();
        update_counter(&state, |report| {
            report.event_count = 6;
            report.last_sequence = 6;
            report.event_chain_sha256 = hex::encode(ready_chain);
            report.continuous_guard = crate::WindowsContinuousGuardReport {
                version: crate::NEVERGUARD_CONTINUOUS_GUARD_VERSION,
                active: true,
                healthy: true,
                sensor_heartbeat_count: 1,
                guard_heartbeat_count: 1,
                cross_check_count: 1,
                last_sensor_sequence: continuous_ready_event.sequence,
                last_guard_sequence: guard_sequence,
                sensor_event_chain_sha256: hex::encode(continuous_chain),
                last_cross_check_sha256: hex::encode(continuous_chain),
                last_sensor_heartbeat_unix_ms: continuous_now,
                last_guard_heartbeat_unix_ms: continuous_now,
                violation_count: 0,
                last_violation: String::new(),
            };
        });
        continuous_ready_packet.zeroize();

        let expected = baseline
            .into_iter()
            .map(|module| (module.base_address, module.normalized_path))
            .collect::<HashMap<_, _>>();
        let task_state = state.clone();
        tokio::spawn(async move {
            monitor_loop(
                &mut server,
                &mut secret,
                pid,
                policy,
                runtime_policy,
                expected,
                continuous_chain,
                guard_sequence,
                task_state,
            )
            .await;
            secret.zeroize();
        });

        Ok(WindowsModuleGuardSession { state })
    }

    async fn monitor_loop(
        server: &mut NamedPipeServer,
        secret: &mut [u8; 32],
        pid: u32,
        policy: WindowsModuleGuardPolicy,
        runtime_policy: crate::RuntimeProcessPolicyGuard,
        mut expected: HashMap<u64, String>,
        mut continuous_chain: [u8; 32],
        mut guard_sequence: u64,
        state: Arc<Mutex<WindowsModuleGuardReport>>,
    ) {
        let mut packet = [0u8; MODULE_EVENT_PACKET_LEN];
        let mut expected_sequence = lock_report(&state).last_sequence.saturating_add(1);
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

            let continuous_chain_before = continuous_chain;
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
                MODULE_EVENT_REASON_HOOK_READY => {
                    Err("NeverGuard Hook Engine emitted duplicate HOOK_READY".to_string())
                }
                MODULE_EVENT_REASON_HOOK_HEARTBEAT => {
                    match hook_digest_from_event(&event) {
                        Err(err) => Err(err),
                        Ok(digest) if event.flags == 0 || event.size_of_image == 0 => {
                            let _ = digest;
                            Err("NeverGuard Hook Engine heartbeat reported zero coverage".to_string())
                        }
                        Ok(digest) => {
                            module_hash = digest.clone();
                            update_counter(&state, |report| {
                                report.hook_engine.active = true;
                                report.hook_engine.healthy = true;
                                report.hook_engine.hooked_module_count = event.flags;
                                report.hook_engine.hooked_slot_count = event.size_of_image;
                                report.hook_engine.intercepted_call_count = event.base_address;
                                report.hook_engine.integrity_check_count = report
                                    .hook_engine
                                    .integrity_check_count
                                    .saturating_add(1);
                                report.hook_engine.hook_set_sha256 = digest;
                            });
                            Ok(())
                        }
                    }
                }
                MODULE_EVENT_REASON_HOOK_TAMPER => {
                    let detail = event.path.to_string_lossy();
                    Err(if detail.is_empty() {
                        "NeverGuard Hook Engine integrity violation".to_string()
                    } else {
                        format!("NeverGuard Hook Engine integrity violation: {detail}")
                    })
                }
                MODULE_EVENT_REASON_MEMORY_READY => {
                    Err("NeverGuard Memory Integrity emitted duplicate MEMORY_READY".to_string())
                }
                MODULE_EVENT_REASON_MEMORY_HEARTBEAT => {
                    match memory_report_from_event(&event) {
                        Err(err) => Err(err),
                        Ok(memory) if memory.executable_region_count == 0 || memory.image_code_region_count == 0 => {
                            Err("NeverGuard Memory Integrity heartbeat reported zero coverage".to_string())
                        }
                        Ok(mut memory) => {
                            module_hash = memory.code_set_sha256.clone();
                            update_counter(&state, |report| {
                                memory.active = true;
                                memory.healthy = true;
                                memory.integrity_check_count = report
                                    .memory_integrity
                                    .integrity_check_count
                                    .saturating_add(1);
                                memory.violation_count = report.memory_integrity.violation_count;
                                report.memory_integrity = memory;
                            });
                            Ok(())
                        }
                    }
                }
                MODULE_EVENT_REASON_MEMORY_TAMPER => {
                    let detail = event.path.to_string_lossy();
                    Err(if detail.is_empty() {
                        "NeverGuard Memory Integrity runtime tampering detected".to_string()
                    } else {
                        format!("NeverGuard Memory Integrity runtime tampering detected: {detail}")
                    })
                }
                MODULE_EVENT_REASON_THREAD_PROCESS_READY => {
                    Err("NeverGuard Thread & Process Integrity emitted duplicate THREAD_PROCESS_READY".to_string())
                }
                MODULE_EVENT_REASON_THREAD_PROCESS_HEARTBEAT => {
                    match thread_process_report_from_event(&event) {
                        Err(err) => Err(err),
                        Ok(thread_report) if thread_report.current_thread_count == 0 => {
                            Err("NeverGuard Thread & Process Integrity heartbeat reported zero live threads".to_string())
                        }
                        Ok(mut thread_report) => {
                            match runtime_policy.verify_process_tree(pid) {
                                Err(err) => Err(format!(
                                    "NeverGuard Thread & Process Integrity process-tree verification failed: {err}"
                                )),
                                Ok(tree) => {
                                    module_hash = thread_report.thread_set_sha256.clone();
                                    update_counter(&state, |report| {
                                        let previous = &report.thread_process_integrity;
                                        let process_changed = !previous.process_tree_sha256.is_empty()
                                            && previous.process_tree_sha256 != tree.process_tree_sha256;
                                        thread_report.active = true;
                                        thread_report.healthy = true;
                                        thread_report.baseline_process_count = previous.baseline_process_count;
                                        thread_report.current_process_count = tree.process_count;
                                        thread_report.descendant_process_count = tree.descendant_count;
                                        thread_report.descendant_process_peak = previous
                                            .descendant_process_peak
                                            .max(tree.descendant_count);
                                        thread_report.process_transition_count = previous
                                            .process_transition_count
                                            .saturating_add(u64::from(process_changed));
                                        thread_report.violation_count = previous.violation_count;
                                        thread_report.job_bound = tree.job_bound;
                                        thread_report.breakaway_allowed = runtime_policy.report().breakaway_allowed;
                                        thread_report.process_tree_sha256 = tree.process_tree_sha256;
                                        report.thread_process_integrity = thread_report;
                                    });
                                    Ok(())
                                }
                            }
                        }
                    }
                }
                MODULE_EVENT_REASON_THREAD_PROCESS_TAMPER => {
                    let detail = event.path.to_string_lossy();
                    Err(if detail.is_empty() {
                        "NeverGuard Thread & Process Integrity suspicious runtime transition detected".to_string()
                    } else {
                        format!(
                            "NeverGuard Thread & Process Integrity suspicious runtime transition detected: {detail}"
                        )
                    })
                }
                MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_READY => {
                    Err("NeverGuard Debug & Instrumentation Guard emitted duplicate DEBUG_INSTRUMENTATION_READY".to_string())
                }
                MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_HEARTBEAT => {
                    match debug_instrumentation_report_from_event(&event) {
                        Err(err) => Err(err),
                        Ok(mut debug_report) => {
                            module_hash = debug_report.state_sha256.clone();
                            update_counter(&state, |report| {
                                debug_report.active = true;
                                debug_report.healthy = true;
                                debug_report.attach_mechanism_disabled = true;
                                debug_report.blocked_startup_instrumentation_count = report
                                    .debug_instrumentation
                                    .blocked_startup_instrumentation_count;
                                debug_report.violation_count = report.debug_instrumentation.violation_count;
                                report.debug_instrumentation = debug_report;
                            });
                            Ok(())
                        }
                    }
                }
                MODULE_EVENT_REASON_DEBUG_INSTRUMENTATION_TAMPER => {
                    let detail = event.path.to_string_lossy();
                    Err(if detail.is_empty() {
                        "NeverGuard Debug & Instrumentation Guard unwanted debug/instrumentation boundary detected".to_string()
                    } else {
                        format!(
                            "NeverGuard Debug & Instrumentation Guard unwanted debug/instrumentation boundary detected: {detail}"
                        )
                    })
                }
                MODULE_EVENT_REASON_JVM_AWARE_READY => {
                    Err("NeverGuard JVM-Aware Protection emitted duplicate JVM_AWARE_READY".to_string())
                }
                MODULE_EVENT_REASON_JVM_AWARE_HEARTBEAT => {
                    match jvm_aware_report_from_event(&event) {
                        Err(err) => Err(err),
                        Ok(mut jvm_report) => {
                            module_hash = jvm_report.state_sha256.clone();
                            update_counter(&state, |report| {
                                jvm_report.active = true;
                                jvm_report.healthy = true;
                                jvm_report.violation_count = report.jvm_aware.violation_count;
                                report.jvm_aware = jvm_report;
                            });
                            Ok(())
                        }
                    }
                }
                MODULE_EVENT_REASON_JVM_AWARE_TAMPER => {
                    let detail = event.path.to_string_lossy();
                    Err(if detail.is_empty() {
                        "NeverGuard JVM-Aware Protection rejected non-JVM executable-memory transition".to_string()
                    } else {
                        format!(
                            "NeverGuard JVM-Aware Protection rejected non-JVM executable-memory transition: {detail}"
                        )
                    })
                }
                MODULE_EVENT_REASON_CONTINUOUS_READY => {
                    Err("NeverGuard Continuous Guard emitted duplicate CONTINUOUS_READY".to_string())
                }
                MODULE_EVENT_REASON_CONTINUOUS_HEARTBEAT => {
                    if event.flags != CONTINUOUS_GUARD_VERSION || event.size_of_image != 0 {
                        Err("NeverGuard Continuous Guard heartbeat metadata mismatch".to_string())
                    } else if event.base_address != guard_sequence {
                        Err(format!(
                            "NeverGuard Continuous Guard guard-sequence mismatch: expected {guard_sequence}, got {}",
                            event.base_address
                        ))
                    } else {
                        match continuous_digest_from_event(&event) {
                            Err(err) => Err(err),
                            Ok(digest) if digest != hex::encode(continuous_chain_before) => {
                                Err("NeverGuard Continuous Guard event-chain cross-check mismatch".to_string())
                            }
                            Ok(digest) => {
                                module_hash = digest;
                                Ok(())
                            }
                        }
                    }
                }
                MODULE_EVENT_REASON_CONTINUOUS_TAMPER => {
                    let detail = event.path.to_string_lossy();
                    Err(if detail.is_empty() {
                        "NeverGuard Continuous Guard Sensor/Guard cross-check failed".to_string()
                    } else {
                        format!("NeverGuard Continuous Guard Sensor/Guard cross-check failed: {detail}")
                    })
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

            let next_continuous_chain = advance_continuous_event_chain(continuous_chain, &packet);
            if event.reason == MODULE_EVENT_REASON_CONTINUOUS_HEARTBEAT {
                let next_guard_sequence = match guard_sequence.checked_add(1) {
                    Some(value) => value,
                    None => {
                        fail_closed(&state, pid, "NeverGuard Continuous Guard guard-sequence overflow", 0);
                        return;
                    }
                };
                if let Err(err) = write_continuous_guard_ack(
                    server,
                    secret,
                    pid,
                    next_guard_sequence,
                    event.sequence,
                    next_continuous_chain,
                )
                .await
                {
                    fail_closed(&state, pid, &err, 0);
                    return;
                }
                guard_sequence = next_guard_sequence;
                let now = now_unix_ms();
                update_counter(&state, |report| {
                    report.continuous_guard.active = true;
                    report.continuous_guard.healthy = true;
                    report.continuous_guard.sensor_heartbeat_count = report
                        .continuous_guard
                        .sensor_heartbeat_count
                        .saturating_add(1);
                    report.continuous_guard.guard_heartbeat_count = report
                        .continuous_guard
                        .guard_heartbeat_count
                        .saturating_add(1);
                    report.continuous_guard.cross_check_count = report
                        .continuous_guard
                        .cross_check_count
                        .saturating_add(1);
                    report.continuous_guard.last_sensor_sequence = event.sequence;
                    report.continuous_guard.last_guard_sequence = guard_sequence;
                    report.continuous_guard.last_cross_check_sha256 = hex::encode(next_continuous_chain);
                    report.continuous_guard.last_sensor_heartbeat_unix_ms = now;
                    report.continuous_guard.last_guard_heartbeat_unix_ms = now;
                });
            }
            continuous_chain = next_continuous_chain;
            event_chain = advance_event_chain(event_chain, &packet, &module_hash);
            update_counter(&state, |report| {
                report.event_count += 1;
                report.last_sequence = event.sequence;
                report.event_chain_sha256 = hex::encode(event_chain);
                report.continuous_guard.sensor_event_chain_sha256 = hex::encode(continuous_chain);
            });
            if event.reason == MODULE_EVENT_REASON_SHUTDOWN {
                mark_stopped(&state);
                return;
            }
        }
    }

    fn hook_digest_from_event(event: &ParsedEvent) -> Result<String, String> {
        let digest = event.path.to_string_lossy().to_string();
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("NeverGuard Hook Engine invalid hook-set digest".to_string());
        }
        Ok(digest.to_ascii_lowercase())
    }

    fn memory_report_from_event(event: &ParsedEvent) -> Result<crate::WindowsMemoryIntegrityReport, String> {
        let payload = event.path.to_string_lossy();
        let mut fields = payload.split('|');
        let code_set_sha256 = validate_memory_digest(
            fields.next().ok_or_else(|| "NeverGuard Memory Integrity missing code-set digest".to_string())?,
            "code-set",
        )?;
        let executable_map_sha256 = validate_memory_digest(
            fields.next().ok_or_else(|| "NeverGuard Memory Integrity missing executable-map digest".to_string())?,
            "executable-map",
        )?;
        let dynamic_executable_region_count = fields
            .next()
            .ok_or_else(|| "NeverGuard Memory Integrity missing dynamic-region count".to_string())?
            .parse::<u32>()
            .map_err(|_| "NeverGuard Memory Integrity invalid dynamic-region count".to_string())?;
        let rwx_region_count = fields
            .next()
            .ok_or_else(|| "NeverGuard Memory Integrity missing RWX-region count".to_string())?
            .parse::<u32>()
            .map_err(|_| "NeverGuard Memory Integrity invalid RWX-region count".to_string())?;
        let observed_transition_count = fields
            .next()
            .ok_or_else(|| "NeverGuard Memory Integrity missing transition count".to_string())?
            .parse::<u64>()
            .map_err(|_| "NeverGuard Memory Integrity invalid transition count".to_string())?;
        if fields.next().is_some() {
            return Err("NeverGuard Memory Integrity malformed evidence payload".to_string());
        }
        Ok(crate::WindowsMemoryIntegrityReport {
            version: crate::NEVERGUARD_MEMORY_INTEGRITY_VERSION,
            active: true,
            healthy: true,
            executable_region_count: event.flags,
            image_code_region_count: event.size_of_image,
            dynamic_executable_region_count,
            rwx_region_count,
            executable_bytes: event.base_address,
            observed_transition_count,
            integrity_check_count: 1,
            violation_count: 0,
            code_set_sha256,
            executable_map_sha256,
            last_violation: String::new(),
        })
    }

    fn thread_process_report_from_event(
        event: &ParsedEvent,
    ) -> Result<crate::WindowsThreadProcessIntegrityReport, String> {
        let payload = event.path.to_string_lossy();
        let mut fields = payload.split('|');
        let thread_set_sha256 = validate_thread_process_digest(
            fields
                .next()
                .ok_or_else(|| "NeverGuard Thread & Process Integrity missing thread-set digest".to_string())?,
            "thread-set",
        )?;
        let thread_origin_set_sha256 = validate_thread_process_digest(
            fields
                .next()
                .ok_or_else(|| "NeverGuard Thread & Process Integrity missing origin-set digest".to_string())?,
            "origin-set",
        )?;
        let retired_thread_count = fields
            .next()
            .ok_or_else(|| "NeverGuard Thread & Process Integrity missing retired-thread count".to_string())?
            .parse::<u64>()
            .map_err(|_| "NeverGuard Thread & Process Integrity invalid retired-thread count".to_string())?;
        let suspicious_thread_count = fields
            .next()
            .ok_or_else(|| "NeverGuard Thread & Process Integrity missing suspicious-thread count".to_string())?
            .parse::<u32>()
            .map_err(|_| "NeverGuard Thread & Process Integrity invalid suspicious-thread count".to_string())?;
        let integrity_check_count = fields
            .next()
            .ok_or_else(|| "NeverGuard Thread & Process Integrity missing check count".to_string())?
            .parse::<u64>()
            .map_err(|_| "NeverGuard Thread & Process Integrity invalid check count".to_string())?;
        if fields.next().is_some() {
            return Err("NeverGuard Thread & Process Integrity malformed evidence payload".to_string());
        }
        if suspicious_thread_count != 0 {
            return Err(format!(
                "NeverGuard Thread & Process Integrity reported {suspicious_thread_count} suspicious threads"
            ));
        }
        Ok(crate::WindowsThreadProcessIntegrityReport {
            version: crate::NEVERGUARD_THREAD_PROCESS_INTEGRITY_VERSION,
            active: true,
            healthy: true,
            baseline_thread_count: event.size_of_image,
            current_thread_count: event.flags,
            new_thread_count: event.base_address,
            retired_thread_count,
            suspicious_thread_count,
            baseline_process_count: 0,
            current_process_count: 0,
            descendant_process_count: 0,
            descendant_process_peak: 0,
            process_transition_count: 0,
            integrity_check_count,
            violation_count: 0,
            job_bound: false,
            breakaway_allowed: true,
            thread_set_sha256,
            thread_origin_set_sha256,
            process_tree_sha256: String::new(),
            last_violation: String::new(),
        })
    }

    fn debug_instrumentation_report_from_event(
        event: &ParsedEvent,
    ) -> Result<crate::WindowsDebugInstrumentationReport, String> {
        let state_sha256 = event.path.to_string_lossy().to_string();
        if state_sha256.len() != 64 || !state_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("NeverGuard Debug & Instrumentation Guard invalid state digest".to_string());
        }
        let debugger_present = event.flags & 0x01 != 0;
        let remote_debugger_present = event.flags & 0x02 != 0;
        let debug_port_present = event.flags & 0x04 != 0;
        let debug_object_present = event.flags & 0x08 != 0;
        let debug_flags_no_debug_inherit = event.flags & 0x10 != 0;
        if debugger_present
            || remote_debugger_present
            || debug_port_present
            || debug_object_present
            || !debug_flags_no_debug_inherit
        {
            return Err(format!(
                "NeverGuard Debug & Instrumentation Guard detected debugger state: flags=0x{:X}",
                event.flags
            ));
        }
        Ok(crate::WindowsDebugInstrumentationReport {
            version: crate::NEVERGUARD_DEBUG_INSTRUMENTATION_VERSION,
            active: true,
            healthy: true,
            attach_mechanism_disabled: true,
            debugger_present,
            remote_debugger_present,
            debug_port_present,
            debug_object_present,
            debug_flags_no_debug_inherit,
            blocked_startup_instrumentation_count: 0,
            integrity_check_count: event.base_address,
            violation_count: 0,
            state_sha256: state_sha256.to_ascii_lowercase(),
            last_violation: String::new(),
        })
    }

    fn jvm_aware_report_from_event(
        event: &ParsedEvent,
    ) -> Result<crate::WindowsJvmAwareProtectionReport, String> {
        let payload = event.path.to_string_lossy();
        let mut fields = payload.split('|');
        let jvm_path_sha256 = validate_jvm_aware_digest(
            fields
                .next()
                .ok_or_else(|| "NeverGuard JVM-Aware Protection missing jvm path digest".to_string())?,
            "jvm-path",
        )?;
        let state_sha256 = validate_jvm_aware_digest(
            fields
                .next()
                .ok_or_else(|| "NeverGuard JVM-Aware Protection missing state digest".to_string())?,
            "state",
        )?;
        let integrity_check_count = fields
            .next()
            .ok_or_else(|| "NeverGuard JVM-Aware Protection missing integrity-check count".to_string())?
            .parse::<u64>()
            .map_err(|_| "NeverGuard JVM-Aware Protection invalid integrity-check count".to_string())?;
        let baseline_private_executable_region_count = fields
            .next()
            .ok_or_else(|| "NeverGuard JVM-Aware Protection missing baseline private executable-region count".to_string())?
            .parse::<u32>()
            .map_err(|_| "NeverGuard JVM-Aware Protection invalid baseline private executable-region count".to_string())?;
        let foreign_executable_transition_count = fields
            .next()
            .ok_or_else(|| "NeverGuard JVM-Aware Protection missing foreign transition count".to_string())?
            .parse::<u64>()
            .map_err(|_| "NeverGuard JVM-Aware Protection invalid foreign transition count".to_string())?;
        let unknown_executable_transition_count = fields
            .next()
            .ok_or_else(|| "NeverGuard JVM-Aware Protection missing unknown transition count".to_string())?
            .parse::<u64>()
            .map_err(|_| "NeverGuard JVM-Aware Protection invalid unknown transition count".to_string())?;
        if fields.next().is_some() {
            return Err("NeverGuard JVM-Aware Protection malformed evidence payload".to_string());
        }
        let java_major = event.flags;
        let certified_major = crate::NEVERGUARD_CERTIFIED_JAVA_MAJORS.contains(&java_major);
        if !certified_major {
            return Err(format!(
                "NeverGuard JVM-Aware Protection reported unsupported Java major {java_major}"
            ));
        }
        if event.size_of_image == 0 {
            return Err("NeverGuard JVM-Aware Protection reported zero jvm.dll image size".to_string());
        }
        if foreign_executable_transition_count != 0 || unknown_executable_transition_count != 0 {
            return Err(format!(
                "NeverGuard JVM-Aware Protection reported untrusted executable transitions: foreign={foreign_executable_transition_count}, unknown={unknown_executable_transition_count}"
            ));
        }
        Ok(crate::WindowsJvmAwareProtectionReport {
            version: crate::NEVERGUARD_JVM_AWARE_PROTECTION_VERSION,
            active: true,
            healthy: true,
            java_major,
            certified_major,
            jvm_module_size: event.size_of_image,
            baseline_private_executable_region_count,
            jit_transition_count: event.base_address,
            foreign_executable_transition_count,
            unknown_executable_transition_count,
            integrity_check_count,
            violation_count: 0,
            jvm_path_sha256,
            state_sha256,
            last_violation: String::new(),
        })
    }

    fn validate_jvm_aware_digest(value: &str, label: &str) -> Result<String, String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "NeverGuard JVM-Aware Protection invalid {label} digest"
            ));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn validate_thread_process_digest(value: &str, label: &str) -> Result<String, String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "NeverGuard Thread & Process Integrity invalid {label} digest"
            ));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn validate_memory_digest(value: &str, label: &str) -> Result<String, String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("NeverGuard Memory Integrity invalid {label} digest"));
        }
        Ok(value.to_ascii_lowercase())
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

    fn advance_continuous_event_chain(previous: [u8; 32], packet: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"NeverLauncher Continuous Guard sensor-event-chain v1\0");
        digest.update(previous);
        digest.update((packet.len() as u32).to_le_bytes());
        digest.update(packet);
        let output = digest.finalize();
        let mut next = [0u8; 32];
        next.copy_from_slice(&output);
        next
    }

    fn continuous_digest_from_event(event: &ParsedEvent) -> Result<String, String> {
        let digest = event.path.to_string_lossy().to_string();
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Continuous Guard received invalid event-chain digest".to_string());
        }
        Ok(digest.to_ascii_lowercase())
    }

    async fn write_continuous_guard_ack(
        server: &mut NamedPipeServer,
        secret: &[u8; 32],
        pid: u32,
        guard_sequence: u64,
        sensor_sequence: u64,
        event_chain: [u8; 32],
    ) -> Result<(), String> {
        let mut packet = [0u8; CONTINUOUS_GUARD_ACK_PACKET_LEN];
        packet[..8].copy_from_slice(CONTINUOUS_GUARD_ACK_MAGIC);
        packet[8..12].copy_from_slice(&CONTINUOUS_GUARD_VERSION.to_le_bytes());
        packet[12..16].copy_from_slice(&pid.to_le_bytes());
        packet[16..24].copy_from_slice(&guard_sequence.to_le_bytes());
        packet[24..32].copy_from_slice(&sensor_sequence.to_le_bytes());
        packet[32..64].copy_from_slice(&event_chain);
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|_| "Continuous Guard ACK HMAC initialization failed".to_string())?;
        mac.update(CONTINUOUS_GUARD_ACK_DOMAIN);
        mac.update(&packet[..CONTINUOUS_GUARD_ACK_PREFIX_LEN]);
        packet[CONTINUOUS_GUARD_ACK_PREFIX_LEN..]
            .copy_from_slice(&mac.finalize().into_bytes());
        server
            .write_all(&packet)
            .await
            .map_err(|err| format!("Continuous Guard ACK write failed: {err}"))?;
        server
            .flush()
            .await
            .map_err(|err| format!("Continuous Guard ACK flush failed: {err}"))?;
        packet.zeroize();
        Ok(())
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
            if reason.contains("Hook Engine") {
                report.hook_engine.active = false;
                report.hook_engine.healthy = false;
                report.hook_engine.violation_count = report.hook_engine.violation_count.saturating_add(1);
                report.hook_engine.last_violation = reason.to_string();
            }
            if reason.contains("Memory Integrity") {
                report.memory_integrity.active = false;
                report.memory_integrity.healthy = false;
                report.memory_integrity.violation_count = report.memory_integrity.violation_count.saturating_add(1);
                report.memory_integrity.last_violation = reason.to_string();
            }
            if reason.contains("Thread & Process Integrity") {
                report.thread_process_integrity.active = false;
                report.thread_process_integrity.healthy = false;
                report.thread_process_integrity.violation_count = report
                    .thread_process_integrity
                    .violation_count
                    .saturating_add(1);
                report.thread_process_integrity.last_violation = reason.to_string();
            }
            if reason.contains("Debug & Instrumentation Guard") {
                report.debug_instrumentation.active = false;
                report.debug_instrumentation.healthy = false;
                report.debug_instrumentation.violation_count = report
                    .debug_instrumentation
                    .violation_count
                    .saturating_add(1);
                report.debug_instrumentation.last_violation = reason.to_string();
            }
            if reason.contains("JVM-Aware Protection") {
                report.jvm_aware.active = false;
                report.jvm_aware.healthy = false;
                report.jvm_aware.violation_count = report.jvm_aware.violation_count.saturating_add(1);
                report.jvm_aware.last_violation = reason.to_string();
            }
            report.continuous_guard.active = false;
            report.continuous_guard.healthy = false;
            report.continuous_guard.violation_count = report
                .continuous_guard
                .violation_count
                .saturating_add(1);
            report.continuous_guard.last_violation = reason.to_string();
        });
        terminate_runtime(pid);
    }

    fn mark_stopped(state: &Arc<Mutex<WindowsModuleGuardReport>>) {
        update_counter(state, |report| {
            report.active = false;
            report.hook_engine.active = false;
            report.memory_integrity.active = false;
            report.thread_process_integrity.active = false;
            report.debug_instrumentation.active = false;
            report.jvm_aware.active = false;
            report.continuous_guard.active = false;
        });
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
