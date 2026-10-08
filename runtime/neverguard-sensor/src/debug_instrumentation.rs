#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::{ffi::c_void, mem::size_of, sync::Mutex};

const PROCESS_DEBUG_PORT: i32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: i32 = 30;
const PROCESS_DEBUG_FLAGS: i32 = 31;
const STATUS_PORT_NOT_SET: i32 = 0xC000_0353u32 as i32;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(process: *mut c_void, present: *mut i32) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process: *mut c_void,
        information_class: i32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[derive(Clone, Debug)]
pub struct DebugInstrumentationSnapshot {
    pub active: bool,
    pub healthy: bool,
    pub debugger_present: bool,
    pub remote_debugger_present: bool,
    pub debug_port_present: bool,
    pub debug_object_present: bool,
    pub debug_flags_no_debug_inherit: bool,
    pub integrity_check_count: u64,
    pub state_sha256: String,
}

#[derive(Clone, Debug)]
struct DebugInstrumentationState {
    active: bool,
    healthy: bool,
    integrity_check_count: u64,
    last: DebugIndicators,
}

#[derive(Clone, Copy, Debug, Default)]
struct DebugIndicators {
    debugger_present: bool,
    remote_debugger_present: bool,
    debug_port_present: bool,
    debug_object_present: bool,
    debug_flags_no_debug_inherit: bool,
}

static DEBUG_STATE: Mutex<Option<DebugInstrumentationState>> = Mutex::new(None);

pub fn initialize() -> Result<DebugInstrumentationSnapshot, String> {
    let indicators = query_debug_indicators()?;
    reject_debug_state(indicators)?;
    let state = DebugInstrumentationState {
        active: true,
        healthy: true,
        integrity_check_count: 1,
        last: indicators,
    };
    let snapshot = snapshot_for_state(&state);
    *DEBUG_STATE
        .lock()
        .map_err(|_| "NeverGuard Debug & Instrumentation Guard state lock poisoned".to_string())? =
        Some(state);
    Ok(snapshot)
}

pub fn reconcile_and_verify() -> Result<DebugInstrumentationSnapshot, String> {
    let indicators = query_debug_indicators()?;
    reject_debug_state(indicators)?;
    let mut guard = DEBUG_STATE
        .lock()
        .map_err(|_| "NeverGuard Debug & Instrumentation Guard state lock poisoned".to_string())?;
    let state = guard
        .as_mut()
        .ok_or_else(|| "NeverGuard Debug & Instrumentation Guard is not initialized".to_string())?;
    if !state.active || !state.healthy {
        return Err("NeverGuard Debug & Instrumentation Guard is not active/healthy".to_string());
    }
    state.last = indicators;
    state.integrity_check_count = state.integrity_check_count.saturating_add(1);
    Ok(snapshot_for_state(state))
}

pub fn shutdown() {
    if let Ok(mut guard) = DEBUG_STATE.lock() {
        *guard = None;
    }
}

fn query_debug_indicators() -> Result<DebugIndicators, String> {
    // SAFETY: all APIs operate on the current process pseudo handle and fixed-size
    // caller-owned output buffers. No foreign process memory is read or modified.
    let process = unsafe { GetCurrentProcess() };
    if process.is_null() {
        return Err("NeverGuard Debug & Instrumentation Guard cannot obtain current process handle".to_string());
    }

    let debugger_present = unsafe { IsDebuggerPresent() } != 0;

    let mut remote_present = 0i32;
    let remote_ok = unsafe { CheckRemoteDebuggerPresent(process, &mut remote_present) } != 0;
    if !remote_ok {
        return Err(format!(
            "NeverGuard Debug & Instrumentation Guard CheckRemoteDebuggerPresent failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut debug_port = 0usize;
    query_process_information(
        process,
        PROCESS_DEBUG_PORT,
        (&mut debug_port as *mut usize).cast(),
        size_of::<usize>() as u32,
        "ProcessDebugPort",
    )?;

    let mut debug_object: *mut c_void = std::ptr::null_mut();
    query_process_information(
        process,
        PROCESS_DEBUG_OBJECT_HANDLE,
        (&mut debug_object as *mut *mut c_void).cast(),
        size_of::<*mut c_void>() as u32,
        "ProcessDebugObjectHandle",
    )?;

    let mut debug_flags = 0u32;
    query_process_information(
        process,
        PROCESS_DEBUG_FLAGS,
        (&mut debug_flags as *mut u32).cast(),
        size_of::<u32>() as u32,
        "ProcessDebugFlags",
    )?;

    Ok(DebugIndicators {
        debugger_present,
        remote_debugger_present: remote_present != 0,
        debug_port_present: debug_port != 0,
        debug_object_present: !debug_object.is_null(),
        // ProcessDebugFlags returns the inverse of the NoDebugInherit state.
        // A healthy non-debugged process reports a nonzero value.
        debug_flags_no_debug_inherit: debug_flags != 0,
    })
}

fn query_process_information(
    process: *mut c_void,
    class: i32,
    output: *mut c_void,
    output_len: u32,
    label: &str,
) -> Result<(), String> {
    let mut returned = 0u32;
    // SAFETY: NtQueryInformationProcess only writes to the supplied fixed-size
    // buffer for the requested debug information class.
    let status = unsafe {
        NtQueryInformationProcess(process, class, output, output_len, &mut returned)
    };
    if status < 0 {
        if class == PROCESS_DEBUG_OBJECT_HANDLE && status == STATUS_PORT_NOT_SET {
            return Ok(());
        }
        return Err(format!(
            "NeverGuard Debug & Instrumentation Guard {label} query failed: NTSTATUS=0x{:08X}",
            status as u32
        ));
    }
    if returned != 0 && returned > output_len {
        return Err(format!(
            "NeverGuard Debug & Instrumentation Guard {label} returned oversized state"
        ));
    }
    Ok(())
}

fn reject_debug_state(indicators: DebugIndicators) -> Result<(), String> {
    if indicators.debugger_present
        || indicators.remote_debugger_present
        || indicators.debug_port_present
        || indicators.debug_object_present
        || !indicators.debug_flags_no_debug_inherit
    {
        return Err(format!(
            "NeverGuard Debug & Instrumentation Guard detected debugger boundary: local={}, remote={}, port={}, object={}, noDebugInherit={}",
            indicators.debugger_present,
            indicators.remote_debugger_present,
            indicators.debug_port_present,
            indicators.debug_object_present,
            indicators.debug_flags_no_debug_inherit
        ));
    }
    Ok(())
}

fn snapshot_for_state(state: &DebugInstrumentationState) -> DebugInstrumentationSnapshot {
    let mut digest = Sha256::new();
    digest.update(b"NeverLauncher Debug & Instrumentation Guard state v1\0");
    digest.update([u8::from(state.last.debugger_present)]);
    digest.update([u8::from(state.last.remote_debugger_present)]);
    digest.update([u8::from(state.last.debug_port_present)]);
    digest.update([u8::from(state.last.debug_object_present)]);
    digest.update([u8::from(state.last.debug_flags_no_debug_inherit)]);
    digest.update(state.integrity_check_count.to_le_bytes());
    DebugInstrumentationSnapshot {
        active: state.active,
        healthy: state.healthy,
        debugger_present: state.last.debugger_present,
        remote_debugger_present: state.last.remote_debugger_present,
        debug_port_present: state.last.debug_port_present,
        debug_object_present: state.last.debug_object_present,
        debug_flags_no_debug_inherit: state.last.debug_flags_no_debug_inherit,
        integrity_check_count: state.integrity_check_count,
        state_sha256: hex::encode(digest.finalize()),
    }
}
