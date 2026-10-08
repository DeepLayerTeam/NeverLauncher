#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_void, OsString},
    mem::size_of,
    os::windows::ffi::OsStringExt,
    sync::Mutex,
};

const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const THREAD_QUERY_SET_WIN32_START_ADDRESS: i32 = 9;
const STILL_ACTIVE: u32 = 259;
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_IMAGE: u32 = 0x0100_0000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const MAX_MODULE_PATH: usize = 32768;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct ThreadEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
    fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(access: u32, inherit_handle: i32, thread_id: u32) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetExitCodeThread(thread: *mut c_void, exit_code: *mut u32) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn VirtualQuery(
        address: *const c_void,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
    fn GetModuleHandleExW(
        flags: u32,
        name_or_address: *const u16,
        module: *mut *mut c_void,
    ) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationThread(
        thread_handle: *mut c_void,
        thread_information_class: i32,
        thread_information: *mut c_void,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[derive(Clone, Debug)]
pub struct ThreadIntegritySnapshot {
    pub active: bool,
    pub healthy: bool,
    pub baseline_threads: u32,
    pub current_threads: u32,
    pub new_thread_count: u64,
    pub retired_thread_count: u64,
    pub suspicious_thread_count: u32,
    pub integrity_check_count: u64,
    pub thread_set_sha256: String,
    pub origin_set_sha256: String,
}

#[derive(Clone, Debug)]
struct ThreadRecord {
    thread_id: u32,
    start_address: usize,
    allocation_base: usize,
    module_path: String,
}

struct ThreadIntegrityState {
    active: bool,
    healthy: bool,
    baseline_threads: u32,
    current: HashMap<u32, ThreadRecord>,
    new_thread_count: u64,
    retired_thread_count: u64,
    integrity_check_count: u64,
}

static THREAD_STATE: Mutex<Option<ThreadIntegrityState>> = Mutex::new(None);

struct OwnedHandle(*mut c_void);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct PinnedModule(*mut c_void);

impl Drop for PinnedModule {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

pub fn initialize() -> Result<ThreadIntegritySnapshot, String> {
    let current = enumerate_threads()?;
    if current.is_empty() {
        return Err("NeverGuard Thread Integrity found no JVM threads at startup".to_string());
    }
    let baseline_threads = current.len().min(u32::MAX as usize) as u32;
    let state = ThreadIntegrityState {
        active: true,
        healthy: true,
        baseline_threads,
        current,
        new_thread_count: 0,
        retired_thread_count: 0,
        integrity_check_count: 1,
    };
    let snapshot = snapshot_for_state(&state);
    *THREAD_STATE
        .lock()
        .map_err(|_| "NeverGuard Thread Integrity state lock poisoned".to_string())? = Some(state);
    Ok(snapshot)
}

pub fn reconcile_and_verify() -> Result<ThreadIntegritySnapshot, String> {
    let observed = enumerate_threads()?;
    let mut guard = THREAD_STATE
        .lock()
        .map_err(|_| "NeverGuard Thread Integrity state lock poisoned".to_string())?;
    let state = guard
        .as_mut()
        .ok_or_else(|| "NeverGuard Thread Integrity is not initialized".to_string())?;
    if !state.active || !state.healthy {
        return Err("NeverGuard Thread Integrity is not active/healthy".to_string());
    }

    for (thread_id, record) in &observed {
        match state.current.get(thread_id) {
            Some(previous)
                if previous.start_address == record.start_address
                    && previous.allocation_base == record.allocation_base
                    && previous.module_path.eq_ignore_ascii_case(&record.module_path) => {}
            Some(_) => {
                // TID повторное использование является возможный после поток выход. вновь наблюдаемый
                // запуск адрес имеет уже пройден исполняемый-образ валидация.
                state.retired_thread_count = state.retired_thread_count.saturating_add(1);
                state.new_thread_count = state.new_thread_count.saturating_add(1);
            }
            None => {
                state.new_thread_count = state.new_thread_count.saturating_add(1);
            }
        }
    }
    for thread_id in state.current.keys() {
        if !observed.contains_key(thread_id) {
            state.retired_thread_count = state.retired_thread_count.saturating_add(1);
        }
    }
    state.current = observed;
    state.integrity_check_count = state.integrity_check_count.saturating_add(1);
    Ok(snapshot_for_state(state))
}

pub fn shutdown() {
    if let Ok(mut guard) = THREAD_STATE.lock() {
        *guard = None;
    }
}

fn enumerate_threads() -> Result<HashMap<u32, ThreadRecord>, String> {
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Err(format!(
            "NeverGuard Поток Целостность поток снимок ошибка: {}",
            std::io::Error::last_os_error()
        ));
    }
    let snapshot = OwnedHandle(snapshot);
    let mut entry = ThreadEntry32 {
        dw_size: size_of::<ThreadEntry32>() as u32,
        ..ThreadEntry32::default()
    };
    let mut has_entry = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
    if !has_entry {
        return Err(format!(
            "NeverGuard Поток Целостность не может enumerate потоки: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut result = HashMap::new();
    while has_entry {
        if entry.owner_process_id == pid {
            if let Some(record) = inspect_thread(entry.thread_id)? {
                result.insert(entry.thread_id, record);
            }
        }
        has_entry = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
    }
    if result.is_empty() {
        return Err("NeverGuard Thread Integrity observed zero live JVM threads".to_string());
    }
    Ok(result)
}

fn inspect_thread(thread_id: u32) -> Result<Option<ThreadRecord>, String> {
    let mut thread = unsafe {
        OpenThread(
            THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            thread_id,
        )
    };
    if thread.is_null() {
        // поток может legitimately выход между ToolHelp снимок и OpenThread.
        // Повторить с ограничение right потому что некоторые Windows собирает отклонять combined mask.
        thread = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, thread_id) };
        if thread.is_null() {
            return Ok(None);
        }
    }
    let thread = OwnedHandle(thread);

    let mut start_address: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        NtQueryInformationThread(
            thread.0,
            THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &mut start_address as *mut *mut c_void as *mut c_void,
            size_of::<*mut c_void>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 || start_address.is_null() {
        // ToolHelp снимок является inherently racy с обычный JVM поток teardown.
        // поток тот имеет уже выход является не целостность нарушение.
        let mut exit_code = 0u32;
        let exit_known = unsafe { GetExitCodeThread(thread.0, &mut exit_code) } != 0;
        if exit_known && exit_code != STILL_ACTIVE {
            return Ok(None);
        }
        return Err(format!(
            "NeverGuard Поток Целостность не может query Win32 запуск адрес для актуальный TID {thread_id}: NTSTATUS=0x{:08X}",
            status as u32
        ));
    }

    let mut memory = MemoryBasicInformation::default();
    let queried = unsafe {
        VirtualQuery(
            start_address as *const c_void,
            &mut memory,
            size_of::<MemoryBasicInformation>(),
        )
    };
    if queried == 0 {
        return Err(format!(
            "NeverGuard Поток Целостность не может query запуск память для TID {thread_id}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if memory.state != MEM_COMMIT
        || !is_executable(memory.protect)
        || memory.protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
    {
        return Err(format!(
            "NeverGuard Поток Целостность suspicious среда выполнения переход: TID {thread_id} запуск 0x{:X} является не committed исполняемый память (состояние=0x{:X}, защищать=0x{:X})",
            start_address as usize, memory.state, memory.protect
        ));
    }
    if memory.kind != MEM_IMAGE {
        return Err(format!(
            "NeverGuard Поток Целостность suspicious среда выполнения переход: TID {thread_id} запускает из non-образ исполняемый память в 0x{:X} (type=0x{:X})",
            start_address as usize, memory.kind
        ));
    }

    let allocation_base = memory.allocation_base as usize;
    let module_path = module_path_for_address(start_address as usize)?;
    Ok(Some(ThreadRecord {
        thread_id,
        start_address: start_address as usize,
        allocation_base,
        module_path,
    }))
}

fn module_path_for_address(address: usize) -> Result<String, String> {
    let mut module = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            address as *const u16,
            &mut module,
        )
    };
    if ok == 0 || module.is_null() {
        return Err(format!(
            "NeverGuard Поток Целостность не может разрешать запуск модуль для 0x{address:X}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let module = PinnedModule(module);
    let mut buffer = vec![0u16; MAX_MODULE_PATH];
    let len = unsafe {
        GetModuleFileNameW(
            module.0,
            buffer.as_mut_ptr(),
            buffer.len().min(u32::MAX as usize) as u32,
        )
    } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(format!(
            "NeverGuard Поток Целостность не может obtain запуск модуль путь для 0x{address:X}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let value = OsString::from_wide(&buffer[..len])
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if value.is_empty() {
        return Err("NeverGuard Thread Integrity resolved an empty start module path".to_string());
    }
    Ok(value)
}

fn snapshot_for_state(state: &ThreadIntegrityState) -> ThreadIntegritySnapshot {
    ThreadIntegritySnapshot {
        active: state.active,
        healthy: state.healthy,
        baseline_threads: state.baseline_threads,
        current_threads: state.current.len().min(u32::MAX as usize) as u32,
        new_thread_count: state.new_thread_count,
        retired_thread_count: state.retired_thread_count,
        suspicious_thread_count: 0,
        integrity_check_count: state.integrity_check_count,
        thread_set_sha256: thread_set_sha256(&state.current),
        origin_set_sha256: origin_set_sha256(&state.current),
    }
}

fn thread_set_sha256(threads: &HashMap<u32, ThreadRecord>) -> String {
    let mut records = threads
        .values()
        .map(|thread| {
            format!(
                "{}\0{:016x}\0{:016x}\0{}",
                thread.thread_id, thread.start_address, thread.allocation_base, thread.module_path
            )
        })
        .collect::<Vec<_>>();
    records.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"NeverLauncher Thread Integrity thread-set v1\0");
    for record in records {
        digest.update((record.len() as u32).to_le_bytes());
        digest.update(record.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn origin_set_sha256(threads: &HashMap<u32, ThreadRecord>) -> String {
    let mut origins = threads
        .values()
        .map(|thread| thread.module_path.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    origins.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"NeverLauncher Thread Integrity origin-set v1\0");
    for origin in origins {
        digest.update((origin.len() as u32).to_le_bytes());
        digest.update(origin.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn is_executable(protect: u32) -> bool {
    matches!(
        protect & 0xFF,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}
