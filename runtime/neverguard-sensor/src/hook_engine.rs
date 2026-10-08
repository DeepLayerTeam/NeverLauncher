#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    ffi::{c_char, c_void},
    mem::size_of,
    sync::{
        atomic::{AtomicPtr, AtomicU64, Ordering},
        Mutex,
    },
};

const PAGE_READWRITE: u32 = 0x04;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const MAX_IMPORT_NAME: usize = 256;
const MAX_MODULE_PATH: usize = 32768;

const HOOK_LOAD_LIBRARY_A: u32 = 1;
const HOOK_LOAD_LIBRARY_W: u32 = 2;
const HOOK_LOAD_LIBRARY_EX_A: u32 = 3;
const HOOK_LOAD_LIBRARY_EX_W: u32 = 4;
const HOOK_VIRTUAL_ALLOC: u32 = 5;
const HOOK_VIRTUAL_PROTECT: u32 = 6;

static HOOK_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
static ORIGINAL_LOAD_LIBRARY_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_LOAD_LIBRARY_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_LOAD_LIBRARY_EX_A: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_LOAD_LIBRARY_EX_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_VIRTUAL_ALLOC: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_VIRTUAL_PROTECT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[repr(C)]
#[allow(dead_code)]
struct ModuleInfo {
    base_of_dll: *mut c_void,
    size_of_image: u32,
    entry_point: *mut c_void,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn K32EnumProcessModules(
        process: *mut c_void,
        modules: *mut *mut c_void,
        cb: u32,
        needed: *mut u32,
    ) -> i32;
    fn K32GetModuleInformation(
        process: *mut c_void,
        module: *mut c_void,
        info: *mut ModuleInfo,
        cb: u32,
    ) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
    fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetModuleHandleExW(flags: u32, name_or_address: *const u16, module: *mut *mut c_void) -> i32;
    fn FreeLibrary(module: *mut c_void) -> i32;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
}

#[derive(Clone, Debug)]
pub struct HookEngineSnapshot {
    pub active: bool,
    pub healthy: bool,
    pub hooked_modules: u32,
    pub hooked_slots: u32,
    pub call_count: u64,
    pub hook_set_sha256: String,
}

#[derive(Clone)]
struct ProcessModule {
    base: usize,
    size: usize,
    path: String,
}

#[derive(Clone)]
struct HookRecord {
    module_base: usize,
    module_path: String,
    slot: usize,
    slot_rva: usize,
    original: usize,
    replacement: usize,
    hook_id: u32,
    hook_name: &'static str,
}

struct HookEngineState {
    active: bool,
    healthy: bool,
    seen_modules: Vec<usize>,
    records: Vec<HookRecord>,
}

impl HookEngineState {
    const fn new() -> Self {
        Self {
            active: false,
            healthy: false,
            seen_modules: Vec::new(),
            records: Vec::new(),
        }
    }
}

static ENGINE_STATE: Mutex<HookEngineState> = Mutex::new(HookEngineState::new());

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

fn pin_module(base: usize) -> Result<PinnedModule, String> {
    let mut module = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            base as *const u16,
            &mut module,
        )
    };
    if ok == 0 || module.is_null() {
        return Err(format!(
            "NeverGuard Хук Движок не может сохранять модуль в 0x{base:X}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PinnedModule(module))
}

#[derive(Clone, Copy)]
struct HookSpec {
    id: u32,
    name: &'static str,
    c_name: &'static [u8],
    replacement: usize,
    canonical: &'static AtomicPtr<c_void>,
}

fn hook_specs() -> [HookSpec; 6] {
    [
        HookSpec {
            id: HOOK_LOAD_LIBRARY_A,
            name: "LoadLibraryA",
            c_name: b"LoadLibraryA\0",
            replacement: hook_load_library_a as usize,
            canonical: &ORIGINAL_LOAD_LIBRARY_A,
        },
        HookSpec {
            id: HOOK_LOAD_LIBRARY_W,
            name: "LoadLibraryW",
            c_name: b"LoadLibraryW\0",
            replacement: hook_load_library_w as usize,
            canonical: &ORIGINAL_LOAD_LIBRARY_W,
        },
        HookSpec {
            id: HOOK_LOAD_LIBRARY_EX_A,
            name: "LoadLibraryExA",
            c_name: b"LoadLibraryExA\0",
            replacement: hook_load_library_ex_a as usize,
            canonical: &ORIGINAL_LOAD_LIBRARY_EX_A,
        },
        HookSpec {
            id: HOOK_LOAD_LIBRARY_EX_W,
            name: "LoadLibraryExW",
            c_name: b"LoadLibraryExW\0",
            replacement: hook_load_library_ex_w as usize,
            canonical: &ORIGINAL_LOAD_LIBRARY_EX_W,
        },
        HookSpec {
            id: HOOK_VIRTUAL_ALLOC,
            name: "VirtualAlloc",
            c_name: b"VirtualAlloc\0",
            replacement: hook_virtual_alloc as usize,
            canonical: &ORIGINAL_VIRTUAL_ALLOC,
        },
        HookSpec {
            id: HOOK_VIRTUAL_PROTECT,
            name: "VirtualProtect",
            c_name: b"VirtualProtect\0",
            replacement: hook_virtual_protect as usize,
            canonical: &ORIGINAL_VIRTUAL_PROTECT,
        },
    ]
}

pub fn initialize() -> Result<HookEngineSnapshot, String> {
    resolve_canonical_targets()?;
    let mut state = ENGINE_STATE
        .lock()
        .map_err(|_| "NeverGuard Hook Engine state lock poisoned".to_string())?;
    if state.active {
        return Err("NeverGuard Hook Engine already active".to_string());
    }
    state.records.clear();
    state.seen_modules.clear();
    HOOK_CALL_COUNT.store(0, Ordering::Release);
    reconcile_locked(&mut state)?;
    if state.records.is_empty() {
        restore_records(&mut state.records);
        return Err("NeverGuard Hook Engine found no eligible JVM/native IAT targets".to_string());
    }
    state.active = true;
    state.healthy = true;
    verify_locked(&mut state)?;
    Ok(snapshot_locked(&state))
}

pub fn reconcile_and_verify() -> Result<HookEngineSnapshot, String> {
    let mut state = ENGINE_STATE
        .lock()
        .map_err(|_| "NeverGuard Hook Engine state lock poisoned".to_string())?;
    if !state.active || !state.healthy {
        return Err("NeverGuard Hook Engine is not active/healthy".to_string());
    }
    reconcile_locked(&mut state)?;
    verify_locked(&mut state)?;
    Ok(snapshot_locked(&state))
}

pub fn shutdown_restore() -> Result<(), String> {
    let mut state = ENGINE_STATE
        .lock()
        .map_err(|_| "NeverGuard Hook Engine state lock poisoned".to_string())?;
    let mut errors = Vec::new();
    for record in state.records.iter().rev() {
        let Ok(_module_pin) = pin_module(record.module_base) else {
            continue;
        };
        let current = unsafe { std::ptr::read_volatile(record.slot as *const usize) };
        if current == record.replacement {
            if let Err(err) = patch_pointer(record.slot, record.original) {
                errors.push(err);
            }
        }
    }
    state.records.clear();
    state.seen_modules.clear();
    state.active = false;
    state.healthy = errors.is_empty();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn resolve_canonical_targets() -> Result<(), String> {
    let kernel32 = wide_null("kernel32.dll");
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    if module.is_null() {
        return Err("NeverGuard Hook Engine cannot resolve kernel32.dll".to_string());
    }
    for spec in hook_specs() {
        let address = unsafe { GetProcAddress(module, spec.c_name.as_ptr().cast()) };
        if address.is_null() {
            return Err(format!("NeverGuard Хук Движок не может разрешать {}", spec.name));
        }
        spec.canonical.store(address, Ordering::Release);
    }
    Ok(())
}

fn reconcile_locked(state: &mut HookEngineState) -> Result<(), String> {
    let modules = enumerate_modules()?;
    let current_bases = modules.iter().map(|module| module.base).collect::<HashSet<_>>();
    state.records.retain(|record| current_bases.contains(&record.module_base));
    state.seen_modules.retain(|base| current_bases.contains(base));

    for module in modules {
        if state.seen_modules.contains(&module.base) || should_skip_module(&module) {
            continue;
        }
        let Ok(_module_pin) = pin_module(module.base) else {
            // обычный выгрузка может гонка модуль снимок. Модуль Защита владеет
            // жизненный цикл принудительное применение; по-прежнему-загружен модуль является retried на 
            // следующий согласование сигнал состояния.
            continue;
        };
        let records = collect_hook_candidates(&module)?;
        if !records.is_empty() {
            let mut applied = Vec::with_capacity(records.len());
            for record in records {
                let current = unsafe { std::ptr::read_volatile(record.slot as *const usize) };
                if current != record.original && current != record.replacement {
                    restore_records(&mut applied);
                    state.healthy = false;
                    return Err(format!(
                        "NeverGuard Хук Движок обнаруживать pre-существующий IAT цель расхождение для {} в {}",
                        record.hook_name, record.module_path
                    ));
                }
                if current != record.replacement {
                    if let Err(err) = patch_pointer(record.slot, record.replacement) {
                        // patch_pointer может завершаться ошибкой после slot запись (для пример
                        // пока восстановление страница защита). Восстановление этот slot и
                        // все earlier записывает до возвращать ошибка.
                        let _ = patch_pointer(record.slot, current);
                        restore_records(&mut applied);
                        state.healthy = false;
                        return Err(err);
                    }
                }
                applied.push(record);
            }
            state.records.extend(applied);
        }
        state.seen_modules.push(module.base);
    }
    Ok(())
}

fn verify_locked(state: &mut HookEngineState) -> Result<(), String> {
    for record in &state.records {
        let Ok(_module_pin) = pin_module(record.module_base) else {
            continue;
        };
        let current = unsafe { std::ptr::read_volatile(record.slot as *const usize) };
        if current != record.replacement {
            state.healthy = false;
            return Err(format!(
                "NeverGuard Хук Движок IAT целостность нарушение для {} в {}",
                record.hook_name, record.module_path
            ));
        }
    }
    Ok(())
}

fn snapshot_locked(state: &HookEngineState) -> HookEngineSnapshot {
    let modules = state
        .records
        .iter()
        .map(|record| record.module_base)
        .collect::<HashSet<_>>()
        .len();
    HookEngineSnapshot {
        active: state.active,
        healthy: state.healthy,
        hooked_modules: modules.min(u32::MAX as usize) as u32,
        hooked_slots: state.records.len().min(u32::MAX as usize) as u32,
        call_count: HOOK_CALL_COUNT.load(Ordering::Acquire),
        hook_set_sha256: hook_set_digest(&state.records),
    }
}

fn hook_set_digest(records: &[HookRecord]) -> String {
    let mut rows = records
        .iter()
        .map(|record| {
            format!(
                "{}\0{}\0{}\0{:x}",
                record.module_path.to_ascii_lowercase(),
                record.hook_id,
                record.hook_name,
                record.slot_rva
            )
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"NeverGuard Aggressive Hook Engine I hook-set v1\0");
    for row in rows {
        digest.update((row.len() as u32).to_le_bytes());
        digest.update(row.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn collect_hook_candidates(module: &ProcessModule) -> Result<Vec<HookRecord>, String> {
    let base = module.base;
    let size = module.size;
    let dos_signature = read_u16(base, size, 0)?;
    if dos_signature != IMAGE_DOS_SIGNATURE {
        return Err(format!("NeverGuard Хук Движок недопустимый DOS header в {}", module.path));
    }
    let nt_offset = read_u32(base, size, 0x3C)? as usize;
    if read_u32(base, size, nt_offset)? != IMAGE_NT_SIGNATURE {
        return Err(format!("NeverGuard Хук Движок недопустимый PE header в {}", module.path));
    }
    let optional = nt_offset
        .checked_add(24)
        .ok_or_else(|| "NeverGuard Hook Engine PE optional-header overflow".to_string())?;
    let magic = read_u16(base, size, optional)?;
    let (data_directory, pointer_size, ordinal_mask) = match magic {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => (optional + 112, 8usize, 0x8000_0000_0000_0000u64),
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => (optional + 96, 4usize, 0x8000_0000u64),
        _ => return Ok(Vec::new()),
    };
    if pointer_size != size_of::<usize>() {
        return Err(format!(
            "NeverGuard Хук Движок module/process архитектура несоответствие в {}",
            module.path
        ));
    }
    let import_entry = data_directory
        .checked_add(IMAGE_DIRECTORY_ENTRY_IMPORT * 8)
        .ok_or_else(|| "NeverGuard Hook Engine import-directory overflow".to_string())?;
    let import_rva = read_u32(base, size, import_entry)? as usize;
    let import_size = read_u32(base, size, import_entry + 4)? as usize;
    if import_rva == 0 || import_size == 0 {
        return Ok(Vec::new());
    }
    checked_range(size, import_rva, import_size.min(size.saturating_sub(import_rva)))?;

    let specs = hook_specs();
    let mut candidates = Vec::new();
    let mut descriptor_offset = import_rva;
    let descriptor_limit = import_rva.saturating_add(import_size).min(size);
    while descriptor_offset.saturating_add(20) <= descriptor_limit {
        let original_first_thunk = read_u32(base, size, descriptor_offset)? as usize;
        let name_rva = read_u32(base, size, descriptor_offset + 12)? as usize;
        let first_thunk = read_u32(base, size, descriptor_offset + 16)? as usize;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if original_first_thunk == 0 || name_rva == 0 || first_thunk == 0 {
            descriptor_offset += 20;
            continue;
        }
        let import_dll = read_ascii(base, size, name_rva, MAX_IMPORT_NAME)?;
        if !supported_import_dll(&import_dll) {
            descriptor_offset += 20;
            continue;
        }
        let mut import_dll_c = import_dll.as_bytes().to_vec();
        import_dll_c.push(0);
        let imported_module = unsafe { GetModuleHandleA(import_dll_c.as_ptr().cast()) };
        if imported_module.is_null() {
            descriptor_offset += 20;
            continue;
        }

        let mut index = 0usize;
        loop {
            let lookup_offset = original_first_thunk
                .checked_add(index.saturating_mul(pointer_size))
                .ok_or_else(|| "NeverGuard Hook Engine thunk overflow".to_string())?;
            let thunk = read_pointer_value(base, size, lookup_offset, pointer_size)?;
            if thunk == 0 {
                break;
            }
            if thunk & ordinal_mask == 0 {
                let name_offset = (thunk & !ordinal_mask) as usize;
                let function_name = read_ascii(base, size, name_offset + 2, MAX_IMPORT_NAME)?;
                if let Some(spec) = specs.iter().find(|spec| spec.name == function_name) {
                    let expected = unsafe { GetProcAddress(imported_module, spec.c_name.as_ptr().cast()) };
                    if expected.is_null() {
                        return Err(format!(
                            "NeverGuard Хук Движок не может разрешать импорт {} из {}",
                            spec.name, import_dll
                        ));
                    }
                    let slot_rva = first_thunk
                        .checked_add(index.saturating_mul(pointer_size))
                        .ok_or_else(|| "NeverGuard Hook Engine IAT slot overflow".to_string())?;
                    checked_range(size, slot_rva, pointer_size)?;
                    candidates.push(HookRecord {
                        module_base: module.base,
                        module_path: module.path.clone(),
                        slot: base + slot_rva,
                        slot_rva,
                        original: expected as usize,
                        replacement: spec.replacement,
                        hook_id: spec.id,
                        hook_name: spec.name,
                    });
                }
            }
            index = index.saturating_add(1);
            if index > 65_536 {
                return Err(format!("NeverGuard Хук Движок excessive импорт таблица в {}", module.path));
            }
        }
        descriptor_offset += 20;
    }
    Ok(candidates)
}

fn patch_pointer(slot: usize, value: usize) -> Result<(), String> {
    let mut old_protect = 0u32;
    let ok = unsafe {
        VirtualProtect(
            slot as *mut c_void,
            size_of::<usize>(),
            PAGE_READWRITE,
            &mut old_protect,
        )
    };
    if ok == 0 {
        return Err(format!(
            "NeverGuard Хук Движок VirtualProtect(IAT) ошибка: {}",
            std::io::Error::last_os_error()
        ));
    }
    unsafe {
        std::ptr::write_volatile(slot as *mut usize, value);
    }
    let mut ignored = 0u32;
    let restore_ok = unsafe {
        VirtualProtect(
            slot as *mut c_void,
            size_of::<usize>(),
            old_protect,
            &mut ignored,
        )
    };
    let flush_ok = unsafe {
        FlushInstructionCache(
            GetCurrentProcess(),
            slot as *const c_void,
            size_of::<usize>(),
        )
    };
    if restore_ok == 0 || flush_ok == 0 {
        return Err(format!(
            "NeverGuard Хук Движок ошибка к restore/flush IAT защита: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn restore_records(records: &mut Vec<HookRecord>) {
    for record in records.iter().rev() {
        let current = unsafe { std::ptr::read_volatile(record.slot as *const usize) };
        if current == record.replacement {
            let _ = patch_pointer(record.slot, record.original);
        }
    }
    records.clear();
}

fn enumerate_modules() -> Result<Vec<ProcessModule>, String> {
    let process = unsafe { GetCurrentProcess() };
    let mut capacity = 128usize;
    loop {
        let mut modules = vec![std::ptr::null_mut(); capacity];
        let mut needed = 0u32;
        let ok = unsafe {
            K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * size_of::<*mut c_void>()).min(u32::MAX as usize) as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(format!(
                "NeverGuard Хук Движок модуль enumeration ошибка: {}",
                std::io::Error::last_os_error()
            ));
        }
        let required = (needed as usize + size_of::<*mut c_void>() - 1) / size_of::<*mut c_void>();
        if required > modules.len() {
            capacity = required.saturating_add(32);
            continue;
        }
        modules.truncate(required);
        let mut result = Vec::with_capacity(modules.len());
        for module in modules {
            if module.is_null() {
                continue;
            }
            let mut info = ModuleInfo {
                base_of_dll: std::ptr::null_mut(),
                size_of_image: 0,
                entry_point: std::ptr::null_mut(),
            };
            if unsafe {
                K32GetModuleInformation(
                    process,
                    module,
                    &mut info,
                    size_of::<ModuleInfo>() as u32,
                )
            } == 0
                || info.base_of_dll.is_null()
                || info.size_of_image == 0
            {
                return Err("NeverGuard Hook Engine module information query failed".to_string());
            }
            let path = module_path(module)?;
            result.push(ProcessModule {
                base: info.base_of_dll as usize,
                size: info.size_of_image as usize,
                path,
            });
        }
        return Ok(result);
    }
}

fn module_path(module: *mut c_void) -> Result<String, String> {
    let mut buffer = vec![0u16; MAX_MODULE_PATH];
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(format!(
            "NeverGuard Хук Движок не может разрешать модуль путь: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn should_skip_module(module: &ProcessModule) -> bool {
    let path = normalize_path(&module.path);
    let system_root = env::var("SystemRoot")
        .or_else(|_| env::var("WINDIR"))
        .unwrap_or_else(|_| r"C:\Windows".to_string());
    let system_root = normalize_path(&system_root);
    if path == system_root || path.strip_prefix(&system_root).is_some_and(|suffix| suffix.starts_with('\\')) {
        return true;
    }
    let wrapper = hook_load_library_w as usize;
    wrapper >= module.base && wrapper < module.base.saturating_add(module.size)
}

fn normalize_path(path: &str) -> String {
    path.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
}

fn supported_import_dll(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "kernel32.dll"
        || lower == "kernelbase.dll"
        || lower.starts_with("api-ms-win-core-libraryloader-")
        || lower.starts_with("api-ms-win-core-memory-")
}

fn checked_range(size: usize, offset: usize, length: usize) -> Result<(), String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "NeverGuard Hook Engine PE range overflow".to_string())?;
    if offset > size || end > size {
        Err("NeverGuard Hook Engine PE range outside mapped image".to_string())
    } else {
        Ok(())
    }
}

fn read_u16(base: usize, size: usize, offset: usize) -> Result<u16, String> {
    checked_range(size, offset, 2)?;
    Ok(unsafe { std::ptr::read_unaligned((base + offset) as *const u16) })
}

fn read_u32(base: usize, size: usize, offset: usize) -> Result<u32, String> {
    checked_range(size, offset, 4)?;
    Ok(unsafe { std::ptr::read_unaligned((base + offset) as *const u32) })
}

fn read_pointer_value(base: usize, size: usize, offset: usize, pointer_size: usize) -> Result<u64, String> {
    match pointer_size {
        8 => {
            checked_range(size, offset, 8)?;
            Ok(unsafe { std::ptr::read_unaligned((base + offset) as *const u64) })
        }
        4 => {
            checked_range(size, offset, 4)?;
            Ok(unsafe { std::ptr::read_unaligned((base + offset) as *const u32) } as u64)
        }
        _ => Err("NeverGuard Hook Engine unsupported pointer size".to_string()),
    }
}

fn read_ascii(base: usize, size: usize, offset: usize, max: usize) -> Result<String, String> {
    checked_range(size, offset, 1)?;
    let mut bytes = Vec::new();
    for index in 0..max {
        checked_range(size, offset + index, 1)?;
        let value = unsafe { *((base + offset + index) as *const u8) };
        if value == 0 {
            return String::from_utf8(bytes)
                .map_err(|_| "NeverGuard Hook Engine invalid non-ASCII import name".to_string());
        }
        if !value.is_ascii() {
            return Err("NeverGuard Hook Engine invalid import name".to_string());
        }
        bytes.push(value);
    }
    Err("NeverGuard Hook Engine unterminated import name".to_string())
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn hook_load_library_a(name: *const c_char) -> *mut c_void {
    HOOK_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let target = ORIGINAL_LOAD_LIBRARY_A.load(Ordering::Acquire);
    if target.is_null() {
        return std::ptr::null_mut();
    }
    let function: unsafe extern "system" fn(*const c_char) -> *mut c_void = unsafe { std::mem::transmute(target) };
    unsafe { function(name) }
}

unsafe extern "system" fn hook_load_library_w(name: *const u16) -> *mut c_void {
    HOOK_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let target = ORIGINAL_LOAD_LIBRARY_W.load(Ordering::Acquire);
    if target.is_null() {
        return std::ptr::null_mut();
    }
    let function: unsafe extern "system" fn(*const u16) -> *mut c_void = unsafe { std::mem::transmute(target) };
    unsafe { function(name) }
}

unsafe extern "system" fn hook_load_library_ex_a(
    name: *const c_char,
    file: *mut c_void,
    flags: u32,
) -> *mut c_void {
    HOOK_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let target = ORIGINAL_LOAD_LIBRARY_EX_A.load(Ordering::Acquire);
    if target.is_null() {
        return std::ptr::null_mut();
    }
    let function: unsafe extern "system" fn(*const c_char, *mut c_void, u32) -> *mut c_void =
        unsafe { std::mem::transmute(target) };
    unsafe { function(name, file, flags) }
}

unsafe extern "system" fn hook_load_library_ex_w(
    name: *const u16,
    file: *mut c_void,
    flags: u32,
) -> *mut c_void {
    HOOK_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let target = ORIGINAL_LOAD_LIBRARY_EX_W.load(Ordering::Acquire);
    if target.is_null() {
        return std::ptr::null_mut();
    }
    let function: unsafe extern "system" fn(*const u16, *mut c_void, u32) -> *mut c_void =
        unsafe { std::mem::transmute(target) };
    unsafe { function(name, file, flags) }
}

unsafe extern "system" fn hook_virtual_alloc(
    address: *mut c_void,
    size: usize,
    allocation_type: u32,
    protect: u32,
) -> *mut c_void {
    HOOK_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let target = ORIGINAL_VIRTUAL_ALLOC.load(Ordering::Acquire);
    if target.is_null() {
        return std::ptr::null_mut();
    }
    let function: unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void =
        unsafe { std::mem::transmute(target) };
    let result = unsafe { function(address, size, allocation_type, protect) };
    if !result.is_null() {
        let provenance = crate::jvm_awareness::capture_transition_provenance();
        crate::jvm_awareness::observe_memory_transition(result, protect, provenance);
        crate::memory_integrity::record_virtual_alloc(result, size, protect);
    }
    result
}

unsafe extern "system" fn hook_virtual_protect(
    address: *mut c_void,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    HOOK_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let target = ORIGINAL_VIRTUAL_PROTECT.load(Ordering::Acquire);
    if target.is_null() {
        return 0;
    }
    let function: unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32 =
        unsafe { std::mem::transmute(target) };
    let result = unsafe { function(address, size, new_protect, old_protect) };
    if result != 0 {
        let provenance = crate::jvm_awareness::capture_transition_provenance();
        crate::jvm_awareness::observe_memory_transition(address, new_protect, provenance);
        crate::memory_integrity::record_virtual_protect(address, size, new_protect);
    }
    result
}
