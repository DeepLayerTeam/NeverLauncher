#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    path::PathBuf,
    mem::size_of,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

const CERTIFIED_JAVA_MAJORS: [u32; 5] = [8, 16, 17, 21, 25];
const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const PAGE_NOACCESS: u32 = 0x01;
const MAX_MODULE_PATH: usize = 32768;
const MAX_STACK_FRAMES: usize = 16;
const GET_MODULE_HANDLE_EX_FLAG_PIN: u32 = 0x0000_0001;
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct ModuleInfo {
    base_of_dll: *mut c_void,
    size_of_image: u32,
    entry_point: *mut c_void,
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

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct VsFixedFileInfo {
    signature: u32,
    struct_version: u32,
    file_version_ms: u32,
    file_version_ls: u32,
    product_version_ms: u32,
    product_version_ls: u32,
    file_flags_mask: u32,
    file_flags: u32,
    file_os: u32,
    file_type: u32,
    file_subtype: u32,
    file_date_ms: u32,
    file_date_ls: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetModuleHandleExW(flags: u32, name_or_address: *const u16, module: *mut *mut c_void) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn K32GetModuleInformation(
        process: *mut c_void,
        module: *mut c_void,
        info: *mut ModuleInfo,
        cb: u32,
    ) -> i32;
    fn VirtualQuery(
        address: *const c_void,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
    fn RtlCaptureStackBackTrace(
        frames_to_skip: u32,
        frames_to_capture: u32,
        back_trace: *mut *mut c_void,
        back_trace_hash: *mut u32,
    ) -> u16;
}

#[link(name = "version")]
extern "system" {
    fn GetFileVersionInfoSizeW(filename: *const u16, handle: *mut u32) -> u32;
    fn GetFileVersionInfoW(
        filename: *const u16,
        handle: u32,
        length: u32,
        data: *mut c_void,
    ) -> i32;
    fn VerQueryValueW(
        block: *const c_void,
        sub_block: *const u16,
        buffer: *mut *mut c_void,
        length: *mut u32,
    ) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionOrigin {
    HotSpotJvm,
    // Verified OS dispatchers may allocate executable pages while servicing
    // HotSpot on Windows; this is not the same as an arbitrary native DLL.
    TrustedSystemDispatcher,
    ForeignNative,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub struct TransitionProvenance {
    pub origin: TransitionOrigin,
    pub caller: usize,
}

#[derive(Clone, Debug)]
pub struct JvmAwareSnapshot {
    pub active: bool,
    pub healthy: bool,
    pub java_major: u32,
    pub jvm_module_size: u32,
    pub jvm_path_sha256: String,
    pub baseline_private_executable_region_count: u32,
    pub jit_transition_count: u64,
    pub trusted_system_transition_count: u64,
    pub foreign_executable_transition_count: u64,
    pub unknown_executable_transition_count: u64,
    pub integrity_check_count: u64,
    pub state_sha256: String,
}

#[derive(Clone, Debug)]
struct JvmIdentity {
    java_major: u32,
    module_base: usize,
    module_size: u32,
    path_sha256: String,
}

#[derive(Clone, Debug)]
struct JvmAwareState {
    active: bool,
    healthy: bool,
    identity: JvmIdentity,
    baseline_private_executable_region_count: u32,
    integrity_check_count: u64,
}

static JVM_STATE: Mutex<Option<JvmAwareState>> = Mutex::new(None);
static JVM_ACTIVE: AtomicBool = AtomicBool::new(false);
static JVM_BASE: AtomicUsize = AtomicUsize::new(0);
static JVM_END: AtomicUsize = AtomicUsize::new(0);
static JVM_MAJOR: AtomicU32 = AtomicU32::new(0);
static SENSOR_BASE: AtomicUsize = AtomicUsize::new(0);
static SENSOR_END: AtomicUsize = AtomicUsize::new(0);
static JIT_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static TRUSTED_SYSTEM_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
// Initialized once before hooks are active. No Win32 pathname resolution,
// allocation or locking is performed from inside a VirtualAlloc hook.
static TRUSTED_SYSTEM_DISPATCHERS: OnceLock<Vec<(usize, usize)>> = OnceLock::new();
// LWJGL is loaded only after Agent_OnLoad. Pin the exact, hashed native from
// the launch directory so its image base cannot be recycled for an untrusted
// DLL. No path resolution or heap allocation is performed inside memory hooks.
static VERIFIED_NATIVE_LAUNCH_ROOT: OnceLock<PathBuf> = OnceLock::new();
static VERIFIED_LWJGL_IMAGE: OnceLock<VerifiedNativeImage> = OnceLock::new();
static RUNTIME_NATIVE_LOAD_FAILED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
struct VerifiedNativeImage {
    base: usize,
    end: usize,
    canonical_path: PathBuf,
    file_sha256: [u8; 32],
}
static FOREIGN_EXECUTABLE_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static UNKNOWN_EXECUTABLE_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static LAST_FOREIGN_CALLER: AtomicUsize = AtomicUsize::new(0);
static LAST_UNKNOWN_CALLER: AtomicUsize = AtomicUsize::new(0);

pub fn initialize(java_vm: *mut c_void) -> Result<JvmAwareSnapshot, String> {
    if java_vm.is_null() {
        return Err("NeverGuard JVM-Aware Protection received null JavaVM".to_string());
    }
    let identity = inspect_jvm_identity()?;
    if !CERTIFIED_JAVA_MAJORS.contains(&identity.java_major) {
        return Err(format!(
            "NeverGuard JVM-Aware Protection unsupported Java major {}; certified majors are 8/16/17/21/25",
            identity.java_major
        ));
    }
    let end = identity
        .module_base
        .checked_add(identity.module_size as usize)
        .ok_or_else(|| "NeverGuard JVM-Aware Protection jvm.dll address range overflow".to_string())?;

    let (sensor_base, sensor_end) = current_sensor_image_range()?;
    let system_dispatchers = resolve_system_dispatchers()?;
    if let Some(existing) = TRUSTED_SYSTEM_DISPATCHERS.get() {
        if existing != &system_dispatchers {
            return Err("NeverGuard JVM-Aware Protection system module identity drift".to_string());
        }
    } else {
        TRUSTED_SYSTEM_DISPATCHERS
            .set(system_dispatchers)
            .map_err(|_| "NeverGuard JVM-Aware Protection system dispatcher initialization race".to_string())?;
    }

    let launch_root = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|err| format!("NeverGuard JVM-Aware cannot resolve native launch root: {err}"))?;
    if let Some(existing) = VERIFIED_NATIVE_LAUNCH_ROOT.get() {
        if existing != &launch_root {
            return Err("NeverGuard JVM-Aware native launch root changed".to_string());
        }
    } else {
        VERIFIED_NATIVE_LAUNCH_ROOT.set(launch_root)
            .map_err(|_| "NeverGuard JVM-Aware native launch root initialization race".to_string())?;
    }
    RUNTIME_NATIVE_LOAD_FAILED.store(false, Ordering::Release);

    JIT_TRANSITIONS.store(0, Ordering::Release);
    TRUSTED_SYSTEM_TRANSITIONS.store(0, Ordering::Release);
    FOREIGN_EXECUTABLE_TRANSITIONS.store(0, Ordering::Release);
    UNKNOWN_EXECUTABLE_TRANSITIONS.store(0, Ordering::Release);
    LAST_FOREIGN_CALLER.store(0, Ordering::Release);
    LAST_UNKNOWN_CALLER.store(0, Ordering::Release);
    JVM_BASE.store(identity.module_base, Ordering::Release);
    JVM_END.store(end, Ordering::Release);
    JVM_MAJOR.store(identity.java_major, Ordering::Release);
    SENSOR_BASE.store(sensor_base, Ordering::Release);
    SENSOR_END.store(sensor_end, Ordering::Release);
    JVM_ACTIVE.store(true, Ordering::Release);

    let baseline_private_executable_region_count = count_private_executable_regions()?;
    let state = JvmAwareState {
        active: true,
        healthy: true,
        identity,
        baseline_private_executable_region_count,
        integrity_check_count: 1,
    };
    let snapshot = snapshot_for_state(&state);
    *JVM_STATE
        .lock()
        .map_err(|_| "NeverGuard JVM-Aware Protection state lock poisoned".to_string())? =
        Some(state);
    Ok(snapshot)
}

pub fn reconcile_and_verify() -> Result<JvmAwareSnapshot, String> {
    if RUNTIME_NATIVE_LOAD_FAILED.load(Ordering::Acquire) {
        return Err("NeverGuard JVM-Aware rejected unexpected LWJGL native image".to_string());
    }
    if let Some(native) = VERIFIED_LWJGL_IMAGE.get() {
        // Loader pinning prevents address recycling. Independently recheck the
        // image on disk, including modifications after successful loading.
        let bytes = std::fs::read(&native.canonical_path)
            .map_err(|err| format!("NeverGuard JVM-Aware LWJGL image disappeared: {err}"))?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(&bytes));
        if digest != native.file_sha256 {
            return Err("NeverGuard JVM-Aware LWJGL image content changed".to_string());
        }
    }
    // A DLL loaded through a direct ntdll path may execute once before the
    // IAT LoadLibrary callback registers it. Only a *single* pending event
    // may be reclassified, and only after the identical strict path/image
    // checks above. Multiple/unknown transitions still fail closed.
    reconcile_first_runtime_native_transition()?;
    let foreign = FOREIGN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire);
    if foreign != 0 {
        let caller = LAST_FOREIGN_CALLER.load(Ordering::Acquire);
        return Err(format!(
            "NeverGuard JVM-Aware Protection rejected {foreign} executable MEM_PRIVATE transition(s) outside jvm.dll provenance; last caller=0x{caller:X}, module={}",
            caller_module_basename(caller)
        ));
    }
    let unknown = UNKNOWN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire);
    if unknown != 0 {
        let caller = LAST_UNKNOWN_CALLER.load(Ordering::Acquire);
        return Err(format!(
            "NeverGuard JVM-Aware Protection rejected {unknown} executable MEM_PRIVATE transition(s) with unknown JVM provenance; last caller=0x{caller:X}, module={}",
            caller_module_basename(caller)
        ));
    }

    let current = inspect_jvm_identity()?;
    let mut guard = JVM_STATE
        .lock()
        .map_err(|_| "NeverGuard JVM-Aware Protection state lock poisoned".to_string())?;
    let state = guard
        .as_mut()
        .ok_or_else(|| "NeverGuard JVM-Aware Protection is not initialized".to_string())?;
    if !state.active || !state.healthy || !JVM_ACTIVE.load(Ordering::Acquire) {
        return Err("NeverGuard JVM-Aware Protection is not active/healthy".to_string());
    }
    if current.java_major != state.identity.java_major
        || current.module_base != state.identity.module_base
        || current.module_size != state.identity.module_size
        || current.path_sha256 != state.identity.path_sha256
    {
        state.healthy = false;
        return Err("NeverGuard JVM-Aware Protection jvm.dll identity drift detected".to_string());
    }
    state.integrity_check_count = state.integrity_check_count.saturating_add(1);
    Ok(snapshot_for_state(state))
}

pub fn shutdown() {
    JVM_ACTIVE.store(false, Ordering::Release);
    JVM_BASE.store(0, Ordering::Release);
    JVM_END.store(0, Ordering::Release);
    JVM_MAJOR.store(0, Ordering::Release);
    SENSOR_BASE.store(0, Ordering::Release);
    SENSOR_END.store(0, Ordering::Release);
    if let Ok(mut guard) = JVM_STATE.lock() {
        *guard = None;
    }
}

// Resolve provenance for diagnostics on the worker thread only; never query
// module paths or allocate strings from inside the VirtualAlloc hook.
fn caller_module_basename(address: usize) -> String {
    if address == 0 { return "unknown".to_string(); }
    let mut module = std::ptr::null_mut();
    let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if unsafe { GetModuleHandleExW(flags, address as *const u16, &mut module) } == 0 || module.is_null() {
        return "unmapped".to_string();
    }
    let mut wide = [0u16; MAX_MODULE_PATH];
    let len = unsafe { GetModuleFileNameW(module, wide.as_mut_ptr(), wide.len() as u32) } as usize;
    if len == 0 || len >= wide.len() { return "unavailable".to_string(); }
    let path = String::from_utf16_lossy(&wide[..len]);
    path.rsplit(['\\', '/']).next().unwrap_or("unknown").to_string()
}

// Trust only verified System32 dispatcher images, plus the exact OpenGL image
// that belongs to the already inspected JVM installation. Module Guard pins
// loaded DLL path and content; Memory Integrity independently checks image
// code. No modpack-native or arbitrary PATH-resolved module is exempted.
fn resolve_system_dispatchers() -> Result<Vec<(usize, usize)>, String> {
    let mut directory = [0u16; MAX_MODULE_PATH];
    let len = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if len == 0 || len >= directory.len() {
        return Err("NeverGuard JVM-Aware Protection cannot resolve System32".to_string());
    }
    let system_root = String::from_utf16_lossy(&directory[..len])
        .trim_end_matches('\\')
        .replace('/', "\\")
        .to_ascii_lowercase();
    let mut ranges = Vec::new();
    // OpenGL dispatchers legitimately allocate executable MEM_PRIVATE memory.
    // The CI uses a SHA-256-verified Mesa opengl32.dll installed beside
    // java.exe, *not* the Windows System32 opengl32.dll. Resolve only the
    // already-certified JVM's bin directory (or the OS System32 fallback).
    // Preloading once before installing hooks prevents a later LoadLibrary
    // from introducing an unclassified dispatcher in the middle of JIT work.
    let jvm_module = unsafe { GetModuleHandleW(wide_null("jvm.dll").as_ptr()) };
    if jvm_module.is_null() {
        return Err("NeverGuard JVM-Aware Protection cannot locate jvm.dll for OpenGL provenance".to_string());
    }
    let jvm_path = module_path(jvm_module)?;
    let jvm_dir = std::path::Path::new(&jvm_path).parent()
        .ok_or_else(|| "NeverGuard JVM-Aware Protection invalid jvm.dll directory".to_string())?;
    let jvm_dir_name = jvm_dir.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let jvm_bin = jvm_dir.parent()
        .ok_or_else(|| "NeverGuard JVM-Aware Protection missing JVM bin directory".to_string())?;
    if !(jvm_dir_name.eq_ignore_ascii_case("server") || jvm_dir_name.eq_ignore_ascii_case("client"))
        || !jvm_bin.file_name().and_then(|name| name.to_str()).unwrap_or("").eq_ignore_ascii_case("bin")
    {
        return Err("NeverGuard JVM-Aware Protection unexpected JVM directory layout".to_string());
    }
    let runtime_opengl = jvm_bin.join("opengl32.dll");
    let runtime_opengl_metadata = std::fs::symlink_metadata(&runtime_opengl);
    let runtime_opengl_exists = match runtime_opengl_metadata {
        Ok(ref metadata) if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 => {
            return Err("NeverGuard JVM-Aware Protection rejected non-regular Java runtime OpenGL image".to_string());
        }
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(format!("NeverGuard JVM-Aware Protection cannot inspect Java runtime OpenGL image: {err}")),
    };
    for name in ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll", "opengl32.dll"] {
        let wide = wide_null(name);
        let (module, expected_path) = if name == "opengl32.dll" {
            if runtime_opengl_exists {
                let path = runtime_opengl.to_string_lossy().into_owned();
                let loaded = unsafe {
                    LoadLibraryExW(wide_null(&path).as_ptr(), std::ptr::null_mut(),
                        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
                };
                (loaded, path.replace('/', "\\").to_ascii_lowercase())
            } else {
                let loaded = unsafe {
                    LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)
                };
                (loaded, format!("{system_root}\\{name}"))
            }
        } else {
            (unsafe { GetModuleHandleW(wide.as_ptr()) }, format!("{system_root}\\{name}"))
        };
        if module.is_null() {
            if name == "opengl32.dll" {
                return Err(format!("NeverGuard JVM-Aware Protection cannot load verified OpenGL dispatcher: {}", std::io::Error::last_os_error()));
            }
            continue;
        }
        let mut path = [0u16; MAX_MODULE_PATH];
        let count = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), path.len() as u32) } as usize;
        if count == 0 || count >= path.len() {
            return Err(format!("NeverGuard JVM-Aware Protection cannot identify {name}"));
        }
        let loaded_path = String::from_utf16_lossy(&path[..count]).replace('/', "\\").to_ascii_lowercase();
        if loaded_path != expected_path {
            return Err(format!("NeverGuard JVM-Aware Protection unexpected dispatcher image location: {name}"));
        }
        let mut info = ModuleInfo::default();
        let ok = unsafe {
            K32GetModuleInformation(GetCurrentProcess(), module, &mut info, size_of::<ModuleInfo>() as u32)
        };
        if ok == 0 || info.size_of_image == 0 {
            return Err(format!("NeverGuard JVM-Aware Protection cannot inspect {name}"));
        }
        let base = info.base_of_dll as usize;
        let end = base.checked_add(info.size_of_image as usize)
            .ok_or_else(|| format!("NeverGuard JVM-Aware Protection {name} image overflow"))?;
        ranges.push((base, end));
    }
    if ranges.is_empty() {
        return Err("NeverGuard JVM-Aware Protection no verified dispatchers".to_string());
    }
    Ok(ranges)
}

fn reconcile_first_runtime_native_transition() -> Result<(), String> {
    if FOREIGN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire) != 1 {
        return Ok(());
    }
    let caller = LAST_FOREIGN_CALLER.load(Ordering::Acquire);
    if caller == 0 {
        return Ok(());
    }
    if VERIFIED_LWJGL_IMAGE.get().is_none() {
        let mut module = std::ptr::null_mut();
        let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        if unsafe { GetModuleHandleExW(flags, caller as *const u16, &mut module) } == 0 || module.is_null() {
            return Ok(());
        }
        // This checks basename only to decide whether registration should be
        // attempted; registration checks canonical path, ancestry and SHA.
        let path = module_path(module)?;
        if !PathBuf::from(path).file_name().is_some_and(|name| {
            name.to_string_lossy().eq_ignore_ascii_case("lwjgl.dll")
        }) {
            return Ok(());
        }
        register_loaded_native_dispatcher(module)?;
    }
    if VERIFIED_LWJGL_IMAGE.get().is_some_and(|native| {
        caller >= native.base && caller < native.end
    }) && FOREIGN_EXECUTABLE_TRANSITIONS.compare_exchange(
        1, 0, Ordering::AcqRel, Ordering::Acquire
    ).is_ok() {
        TRUSTED_SYSTEM_TRANSITIONS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Register the one permitted LWJGL dispatcher after LoadLibrary returns.
/// The complete canonical path must be exactly the platform-specific native
/// from the materialized client, not merely any file named lwjgl.dll. Module
/// Guard independently verifies and hashes authenticated DLL load events.
pub fn register_loaded_native_dispatcher(module: *mut c_void) -> Result<(), String> {
    if module.is_null() || !JVM_ACTIVE.load(Ordering::Acquire) {
        return Ok(());
    }
    let path = module_path(module)?;
    let loaded = PathBuf::from(path.as_str());
    if !loaded.file_name().is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("lwjgl.dll")) {
        return Ok(());
    }
    let result = (|| -> Result<(), String> {
        let launch_root = VERIFIED_NATIVE_LAUNCH_ROOT.get()
            .ok_or_else(|| "NeverGuard JVM-Aware missing pinned native launch root".to_string())?;
        let native_root = launch_root.join("natives").join("windows")
            .join(std::env::consts::ARCH);
        // The materialized Mojang LWJGL classifier preserves its archive
        // entry hierarchy. The approved Windows/x86_64 manifest records
        // natives/windows/x86_64/windows/x64/org/lwjgl/lwjgl.dll, rather
        // than the older flat natives/windows/x86_64/lwjgl.dll. Only these
        // *exact* platform layouts are permitted, never a filename search.
        let classifier_arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            arch => return Err(format!("NeverGuard JVM-Aware unsupported LWJGL architecture: {arch}")),
        };
        let candidates = [
            native_root.join("lwjgl.dll"),
            native_root.join("windows").join(classifier_arch)
                .join("org").join("lwjgl").join("lwjgl.dll"),
            // LWJGL 3 can extract the classpath native rather than loading
            // java.library.path. NeverRuntime pins this extraction directory
            // with org.lwjgl.system.SharedLibraryExtractPath. A file here
            // is trusted only if its SHA-256 equals the certified flat copy.
            launch_root.join(".neverlauncher").join("lwjgl-extract")
                .join("windows").join(std::env::consts::ARCH).join("lwjgl.dll"),
        ];
        let canonical_path = std::fs::canonicalize(&loaded)
            .map_err(|err| format!("NeverGuard JVM-Aware cannot canonicalize LWJGL: {err}"))?;
        // A missing legacy layout must not poison the Sensor when the native
        // is legitimately stored under the platform's archive hierarchy.
        let mut matched = None;
        for (candidate_index, expected) in candidates.iter().enumerate() {
            // Check each directory component before canonicalizing: no
            // symlink/reparse traversal from inside the certified client.
            let mut component = expected.as_path();
            let mut safe = true;
            while component != launch_root.as_path() {
                match std::fs::symlink_metadata(component) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err("NeverGuard JVM-Aware rejected reparse/symlink native path".to_string());
                    }
                    Ok(_) => {},
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        safe = false;
                        break;
                    }
                    Err(err) => return Err(format!("NeverGuard JVM-Aware native path inspection failed: {err}")),
                }
                component = component.parent()
                    .ok_or_else(|| "NeverGuard JVM-Aware invalid native directory ancestry".to_string())?;
            }
            if !safe { continue; }
            let expected_path = std::fs::canonicalize(expected)
                .map_err(|err| format!("NeverGuard JVM-Aware cannot find expected native: {err}"))?;
            if !expected_path.starts_with(launch_root) {
                return Err("NeverGuard JVM-Aware native path escapes the launch root".to_string());
            }
            if canonical_path.to_string_lossy().eq_ignore_ascii_case(&expected_path.to_string_lossy()) {
                matched = Some(candidate_index);
                break;
            }
        }
        let matched = matched.ok_or_else(|| {
            let location = canonical_path.strip_prefix(launch_root)
                .map(|relative| relative.to_string_lossy().chars().take(180).collect::<String>())
                .unwrap_or_else(|_| "outside pinned client root".to_string());
            format!("NeverGuard JVM-Aware LWJGL loaded outside certified natives directory ({location})")
        })?;
        let metadata = std::fs::symlink_metadata(&loaded)
            .map_err(|err| format!("NeverGuard JVM-Aware cannot inspect LWJGL native: {err}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err("NeverGuard JVM-Aware LWJGL native is not a regular file".to_string());
        }
        let mut info = ModuleInfo::default();
        if unsafe { K32GetModuleInformation(GetCurrentProcess(), module, &mut info,
            size_of::<ModuleInfo>() as u32) } == 0 || info.size_of_image == 0 {
            return Err("NeverGuard JVM-Aware cannot inspect loaded LWJGL image".to_string());
        }
        let base = info.base_of_dll as usize;
        let end = base.checked_add(info.size_of_image as usize)
            .ok_or_else(|| "NeverGuard JVM-Aware LWJGL module address overflow".to_string())?;
        if let Some(existing) = VERIFIED_LWJGL_IMAGE.get() {
            if existing.base == base && existing.end == end && existing.canonical_path == canonical_path {
                return Ok(());
            }
            return Err("NeverGuard JVM-Aware unexpected LWJGL module replacement".to_string());
        }
        let bytes = std::fs::read(&canonical_path)
            .map_err(|err| format!("NeverGuard JVM-Aware cannot hash LWJGL image: {err}"))?;
        let mut file_sha256 = [0u8; 32];
        file_sha256.copy_from_slice(&Sha256::digest(&bytes));
        if matched == 2 {
            // Extracted bytes come from a classpath resource, not the
            // already-certified package tree. Require an exact digest match
            // to the pinned flat alias published by the Mojang-verified
            // installer. This disallows arbitrary DLLs in the extract cache.
            let certified = &candidates[0];
            let mut current = certified.as_path();
            while current != launch_root.as_path() {
                let metadata = std::fs::symlink_metadata(current)
                    .map_err(|err| format!("NeverGuard JVM-Aware cannot inspect certified LWJGL component: {err}"))?;
                if metadata.file_type().is_symlink() {
                    return Err("NeverGuard JVM-Aware certified LWJGL path contains reparse/symlink".to_string());
                }
                current = current.parent().ok_or_else(||
                    "NeverGuard JVM-Aware invalid certified LWJGL ancestry".to_string())?;
            }
            let canonical_certified = std::fs::canonicalize(certified)
                .map_err(|err| format!("NeverGuard JVM-Aware cannot canonicalize certified LWJGL: {err}"))?;
            if !canonical_certified.starts_with(launch_root) {
                return Err("NeverGuard JVM-Aware certified LWJGL escapes pinned client root".to_string());
            }
            let metadata = std::fs::metadata(&canonical_certified)
                .map_err(|err| format!("NeverGuard JVM-Aware certified LWJGL metadata failed: {err}"))?;
            if !metadata.is_file() || metadata.len() == 0 {
                return Err("NeverGuard JVM-Aware certified LWJGL is not a regular file".to_string());
            }
            let expected_digest = Sha256::digest(std::fs::read(&canonical_certified)
                .map_err(|err| format!("NeverGuard JVM-Aware cannot hash certified LWJGL: {err}"))?);
            if file_sha256.as_slice() != expected_digest.as_slice() {
                return Err("NeverGuard JVM-Aware extracted LWJGL differs from certified package image".to_string());
            }
        }
        // Permanently pin this one verified native for the process lifetime:
        // otherwise an unload/reload could recycle its trusted address range.
        let mut pinned = std::ptr::null_mut();
        if unsafe { GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            base as *const u16, &mut pinned) } == 0 || pinned != module {
            return Err("NeverGuard JVM-Aware cannot pin verified LWJGL module".to_string());
        }
        VERIFIED_LWJGL_IMAGE.set(VerifiedNativeImage {
            base, end, canonical_path, file_sha256,
        }).map_err(|_| "NeverGuard JVM-Aware LWJGL registration race".to_string())
    })();
    if result.is_err() {
        RUNTIME_NATIVE_LOAD_FAILED.store(true, Ordering::Release);
    }
    result
}

/// Захватывает цепочку вызовов внутри обёртки IAT NeverGuard. Реализация памяти
/// HotSpot для Windows вызывает VirtualAlloc/VirtualProtect из jvm.dll, поэтому
/// допустимый JIT-переход или изменение кеша кода должны иметь прямой внешний
/// вызов из неизменяемого диапазона образа jvm.dll. Операция не выделяет память.
pub fn capture_transition_provenance() -> TransitionProvenance {
    if !JVM_ACTIVE.load(Ordering::Acquire) {
        return TransitionProvenance {
            origin: TransitionOrigin::Unknown,
            caller: 0,
        };
    }
    let jvm_base = JVM_BASE.load(Ordering::Acquire);
    let jvm_end = JVM_END.load(Ordering::Acquire);
    let sensor_base = SENSOR_BASE.load(Ordering::Acquire);
    let sensor_end = SENSOR_END.load(Ordering::Acquire);
    if jvm_base == 0
        || jvm_end <= jvm_base
        || sensor_base == 0
        || sensor_end <= sensor_base
    {
        return TransitionProvenance {
            origin: TransitionOrigin::Unknown,
            caller: 0,
        };
    }

    let mut frames = [std::ptr::null_mut(); MAX_STACK_FRAMES];
    let captured = unsafe {
        RtlCaptureStackBackTrace(
            0,
            MAX_STACK_FRAMES as u32,
            frames.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    } as usize;
    if captured == 0 {
        return TransitionProvenance {
            origin: TransitionOrigin::Unknown,
            caller: 0,
        };
    }

    // Найдите первый адрес возврата после собственных кадров обёртки
    // Sensor. Искать любой кадр jvm.dll недостаточно: JNI или нативный
    // код, вызванный HotSpot, естественно содержит jvm.dll глубже в стеке.
    // Только прямой внешний вызов обёртки IAT может разрешать JIT-память.
    let mut saw_sensor_frame = false;
    for frame in frames.iter().take(captured) {
        let address = *frame as usize;
        if address == 0 {
            continue;
        }
        if address >= sensor_base && address < sensor_end {
            saw_sensor_frame = true;
            continue;
        }
        if !saw_sensor_frame {
            continue;
        }
        return TransitionProvenance {
            origin: if address >= jvm_base && address < jvm_end {
                TransitionOrigin::HotSpotJvm
            } else if TRUSTED_SYSTEM_DISPATCHERS
                .get()
                .is_some_and(|ranges| ranges.iter().any(|(base, end)| address >= *base && address < *end))
                || VERIFIED_LWJGL_IMAGE.get().is_some_and(|native| {
                    address >= native.base && address < native.end
                })
            {
                TransitionOrigin::TrustedSystemDispatcher
            } else {
                TransitionOrigin::ForeignNative
            },
            caller: address,
        };
    }

    TransitionProvenance {
        origin: TransitionOrigin::Unknown,
        caller: 0,
    }
}

/// Учитывайте лишь переходы, чей результат — зафиксированная исполняемая
/// память MEM_PRIVATE. Изменения страниц образов остаются в ведении Memory
/// Integrity, сохраняя отдельный механизм обнаружения изменений кода.
pub fn observe_memory_transition(
    address: *mut c_void,
    protect: u32,
    provenance: TransitionProvenance,
) {
    if address.is_null() || !is_executable(protect) || !JVM_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let mut info = MemoryBasicInformation::default();
    let queried = unsafe {
        VirtualQuery(
            address as *const c_void,
            &mut info,
            size_of::<MemoryBasicInformation>(),
        )
    };
    if queried == 0
        || info.state != MEM_COMMIT
        || info.kind != MEM_PRIVATE
        || !is_executable(info.protect)
        || info.protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
    {
        return;
    }

    match provenance.origin {
        TransitionOrigin::HotSpotJvm => {
            JIT_TRANSITIONS.fetch_add(1, Ordering::Relaxed);
        }
        TransitionOrigin::TrustedSystemDispatcher => {
            TRUSTED_SYSTEM_TRANSITIONS.fetch_add(1, Ordering::Relaxed);
        }
        TransitionOrigin::ForeignNative => {
            LAST_FOREIGN_CALLER.store(provenance.caller, Ordering::Release);
            FOREIGN_EXECUTABLE_TRANSITIONS.fetch_add(1, Ordering::AcqRel);
        }
        TransitionOrigin::Unknown => {
            LAST_UNKNOWN_CALLER.store(provenance.caller, Ordering::Release);
            UNKNOWN_EXECUTABLE_TRANSITIONS.fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn current_sensor_image_range() -> Result<(usize, usize), String> {
    let mut module = std::ptr::null_mut();
    let address = capture_transition_provenance as usize as *const u16;
    let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if unsafe { GetModuleHandleExW(flags, address, &mut module) } == 0 || module.is_null() {
        return Err(format!(
            "NeverGuard JVM-Aware Protection cannot resolve Sensor module: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut info = ModuleInfo::default();
    if unsafe {
        K32GetModuleInformation(
            GetCurrentProcess(),
            module,
            &mut info,
            size_of::<ModuleInfo>() as u32,
        )
    } == 0
        || info.base_of_dll.is_null()
        || info.size_of_image == 0
    {
        return Err(format!(
            "NeverGuard JVM-Aware Protection cannot query Sensor module information: {}",
            std::io::Error::last_os_error()
        ));
    }
    let base = info.base_of_dll as usize;
    let end = base
        .checked_add(info.size_of_image as usize)
        .ok_or_else(|| "NeverGuard JVM-Aware Protection Sensor address range overflow".to_string())?;
    Ok((base, end))
}

fn count_private_executable_regions() -> Result<u32, String> {
    let mut count = 0u32;
    let mut cursor = 0usize;
    loop {
        let mut info = MemoryBasicInformation::default();
        let queried = unsafe {
            VirtualQuery(
                cursor as *const c_void,
                &mut info,
                size_of::<MemoryBasicInformation>(),
            )
        };
        if queried == 0 {
            break;
        }
        let base = info.base_address as usize;
        let size = info.region_size;
        if size == 0 {
            return Err("NeverGuard JVM-Aware Protection VirtualQuery returned zero region size".to_string());
        }
        if info.state == MEM_COMMIT
            && info.kind == MEM_PRIVATE
            && is_executable(info.protect)
            && info.protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        {
            count = count.saturating_add(1);
        }
        let next = base
            .checked_add(size)
            .ok_or_else(|| "NeverGuard JVM-Aware Protection address-space overflow".to_string())?;
        if next <= cursor {
            return Err("NeverGuard JVM-Aware Protection VirtualQuery did not advance".to_string());
        }
        cursor = next;
    }
    Ok(count)
}

fn inspect_jvm_identity() -> Result<JvmIdentity, String> {
    let jvm_name = wide_null("jvm.dll");
    let module = unsafe { GetModuleHandleW(jvm_name.as_ptr()) };
    if module.is_null() {
        return Err("NeverGuard JVM-Aware Protection cannot locate loaded jvm.dll".to_string());
    }

    let mut info = ModuleInfo::default();
    if unsafe {
        K32GetModuleInformation(
            GetCurrentProcess(),
            module,
            &mut info,
            size_of::<ModuleInfo>() as u32,
        )
    } == 0
        || info.base_of_dll.is_null()
        || info.size_of_image == 0
    {
        return Err(format!(
            "NeverGuard JVM-Aware Protection cannot query jvm.dll module information: {}",
            std::io::Error::last_os_error()
        ));
    }

    let path = module_path(module)?;
    let java_major = file_java_major(&path)?;
    let normalized_path = path.replace('/', "\\").to_ascii_lowercase();
    let path_sha256 = hex::encode(Sha256::digest(normalized_path.as_bytes()));
    Ok(JvmIdentity {
        java_major,
        module_base: info.base_of_dll as usize,
        module_size: info.size_of_image,
        path_sha256,
    })
}

fn module_path(module: *mut c_void) -> Result<String, String> {
    let mut buffer = vec![0u16; MAX_MODULE_PATH];
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) }
        as usize;
    if length == 0 || length >= buffer.len() {
        return Err(format!(
            "NeverGuard JVM-Aware Protection cannot resolve jvm.dll path: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn file_java_major(path: &str) -> Result<u32, String> {
    let path_w = wide_null(path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(path_w.as_ptr(), &mut handle) };
    if size == 0 {
        return Err(format!(
            "NeverGuard JVM-Aware Protection cannot read jvm.dll version resource: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut data = vec![0u8; size as usize];
    if unsafe {
        GetFileVersionInfoW(path_w.as_ptr(), 0, size, data.as_mut_ptr().cast())
    } == 0
    {
        return Err(format!(
            "NeverGuard JVM-Aware Protection cannot load jvm.dll version resource: {}",
            std::io::Error::last_os_error()
        ));
    }
    let root = wide_null("\\");
    let mut value = std::ptr::null_mut();
    let mut value_len = 0u32;
    if unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            root.as_ptr(),
            &mut value,
            &mut value_len,
        )
    } == 0
        || value.is_null()
        || value_len < size_of::<VsFixedFileInfo>() as u32
    {
        return Err("NeverGuard JVM-Aware Protection jvm.dll has no fixed version information".to_string());
    }
    let info = unsafe { &*(value as *const VsFixedFileInfo) };
    if info.signature != VS_FFI_SIGNATURE {
        return Err("NeverGuard JVM-Aware Protection invalid jvm.dll version signature".to_string());
    }
    let mut major = info.file_version_ms >> 16;
    let minor = info.file_version_ms & 0xFFFF;
    if major == 1 && minor != 0 {
        major = minor;
    }
    if major == 0 {
        major = info.product_version_ms >> 16;
    }
    if major == 1 {
        let product_minor = info.product_version_ms & 0xFFFF;
        if product_minor != 0 {
            major = product_minor;
        }
    }
    if major == 0 {
        return Err("NeverGuard JVM-Aware Protection cannot determine Java major from jvm.dll".to_string());
    }
    Ok(major)
}

fn snapshot_for_state(state: &JvmAwareState) -> JvmAwareSnapshot {
    let jit = JIT_TRANSITIONS.load(Ordering::Acquire);
    let trusted_system = TRUSTED_SYSTEM_TRANSITIONS.load(Ordering::Acquire);
    let foreign = FOREIGN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire);
    let unknown = UNKNOWN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire);
    let mut digest = Sha256::new();
    digest.update(b"NeverGuard JVM-Aware Protection state v1\0");
    digest.update(state.identity.java_major.to_le_bytes());
    digest.update((state.identity.module_base as u64).to_le_bytes());
    digest.update(state.identity.module_size.to_le_bytes());
    digest.update(state.identity.path_sha256.as_bytes());
    digest.update(state.baseline_private_executable_region_count.to_le_bytes());
    digest.update(jit.to_le_bytes());
    digest.update(trusted_system.to_le_bytes());
    digest.update(foreign.to_le_bytes());
    digest.update(unknown.to_le_bytes());
    digest.update(state.integrity_check_count.to_le_bytes());
    JvmAwareSnapshot {
        active: state.active,
        healthy: state.healthy && foreign == 0 && unknown == 0,
        java_major: state.identity.java_major,
        jvm_module_size: state.identity.module_size,
        jvm_path_sha256: state.identity.path_sha256.clone(),
        baseline_private_executable_region_count: state.baseline_private_executable_region_count,
        jit_transition_count: jit,
        trusted_system_transition_count: trusted_system,
        foreign_executable_transition_count: foreign,
        unknown_executable_transition_count: unknown,
        integrity_check_count: state.integrity_check_count,
        state_sha256: hex::encode(digest.finalize()),
    }
}

fn is_executable(protect: u32) -> bool {
    matches!(
        protect & 0xFF,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
