#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    mem::size_of,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Mutex,
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
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;

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
    fn GetModuleHandleExW(flags: u32, name_or_address: *const u16, module: *mut *mut c_void) -> i32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
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

    JIT_TRANSITIONS.store(0, Ordering::Release);
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
    let foreign = FOREIGN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire);
    if foreign != 0 {
        let caller = LAST_FOREIGN_CALLER.load(Ordering::Acquire);
        return Err(format!(
            "NeverGuard JVM-Aware Protection rejected {foreign} executable MEM_PRIVATE transition(s) outside jvm.dll provenance; last caller=0x{caller:X}"
        ));
    }
    let unknown = UNKNOWN_EXECUTABLE_TRANSITIONS.load(Ordering::Acquire);
    if unknown != 0 {
        let caller = LAST_UNKNOWN_CALLER.load(Ordering::Acquire);
        return Err(format!(
            "NeverGuard JVM-Aware Protection rejected {unknown} executable MEM_PRIVATE transition(s) with unknown JVM provenance; last caller=0x{caller:X}"
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

/// Captures the caller chain while executing inside the NeverGuard IAT wrapper.
/// HotSpot's Windows memory implementation calls VirtualAlloc/VirtualProtect from
/// jvm.dll, so a legitimate JIT/code-cache transition must have its direct external
/// caller in the immutable jvm.dll image range. The operation is allocation-free.
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

    // Find the first return address after the Sensor's own wrapper frames.
    // Looking for "any" jvm.dll frame is insufficient: JNI/native code invoked
    // by HotSpot naturally has jvm.dll deeper in its stack. Only the direct
    // external caller of our IAT wrapper is allowed to authorize JIT memory.
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

/// Records only transitions whose resulting target is committed executable
/// MEM_PRIVATE memory. Image code-page changes remain owned by Memory Integrity,
/// preserving its independent code-drift detection path.
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
