#![cfg(windows)]

use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const MEM_MAPPED: u32 = 0x0004_0000;
const MEM_IMAGE: u32 = 0x0100_0000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const MEMORY_TRANSITION_RING_CAPACITY: usize = 1024;
const MAX_HASHABLE_IMAGE_REGION: usize = 256 * 1024 * 1024;

const TRANSITION_VIRTUAL_ALLOC: u32 = 1;
const TRANSITION_VIRTUAL_PROTECT: u32 = 2;

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
    fn FreeLibrary(module: *mut c_void) -> i32;
}

#[derive(Clone, Debug)]
pub struct MemoryIntegritySnapshot {
    pub active: bool,
    pub healthy: bool,
    pub executable_regions: u32,
    pub image_code_regions: u32,
    pub dynamic_executable_regions: u32,
    pub rwx_regions: u32,
    pub executable_bytes: u64,
    pub transition_count: u64,
    pub code_set_sha256: String,
    pub executable_map_sha256: String,
}

#[derive(Clone, Copy, Default)]
struct MemoryTransition {
    kind: u32,
    address: usize,
    size: usize,
    protect: u32,
}

struct TransitionSlot {
    ready: AtomicBool,
    event: std::cell::UnsafeCell<MemoryTransition>,
}

impl TransitionSlot {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            event: std::cell::UnsafeCell::new(MemoryTransition {
                kind: 0,
                address: 0,
                size: 0,
                protect: 0,
            }),
        }
    }
}

unsafe impl Sync for TransitionSlot {}

static TRANSITION_RING: [TransitionSlot; MEMORY_TRANSITION_RING_CAPACITY] =
    [const { TransitionSlot::new() }; MEMORY_TRANSITION_RING_CAPACITY];
static TRANSITION_WRITE_INDEX: AtomicU64 = AtomicU64::new(0);
static TRANSITION_READ_INDEX: AtomicU64 = AtomicU64::new(0);
static TRANSITION_DROPPED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
struct ImageCodeBaseline {
    base: usize,
    size: usize,
    protect: u32,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct AddressRange {
    start: usize,
    end: usize,
}

impl AddressRange {
    fn from_base_size(base: usize, size: usize) -> Option<Self> {
        if base == 0 || size == 0 {
            return None;
        }
        let page = 4096usize;
        let start = base & !(page - 1);
        let raw_end = base.checked_add(size)?;
        let end = raw_end.checked_add(page - 1)? & !(page - 1);
        (end > start).then_some(Self { start, end })
    }

    fn contains(&self, start: usize, size: usize) -> bool {
        start
            .checked_add(size)
            .is_some_and(|end| start >= self.start && end <= self.end)
    }
}

struct MemoryIntegrityState {
    active: bool,
    healthy: bool,
    image_code: HashMap<(usize, usize), ImageCodeBaseline>,
    allowed_dynamic: Vec<AddressRange>,
    allowed_mapped: Vec<AddressRange>,
    transition_count: u64,
}

impl MemoryIntegrityState {
    fn new() -> Self {
        Self {
            active: false,
            healthy: false,
            image_code: HashMap::new(),
            allowed_dynamic: Vec::new(),
            allowed_mapped: Vec::new(),
            transition_count: 0,
        }
    }
}

static MEMORY_STATE: Mutex<Option<MemoryIntegrityState>> = Mutex::new(None);

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

pub fn initialize() -> Result<MemoryIntegritySnapshot, String> {
    TRANSITION_WRITE_INDEX.store(0, Ordering::Release);
    TRANSITION_READ_INDEX.store(0, Ordering::Release);
    TRANSITION_DROPPED.store(0, Ordering::Release);

    let mut state = MemoryIntegrityState::new();
    let regions = enumerate_executable_regions()?;
    for region in &regions {
        if region.kind == MEM_IMAGE {
            let baseline = hash_image_region(region)?;
            state
                .image_code
                .insert((baseline.base, baseline.size), baseline);
        } else if region.kind == MEM_PRIVATE {
            if let Some(range) = AddressRange::from_base_size(region.base, region.size) {
                state.allowed_dynamic.push(range);
            }
        } else if region.kind == MEM_MAPPED {
            if let Some(range) = AddressRange::from_base_size(region.base, region.size) {
                state.allowed_mapped.push(range);
            }
        }
    }
    state.active = true;
    state.healthy = true;
    let snapshot = snapshot_for_regions(&state, &regions);
    *MEMORY_STATE
        .lock()
        .map_err(|_| "NeverGuard Memory Integrity state lock poisoned".to_string())? = Some(state);
    Ok(snapshot)
}

pub fn reconcile_and_verify() -> Result<MemoryIntegritySnapshot, String> {
    let mut guard = MEMORY_STATE
        .lock()
        .map_err(|_| "NeverGuard Memory Integrity state lock poisoned".to_string())?;
    let state = guard
        .as_mut()
        .ok_or_else(|| "NeverGuard Memory Integrity is not initialized".to_string())?;
    if !state.active || !state.healthy {
        return Err("NeverGuard Memory Integrity is not active/healthy".to_string());
    }

    drain_transitions(state)?;
    let regions = enumerate_executable_regions()?;
    let mut current_image_keys = HashSet::new();

    for region in &regions {
        match region.kind {
            MEM_IMAGE => {
                let current = hash_image_region(region)?;
                let key = (current.base, current.size);
                current_image_keys.insert(key);
                if let Some(baseline) = state.image_code.get(&key) {
                    if baseline.protect != current.protect {
                        state.healthy = false;
                        return Err(format!(
                            "NeverGuard Memory Integrity executable image protection drift at 0x{:X}: 0x{:X} -> 0x{:X}",
                            current.base, baseline.protect, current.protect
                        ));
                    }
                    if baseline.digest != current.digest {
                        state.healthy = false;
                        return Err(format!(
                            "NeverGuard Memory Integrity code-page drift at 0x{:X} ({} bytes)",
                            current.base, current.size
                        ));
                    }
                } else {
                    // Newly loaded images are admitted only after the loader has mapped
                    // them. Module Guard independently authenticates the backing DLL;
                    // from this point onward the executable bytes are immutable.
                    state.image_code.insert(key, current);
                }
            }
            MEM_PRIVATE => {
                if !range_allowed(region, &state.allowed_dynamic) {
                    state.healthy = false;
                    return Err(format!(
                        "NeverGuard Memory Integrity detected executable private memory without observed VirtualAlloc/VirtualProtect provenance at 0x{:X} ({} bytes)",
                        region.base, region.size
                    ));
                }
            }
            MEM_MAPPED => {
                if !range_allowed(region, &state.allowed_mapped) {
                    state.healthy = false;
                    return Err(format!(
                        "NeverGuard Memory Integrity detected new executable mapped memory at 0x{:X} ({} bytes)",
                        region.base, region.size
                    ));
                }
            }
            _ => {}
        }
    }

    state
        .image_code
        .retain(|key, _| current_image_keys.contains(key));
    Ok(snapshot_for_regions(state, &regions))
}

pub fn shutdown() {
    if let Ok(mut guard) = MEMORY_STATE.lock() {
        *guard = None;
    }
}

/// Called from the IAT wrapper after a successful VirtualAlloc. This path is
/// allocation-free and lock-free so it is safe even if the caller is a JVM
/// allocator/compiler thread.
pub fn record_virtual_alloc(address: *mut c_void, size: usize, protect: u32) {
    if address.is_null() || size == 0 {
        return;
    }
    queue_transition(MemoryTransition {
        kind: TRANSITION_VIRTUAL_ALLOC,
        address: address as usize,
        size,
        protect,
    });
}

/// Called from the IAT wrapper after a successful VirtualProtect.
pub fn record_virtual_protect(address: *mut c_void, size: usize, protect: u32) {
    if address.is_null() || size == 0 {
        return;
    }
    queue_transition(MemoryTransition {
        kind: TRANSITION_VIRTUAL_PROTECT,
        address: address as usize,
        size,
        protect,
    });
}

#[derive(Clone, Debug)]
struct ExecutableRegion {
    base: usize,
    allocation_base: usize,
    size: usize,
    protect: u32,
    kind: u32,
}

fn enumerate_executable_regions() -> Result<Vec<ExecutableRegion>, String> {
    let mut regions = Vec::new();
    let mut cursor = 0usize;
    loop {
        let mut info = MemoryBasicInformation::default();
        let queried = unsafe {
            VirtualQuery(
                cursor as *const c_void,
                &mut info,
                std::mem::size_of::<MemoryBasicInformation>(),
            )
        };
        if queried == 0 {
            break;
        }
        let base = info.base_address as usize;
        let size = info.region_size;
        if size == 0 {
            return Err("NeverGuard Memory Integrity VirtualQuery returned zero region size".to_string());
        }
        if info.state == MEM_COMMIT
            && is_executable(info.protect)
            && info.protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        {
            regions.push(ExecutableRegion {
                base,
                allocation_base: info.allocation_base as usize,
                size,
                protect: info.protect,
                kind: info.kind,
            });
        }
        let next = base
            .checked_add(size)
            .ok_or_else(|| "NeverGuard Memory Integrity address-space overflow".to_string())?;
        if next <= cursor {
            return Err("NeverGuard Memory Integrity VirtualQuery did not advance".to_string());
        }
        cursor = next;
    }
    Ok(regions)
}

fn hash_image_region(region: &ExecutableRegion) -> Result<ImageCodeBaseline, String> {
    if region.size > MAX_HASHABLE_IMAGE_REGION {
        return Err(format!(
            "NeverGuard Memory Integrity executable image region exceeds hash limit at 0x{:X}: {} bytes",
            region.base, region.size
        ));
    }
    let _pin = pin_image(region.allocation_base.max(region.base))?;
    let bytes = unsafe { std::slice::from_raw_parts(region.base as *const u8, region.size) };
    let digest = Sha256::digest(bytes);
    let mut value = [0u8; 32];
    value.copy_from_slice(&digest);
    Ok(ImageCodeBaseline {
        base: region.base,
        size: region.size,
        protect: region.protect,
        digest: value,
    })
}

fn pin_image(address: usize) -> Result<PinnedModule, String> {
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
            "NeverGuard Memory Integrity cannot retain executable image at 0x{address:X}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PinnedModule(module))
}

fn drain_transitions(state: &mut MemoryIntegrityState) -> Result<(), String> {
    let dropped = TRANSITION_DROPPED.swap(0, Ordering::AcqRel);
    if dropped != 0 {
        state.healthy = false;
        return Err(format!(
            "NeverGuard Memory Integrity transition ring overflow: dropped {dropped} events"
        ));
    }
    loop {
        let read = TRANSITION_READ_INDEX.load(Ordering::Acquire);
        let write = TRANSITION_WRITE_INDEX.load(Ordering::Acquire);
        if read >= write {
            break;
        }
        let slot = &TRANSITION_RING[(read % MEMORY_TRANSITION_RING_CAPACITY as u64) as usize];
        if !slot.ready.load(Ordering::Acquire) {
            break;
        }
        let event = unsafe { *slot.event.get() };
        slot.ready.store(false, Ordering::Release);
        TRANSITION_READ_INDEX.store(read + 1, Ordering::Release);
        state.transition_count = state.transition_count.saturating_add(1);
        if is_executable(event.protect) {
            if let Some(range) = AddressRange::from_base_size(event.address, event.size) {
                if !state
                    .allowed_dynamic
                    .iter()
                    .any(|existing| existing.start == range.start && existing.end == range.end)
                {
                    state.allowed_dynamic.push(range);
                }
            }
        }
        let _ = event.kind;
    }
    Ok(())
}

fn queue_transition(event: MemoryTransition) {
    loop {
        let write = TRANSITION_WRITE_INDEX.load(Ordering::Acquire);
        let read = TRANSITION_READ_INDEX.load(Ordering::Acquire);
        if write.wrapping_sub(read) >= MEMORY_TRANSITION_RING_CAPACITY as u64 {
            TRANSITION_DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if TRANSITION_WRITE_INDEX
            .compare_exchange_weak(write, write + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let slot = &TRANSITION_RING[(write % MEMORY_TRANSITION_RING_CAPACITY as u64) as usize];
            unsafe {
                *slot.event.get() = event;
            }
            slot.ready.store(true, Ordering::Release);
            return;
        }
    }
}

fn range_allowed(region: &ExecutableRegion, allowed: &[AddressRange]) -> bool {
    allowed
        .iter()
        .any(|range| range.contains(region.base, region.size))
}

fn snapshot_for_regions(
    state: &MemoryIntegrityState,
    regions: &[ExecutableRegion],
) -> MemoryIntegritySnapshot {
    let mut executable_bytes = 0u64;
    let mut image_count = 0u32;
    let mut dynamic_count = 0u32;
    let mut rwx_count = 0u32;
    let mut map_rows = Vec::with_capacity(regions.len());

    for region in regions {
        executable_bytes = executable_bytes.saturating_add(region.size as u64);
        if region.kind == MEM_IMAGE {
            image_count = image_count.saturating_add(1);
        } else {
            dynamic_count = dynamic_count.saturating_add(1);
        }
        if region.protect == PAGE_EXECUTE_READWRITE || region.protect == PAGE_EXECUTE_WRITECOPY {
            rwx_count = rwx_count.saturating_add(1);
        }
        map_rows.push(format!(
            "{:016x}\0{:016x}\0{}\0{:08x}\0{:08x}",
            region.base, region.allocation_base, region.size, region.protect, region.kind
        ));
    }
    map_rows.sort_unstable();
    let mut map_digest = Sha256::new();
    map_digest.update(b"NeverGuard Memory Integrity executable-map v1\0");
    for row in map_rows {
        map_digest.update((row.len() as u32).to_le_bytes());
        map_digest.update(row.as_bytes());
    }

    let mut code_rows = state
        .image_code
        .values()
        .map(|baseline| {
            format!(
                "{:016x}\0{}\0{:08x}\0{}",
                baseline.base,
                baseline.size,
                baseline.protect,
                hex::encode(baseline.digest)
            )
        })
        .collect::<Vec<_>>();
    code_rows.sort_unstable();
    let mut code_digest = Sha256::new();
    code_digest.update(b"NeverGuard Memory Integrity code-set v1\0");
    for row in code_rows {
        code_digest.update((row.len() as u32).to_le_bytes());
        code_digest.update(row.as_bytes());
    }

    MemoryIntegritySnapshot {
        active: state.active,
        healthy: state.healthy,
        executable_regions: regions.len().min(u32::MAX as usize) as u32,
        image_code_regions: image_count,
        dynamic_executable_regions: dynamic_count,
        rwx_regions: rwx_count,
        executable_bytes,
        transition_count: state.transition_count,
        code_set_sha256: hex::encode(code_digest.finalize()),
        executable_map_sha256: hex::encode(map_digest.finalize()),
    }
}

fn is_executable(protect: u32) -> bool {
    matches!(
        protect & 0xFF,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}
