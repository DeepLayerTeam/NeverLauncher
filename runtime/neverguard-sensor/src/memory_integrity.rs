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
// Большая нагрузка запуска HotSpot может превысить очередь на 1024 события до
// двухсекундного heartbeat целостности образов. Сохраняйте все события происхождения;
// настоящее переполнение по-прежнему приводит к отказу в drain_transitions().
const MEMORY_TRANSITION_RING_CAPACITY: usize = 32768;
const MAX_HASHABLE_IMAGE_REGION: usize = 256 * 1024 * 1024;
// Allow in-flight successful IAT callbacks to publish their evidence before
// refusing an otherwise unknown executable page; never trust a timer alone.
const PROVENANCE_RECHECKS: usize = 16;
// Windows may report ERROR_PARTIAL_COPY while a loader mapping is settling.
// Retry only while VirtualQuery proves that the same executable MEM_IMAGE
// segment remains mapped. Hash validation and fail-closed still apply.
const IMAGE_READ_RECHECKS: usize = 4;
const ERROR_PARTIAL_COPY: i32 = 299;


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
    fn GetCurrentProcess() -> *mut c_void;
    fn ReadProcessMemory(
        process: *mut c_void,
        base: *const c_void,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32;
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
    // Hook Engine is already active when this function runs. Do not reset the
    // producer/consumer indices here: a concurrent JIT allocation can publish a
    // successful transition between the first hook installation and this scan.
    // Zeroing the indices discards that evidence and produces a false fail-closed
    // violation for newly executable pages. The ring is initialized statically
    // once per Sensor process; all producer events remain ordered and auditable.
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
    // Объединяйте только пересекающиеся или смежные страницы из одного доверенного
    // исходного снимка. Объединение покрывает строго ту же область без ненаблюдаемых
    // разрывов и предотвращает квадратичное сканирование горячего пути.
    coalesce_ranges(&mut state.allowed_dynamic);
    coalesce_ranges(&mut state.allowed_mapped);
    // Account for executable transitions completed while VirtualQuery walked
    // the initial address space, including events queued before this method.
    // A real overflow remains fatal in drain_transitions().
    drain_transitions(&mut state)?;
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
    // JVM может завершить VirtualProtect в другом потоке одновременно с
    // обходом адресов VirtualQuery. Ещё раз опустошите очередь после снимка,
    // чтобы завершённые и опубликованные события перехвата стали видны до
    // проверки. Переход никогда не допускается без успешно перехваченного
    // вызова API; отсутствие доказательства по-прежнему приводит к отказу.
    drain_transitions(state)?;
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
                    // Недавно загруженные образы разрешаются только после отображения
                    // загрузчиком. Module Guard независимо аутентифицирует исходную
                    // DLL; после этого исполняемые байты неизменяемы.
                    state.image_code.insert(key, current);
                }
            }
            MEM_PRIVATE => {
                if !range_allowed(region, &state.allowed_dynamic) {
                    // VirtualQuery can observe a newly executable page after the
                    // OS call returned but before its IAT wrapper published the
                    // transition. Recheck the lock-free queue a bounded number
                    // of times; do not whitelist any region without evidence.
                    for _ in 0..PROVENANCE_RECHECKS {
                        // A runnable producer may still be waiting for its time slice.
                        // Bound the race with a short wait, without ever trusting
                        // elapsed time as a substitute for observed provenance.
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        drain_transitions(state)?;
                        if range_allowed(region, &state.allowed_dynamic) {
                            break;
                        }
                    }
                    if !range_allowed(region, &state.allowed_dynamic) {
                        state.healthy = false;
                        return Err(format!(
                            "NeverGuard Memory Integrity detected executable private memory without observed VirtualAlloc/VirtualProtect provenance at 0x{:X} ({} bytes)",
                            region.base, region.size
                        ));
                    }
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

/// Опустошайте наблюдаемые аутентифицированные локальные переходы памяти процесса
/// между более дорогими снимками исполняемых образов. Это предотвращает
/// переполнение кольца при запуске, сохраняя независимое полное сканирование.
pub fn drain_pending_transitions() -> Result<(), String> {
    let mut guard = MEMORY_STATE
        .lock()
        .map_err(|_| "NeverGuard Memory Integrity state lock poisoned".to_string())?;
    let state = guard
        .as_mut()
        .ok_or_else(|| "NeverGuard Memory Integrity is not initialized".to_string())?;
    if !state.active || !state.healthy {
        return Err("NeverGuard Memory Integrity is not active/healthy".to_string());
    }
    drain_transitions(state)
}

pub fn shutdown() {
    if let Ok(mut guard) = MEMORY_STATE.lock() {
        *guard = None;
    }
}

/// Вызывается обёрткой IAT после успешного VirtualAlloc. Этот
/// путь не выделяет память и не использует блокировки, поэтому
/// безопасен даже в потоке выделителя или компилятора JVM.
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

/// Вызывается обёрткой IAT после успешного VirtualProtect.
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
    // VirtualQuery MEM_IMAGE охватывает и секции образов, отображённые через
    // MapViewOfFile(SEC_IMAGE), а не только модули из списка Windows-загрузчика.
    // GetModuleHandleExW(FROM_ADDRESS) возвращает ERROR_MOD_NOT_FOUND для таких
    // законных отображений. При возможности сохраняйте ссылку загрузчика, но никогда
    // не исключайте незарегистрированный исполняемый образ из контроля целостности.
    let _pin = pin_image(region.allocation_base.max(region.base)).ok();
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0usize;
    let process = unsafe { GetCurrentProcess() };
    while offset < region.size {
        let chunk = (region.size - offset).min(buffer.len());
        let mut copied_all = false;
        let mut last_error = String::new();
        for attempt in 0..IMAGE_READ_RECHECKS {
            let mut read = 0usize;
            let copied = unsafe {
                ReadProcessMemory(
                    process,
                    (region.base + offset) as *const c_void,
                    buffer.as_mut_ptr().cast(),
                    chunk,
                    &mut read,
                )
            };
            if copied != 0 && read == chunk {
                copied_all = true;
                break;
            }
            let error = std::io::Error::last_os_error();
            last_error = error.to_string();
            // Retry only a known transient Windows error, after confirming
            // the exact original mapping is still executable and unchanged.
            if error.raw_os_error() != Some(ERROR_PARTIAL_COPY)
                || attempt + 1 == IMAGE_READ_RECHECKS
            {
                break;
            }
            let mut now = MemoryBasicInformation::default();
            let queried = unsafe { VirtualQuery(
                (region.base + offset) as *const c_void,
                &mut now,
                std::mem::size_of::<MemoryBasicInformation>(),
            ) };
            if queried == 0
                || now.base_address as usize != region.base
                || now.allocation_base as usize != region.allocation_base
                || now.region_size != region.size
                || now.protect != region.protect
                || now.state != MEM_COMMIT
                || now.kind != MEM_IMAGE
            {
                buffer.fill(0);
                return Err(format!(
                    "NeverGuard Memory Integrity executable image mapping changed during read at 0x{:X}",
                    region.base + offset
                ));
            }
            buffer.fill(0);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if !copied_all {
            buffer.fill(0);
            return Err(format!(
                "NeverGuard Memory Integrity executable image unreadable at 0x{:X}: {}",
                region.base + offset, last_error
            ));
        }
        digest.update(&buffer[..chunk]);
        offset += chunk;
    }
    buffer.fill(0);
    // Строго отказывайте, если во время чтения образ размонтирован, отображён заново или
    // изменил разрешения; не доверяйте дайджесту, полученному из двух разных отображений.
    let mut after = MemoryBasicInformation::default();
    let queried = unsafe {
        VirtualQuery(
            region.base as *const c_void,
            &mut after,
            std::mem::size_of::<MemoryBasicInformation>(),
        )
    };
    if queried == 0
        || after.base_address as usize != region.base
        || after.allocation_base as usize != region.allocation_base
        || after.region_size != region.size
        || after.protect != region.protect
        || after.state != MEM_COMMIT
        || after.kind != MEM_IMAGE
    {
        return Err(format!(
            "NeverGuard Memory Integrity executable image mapping changed while hashing at 0x{:X}",
            region.base
        ));
    }
    let mut value = [0u8; 32];
    value.copy_from_slice(&digest.finalize());
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
    let mut updated_dynamic = false;
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
        if let Some(range) = AddressRange::from_base_size(event.address, event.size) {
            if is_executable(event.protect) {
                if !state
                    .allowed_dynamic
                    .iter()
                    .any(|existing| existing.start == range.start && existing.end == range.end)
                {
                    state.allowed_dynamic.push(range);
                    updated_dynamic = true;
                }
            } else {
                // Previously executable pages can be returned to read/write
                // memory and later reallocated. Revoke precisely those pages:
                // a new executable mapping requires another observed success.
                revoke_range(&mut state.allowed_dynamic, range);
                updated_dynamic = true;
            }
        }
        let _ = event.kind;
    }
    if updated_dynamic {
        coalesce_ranges(&mut state.allowed_dynamic);
    }
    Ok(())
}

// Remove only pages affected by a successful non-executable allocation/protection
// change. Other pages in a larger trusted allocation keep their provenance.
fn revoke_range(ranges: &mut Vec<AddressRange>, revoked: AddressRange) {
    let mut replacement = Vec::with_capacity(ranges.len().saturating_add(1));
    for current in ranges.drain(..) {
        if current.end <= revoked.start || current.start >= revoked.end {
            replacement.push(current);
            continue;
        }
        if current.start < revoked.start {
            replacement.push(AddressRange { start: current.start, end: revoked.start });
        }
        if current.end > revoked.end {
            replacement.push(AddressRange { start: revoked.end, end: current.end });
        }
    }
    *ranges = replacement;
}

// Объединяйте только пересекающиеся или соприкасающиеся интервалы. Математическое покрытие
// неизменно, а одна пропущенная исполняемая страница остаётся критическим пробелом.
fn coalesce_ranges(ranges: &mut Vec<AddressRange>) {
    if ranges.len() < 2 {
        return;
    }
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut output = 1usize;
    for idx in 1..ranges.len() {
        let current = ranges[idx];
        let last = &mut ranges[output - 1];
        if current.start <= last.end {
            last.end = last.end.max(current.end);
        } else {
            ranges[output] = current;
            output += 1;
        }
    }
    ranges.truncate(output);
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
    // VirtualQuery объединяет соседние страницы с одинаковой защитой, а
    // VirtualProtect записывает каждый независимо проверенный диапазон перехода.
    // Требуйте полного покрытия объединения; любой ненаблюдаемый пробел критичен.
    if allowed.iter().any(|range| range.contains(region.base, region.size)) {
        return true;
    }
    let Some(end) = region.base.checked_add(region.size) else {
        return false;
    };
    let mut covered = region.base;
    while covered < end {
        let Some(next) = allowed
            .iter()
            .filter(|range| range.start <= covered && range.end > covered)
            .map(|range| range.end)
            .max()
        else {
            return false;
        };
        covered = next;
    }
    true
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
    // Отделяйте домен хеша набора кода от сырых байтов образа фиксированным
    // SHA-256-тегом. На дайджест влияют и тег, и измеренные области.
    let code_domain = Sha256::digest(b"NeverGuard Memory Integrity code-set v1\0");
    let mut code_digest = Sha256::new();
    code_digest.update(code_domain);
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

#[cfg(test)]
mod transition_coverage_tests {
    use super::*;

    fn private_region(base: usize, size: usize) -> ExecutableRegion {
        ExecutableRegion {
            base,
            allocation_base: base,
            size,
            protect: PAGE_EXECUTE_READ,
            kind: MEM_PRIVATE,
        }
    }

    #[test]
    fn adjacent_observed_transitions_cover_merged_virtualquery_region() {
        let pages = [
            AddressRange::from_base_size(0x10000, 0x1000).unwrap(),
            AddressRange::from_base_size(0x11000, 0x1000).unwrap(),
            AddressRange::from_base_size(0x12000, 0x1000).unwrap(),
        ];
        assert!(range_allowed(&private_region(0x10000, 0x3000), &pages));
    }

    #[test]
    fn unknown_executable_page_between_transitions_remains_blocked() {
        let pages = [
            AddressRange::from_base_size(0x10000, 0x1000).unwrap(),
            AddressRange::from_base_size(0x12000, 0x1000).unwrap(),
        ];
        assert!(!range_allowed(&private_region(0x10000, 0x3000), &pages));
    }

    #[test]
    fn coalescing_preserves_observed_union_without_admitting_gaps() {
        let mut pages = vec![
            AddressRange::from_base_size(0x15000, 0x1000).unwrap(),
            AddressRange::from_base_size(0x10000, 0x1000).unwrap(),
            AddressRange::from_base_size(0x11000, 0x1000).unwrap(),
            AddressRange::from_base_size(0x10000, 0x1000).unwrap(),
        ];
        coalesce_ranges(&mut pages);
        assert_eq!(pages.len(), 2);
        assert_eq!((pages[0].start, pages[0].end), (0x10000, 0x12000));
        assert!(!range_allowed(&private_region(0x10000, 0x6000), &pages));
        assert!(range_allowed(&private_region(0x10000, 0x2000), &pages));
        assert!(range_allowed(&private_region(0x15000, 0x1000), &pages));
    }

    #[test]
    fn ring_can_retain_startup_bursts_without_relaxing_fail_closed() {
        assert!(MEMORY_TRANSITION_RING_CAPACITY >= 32768);
    }
}

#[cfg(test)]
mod provenance_range_tests {
    use super::{coalesce_ranges, range_allowed, revoke_range, AddressRange, ExecutableRegion, MEM_PRIVATE};

    fn region(base: usize, size: usize) -> ExecutableRegion {
        ExecutableRegion { base, allocation_base: base, size, protect: 0x20, kind: MEM_PRIVATE }
    }

    #[test]
    fn removal_revokes_only_touched_executable_pages() {
        let mut ranges = vec![AddressRange { start: 0x1000, end: 0x6000 }];
        revoke_range(&mut ranges, AddressRange { start: 0x3000, end: 0x4000 });
        assert!(range_allowed(&region(0x1000, 0x2000), &ranges));
        assert!(!range_allowed(&region(0x3000, 0x1000), &ranges));
        assert!(range_allowed(&region(0x4000, 0x2000), &ranges));
        assert!(!range_allowed(&region(0x2000, 0x3000), &ranges));
    }

    #[test]
    fn full_revoke_and_new_grant_do_not_preserve_stale_permissions() {
        let mut ranges = vec![AddressRange { start: 0x1000, end: 0x3000 }];
        revoke_range(&mut ranges, AddressRange { start: 0x1000, end: 0x3000 });
        assert!(!range_allowed(&region(0x1000, 0x1000), &ranges));
        ranges.push(AddressRange { start: 0x2000, end: 0x3000 });
        assert!(!range_allowed(&region(0x1000, 0x2000), &ranges));
        assert!(range_allowed(&region(0x2000, 0x1000), &ranges));
    }

    #[test]
    fn adjacent_real_grants_cover_a_region_but_gaps_do_not() {
        let mut ranges = vec![
            AddressRange { start: 0x1000, end: 0x2000 },
            AddressRange { start: 0x3000, end: 0x4000 },
        ];
        coalesce_ranges(&mut ranges);
        assert!(!range_allowed(&region(0x1000, 0x3000), &ranges));
        ranges.push(AddressRange { start: 0x2000, end: 0x3000 });
        coalesce_ranges(&mut ranges);
        assert!(range_allowed(&region(0x1000, 0x3000), &ranges));
    }
}
